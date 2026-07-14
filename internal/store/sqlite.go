package store

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	roomv1 "github.com/haasonsaas/room/gen/go/room/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS room_state (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  snapshot BLOB NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS ruleset_versions (
  version INTEGER PRIMARY KEY,
  payload BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_events (
  event_id TEXT PRIMARY KEY,
  occurred_at INTEGER NOT NULL,
  kind INTEGER NOT NULL,
  workspace_id TEXT NOT NULL,
  repository TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  payload BLOB NOT NULL,
  payload_sha256 BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_events_time_idx ON audit_events(occurred_at DESC, event_id DESC);
CREATE INDEX IF NOT EXISTS audit_events_scope_idx ON audit_events(workspace_id, repository, occurred_at DESC);
`

type Store struct {
	db       *sql.DB
	mu       sync.Mutex
	snapshot *roomv1.StoreSnapshot
}

func Open(path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("store path is required")
	}
	legacy, err := importLegacySnapshot(path)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil && filepath.Dir(path) != "." {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	if info, statErr := file.Stat(); statErr != nil {
		_ = file.Close()
		return nil, statErr
	} else if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		_ = file.Close()
		return nil, errors.New("store must be a private regular file")
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, statement := range []string{"PRAGMA journal_mode=WAL", "PRAGMA foreign_keys=ON", "PRAGMA busy_timeout=5000", schema} {
		if _, err := db.Exec(statement); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("initialize sqlite store: %w", err)
		}
	}
	s := &Store{db: db}
	if legacy != nil {
		s.snapshot = legacy
	} else if err := s.load(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if s.snapshot == nil {
		legacy, err = readLegacySnapshot(path + ".legacy.json")
		if err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("recover legacy store: %w", err)
		}
		if legacy != nil {
			s.snapshot = legacy
		}
	}
	if s.snapshot == nil {
		s.snapshot = &roomv1.StoreSnapshot{NextVersion: 1, DraftMcpPolicy: secureDefaultMCPPolicy()}
	}
	if s.snapshot.GetDraftMcpPolicy() == nil {
		s.snapshot.DraftMcpPolicy = secureDefaultMCPPolicy()
	}
	draftMigrated := migrateKnownRules(s.snapshot.GetDraftRules())
	for _, version := range s.snapshot.GetVersions() {
		if migrateKnownRules(version.GetRules()) {
			version.Hash = rulesetHash(version)
		}
		for _, rule := range version.GetRules() {
			if err := validateRule(rule); err != nil {
				_ = db.Close()
				return nil, fmt.Errorf("migrate ruleset version %d rule %q: %w", version.GetVersion(), rule.GetId(), err)
			}
		}
	}
	if len(s.snapshot.GetDraftRules()) == 0 && len(s.snapshot.GetVersions()) == 0 {
		s.snapshot.DraftRules = defaultRules()
		draftMigrated = true
	}
	if draftMigrated || len(s.snapshot.GetVersions()) == 0 {
		if draftMigrated && len(s.snapshot.GetVersions()) > 0 {
			if err := s.save(); err != nil {
				_ = db.Close()
				return nil, fmt.Errorf("persist migrated ruleset history: %w", err)
			}
		}
		if _, err := s.Publish("system", "Publish typed security-signal rules"); err != nil {
			_ = db.Close()
			return nil, err
		}
	} else if err := s.save(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if legacy != nil {
		if err := syncDirectory(filepath.Dir(path)); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("sync migrated store directory: %w", err)
		}
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) UpsertRule(rule *roomv1.Rule) (*roomv1.Rule, error) {
	copyRule := cloneRule(rule)
	migrateKnownRule(copyRule)
	if err := validateRule(copyRule); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	candidate := proto.Clone(s.snapshot).(*roomv1.StoreSnapshot)
	now := timestamppb.Now()
	if copyRule.GetCreatedAt() == nil {
		copyRule.CreatedAt = now
	}
	copyRule.UpdatedAt = now
	for i, existing := range candidate.DraftRules {
		if existing.GetId() == copyRule.GetId() {
			copyRule.CreatedAt = existing.GetCreatedAt()
			candidate.DraftRules[i] = copyRule
			sortRules(candidate.DraftRules)
			return cloneRule(copyRule), s.commitCandidateLocked(candidate, nil, nil)
		}
	}
	candidate.DraftRules = append(candidate.DraftRules, copyRule)
	sortRules(candidate.DraftRules)
	return cloneRule(copyRule), s.commitCandidateLocked(candidate, nil, nil)
}

func (s *Store) DeleteRule(id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	candidate := proto.Clone(s.snapshot).(*roomv1.StoreSnapshot)
	for i, rule := range candidate.DraftRules {
		if rule.GetId() == id {
			candidate.DraftRules = append(candidate.DraftRules[:i], candidate.DraftRules[i+1:]...)
			return true, s.commitCandidateLocked(candidate, nil, nil)
		}
	}
	return false, nil
}

func (s *Store) ListRules(includeDisabled bool) []*roomv1.Rule {
	s.mu.Lock()
	defer s.mu.Unlock()
	rules := make([]*roomv1.Rule, 0, len(s.snapshot.DraftRules))
	for _, rule := range s.snapshot.DraftRules {
		if includeDisabled || rule.GetEnabled() {
			rules = append(rules, cloneRule(rule))
		}
	}
	return rules
}

func (s *Store) Publish(author, notes string) (*roomv1.RulesetVersion, error) {
	return s.PublishAudited(author, notes, nil)
}

func (s *Store) PublishAudited(author, notes string, audit *roomv1.AuditEvent) (*roomv1.RulesetVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	candidate := proto.Clone(s.snapshot).(*roomv1.StoreSnapshot)
	for _, rule := range candidate.GetDraftRules() {
		if err := validateRule(rule); err != nil {
			return nil, fmt.Errorf("publish rule %q: %w", rule.GetId(), err)
		}
	}
	version := candidate.GetNextVersion()
	if version <= 0 {
		version = 1
	}
	rules := cloneRules(candidate.GetDraftRules())
	sortRules(rules)
	ruleset := &roomv1.RulesetVersion{Id: fmt.Sprintf("ruleset-%d", version), Version: version, Status: roomv1.RulesetStatus_RULESET_STATUS_ACTIVE, Rules: rules, Author: author, Notes: notes, PublishedAt: timestamppb.Now(), McpPolicy: cloneMCPPolicy(candidate.GetDraftMcpPolicy())}
	ruleset.Hash = rulesetHash(ruleset)
	for _, existing := range candidate.Versions {
		if existing.GetStatus() == roomv1.RulesetStatus_RULESET_STATUS_ACTIVE {
			existing.Status = roomv1.RulesetStatus_RULESET_STATUS_ARCHIVED
		}
	}
	candidate.Versions = append(candidate.Versions, ruleset)
	candidate.ActiveVersion = version
	candidate.NextVersion = version + 1
	if audit != nil {
		audit.RulesetId, audit.RulesetVersion, audit.RulesetHash = ruleset.GetId(), ruleset.GetVersion(), ruleset.GetHash()
	}
	return cloneRuleset(ruleset), s.commitCandidateLocked(candidate, []*roomv1.RulesetVersion{ruleset}, audit)
}

func (s *Store) Rollback(version int32) (*roomv1.RulesetVersion, error) {
	return s.RollbackAudited(version, nil)
}

func (s *Store) RollbackAudited(version int32, audit *roomv1.AuditEvent) (*roomv1.RulesetVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	candidate := proto.Clone(s.snapshot).(*roomv1.StoreSnapshot)
	var target *roomv1.RulesetVersion
	for _, ruleset := range candidate.Versions {
		if ruleset.GetVersion() == version {
			target = ruleset
			break
		}
	}
	if target == nil {
		return nil, fmt.Errorf("ruleset version %d not found", version)
	}
	for _, ruleset := range candidate.Versions {
		ruleset.Status = roomv1.RulesetStatus_RULESET_STATUS_ARCHIVED
	}
	target.Status = roomv1.RulesetStatus_RULESET_STATUS_ACTIVE
	candidate.ActiveVersion = version
	candidate.DraftRules = cloneRules(target.GetRules())
	candidate.DraftMcpPolicy = cloneMCPPolicy(target.GetMcpPolicy())
	if audit != nil {
		audit.RulesetId, audit.RulesetVersion, audit.RulesetHash = target.GetId(), target.GetVersion(), target.GetHash()
	}
	return cloneRuleset(target), s.commitCandidateLocked(candidate, nil, audit)
}

func (s *Store) ActiveRuleset() *roomv1.RulesetVersion {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activeRulesetLocked(0, false)
}

// ActiveRulesetIfChanged returns the active ruleset only when its version
// differs from lastVersion.
func (s *Store) ActiveRulesetIfChanged(lastVersion int32) *roomv1.RulesetVersion {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activeRulesetLocked(lastVersion, true)
}

func (s *Store) activeRulesetLocked(lastVersion int32, onlyIfChanged bool) *roomv1.RulesetVersion {
	for _, ruleset := range s.snapshot.Versions {
		if ruleset.GetVersion() == s.snapshot.GetActiveVersion() {
			if onlyIfChanged && ruleset.GetVersion() == lastVersion {
				return nil
			}
			return cloneRuleset(ruleset)
		}
	}
	return nil
}

func (s *Store) MCPPolicy() *roomv1.McpCompliancePolicy {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneMCPPolicy(s.snapshot.GetDraftMcpPolicy())
}

func (s *Store) UpdateMCPPolicy(policy *roomv1.McpCompliancePolicy) (*roomv1.McpCompliancePolicy, error) {
	return s.UpdateMCPPolicyAudited(policy, nil)
}

func (s *Store) UpdateMCPPolicyAudited(policy *roomv1.McpCompliancePolicy, audit *roomv1.AuditEvent) (*roomv1.McpCompliancePolicy, error) {
	if err := validateMCPPolicy(policy); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	candidate := proto.Clone(s.snapshot).(*roomv1.StoreSnapshot)
	candidate.DraftMcpPolicy = cloneMCPPolicy(policy)
	return cloneMCPPolicy(policy), s.commitCandidateLocked(candidate, nil, audit)
}

func (s *Store) AppendAudit(event *roomv1.AuditEvent) (string, error) {
	return appendAudit(s.db, event)
}

type auditExecutor interface {
	Exec(query string, args ...any) (sql.Result, error)
	QueryRow(query string, args ...any) *sql.Row
}

func appendAudit(executor auditExecutor, event *roomv1.AuditEvent) (string, error) {
	if event == nil {
		return "", errors.New("audit event is required")
	}
	if event.GetId() == "" {
		event.Id = newID()
	}
	if event.GetOccurredAt() == nil {
		event.OccurredAt = timestamppb.Now()
	}
	copyEvent := proto.Clone(event).(*roomv1.AuditEvent)
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(copyEvent)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(payload)
	result, err := executor.Exec(`INSERT INTO audit_events(event_id, occurred_at, kind, workspace_id, repository, subject_id, payload, payload_sha256) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(event_id) DO NOTHING`, copyEvent.GetId(), copyEvent.GetOccurredAt().AsTime().UnixNano(), int32(copyEvent.GetKind()), copyEvent.GetWorkspaceId(), copyEvent.GetRepository(), copyEvent.GetSubjectId(), payload, digest[:])
	if err != nil {
		return "", err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		var existingPayload, existingDigest []byte
		if err := executor.QueryRow(`SELECT payload, payload_sha256 FROM audit_events WHERE event_id = ?`, copyEvent.GetId()).Scan(&existingPayload, &existingDigest); err != nil {
			return "", err
		}
		if !bytes.Equal(existingPayload, payload) || !bytes.Equal(existingDigest, digest[:]) {
			return "", errors.New("audit event id reused with different payload")
		}
	}
	return copyEvent.GetId(), nil
}

func (s *Store) ListAudit(limit int32, kind roomv1.AuditEventKind) ([]*roomv1.AuditEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query := `SELECT payload FROM audit_events`
	args := []any{}
	if kind != roomv1.AuditEventKind_AUDIT_EVENT_KIND_UNSPECIFIED {
		query += ` WHERE kind = ?`
		args = append(args, int32(kind))
	}
	query += ` ORDER BY occurred_at DESC, event_id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := make([]*roomv1.AuditEvent, 0)
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		event := &roomv1.AuditEvent{}
		if err := proto.Unmarshal(payload, event); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func (s *Store) AuditEvent(id string) (*roomv1.AuditEvent, error) {
	if strings.TrimSpace(id) == "" {
		return nil, errors.New("audit event id is required")
	}
	var payload []byte
	if err := s.db.QueryRow(`SELECT payload FROM audit_events WHERE event_id = ?`, id).Scan(&payload); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	event := &roomv1.AuditEvent{}
	if err := proto.Unmarshal(payload, event); err != nil {
		return nil, err
	}
	return event, nil
}

func (s *Store) load() error {
	var payload []byte
	err := s.db.QueryRow(`SELECT snapshot FROM room_state WHERE id = 1`).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	snapshot := &roomv1.StoreSnapshot{}
	if err := proto.Unmarshal(payload, snapshot); err != nil {
		return fmt.Errorf("decode sqlite snapshot: %w", err)
	}
	rows, err := s.db.Query(`SELECT payload FROM ruleset_versions ORDER BY version`)
	if err != nil {
		return err
	}
	defer rows.Close()
	versions := make([]*roomv1.RulesetVersion, 0)
	for rows.Next() {
		var versionPayload []byte
		if err := rows.Scan(&versionPayload); err != nil {
			return err
		}
		version := &roomv1.RulesetVersion{}
		if err := proto.Unmarshal(versionPayload, version); err != nil {
			return fmt.Errorf("decode ruleset version: %w", err)
		}
		versions = append(versions, version)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(versions) > 0 {
		snapshot.Versions = versions
	}
	for _, version := range snapshot.GetVersions() {
		version.Status = roomv1.RulesetStatus_RULESET_STATUS_ARCHIVED
		if version.GetVersion() == snapshot.GetActiveVersion() {
			version.Status = roomv1.RulesetStatus_RULESET_STATUS_ACTIVE
		}
	}
	s.snapshot = snapshot
	return nil
}

func (s *Store) save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.persistSnapshotLocked(s.snapshot, s.snapshot.GetVersions(), nil)
}

func (s *Store) commitCandidateLocked(candidate *roomv1.StoreSnapshot, versions []*roomv1.RulesetVersion, audit *roomv1.AuditEvent) error {
	if err := s.persistSnapshotLocked(candidate, versions, audit); err != nil {
		return err
	}
	s.snapshot = candidate
	return nil
}

func (s *Store) persistSnapshotLocked(snapshot *roomv1.StoreSnapshot, versions []*roomv1.RulesetVersion, audit *roomv1.AuditEvent) error {
	state := proto.Clone(snapshot).(*roomv1.StoreSnapshot)
	state.Versions = nil
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(state)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, version := range versions {
		stored := cloneRuleset(version)
		stored.Status = roomv1.RulesetStatus_RULESET_STATUS_UNSPECIFIED
		versionPayload, marshalErr := proto.MarshalOptions{Deterministic: true}.Marshal(stored)
		if marshalErr != nil {
			return marshalErr
		}
		if _, err := tx.Exec(`INSERT INTO ruleset_versions(version, payload) VALUES(?, ?) ON CONFLICT(version) DO UPDATE SET payload=excluded.payload`, version.GetVersion(), versionPayload); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`INSERT INTO room_state(id, snapshot, updated_at) VALUES(1, ?, ?) ON CONFLICT(id) DO UPDATE SET snapshot=excluded.snapshot, updated_at=excluded.updated_at`, payload, time.Now().UnixNano()); err != nil {
		return err
	}
	if audit != nil {
		if _, err := appendAudit(tx, audit); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func importLegacySnapshot(path string) (*roomv1.StoreSnapshot, error) {
	snapshot, err := readLegacySnapshot(path)
	if err != nil || snapshot == nil {
		return snapshot, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, fmt.Errorf("secure legacy store: %w", err)
	}
	backup := path + ".legacy.json"
	if err := os.Rename(path, backup); err != nil {
		return nil, fmt.Errorf("preserve legacy store: %w", err)
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("sync legacy backup directory: %w", err)
	}
	return snapshot, nil
}

func readLegacySnapshot(path string) (*roomv1.StoreSnapshot, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(data)) == 0 || bytes.TrimSpace(data)[0] != '{' {
		return nil, nil
	}
	snapshot := &roomv1.StoreSnapshot{}
	if err := protojson.Unmarshal(data, snapshot); err != nil {
		return nil, fmt.Errorf("read legacy store %s: %w", path, err)
	}
	return snapshot, nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func validateRule(rule *roomv1.Rule) error {
	if rule == nil || strings.TrimSpace(rule.GetId()) == "" {
		return errors.New("rule.id is required")
	}
	if len(rule.GetTriggers()) == 0 {
		return errors.New("typed signal trigger is required; legacy text checks are not executable")
	}
	if len(rule.GetChecks()) != 0 {
		return errors.New("legacy text checks cannot be combined with typed signal policy")
	}
	for _, trigger := range rule.GetTriggers() {
		if trigger == nil || trigger.GetSignal() <= roomv1.SignalKind_SIGNAL_KIND_UNSPECIFIED || trigger.GetSignal() > roomv1.SignalKind_SIGNAL_KIND_RUST_UNVALIDATED_EXTERNAL_DESERIALIZATION || trigger.GetMinimumConfidenceBasisPoints() > 10000 {
			return errors.New("invalid signal trigger")
		}
		for _, phase := range trigger.GetPhases() {
			if phase != roomv1.AnalysisPhase_ANALYSIS_PHASE_PLAN && phase != roomv1.AnalysisPhase_ANALYSIS_PHASE_DIFF {
				return errors.New("invalid analysis phase")
			}
		}
	}
	for _, signal := range rule.GetRequiredCoverage() {
		if signal <= roomv1.SignalKind_SIGNAL_KIND_UNSPECIFIED || signal > roomv1.SignalKind_SIGNAL_KIND_RUST_UNVALIDATED_EXTERNAL_DESERIALIZATION {
			return errors.New("invalid required signal coverage")
		}
	}
	return nil
}

func validateMCPPolicy(policy *roomv1.McpCompliancePolicy) error {
	if policy == nil || policy.GetMode() == roomv1.McpComplianceMode_MCP_COMPLIANCE_MODE_UNSPECIFIED {
		return errors.New("MCP policy mode is required")
	}
	selectors := make(map[string]struct{}, len(policy.GetSelectors()))
	for _, selector := range policy.GetSelectors() {
		if selector == nil || strings.TrimSpace(selector.GetServerId()) == "" || strings.TrimSpace(selector.GetToolName()) == "" {
			return errors.New("MCP selectors require server_id and tool_name")
		}
		key := selector.GetServerId() + "\x00" + selector.GetToolName()
		if _, duplicate := selectors[key]; duplicate {
			return errors.New("duplicate MCP selector")
		}
		selectors[key] = struct{}{}
	}
	bindings := make(map[string]struct{}, len(policy.GetProviderBindings()))
	for _, binding := range policy.GetProviderBindings() {
		if binding == nil || binding.GetProvider() == roomv1.HookProvider_HOOK_PROVIDER_UNSPECIFIED || binding.GetProviderToolId() == "" || binding.GetServerId() == "" || binding.GetToolName() == "" {
			return errors.New("provider bindings require provider, provider_tool_id, server_id, and tool_name")
		}
		key := fmt.Sprintf("%d\x00%s", binding.GetProvider(), binding.GetProviderToolId())
		if _, duplicate := bindings[key]; duplicate {
			return errors.New("duplicate MCP provider binding")
		}
		bindings[key] = struct{}{}
	}
	return nil
}

func rulesetHash(ruleset *roomv1.RulesetVersion) string {
	clone := cloneRuleset(ruleset)
	clone.Hash = ""
	clone.Status = roomv1.RulesetStatus_RULESET_STATUS_UNSPECIFIED
	clone.AuthorizedScope = nil
	clone.SourceHash = ""
	data, _ := proto.MarshalOptions{Deterministic: true}.Marshal(clone)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func cloneRule(rule *roomv1.Rule) *roomv1.Rule {
	if rule == nil {
		return nil
	}
	return proto.Clone(rule).(*roomv1.Rule)
}

func cloneRules(rules []*roomv1.Rule) []*roomv1.Rule {
	out := make([]*roomv1.Rule, 0, len(rules))
	for _, rule := range rules {
		out = append(out, cloneRule(rule))
	}
	return out
}

func cloneRuleset(ruleset *roomv1.RulesetVersion) *roomv1.RulesetVersion {
	if ruleset == nil {
		return nil
	}
	return proto.Clone(ruleset).(*roomv1.RulesetVersion)
}

func cloneMCPPolicy(policy *roomv1.McpCompliancePolicy) *roomv1.McpCompliancePolicy {
	if policy == nil {
		return nil
	}
	return proto.Clone(policy).(*roomv1.McpCompliancePolicy)
}

func sortRules(rules []*roomv1.Rule) {
	sort.Slice(rules, func(i, j int) bool { return rules[i].GetId() < rules[j].GetId() })
}

func secureDefaultMCPPolicy() *roomv1.McpCompliancePolicy {
	return &roomv1.McpCompliancePolicy{Mode: roomv1.McpComplianceMode_MCP_COMPLIANCE_MODE_ALLOWLIST, DenyUnknownIdentity: true, AuditAllowed: true}
}

func newID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return fmt.Sprintf("event-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(value[:])
}
