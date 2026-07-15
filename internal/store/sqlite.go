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
CREATE TABLE IF NOT EXISTS review_findings (
  finding_id TEXT PRIMARY KEY,
  repository TEXT NOT NULL,
  claim_kind INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  payload BLOB NOT NULL,
  payload_sha256 BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS policy_candidates (
  candidate_id TEXT PRIMARY KEY,
  rollout_stage INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  payload BLOB NOT NULL,
  payload_sha256 BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS policy_replay_runs (
  replay_id TEXT PRIMARY KEY,
  policy_candidate_id TEXT NOT NULL,
  started_at INTEGER NOT NULL,
  completed_at INTEGER NOT NULL,
  payload BLOB NOT NULL,
  payload_sha256 BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS tuning_decisions (
  decision_id TEXT PRIMARY KEY,
  policy_candidate_id TEXT NOT NULL,
  occurred_at INTEGER NOT NULL,
  payload BLOB NOT NULL,
  payload_sha256 BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_events_time_idx ON audit_events(occurred_at DESC, event_id DESC);
CREATE INDEX IF NOT EXISTS audit_events_scope_idx ON audit_events(workspace_id, repository, occurred_at DESC);
CREATE INDEX IF NOT EXISTS review_findings_repository_idx ON review_findings(repository, updated_at DESC, finding_id DESC);
CREATE INDEX IF NOT EXISTS review_findings_claim_idx ON review_findings(claim_kind, updated_at DESC, finding_id DESC);
CREATE INDEX IF NOT EXISTS policy_candidates_stage_idx ON policy_candidates(rollout_stage, updated_at DESC, candidate_id DESC);
CREATE INDEX IF NOT EXISTS policy_replay_candidate_idx ON policy_replay_runs(policy_candidate_id, completed_at DESC, replay_id DESC);
CREATE INDEX IF NOT EXISTS tuning_candidate_idx ON tuning_decisions(policy_candidate_id, occurred_at DESC, decision_id DESC);
`

type Store struct {
	db       *sql.DB
	mu       sync.Mutex
	snapshot *roomv1.StoreSnapshot
}

// ErrPolicyCandidateConflict indicates that a candidate changed after the
// caller read it. Callers should reload the candidate before retrying.
var ErrPolicyCandidateConflict = errors.New("policy candidate update conflict")

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
			if copyRule.Scope == nil {
				copyRule.Scope = cloneRule(existing).GetScope()
			}
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

func (s *Store) commitIntelligenceMutation(audit *roomv1.AuditEvent, mutate func(*sql.Tx) error) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if mutate != nil {
		if err := mutate(tx); err != nil {
			return err
		}
	}
	if audit != nil {
		if _, err := appendAudit(tx, audit); err != nil {
			return err
		}
	}
	return tx.Commit()
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
	query := `SELECT event_id, kind, workspace_id, repository, subject_id, payload, payload_sha256 FROM audit_events`
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
		var eventID, workspaceID, repository, subjectID string
		var kind int32
		var payload, digest []byte
		if err := rows.Scan(&eventID, &kind, &workspaceID, &repository, &subjectID, &payload, &digest); err != nil {
			return nil, err
		}
		if err := verifyPayloadDigest(payload, digest, "audit event"); err != nil {
			return nil, err
		}
		event := &roomv1.AuditEvent{}
		if err := proto.Unmarshal(payload, event); err != nil {
			return nil, err
		}
		if event.GetId() != eventID || int32(event.GetKind()) != kind || event.GetWorkspaceId() != workspaceID || event.GetRepository() != repository || event.GetSubjectId() != subjectID {
			return nil, errors.New("audit event indexed identity does not match payload")
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func (s *Store) AuditEvent(id string) (*roomv1.AuditEvent, error) {
	if strings.TrimSpace(id) == "" {
		return nil, errors.New("audit event id is required")
	}
	var indexedID string
	var payload, digest []byte
	if err := s.db.QueryRow(`SELECT event_id, payload, payload_sha256 FROM audit_events WHERE event_id = ?`, id).Scan(&indexedID, &payload, &digest); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if err := verifyPayloadDigest(payload, digest, "audit event"); err != nil {
		return nil, err
	}
	event := &roomv1.AuditEvent{}
	if err := proto.Unmarshal(payload, event); err != nil {
		return nil, err
	}
	if event.GetId() != indexedID {
		return nil, errors.New("audit event indexed identity does not match payload")
	}
	return event, nil
}

func (s *Store) UpsertReviewFinding(finding *roomv1.ReviewFinding) (*roomv1.ReviewFinding, error) {
	return s.UpsertReviewFindingAudited(finding, nil)
}

func (s *Store) UpsertReviewFindingAudited(finding *roomv1.ReviewFinding, audit *roomv1.AuditEvent) (*roomv1.ReviewFinding, error) {
	copyFinding := cloneReviewFinding(finding)
	if copyFinding != nil && (len(copyFinding.GetOutcomes()) != 0 || len(copyFinding.GetAdjudications()) != 0) {
		return nil, errors.New("review outcomes and adjudications must use append APIs")
	}
	if err := validateReviewFinding(copyFinding); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, err := s.reviewFinding(copyFinding.GetId())
	if err != nil {
		return nil, err
	}
	now := timestamppb.Now()
	if existing == nil {
		if copyFinding.GetCreatedAt() == nil {
			copyFinding.CreatedAt = now
		}
		if copyFinding.GetUpdatedAt() == nil {
			copyFinding.UpdatedAt = copyFinding.GetCreatedAt()
		}
	} else {
		if copyFinding.GetCreatedAt() == nil {
			copyFinding.CreatedAt = existing.GetCreatedAt()
		}
		copyFinding.UpdatedAt = existing.GetUpdatedAt()
		existingBase := cloneReviewFinding(existing)
		existingBase.Outcomes = nil
		existingBase.Adjudications = nil
		if proto.Equal(copyFinding, existingBase) {
			if err := s.commitIntelligenceMutation(audit, nil); err != nil {
				return nil, err
			}
			return cloneReviewFinding(existing), nil
		}
		return nil, errors.New("review finding id reused with different immutable payload")
	}
	if err := validateReviewFinding(copyFinding); err != nil {
		return nil, err
	}
	if err := s.commitIntelligenceMutation(audit, func(tx *sql.Tx) error { return writeReviewFinding(tx, copyFinding) }); err != nil {
		return nil, err
	}
	return cloneReviewFinding(copyFinding), nil
}

func (s *Store) ReviewFinding(id string) (*roomv1.ReviewFinding, error) {
	if strings.TrimSpace(id) == "" {
		return nil, errors.New("finding id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	finding, err := s.reviewFinding(id)
	return cloneReviewFinding(finding), err
}

func (s *Store) reviewFinding(id string) (*roomv1.ReviewFinding, error) {
	var indexedID, repository string
	var claimKind int32
	var payload, digest []byte
	if err := s.db.QueryRow(`SELECT finding_id, repository, claim_kind, payload, payload_sha256 FROM review_findings WHERE finding_id = ?`, id).Scan(&indexedID, &repository, &claimKind, &payload, &digest); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if err := verifyPayloadDigest(payload, digest, "review finding"); err != nil {
		return nil, err
	}
	finding := &roomv1.ReviewFinding{}
	if err := proto.Unmarshal(payload, finding); err != nil {
		return nil, fmt.Errorf("decode review finding: %w", err)
	}
	if finding.GetId() != indexedID || finding.GetSource().GetRepository() != repository || int32(finding.GetClaimKind()) != claimKind {
		return nil, errors.New("review finding indexed identity does not match payload")
	}
	return finding, nil
}

func (s *Store) ListReviewFindings(repository string, claimKind roomv1.ReviewClaimKind, limit int32) ([]*roomv1.ReviewFinding, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query := `SELECT finding_id, repository, claim_kind, payload, payload_sha256 FROM review_findings`
	clauses := make([]string, 0, 2)
	args := make([]any, 0, 3)
	if strings.TrimSpace(repository) != "" {
		clauses = append(clauses, `repository = ?`)
		args = append(args, repository)
	}
	if claimKind != roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_UNSPECIFIED {
		if !validReviewClaimKind(claimKind) {
			return nil, errors.New("invalid review claim kind")
		}
		clauses = append(clauses, `claim_kind = ?`)
		args = append(args, int32(claimKind))
	}
	if len(clauses) > 0 {
		query += ` WHERE ` + strings.Join(clauses, ` AND `)
	}
	query += ` ORDER BY updated_at DESC, finding_id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	findings := make([]*roomv1.ReviewFinding, 0)
	for rows.Next() {
		finding := &roomv1.ReviewFinding{}
		var indexedID, indexedRepository string
		var indexedClaimKind int32
		var payload, digest []byte
		if err := rows.Scan(&indexedID, &indexedRepository, &indexedClaimKind, &payload, &digest); err != nil {
			return nil, err
		}
		if err := verifyPayloadDigest(payload, digest, "review finding"); err != nil {
			return nil, err
		}
		if err := proto.Unmarshal(payload, finding); err != nil {
			return nil, fmt.Errorf("decode review finding: %w", err)
		}
		if finding.GetId() != indexedID || finding.GetSource().GetRepository() != indexedRepository || int32(finding.GetClaimKind()) != indexedClaimKind {
			return nil, errors.New("review finding indexed identity does not match payload")
		}
		findings = append(findings, finding)
	}
	return findings, rows.Err()
}

func (s *Store) AppendReviewOutcome(findingID string, outcome *roomv1.ReviewOutcome) (*roomv1.ReviewFinding, error) {
	return s.AppendReviewOutcomeAudited(findingID, outcome, nil)
}

func (s *Store) AppendReviewOutcomeAudited(findingID string, outcome *roomv1.ReviewOutcome, audit *roomv1.AuditEvent) (*roomv1.ReviewFinding, error) {
	copyOutcome := cloneReviewOutcome(outcome)
	if err := validateReviewOutcome(copyOutcome); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	finding, err := s.reviewFinding(findingID)
	if err != nil {
		return nil, err
	}
	if finding == nil {
		return nil, fmt.Errorf("review finding %q not found", findingID)
	}
	for _, existing := range finding.GetOutcomes() {
		if existing.GetId() != copyOutcome.GetId() {
			continue
		}
		if copyOutcome.GetOccurredAt() == nil {
			copyOutcome.OccurredAt = existing.GetOccurredAt()
		}
		if proto.Equal(existing, copyOutcome) {
			if err := s.commitIntelligenceMutation(audit, nil); err != nil {
				return nil, err
			}
			return cloneReviewFinding(finding), nil
		}
		return nil, errors.New("review outcome id reused with different payload")
	}
	if copyOutcome.GetOccurredAt() == nil {
		copyOutcome.OccurredAt = timestamppb.Now()
	}
	finding.Outcomes = append(finding.Outcomes, copyOutcome)
	finding.UpdatedAt = timestamppb.Now()
	if err := s.commitIntelligenceMutation(audit, func(tx *sql.Tx) error { return writeReviewFinding(tx, finding) }); err != nil {
		return nil, err
	}
	return cloneReviewFinding(finding), nil
}

func (s *Store) AppendReviewAdjudication(findingID string, adjudication *roomv1.ReviewAdjudication) (*roomv1.ReviewFinding, error) {
	return s.AppendReviewAdjudicationAudited(findingID, adjudication, nil)
}

func (s *Store) AppendReviewAdjudicationAudited(findingID string, adjudication *roomv1.ReviewAdjudication, audit *roomv1.AuditEvent) (*roomv1.ReviewFinding, error) {
	copyAdjudication := cloneReviewAdjudication(adjudication)
	if err := validateReviewAdjudication(copyAdjudication); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	finding, err := s.reviewFinding(findingID)
	if err != nil {
		return nil, err
	}
	if finding == nil {
		return nil, fmt.Errorf("review finding %q not found", findingID)
	}
	for _, existing := range finding.GetAdjudications() {
		if existing.GetId() != copyAdjudication.GetId() {
			continue
		}
		if copyAdjudication.GetOccurredAt() == nil {
			copyAdjudication.OccurredAt = existing.GetOccurredAt()
		}
		if proto.Equal(existing, copyAdjudication) {
			if err := s.commitIntelligenceMutation(audit, nil); err != nil {
				return nil, err
			}
			return cloneReviewFinding(finding), nil
		}
		return nil, errors.New("review adjudication id reused with different payload")
	}
	if copyAdjudication.GetOccurredAt() == nil {
		copyAdjudication.OccurredAt = timestamppb.Now()
	}
	finding.Adjudications = append(finding.Adjudications, copyAdjudication)
	finding.UpdatedAt = timestamppb.Now()
	if err := s.commitIntelligenceMutation(audit, func(tx *sql.Tx) error { return writeReviewFinding(tx, finding) }); err != nil {
		return nil, err
	}
	return cloneReviewFinding(finding), nil
}

func writeReviewFinding(executor auditExecutor, finding *roomv1.ReviewFinding) error {
	payload, digest, err := deterministicPayload(finding)
	if err != nil {
		return err
	}
	_, err = executor.Exec(`INSERT INTO review_findings(finding_id, repository, claim_kind, created_at, updated_at, payload, payload_sha256) VALUES(?,?,?,?,?,?,?) ON CONFLICT(finding_id) DO UPDATE SET repository=excluded.repository, claim_kind=excluded.claim_kind, created_at=excluded.created_at, updated_at=excluded.updated_at, payload=excluded.payload, payload_sha256=excluded.payload_sha256`, finding.GetId(), finding.GetSource().GetRepository(), int32(finding.GetClaimKind()), finding.GetCreatedAt().AsTime().UnixNano(), finding.GetUpdatedAt().AsTime().UnixNano(), payload, digest)
	return err
}

func (s *Store) UpsertPolicyCandidate(candidate *roomv1.PolicyCandidate) (*roomv1.PolicyCandidate, error) {
	return s.UpsertPolicyCandidateAudited(candidate, nil)
}

func (s *Store) UpsertPolicyCandidateAudited(candidate *roomv1.PolicyCandidate, audit *roomv1.AuditEvent) (*roomv1.PolicyCandidate, error) {
	copyCandidate := clonePolicyCandidate(candidate)
	if err := validatePolicyCandidate(copyCandidate); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, err := s.policyCandidate(copyCandidate.GetId())
	if err != nil {
		return nil, err
	}
	now := timestamppb.Now()
	if existing == nil {
		if copyCandidate.GetCreatedAt() == nil {
			copyCandidate.CreatedAt = now
		}
		if copyCandidate.GetUpdatedAt() == nil {
			copyCandidate.UpdatedAt = copyCandidate.GetCreatedAt()
		}
	} else {
		if copyCandidate.GetCreatedAt() == nil {
			copyCandidate.CreatedAt = existing.GetCreatedAt()
		}
		if copyCandidate.GetUpdatedAt() == nil {
			copyCandidate.UpdatedAt = existing.GetUpdatedAt()
			if !proto.Equal(copyCandidate, existing) {
				copyCandidate.UpdatedAt = now
			}
		}
	}
	if err := validatePolicyCandidate(copyCandidate); err != nil {
		return nil, err
	}
	payload, digest, err := deterministicPayload(copyCandidate)
	if err != nil {
		return nil, err
	}
	if err := s.commitIntelligenceMutation(audit, func(tx *sql.Tx) error {
		_, writeErr := tx.Exec(`INSERT INTO policy_candidates(candidate_id, rollout_stage, created_at, updated_at, payload, payload_sha256) VALUES(?,?,?,?,?,?) ON CONFLICT(candidate_id) DO UPDATE SET rollout_stage=excluded.rollout_stage, created_at=excluded.created_at, updated_at=excluded.updated_at, payload=excluded.payload, payload_sha256=excluded.payload_sha256`, copyCandidate.GetId(), int32(copyCandidate.GetRolloutStage()), copyCandidate.GetCreatedAt().AsTime().UnixNano(), copyCandidate.GetUpdatedAt().AsTime().UnixNano(), payload, digest)
		return writeErr
	}); err != nil {
		return nil, err
	}
	return clonePolicyCandidate(copyCandidate), nil
}

// UpsertPolicyCandidatesAudited persists an inferred candidate batch and its
// aligned audit records atomically.
func (s *Store) UpsertPolicyCandidatesAudited(candidates []*roomv1.PolicyCandidate, audits []*roomv1.AuditEvent) ([]*roomv1.PolicyCandidate, error) {
	if len(candidates) != len(audits) {
		return nil, errors.New("policy candidate and audit batch lengths must match")
	}
	if len(candidates) == 0 {
		return []*roomv1.PolicyCandidate{}, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	type preparedCandidate struct {
		candidate *roomv1.PolicyCandidate
		audit     *roomv1.AuditEvent
		payload   []byte
		digest    []byte
	}
	prepared := make([]preparedCandidate, 0, len(candidates))
	seenCandidateIDs := make(map[string]struct{}, len(candidates))
	for i, candidate := range candidates {
		copyCandidate := clonePolicyCandidate(candidate)
		if err := validatePolicyCandidate(copyCandidate); err != nil {
			return nil, fmt.Errorf("policy candidate batch item %d: %w", i, err)
		}
		if _, duplicate := seenCandidateIDs[copyCandidate.GetId()]; duplicate {
			return nil, fmt.Errorf("policy candidate batch contains duplicate id %q", copyCandidate.GetId())
		}
		seenCandidateIDs[copyCandidate.GetId()] = struct{}{}
		existing, err := s.policyCandidate(copyCandidate.GetId())
		if err != nil {
			return nil, err
		}
		now := timestamppb.Now()
		if existing == nil {
			if copyCandidate.GetCreatedAt() == nil {
				copyCandidate.CreatedAt = now
			}
			if copyCandidate.GetUpdatedAt() == nil {
				copyCandidate.UpdatedAt = copyCandidate.GetCreatedAt()
			}
		} else {
			if copyCandidate.GetCreatedAt() == nil {
				copyCandidate.CreatedAt = existing.GetCreatedAt()
			}
			if copyCandidate.GetUpdatedAt() == nil {
				copyCandidate.UpdatedAt = existing.GetUpdatedAt()
				if !proto.Equal(copyCandidate, existing) {
					copyCandidate.UpdatedAt = now
				}
			}
		}
		if err := validatePolicyCandidate(copyCandidate); err != nil {
			return nil, fmt.Errorf("policy candidate batch item %d: %w", i, err)
		}
		if audits[i] == nil {
			return nil, fmt.Errorf("policy candidate batch audit %d is required", i)
		}
		copyAudit := proto.Clone(audits[i]).(*roomv1.AuditEvent)
		if copyAudit.GetPolicyCandidateId() == "" {
			copyAudit.PolicyCandidateId = copyCandidate.GetId()
		} else if copyAudit.GetPolicyCandidateId() != copyCandidate.GetId() {
			return nil, fmt.Errorf("policy candidate batch audit %d does not match candidate", i)
		}
		payload, digest, err := deterministicPayload(copyCandidate)
		if err != nil {
			return nil, err
		}
		prepared = append(prepared, preparedCandidate{candidate: copyCandidate, audit: copyAudit, payload: payload, digest: digest})
	}

	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	for _, item := range prepared {
		if _, err := tx.Exec(`INSERT INTO policy_candidates(candidate_id, rollout_stage, created_at, updated_at, payload, payload_sha256) VALUES(?,?,?,?,?,?) ON CONFLICT(candidate_id) DO UPDATE SET rollout_stage=excluded.rollout_stage, created_at=excluded.created_at, updated_at=excluded.updated_at, payload=excluded.payload, payload_sha256=excluded.payload_sha256`, item.candidate.GetId(), int32(item.candidate.GetRolloutStage()), item.candidate.GetCreatedAt().AsTime().UnixNano(), item.candidate.GetUpdatedAt().AsTime().UnixNano(), item.payload, item.digest); err != nil {
			return nil, err
		}
		if _, err := appendAudit(tx, item.audit); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	stored := make([]*roomv1.PolicyCandidate, 0, len(prepared))
	for _, item := range prepared {
		stored = append(stored, clonePolicyCandidate(item.candidate))
	}
	return stored, nil
}

// ApplyPolicyCandidate atomically applies a candidate transition to both the
// intelligence records and the executable ruleset state.
func (s *Store) ApplyPolicyCandidate(candidate *roomv1.PolicyCandidate, expectedUpdatedAt *timestamppb.Timestamp, decision *roomv1.TuningDecision, audit *roomv1.AuditEvent) (*roomv1.PolicyCandidate, *roomv1.RulesetVersion, error) {
	copyCandidate := clonePolicyCandidate(candidate)
	copyDecision := cloneTuningDecision(decision)
	var copyAudit *roomv1.AuditEvent
	if audit != nil {
		copyAudit = proto.Clone(audit).(*roomv1.AuditEvent)
	}
	if copyCandidate == nil || strings.TrimSpace(copyCandidate.GetId()) == "" {
		return nil, nil, errors.New("policy candidate id is required")
	}
	if expectedUpdatedAt == nil {
		return nil, nil, fmt.Errorf("%w: expected updated_at is required", ErrPolicyCandidateConflict)
	}
	if err := expectedUpdatedAt.CheckValid(); err != nil {
		return nil, nil, fmt.Errorf("%w: expected updated_at is invalid: %v", ErrPolicyCandidateConflict, err)
	}
	if copyAudit == nil {
		return nil, nil, errors.New("audit event is required")
	}
	if copyAudit.GetPolicyCandidateId() == "" {
		copyAudit.PolicyCandidateId = copyCandidate.GetId()
	} else if copyAudit.GetPolicyCandidateId() != copyCandidate.GetId() {
		return nil, nil, errors.New("audit policy_candidate_id does not match candidate")
	}
	if copyDecision != nil && copyDecision.GetPolicyCandidateId() != copyCandidate.GetId() {
		return nil, nil, errors.New("tuning decision policy_candidate_id does not match candidate")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	existing, err := s.policyCandidate(copyCandidate.GetId())
	if err != nil {
		return nil, nil, err
	}
	if existing == nil || !proto.Equal(existing.GetUpdatedAt(), expectedUpdatedAt) {
		return nil, nil, fmt.Errorf("%w: candidate %q has changed", ErrPolicyCandidateConflict, copyCandidate.GetId())
	}
	copyCandidate.CreatedAt = existing.GetCreatedAt()
	if copyCandidate.GetUpdatedAt() == nil || !copyCandidate.GetUpdatedAt().AsTime().After(existing.GetUpdatedAt().AsTime()) {
		now := timestamppb.Now()
		if !now.AsTime().After(existing.GetUpdatedAt().AsTime()) {
			now = timestamppb.New(existing.GetUpdatedAt().AsTime().Add(time.Nanosecond))
		}
		copyCandidate.UpdatedAt = now
	}
	if err := validatePolicyCandidate(copyCandidate); err != nil {
		return nil, nil, err
	}
	if copyDecision != nil {
		if copyDecision.GetOccurredAt() == nil {
			copyDecision.OccurredAt = timestamppb.Now()
		}
		if err := validateTuningDecision(copyDecision); err != nil {
			return nil, nil, err
		}
	}

	nextSnapshot := proto.Clone(s.snapshot).(*roomv1.StoreSnapshot)
	materialized := materializeCandidateRule(copyCandidate, nextSnapshot.GetDraftRules())
	upsertDraftRule(nextSnapshot, materialized)
	shouldPublish := candidateRequiresPublish(existing, copyCandidate)
	var published *roomv1.RulesetVersion
	if shouldPublish {
		published, err = publishCandidateSnapshot(nextSnapshot, copyCandidate)
		if err != nil {
			return nil, nil, err
		}
		copyAudit.RulesetId = published.GetId()
		copyAudit.RulesetVersion = published.GetVersion()
		copyAudit.RulesetHash = published.GetHash()
	}

	candidatePayload, candidateDigest, err := deterministicPayload(copyCandidate)
	if err != nil {
		return nil, nil, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`UPDATE policy_candidates SET rollout_stage=?, created_at=?, updated_at=?, payload=?, payload_sha256=? WHERE candidate_id=? AND updated_at=?`, int32(copyCandidate.GetRolloutStage()), copyCandidate.GetCreatedAt().AsTime().UnixNano(), copyCandidate.GetUpdatedAt().AsTime().UnixNano(), candidatePayload, candidateDigest, copyCandidate.GetId(), expectedUpdatedAt.AsTime().UnixNano())
	if err != nil {
		return nil, nil, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return nil, nil, err
	}
	if rows != 1 {
		return nil, nil, fmt.Errorf("%w: candidate %q has changed", ErrPolicyCandidateConflict, copyCandidate.GetId())
	}
	if existing.GetRolloutStage() == roomv1.RolloutStage_ROLLOUT_STAGE_DRAFT && activeRolloutStage(copyCandidate.GetRolloutStage()) {
		if err := supersedePolicyCandidateRevisionsTx(tx, copyCandidate); err != nil {
			return nil, nil, err
		}
	}
	if copyDecision != nil {
		if err := saveTuningDecisionTx(tx, copyDecision); err != nil {
			return nil, nil, err
		}
	}
	versions := []*roomv1.RulesetVersion(nil)
	if published != nil {
		versions = []*roomv1.RulesetVersion{published}
	}
	if err := persistSnapshotTx(tx, nextSnapshot, versions, copyAudit); err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, err
	}
	s.snapshot = nextSnapshot
	return clonePolicyCandidate(copyCandidate), cloneRuleset(published), nil
}

func (s *Store) PolicyCandidate(id string) (*roomv1.PolicyCandidate, error) {
	if strings.TrimSpace(id) == "" {
		return nil, errors.New("policy candidate id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	candidate, err := s.policyCandidate(id)
	return clonePolicyCandidate(candidate), err
}

func (s *Store) policyCandidate(id string) (*roomv1.PolicyCandidate, error) {
	var indexedID string
	var rolloutStage int32
	var payload, digest []byte
	if err := s.db.QueryRow(`SELECT candidate_id, rollout_stage, payload, payload_sha256 FROM policy_candidates WHERE candidate_id = ?`, id).Scan(&indexedID, &rolloutStage, &payload, &digest); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if err := verifyPayloadDigest(payload, digest, "policy candidate"); err != nil {
		return nil, err
	}
	candidate := &roomv1.PolicyCandidate{}
	if err := proto.Unmarshal(payload, candidate); err != nil {
		return nil, fmt.Errorf("decode policy candidate: %w", err)
	}
	if candidate.GetId() != indexedID || int32(candidate.GetRolloutStage()) != rolloutStage {
		return nil, errors.New("policy candidate indexed identity does not match payload")
	}
	return candidate, nil
}

func (s *Store) ListPolicyCandidates(stage roomv1.RolloutStage) ([]*roomv1.PolicyCandidate, error) {
	query := `SELECT candidate_id, rollout_stage, payload, payload_sha256 FROM policy_candidates`
	args := []any{}
	if stage != roomv1.RolloutStage_ROLLOUT_STAGE_UNSPECIFIED {
		if !validRolloutStage(stage) {
			return nil, errors.New("invalid rollout stage")
		}
		query += ` WHERE rollout_stage = ?`
		args = append(args, int32(stage))
	}
	query += ` ORDER BY updated_at DESC, candidate_id DESC`
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	candidates := make([]*roomv1.PolicyCandidate, 0)
	for rows.Next() {
		candidate := &roomv1.PolicyCandidate{}
		var indexedID string
		var indexedStage int32
		var payload, digest []byte
		if err := rows.Scan(&indexedID, &indexedStage, &payload, &digest); err != nil {
			return nil, err
		}
		if err := verifyPayloadDigest(payload, digest, "policy candidate"); err != nil {
			return nil, err
		}
		if err := proto.Unmarshal(payload, candidate); err != nil {
			return nil, fmt.Errorf("decode policy candidate: %w", err)
		}
		if candidate.GetId() != indexedID || int32(candidate.GetRolloutStage()) != indexedStage {
			return nil, errors.New("policy candidate indexed identity does not match payload")
		}
		candidates = append(candidates, candidate)
	}
	return candidates, rows.Err()
}

func (s *Store) SavePolicyReplayRun(replay *roomv1.PolicyReplayRun) (*roomv1.PolicyReplayRun, error) {
	return s.SavePolicyReplayRunAudited(replay, nil)
}

func (s *Store) SavePolicyReplayRunAudited(replay *roomv1.PolicyReplayRun, audit *roomv1.AuditEvent) (*roomv1.PolicyReplayRun, error) {
	copyReplay := clonePolicyReplayRun(replay)
	if err := validatePolicyReplayRun(copyReplay); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var indexedID, indexedCandidateID string
	var existingPayload, existingDigest []byte
	err := s.db.QueryRow(`SELECT replay_id, policy_candidate_id, payload, payload_sha256 FROM policy_replay_runs WHERE replay_id = ?`, copyReplay.GetId()).Scan(&indexedID, &indexedCandidateID, &existingPayload, &existingDigest)
	if err == nil {
		if err := verifyPayloadDigest(existingPayload, existingDigest, "policy replay"); err != nil {
			return nil, err
		}
		existing := &roomv1.PolicyReplayRun{}
		if err := proto.Unmarshal(existingPayload, existing); err != nil {
			return nil, fmt.Errorf("decode policy replay: %w", err)
		}
		if existing.GetId() != indexedID || existing.GetPolicyCandidateId() != indexedCandidateID {
			return nil, errors.New("policy replay indexed identity does not match payload")
		}
		if copyReplay.GetStartedAt() == nil {
			copyReplay.StartedAt = existing.GetStartedAt()
		}
		if copyReplay.GetCompletedAt() == nil {
			copyReplay.CompletedAt = existing.GetCompletedAt()
		}
		payload, digest, marshalErr := deterministicPayload(copyReplay)
		if marshalErr != nil {
			return nil, marshalErr
		}
		if bytes.Equal(existingPayload, payload) && bytes.Equal(existingDigest, digest) {
			if err := s.commitIntelligenceMutation(audit, nil); err != nil {
				return nil, err
			}
			return clonePolicyReplayRun(copyReplay), nil
		}
		return nil, errors.New("policy replay id reused with different payload")
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	now := timestamppb.Now()
	if copyReplay.GetStartedAt() == nil {
		copyReplay.StartedAt = now
	}
	if copyReplay.GetCompletedAt() == nil {
		copyReplay.CompletedAt = now
	}
	if err := validatePolicyReplayRun(copyReplay); err != nil {
		return nil, err
	}
	payload, digest, err := deterministicPayload(copyReplay)
	if err != nil {
		return nil, err
	}
	if err := s.commitIntelligenceMutation(audit, func(tx *sql.Tx) error {
		_, writeErr := tx.Exec(`INSERT INTO policy_replay_runs(replay_id, policy_candidate_id, started_at, completed_at, payload, payload_sha256) VALUES(?,?,?,?,?,?)`, copyReplay.GetId(), copyReplay.GetPolicyCandidateId(), copyReplay.GetStartedAt().AsTime().UnixNano(), copyReplay.GetCompletedAt().AsTime().UnixNano(), payload, digest)
		return writeErr
	}); err != nil {
		return nil, err
	}
	return clonePolicyReplayRun(copyReplay), nil
}

func (s *Store) SavePolicyReplay(replay *roomv1.PolicyReplayRun) error {
	return s.SavePolicyReplayAudited(replay, nil)

}

func (s *Store) SavePolicyReplayAudited(replay *roomv1.PolicyReplayRun, audit *roomv1.AuditEvent) error {
	_, err := s.SavePolicyReplayRunAudited(replay, audit)
	return err
}

func (s *Store) ListPolicyReplayRuns(candidateID string, limit int32) ([]*roomv1.PolicyReplayRun, error) {
	return listIntelligenceRecords(s.db, `policy_replay_runs`, `policy_candidate_id`, candidateID, `completed_at`, `replay_id`, limit, "policy replay", func(payload []byte) (*roomv1.PolicyReplayRun, error) {
		value := &roomv1.PolicyReplayRun{}
		return value, proto.Unmarshal(payload, value)
	}, func(value *roomv1.PolicyReplayRun) (string, string) {
		return value.GetId(), value.GetPolicyCandidateId()
	})
}

func (s *Store) ListPolicyReplays(candidateID string, limit int32) ([]*roomv1.PolicyReplayRun, error) {
	return s.ListPolicyReplayRuns(candidateID, limit)
}

func (s *Store) SaveTuningDecision(decision *roomv1.TuningDecision) error {
	copyDecision := cloneTuningDecision(decision)
	if err := validateTuningDecision(copyDecision); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var indexedID, indexedCandidateID string
	var existingPayload, existingDigest []byte
	err := s.db.QueryRow(`SELECT decision_id, policy_candidate_id, payload, payload_sha256 FROM tuning_decisions WHERE decision_id = ?`, copyDecision.GetId()).Scan(&indexedID, &indexedCandidateID, &existingPayload, &existingDigest)
	if err == nil {
		if err := verifyPayloadDigest(existingPayload, existingDigest, "tuning decision"); err != nil {
			return err
		}
		existing := &roomv1.TuningDecision{}
		if err := proto.Unmarshal(existingPayload, existing); err != nil {
			return fmt.Errorf("decode tuning decision: %w", err)
		}
		if existing.GetId() != indexedID || existing.GetPolicyCandidateId() != indexedCandidateID {
			return errors.New("tuning decision indexed identity does not match payload")
		}
		if copyDecision.GetOccurredAt() == nil {
			copyDecision.OccurredAt = existing.GetOccurredAt()
		}
		payload, digest, marshalErr := deterministicPayload(copyDecision)
		if marshalErr != nil {
			return marshalErr
		}
		if bytes.Equal(existingPayload, payload) && bytes.Equal(existingDigest, digest) {
			return nil
		}
		return errors.New("tuning decision id reused with different payload")
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if copyDecision.GetOccurredAt() == nil {
		copyDecision.OccurredAt = timestamppb.Now()
	}
	if err := validateTuningDecision(copyDecision); err != nil {
		return err
	}
	payload, digest, err := deterministicPayload(copyDecision)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO tuning_decisions(decision_id, policy_candidate_id, occurred_at, payload, payload_sha256) VALUES(?,?,?,?,?)`, copyDecision.GetId(), copyDecision.GetPolicyCandidateId(), copyDecision.GetOccurredAt().AsTime().UnixNano(), payload, digest)
	if err != nil {
		return err
	}
	return nil
}

func (s *Store) ListTuningDecisions(candidateID string, limit int32) ([]*roomv1.TuningDecision, error) {
	return listIntelligenceRecords(s.db, `tuning_decisions`, `policy_candidate_id`, candidateID, `occurred_at`, `decision_id`, limit, "tuning decision", func(payload []byte) (*roomv1.TuningDecision, error) {
		value := &roomv1.TuningDecision{}
		return value, proto.Unmarshal(payload, value)
	}, func(value *roomv1.TuningDecision) (string, string) {
		return value.GetId(), value.GetPolicyCandidateId()
	})
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
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := persistSnapshotTx(tx, snapshot, versions, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func persistSnapshotTx(tx *sql.Tx, snapshot *roomv1.StoreSnapshot, versions []*roomv1.RulesetVersion, audit *roomv1.AuditEvent) error {
	state := proto.Clone(snapshot).(*roomv1.StoreSnapshot)
	state.Versions = nil
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(state)
	if err != nil {
		return err
	}
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
	return nil
}

func materializeCandidateRule(candidate *roomv1.PolicyCandidate, draft []*roomv1.Rule) *roomv1.Rule {
	rule := cloneRule(candidate.GetProposedRule())
	rule.RolloutStage = candidate.GetRolloutStage()
	rule.Enabled = activeRolloutStage(candidate.GetRolloutStage())
	for _, trigger := range rule.GetTriggers() {
		trigger.MinimumConfidenceBasisPoints = candidate.GetMinimumConfidenceBasisPoints()
	}
	for _, existing := range draft {
		if existing.GetId() == rule.GetId() {
			rule.CreatedAt = existing.GetCreatedAt()
			break
		}
	}
	if rule.GetCreatedAt() == nil {
		rule.CreatedAt = candidate.GetCreatedAt()
	}
	rule.UpdatedAt = candidate.GetUpdatedAt()
	return rule
}

func upsertDraftRule(snapshot *roomv1.StoreSnapshot, rule *roomv1.Rule) {
	for i, existing := range snapshot.GetDraftRules() {
		if existing.GetId() == rule.GetId() {
			snapshot.DraftRules[i] = rule
			sortRules(snapshot.DraftRules)
			return
		}
	}
	snapshot.DraftRules = append(snapshot.DraftRules, rule)
	sortRules(snapshot.DraftRules)
}

func activeRolloutStage(stage roomv1.RolloutStage) bool {
	return stage == roomv1.RolloutStage_ROLLOUT_STAGE_SHADOW || stage == roomv1.RolloutStage_ROLLOUT_STAGE_WARN || stage == roomv1.RolloutStage_ROLLOUT_STAGE_BLOCK
}

func candidateRequiresPublish(existing, candidate *roomv1.PolicyCandidate) bool {
	oldActive := activeRolloutStage(existing.GetRolloutStage())
	newActive := activeRolloutStage(candidate.GetRolloutStage())
	if oldActive != newActive {
		return true
	}
	if !oldActive {
		return false
	}
	if existing.GetRolloutStage() != candidate.GetRolloutStage() || existing.GetMinimumConfidenceBasisPoints() != candidate.GetMinimumConfidenceBasisPoints() {
		return true
	}
	oldRule := cloneRule(existing.GetProposedRule())
	newRule := cloneRule(candidate.GetProposedRule())
	oldRule.RolloutStage, newRule.RolloutStage = candidate.GetRolloutStage(), candidate.GetRolloutStage()
	oldRule.Enabled, newRule.Enabled = true, true
	oldRule.CreatedAt, oldRule.UpdatedAt = nil, nil
	newRule.CreatedAt, newRule.UpdatedAt = nil, nil
	return !proto.Equal(oldRule, newRule)
}

func publishCandidateSnapshot(snapshot *roomv1.StoreSnapshot, candidate *roomv1.PolicyCandidate) (*roomv1.RulesetVersion, error) {
	for _, rule := range snapshot.GetDraftRules() {
		if err := validateRule(rule); err != nil {
			return nil, fmt.Errorf("publish rule %q: %w", rule.GetId(), err)
		}
	}
	version := snapshot.GetNextVersion()
	if version <= 0 {
		version = 1
	}
	rules := cloneRules(snapshot.GetDraftRules())
	sortRules(rules)
	ruleset := &roomv1.RulesetVersion{
		Id:          fmt.Sprintf("ruleset-%d", version),
		Version:     version,
		Status:      roomv1.RulesetStatus_RULESET_STATUS_ACTIVE,
		Rules:       rules,
		Author:      candidate.GetCreatedBy(),
		Notes:       fmt.Sprintf("Apply policy candidate %s at %s", candidate.GetId(), candidate.GetRolloutStage().String()),
		PublishedAt: timestamppb.Now(),
		McpPolicy:   cloneMCPPolicy(snapshot.GetDraftMcpPolicy()),
	}
	ruleset.Hash = rulesetHash(ruleset)
	for _, prior := range snapshot.GetVersions() {
		if prior.GetStatus() == roomv1.RulesetStatus_RULESET_STATUS_ACTIVE {
			prior.Status = roomv1.RulesetStatus_RULESET_STATUS_ARCHIVED
		}
	}
	snapshot.Versions = append(snapshot.Versions, ruleset)
	snapshot.ActiveVersion = version
	snapshot.NextVersion = version + 1
	return ruleset, nil
}

func saveTuningDecisionTx(tx *sql.Tx, decision *roomv1.TuningDecision) error {
	payload, digest, err := deterministicPayload(decision)
	if err != nil {
		return err
	}
	result, err := tx.Exec(`INSERT INTO tuning_decisions(decision_id, policy_candidate_id, occurred_at, payload, payload_sha256) VALUES(?,?,?,?,?) ON CONFLICT(decision_id) DO NOTHING`, decision.GetId(), decision.GetPolicyCandidateId(), decision.GetOccurredAt().AsTime().UnixNano(), payload, digest)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 1 {
		return nil
	}
	var indexedID, indexedCandidateID string
	var existingPayload, existingDigest []byte
	if err := tx.QueryRow(`SELECT decision_id, policy_candidate_id, payload, payload_sha256 FROM tuning_decisions WHERE decision_id = ?`, decision.GetId()).Scan(&indexedID, &indexedCandidateID, &existingPayload, &existingDigest); err != nil {
		return err
	}
	if err := verifyPayloadDigest(existingPayload, existingDigest, "tuning decision"); err != nil {
		return err
	}
	if indexedID != decision.GetId() || indexedCandidateID != decision.GetPolicyCandidateId() || !bytes.Equal(existingPayload, payload) || !bytes.Equal(existingDigest, digest) {
		return errors.New("tuning decision id reused with different payload")
	}
	return nil
}

func supersedePolicyCandidateRevisionsTx(tx *sql.Tx, replacement *roomv1.PolicyCandidate) error {
	ruleID := strings.TrimSpace(replacement.GetProposedRule().GetId())
	if ruleID == "" {
		return errors.New("replacement candidate proposed rule id is required")
	}
	rows, err := tx.Query(`SELECT candidate_id, rollout_stage, updated_at, payload, payload_sha256 FROM policy_candidates WHERE candidate_id <> ?`, replacement.GetId())
	if err != nil {
		return err
	}
	type revision struct {
		candidate *roomv1.PolicyCandidate
		updatedAt int64
	}
	revisions := make([]revision, 0)
	for rows.Next() {
		var indexedID string
		var indexedStage int32
		var updatedAt int64
		var payload, digest []byte
		if err := rows.Scan(&indexedID, &indexedStage, &updatedAt, &payload, &digest); err != nil {
			rows.Close()
			return err
		}
		if err := verifyPayloadDigest(payload, digest, "policy candidate"); err != nil {
			rows.Close()
			return err
		}
		candidate := &roomv1.PolicyCandidate{}
		if err := proto.Unmarshal(payload, candidate); err != nil {
			rows.Close()
			return fmt.Errorf("decode policy candidate: %w", err)
		}
		if candidate.GetId() != indexedID || int32(candidate.GetRolloutStage()) != indexedStage {
			rows.Close()
			return errors.New("policy candidate indexed identity does not match payload")
		}
		if activeRolloutStage(candidate.GetRolloutStage()) && candidate.GetProposedRule().GetId() == ruleID {
			revisions = append(revisions, revision{candidate: candidate, updatedAt: updatedAt})
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, prior := range revisions {
		prior.candidate.RolloutStage = roomv1.RolloutStage_ROLLOUT_STAGE_ROLLED_BACK
		updatedAt := replacement.GetUpdatedAt().AsTime()
		if !updatedAt.After(prior.candidate.GetUpdatedAt().AsTime()) {
			updatedAt = prior.candidate.GetUpdatedAt().AsTime().Add(time.Nanosecond)
		}
		prior.candidate.UpdatedAt = timestamppb.New(updatedAt)
		payload, digest, err := deterministicPayload(prior.candidate)
		if err != nil {
			return err
		}
		result, err := tx.Exec(`UPDATE policy_candidates SET rollout_stage=?, updated_at=?, payload=?, payload_sha256=? WHERE candidate_id=? AND updated_at=?`, int32(prior.candidate.GetRolloutStage()), prior.candidate.GetUpdatedAt().AsTime().UnixNano(), payload, digest, prior.candidate.GetId(), prior.updatedAt)
		if err != nil {
			return err
		}
		changed, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if changed != 1 {
			return fmt.Errorf("%w: superseded candidate %q has changed", ErrPolicyCandidateConflict, prior.candidate.GetId())
		}
	}
	return nil
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

func deterministicPayload(message proto.Message) ([]byte, []byte, error) {
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		return nil, nil, err
	}
	digest := sha256.Sum256(payload)
	return payload, digest[:], nil
}

func verifyPayloadDigest(payload, expected []byte, recordType string) error {
	actual := sha256.Sum256(payload)
	if len(expected) != sha256.Size || !bytes.Equal(actual[:], expected) {
		return fmt.Errorf("%s payload digest mismatch", recordType)
	}
	return nil
}

func listIntelligenceRecords[T any](db *sql.DB, table, filterColumn, filterValue, timeColumn, idColumn string, limit int32, recordType string, decode func([]byte) (*T, error), indexedIdentity func(*T) (string, string)) ([]*T, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query := `SELECT ` + idColumn + `, ` + filterColumn + `, payload, payload_sha256 FROM ` + table
	args := make([]any, 0, 2)
	if strings.TrimSpace(filterValue) != "" {
		query += ` WHERE ` + filterColumn + ` = ?`
		args = append(args, filterValue)
	}
	query += ` ORDER BY ` + timeColumn + ` DESC, ` + idColumn + ` DESC LIMIT ?`
	args = append(args, limit)
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]*T, 0)
	for rows.Next() {
		var indexedID, indexedFilter string
		var payload, digest []byte
		if err := rows.Scan(&indexedID, &indexedFilter, &payload, &digest); err != nil {
			return nil, err
		}
		if err := verifyPayloadDigest(payload, digest, recordType); err != nil {
			return nil, err
		}
		value, err := decode(payload)
		if err != nil {
			return nil, fmt.Errorf("decode %s: %w", recordType, err)
		}
		payloadID, payloadFilter := indexedIdentity(value)
		if payloadID != indexedID || payloadFilter != indexedFilter {
			return nil, fmt.Errorf("%s indexed identity does not match payload", recordType)
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func validateReviewFinding(finding *roomv1.ReviewFinding) error {
	if finding == nil || strings.TrimSpace(finding.GetId()) == "" {
		return errors.New("review finding id is required")
	}
	if finding.GetSource() == nil || strings.TrimSpace(finding.GetSource().GetRepository()) == "" {
		return errors.New("review finding source repository is required")
	}
	if !validReviewClaimKind(finding.GetClaimKind()) {
		return errors.New("review finding claim kind is required")
	}
	if _, ok := roomv1.Severity_name[int32(finding.GetSeverity())]; !ok || finding.GetSeverity() == roomv1.Severity_SEVERITY_UNSPECIFIED {
		return errors.New("review finding severity is required")
	}
	if finding.GetConfidenceBasisPoints() > 10000 {
		return errors.New("review finding confidence must be at most 10000 basis points")
	}
	if finding.GetReviewerCostMicros() < 0 || finding.GetReviewerInputTokens() < 0 || finding.GetReviewerOutputTokens() < 0 {
		return errors.New("reviewer cost and token counts must be non-negative")
	}
	if err := validateTimestamp(finding.GetCreatedAt(), "review finding created_at"); err != nil {
		return err
	}
	if err := validateTimestamp(finding.GetUpdatedAt(), "review finding updated_at"); err != nil {
		return err
	}
	if finding.GetCreatedAt() != nil && finding.GetUpdatedAt() != nil && finding.GetUpdatedAt().AsTime().Before(finding.GetCreatedAt().AsTime()) {
		return errors.New("review finding updated_at cannot precede created_at")
	}
	seenOutcomes := make(map[string]*roomv1.ReviewOutcome, len(finding.GetOutcomes()))
	for _, outcome := range finding.GetOutcomes() {
		if err := validateReviewOutcome(outcome); err != nil {
			return err
		}
		if previous := seenOutcomes[outcome.GetId()]; previous != nil && !proto.Equal(previous, outcome) {
			return errors.New("review outcome id reused with different payload")
		}
		if previous := seenOutcomes[outcome.GetId()]; previous != nil {
			return errors.New("duplicate review outcome id")
		}
		seenOutcomes[outcome.GetId()] = outcome
	}
	seenAdjudications := make(map[string]*roomv1.ReviewAdjudication, len(finding.GetAdjudications()))
	for _, adjudication := range finding.GetAdjudications() {
		if err := validateReviewAdjudication(adjudication); err != nil {
			return err
		}
		if previous := seenAdjudications[adjudication.GetId()]; previous != nil && !proto.Equal(previous, adjudication) {
			return errors.New("review adjudication id reused with different payload")
		}
		if previous := seenAdjudications[adjudication.GetId()]; previous != nil {
			return errors.New("duplicate review adjudication id")
		}
		seenAdjudications[adjudication.GetId()] = adjudication
	}
	return nil
}

func validateReviewOutcome(outcome *roomv1.ReviewOutcome) error {
	if outcome == nil || strings.TrimSpace(outcome.GetId()) == "" {
		return errors.New("review outcome id is required")
	}
	if _, ok := roomv1.ReviewOutcomeKind_name[int32(outcome.GetKind())]; !ok || outcome.GetKind() == roomv1.ReviewOutcomeKind_REVIEW_OUTCOME_KIND_UNSPECIFIED {
		return errors.New("review outcome kind is required")
	}
	if outcome.GetWeightBasisPoints() < 0 || outcome.GetWeightBasisPoints() > 10000 {
		return errors.New("review outcome weight must be between 0 and 10000 basis points")
	}
	return validateTimestamp(outcome.GetOccurredAt(), "review outcome occurred_at")
}

func validateReviewAdjudication(adjudication *roomv1.ReviewAdjudication) error {
	if adjudication == nil || strings.TrimSpace(adjudication.GetId()) == "" {
		return errors.New("review adjudication id is required")
	}
	if _, ok := roomv1.AdjudicationVerdict_name[int32(adjudication.GetVerdict())]; !ok || adjudication.GetVerdict() == roomv1.AdjudicationVerdict_ADJUDICATION_VERDICT_UNSPECIFIED {
		return errors.New("review adjudication verdict is required")
	}
	if strings.TrimSpace(adjudication.GetAgentId()) == "" || strings.TrimSpace(adjudication.GetModelId()) == "" {
		return errors.New("review adjudication agent_id and model_id are required")
	}
	if adjudication.GetConfidenceBasisPoints() > 10000 {
		return errors.New("review adjudication confidence must be at most 10000 basis points")
	}
	if len(adjudication.GetInputSha256()) != 0 && len(adjudication.GetInputSha256()) != sha256.Size {
		return errors.New("review adjudication input_sha256 must be 32 bytes")
	}
	return validateTimestamp(adjudication.GetOccurredAt(), "review adjudication occurred_at")
}

func validatePolicyCandidate(candidate *roomv1.PolicyCandidate) error {
	if candidate == nil || strings.TrimSpace(candidate.GetId()) == "" {
		return errors.New("policy candidate id is required")
	}
	if !validReviewClaimKind(candidate.GetClaimKind()) {
		return errors.New("policy candidate claim kind is required")
	}
	if _, ok := roomv1.PolicyArtifactKind_name[int32(candidate.GetArtifactKind())]; !ok || candidate.GetArtifactKind() == roomv1.PolicyArtifactKind_POLICY_ARTIFACT_KIND_UNSPECIFIED {
		return errors.New("policy candidate artifact kind is required")
	}
	if !validRolloutStage(candidate.GetRolloutStage()) {
		return errors.New("policy candidate rollout stage is required")
	}
	if err := validateRule(candidate.GetProposedRule()); err != nil {
		return fmt.Errorf("policy candidate proposed rule: %w", err)
	}
	if candidate.GetMinimumConfidenceBasisPoints() > 10000 {
		return errors.New("policy candidate confidence must be at most 10000 basis points")
	}
	if err := validatePolicyMetrics(candidate.GetMetrics()); err != nil {
		return err
	}
	if err := validateTimestamp(candidate.GetCreatedAt(), "policy candidate created_at"); err != nil {
		return err
	}
	if err := validateTimestamp(candidate.GetUpdatedAt(), "policy candidate updated_at"); err != nil {
		return err
	}
	if candidate.GetCreatedAt() != nil && candidate.GetUpdatedAt() != nil && candidate.GetUpdatedAt().AsTime().Before(candidate.GetCreatedAt().AsTime()) {
		return errors.New("policy candidate updated_at cannot precede created_at")
	}
	return nil
}

func validatePolicyReplayRun(replay *roomv1.PolicyReplayRun) error {
	if replay == nil || strings.TrimSpace(replay.GetId()) == "" || strings.TrimSpace(replay.GetPolicyCandidateId()) == "" {
		return errors.New("policy replay id and policy_candidate_id are required")
	}
	for _, replayCase := range replay.GetCases() {
		if replayCase == nil || strings.TrimSpace(replayCase.GetFindingId()) == "" {
			return errors.New("policy replay cases require finding_id")
		}
		if replayCase.GetConfidenceBasisPoints() > 10000 {
			return errors.New("policy replay confidence must be at most 10000 basis points")
		}
	}
	if err := validatePolicyMetrics(replay.GetMetrics()); err != nil {
		return err
	}
	if err := validateTimestamp(replay.GetStartedAt(), "policy replay started_at"); err != nil {
		return err
	}
	if err := validateTimestamp(replay.GetCompletedAt(), "policy replay completed_at"); err != nil {
		return err
	}
	if replay.GetStartedAt() != nil && replay.GetCompletedAt() != nil && replay.GetCompletedAt().AsTime().Before(replay.GetStartedAt().AsTime()) {
		return errors.New("policy replay completed_at cannot precede started_at")
	}
	return nil
}

func validateTuningDecision(decision *roomv1.TuningDecision) error {
	if decision == nil || strings.TrimSpace(decision.GetId()) == "" || strings.TrimSpace(decision.GetPolicyCandidateId()) == "" {
		return errors.New("tuning decision id and policy_candidate_id are required")
	}
	if _, ok := roomv1.TuningActionKind_name[int32(decision.GetAction())]; !ok || decision.GetAction() == roomv1.TuningActionKind_TUNING_ACTION_KIND_UNSPECIFIED {
		return errors.New("tuning decision action is required")
	}
	if decision.GetPreviousConfidenceBasisPoints() > 10000 || decision.GetNewConfidenceBasisPoints() > 10000 {
		return errors.New("tuning decision confidence must be at most 10000 basis points")
	}
	if strings.TrimSpace(decision.GetActorId()) == "" {
		return errors.New("tuning decision actor_id is required")
	}
	return validateTimestamp(decision.GetOccurredAt(), "tuning decision occurred_at")
}

func validatePolicyMetrics(metrics *roomv1.PolicyMetrics) error {
	if metrics == nil {
		return nil
	}
	if metrics.GetPrecisionBasisPoints() > 10000 || metrics.GetRecallBasisPoints() > 10000 {
		return errors.New("policy metric rates must be at most 10000 basis points")
	}
	if metrics.GetEstimatedReviewerCostAvoidedMicros() < 0 || metrics.GetEstimatedReviewerTokensAvoided() < 0 {
		return errors.New("estimated reviewer savings must be non-negative")
	}
	return nil
}

func validateTimestamp(value *timestamppb.Timestamp, name string) error {
	if value == nil {
		return nil
	}
	if err := value.CheckValid(); err != nil {
		return fmt.Errorf("%s is invalid: %w", name, err)
	}
	return nil
}

func validReviewClaimKind(value roomv1.ReviewClaimKind) bool {
	_, ok := roomv1.ReviewClaimKind_name[int32(value)]
	return ok && value != roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_UNSPECIFIED
}

func validRolloutStage(value roomv1.RolloutStage) bool {
	_, ok := roomv1.RolloutStage_name[int32(value)]
	return ok && value != roomv1.RolloutStage_ROLLOUT_STAGE_UNSPECIFIED
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
		if trigger == nil || trigger.GetSignal() <= roomv1.SignalKind_SIGNAL_KIND_UNSPECIFIED || trigger.GetSignal() > roomv1.SignalKind_SIGNAL_KIND_REVIEW_NEGATIVE_TEST_GAP || trigger.GetMinimumConfidenceBasisPoints() > 10000 {
			return errors.New("invalid signal trigger")
		}
		for _, phase := range trigger.GetPhases() {
			if phase != roomv1.AnalysisPhase_ANALYSIS_PHASE_PLAN && phase != roomv1.AnalysisPhase_ANALYSIS_PHASE_DIFF {
				return errors.New("invalid analysis phase")
			}
		}
	}
	for _, signal := range rule.GetRequiredCoverage() {
		if signal <= roomv1.SignalKind_SIGNAL_KIND_UNSPECIFIED || signal > roomv1.SignalKind_SIGNAL_KIND_REVIEW_NEGATIVE_TEST_GAP {
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

func cloneReviewFinding(finding *roomv1.ReviewFinding) *roomv1.ReviewFinding {
	if finding == nil {
		return nil
	}
	return proto.Clone(finding).(*roomv1.ReviewFinding)
}

func cloneReviewOutcome(outcome *roomv1.ReviewOutcome) *roomv1.ReviewOutcome {
	if outcome == nil {
		return nil
	}
	return proto.Clone(outcome).(*roomv1.ReviewOutcome)
}

func cloneReviewAdjudication(adjudication *roomv1.ReviewAdjudication) *roomv1.ReviewAdjudication {
	if adjudication == nil {
		return nil
	}
	return proto.Clone(adjudication).(*roomv1.ReviewAdjudication)
}

func clonePolicyCandidate(candidate *roomv1.PolicyCandidate) *roomv1.PolicyCandidate {
	if candidate == nil {
		return nil
	}
	return proto.Clone(candidate).(*roomv1.PolicyCandidate)
}

func clonePolicyReplayRun(replay *roomv1.PolicyReplayRun) *roomv1.PolicyReplayRun {
	if replay == nil {
		return nil
	}
	return proto.Clone(replay).(*roomv1.PolicyReplayRun)
}

func cloneTuningDecision(decision *roomv1.TuningDecision) *roomv1.TuningDecision {
	if decision == nil {
		return nil
	}
	return proto.Clone(decision).(*roomv1.TuningDecision)
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
