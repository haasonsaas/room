package store

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	roomv1 "github.com/haasonsaas/room/gen/go/room/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Store struct {
	path     string
	mu       sync.Mutex
	snapshot *roomv1.StoreSnapshot
}

func Open(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("store path is required")
	}
	s := &Store{path: path, snapshot: &roomv1.StoreSnapshot{NextVersion: 1}}
	if err := s.load(); err != nil {
		return nil, err
	}
	if len(s.snapshot.GetDraftRules()) == 0 && len(s.snapshot.GetVersions()) == 0 {
		s.snapshot.DraftRules = defaultRules()
		if _, err := s.Publish("system", "Initial Room security rules"); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *Store) UpsertRule(rule *roomv1.Rule) (*roomv1.Rule, error) {
	if rule == nil {
		return nil, errors.New("rule is required")
	}
	if rule.GetId() == "" {
		return nil, errors.New("rule.id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := timestamppb.Now()
	copyRule := cloneRule(rule)
	if copyRule.GetCreatedAt() == nil {
		copyRule.CreatedAt = now
	}
	copyRule.UpdatedAt = now
	if !copyRule.GetEnabled() {
		copyRule.Enabled = true
	}
	for i, existing := range s.snapshot.DraftRules {
		if existing.GetId() == copyRule.GetId() {
			if existing.GetCreatedAt() != nil {
				copyRule.CreatedAt = existing.GetCreatedAt()
			}
			s.snapshot.DraftRules[i] = copyRule
			return cloneRule(copyRule), s.saveLocked()
		}
	}
	s.snapshot.DraftRules = append(s.snapshot.DraftRules, copyRule)
	sortRules(s.snapshot.DraftRules)
	return cloneRule(copyRule), s.saveLocked()
}

func (s *Store) DeleteRule(id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, rule := range s.snapshot.DraftRules {
		if rule.GetId() == id {
			s.snapshot.DraftRules = append(s.snapshot.DraftRules[:i], s.snapshot.DraftRules[i+1:]...)
			return true, s.saveLocked()
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
	s.mu.Lock()
	defer s.mu.Unlock()
	version := s.snapshot.GetNextVersion()
	if version <= 0 {
		version = 1
	}
	rules := cloneRules(s.snapshot.GetDraftRules())
	sortRules(rules)
	ruleset := &roomv1.RulesetVersion{
		Id:          fmt.Sprintf("ruleset-%d", version),
		Version:     version,
		Status:      roomv1.RulesetStatus_RULESET_STATUS_ACTIVE,
		Rules:       rules,
		Author:      author,
		Notes:       notes,
		PublishedAt: timestamppb.Now(),
	}
	ruleset.Hash = rulesetHash(ruleset)
	for _, existing := range s.snapshot.Versions {
		if existing.GetStatus() == roomv1.RulesetStatus_RULESET_STATUS_ACTIVE {
			existing.Status = roomv1.RulesetStatus_RULESET_STATUS_ARCHIVED
		}
	}
	s.snapshot.Versions = append(s.snapshot.Versions, ruleset)
	s.snapshot.ActiveVersion = version
	s.snapshot.NextVersion = version + 1
	return cloneRuleset(ruleset), s.saveLocked()
}

func (s *Store) Rollback(version int32) (*roomv1.RulesetVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var target *roomv1.RulesetVersion
	for _, ruleset := range s.snapshot.Versions {
		if ruleset.GetVersion() == version {
			target = ruleset
			break
		}
	}
	if target == nil {
		return nil, fmt.Errorf("ruleset version %d not found", version)
	}
	for _, ruleset := range s.snapshot.Versions {
		ruleset.Status = roomv1.RulesetStatus_RULESET_STATUS_ARCHIVED
	}
	target.Status = roomv1.RulesetStatus_RULESET_STATUS_ACTIVE
	s.snapshot.ActiveVersion = version
	s.snapshot.DraftRules = cloneRules(target.GetRules())
	return cloneRuleset(target), s.saveLocked()
}

func (s *Store) ActiveRuleset() *roomv1.RulesetVersion {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ruleset := range s.snapshot.Versions {
		if ruleset.GetVersion() == s.snapshot.GetActiveVersion() {
			return cloneRuleset(ruleset)
		}
	}
	return nil
}

func (s *Store) load() error {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}
	var snapshot roomv1.StoreSnapshot
	if err := protojson.Unmarshal(data, &snapshot); err != nil {
		return fmt.Errorf("read store %s: %w", s.path, err)
	}
	s.snapshot = &snapshot
	return nil
}

func (s *Store) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil && filepath.Dir(s.path) != "." {
		return err
	}
	data, err := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(s.snapshot)
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, append(data, '\n'), 0o644)
}

func rulesetHash(ruleset *roomv1.RulesetVersion) string {
	clone := cloneRuleset(ruleset)
	clone.Hash = ""
	data, _ := protojson.MarshalOptions{UseProtoNames: true}.Marshal(clone)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func cloneRule(rule *roomv1.Rule) *roomv1.Rule {
	if rule == nil {
		return nil
	}
	return &roomv1.Rule{
		Id:               rule.GetId(),
		Title:            rule.GetTitle(),
		Description:      rule.GetDescription(),
		Severity:         rule.GetSeverity(),
		Tags:             append([]string(nil), rule.GetTags()...),
		Scope:            cloneScope(rule.GetScope()),
		Checks:           cloneChecks(rule.GetChecks()),
		RequiredEvidence: append([]string(nil), rule.GetRequiredEvidence()...),
		Remediation:      append([]string(nil), rule.GetRemediation()...),
		Enabled:          rule.GetEnabled(),
		Owner:            rule.GetOwner(),
		CreatedAt:        rule.GetCreatedAt(),
		UpdatedAt:        rule.GetUpdatedAt(),
	}
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
	return &roomv1.RulesetVersion{
		Id:          ruleset.GetId(),
		Version:     ruleset.GetVersion(),
		Hash:        ruleset.GetHash(),
		Status:      ruleset.GetStatus(),
		Rules:       cloneRules(ruleset.GetRules()),
		Author:      ruleset.GetAuthor(),
		Notes:       ruleset.GetNotes(),
		PublishedAt: ruleset.GetPublishedAt(),
	}
}

func cloneScope(scope *roomv1.RuleScope) *roomv1.RuleScope {
	if scope == nil {
		return nil
	}
	return &roomv1.RuleScope{
		Workspaces:   append([]string(nil), scope.GetWorkspaces()...),
		Repositories: append([]string(nil), scope.GetRepositories()...),
		Languages:    append([]string(nil), scope.GetLanguages()...),
		Frameworks:   append([]string(nil), scope.GetFrameworks()...),
		Paths:        append([]string(nil), scope.GetPaths()...),
		AgentTypes:   append([]string(nil), scope.GetAgentTypes()...),
	}
}

func cloneChecks(checks []*roomv1.RuleCheck) []*roomv1.RuleCheck {
	out := make([]*roomv1.RuleCheck, 0, len(checks))
	for _, check := range checks {
		if check == nil {
			continue
		}
		out = append(out, &roomv1.RuleCheck{
			Kind:       check.GetKind(),
			Expression: check.GetExpression(),
			FileGlobs:  append([]string(nil), check.GetFileGlobs()...),
			Message:    check.GetMessage(),
		})
	}
	return out
}

func sortRules(rules []*roomv1.Rule) {
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].GetId() < rules[j].GetId()
	})
}

func defaultRules() []*roomv1.Rule {
	now := timestamppb.New(time.Now())
	return []*roomv1.Rule{
		{
			Id:          "tenant-org-scope-required",
			Title:       "Tenant data must be organization scoped",
			Description: "Any code path touching tenant-owned data must derive org/workspace scope from trusted context and enforce it in reads and writes.",
			Severity:    roomv1.Severity_SEVERITY_CRITICAL,
			Tags:        []string{"security", "tenancy", "authorization"},
			Scope:       &roomv1.RuleScope{Paths: []string{"internal/**", "app/**", "src/**", "services/**"}},
			Checks: []*roomv1.RuleCheck{
				{Kind: roomv1.CheckKind_CHECK_KIND_HEURISTIC, Expression: "touches_tenant_data_without_scope"},
			},
			RequiredEvidence: []string{
				"organization_id/workspace_id comes from authenticated context",
				"query or repository method filters by organization/workspace",
				"cross-organization denial test is added or updated",
			},
			Remediation: []string{
				"use an org-scoped repository/helper",
				"reject request-body organization ids unless membership is verified",
			},
			Enabled:   true,
			Owner:     "room",
			CreatedAt: now,
			UpdatedAt: now,
		},
		{
			Id:          "no-secret-literals",
			Title:       "Do not commit secret literals",
			Description: "Plans and diffs must not include API keys, passwords, long-lived tokens, or other secret literals.",
			Severity:    roomv1.Severity_SEVERITY_CRITICAL,
			Tags:        []string{"security", "secrets"},
			Checks: []*roomv1.RuleCheck{
				{Kind: roomv1.CheckKind_CHECK_KIND_HEURISTIC, Expression: "secret_literal"},
			},
			RequiredEvidence: []string{"secret values are loaded from a configured secret manager or environment variable"},
			Remediation:      []string{"remove the literal and rotate any exposed credential"},
			Enabled:          true,
			Owner:            "room",
			CreatedAt:        now,
			UpdatedAt:        now,
		},
		{
			Id:          "destructive-actions-need-approval",
			Title:       "Destructive operations require explicit approval",
			Description: "Agents must not run destructive shell/database/infrastructure operations without human approval.",
			Severity:    roomv1.Severity_SEVERITY_HIGH,
			Tags:        []string{"safety", "operations"},
			Checks: []*roomv1.RuleCheck{
				{Kind: roomv1.CheckKind_CHECK_KIND_HEURISTIC, Expression: "destructive_shell"},
			},
			RequiredEvidence: []string{"human approval is recorded before the destructive operation"},
			Remediation:      []string{"ask for approval or replace the command with a read-only inspection"},
			Enabled:          true,
			Owner:            "room",
			CreatedAt:        now,
			UpdatedAt:        now,
		},
	}
}
