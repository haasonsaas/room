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
		{
			Id:          "protected-handlers-require-auth-context",
			Title:       "Protected handlers must load auth context",
			Description: "Protected API handlers must load authenticated principal/session context before reading or mutating data.",
			Severity:    roomv1.Severity_SEVERITY_HIGH,
			Tags:        []string{"security", "authorization", "api"},
			Scope:       &roomv1.RuleScope{Paths: []string{"app/**", "src/**", "internal/**", "services/**"}},
			Checks: []*roomv1.RuleCheck{
				{Kind: roomv1.CheckKind_CHECK_KIND_HEURISTIC, Expression: "protected_handler_without_auth_context"},
			},
			RequiredEvidence: []string{"handler reads authenticated principal/session context", "unauthenticated request test is added or updated"},
			Remediation:      []string{"thread auth context into the handler before data access", "add middleware or guard coverage"},
			Enabled:          true,
			Owner:            "room",
			CreatedAt:        now,
			UpdatedAt:        now,
		},
		{
			Id:          "sql-must-be-parameterized",
			Title:       "SQL must be parameterized",
			Description: "Database queries built from user input must use parameters, prepared statements, or a safe query builder.",
			Severity:    roomv1.Severity_SEVERITY_HIGH,
			Tags:        []string{"security", "database", "injection"},
			Checks: []*roomv1.RuleCheck{
				{Kind: roomv1.CheckKind_CHECK_KIND_HEURISTIC, Expression: "unsafe_sql_construction"},
			},
			RequiredEvidence: []string{"user-controlled values are bound as parameters", "injection regression test is present for the query path"},
			Remediation:      []string{"replace string concatenation with parameters or a typed query helper"},
			Enabled:          true,
			Owner:            "room",
			CreatedAt:        now,
			UpdatedAt:        now,
		},
		{
			Id:          "external-fetches-require-allowlist",
			Title:       "External fetches require URL allowlists",
			Description: "Code that fetches user-controlled URLs must validate scheme and host against an allowlist and block private network targets.",
			Severity:    roomv1.Severity_SEVERITY_HIGH,
			Tags:        []string{"security", "ssrf", "network"},
			Checks: []*roomv1.RuleCheck{
				{Kind: roomv1.CheckKind_CHECK_KIND_HEURISTIC, Expression: "external_fetch_without_allowlist"},
			},
			RequiredEvidence: []string{"URL scheme/host validation is present", "private/internal network targets are blocked"},
			Remediation:      []string{"use an allowlisted outbound client", "resolve and reject private IP ranges before fetching"},
			Enabled:          true,
			Owner:            "room",
			CreatedAt:        now,
			UpdatedAt:        now,
		},
		{
			Id:          "privilege-changes-require-audit",
			Title:       "Privilege changes require audit events",
			Description: "Role, permission, membership, and owner/admin changes must emit an audit event.",
			Severity:    roomv1.Severity_SEVERITY_HIGH,
			Tags:        []string{"security", "audit", "authorization"},
			Checks: []*roomv1.RuleCheck{
				{Kind: roomv1.CheckKind_CHECK_KIND_HEURISTIC, Expression: "privilege_change_without_audit"},
			},
			RequiredEvidence: []string{"audit event captures actor, subject, action, and timestamp"},
			Remediation:      []string{"emit a durable audit event in the same transaction or workflow as the privilege change"},
			Enabled:          true,
			Owner:            "room",
			CreatedAt:        now,
			UpdatedAt:        now,
		},
		{
			Id:          "webhooks-require-signature-verification",
			Title:       "Webhooks require signature verification",
			Description: "Public webhook endpoints must verify provider signatures before processing payloads.",
			Severity:    roomv1.Severity_SEVERITY_HIGH,
			Tags:        []string{"security", "webhook", "integrations"},
			Checks: []*roomv1.RuleCheck{
				{Kind: roomv1.CheckKind_CHECK_KIND_HEURISTIC, Expression: "webhook_without_signature_verification"},
			},
			RequiredEvidence: []string{"provider signature or HMAC verification is performed before parsing trusted event fields"},
			Remediation:      []string{"verify the signed payload using the provider secret and reject unsigned or invalid requests"},
			Enabled:          true,
			Owner:            "room",
			CreatedAt:        now,
			UpdatedAt:        now,
		},
		{
			Id:          "passwords-must-be-hashed",
			Title:       "Passwords must be hashed before storage",
			Description: "Any password persistence must use a dedicated password hashing algorithm such as bcrypt, scrypt, Argon2, or PBKDF2.",
			Severity:    roomv1.Severity_SEVERITY_CRITICAL,
			Tags:        []string{"security", "auth", "passwords"},
			Checks: []*roomv1.RuleCheck{
				{Kind: roomv1.CheckKind_CHECK_KIND_HEURISTIC, Expression: "password_storage_without_hashing"},
			},
			RequiredEvidence: []string{"passwords are hashed with a password hashing algorithm and never stored in plaintext"},
			Remediation:      []string{"hash passwords with bcrypt, scrypt, Argon2, or PBKDF2 before persistence"},
			Enabled:          true,
			Owner:            "room",
			CreatedAt:        now,
			UpdatedAt:        now,
		},
		{
			Id:          "sensitive-public-endpoints-need-rate-limits",
			Title:       "Sensitive public endpoints need rate limits",
			Description: "Public login, signup, token, OTP, and password-reset endpoints must include rate limiting or abuse throttling.",
			Severity:    roomv1.Severity_SEVERITY_HIGH,
			Tags:        []string{"security", "abuse", "auth"},
			Checks: []*roomv1.RuleCheck{
				{Kind: roomv1.CheckKind_CHECK_KIND_HEURISTIC, Expression: "public_sensitive_endpoint_without_rate_limit"},
			},
			RequiredEvidence: []string{"rate limit or throttling is enforced before expensive or sensitive work"},
			Remediation:      []string{"add per-identity and per-IP rate limits for the endpoint"},
			Enabled:          true,
			Owner:            "room",
			CreatedAt:        now,
			UpdatedAt:        now,
		},
		{
			Id:          "rust-unsafe-requires-safety-rationale",
			Title:       "Rust unsafe code requires a safety rationale",
			Description: "Rust unsafe blocks, unsafe functions, unsafe impls, and unsafe traits must include a concrete SAFETY rationale or invariant.",
			Severity:    roomv1.Severity_SEVERITY_HIGH,
			Tags:        []string{"security", "rust", "unsafe"},
			Scope:       &roomv1.RuleScope{Paths: []string{"**/*.rs", "src/**", "crates/**"}},
			Checks: []*roomv1.RuleCheck{
				{Kind: roomv1.CheckKind_CHECK_KIND_HEURISTIC, Expression: "rust_unsafe_without_safety_rationale"},
			},
			RequiredEvidence: []string{"unsafe usage has a SAFETY comment that states the invariant and caller requirements"},
			Remediation:      []string{"remove unsafe code or document the invariant with a SAFETY rationale next to the unsafe usage"},
			Enabled:          true,
			Owner:            "room",
			CreatedAt:        now,
			UpdatedAt:        now,
		},
		{
			Id:          "rust-request-paths-must-not-unwrap",
			Title:       "Rust request paths must not unwrap or expect",
			Description: "Rust handlers, routes, and API paths must return typed errors instead of panicking with unwrap or expect.",
			Severity:    roomv1.Severity_SEVERITY_HIGH,
			Tags:        []string{"security", "rust", "availability", "api"},
			Scope:       &roomv1.RuleScope{Paths: []string{"**/*.rs", "src/**", "crates/**"}},
			Checks: []*roomv1.RuleCheck{
				{Kind: roomv1.CheckKind_CHECK_KIND_HEURISTIC, Expression: "rust_unwrap_or_expect_in_request_path"},
			},
			RequiredEvidence: []string{"request parsing and downstream calls use typed error handling instead of unwrap/expect"},
			Remediation:      []string{"replace unwrap/expect with ?, map_err, ok_or, or a typed error response"},
			Enabled:          true,
			Owner:            "room",
			CreatedAt:        now,
			UpdatedAt:        now,
		},
		{
			Id:          "rust-command-exec-requires-allowlist",
			Title:       "Rust command execution requires allowlisted arguments",
			Description: "Rust process execution must not pass request-controlled arguments unless commands and arguments are validated against an allowlist.",
			Severity:    roomv1.Severity_SEVERITY_HIGH,
			Tags:        []string{"security", "rust", "command-injection"},
			Scope:       &roomv1.RuleScope{Paths: []string{"**/*.rs", "src/**", "crates/**"}},
			Checks: []*roomv1.RuleCheck{
				{Kind: roomv1.CheckKind_CHECK_KIND_HEURISTIC, Expression: "rust_command_with_user_input"},
			},
			RequiredEvidence: []string{"command names and arguments are fixed or validated through an allowlist before execution"},
			Remediation:      []string{"replace user-controlled command arguments with validated enums or fixed argument templates"},
			Enabled:          true,
			Owner:            "room",
			CreatedAt:        now,
			UpdatedAt:        now,
		},
		{
			Id:          "rust-secrets-require-crypto-rng",
			Title:       "Rust secrets require cryptographic randomness",
			Description: "Rust tokens, nonces, sessions, password-reset values, and API keys must use a cryptographically secure RNG.",
			Severity:    roomv1.Severity_SEVERITY_CRITICAL,
			Tags:        []string{"security", "rust", "crypto", "secrets"},
			Scope:       &roomv1.RuleScope{Paths: []string{"**/*.rs", "src/**", "crates/**"}},
			Checks: []*roomv1.RuleCheck{
				{Kind: roomv1.CheckKind_CHECK_KIND_HEURISTIC, Expression: "rust_weak_rng_for_secret"},
			},
			RequiredEvidence: []string{"secret material is generated with OsRng, getrandom, ring::rand, or equivalent cryptographic randomness"},
			Remediation:      []string{"replace rand::thread_rng/rand::random/fastrand with a cryptographic RNG for secret material"},
			Enabled:          true,
			Owner:            "room",
			CreatedAt:        now,
			UpdatedAt:        now,
		},
		{
			Id:          "rust-paths-must-be-canonicalized",
			Title:       "Rust user paths must be canonicalized",
			Description: "Rust file upload/download paths derived from users must be canonicalized and checked against a trusted base directory.",
			Severity:    roomv1.Severity_SEVERITY_HIGH,
			Tags:        []string{"security", "rust", "path-traversal"},
			Scope:       &roomv1.RuleScope{Paths: []string{"**/*.rs", "src/**", "crates/**"}},
			Checks: []*roomv1.RuleCheck{
				{Kind: roomv1.CheckKind_CHECK_KIND_HEURISTIC, Expression: "rust_path_traversal_without_canonicalize"},
			},
			RequiredEvidence: []string{"user-controlled paths are canonicalized and verified to remain under a trusted base directory"},
			Remediation:      []string{"canonicalize the path, reject traversal, and check starts_with on the canonical trusted base"},
			Enabled:          true,
			Owner:            "room",
			CreatedAt:        now,
			UpdatedAt:        now,
		},
		{
			Id:          "rust-library-api-must-not-panic",
			Title:       "Rust library and API code must not panic on input",
			Description: "Rust libraries, services, and API handlers must return errors for bad input instead of panicking or using todo/unimplemented placeholders.",
			Severity:    roomv1.Severity_SEVERITY_HIGH,
			Tags:        []string{"security", "rust", "availability", "api"},
			Scope:       &roomv1.RuleScope{Paths: []string{"**/*.rs", "src/**", "crates/**"}},
			Checks: []*roomv1.RuleCheck{
				{Kind: roomv1.CheckKind_CHECK_KIND_HEURISTIC, Expression: "rust_panic_in_library_or_api"},
			},
			RequiredEvidence: []string{"library/API failure paths return Result or typed errors rather than panic/todo/unimplemented"},
			Remediation:      []string{"replace panic/todo/unimplemented with typed errors and caller-visible failure handling"},
			Enabled:          true,
			Owner:            "room",
			CreatedAt:        now,
			UpdatedAt:        now,
		},
		{
			Id:          "rust-no-std-mutex-across-await",
			Title:       "Rust async code must not hold blocking mutexes across await",
			Description: "Rust async services must not hold std::sync or parking_lot locks across await points.",
			Severity:    roomv1.Severity_SEVERITY_HIGH,
			Tags:        []string{"security", "rust", "async", "availability"},
			Scope:       &roomv1.RuleScope{Paths: []string{"**/*.rs", "src/**", "crates/**"}},
			Checks: []*roomv1.RuleCheck{
				{Kind: roomv1.CheckKind_CHECK_KIND_HEURISTIC, Expression: "rust_std_mutex_across_await"},
			},
			RequiredEvidence: []string{"blocking locks are dropped before await or replaced with async-aware synchronization"},
			Remediation:      []string{"drop the lock before awaiting or use tokio::sync primitives with careful critical sections"},
			Enabled:          true,
			Owner:            "room",
			CreatedAt:        now,
			UpdatedAt:        now,
		},
		{
			Id:          "rust-serde-external-input-deny-unknown-fields",
			Title:       "Rust external serde input must reject unknown fields",
			Description: "Rust structs deserializing external JSON payloads must use deny_unknown_fields or explicit validation to avoid silently accepting unexpected data.",
			Severity:    roomv1.Severity_SEVERITY_HIGH,
			Tags:        []string{"security", "rust", "serde", "validation"},
			Scope:       &roomv1.RuleScope{Paths: []string{"**/*.rs", "src/**", "crates/**"}},
			Checks: []*roomv1.RuleCheck{
				{Kind: roomv1.CheckKind_CHECK_KIND_HEURISTIC, Expression: "rust_serde_external_input_missing_deny_unknown_fields"},
			},
			RequiredEvidence: []string{"external request/webhook/config structs use deny_unknown_fields or explicit schema validation"},
			Remediation:      []string{"add #[serde(deny_unknown_fields)] or validate the deserialized payload against an explicit schema"},
			Enabled:          true,
			Owner:            "room",
			CreatedAt:        now,
			UpdatedAt:        now,
		},
	}
}
