package store

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	roomv1 "github.com/haasonsaas/room/gen/go/room/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func TestOpenPublishesRustDefaultRules(t *testing.T) {
	path := filepath.Join(t.TempDir(), "room.db")
	ruleStore, err := Open(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	ruleset := ruleStore.ActiveRuleset()
	if ruleset == nil {
		t.Fatal("active ruleset is nil")
	}

	want := []string{
		"rust-unsafe-requires-safety-rationale",
		"rust-request-paths-must-not-unwrap",
		"rust-command-exec-requires-allowlist",
		"rust-secrets-require-crypto-rng",
		"rust-paths-must-be-canonicalized",
		"rust-library-api-must-not-panic",
		"rust-no-std-mutex-across-await",
		"rust-serde-external-input-deny-unknown-fields",
	}
	seen := make(map[string]bool, len(ruleset.GetRules()))
	for _, rule := range ruleset.GetRules() {
		seen[rule.GetId()] = true
	}
	for _, id := range want {
		if !seen[id] {
			t.Fatalf("default ruleset missing %s", id)
		}
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("database permissions = %v, err=%v; want private", info.Mode().Perm(), err)
	}
	if ruleset.GetRules()[0].GetTriggers()[0].GetSignal() == roomv1.SignalKind_SIGNAL_KIND_UNSPECIFIED {
		t.Fatal("default rule is not backed by a typed signal")
	}
}

func TestAuditAppendIsIdempotentAndRejectsConflictingReuse(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "room.db"))
	if err != nil {
		t.Fatal(err)
	}
	event := &roomv1.AuditEvent{Id: "event-1", Kind: roomv1.AuditEventKind_AUDIT_EVENT_KIND_EVALUATION, Repository: "github.com/acme/room"}
	if _, err := s.AppendAudit(event); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AppendAudit(event); err != nil {
		t.Fatalf("idempotent append: %v", err)
	}
	event.Repository = "github.com/other/repo"
	if _, err := s.AppendAudit(event); err == nil {
		t.Fatal("expected conflicting event id to fail")
	}
	events, err := s.ListAudit(10, roomv1.AuditEventKind_AUDIT_EVENT_KIND_EVALUATION)
	if err != nil || len(events) != 1 {
		t.Fatalf("events=%d err=%v", len(events), err)
	}
}

func TestLegacyProtoJSONIsPreservedAndMigrated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "room.json")
	snapshot := &roomv1.StoreSnapshot{NextVersion: 1, DraftRules: []*roomv1.Rule{{Id: "no-secret-literals", Enabled: true, Checks: []*roomv1.RuleCheck{{Kind: roomv1.CheckKind_CHECK_KIND_HEURISTIC, Expression: "secret_literal"}}}}}
	data, err := protojson.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".legacy.json"); err != nil {
		t.Fatalf("legacy backup: %v", err)
	}
	ruleset := s.ActiveRuleset()
	if ruleset == nil || len(ruleset.GetRules()) != 1 || len(ruleset.GetRules()[0].GetTriggers()) != 1 || len(ruleset.GetRules()[0].GetChecks()) != 0 {
		t.Fatalf("legacy rule not migrated: %+v", ruleset)
	}
}

func TestLegacyHistoricalVersionsCanRollbackAndRepublish(t *testing.T) {
	path := filepath.Join(t.TempDir(), "room-data.json")
	legacyRule := func(id string) *roomv1.Rule {
		return &roomv1.Rule{Id: id, Enabled: true, Checks: []*roomv1.RuleCheck{{Kind: roomv1.CheckKind_CHECK_KIND_HEURISTIC, Expression: "secret_literal"}}}
	}
	snapshot := &roomv1.StoreSnapshot{
		DraftRules:    []*roomv1.Rule{legacyRule("draft")},
		ActiveVersion: 2,
		NextVersion:   3,
		Versions: []*roomv1.RulesetVersion{
			{Id: "ruleset-1", Version: 1, Rules: []*roomv1.Rule{legacyRule("historical-1")}},
			{Id: "ruleset-2", Version: 2, Rules: []*roomv1.Rule{legacyRule("historical-2")}},
		},
	}
	data, err := protojson.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var storedVersions int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM ruleset_versions`).Scan(&storedVersions); err != nil {
		t.Fatal(err)
	}
	if storedVersions != 3 {
		t.Fatalf("stored versions = %d, want 3 imported/published versions", storedVersions)
	}

	for _, version := range []int32{1, 2} {
		rolledBack, err := s.Rollback(version)
		if err != nil {
			t.Fatalf("rollback %d: %v", version, err)
		}
		for _, rule := range rolledBack.GetRules() {
			if len(rule.GetTriggers()) == 0 || len(rule.GetChecks()) != 0 {
				t.Fatalf("version %d retained legacy rule: %+v", version, rule)
			}
		}
		if _, err := s.Publish("migration-test", fmt.Sprintf("republish %d", version)); err != nil {
			t.Fatalf("republish %d: %v", version, err)
		}
	}
}

func TestLegacyMigrationRetriesFromBackupAfterInterruptedDatabaseCreation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "room.json")
	snapshot := &roomv1.StoreSnapshot{NextVersion: 1, DraftRules: []*roomv1.Rule{{Id: "no-secret-literals", Enabled: true, Checks: []*roomv1.RuleCheck{{Kind: roomv1.CheckKind_CHECK_KIND_HEURISTIC, Expression: "secret_literal"}}}}}
	data, err := protojson.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".legacy.json", data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ruleset := s.ActiveRuleset()
	if ruleset == nil || len(ruleset.GetRules()) != 1 || ruleset.GetRules()[0].GetId() != "no-secret-literals" || len(ruleset.GetRules()[0].GetTriggers()) != 1 {
		t.Fatalf("legacy backup was not retried: %+v", ruleset)
	}
	backup, err := os.ReadFile(path + ".legacy.json")
	if err != nil {
		t.Fatalf("read preserved backup: %v", err)
	}
	if string(backup) != string(data) {
		t.Fatal("retry modified the preserved legacy backup")
	}
}

func TestUpsertRuleMigratesRecognizedLegacyPlanCheck(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "room.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	rule, err := s.UpsertRule(&roomv1.Rule{
		Id:      "legacy-auth-context",
		Enabled: true,
		Checks: []*roomv1.RuleCheck{{
			Kind:       roomv1.CheckKind_CHECK_KIND_PLAN_TEXT,
			Expression: "missing_any:auth,session,principal,claims",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rule.GetChecks()) != 0 || len(rule.GetTriggers()) != 1 || rule.GetTriggers()[0].GetSignal() != roomv1.SignalKind_SIGNAL_KIND_PROTECTED_ACCESS_WITHOUT_AUTH_CONTEXT {
		t.Fatalf("legacy rule was not migrated to typed signal: %+v", rule)
	}
}

func TestUpsertRuleRejectsUnknownLegacyPlanCheck(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "room.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	_, err = s.UpsertRule(&roomv1.Rule{
		Id:      "unknown-legacy-check",
		Enabled: true,
		Checks: []*roomv1.RuleCheck{{
			Kind:       roomv1.CheckKind_CHECK_KIND_PLAN_TEXT,
			Expression: "missing_any:invented,prose",
		}},
	})
	if err == nil {
		t.Fatal("unknown legacy check was accepted")
	}
}

func TestPolicyChangesRulesetHash(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "room.db"))
	if err != nil {
		t.Fatal(err)
	}
	first := s.ActiveRuleset().GetHash()
	policy := s.MCPPolicy()
	policy.Selectors = append(policy.Selectors, &roomv1.McpToolSelector{ServerId: "github", ToolName: "read"})
	if _, err := s.UpdateMCPPolicy(policy); err != nil {
		t.Fatal(err)
	}
	second, err := s.Publish("test", "policy")
	if err != nil {
		t.Fatal(err)
	}
	if first == second.GetHash() {
		t.Fatal("ruleset hash did not include MCP policy")
	}
}

func TestActiveRulesetIfChangedSkipsCurrentVersion(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "room.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	active := s.ActiveRuleset()
	if active == nil {
		t.Fatal("active ruleset is nil")
	}
	if got := s.ActiveRulesetIfChanged(active.GetVersion()); got != nil {
		t.Fatalf("unchanged ruleset = %v, want nil", got)
	}
	if got := s.ActiveRulesetIfChanged(0); got == nil || got.GetVersion() != active.GetVersion() {
		t.Fatalf("changed ruleset = %v, want version %d", got, active.GetVersion())
	}
}

func TestRulesetHistoryIsStoredSeparatelyAndSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "room.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	first := s.ActiveRuleset().GetVersion()
	second, err := s.Publish("test", "second")
	if err != nil {
		t.Fatal(err)
	}
	var statePayload []byte
	if err := s.db.QueryRow(`SELECT snapshot FROM room_state WHERE id = 1`).Scan(&statePayload); err != nil {
		t.Fatal(err)
	}
	state := &roomv1.StoreSnapshot{}
	if err := proto.Unmarshal(statePayload, state); err != nil {
		t.Fatal(err)
	}
	if len(state.GetVersions()) != 0 {
		t.Fatalf("room_state contains %d historical versions", len(state.GetVersions()))
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.ActiveRuleset().GetVersion() != second.GetVersion() {
		t.Fatalf("active version = %d, want %d", reopened.ActiveRuleset().GetVersion(), second.GetVersion())
	}
	rolledBack, err := reopened.Rollback(first)
	if err != nil {
		t.Fatal(err)
	}
	if rolledBack.GetVersion() != first {
		t.Fatalf("rollback version = %d, want %d", rolledBack.GetVersion(), first)
	}
}

func TestFailedPublishDoesNotAdvanceLiveSnapshot(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "room.db"))
	if err != nil {
		t.Fatal(err)
	}
	before := s.ActiveRuleset()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := s.Publish("test", "must fail"); err == nil {
		t.Fatal("publish succeeded after database close")
	}
	after := s.ActiveRuleset()
	if after.GetVersion() != before.GetVersion() || after.GetHash() != before.GetHash() {
		t.Fatalf("failed publish changed live ruleset from version %d to %d", before.GetVersion(), after.GetVersion())
	}
}

func TestAuditedPublishIsAtomicOnAuditConflict(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "room.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	before := s.ActiveRuleset()
	existing := &roomv1.AuditEvent{Id: "publish-event", Kind: roomv1.AuditEventKind_AUDIT_EVENT_KIND_RULESET_PUBLISHED, Repository: "github.com/acme/room"}
	if _, err := s.AppendAudit(existing); err != nil {
		t.Fatal(err)
	}
	conflicting := proto.Clone(existing).(*roomv1.AuditEvent)
	conflicting.Repository = "github.com/other/repo"
	if _, err := s.PublishAudited("test", "must roll back", conflicting); err == nil {
		t.Fatal("publish succeeded with a conflicting audit id")
	}
	after := s.ActiveRuleset()
	if after.GetVersion() != before.GetVersion() || after.GetHash() != before.GetHash() {
		t.Fatalf("failed audited publish changed live ruleset from version %d to %d", before.GetVersion(), after.GetVersion())
	}

	var versions int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM ruleset_versions`).Scan(&versions); err != nil {
		t.Fatal(err)
	}
	if versions != 1 {
		t.Fatalf("ruleset_versions count = %d, want 1 after rollback", versions)
	}
}

func TestDraftAndPolicyMutationsDoNotRewriteVersionHistory(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "room.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.db.Exec(`CREATE TRIGGER reject_version_rewrite BEFORE INSERT ON ruleset_versions BEGIN SELECT RAISE(ABORT, 'history rewrite'); END`); err != nil {
		t.Fatal(err)
	}

	policy := s.MCPPolicy()
	policy.AuditAllowed = !policy.GetAuditAllowed()
	if _, err := s.UpdateMCPPolicy(policy); err != nil {
		t.Fatalf("policy update rewrote version history: %v", err)
	}
	rule := s.ListRules(true)[0]
	rule.Title += " updated"
	if _, err := s.UpsertRule(rule); err != nil {
		t.Fatalf("draft update rewrote version history: %v", err)
	}
}
