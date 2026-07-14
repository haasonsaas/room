package app

import (
	"context"
	"crypto/sha256"
	"path/filepath"
	"testing"

	"connectrpc.com/connect"
	roomv1 "github.com/haasonsaas/room/gen/go/room/v1"
	"github.com/haasonsaas/room/internal/analyzer"
	"github.com/haasonsaas/room/internal/auth"
	"github.com/haasonsaas/room/internal/compliance"
	"github.com/haasonsaas/room/internal/store"
)

func TestAgentIdentityOverridesForgedEvaluationScope(t *testing.T) {
	database, err := store.Open(filepath.Join(t.TempDir(), "room.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer database.Close()
	provider := newCompleteAnalyzer()
	service := New(database, WithAnalyzer(provider))
	principal := auth.Principal{ID: "agent-token", Role: auth.RoleAgent, Scope: auth.Scope{WorkspaceID: "trusted-workspace", Repository: "trusted-repo", AgentID: "codex-1"}}
	ctx := auth.WithPrincipal(context.Background(), principal)

	response, err := service.Agent().GetActiveRuleset(ctx, connect.NewRequest(&roomv1.AgentRulesServiceGetActiveRulesetRequest{}))
	if err != nil {
		t.Fatalf("get ruleset: %v", err)
	}
	scope := response.Msg.GetRuleset().GetAuthorizedScope()
	if scope.GetWorkspaceId() != "trusted-workspace" || scope.GetRepository() != "trusted-repo" || scope.GetAgentType() != "codex-1" {
		t.Fatalf("authorized scope = %+v", scope)
	}

	_, err = service.EvaluatePlan(ctx, connect.NewRequest(&roomv1.EvaluatePlanRequest{Input: &roomv1.EvaluationInput{
		Context: &roomv1.EvaluationContext{WorkspaceId: "forged", Repository: "forged", AgentType: "forged"},
		Plan:    "test",
	}}))
	if err != nil {
		t.Fatalf("evaluate plan: %v", err)
	}
	admin := auth.WithPrincipal(context.Background(), auth.Principal{ID: "admin", Role: auth.RoleAdmin})
	audit, err := service.ListAuditEvents(admin, connect.NewRequest(&roomv1.ListAuditEventsRequest{Limit: 10}))
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	if len(audit.Msg.GetEvents()) == 0 {
		t.Fatal("missing evaluation audit event")
	}
	event := audit.Msg.GetEvents()[0]
	if event.GetWorkspaceId() != "trusted-workspace" || event.GetRepository() != "trusted-repo" || event.GetAgentType() != "codex-1" {
		t.Fatalf("audit used caller scope: %+v", event)
	}
}

func TestAdminRPCRejectsAgentRole(t *testing.T) {
	database, err := store.Open(filepath.Join(t.TempDir(), "room.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer database.Close()
	service := New(database)
	ctx := auth.WithPrincipal(context.Background(), auth.Principal{ID: "agent", Role: auth.RoleAgent, Scope: auth.Scope{WorkspaceID: "w", Repository: "r", AgentID: "a"}})
	if _, err := service.ListRules(ctx, connect.NewRequest(&roomv1.ListRulesRequest{})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("code = %s, want permission denied", connect.CodeOf(err))
	}
}

func TestReportEvaluationOnlyAcknowledgesServerMintedReceipt(t *testing.T) {
	database, err := store.Open(filepath.Join(t.TempDir(), "room.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer database.Close()
	service := New(database, WithAnalyzer(newCompleteAnalyzer()))
	principal := auth.Principal{ID: "agent", Role: auth.RoleAgent, Scope: auth.Scope{WorkspaceID: "w", Repository: "r", AgentID: "a"}}
	ctx := auth.WithPrincipal(context.Background(), principal)
	evaluated, err := service.EvaluatePlan(ctx, connect.NewRequest(&roomv1.EvaluatePlanRequest{Input: &roomv1.EvaluationInput{Plan: "test"}}))
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	result := evaluated.Msg.GetResult()
	if response, err := service.ReportEvaluation(ctx, connect.NewRequest(&roomv1.ReportEvaluationRequest{Result: result})); err != nil || !response.Msg.GetAccepted() {
		t.Fatalf("report valid receipt: response=%v err=%v", response, err)
	}
	result.RulesetHash = "forged"
	if _, err := service.ReportEvaluation(ctx, connect.NewRequest(&roomv1.ReportEvaluationRequest{Result: result})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("forged report code = %s, want invalid argument", connect.CodeOf(err))
	}
}

func TestServiceBuildsEvaluationPolicyOnce(t *testing.T) {
	database, err := store.Open(filepath.Join(t.TempDir(), "room.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	provider := newCompleteAnalyzer()
	service := New(database, WithAnalyzer(provider))
	principal := auth.Principal{ID: "agent", Role: auth.RoleAgent, Scope: auth.Scope{WorkspaceID: "w", Repository: "r", AgentID: "a"}}
	ctx := auth.WithPrincipal(context.Background(), principal)

	for range 2 {
		if _, err := service.EvaluatePlan(ctx, connect.NewRequest(&roomv1.EvaluatePlanRequest{Input: &roomv1.EvaluationInput{Plan: "test"}})); err != nil {
			t.Fatalf("evaluate: %v", err)
		}
	}
	if provider.identityCalls != 1 {
		t.Fatalf("Identity calls = %d, want 1", provider.identityCalls)
	}
}

func TestMCPInvocationTrustComesFromCredential(t *testing.T) {
	tests := []struct {
		name       string
		scope      auth.Scope
		policy     *roomv1.McpCompliancePolicy
		invocation *roomv1.McpInvocation
		allowed    bool
		reason     string
	}{
		{
			name:  "ordinary agent cannot forge proxy identity",
			scope: auth.Scope{WorkspaceID: "w", Repository: "r", AgentID: "a"},
			policy: &roomv1.McpCompliancePolicy{Mode: roomv1.McpComplianceMode_MCP_COMPLIANCE_MODE_ALLOWLIST, DenyUnknownIdentity: true,
				Selectors: []*roomv1.McpToolSelector{{ServerId: "github", ToolName: "get_issue"}}},
			invocation: &roomv1.McpInvocation{ServerId: "github", ToolName: "get_issue", Provider: roomv1.HookProvider_HOOK_PROVIDER_MCP_PROXY, IdentityAssurance: roomv1.IdentityAssurance_IDENTITY_ASSURANCE_TRANSPORT_VERIFIED},
			allowed:    false,
			reason:     compliance.ReasonIdentityUnknown,
		},
		{
			name:  "proxy capability supplies transport trust",
			scope: auth.Scope{WorkspaceID: "w", Repository: "r", AgentID: "a", MCPProxy: true},
			policy: &roomv1.McpCompliancePolicy{Mode: roomv1.McpComplianceMode_MCP_COMPLIANCE_MODE_ALLOWLIST, DenyUnknownIdentity: true,
				Selectors: []*roomv1.McpToolSelector{{ServerId: "github", ToolName: "get_issue"}}},
			invocation: &roomv1.McpInvocation{ServerId: "github", ToolName: "get_issue", Provider: roomv1.HookProvider_HOOK_PROVIDER_CURSOR, IdentityAssurance: roomv1.IdentityAssurance_IDENTITY_ASSURANCE_UNVERIFIED},
			allowed:    true,
			reason:     compliance.ReasonAllowlistMatch,
		},
		{
			name:  "hook credential uses configured provider binding",
			scope: auth.Scope{WorkspaceID: "w", Repository: "r", AgentID: "a", HookProvider: auth.HookProviderCodex},
			policy: &roomv1.McpCompliancePolicy{Mode: roomv1.McpComplianceMode_MCP_COMPLIANCE_MODE_ALLOWLIST, DenyUnknownIdentity: true,
				Selectors:        []*roomv1.McpToolSelector{{ServerId: "github", ToolName: "create_pull_request"}},
				ProviderBindings: []*roomv1.ProviderToolBinding{{Provider: roomv1.HookProvider_HOOK_PROVIDER_CODEX, ProviderToolId: "opaque-tool", ServerId: "github", ToolName: "create_pull_request"}}},
			invocation: &roomv1.McpInvocation{ProviderToolId: "opaque-tool", Provider: roomv1.HookProvider_HOOK_PROVIDER_MCP_PROXY, IdentityAssurance: roomv1.IdentityAssurance_IDENTITY_ASSURANCE_TRANSPORT_VERIFIED},
			allowed:    true,
			reason:     compliance.ReasonAllowlistMatch,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			database, err := store.Open(filepath.Join(t.TempDir(), "room.db"))
			if err != nil {
				t.Fatalf("open store: %v", err)
			}
			defer database.Close()
			if _, err := database.UpdateMCPPolicy(tt.policy); err != nil {
				t.Fatalf("update policy: %v", err)
			}
			if _, err := database.Publish("test", "credential-derived MCP trust"); err != nil {
				t.Fatalf("publish policy: %v", err)
			}
			service := New(database)
			ctx := auth.WithPrincipal(context.Background(), auth.Principal{ID: "agent", Role: auth.RoleAgent, Scope: tt.scope})
			response, err := service.EvaluateMcpInvocation(ctx, connect.NewRequest(&roomv1.EvaluateMcpInvocationRequest{Invocation: tt.invocation}))
			if err != nil {
				t.Fatalf("evaluate MCP invocation: %v", err)
			}
			decision := response.Msg.GetDecision()
			if decision.GetAllowed() != tt.allowed || decision.GetReasonCode() != tt.reason {
				t.Fatalf("decision = %+v, want allowed=%v reason=%q", decision, tt.allowed, tt.reason)
			}
		})
	}
}

func TestForgedChangedFilesCannotBypassPathScopedRule(t *testing.T) {
	database, err := store.Open(filepath.Join(t.TempDir(), "room.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer database.Close()
	provider := newPathSignalAnalyzer()
	service := New(database, WithAnalyzer(provider))
	ctx := auth.WithPrincipal(context.Background(), auth.Principal{ID: "agent", Role: auth.RoleAgent, Scope: auth.Scope{WorkspaceID: "w", Repository: "r", AgentID: "a"}})
	response, err := service.EvaluateDiff(ctx, connect.NewRequest(&roomv1.EvaluateDiffRequest{Input: &roomv1.EvaluationInput{
		Diff:    "trusted analyzer detects a tenant scope violation",
		Context: &roomv1.EvaluationContext{ChangedFiles: []string{"docs/harmless.md"}},
	}}))
	if err != nil {
		t.Fatalf("evaluate diff: %v", err)
	}
	if len(provider.changedFiles) != 0 {
		t.Fatalf("analyzer received caller changed_files: %v", provider.changedFiles)
	}
	if response.Msg.GetResult().GetDecision() != roomv1.Decision_DECISION_DENY {
		t.Fatalf("decision = %s, want deny", response.Msg.GetResult().GetDecision())
	}
	found := false
	for _, match := range response.Msg.GetResult().GetMatches() {
		found = found || match.GetRuleId() == "tenant-org-scope-required"
	}
	if !found {
		t.Fatalf("path-scoped rule missing from matches: %+v", response.Msg.GetResult().GetMatches())
	}
}

func TestPreviewRulesetUsesExplicitEvaluationPhase(t *testing.T) {
	database, err := store.Open(filepath.Join(t.TempDir(), "room.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer database.Close()
	provider := newCompleteAnalyzer()
	service := New(database, WithAnalyzer(provider))
	ctx := auth.WithPrincipal(context.Background(), auth.Principal{ID: "admin", Role: auth.RoleAdmin})

	_, err = service.PreviewRuleset(ctx, connect.NewRequest(&roomv1.PreviewRulesetRequest{Input: &roomv1.EvaluationInput{
		Phase: roomv1.AnalysisPhase_ANALYSIS_PHASE_DIFF,
		Plan:  "nonempty plan must not select the phase",
		Diff:  "",
	}}))
	if err != nil {
		t.Fatalf("preview empty diff: %v", err)
	}
	if len(provider.inputs) != 1 || provider.inputs[0].Phase != roomv1.AnalysisPhase_ANALYSIS_PHASE_DIFF || len(provider.inputs[0].Content) != 0 {
		t.Fatalf("analyzer input = %+v, want explicit diff phase with empty content", provider.inputs)
	}

	_, err = service.PreviewRuleset(ctx, connect.NewRequest(&roomv1.PreviewRulesetRequest{Input: &roomv1.EvaluationInput{Plan: "missing phase"}}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("missing phase code = %s, want invalid argument", connect.CodeOf(err))
	}
}

func TestAuthorizedContextKeepsIdentityTrustedAndClassificationConservative(t *testing.T) {
	principal := auth.Principal{ID: "agent", Role: auth.RoleAgent, Scope: auth.Scope{WorkspaceID: "trusted-workspace", Repository: "trusted-repo", AgentID: "trusted-agent"}}
	supplied := &roomv1.EvaluationContext{
		WorkspaceId: "forged-workspace", Repository: "forged-repo", AgentType: "forged-agent", SubjectId: "forged-subject",
		Cwd: "/workspace", ChangedFiles: []string{"harmless.txt"}, Languages: []string{"forged-language"}, Frameworks: []string{"forged-framework"},
	}

	got := authorizedContext(principal, supplied)
	if got.GetWorkspaceId() != principal.Scope.WorkspaceID || got.GetRepository() != principal.Scope.Repository || got.GetAgentType() != principal.Scope.AgentID || got.GetSubjectId() != principal.ID {
		t.Fatalf("authorized identity = %+v", got)
	}
	if got.GetCwd() != supplied.GetCwd() {
		t.Fatalf("cwd = %q, want %q", got.GetCwd(), supplied.GetCwd())
	}
	if len(got.GetChangedFiles()) != 0 || len(got.GetLanguages()) != 0 || len(got.GetFrameworks()) != 0 {
		t.Fatalf("untrusted artifact classification survived authorization: %+v", got)
	}
}

func TestScopedRulesetUsesIdentityScopeWithoutDiscardingArtifactScopes(t *testing.T) {
	principal := auth.Principal{ID: "agent", Role: auth.RoleAgent, Scope: auth.Scope{WorkspaceID: " w ", Repository: "org/team/repo", AgentID: "Codex"}}
	rule := &roomv1.Rule{Id: "recursive", Enabled: true, Scope: &roomv1.RuleScope{
		Workspaces: []string{"w"}, Repositories: []string{"org/**"}, AgentTypes: []string{"codex"},
		Languages: []string{"go"}, Frameworks: []string{"connectrpc"}, Paths: []string{"internal/**"},
	}}
	source := &roomv1.RulesetVersion{Id: "ruleset-1", Version: 1, Hash: "source", Rules: []*roomv1.Rule{rule}}
	view := scopedRuleset(source, principal)
	if len(view.GetRules()) != 1 || view.GetRules()[0].GetId() != rule.GetId() {
		t.Fatalf("scoped rules = %+v, want recursive identity match", view.GetRules())
	}
}

type completeAnalyzer struct {
	identity      *roomv1.AnalyzerIdentity
	identityCalls int
	inputs        []analyzer.Input
}

type pathSignalAnalyzer struct {
	identity     *roomv1.AnalyzerIdentity
	changedFiles []string
}

func newPathSignalAnalyzer() *pathSignalAnalyzer {
	return &pathSignalAnalyzer{identity: &roomv1.AnalyzerIdentity{Id: "path-test", Version: "1", ConfigSha256: make([]byte, 32)}}
}

func (a *pathSignalAnalyzer) Identity() *roomv1.AnalyzerIdentity { return a.identity }

func (a *pathSignalAnalyzer) Analyze(_ context.Context, input analyzer.Input) *roomv1.AnalysisReport {
	a.changedFiles = append([]string(nil), input.ChangedFiles...)
	digest := sha256.Sum256(input.Content)
	receipt := &roomv1.AnalyzerReceipt{Analyzer: a.identity, Status: roomv1.AnalysisStatus_ANALYSIS_STATUS_COMPLETE, InputSha256: digest[:]}
	for signal := roomv1.SignalKind(1); signal <= roomv1.SignalKind_SIGNAL_KIND_RUST_UNVALIDATED_EXTERNAL_DESERIALIZATION; signal++ {
		receipt.CoveredSignals = append(receipt.CoveredSignals, signal)
	}
	receipt.Signals = []*roomv1.SecuritySignal{{Kind: roomv1.SignalKind_SIGNAL_KIND_TENANT_ACCESS_WITHOUT_TRUSTED_SCOPE, Fingerprint: "tenant-scope", Analyzer: a.identity, ConfidenceBasisPoints: 10000}}
	return &roomv1.AnalysisReport{Status: roomv1.AnalysisStatus_ANALYSIS_STATUS_COMPLETE, Artifact: &roomv1.ArtifactRef{Phase: input.Phase, Sha256: digest[:], ChangedFiles: input.ChangedFiles}, Receipts: []*roomv1.AnalyzerReceipt{receipt}}
}

func newCompleteAnalyzer() *completeAnalyzer {
	return &completeAnalyzer{identity: &roomv1.AnalyzerIdentity{Id: "test", Version: "1", ConfigSha256: make([]byte, 32)}}
}

func (a *completeAnalyzer) Identity() *roomv1.AnalyzerIdentity {
	a.identityCalls++
	return a.identity
}

func (a *completeAnalyzer) Analyze(_ context.Context, input analyzer.Input) *roomv1.AnalysisReport {
	a.inputs = append(a.inputs, input)
	digest := sha256.Sum256(input.Content)
	receipt := &roomv1.AnalyzerReceipt{Analyzer: a.identity, Status: roomv1.AnalysisStatus_ANALYSIS_STATUS_COMPLETE, InputSha256: digest[:]}
	for signal := roomv1.SignalKind(1); signal <= roomv1.SignalKind_SIGNAL_KIND_RUST_UNVALIDATED_EXTERNAL_DESERIALIZATION; signal++ {
		receipt.CoveredSignals = append(receipt.CoveredSignals, signal)
	}
	return &roomv1.AnalysisReport{Status: roomv1.AnalysisStatus_ANALYSIS_STATUS_COMPLETE, Artifact: &roomv1.ArtifactRef{Phase: input.Phase, Sha256: digest[:], ChangedFiles: input.ChangedFiles}, Receipts: []*roomv1.AnalyzerReceipt{receipt}}
}
