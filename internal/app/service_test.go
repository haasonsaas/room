package app

import (
	"context"
	"crypto/sha256"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"
	roomv1 "github.com/haasonsaas/room/gen/go/room/v1"
	"github.com/haasonsaas/room/internal/analyzer"
	"github.com/haasonsaas/room/internal/auth"
	"github.com/haasonsaas/room/internal/compliance"
	"github.com/haasonsaas/room/internal/intelligence"
	"github.com/haasonsaas/room/internal/store"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
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

func TestRecordMcpElicitationBindsAuditToAuthenticatedAgent(t *testing.T) {
	database, err := store.Open(filepath.Join(t.TempDir(), "room.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer database.Close()
	service := New(database)
	principal := auth.Principal{ID: "trusted-agent", Role: auth.RoleAgent, Scope: auth.Scope{WorkspaceID: "trusted-workspace", Repository: "trusted-repo", AgentID: "codex-1"}}
	ctx := auth.WithPrincipal(context.Background(), principal)
	evaluationAuditID, err := database.AppendAudit(&roomv1.AuditEvent{Kind: roomv1.AuditEventKind_AUDIT_EVENT_KIND_EVALUATION, SubjectId: principal.ID, WorkspaceId: principal.Scope.WorkspaceID, Repository: principal.Scope.Repository, AgentType: principal.Scope.AgentID, EvaluationId: "evaluation-1"})
	if err != nil {
		t.Fatalf("append evaluation audit: %v", err)
	}
	receipt := &roomv1.McpElicitationReceipt{
		Id: "elicitation-1", EvaluationId: "evaluation-1", EvaluationAuditEventId: evaluationAuditID,
		Mode: roomv1.McpElicitationMode_MCP_ELICITATION_MODE_FORM, Purpose: roomv1.McpElicitationPurpose_MCP_ELICITATION_PURPOSE_EVALUATION_RESOLUTION,
		Action: roomv1.McpElicitationAction_MCP_ELICITATION_ACTION_ACCEPT, Resolution: roomv1.McpResolutionAction_MCP_RESOLUTION_ACTION_RUN_REQUIRED_CHECKS,
		OccurredAt: timestamppb.Now(),
	}
	response, err := service.RecordMcpElicitation(ctx, connect.NewRequest(&roomv1.RecordMcpElicitationRequest{Receipt: receipt}))
	if err != nil {
		t.Fatalf("record elicitation: %v", err)
	}
	if response.Msg.GetAuditEventId() == "" {
		t.Fatal("record elicitation omitted audit id")
	}
	events, err := database.ListAudit(10, roomv1.AuditEventKind_AUDIT_EVENT_KIND_MCP_ELICITATION)
	if err != nil || len(events) != 1 {
		t.Fatalf("elicitation audits = %d, err %v", len(events), err)
	}
	event := events[0]
	if event.GetSubjectId() != principal.ID || event.GetWorkspaceId() != principal.Scope.WorkspaceID || event.GetRepository() != principal.Scope.Repository || event.GetAgentType() != principal.Scope.AgentID {
		t.Fatalf("audit scope = %+v", event)
	}
	if event.GetMcpElicitation().GetId() != receipt.GetId() {
		t.Fatalf("audit receipt = %+v", event.GetMcpElicitation())
	}
}

func TestRecordMcpElicitationRejectsEvaluationFromAnotherAgentScope(t *testing.T) {
	database, err := store.Open(filepath.Join(t.TempDir(), "room.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer database.Close()
	evaluationAuditID, err := database.AppendAudit(&roomv1.AuditEvent{Kind: roomv1.AuditEventKind_AUDIT_EVENT_KIND_EVALUATION, SubjectId: "other-agent", WorkspaceId: "workspace", Repository: "repo", AgentType: "codex-2", EvaluationId: "evaluation-1"})
	if err != nil {
		t.Fatalf("append evaluation audit: %v", err)
	}
	service := New(database)
	principal := auth.Principal{ID: "trusted-agent", Role: auth.RoleAgent, Scope: auth.Scope{WorkspaceID: "workspace", Repository: "repo", AgentID: "codex-1"}}
	receipt := &roomv1.McpElicitationReceipt{Id: "elicitation-1", EvaluationId: "evaluation-1", EvaluationAuditEventId: evaluationAuditID, Mode: roomv1.McpElicitationMode_MCP_ELICITATION_MODE_FORM, Purpose: roomv1.McpElicitationPurpose_MCP_ELICITATION_PURPOSE_EVALUATION_RESOLUTION, Action: roomv1.McpElicitationAction_MCP_ELICITATION_ACTION_UNSUPPORTED}
	_, err = service.RecordMcpElicitation(auth.WithPrincipal(context.Background(), principal), connect.NewRequest(&roomv1.RecordMcpElicitationRequest{Receipt: receipt}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("cross-scope receipt code = %s, want permission denied", connect.CodeOf(err))
	}
}

func TestRecordMcpPolicyControlElicitationRequiresCurrentScopedCandidate(t *testing.T) {
	database, err := store.Open(filepath.Join(t.TempDir(), "room.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer database.Close()
	now := timestamppb.Now()
	candidate := &roomv1.PolicyCandidate{Id: "candidate-1", ClaimKind: roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_STATE_TRANSITION, ArtifactKind: roomv1.PolicyArtifactKind_POLICY_ARTIFACT_KIND_DETERMINISTIC_CHECK, ProposedRule: &roomv1.Rule{Id: "rule-1", Title: "Typed transition", Severity: roomv1.Severity_SEVERITY_HIGH, Scope: &roomv1.RuleScope{Repositories: []string{"repo"}}, RequiredEvidence: []string{"receipt"}, Remediation: []string{"persist"}, Owner: "reviewer", Triggers: []*roomv1.SignalSelector{{Signal: roomv1.SignalKind_SIGNAL_KIND_REVIEW_STATE_TRANSITION, Phases: []roomv1.AnalysisPhase{roomv1.AnalysisPhase_ANALYSIS_PHASE_PLAN}, MinimumConfidenceBasisPoints: 9000}}, RequiredCoverage: []roomv1.SignalKind{roomv1.SignalKind_SIGNAL_KIND_REVIEW_STATE_TRANSITION}, CreatedAt: now, UpdatedAt: now}, SourceFindingIds: []string{"finding-1"}, Metrics: &roomv1.PolicyMetrics{SupportCount: 1}, RolloutStage: roomv1.RolloutStage_ROLLOUT_STAGE_DRAFT, MinimumConfidenceBasisPoints: 9000, CreatedBy: "reviewer", CreatedAt: now, UpdatedAt: now}
	stored, err := database.UpsertPolicyCandidate(candidate)
	if err != nil {
		t.Fatalf("seed candidate: %v", err)
	}
	service := New(database)
	receipt := &roomv1.McpElicitationReceipt{Id: "elicitation-1", PolicyCandidateId: candidate.GetId(), Mode: roomv1.McpElicitationMode_MCP_ELICITATION_MODE_URL, Purpose: roomv1.McpElicitationPurpose_MCP_ELICITATION_PURPOSE_POLICY_CONTROL, Action: roomv1.McpElicitationAction_MCP_ELICITATION_ACTION_OFFERED, TargetRolloutStage: roomv1.RolloutStage_ROLLOUT_STAGE_BLOCK, ExpectedCandidateUpdatedAt: stored.GetUpdatedAt()}
	principal := auth.Principal{ID: "agent", Role: auth.RoleAgent, Scope: auth.Scope{WorkspaceID: "workspace", Repository: "other-repo", AgentID: "codex"}}
	_, err = service.RecordMcpElicitation(auth.WithPrincipal(context.Background(), principal), connect.NewRequest(&roomv1.RecordMcpElicitationRequest{Receipt: receipt}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("cross-repository policy handoff code = %s, want permission denied", connect.CodeOf(err))
	}
	principal.Scope.Repository = "repo"
	stale := proto.Clone(receipt).(*roomv1.McpElicitationReceipt)
	stale.ExpectedCandidateUpdatedAt = timestamppb.New(stored.GetUpdatedAt().AsTime().Add(-time.Second))
	_, err = service.RecordMcpElicitation(auth.WithPrincipal(context.Background(), principal), connect.NewRequest(&roomv1.RecordMcpElicitationRequest{Receipt: stale}))
	if connect.CodeOf(err) != connect.CodeAborted {
		t.Fatalf("stale policy handoff code = %s, want aborted", connect.CodeOf(err))
	}
	response, err := service.RecordMcpElicitation(auth.WithPrincipal(context.Background(), principal), connect.NewRequest(&roomv1.RecordMcpElicitationRequest{Receipt: receipt}))
	if err != nil || response.Msg.GetAuditEventId() == "" {
		t.Fatalf("record current policy handoff: response %+v, err %v", response, err)
	}
	updated := proto.Clone(stored).(*roomv1.PolicyCandidate)
	updated.UpdatedAt = nil
	updated.MinimumConfidenceBasisPoints = 8500
	for _, trigger := range updated.GetProposedRule().GetTriggers() {
		trigger.MinimumConfidenceBasisPoints = 8500
	}
	if _, err := database.UpsertPolicyCandidate(updated); err != nil {
		t.Fatalf("update candidate after offer: %v", err)
	}
	final := proto.Clone(receipt).(*roomv1.McpElicitationReceipt)
	final.Action = roomv1.McpElicitationAction_MCP_ELICITATION_ACTION_ACCEPT
	final.OfferAuditEventId = response.Msg.GetAuditEventId()
	finalResponse, err := service.RecordMcpElicitation(auth.WithPrincipal(context.Background(), principal), connect.NewRequest(&roomv1.RecordMcpElicitationRequest{Receipt: final}))
	if err != nil || finalResponse.Msg.GetAuditEventId() == "" {
		t.Fatalf("record final handoff after candidate update: response %+v, err %v", finalResponse, err)
	}
	finalAudit, err := database.AuditEvent(finalResponse.Msg.GetAuditEventId())
	if err != nil || finalAudit.GetMcpElicitation().GetOfferAuditEventId() != response.Msg.GetAuditEventId() {
		t.Fatalf("final audit offer binding = %+v, err %v", finalAudit.GetMcpElicitation(), err)
	}
	forged := proto.Clone(final).(*roomv1.McpElicitationReceipt)
	forged.ExpectedCandidateUpdatedAt = timestamppb.New(final.GetExpectedCandidateUpdatedAt().AsTime().Add(time.Nanosecond))
	if _, err := service.RecordMcpElicitation(auth.WithPrincipal(context.Background(), principal), connect.NewRequest(&roomv1.RecordMcpElicitationRequest{Receipt: forged})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("forged offer binding code = %s, want permission denied", connect.CodeOf(err))
	}
	audits, err := database.ListAudit(10, roomv1.AuditEventKind_AUDIT_EVENT_KIND_MCP_ELICITATION)
	if err != nil {
		t.Fatalf("list policy handoff audits: %v", err)
	}
	foundCandidateAudit := false
	for _, audit := range audits {
		if audit.GetPolicyCandidateId() == candidate.GetId() {
			foundCandidateAudit = true
			break
		}
	}
	if !foundCandidateAudit {
		t.Fatalf("policy handoff audit not discoverable by candidate %q: %+v", candidate.GetId(), audits)
	}
	unchanged, err := database.PolicyCandidate(candidate.GetId())
	if err != nil || unchanged.GetRolloutStage() != roomv1.RolloutStage_ROLLOUT_STAGE_DRAFT {
		t.Fatalf("policy handoff mutated candidate: stage %v, err %v", unchanged.GetRolloutStage(), err)
	}
}

func TestValidateMcpElicitationReceiptRejectsPurposeModeMismatch(t *testing.T) {
	for _, receipt := range []*roomv1.McpElicitationReceipt{
		{Id: "form-as-url", EvaluationId: "evaluation-1", EvaluationAuditEventId: "audit-1", Mode: roomv1.McpElicitationMode_MCP_ELICITATION_MODE_URL, Purpose: roomv1.McpElicitationPurpose_MCP_ELICITATION_PURPOSE_EVALUATION_RESOLUTION, Action: roomv1.McpElicitationAction_MCP_ELICITATION_ACTION_DECLINE},
		{Id: "url-as-form", PolicyCandidateId: "candidate-1", Mode: roomv1.McpElicitationMode_MCP_ELICITATION_MODE_FORM, Purpose: roomv1.McpElicitationPurpose_MCP_ELICITATION_PURPOSE_POLICY_CONTROL, Action: roomv1.McpElicitationAction_MCP_ELICITATION_ACTION_DECLINE, TargetRolloutStage: roomv1.RolloutStage_ROLLOUT_STAGE_BLOCK},
	} {
		if err := validateMcpElicitationReceipt(receipt); err == nil {
			t.Fatalf("accepted purpose/mode mismatch: %+v", receipt)
		}
	}
}

func TestValidateMcpElicitationReceiptEnforcesClosedResolutionContract(t *testing.T) {
	valid := &roomv1.McpElicitationReceipt{
		Id: "elicitation", EvaluationId: "evaluation", EvaluationAuditEventId: "evaluation-audit",
		Mode: roomv1.McpElicitationMode_MCP_ELICITATION_MODE_FORM, Purpose: roomv1.McpElicitationPurpose_MCP_ELICITATION_PURPOSE_EVALUATION_RESOLUTION,
		Action: roomv1.McpElicitationAction_MCP_ELICITATION_ACTION_ACCEPT, Resolution: roomv1.McpResolutionAction_MCP_RESOLUTION_ACTION_REVISE,
	}
	if err := validateMcpElicitationReceipt(valid); err != nil {
		t.Fatalf("valid accepted evaluation resolution rejected: %v", err)
	}
	unknown := proto.Clone(valid).(*roomv1.McpElicitationReceipt)
	unknown.Resolution = roomv1.McpResolutionAction(999)
	if err := validateMcpElicitationReceipt(unknown); err == nil {
		t.Fatal("unknown numeric resolution was accepted")
	}
	nonAccept := proto.Clone(valid).(*roomv1.McpElicitationReceipt)
	nonAccept.Action = roomv1.McpElicitationAction_MCP_ELICITATION_ACTION_DECLINE
	if err := validateMcpElicitationReceipt(nonAccept); err == nil {
		t.Fatal("resolution on declined receipt was accepted")
	}
	policy := &roomv1.McpElicitationReceipt{
		Id: "policy", PolicyCandidateId: "candidate", Mode: roomv1.McpElicitationMode_MCP_ELICITATION_MODE_URL,
		Purpose: roomv1.McpElicitationPurpose_MCP_ELICITATION_PURPOSE_POLICY_CONTROL, Action: roomv1.McpElicitationAction_MCP_ELICITATION_ACTION_OFFERED,
		Resolution: roomv1.McpResolutionAction_MCP_RESOLUTION_ACTION_OPEN_CONTROL_PLANE, TargetRolloutStage: roomv1.RolloutStage_ROLLOUT_STAGE_BLOCK,
	}
	if err := validateMcpElicitationReceipt(policy); err == nil {
		t.Fatal("resolution on policy control receipt was accepted")
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

func TestReviewerCannotBypassHumanPolicyPublication(t *testing.T) {
	database, err := store.Open(filepath.Join(t.TempDir(), "room.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	service := New(database)
	reviewer := auth.WithPrincipal(context.Background(), auth.Principal{ID: "review-bot", Role: auth.RoleReviewer})
	if _, err := service.IngestReviewFinding(reviewer, connect.NewRequest(&roomv1.IngestReviewFindingRequest{Finding: &roomv1.ReviewFinding{Id: "f", Source: &roomv1.ReviewSource{Repository: "evalops/room"}, ClaimKind: roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_PROTOCOL_CONTRACT, Severity: roomv1.Severity_SEVERITY_HIGH}})); err != nil {
		t.Fatalf("reviewer ingestion rejected: %v", err)
	}
	if _, err := service.PublishRuleset(reviewer, connect.NewRequest(&roomv1.PublishRulesetRequest{})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("reviewer publish code = %s, want permission denied", connect.CodeOf(err))
	}
	admin := auth.WithPrincipal(context.Background(), auth.Principal{ID: "automation-admin", Role: auth.RoleAdmin})
	if _, err := service.PublishRuleset(admin, connect.NewRequest(&roomv1.PublishRulesetRequest{})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("non-human admin publish code = %s, want permission denied", connect.CodeOf(err))
	}
	human := auth.WithPrincipal(context.Background(), auth.Principal{ID: "operator", Role: auth.RoleAdmin, HumanOperator: true})
	if _, err := service.PublishRuleset(human, connect.NewRequest(&roomv1.PublishRulesetRequest{Author: "operator"})); err != nil {
		t.Fatalf("human publish rejected: %v", err)
	}
}

func TestProtectedOrgPolicyRequiresHumanApprovalToBlock(t *testing.T) {
	candidate := &roomv1.PolicyCandidate{RolloutStage: roomv1.RolloutStage_ROLLOUT_STAGE_WARN, ProtectedOrgPolicy: true}
	replay := &roomv1.PolicyReplayRun{PolicyCandidateId: candidate.GetId(), Metrics: &roomv1.PolicyMetrics{AcceptedCount: 1, TruePositiveCount: 1, PrecisionBasisPoints: 10000, RecallBasisPoints: 10000}}
	replay.PolicyCandidateSha256, _ = intelligence.CandidateDigest(candidate)
	if err := validateRolloutTransition(candidate, roomv1.RolloutStage_ROLLOUT_STAGE_BLOCK, false, replay); err == nil {
		t.Fatal("protected org policy advanced to blocking without human approval")
	}
	if err := validateRolloutTransition(candidate, roomv1.RolloutStage_ROLLOUT_STAGE_BLOCK, true, replay); err != nil {
		t.Fatalf("approved transition rejected: %v", err)
	}
	if err := validateRolloutTransition(candidate, roomv1.RolloutStage_ROLLOUT_STAGE_SHADOW, true, replay); err == nil {
		t.Fatal("backward non-rollback transition accepted")
	}
	if err := validateRolloutTransition(candidate, roomv1.RolloutStage_ROLLOUT_STAGE_ROLLED_BACK, false, replay); err == nil {
		t.Fatal("emergency rollback accepted without human operator")
	}
	if err := validateRolloutTransition(candidate, roomv1.RolloutStage_ROLLOUT_STAGE_ROLLED_BACK, true, replay); err != nil {
		t.Fatalf("human emergency rollback rejected: %v", err)
	}
}

func TestRolloutPromotionRequiresReplayQualityGates(t *testing.T) {
	draft := &roomv1.PolicyCandidate{Id: "candidate", RolloutStage: roomv1.RolloutStage_ROLLOUT_STAGE_DRAFT}
	if err := validateRolloutTransition(draft, roomv1.RolloutStage_ROLLOUT_STAGE_SHADOW, false, nil); err == nil {
		t.Fatal("shadow promotion accepted without replay")
	}
	shadow := &roomv1.PolicyCandidate{Id: "candidate", RolloutStage: roomv1.RolloutStage_ROLLOUT_STAGE_SHADOW}
	weak := &roomv1.PolicyReplayRun{PolicyCandidateId: "candidate", Metrics: &roomv1.PolicyMetrics{AcceptedCount: 1, PrecisionBasisPoints: 7000, RecallBasisPoints: 9000}}
	weak.PolicyCandidateSha256, _ = intelligence.CandidateDigest(shadow)
	if err := validateRolloutTransition(shadow, roomv1.RolloutStage_ROLLOUT_STAGE_WARN, false, weak); err == nil {
		t.Fatal("warn promotion accepted below precision gate")
	}
	strong := &roomv1.PolicyReplayRun{PolicyCandidateId: "candidate", Metrics: &roomv1.PolicyMetrics{AcceptedCount: 1, PrecisionBasisPoints: 9000, RecallBasisPoints: 7000}}
	strong.PolicyCandidateSha256, _ = intelligence.CandidateDigest(shadow)
	if err := validateRolloutTransition(shadow, roomv1.RolloutStage_ROLLOUT_STAGE_WARN, false, strong); err != nil {
		t.Fatalf("qualified warn promotion rejected: %v", err)
	}
}

func TestRolloutPromotionRejectsReplayFromStaleCandidateRevision(t *testing.T) {
	candidate := &roomv1.PolicyCandidate{Id: "candidate", RolloutStage: roomv1.RolloutStage_ROLLOUT_STAGE_DRAFT, MinimumConfidenceBasisPoints: 8000}
	replay := &roomv1.PolicyReplayRun{PolicyCandidateId: candidate.GetId(), Metrics: &roomv1.PolicyMetrics{AcceptedCount: 1}}
	replay.PolicyCandidateSha256, _ = intelligence.CandidateDigest(candidate)
	candidate.MinimumConfidenceBasisPoints = 9000
	if err := validateRolloutTransition(candidate, roomv1.RolloutStage_ROLLOUT_STAGE_SHADOW, false, replay); err == nil {
		t.Fatal("promotion accepted replay from stale candidate revision")
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

func TestAgentEvaluationUsesTrustedAnalyzerClassification(t *testing.T) {
	database, err := store.Open(filepath.Join(t.TempDir(), "room.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer database.Close()
	for _, rule := range database.ListRules(true) {
		if _, err := database.DeleteRule(rule.GetId()); err != nil {
			t.Fatalf("delete default rule %q: %v", rule.GetId(), err)
		}
	}
	_, err = database.UpsertRule(&roomv1.Rule{
		Id: "rust-only", Title: "Rust only", Description: "classified by the trusted analyzer", Enabled: true, Severity: roomv1.Severity_SEVERITY_CRITICAL,
		Scope:            &roomv1.RuleScope{Languages: []string{"rust"}},
		Triggers:         []*roomv1.SignalSelector{{Signal: roomv1.SignalKind_SIGNAL_KIND_SECRET_LITERAL, Phases: []roomv1.AnalysisPhase{roomv1.AnalysisPhase_ANALYSIS_PHASE_DIFF}, MinimumConfidenceBasisPoints: 8000}},
		RequiredCoverage: []roomv1.SignalKind{roomv1.SignalKind_SIGNAL_KIND_SECRET_LITERAL},
	})
	if err != nil {
		t.Fatalf("upsert classified rule: %v", err)
	}
	if _, err := database.Publish("test", "trusted classification"); err != nil {
		t.Fatalf("publish classified rule: %v", err)
	}

	provider := newClassifiedAnalyzer("go")
	service := New(database, WithAnalyzer(provider))
	ctx := auth.WithPrincipal(context.Background(), auth.Principal{ID: "agent", Role: auth.RoleAgent, Scope: auth.Scope{WorkspaceID: "w", Repository: "r", AgentID: "a"}})
	request := connect.NewRequest(&roomv1.EvaluateDiffRequest{Input: &roomv1.EvaluationInput{
		Diff: "classified artifact", Context: &roomv1.EvaluationContext{Languages: []string{"rust"}},
	}})
	response, err := service.EvaluateDiff(ctx, request)
	if err != nil {
		t.Fatalf("evaluate analyzer language mismatch: %v", err)
	}
	if response.Msg.GetResult().GetDecision() != roomv1.Decision_DECISION_ALLOW {
		t.Fatalf("forged caller language narrowed analyzer scope: %+v", response.Msg.GetResult())
	}

	provider.language = "rust"
	response, err = service.EvaluateDiff(ctx, request)
	if err != nil {
		t.Fatalf("evaluate analyzer language match: %v", err)
	}
	if response.Msg.GetResult().GetDecision() != roomv1.Decision_DECISION_DENY {
		t.Fatalf("trusted analyzer language did not activate rule: %+v", response.Msg.GetResult())
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

type classifiedAnalyzer struct {
	identity *roomv1.AnalyzerIdentity
	language string
}

func newClassifiedAnalyzer(language string) *classifiedAnalyzer {
	return &classifiedAnalyzer{identity: &roomv1.AnalyzerIdentity{Id: "classifier", Version: "1", ConfigSha256: make([]byte, 32)}, language: language}
}

func (a *classifiedAnalyzer) Identity() *roomv1.AnalyzerIdentity { return a.identity }

func (a *classifiedAnalyzer) Analyze(_ context.Context, input analyzer.Input) *roomv1.AnalysisReport {
	digest := sha256.Sum256(input.Content)
	signal := &roomv1.SecuritySignal{Kind: roomv1.SignalKind_SIGNAL_KIND_SECRET_LITERAL, Fingerprint: "secret", Analyzer: a.identity, ConfidenceBasisPoints: 10000}
	receipt := &roomv1.AnalyzerReceipt{
		Analyzer: a.identity, Status: roomv1.AnalysisStatus_ANALYSIS_STATUS_COMPLETE,
		CoveredSignals: []roomv1.SignalKind{roomv1.SignalKind_SIGNAL_KIND_SECRET_LITERAL}, Signals: []*roomv1.SecuritySignal{signal}, InputSha256: digest[:],
	}
	return &roomv1.AnalysisReport{
		Status:   roomv1.AnalysisStatus_ANALYSIS_STATUS_COMPLETE,
		Artifact: &roomv1.ArtifactRef{Phase: input.Phase, Sha256: digest[:], Languages: []string{a.language}},
		Receipts: []*roomv1.AnalyzerReceipt{receipt},
	}
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
