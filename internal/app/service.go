package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"connectrpc.com/connect"
	roomv1 "github.com/haasonsaas/room/gen/go/room/v1"
	"github.com/haasonsaas/room/internal/analyzer"
	"github.com/haasonsaas/room/internal/auth"
	"github.com/haasonsaas/room/internal/compliance"
	"github.com/haasonsaas/room/internal/eval"
	"github.com/haasonsaas/room/internal/intelligence"
	"github.com/haasonsaas/room/internal/store"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Service struct {
	store            *store.Store
	analyzer         analyzer.Analyzer
	evaluationPolicy *eval.Policy
	auditOnly        bool
}

type RuleAdmin struct{ *Service }
type AgentRules struct{ *Service }

type Option func(*Service)

func WithAnalyzer(value analyzer.Analyzer) Option { return func(s *Service) { s.analyzer = value } }
func WithAuditOnly(value bool) Option             { return func(s *Service) { s.auditOnly = value } }

func New(ruleStore *store.Store, options ...Option) *Service {
	s := &Service{store: ruleStore}
	for _, option := range options {
		option(s)
	}
	var trusted []*roomv1.AnalyzerIdentity
	if s.analyzer != nil {
		trusted = []*roomv1.AnalyzerIdentity{s.analyzer.Identity()}
	}
	s.evaluationPolicy = eval.NewPolicy(trusted, s.auditOnly)
	return s
}

func (s *Service) Admin() *RuleAdmin  { return &RuleAdmin{Service: s} }
func (s *Service) Agent() *AgentRules { return &AgentRules{Service: s} }

func (s *Service) CreateRule(ctx context.Context, req *connect.Request[roomv1.CreateRuleRequest]) (*connect.Response[roomv1.CreateRuleResponse], error) {
	if err := requireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	rule, err := s.store.UpsertRule(req.Msg.GetRule())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	return connect.NewResponse(&roomv1.CreateRuleResponse{Rule: rule}), nil
}

func (s *Service) UpdateRule(ctx context.Context, req *connect.Request[roomv1.UpdateRuleRequest]) (*connect.Response[roomv1.UpdateRuleResponse], error) {
	if err := requireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	rule, err := s.store.UpsertRule(req.Msg.GetRule())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	return connect.NewResponse(&roomv1.UpdateRuleResponse{Rule: rule}), nil
}

func (s *Service) DeleteRule(ctx context.Context, req *connect.Request[roomv1.DeleteRuleRequest]) (*connect.Response[roomv1.DeleteRuleResponse], error) {
	if err := requireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	deleted, err := s.store.DeleteRule(req.Msg.GetRuleId())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&roomv1.DeleteRuleResponse{Deleted: deleted}), nil
}

func (s *Service) ListRules(ctx context.Context, req *connect.Request[roomv1.ListRulesRequest]) (*connect.Response[roomv1.ListRulesResponse], error) {
	if err := requireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	return connect.NewResponse(&roomv1.ListRulesResponse{Rules: s.store.ListRules(req.Msg.GetIncludeDisabled())}), nil
}

func (s *Service) PreviewRuleset(ctx context.Context, req *connect.Request[roomv1.PreviewRulesetRequest]) (*connect.Response[roomv1.PreviewRulesetResponse], error) {
	if err := requireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	rules := req.Msg.GetRules()
	if len(rules) == 0 {
		rules = s.store.ListRules(false)
	}
	base := s.store.ActiveRuleset()
	preview := &roomv1.RulesetVersion{Id: "preview", Version: base.GetVersion(), Rules: rules, Hash: base.GetHash()}
	input := req.Msg.GetInput()
	phase, content, phaseErr := phaseAndContent(input)
	if phaseErr != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, phaseErr)
	}
	report := s.analyze(ctx, phase, content, input.GetContext().GetChangedFiles())
	result := s.evaluationPolicy.Evaluate(preview, input.GetContext(), report)
	return connect.NewResponse(&roomv1.PreviewRulesetResponse{Result: result}), nil
}

func (s *Service) PublishRuleset(ctx context.Context, req *connect.Request[roomv1.PublishRulesetRequest]) (*connect.Response[roomv1.PublishRulesetResponse], error) {
	principal, err := principalForHumanAdmin(ctx)
	if err != nil {
		return nil, err
	}
	audit := &roomv1.AuditEvent{Kind: roomv1.AuditEventKind_AUDIT_EVENT_KIND_RULESET_PUBLISHED, SubjectId: principal.ID}
	ruleset, publishErr := s.store.PublishAudited(req.Msg.GetAuthor(), req.Msg.GetNotes(), audit)
	if publishErr != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, publishErr)
	}
	return connect.NewResponse(&roomv1.PublishRulesetResponse{Ruleset: ruleset}), nil
}

func (s *Service) RollbackRuleset(ctx context.Context, req *connect.Request[roomv1.RollbackRulesetRequest]) (*connect.Response[roomv1.RollbackRulesetResponse], error) {
	principal, err := principalForHumanAdmin(ctx)
	if err != nil {
		return nil, err
	}
	audit := &roomv1.AuditEvent{Kind: roomv1.AuditEventKind_AUDIT_EVENT_KIND_RULESET_ROLLED_BACK, SubjectId: principal.ID}
	ruleset, rollbackErr := s.store.RollbackAudited(req.Msg.GetVersion(), audit)
	if rollbackErr != nil {
		return nil, connect.NewError(connect.CodeNotFound, rollbackErr)
	}
	return connect.NewResponse(&roomv1.RollbackRulesetResponse{Ruleset: ruleset}), nil
}

func (a *RuleAdmin) GetActiveRuleset(ctx context.Context, _ *connect.Request[roomv1.RuleAdminServiceGetActiveRulesetRequest]) (*connect.Response[roomv1.RuleAdminServiceGetActiveRulesetResponse], error) {
	if err := requireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	return connect.NewResponse(&roomv1.RuleAdminServiceGetActiveRulesetResponse{Ruleset: a.store.ActiveRuleset()}), nil
}

func (a *AgentRules) GetActiveRuleset(ctx context.Context, _ *connect.Request[roomv1.AgentRulesServiceGetActiveRulesetRequest]) (*connect.Response[roomv1.AgentRulesServiceGetActiveRulesetResponse], error) {
	principal, err := principalForRole(ctx, auth.RoleAgent)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&roomv1.AgentRulesServiceGetActiveRulesetResponse{Ruleset: scopedRuleset(a.store.ActiveRuleset(), principal)}), nil
}

func (s *Service) WatchRuleset(ctx context.Context, req *connect.Request[roomv1.WatchRulesetRequest], stream *connect.ServerStream[roomv1.WatchRulesetResponse]) error {
	principal, err := principalForRole(ctx, auth.RoleAgent)
	if err != nil {
		return err
	}
	lastVersion := req.Msg.GetCurrentVersion()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		ruleset := scopedRuleset(s.store.ActiveRulesetIfChanged(lastVersion), principal)
		if ruleset != nil {
			if err := stream.Send(&roomv1.WatchRulesetResponse{Ruleset: ruleset}); err != nil {
				return err
			}
			lastVersion = ruleset.GetVersion()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (s *Service) EvaluatePlan(ctx context.Context, req *connect.Request[roomv1.EvaluatePlanRequest]) (*connect.Response[roomv1.EvaluatePlanResponse], error) {
	result, err := s.evaluate(ctx, roomv1.AnalysisPhase_ANALYSIS_PHASE_PLAN, req.Msg.GetInput())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&roomv1.EvaluatePlanResponse{Result: result}), nil
}

func (s *Service) EvaluateDiff(ctx context.Context, req *connect.Request[roomv1.EvaluateDiffRequest]) (*connect.Response[roomv1.EvaluateDiffResponse], error) {
	result, err := s.evaluate(ctx, roomv1.AnalysisPhase_ANALYSIS_PHASE_DIFF, req.Msg.GetInput())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&roomv1.EvaluateDiffResponse{Result: result}), nil
}

func (s *Service) evaluate(ctx context.Context, phase roomv1.AnalysisPhase, input *roomv1.EvaluationInput) (*roomv1.EvaluationResult, error) {
	principal, err := principalForRole(ctx, auth.RoleAgent)
	if err != nil {
		return nil, err
	}
	verified := authorizedContext(principal, nil)
	if input != nil {
		verified = authorizedContext(principal, input.GetContext())
	}
	content := ""
	if input != nil && phase == roomv1.AnalysisPhase_ANALYSIS_PHASE_PLAN {
		content = input.GetPlan()
	}
	if input != nil && phase == roomv1.AnalysisPhase_ANALYSIS_PHASE_DIFF {
		content = input.GetDiff()
	}
	report := s.analyze(ctx, phase, []byte(content), verified.GetChangedFiles())
	ruleset := scopedRuleset(s.store.ActiveRuleset(), principal)
	result := s.evaluationPolicy.Evaluate(ruleset, verified, report)
	eventID, auditErr := s.store.AppendAudit(evaluationEvent(principal, phase, result))
	if auditErr != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("persist evaluation audit: %w", auditErr))
	}
	result.AuditEventId = eventID
	return result, nil
}

func (s *Service) EvaluateMcpInvocation(ctx context.Context, req *connect.Request[roomv1.EvaluateMcpInvocationRequest]) (*connect.Response[roomv1.EvaluateMcpInvocationResponse], error) {
	principal, err := principalForRole(ctx, auth.RoleAgent)
	if err != nil {
		return nil, err
	}
	ruleset := scopedRuleset(s.store.ActiveRuleset(), principal)
	invocation := authenticatedMCPInvocation(principal, req.Msg.GetInvocation())
	decision := compliance.Evaluate(ruleset.GetMcpPolicy(), invocation)
	event := &roomv1.AuditEvent{Kind: roomv1.AuditEventKind_AUDIT_EVENT_KIND_MCP_INVOCATION, SubjectId: principal.ID, WorkspaceId: principal.Scope.WorkspaceID, Repository: principal.Scope.Repository, AgentType: principal.Scope.AgentID, RulesetId: ruleset.GetId(), RulesetVersion: ruleset.GetVersion(), RulesetHash: ruleset.GetHash(), McpInvocation: invocation, ReasonCode: decision.GetReasonCode()}
	if !decision.GetAllowed() {
		event.Decision = roomv1.Decision_DECISION_DENY
	} else {
		event.Decision = roomv1.Decision_DECISION_ALLOW
	}
	eventID, auditErr := s.store.AppendAudit(event)
	if auditErr != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("persist MCP audit: %w", auditErr))
	}
	return connect.NewResponse(&roomv1.EvaluateMcpInvocationResponse{Decision: decision, AuditEventId: eventID}), nil
}

func (s *Service) RecordMcpElicitation(ctx context.Context, req *connect.Request[roomv1.RecordMcpElicitationRequest]) (*connect.Response[roomv1.RecordMcpElicitationResponse], error) {
	principal, err := principalForRole(ctx, auth.RoleAgent)
	if err != nil {
		return nil, err
	}
	receipt := req.Msg.GetReceipt()
	if err := validateMcpElicitationReceipt(receipt); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if receipt.GetPurpose() == roomv1.McpElicitationPurpose_MCP_ELICITATION_PURPOSE_EVALUATION_RESOLUTION {
		evaluationAudit, lookupErr := s.store.AuditEvent(receipt.GetEvaluationAuditEventId())
		if lookupErr != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("load evaluation audit: %w", lookupErr))
		}
		if evaluationAudit == nil || evaluationAudit.GetKind() != roomv1.AuditEventKind_AUDIT_EVENT_KIND_EVALUATION || evaluationAudit.GetEvaluationId() != receipt.GetEvaluationId() || !auditScopeMatchesPrincipal(evaluationAudit, principal) {
			return nil, connect.NewError(connect.CodePermissionDenied, errors.New("evaluation audit is not bound to the authenticated agent scope"))
		}
	}
	if receipt.GetPurpose() == roomv1.McpElicitationPurpose_MCP_ELICITATION_PURPOSE_POLICY_CONTROL {
		candidate, lookupErr := s.store.PolicyCandidate(receipt.GetPolicyCandidateId())
		if lookupErr != nil {
			return nil, connect.NewError(connect.CodeInternal, lookupErr)
		}
		if candidate == nil {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("policy candidate not found"))
		}
		repository, repositoryErr := candidateRepository(candidate)
		if repositoryErr != nil {
			return nil, connect.NewError(connect.CodeFailedPrecondition, repositoryErr)
		}
		localHumanAdmin := principal.Role == auth.RoleAdmin && principal.HumanOperator && principal.Scope.Repository == ""
		if repository != principal.Scope.Repository && !localHumanAdmin {
			return nil, connect.NewError(connect.CodePermissionDenied, errors.New("policy candidate is outside the authenticated repository scope"))
		}
		if receipt.GetExpectedCandidateUpdatedAt() == nil || !proto.Equal(receipt.GetExpectedCandidateUpdatedAt(), candidate.GetUpdatedAt()) {
			return nil, connect.NewError(connect.CodeAborted, errors.New("policy candidate changed; refresh before opening human controls"))
		}
	}
	receipt = proto.Clone(receipt).(*roomv1.McpElicitationReceipt)
	receipt.OccurredAt = timestamppb.Now()
	event := &roomv1.AuditEvent{
		Kind: roomv1.AuditEventKind_AUDIT_EVENT_KIND_MCP_ELICITATION, OccurredAt: timestamppb.Now(),
		SubjectId: principal.ID, WorkspaceId: principal.Scope.WorkspaceID, Repository: principal.Scope.Repository, AgentType: principal.Scope.AgentID,
		PolicyCandidateId: receipt.GetPolicyCandidateId(), EvidenceRecordId: receipt.GetId(), McpElicitation: receipt,
	}
	eventID, err := s.store.AppendAudit(event)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("persist MCP elicitation audit: %w", err))
	}
	return connect.NewResponse(&roomv1.RecordMcpElicitationResponse{AuditEventId: eventID}), nil
}

func validateMcpElicitationReceipt(receipt *roomv1.McpElicitationReceipt) error {
	if receipt == nil || strings.TrimSpace(receipt.GetId()) == "" {
		return errors.New("MCP elicitation id is required")
	}
	if receipt.GetMode() == roomv1.McpElicitationMode_MCP_ELICITATION_MODE_UNSPECIFIED || roomv1.McpElicitationMode_name[int32(receipt.GetMode())] == "" {
		return errors.New("MCP elicitation mode is required")
	}
	if receipt.GetPurpose() == roomv1.McpElicitationPurpose_MCP_ELICITATION_PURPOSE_UNSPECIFIED || roomv1.McpElicitationPurpose_name[int32(receipt.GetPurpose())] == "" {
		return errors.New("MCP elicitation purpose is required")
	}
	if receipt.GetAction() == roomv1.McpElicitationAction_MCP_ELICITATION_ACTION_UNSPECIFIED || roomv1.McpElicitationAction_name[int32(receipt.GetAction())] == "" {
		return errors.New("MCP elicitation action is required")
	}
	if receipt.GetPurpose() == roomv1.McpElicitationPurpose_MCP_ELICITATION_PURPOSE_EVALUATION_RESOLUTION && strings.TrimSpace(receipt.GetEvaluationId()) == "" {
		return errors.New("evaluation resolution elicitation requires an evaluation id")
	}
	if receipt.GetPurpose() == roomv1.McpElicitationPurpose_MCP_ELICITATION_PURPOSE_EVALUATION_RESOLUTION && receipt.GetMode() != roomv1.McpElicitationMode_MCP_ELICITATION_MODE_FORM {
		return errors.New("evaluation resolution elicitation requires form mode")
	}
	if receipt.GetPurpose() == roomv1.McpElicitationPurpose_MCP_ELICITATION_PURPOSE_EVALUATION_RESOLUTION && strings.TrimSpace(receipt.GetEvaluationAuditEventId()) == "" {
		return errors.New("evaluation resolution elicitation requires an evaluation audit event id")
	}
	if receipt.GetPurpose() == roomv1.McpElicitationPurpose_MCP_ELICITATION_PURPOSE_POLICY_CONTROL && strings.TrimSpace(receipt.GetPolicyCandidateId()) == "" {
		return errors.New("policy control elicitation requires a policy candidate id")
	}
	if receipt.GetPurpose() == roomv1.McpElicitationPurpose_MCP_ELICITATION_PURPOSE_POLICY_CONTROL && receipt.GetMode() != roomv1.McpElicitationMode_MCP_ELICITATION_MODE_URL {
		return errors.New("policy control elicitation requires URL mode")
	}
	if receipt.GetPurpose() == roomv1.McpElicitationPurpose_MCP_ELICITATION_PURPOSE_POLICY_CONTROL {
		switch receipt.GetTargetRolloutStage() {
		case roomv1.RolloutStage_ROLLOUT_STAGE_BLOCK, roomv1.RolloutStage_ROLLOUT_STAGE_PAUSED, roomv1.RolloutStage_ROLLOUT_STAGE_ROLLED_BACK:
		default:
			return errors.New("policy control elicitation target must be block, paused, or rolled back")
		}
	}
	if receipt.GetAction() == roomv1.McpElicitationAction_MCP_ELICITATION_ACTION_ACCEPT && receipt.GetPurpose() == roomv1.McpElicitationPurpose_MCP_ELICITATION_PURPOSE_EVALUATION_RESOLUTION && receipt.GetResolution() == roomv1.McpResolutionAction_MCP_RESOLUTION_ACTION_UNSPECIFIED {
		return errors.New("accepted evaluation resolution requires a typed resolution")
	}
	return nil
}

func auditScopeMatchesPrincipal(event *roomv1.AuditEvent, principal auth.Principal) bool {
	return event.GetSubjectId() == principal.ID && event.GetWorkspaceId() == principal.Scope.WorkspaceID && event.GetRepository() == principal.Scope.Repository && event.GetAgentType() == principal.Scope.AgentID
}

func (s *Service) ReportEvaluation(ctx context.Context, req *connect.Request[roomv1.ReportEvaluationRequest]) (*connect.Response[roomv1.ReportEvaluationResponse], error) {
	principal, err := principalForRole(ctx, auth.RoleAgent)
	if err != nil {
		return nil, err
	}
	result := req.Msg.GetResult()
	if result == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("result is required"))
	}
	event, err := s.store.AuditEvent(result.GetAuditEventId())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if event == nil || event.GetKind() != roomv1.AuditEventKind_AUDIT_EVENT_KIND_EVALUATION ||
		event.GetSubjectId() != principal.ID || event.GetWorkspaceId() != principal.Scope.WorkspaceID ||
		event.GetRepository() != principal.Scope.Repository || event.GetAgentType() != principal.Scope.AgentID ||
		event.GetRulesetId() != result.GetRulesetId() || event.GetRulesetVersion() != result.GetRulesetVersion() ||
		event.GetRulesetHash() != result.GetRulesetHash() || event.GetDecision() != result.GetDecision() ||
		event.GetAnalysisStatus() != result.GetAnalysisStatus() {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("evaluation receipt does not match a server audit event"))
	}
	return connect.NewResponse(&roomv1.ReportEvaluationResponse{Accepted: true}), nil
}

func (s *Service) GetMcpPolicy(ctx context.Context, _ *connect.Request[roomv1.GetMcpPolicyRequest]) (*connect.Response[roomv1.GetMcpPolicyResponse], error) {
	if err := requireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	return connect.NewResponse(&roomv1.GetMcpPolicyResponse{Policy: s.store.MCPPolicy()}), nil
}

func (s *Service) UpdateMcpPolicy(ctx context.Context, req *connect.Request[roomv1.UpdateMcpPolicyRequest]) (*connect.Response[roomv1.UpdateMcpPolicyResponse], error) {
	principal, err := principalForHumanAdmin(ctx)
	if err != nil {
		return nil, err
	}
	audit := &roomv1.AuditEvent{Kind: roomv1.AuditEventKind_AUDIT_EVENT_KIND_POLICY_UPDATED, SubjectId: principal.ID}
	policy, updateErr := s.store.UpdateMCPPolicyAudited(req.Msg.GetPolicy(), audit)
	if updateErr != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, updateErr)
	}
	return connect.NewResponse(&roomv1.UpdateMcpPolicyResponse{Policy: policy}), nil
}

func (s *Service) ListAuditEvents(ctx context.Context, req *connect.Request[roomv1.ListAuditEventsRequest]) (*connect.Response[roomv1.ListAuditEventsResponse], error) {
	if err := requireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	events, err := s.store.ListAudit(req.Msg.GetLimit(), req.Msg.GetKind())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&roomv1.ListAuditEventsResponse{Events: events}), nil
}

func (s *Service) IngestReviewFinding(ctx context.Context, req *connect.Request[roomv1.IngestReviewFindingRequest]) (*connect.Response[roomv1.IngestReviewFindingResponse], error) {
	principal, err := principalForReview(ctx)
	if err != nil {
		return nil, err
	}
	requested := req.Msg.GetFinding()
	audit := &roomv1.AuditEvent{Kind: roomv1.AuditEventKind_AUDIT_EVENT_KIND_REVIEW_FINDING_INGESTED, SubjectId: principal.ID}
	if requested != nil {
		audit.Repository = requested.GetSource().GetRepository()
		audit.EvidenceRecordId = requested.GetId()
	}
	finding, err := s.store.UpsertReviewFindingAudited(requested, audit)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	return connect.NewResponse(&roomv1.IngestReviewFindingResponse{Finding: finding}), nil
}

func (s *Service) RecordReviewOutcome(ctx context.Context, req *connect.Request[roomv1.RecordReviewOutcomeRequest]) (*connect.Response[roomv1.RecordReviewOutcomeResponse], error) {
	principal, err := principalForReview(ctx)
	if err != nil {
		return nil, err
	}
	outcome := req.Msg.GetOutcome()
	if outcome != nil {
		outcome = proto.Clone(outcome).(*roomv1.ReviewOutcome)
		outcome.ActorId = principal.ID
	}
	audit := &roomv1.AuditEvent{Kind: roomv1.AuditEventKind_AUDIT_EVENT_KIND_REVIEW_OUTCOME_RECORDED, SubjectId: principal.ID, EvidenceRecordId: outcome.GetId()}
	finding, err := s.store.AppendReviewOutcomeAudited(req.Msg.GetFindingId(), outcome, audit)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	return connect.NewResponse(&roomv1.RecordReviewOutcomeResponse{Finding: finding}), nil
}

func (s *Service) AdjudicateReviewFinding(ctx context.Context, req *connect.Request[roomv1.AdjudicateReviewFindingRequest]) (*connect.Response[roomv1.AdjudicateReviewFindingResponse], error) {
	principal, err := principalForReview(ctx)
	if err != nil {
		return nil, err
	}
	adjudication := req.Msg.GetAdjudication()
	if adjudication != nil {
		adjudication = proto.Clone(adjudication).(*roomv1.ReviewAdjudication)
		adjudication.AgentId = principal.ID
	}
	audit := &roomv1.AuditEvent{Kind: roomv1.AuditEventKind_AUDIT_EVENT_KIND_REVIEW_ADJUDICATED, SubjectId: principal.ID, EvidenceRecordId: adjudication.GetId()}
	finding, err := s.store.AppendReviewAdjudicationAudited(req.Msg.GetFindingId(), adjudication, audit)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	return connect.NewResponse(&roomv1.AdjudicateReviewFindingResponse{Finding: finding}), nil
}

func (s *Service) ListReviewFindings(ctx context.Context, req *connect.Request[roomv1.ListReviewFindingsRequest]) (*connect.Response[roomv1.ListReviewFindingsResponse], error) {
	if _, err := principalForReview(ctx); err != nil {
		return nil, err
	}
	findings, err := s.store.ListReviewFindings(req.Msg.GetRepository(), req.Msg.GetClaimKind(), req.Msg.GetLimit())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&roomv1.ListReviewFindingsResponse{Findings: findings}), nil
}

func (s *Service) InferPolicyCandidates(ctx context.Context, req *connect.Request[roomv1.InferPolicyCandidatesRequest]) (*connect.Response[roomv1.InferPolicyCandidatesResponse], error) {
	principal, err := principalForReview(ctx)
	if err != nil {
		return nil, err
	}
	findings, err := s.store.ListReviewFindings(req.Msg.GetRepository(), roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_UNSPECIFIED, 500)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	candidates, err := intelligence.Infer(findings, req.Msg.GetMinimumSupport(), principal.ID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	audits := make([]*roomv1.AuditEvent, 0, len(candidates))
	for _, candidate := range candidates {
		existing, lookupErr := s.store.PolicyCandidate(candidate.GetId())
		if lookupErr != nil {
			return nil, connect.NewError(connect.CodeInternal, lookupErr)
		}
		if existing != nil {
			candidate.CreatedAt = existing.GetCreatedAt()
			candidate.CreatedBy = existing.GetCreatedBy()
			candidate.RolloutStage = existing.GetRolloutStage()
			candidate.MinimumConfidenceBasisPoints = existing.GetMinimumConfidenceBasisPoints()
			for _, trigger := range candidate.GetProposedRule().GetTriggers() {
				trigger.MinimumConfidenceBasisPoints = existing.GetMinimumConfidenceBasisPoints()
			}
			candidate.ProtectedOrgPolicy = candidate.GetProtectedOrgPolicy() || existing.GetProtectedOrgPolicy()
		}
		audits = append(audits, &roomv1.AuditEvent{Kind: roomv1.AuditEventKind_AUDIT_EVENT_KIND_POLICY_INFERRED, SubjectId: principal.ID, Repository: req.Msg.GetRepository(), PolicyCandidateId: candidate.GetId()})
	}
	stored, err := s.store.UpsertPolicyCandidatesAudited(candidates, audits)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&roomv1.InferPolicyCandidatesResponse{Candidates: stored}), nil
}

func (s *Service) ListPolicyCandidates(ctx context.Context, req *connect.Request[roomv1.ListPolicyCandidatesRequest]) (*connect.Response[roomv1.ListPolicyCandidatesResponse], error) {
	if _, err := principalForReview(ctx); err != nil {
		return nil, err
	}
	candidates, err := s.store.ListPolicyCandidates(req.Msg.GetRolloutStage())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&roomv1.ListPolicyCandidatesResponse{Candidates: candidates}), nil
}

func (s *Service) RunPolicyReplay(ctx context.Context, req *connect.Request[roomv1.RunPolicyReplayRequest]) (*connect.Response[roomv1.RunPolicyReplayResponse], error) {
	principal, err := principalForReview(ctx)
	if err != nil {
		return nil, err
	}
	candidate, err := s.store.PolicyCandidate(req.Msg.GetPolicyCandidateId())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if candidate == nil {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("policy candidate not found"))
	}
	repository, err := candidateRepository(candidate)
	if err != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	}
	findings, err := s.store.ListReviewFindings(repository, candidate.GetClaimKind(), 500)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	replay, err := intelligence.Replay(candidate, findings)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	audit := &roomv1.AuditEvent{Kind: roomv1.AuditEventKind_AUDIT_EVENT_KIND_POLICY_REPLAYED, SubjectId: principal.ID, PolicyCandidateId: candidate.GetId(), EvidenceRecordId: replay.GetId()}
	if err := s.store.SavePolicyReplayAudited(replay, audit); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&roomv1.RunPolicyReplayResponse{Replay: replay}), nil
}

func (s *Service) TransitionPolicyCandidate(ctx context.Context, req *connect.Request[roomv1.TransitionPolicyCandidateRequest]) (*connect.Response[roomv1.TransitionPolicyCandidateResponse], error) {
	principal, err := principalForReview(ctx)
	if err != nil {
		return nil, err
	}
	candidate, err := s.store.PolicyCandidate(req.Msg.GetPolicyCandidateId())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if candidate == nil {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("policy candidate not found"))
	}
	if req.Msg.GetExpectedUpdatedAt() == nil || !proto.Equal(req.Msg.GetExpectedUpdatedAt(), candidate.GetUpdatedAt()) {
		return nil, connect.NewError(connect.CodeAborted, fmt.Errorf("policy candidate changed; refresh before transitioning"))
	}
	replays, err := s.store.ListPolicyReplays(candidate.GetId(), 1)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	var latestReplay *roomv1.PolicyReplayRun
	if len(replays) > 0 {
		latestReplay = replays[0]
	}
	if err := validateRolloutTransition(candidate, req.Msg.GetTargetStage(), req.Msg.GetHumanApproved() && principal.HumanOperator, latestReplay); err != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	}
	candidate.RolloutStage = req.Msg.GetTargetStage()
	audit := &roomv1.AuditEvent{Kind: roomv1.AuditEventKind_AUDIT_EVENT_KIND_POLICY_TRANSITIONED, SubjectId: principal.ID, PolicyCandidateId: candidate.GetId()}
	candidate, _, err = s.store.ApplyPolicyCandidate(candidate, req.Msg.GetExpectedUpdatedAt(), nil, audit)
	if err != nil {
		if errors.Is(err, store.ErrPolicyCandidateConflict) {
			return nil, connect.NewError(connect.CodeAborted, err)
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&roomv1.TransitionPolicyCandidateResponse{Candidate: candidate}), nil
}

func (s *Service) TunePolicyCandidate(ctx context.Context, req *connect.Request[roomv1.TunePolicyCandidateRequest]) (*connect.Response[roomv1.TunePolicyCandidateResponse], error) {
	principal, err := principalForReview(ctx)
	if err != nil {
		return nil, err
	}
	candidate, err := s.store.PolicyCandidate(req.Msg.GetPolicyCandidateId())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if candidate == nil {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("policy candidate not found"))
	}
	if req.Msg.GetExpectedUpdatedAt() == nil || !proto.Equal(req.Msg.GetExpectedUpdatedAt(), candidate.GetUpdatedAt()) {
		return nil, connect.NewError(connect.CodeAborted, fmt.Errorf("policy candidate changed; refresh before tuning"))
	}
	replays, err := s.store.ListPolicyReplays(candidate.GetId(), 50)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	tuned, decision, err := intelligence.Tune(candidate, replays, principal.ID)
	if err != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	}
	if decision.GetAction() == roomv1.TuningActionKind_TUNING_ACTION_KIND_ROLLBACK {
		// Autonomous tuning may recommend an emergency rollback, but only the
		// credential-gated transition path can apply it.
		tuned = proto.Clone(candidate).(*roomv1.PolicyCandidate)
	} else {
		for _, trigger := range tuned.GetProposedRule().GetTriggers() {
			trigger.MinimumConfidenceBasisPoints = tuned.GetMinimumConfidenceBasisPoints()
		}
	}
	audit := &roomv1.AuditEvent{Kind: roomv1.AuditEventKind_AUDIT_EVENT_KIND_POLICY_TUNED, SubjectId: principal.ID, PolicyCandidateId: candidate.GetId(), EvidenceRecordId: decision.GetId()}
	tuned, _, err = s.store.ApplyPolicyCandidate(tuned, req.Msg.GetExpectedUpdatedAt(), decision, audit)
	if err != nil {
		if errors.Is(err, store.ErrPolicyCandidateConflict) {
			return nil, connect.NewError(connect.CodeAborted, err)
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&roomv1.TunePolicyCandidateResponse{Candidate: tuned, Decision: decision}), nil
}

func validateRolloutTransition(candidate *roomv1.PolicyCandidate, target roomv1.RolloutStage, humanAuthorized bool, replay *roomv1.PolicyReplayRun) error {
	current := candidate.GetRolloutStage()
	if target == roomv1.RolloutStage_ROLLOUT_STAGE_PAUSED || target == roomv1.RolloutStage_ROLLOUT_STAGE_ROLLED_BACK {
		if !humanAuthorized {
			return fmt.Errorf("a human-operator credential and explicit confirmation are required for emergency controls")
		}
		return nil
	}
	allowed := map[roomv1.RolloutStage]roomv1.RolloutStage{
		roomv1.RolloutStage_ROLLOUT_STAGE_DRAFT:  roomv1.RolloutStage_ROLLOUT_STAGE_SHADOW,
		roomv1.RolloutStage_ROLLOUT_STAGE_SHADOW: roomv1.RolloutStage_ROLLOUT_STAGE_WARN,
		roomv1.RolloutStage_ROLLOUT_STAGE_WARN:   roomv1.RolloutStage_ROLLOUT_STAGE_BLOCK,
	}
	if allowed[current] != target {
		return fmt.Errorf("invalid rollout transition from %s to %s", current, target)
	}
	if replay == nil || replay.GetPolicyCandidateId() != candidate.GetId() || replay.GetMetrics().GetAcceptedCount() == 0 {
		return fmt.Errorf("a successful replay with accepted evidence is required before promotion")
	}
	candidateDigest, err := intelligence.CandidateDigest(candidate)
	if err != nil {
		return fmt.Errorf("digest policy candidate: %w", err)
	}
	if !bytes.Equal(replay.GetPolicyCandidateSha256(), candidateDigest) {
		return fmt.Errorf("replay evidence is stale; rerun replay for this policy candidate revision")
	}
	metrics := replay.GetMetrics()
	if target == roomv1.RolloutStage_ROLLOUT_STAGE_WARN && (metrics.GetPrecisionBasisPoints() < 8000 || metrics.GetRecallBasisPoints() < 5000) {
		return fmt.Errorf("warn rollout requires at least 80%% precision and 50%% recall")
	}
	if target == roomv1.RolloutStage_ROLLOUT_STAGE_BLOCK && (metrics.GetPrecisionBasisPoints() < 9500 || metrics.GetRecallBasisPoints() < 8000 || metrics.GetFalsePositiveCount() != 0) {
		return fmt.Errorf("block rollout requires at least 95%% precision, 80%% recall, and zero false positives")
	}
	if target == roomv1.RolloutStage_ROLLOUT_STAGE_BLOCK && candidate.GetProtectedOrgPolicy() && !humanAuthorized {
		return fmt.Errorf("a human-operator credential and explicit confirmation are required for protected org-wide blocking policies")
	}
	return nil
}

func candidateRepository(candidate *roomv1.PolicyCandidate) (string, error) {
	repositories := candidate.GetProposedRule().GetScope().GetRepositories()
	if len(repositories) != 1 || repositories[0] == "" {
		return "", fmt.Errorf("policy candidate must have exactly one typed repository scope")
	}
	return repositories[0], nil
}

func (s *Service) analyze(ctx context.Context, phase roomv1.AnalysisPhase, content []byte, changedFiles []string) *roomv1.AnalysisReport {
	if s.analyzer != nil {
		return s.analyzer.Analyze(ctx, analyzer.Input{Phase: phase, Content: content, ChangedFiles: changedFiles})
	}
	digest := sha256.Sum256(content)
	return &roomv1.AnalysisReport{ReportId: "unavailable", Status: roomv1.AnalysisStatus_ANALYSIS_STATUS_UNAVAILABLE, Artifact: &roomv1.ArtifactRef{Phase: phase, Sha256: digest[:], ChangedFiles: append([]string(nil), changedFiles...)}}
}

func principalForRole(ctx context.Context, role auth.Role) (auth.Principal, error) {
	principal, ok := auth.PrincipalFromContext(ctx)
	if !ok {
		return auth.Principal{}, connect.NewError(connect.CodeUnauthenticated, auth.ErrUnauthenticated)
	}
	if principal.Role != role {
		return auth.Principal{}, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("permission denied"))
	}
	return principal, nil
}

func requireRole(ctx context.Context, role auth.Role) error {
	_, err := principalForRole(ctx, role)
	return err
}

func principalForReview(ctx context.Context) (auth.Principal, error) {
	principal, ok := auth.PrincipalFromContext(ctx)
	if !ok {
		return auth.Principal{}, connect.NewError(connect.CodeUnauthenticated, auth.ErrUnauthenticated)
	}
	if principal.Role != auth.RoleAdmin && principal.Role != auth.RoleReviewer {
		return auth.Principal{}, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("permission denied"))
	}
	return principal, nil
}

func principalForHumanAdmin(ctx context.Context) (auth.Principal, error) {
	principal, err := principalForRole(ctx, auth.RoleAdmin)
	if err != nil {
		return auth.Principal{}, err
	}
	if !principal.HumanOperator {
		return auth.Principal{}, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("human-operator credential required"))
	}
	return principal, nil
}

func authorizedContext(principal auth.Principal, supplied *roomv1.EvaluationContext) *roomv1.EvaluationContext {
	contextInfo := &roomv1.EvaluationContext{}
	if supplied != nil {
		contextInfo.Cwd = supplied.GetCwd()
	}
	contextInfo.WorkspaceId = principal.Scope.WorkspaceID
	contextInfo.Repository = principal.Scope.Repository
	contextInfo.AgentType = principal.Scope.AgentID
	contextInfo.SubjectId = principal.ID
	return contextInfo
}

func authenticatedMCPInvocation(principal auth.Principal, supplied *roomv1.McpInvocation) *roomv1.McpInvocation {
	invocation := &roomv1.McpInvocation{}
	if supplied != nil {
		invocation = proto.Clone(supplied).(*roomv1.McpInvocation)
	}
	switch {
	case principal.Scope.MCPProxy:
		invocation.Provider = roomv1.HookProvider_HOOK_PROVIDER_MCP_PROXY
		invocation.IdentityAssurance = roomv1.IdentityAssurance_IDENTITY_ASSURANCE_TRANSPORT_VERIFIED
	default:
		switch principal.Scope.HookProvider {
		case auth.HookProviderClaudeCode:
			invocation.Provider = roomv1.HookProvider_HOOK_PROVIDER_CLAUDE_CODE
		case auth.HookProviderCodex:
			invocation.Provider = roomv1.HookProvider_HOOK_PROVIDER_CODEX
		case auth.HookProviderCursor:
			invocation.Provider = roomv1.HookProvider_HOOK_PROVIDER_CURSOR
		default:
			invocation.Provider = roomv1.HookProvider_HOOK_PROVIDER_UNSPECIFIED
		}
		if invocation.Provider == roomv1.HookProvider_HOOK_PROVIDER_UNSPECIFIED {
			invocation.IdentityAssurance = roomv1.IdentityAssurance_IDENTITY_ASSURANCE_UNVERIFIED
		} else {
			invocation.IdentityAssurance = roomv1.IdentityAssurance_IDENTITY_ASSURANCE_CONFIG_BOUND
		}
	}
	return invocation
}

func scopedRuleset(source *roomv1.RulesetVersion, principal auth.Principal) *roomv1.RulesetVersion {
	if source == nil {
		return nil
	}
	view := proto.Clone(source).(*roomv1.RulesetVersion)
	view.SourceHash = source.GetHash()
	view.AuthorizedScope = &roomv1.AuthorizationScope{CredentialId: principal.ID, SubjectId: principal.ID, WorkspaceId: principal.Scope.WorkspaceID, Repository: principal.Scope.Repository, AgentType: principal.Scope.AgentID}
	filtered := make([]*roomv1.Rule, 0, len(view.GetRules()))
	contextInfo := &roomv1.EvaluationContext{WorkspaceId: principal.Scope.WorkspaceID, Repository: principal.Scope.Repository, AgentType: principal.Scope.AgentID}
	for _, rule := range view.GetRules() {
		if eval.ScopeMatches(rule.GetScope(), contextInfo) {
			filtered = append(filtered, rule)
		}
	}
	view.Rules = filtered
	view.Hash = ""
	payload, _ := proto.MarshalOptions{Deterministic: true}.Marshal(view)
	digest := sha256.Sum256(payload)
	view.Hash = hex.EncodeToString(digest[:])
	return view
}

func evaluationEvent(principal auth.Principal, phase roomv1.AnalysisPhase, result *roomv1.EvaluationResult) *roomv1.AuditEvent {
	event := &roomv1.AuditEvent{Kind: roomv1.AuditEventKind_AUDIT_EVENT_KIND_EVALUATION, OccurredAt: timestamppb.Now(), SubjectId: principal.ID, WorkspaceId: principal.Scope.WorkspaceID, Repository: principal.Scope.Repository, AgentType: principal.Scope.AgentID, RulesetId: result.GetRulesetId(), RulesetVersion: result.GetRulesetVersion(), RulesetHash: result.GetRulesetHash(), Decision: result.GetDecision(), HighestSeverity: result.GetHighestSeverity(), AnalysisStatus: result.GetAnalysisStatus(), EvaluationId: result.GetEvaluationId()}
	for _, match := range result.GetMatches() {
		event.MatchedRuleIds = append(event.MatchedRuleIds, match.GetRuleId())
	}
	return event
}

func phaseAndContent(input *roomv1.EvaluationInput) (roomv1.AnalysisPhase, []byte, error) {
	if input == nil {
		return roomv1.AnalysisPhase_ANALYSIS_PHASE_UNSPECIFIED, nil, errors.New("evaluation input is required")
	}
	switch input.GetPhase() {
	case roomv1.AnalysisPhase_ANALYSIS_PHASE_PLAN:
		return input.GetPhase(), []byte(input.GetPlan()), nil
	case roomv1.AnalysisPhase_ANALYSIS_PHASE_DIFF:
		return input.GetPhase(), []byte(input.GetDiff()), nil
	default:
		return roomv1.AnalysisPhase_ANALYSIS_PHASE_UNSPECIFIED, nil, errors.New("evaluation phase must be plan or diff")
	}
}
