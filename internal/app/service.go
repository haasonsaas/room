package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"
	roomv1 "github.com/haasonsaas/room/gen/go/room/v1"
	"github.com/haasonsaas/room/internal/analyzer"
	"github.com/haasonsaas/room/internal/auth"
	"github.com/haasonsaas/room/internal/compliance"
	"github.com/haasonsaas/room/internal/eval"
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
	principal, err := principalForRole(ctx, auth.RoleAdmin)
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
	principal, err := principalForRole(ctx, auth.RoleAdmin)
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
	principal, err := principalForRole(ctx, auth.RoleAdmin)
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
	event := &roomv1.AuditEvent{Kind: roomv1.AuditEventKind_AUDIT_EVENT_KIND_EVALUATION, OccurredAt: timestamppb.Now(), SubjectId: principal.ID, WorkspaceId: principal.Scope.WorkspaceID, Repository: principal.Scope.Repository, AgentType: principal.Scope.AgentID, RulesetId: result.GetRulesetId(), RulesetVersion: result.GetRulesetVersion(), RulesetHash: result.GetRulesetHash(), Decision: result.GetDecision(), HighestSeverity: result.GetHighestSeverity(), AnalysisStatus: result.GetAnalysisStatus()}
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
