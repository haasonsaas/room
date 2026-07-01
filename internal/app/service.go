package app

import (
	"context"
	"time"

	"connectrpc.com/connect"
	roomv1 "github.com/haasonsaas/room/gen/go/room/v1"
	"github.com/haasonsaas/room/internal/eval"
	"github.com/haasonsaas/room/internal/store"
)

type Service struct {
	store *store.Store
}

type RuleAdmin struct {
	*Service
}

type AgentRules struct {
	*Service
}

func New(store *store.Store) *Service {
	return &Service{store: store}
}

func (s *Service) Admin() *RuleAdmin {
	return &RuleAdmin{Service: s}
}

func (s *Service) Agent() *AgentRules {
	return &AgentRules{Service: s}
}

func (s *Service) CreateRule(_ context.Context, req *connect.Request[roomv1.CreateRuleRequest]) (*connect.Response[roomv1.CreateRuleResponse], error) {
	rule, err := s.store.UpsertRule(req.Msg.GetRule())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	return connect.NewResponse(&roomv1.CreateRuleResponse{Rule: rule}), nil
}

func (s *Service) UpdateRule(_ context.Context, req *connect.Request[roomv1.UpdateRuleRequest]) (*connect.Response[roomv1.UpdateRuleResponse], error) {
	rule, err := s.store.UpsertRule(req.Msg.GetRule())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	return connect.NewResponse(&roomv1.UpdateRuleResponse{Rule: rule}), nil
}

func (s *Service) DeleteRule(_ context.Context, req *connect.Request[roomv1.DeleteRuleRequest]) (*connect.Response[roomv1.DeleteRuleResponse], error) {
	deleted, err := s.store.DeleteRule(req.Msg.GetRuleId())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&roomv1.DeleteRuleResponse{Deleted: deleted}), nil
}

func (s *Service) ListRules(_ context.Context, req *connect.Request[roomv1.ListRulesRequest]) (*connect.Response[roomv1.ListRulesResponse], error) {
	return connect.NewResponse(&roomv1.ListRulesResponse{Rules: s.store.ListRules(req.Msg.GetIncludeDisabled())}), nil
}

func (s *Service) PreviewRuleset(_ context.Context, req *connect.Request[roomv1.PreviewRulesetRequest]) (*connect.Response[roomv1.PreviewRulesetResponse], error) {
	rules := req.Msg.GetRules()
	if len(rules) == 0 {
		rules = s.store.ListRules(false)
	}
	result := eval.Evaluate(rules, nil, req.Msg.GetInput())
	return connect.NewResponse(&roomv1.PreviewRulesetResponse{Result: result}), nil
}

func (s *Service) PublishRuleset(_ context.Context, req *connect.Request[roomv1.PublishRulesetRequest]) (*connect.Response[roomv1.PublishRulesetResponse], error) {
	ruleset, err := s.store.Publish(req.Msg.GetAuthor(), req.Msg.GetNotes())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&roomv1.PublishRulesetResponse{Ruleset: ruleset}), nil
}

func (s *Service) RollbackRuleset(_ context.Context, req *connect.Request[roomv1.RollbackRulesetRequest]) (*connect.Response[roomv1.RollbackRulesetResponse], error) {
	ruleset, err := s.store.Rollback(req.Msg.GetVersion())
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}
	return connect.NewResponse(&roomv1.RollbackRulesetResponse{Ruleset: ruleset}), nil
}

func (a *RuleAdmin) GetActiveRuleset(_ context.Context, _ *connect.Request[roomv1.RuleAdminServiceGetActiveRulesetRequest]) (*connect.Response[roomv1.RuleAdminServiceGetActiveRulesetResponse], error) {
	return connect.NewResponse(&roomv1.RuleAdminServiceGetActiveRulesetResponse{Ruleset: a.store.ActiveRuleset()}), nil
}

func (a *AgentRules) GetActiveRuleset(_ context.Context, _ *connect.Request[roomv1.AgentRulesServiceGetActiveRulesetRequest]) (*connect.Response[roomv1.AgentRulesServiceGetActiveRulesetResponse], error) {
	return connect.NewResponse(&roomv1.AgentRulesServiceGetActiveRulesetResponse{Ruleset: a.store.ActiveRuleset()}), nil
}

func (s *Service) WatchRuleset(ctx context.Context, req *connect.Request[roomv1.WatchRulesetRequest], stream *connect.ServerStream[roomv1.WatchRulesetResponse]) error {
	lastVersion := req.Msg.GetCurrentVersion()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		ruleset := s.store.ActiveRuleset()
		if ruleset != nil && ruleset.GetVersion() != lastVersion {
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

func (s *Service) EvaluatePlan(_ context.Context, req *connect.Request[roomv1.EvaluatePlanRequest]) (*connect.Response[roomv1.EvaluatePlanResponse], error) {
	ruleset := s.store.ActiveRuleset()
	var rules []*roomv1.Rule
	if ruleset != nil {
		rules = ruleset.GetRules()
	}
	return connect.NewResponse(&roomv1.EvaluatePlanResponse{Result: eval.Evaluate(rules, ruleset, req.Msg.GetInput())}), nil
}

func (s *Service) EvaluateDiff(_ context.Context, req *connect.Request[roomv1.EvaluateDiffRequest]) (*connect.Response[roomv1.EvaluateDiffResponse], error) {
	ruleset := s.store.ActiveRuleset()
	var rules []*roomv1.Rule
	if ruleset != nil {
		rules = ruleset.GetRules()
	}
	return connect.NewResponse(&roomv1.EvaluateDiffResponse{Result: eval.Evaluate(rules, ruleset, req.Msg.GetInput())}), nil
}

func (s *Service) ReportEvaluation(_ context.Context, _ *connect.Request[roomv1.ReportEvaluationRequest]) (*connect.Response[roomv1.ReportEvaluationResponse], error) {
	return connect.NewResponse(&roomv1.ReportEvaluationResponse{Accepted: true}), nil
}
