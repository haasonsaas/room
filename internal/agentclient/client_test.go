package agentclient

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"connectrpc.com/connect"
	roomv1 "github.com/haasonsaas/room/gen/go/room/v1"
	"github.com/haasonsaas/room/gen/go/room/v1/roomv1connect"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestEvaluateFallsBackToCachedRulesetWhenServerUnavailable(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "ruleset.json")
	client := New("http://127.0.0.1:1", cachePath)
	ruleset := &roomv1.RulesetVersion{
		Id:      "ruleset-test",
		Version: 7,
		Hash:    "abc123",
		Status:  roomv1.RulesetStatus_RULESET_STATUS_ACTIVE,
		Rules: []*roomv1.Rule{
			{
				Id:          "tenant-org-scope-required",
				Title:       "Tenant data must be organization scoped",
				Description: "Tenant reads need org scope.",
				Severity:    roomv1.Severity_SEVERITY_CRITICAL,
				Enabled:     true,
				Checks: []*roomv1.RuleCheck{
					{Kind: roomv1.CheckKind_CHECK_KIND_HEURISTIC, Expression: "touches_tenant_data_without_scope"},
				},
			},
		},
		PublishedAt: timestamppb.Now(),
	}
	if err := SaveRuleset(cachePath, ruleset); err != nil {
		t.Fatalf("save cached ruleset: %v", err)
	}

	result, err := client.EvaluatePlan(context.Background(), &roomv1.EvaluationInput{
		Plan: "Add customer endpoint that queries projects from the database.",
	})
	if err != nil {
		t.Fatalf("evaluate with cache fallback: %v", err)
	}
	if result.GetDecision() != roomv1.Decision_DECISION_DENY {
		t.Fatalf("decision = %s, want deny", result.GetDecision())
	}
	if result.GetRulesetVersion() != 7 {
		t.Fatalf("ruleset version = %d, want 7", result.GetRulesetVersion())
	}
}

func TestActiveRulesetFetchUpdatesCache(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "ruleset.json")
	service := &stubAgentRulesService{
		ruleset: &roomv1.RulesetVersion{
			Id:          "ruleset-live",
			Version:     3,
			Hash:        "live-hash",
			Status:      roomv1.RulesetStatus_RULESET_STATUS_ACTIVE,
			PublishedAt: timestamppb.Now(),
		},
	}
	path, handler := roomv1connect.NewAgentRulesServiceHandler(service)
	server := httptest.NewServer(handler)
	defer server.Close()

	client := New(server.URL, cachePath)
	ruleset, err := client.ActiveRuleset(context.Background(), &roomv1.EvaluationContext{})
	if err != nil {
		t.Fatalf("active ruleset: %v", err)
	}
	if ruleset.GetVersion() != 3 {
		t.Fatalf("version = %d, want 3", ruleset.GetVersion())
	}
	cached, err := LoadRuleset(cachePath)
	if err != nil {
		t.Fatalf("load cached ruleset: %v", err)
	}
	if cached.GetHash() != "live-hash" {
		t.Fatalf("cached hash = %q, want live-hash", cached.GetHash())
	}
	if path == "" {
		t.Fatal("generated handler path is empty")
	}
}

type stubAgentRulesService struct {
	roomv1connect.UnimplementedAgentRulesServiceHandler
	ruleset *roomv1.RulesetVersion
}

func (s *stubAgentRulesService) GetActiveRuleset(_ context.Context, _ *connect.Request[roomv1.AgentRulesServiceGetActiveRulesetRequest]) (*connect.Response[roomv1.AgentRulesServiceGetActiveRulesetResponse], error) {
	return connect.NewResponse(&roomv1.AgentRulesServiceGetActiveRulesetResponse{Ruleset: s.ruleset}), nil
}

func (s *stubAgentRulesService) WatchRuleset(context.Context, *connect.Request[roomv1.WatchRulesetRequest], *connect.ServerStream[roomv1.WatchRulesetResponse]) error {
	return nil
}

func (s *stubAgentRulesService) EvaluatePlan(context.Context, *connect.Request[roomv1.EvaluatePlanRequest]) (*connect.Response[roomv1.EvaluatePlanResponse], error) {
	return nil, nil
}

func (s *stubAgentRulesService) EvaluateDiff(context.Context, *connect.Request[roomv1.EvaluateDiffRequest]) (*connect.Response[roomv1.EvaluateDiffResponse], error) {
	return nil, nil
}

func (s *stubAgentRulesService) ReportEvaluation(context.Context, *connect.Request[roomv1.ReportEvaluationRequest]) (*connect.Response[roomv1.ReportEvaluationResponse], error) {
	return nil, nil
}
