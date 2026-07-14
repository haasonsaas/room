package agentclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"connectrpc.com/connect"
	roomv1 "github.com/haasonsaas/room/gen/go/room/v1"
	"github.com/haasonsaas/room/gen/go/room/v1/roomv1connect"
	"github.com/haasonsaas/room/internal/auth"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestEvaluateDoesNotUseUnauthenticatedCacheAsPolicyEngine(t *testing.T) {
	client := New("http://127.0.0.1:1", filepath.Join(t.TempDir(), "ruleset.json"))
	if _, err := client.EvaluatePlan(context.Background(), &roomv1.EvaluationInput{}); err == nil {
		t.Fatal("expected unavailable server to fail closed")
	}
}

func TestAuthenticatedCacheIsCredentialScoped(t *testing.T) {
	registry := filepath.Join(t.TempDir(), "credentials.json")
	token, err := auth.IssueOrUpdateToken(registry, auth.Principal{ID: "agent-one", Role: auth.RoleAgent, Scope: auth.Scope{WorkspaceID: "w", Repository: "r", AgentID: "a"}})
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	base := filepath.Join(t.TempDir(), "ruleset.json")
	client := NewAuthenticated("http://127.0.0.1:1", base, token)
	if client.CachePath() == base {
		t.Fatal("authenticated cache path was not credential scoped")
	}
	matching := &roomv1.RulesetVersion{AuthorizedScope: &roomv1.AuthorizationScope{CredentialId: "agent-one"}}
	if err := client.ValidateRuleset(matching); err != nil {
		t.Fatalf("matching scope rejected: %v", err)
	}
	matching.AuthorizedScope.CredentialId = "agent-two"
	if err := client.ValidateRuleset(matching); err == nil {
		t.Fatal("mismatched credential scope accepted")
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
	ruleset, provenance, err := client.ActiveRulesetWithProvenance(context.Background(), &roomv1.EvaluationContext{})
	if err != nil {
		t.Fatalf("active ruleset: %v", err)
	}
	if provenance.Source != RulesetSourceServer || provenance.Stale {
		t.Fatalf("provenance = %+v, want live server", provenance)
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
	info, err := os.Stat(cachePath)
	if err != nil {
		t.Fatalf("stat cache: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("cache mode = %o, want 600", got)
	}
	if path == "" {
		t.Fatal("generated handler path is empty")
	}
}

func TestActiveRulesetFallbackReportsStaleCacheProvenance(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "ruleset.json")
	service := &stubAgentRulesService{ruleset: &roomv1.RulesetVersion{Id: "ruleset-cached", Version: 7, Hash: "cached-hash"}}
	_, handler := roomv1connect.NewAgentRulesServiceHandler(service)
	server := httptest.NewServer(handler)
	client := New(server.URL, cachePath)
	if _, provenance, err := client.ActiveRulesetWithProvenance(context.Background(), &roomv1.EvaluationContext{}); err != nil {
		server.Close()
		t.Fatalf("prime ruleset cache: %v", err)
	} else if provenance.Source != RulesetSourceServer || provenance.Stale {
		server.Close()
		t.Fatalf("prime provenance = %+v, want live server", provenance)
	}
	server.Close()

	ruleset, provenance, err := client.ActiveRulesetWithProvenance(context.Background(), &roomv1.EvaluationContext{})
	if err != nil {
		t.Fatalf("cached ruleset: %v", err)
	}
	if ruleset.GetVersion() != 7 {
		t.Fatalf("cached version = %d, want 7", ruleset.GetVersion())
	}
	if provenance.Source != RulesetSourceCache || !provenance.Stale || provenance.CachedAt.IsZero() || provenance.Warning == "" {
		t.Fatalf("cache provenance = %+v, want stale cache metadata", provenance)
	}
}

func TestAuthenticatedClientSendsBearerToken(t *testing.T) {
	service := &stubAgentRulesService{ruleset: &roomv1.RulesetVersion{Id: "scoped"}}
	path, handler := roomv1connect.NewAgentRulesServiceHandler(service)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == path && r.Header.Get("Authorization") != "Bearer secret" {
			http.Error(w, "missing token", http.StatusUnauthorized)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	defer server.Close()
	client := NewAuthenticated(server.URL, filepath.Join(t.TempDir(), "ruleset.json"), "secret")
	if _, err := client.ActiveRuleset(context.Background(), &roomv1.EvaluationContext{}); err != nil {
		t.Fatalf("active ruleset: %v", err)
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
	return nil, errors.New("not implemented")
}

func (s *stubAgentRulesService) EvaluateDiff(context.Context, *connect.Request[roomv1.EvaluateDiffRequest]) (*connect.Response[roomv1.EvaluateDiffResponse], error) {
	return nil, nil
}

func (s *stubAgentRulesService) ReportEvaluation(context.Context, *connect.Request[roomv1.ReportEvaluationRequest]) (*connect.Response[roomv1.ReportEvaluationResponse], error) {
	return nil, nil
}
