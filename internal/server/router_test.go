package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect"
	roomv1 "github.com/haasonsaas/room/gen/go/room/v1"
	"github.com/haasonsaas/room/gen/go/room/v1/roomv1connect"
	"github.com/haasonsaas/room/internal/analyzer"
	"github.com/haasonsaas/room/internal/app"
	"github.com/haasonsaas/room/internal/auth"
	"github.com/haasonsaas/room/internal/store"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func TestDashboardRuleLifecycleAPI(t *testing.T) {
	ruleStore, err := store.Open(filepath.Join(t.TempDir(), "room.json"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	server := httptest.NewServer(New(app.New(ruleStore), WithLocalAuth()))
	defer server.Close()

	body := `{"rule":{"id":"test-dashboard-rule","title":"Dashboard rule","description":"Created from API","severity":4,"enabled":true,"triggers":[{"signal":3}],"requiredCoverage":[3]}}`
	resp, err := http.Post(server.URL+"/api/rules", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("create rule: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create status = %d, want 200", resp.StatusCode)
	}
	created := &roomv1.CreateRuleResponse{}
	decodeProtoResponse(t, resp, created)
	if created.GetRule().GetId() != "test-dashboard-rule" {
		t.Fatalf("created rule = %+v", created.GetRule())
	}
	if !dashboardRuleExists(t, server.URL, "test-dashboard-rule") {
		t.Fatal("created rule was not persisted")
	}

	req, err := http.NewRequest(http.MethodDelete, server.URL+"/api/rules/test-dashboard-rule", nil)
	if err != nil {
		t.Fatalf("delete request: %v", err)
	}
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete rule: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete status = %d, want 200", resp.StatusCode)
	}
	deleted := &roomv1.DeleteRuleResponse{}
	decodeProtoResponse(t, resp, deleted)
	if !deleted.GetDeleted() {
		t.Fatal("delete response did not confirm mutation")
	}
	if dashboardRuleExists(t, server.URL, "test-dashboard-rule") {
		t.Fatal("deleted rule remains persisted")
	}
}

func TestDashboardEvaluationUsesExplicitPhase(t *testing.T) {
	ruleStore, err := store.Open(filepath.Join(t.TempDir(), "room.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer ruleStore.Close()
	provider := &phaseRecordingAnalyzer{}
	server := httptest.NewServer(New(app.New(ruleStore, app.WithAnalyzer(provider)), WithLocalAuth()))
	defer server.Close()

	response, err := http.Post(server.URL+"/api/evaluate", "application/json", strings.NewReader(`{"phase":2,"plan":"nonempty plan","diff":""}`))
	if err != nil {
		t.Fatalf("evaluate empty diff: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("empty diff status = %d, want 200", response.StatusCode)
	}
	_ = response.Body.Close()
	if provider.input.Phase != roomv1.AnalysisPhase_ANALYSIS_PHASE_DIFF || len(provider.input.Content) != 0 {
		t.Fatalf("analyzer input = %+v, want explicit diff phase with empty content", provider.input)
	}

	response, err = http.Post(server.URL+"/api/evaluate", "application/json", strings.NewReader(`{"phase":0,"plan":"missing typed phase"}`))
	if err != nil {
		t.Fatalf("evaluate invalid phase: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid phase status = %d, want 400", response.StatusCode)
	}
}

func TestLocalAuthMiddlewareUsesDeclaredRouteRole(t *testing.T) {
	tests := []struct {
		name string
		role auth.Role
		want auth.Principal
	}{
		{name: "admin", role: auth.RoleAdmin, want: auth.Principal{ID: "local-admin", Role: auth.RoleAdmin}},
		{name: "agent", role: auth.RoleAgent, want: auth.Principal{ID: "local-agent", Role: auth.RoleAgent, Scope: auth.Scope{WorkspaceID: "local", Repository: "local", AgentID: "local-agent"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got auth.Principal
			handler := protectedHandler(options{localAuth: true}, tt.role, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got, _ = auth.PrincipalFromContext(r.Context())
				w.WriteHeader(http.StatusNoContent)
			}))
			request := httptest.NewRequest(http.MethodGet, "/path-name-does-not-determine-role", nil)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusNoContent || got != tt.want {
				t.Fatalf("status=%d principal=%+v, want status=204 principal=%+v", response.Code, got, tt.want)
			}
		})
	}
}

type phaseRecordingAnalyzer struct{ input analyzer.Input }

func (a *phaseRecordingAnalyzer) Identity() *roomv1.AnalyzerIdentity {
	return &roomv1.AnalyzerIdentity{Id: "phase-recorder", Version: "1", ConfigSha256: make([]byte, 32)}
}

func (a *phaseRecordingAnalyzer) Analyze(_ context.Context, input analyzer.Input) *roomv1.AnalysisReport {
	a.input = input
	return nil
}

func dashboardRuleExists(t *testing.T, serverURL, ruleID string) bool {
	t.Helper()
	response, err := http.Get(serverURL + "/api/rules")
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("list status = %d, want 200", response.StatusCode)
	}
	listed := &roomv1.ListRulesResponse{}
	decodeProtoResponse(t, response, listed)
	for _, rule := range listed.GetRules() {
		if rule.GetId() == ruleID {
			return true
		}
	}
	return false
}

func decodeProtoResponse(t *testing.T, response *http.Response, target proto.Message) {
	t.Helper()
	data, err := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if closeErr != nil {
		t.Fatalf("close response: %v", closeErr)
	}
	if err := protojson.Unmarshal(data, target); err != nil {
		t.Fatalf("decode response %q: %v", data, err)
	}
}

func TestRegistryAuthenticationAndRoles(t *testing.T) {
	dir := t.TempDir()
	credentials := filepath.Join(dir, "credentials.json")
	adminToken, err := auth.IssueOrUpdateToken(credentials, auth.Principal{ID: "admin", Role: auth.RoleAdmin})
	if err != nil {
		t.Fatalf("issue admin: %v", err)
	}
	agentToken, err := auth.IssueOrUpdateToken(credentials, auth.Principal{ID: "agent", Role: auth.RoleAgent, Scope: auth.Scope{WorkspaceID: "w", Repository: "r", AgentID: "a"}})
	if err != nil {
		t.Fatalf("issue agent: %v", err)
	}
	registry, err := auth.LoadRegistry(credentials)
	if err != nil {
		t.Fatalf("load registry: %v", err)
	}
	ruleStore, err := store.Open(filepath.Join(dir, "room.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer ruleStore.Close()
	httpServer := httptest.NewServer(New(app.New(ruleStore), WithRegistry(registry)))
	defer httpServer.Close()

	for _, test := range []struct {
		name, token string
		want        int
	}{{"admin", adminToken, http.StatusOK}, {"agent", agentToken, http.StatusForbidden}} {
		t.Run(test.name, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodGet, httpServer.URL+"/api/rules", nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Authorization", "Bearer "+test.token)
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != test.want {
				t.Fatalf("status = %d, want %d", response.StatusCode, test.want)
			}
		})
	}
}

func TestRESTBodyLimit(t *testing.T) {
	ruleStore, err := store.Open(filepath.Join(t.TempDir(), "room.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer ruleStore.Close()
	httpServer := httptest.NewServer(New(app.New(ruleStore), WithLocalAuth(), WithMaxBodyBytes(32)))
	defer httpServer.Close()
	response, err := http.Post(httpServer.URL+"/api/rules", "application/json", strings.NewReader(strings.Repeat("x", 64)))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusRequestEntityTooLarge)
	}
}

func TestConnectBodyLimit(t *testing.T) {
	ruleStore, err := store.Open(filepath.Join(t.TempDir(), "room.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer ruleStore.Close()
	httpServer := httptest.NewServer(New(app.New(ruleStore), WithLocalAuth(), WithMaxBodyBytes(64)))
	defer httpServer.Close()
	client := roomv1connect.NewAgentRulesServiceClient(http.DefaultClient, httpServer.URL)

	_, err = client.EvaluatePlan(context.Background(), connect.NewRequest(&roomv1.EvaluatePlanRequest{
		Input: &roomv1.EvaluationInput{Plan: strings.Repeat("x", 1024)},
	}))
	if connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("code = %s, want resource exhausted", connect.CodeOf(err))
	}
}

func TestProtectedRoutesRequireAuthenticationByDefault(t *testing.T) {
	ruleStore, err := store.Open(filepath.Join(t.TempDir(), "room.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	server := httptest.NewServer(New(app.New(ruleStore)))
	defer server.Close()

	resp, err := http.Get(server.URL + "/api/rules")
	if err != nil {
		t.Fatalf("get rules: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
}
