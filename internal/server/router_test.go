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

func TestDashboardSupportsNonMutatingPolicyControlDeepLinks(t *testing.T) {
	ruleStore, err := store.Open(filepath.Join(t.TempDir(), "room.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer ruleStore.Close()
	httpServer := httptest.NewServer(New(app.New(ruleStore), WithLocalAuth()))
	defer httpServer.Close()

	resp, err := http.Get(httpServer.URL + "/")
	if err != nil {
		t.Fatalf("get dashboard: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read dashboard: %v", err)
	}
	html := string(body)
	for _, contract := range []string{"location.hash", "applyPolicyControlDeepLink", "Opening this link did not change policy", `state.selected = { kind: "candidate", id: candidate.id }`, `state.tab = "rollout"`} {
		if !strings.Contains(html, contract) {
			t.Fatalf("dashboard missing deep-link contract %q", contract)
		}
	}
	start := strings.Index(html, "function applyPolicyControlDeepLink")
	end := strings.Index(html[start:], "async function refreshCandidates")
	if start < 0 || end < 0 {
		t.Fatal("could not isolate policy-control deep-link handler")
	}
	handler := html[start : start+end]
	if strings.Contains(handler, "transitionCandidate(") || strings.Contains(handler, "requestTransition(") || strings.Contains(handler, "showModal(") {
		t.Fatal("deep-link handler must not trigger a policy mutation or approval dialog")
	}
}

func TestReviewIntelligenceLifecycleAPI(t *testing.T) {
	ruleStore, err := store.Open(filepath.Join(t.TempDir(), "room.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer ruleStore.Close()
	server := httptest.NewServer(New(app.New(ruleStore), WithLocalAuth()))
	defer server.Close()

	finding := &roomv1.ReviewFinding{
		Id: "finding-1", Source: &roomv1.ReviewSource{Repository: "evalops/platform", PullRequestNumber: 4458, HeadSha: "abc123"},
		ClaimKind: roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_PROTOCOL_CONTRACT, Invariant: "responses correlate to request ids",
		Severity: roomv1.Severity_SEVERITY_HIGH, ConfidenceBasisPoints: 9000, ReviewerCostMicros: 125000, ReviewerInputTokens: 4000,
	}
	response := postProto(t, server.URL+"/api/review-findings", &roomv1.IngestReviewFindingRequest{Finding: finding})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("ingest status = %d", response.StatusCode)
	}
	decodeProtoResponse(t, response, &roomv1.IngestReviewFindingResponse{})

	response = postProto(t, server.URL+"/api/review-findings/finding-1/outcomes", &roomv1.RecordReviewOutcomeRequest{Outcome: &roomv1.ReviewOutcome{Id: "outcome-1", Kind: roomv1.ReviewOutcomeKind_REVIEW_OUTCOME_KIND_FIX_COMMITTED, WeightBasisPoints: 10000}})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("outcome status = %d", response.StatusCode)
	}
	recorded := &roomv1.RecordReviewOutcomeResponse{}
	decodeProtoResponse(t, response, recorded)
	if got := recorded.GetFinding().GetOutcomes()[0].GetActorId(); got != "local-admin" {
		t.Fatalf("outcome actor = %q, want authenticated principal", got)
	}

	response = postProto(t, server.URL+"/api/review-findings/finding-1/adjudications", &roomv1.AdjudicateReviewFindingRequest{Adjudication: &roomv1.ReviewAdjudication{Id: "adjudication-1", Verdict: roomv1.AdjudicationVerdict_ADJUDICATION_VERDICT_VALID_GENERALIZABLE, ModelId: "review-agent-v1", ConfidenceBasisPoints: 9500}})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("adjudication status = %d", response.StatusCode)
	}
	adjudicated := &roomv1.AdjudicateReviewFindingResponse{}
	decodeProtoResponse(t, response, adjudicated)
	if got := adjudicated.GetFinding().GetAdjudications()[0].GetAgentId(); got != "local-admin" {
		t.Fatalf("adjudication agent = %q, want authenticated principal", got)
	}

	response = postProto(t, server.URL+"/api/policy-infer", &roomv1.InferPolicyCandidatesRequest{Repository: "evalops/platform", MinimumSupport: 1})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("infer status = %d", response.StatusCode)
	}
	inferred := &roomv1.InferPolicyCandidatesResponse{}
	decodeProtoResponse(t, response, inferred)
	if len(inferred.GetCandidates()) != 1 {
		t.Fatalf("candidates = %d, want 1", len(inferred.GetCandidates()))
	}
	candidateID := inferred.GetCandidates()[0].GetId()

	response = postProto(t, server.URL+"/api/policy-candidates/"+candidateID+"/replay", &roomv1.RunPolicyReplayRequest{})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("replay status = %d", response.StatusCode)
	}
	replayed := &roomv1.RunPolicyReplayResponse{}
	decodeProtoResponse(t, response, replayed)
	if replayed.GetReplay().GetMetrics().GetTruePositiveCount() != 1 {
		t.Fatalf("replay metrics = %+v", replayed.GetReplay().GetMetrics())
	}

	response = postProto(t, server.URL+"/api/policy-candidates/"+candidateID+"/transition", &roomv1.TransitionPolicyCandidateRequest{TargetStage: roomv1.RolloutStage_ROLLOUT_STAGE_SHADOW, ExpectedUpdatedAt: inferred.GetCandidates()[0].GetUpdatedAt()})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("transition status = %d", response.StatusCode)
	}
	transitioned := &roomv1.TransitionPolicyCandidateResponse{}
	decodeProtoResponse(t, response, transitioned)
	if transitioned.GetCandidate().GetRolloutStage() != roomv1.RolloutStage_ROLLOUT_STAGE_SHADOW {
		t.Fatalf("transitioned candidate = %+v", transitioned.GetCandidate())
	}
	foundMaterialized := false
	for _, rule := range ruleStore.ActiveRuleset().GetRules() {
		if rule.GetId() == transitioned.GetCandidate().GetProposedRule().GetId() {
			foundMaterialized = rule.GetEnabled() && rule.GetRolloutStage() == roomv1.RolloutStage_ROLLOUT_STAGE_SHADOW
		}
	}
	if !foundMaterialized {
		t.Fatal("shadow transition did not publish an executable shadow rule")
	}

	response, err = http.Get(server.URL + "/api/policy-candidates")
	if err != nil {
		t.Fatal(err)
	}
	listed := &roomv1.ListPolicyCandidatesResponse{}
	decodeProtoResponse(t, response, listed)
	if len(listed.GetCandidates()) != 1 {
		t.Fatalf("listed candidates = %d", len(listed.GetCandidates()))
	}
}

func postProto(t *testing.T, url string, message proto.Message) *http.Response {
	t.Helper()
	body, err := protojson.Marshal(message)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	response, err := http.Post(url, "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("post %s: %v", url, err)
	}
	return response
}

func TestDashboardEditPreservesExistingRuleScope(t *testing.T) {
	ruleStore, err := store.Open(filepath.Join(t.TempDir(), "room.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer ruleStore.Close()
	server := httptest.NewServer(New(app.New(ruleStore), WithLocalAuth()))
	defer server.Close()

	var original *roomv1.Rule
	for _, rule := range ruleStore.ListRules(true) {
		if rule.GetId() == "tenant-org-scope-required" {
			original = rule
			break
		}
	}
	if original == nil || len(original.GetScope().GetPaths()) == 0 {
		t.Fatalf("expected path-scoped built-in rule, got %+v", original)
	}
	originalScope := proto.Clone(original.GetScope()).(*roomv1.RuleScope)
	edited := proto.Clone(original).(*roomv1.Rule)
	edited.Title = "Edited title"
	edited.Scope = nil // The dashboard's legacy form omitted non-editable scope fields.
	body, err := protojson.Marshal(&roomv1.CreateRuleRequest{Rule: edited})
	if err != nil {
		t.Fatalf("marshal dashboard edit: %v", err)
	}

	response, err := http.Post(server.URL+"/api/rules", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("save dashboard edit: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("save status = %d, want 200", response.StatusCode)
	}
	created := &roomv1.CreateRuleResponse{}
	decodeProtoResponse(t, response, created)
	if !proto.Equal(created.GetRule().GetScope(), originalScope) {
		t.Fatalf("saved scope = %+v, want %+v", created.GetRule().GetScope(), originalScope)
	}

	cleared := proto.Clone(created.GetRule()).(*roomv1.Rule)
	cleared.Scope = &roomv1.RuleScope{}
	body, err = protojson.Marshal(&roomv1.CreateRuleRequest{Rule: cleared})
	if err != nil {
		t.Fatalf("marshal explicit scope clear: %v", err)
	}
	response, err = http.Post(server.URL+"/api/rules", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("save explicit scope clear: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("clear status = %d, want 200", response.StatusCode)
	}
	decodeProtoResponse(t, response, &roomv1.CreateRuleResponse{})
	found := false
	for _, rule := range ruleStore.ListRules(true) {
		if rule.GetId() == cleared.GetId() {
			found = true
			if rule.Scope == nil || len(rule.GetScope().GetPaths()) != 0 {
				t.Fatalf("explicit empty scope was not persisted: %+v", rule.GetScope())
			}
		}
	}
	if !found {
		t.Fatal("explicitly cleared rule was not persisted")
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
		{name: "admin", role: auth.RoleAdmin, want: auth.Principal{ID: "local-admin", Role: auth.RoleAdmin, HumanOperator: true}},
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
	reviewerToken, err := auth.IssueOrUpdateToken(credentials, auth.Principal{ID: "reviewer", Role: auth.RoleReviewer})
	if err != nil {
		t.Fatalf("issue reviewer: %v", err)
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
	}{{"admin", adminToken, http.StatusOK}, {"reviewer", reviewerToken, http.StatusForbidden}, {"agent", agentToken, http.StatusForbidden}} {
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
	request, err := http.NewRequest(http.MethodGet, httpServer.URL+"/api/policy-candidates", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+reviewerToken)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("reviewer intelligence status = %d, want 200", response.StatusCode)
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
