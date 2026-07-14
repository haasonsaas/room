package mcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	roomv1 "github.com/haasonsaas/room/gen/go/room/v1"
	"github.com/haasonsaas/room/internal/agentclient"
	"github.com/haasonsaas/room/internal/analyzer"
	"github.com/haasonsaas/room/internal/app"
	roomauth "github.com/haasonsaas/room/internal/auth"
	"github.com/haasonsaas/room/internal/server"
	"github.com/haasonsaas/room/internal/store"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestAuthenticatedHandlerRejectsSessionReuseAcrossPrincipals(t *testing.T) {
	authenticator := authenticatorFunc(func(token string) (roomauth.Principal, error) {
		switch token {
		case "token-a":
			return roomauth.Principal{ID: "agent-a", Role: roomauth.RoleAgent, Scope: roomauth.Scope{WorkspaceID: "w-a", Repository: "r-a", AgentID: "a"}}, nil
		case "token-b":
			return roomauth.Principal{ID: "agent-b", Role: roomauth.RoleAgent, Scope: roomauth.Scope{WorkspaceID: "w-b", Repository: "r-b", AgentID: "b"}}, nil
		default:
			return roomauth.Principal{}, roomauth.ErrUnauthenticated
		}
	})
	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls++
		http.Error(w, "unexpected upstream execution", http.StatusInternalServerError)
	}))
	defer upstream.Close()
	server := httptest.NewServer(NewAuthenticatedHandler(upstream.URL, authenticator))
	defer server.Close()

	initialize := []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`)
	response := mcpRequest(t, server.URL, "token-a", "", initialize)
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("initialize status = %d: %s", response.StatusCode, body)
	}
	sessionID := response.Header.Get("Mcp-Session-Id")
	if sessionID == "" {
		t.Fatal("initialize response omitted MCP session id")
	}

	call := []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"room_get_rules","arguments":{}}}`)
	hijack := mcpRequest(t, server.URL, "token-b", sessionID, call)
	defer hijack.Body.Close()
	if hijack.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(hijack.Body)
		t.Fatalf("cross-principal reuse status = %d, want %d: %s", hijack.StatusCode, http.StatusForbidden, body)
	}
	if upstreamCalls != 0 {
		t.Fatalf("cross-principal request executed %d upstream calls", upstreamCalls)
	}
}

func TestEvaluationOutputFailsClosedWithoutResult(t *testing.T) {
	output := evaluationOutput(nil)
	if output.Decision != "indeterminate" || !output.Blocking {
		t.Fatalf("output = %+v, want blocking indeterminate", output)
	}
}

func TestRulesetOutputIncludesScopedRuleContextAndProvenance(t *testing.T) {
	cachedAt := time.Date(2026, time.July, 14, 12, 30, 0, 0, time.UTC)
	ruleset := &roomv1.RulesetVersion{
		Id: "ruleset-7", Version: 7, Hash: "scoped-hash", SourceHash: "source-hash",
		AuthorizedScope: &roomv1.AuthorizationScope{CredentialId: "agent-1", SubjectId: "agent-1", WorkspaceId: "workspace", Repository: "repo", AgentType: "codex"},
		Rules: []*roomv1.Rule{{
			Id: "auth-required", Title: "Auth required", Description: "Use trusted auth context", Severity: roomv1.Severity_SEVERITY_HIGH,
			Tags: []string{"security"}, Scope: &roomv1.RuleScope{Paths: []string{"internal/**"}, Repositories: []string{"repo"}},
			Triggers:         []*roomv1.SignalSelector{{Signal: roomv1.SignalKind_SIGNAL_KIND_PROTECTED_ACCESS_WITHOUT_AUTH_CONTEXT, Phases: []roomv1.AnalysisPhase{roomv1.AnalysisPhase_ANALYSIS_PHASE_PLAN}, MinimumConfidenceBasisPoints: 8000}},
			RequiredCoverage: []roomv1.SignalKind{roomv1.SignalKind_SIGNAL_KIND_PROTECTED_ACCESS_WITHOUT_AUTH_CONTEXT}, RequiredEvidence: []string{"denial test"}, Remediation: []string{"load principal"},
		}},
	}
	output := rulesetOutput(ruleset, agentclient.RulesetProvenance{Source: agentclient.RulesetSourceCache, Stale: true, CachedAt: cachedAt, Warning: "server unavailable"})
	if output.RulesetProvenance == nil || output.RulesetProvenance.Source != "cache" || !output.RulesetProvenance.Stale || output.RulesetProvenance.CachedAt != cachedAt.Format(time.RFC3339Nano) {
		t.Fatalf("provenance = %+v", output.RulesetProvenance)
	}
	if !strings.Contains(output.Summary, "cached advisory") || !strings.Contains(output.Summary, "server unavailable") {
		t.Fatalf("summary = %q", output.Summary)
	}
	if output.SourceHash != "source-hash" || output.AuthorizedScope == nil || output.AuthorizedScope.Repository != "repo" {
		t.Fatalf("ruleset context = source %q scope %+v", output.SourceHash, output.AuthorizedScope)
	}
	if len(output.Rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(output.Rules))
	}
	rule := output.Rules[0]
	if rule.Description != "Use trusted auth context" || rule.Scope == nil || len(rule.Triggers) != 1 || len(rule.RequiredCoverage) != 1 || len(rule.RequiredEvidence) != 1 || len(rule.Remediation) != 1 {
		t.Fatalf("rule context = %+v", rule)
	}
	if rule.Triggers[0].Signal != "protected_access_without_auth_context" || rule.Triggers[0].Phases[0] != "plan" {
		t.Fatalf("trigger = %+v", rule.Triggers[0])
	}
}

func TestEvaluationOutputIncludesAnalysisReceiptsAndGaps(t *testing.T) {
	identity := &roomv1.AnalyzerIdentity{Id: "semgrep", Version: "1.2.3", ConfigSha256: []byte{0x01, 0x02}}
	result := &roomv1.EvaluationResult{
		Decision: roomv1.Decision_DECISION_INDETERMINATE, AnalysisStatus: roomv1.AnalysisStatus_ANALYSIS_STATUS_UNAVAILABLE,
		RulesetId: "ruleset-4", RulesetVersion: 4, RulesetHash: "hash", AuditEventId: "audit-1", EvaluationId: "evaluation-1", InputSha256: []byte{0xaa, 0xbb},
		Gaps: []*roomv1.EvaluationGap{{RequiredSignal: roomv1.SignalKind_SIGNAL_KIND_SECRET_LITERAL, AnalyzerId: "semgrep", Status: roomv1.AnalysisStatus_ANALYSIS_STATUS_UNAVAILABLE, ReasonCode: "analyzer_unavailable"}},
		AnalyzerReceipts: []*roomv1.AnalyzerReceipt{{
			Analyzer: identity, Status: roomv1.AnalysisStatus_ANALYSIS_STATUS_FAILED, CoveredSignals: []roomv1.SignalKind{roomv1.SignalKind_SIGNAL_KIND_SECRET_LITERAL}, FailureCode: "exit_nonzero", InputSha256: []byte{0xaa, 0xbb},
			Signals: []*roomv1.SecuritySignal{{Kind: roomv1.SignalKind_SIGNAL_KIND_SECRET_LITERAL, Fingerprint: "finding-1", Analyzer: identity, Location: &roomv1.SourceLocation{FilePath: "main.go", StartLine: 10, EndLine: 10}, ConfidenceBasisPoints: 9000, EvidenceSha256: []byte{0xcc}}},
		}},
	}
	output := evaluationOutput(result)
	if output.AnalysisStatus != "unavailable" || output.AuditEventID != "audit-1" || output.EvaluationID != "evaluation-1" || output.InputSHA256 != "aabb" {
		t.Fatalf("evaluation metadata = %+v", output)
	}
	if len(output.Gaps) != 1 || output.Gaps[0].ReasonCode != "analyzer_unavailable" || output.Gaps[0].RequiredSignal != "secret_literal" {
		t.Fatalf("gaps = %+v", output.Gaps)
	}
	if len(output.AnalyzerReceipts) != 1 || output.AnalyzerReceipts[0].Analyzer.ID != "semgrep" || len(output.AnalyzerReceipts[0].Signals) != 1 || output.AnalyzerReceipts[0].Signals[0].Location.FilePath != "main.go" {
		t.Fatalf("receipts = %+v", output.AnalyzerReceipts)
	}
	if !strings.Contains(output.Summary, "Analysis status: unavailable") || !strings.Contains(output.Summary, "analyzer_unavailable") || !strings.Contains(output.Summary, "semgrep: failed (exit_nonzero)") || !strings.Contains(output.Summary, "Audit event: audit-1") {
		t.Fatalf("summary = %q", output.Summary)
	}
}

type authenticatorFunc func(string) (roomauth.Principal, error)

func (f authenticatorFunc) Authenticate(token string) (roomauth.Principal, error) {
	if f == nil {
		return roomauth.Principal{}, errors.New("nil authenticator")
	}
	return f(token)
}

func mcpRequest(t *testing.T, endpoint, token, sessionID string, body []byte) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("Authorization", "Bearer "+token)
	if sessionID != "" {
		request.Header.Set("Mcp-Session-Id", sessionID)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func TestAnalyzePlanFlagsUnsafePlanThroughMCP(t *testing.T) {
	t.Setenv("ROOM_CACHE_FILE", filepath.Join(t.TempDir(), "ruleset.json"))
	ruleStore, err := store.Open(filepath.Join(t.TempDir(), "room.json"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	identity := &roomv1.AnalyzerIdentity{Id: "test", Version: "1", ConfigSha256: make([]byte, 32)}
	roomServer := httptest.NewServer(server.New(app.New(ruleStore, app.WithAnalyzer(&signalAnalyzer{identity: identity})), server.WithLocalAuth()))
	defer roomServer.Close()

	mcpServer := httptest.NewServer(NewHandler(roomServer.URL))
	defer mcpServer.Close()

	ctx := context.Background()
	client := mcpsdk.NewClient(&mcpsdk.Implementation{Name: "room-test", Version: "test"}, nil)
	session, err := client.Connect(ctx, &mcpsdk.StreamableClientTransport{Endpoint: mcpServer.URL}, nil)
	if err != nil {
		t.Fatalf("connect mcp client: %v", err)
	}
	defer session.Close()

	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	toolNames := make([]string, 0, len(tools.Tools))
	for _, tool := range tools.Tools {
		toolNames = append(toolNames, tool.Name)
	}
	slices.Sort(toolNames)
	wantToolNames := []string{"room_analyze_plan", "room_check_diff", "room_get_rules"}
	if !slices.Equal(toolNames, wantToolNames) {
		t.Fatalf("MCP tools = %v, want exactly %v", toolNames, wantToolNames)
	}
	for _, tool := range tools.Tools {
		schemaJSON, err := json.Marshal(tool.InputSchema)
		if err != nil {
			t.Fatalf("marshal %s input schema: %v", tool.Name, err)
		}
		for _, forbidden := range []string{"workspace_id", "repository", "agent_type"} {
			if strings.Contains(string(schemaJSON), `"`+forbidden+`"`) {
				t.Fatalf("MCP tool %s exposes caller-controlled identity field %q", tool.Name, forbidden)
			}
		}
	}

	result, err := session.CallTool(ctx, &mcpsdk.CallToolParams{
		Name: "room_analyze_plan",
		Arguments: map[string]any{
			"plan":          "Add a customer endpoint that queries projects from the database.",
			"changed_files": []string{"internal/api/projects.go"},
		},
	})
	if err != nil {
		t.Fatalf("call room_analyze_plan: %v", err)
	}
	if result.IsError {
		t.Fatalf("tool returned protocol error content: %#v", result.Content)
	}
	text := firstText(result)
	if !strings.Contains(text, "Room decision: deny") {
		t.Fatalf("tool text = %q, want Room decision: deny", text)
	}
	if !strings.Contains(text, "tenant-org-scope-required") {
		t.Fatalf("tool text = %q, want tenant-org-scope-required", text)
	}

	data, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structured content: %v", err)
	}
	var structured struct {
		Decision string `json:"decision"`
		Blocking bool   `json:"blocking"`
	}
	if err := json.Unmarshal(data, &structured); err != nil {
		t.Fatalf("unmarshal structured content: %v", err)
	}
	if structured.Decision != "deny" || !structured.Blocking {
		t.Fatalf("structured = %+v, want deny blocking", structured)
	}
}

type signalAnalyzer struct{ identity *roomv1.AnalyzerIdentity }

func (a *signalAnalyzer) Identity() *roomv1.AnalyzerIdentity { return a.identity }

func (a *signalAnalyzer) Analyze(_ context.Context, input analyzer.Input) *roomv1.AnalysisReport {
	digest := sha256.Sum256(input.Content)
	signal := &roomv1.SecuritySignal{
		Kind:                  roomv1.SignalKind_SIGNAL_KIND_TENANT_ACCESS_WITHOUT_TRUSTED_SCOPE,
		Fingerprint:           "test-signal",
		ConfidenceBasisPoints: 10000,
		Analyzer:              a.identity,
	}
	receipt := &roomv1.AnalyzerReceipt{
		Analyzer:    a.identity,
		Status:      roomv1.AnalysisStatus_ANALYSIS_STATUS_COMPLETE,
		Signals:     []*roomv1.SecuritySignal{signal},
		InputSha256: digest[:],
	}
	for kind := roomv1.SignalKind(1); kind <= roomv1.SignalKind_SIGNAL_KIND_RUST_UNVALIDATED_EXTERNAL_DESERIALIZATION; kind++ {
		receipt.CoveredSignals = append(receipt.CoveredSignals, kind)
	}
	return &roomv1.AnalysisReport{
		Artifact: &roomv1.ArtifactRef{Phase: input.Phase, Sha256: digest[:], ChangedFiles: input.ChangedFiles},
		Status:   roomv1.AnalysisStatus_ANALYSIS_STATUS_COMPLETE,
		Receipts: []*roomv1.AnalyzerReceipt{receipt},
	}
}

func firstText(result *mcpsdk.CallToolResult) string {
	for _, content := range result.Content {
		if text, ok := content.(*mcpsdk.TextContent); ok {
			return text.Text
		}
	}
	return ""
}
