package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIssueOrUpdateTokenStoresOnlyDigestAndAuthenticates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	want := Principal{
		ID:    "build-agent",
		Role:  RoleAgent,
		Scope: Scope{WorkspaceID: "workspace-1", Repository: "haasonsaas/room", AgentID: "codex-1"},
	}

	token, err := IssueOrUpdateToken(path, want)
	if err != nil {
		t.Fatalf("IssueOrUpdateToken: %v", err)
	}
	if !strings.HasPrefix(token, "room_build-agent_") {
		t.Fatalf("token = %q, want room_<id>_<secret>", token)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("registry mode = %o, want 600", got)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), token) || strings.Contains(string(data), strings.TrimPrefix(token, "room_build-agent_")) {
		t.Fatal("registry persisted token material")
	}
	digest := sha256.Sum256([]byte(token))
	if !strings.Contains(string(data), hex.EncodeToString(digest[:])) {
		t.Fatal("registry does not contain the token SHA-256 digest")
	}

	registry, err := LoadRegistry(path)
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	got, err := registry.Authenticate(token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if got != want {
		t.Fatalf("principal = %#v, want %#v", got, want)
	}
	if _, err := registry.Authenticate(token + "tampered"); err != ErrUnauthenticated {
		t.Fatalf("tampered token error = %v, want ErrUnauthenticated", err)
	}
}

func TestIssueOrUpdateTokenRejectsUnauditedReplacementAndPreservesOthers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	admin := Principal{ID: "operator", Role: RoleAdmin}
	oldToken, err := IssueOrUpdateToken(path, admin)
	if err != nil {
		t.Fatal(err)
	}
	agent := Principal{ID: "runner", Role: RoleAgent, Scope: Scope{WorkspaceID: "w", Repository: "r", AgentID: "a"}}
	agentToken, err := IssueOrUpdateToken(path, agent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := IssueOrUpdateToken(path, admin); err == nil {
		t.Fatal("unaudited credential replacement succeeded")
	}
	registry, err := LoadRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Authenticate(oldToken); err != nil {
		t.Fatalf("rejected replacement revoked old token: %v", err)
	}
	if _, err := registry.Authenticate(agentToken); err != nil {
		t.Fatalf("preserved token: %v", err)
	}
}

func TestHumanOperatorCapabilityIsCredentialBound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	want := Principal{ID: "human-admin", Role: RoleAdmin, HumanOperator: true}
	token, err := IssueOrUpdateToken(path, want)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := LoadRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := registry.Authenticate(token)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("principal = %#v, want %#v", got, want)
	}
	if _, err := IssueOrUpdateToken(path, Principal{ID: "agent", Role: RoleAgent, HumanOperator: true, Scope: Scope{WorkspaceID: "w", Repository: "r", AgentID: "a"}}); err == nil {
		t.Fatal("agent credential accepted human-operator capability")
	}
}

func TestRotateAgentScopeRequiresHumanApprovalAndPersistsReceiptAtomically(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	human := Principal{ID: "human-admin", Role: RoleAdmin, HumanOperator: true}
	if _, err := IssueOrUpdateToken(path, human); err != nil {
		t.Fatal(err)
	}
	oldScope := Scope{WorkspaceID: "local", Repository: "evalops/room", AgentID: "codex", HookProvider: HookProviderCodex}
	oldToken, err := IssueOrUpdateToken(path, Principal{ID: "codex-local", Role: RoleAgent, Scope: oldScope})
	if err != nil {
		t.Fatal(err)
	}
	newToken, receipt, err := RotateAgentScope(path, human, "codex-local", Scope{WorkspaceID: "local", Repository: "evalops/platform", AgentID: "codex"}, "APPROVE")
	if err != nil {
		t.Fatal(err)
	}
	if receipt.ActorID != human.ID || receipt.CredentialID != "codex-local" || receipt.Action != "rotate_agent_scope" || receipt.OldScope != oldScope || receipt.NewScope.Repository != "evalops/platform" || receipt.NewScope.HookProvider != HookProviderCodex {
		t.Fatalf("receipt = %#v", receipt)
	}
	registry, err := LoadRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Authenticate(oldToken); err != ErrUnauthenticated {
		t.Fatalf("old token remains valid: %v", err)
	}
	principal, err := registry.Authenticate(newToken)
	if err != nil || principal.Scope != receipt.NewScope {
		t.Fatalf("new principal = %#v, err = %v", principal, err)
	}
	receipts := registry.CredentialMutationReceipts()
	if len(receipts) != 1 || receipts[0] != receipt {
		t.Fatalf("persisted receipts = %#v", receipts)
	}
}

func TestRotateAgentScopeRejectsUnapprovedOrInexactMutationWithoutRevokingToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	human := Principal{ID: "human-admin", Role: RoleAdmin, HumanOperator: true}
	if _, err := IssueOrUpdateToken(path, human); err != nil {
		t.Fatal(err)
	}
	token, err := IssueOrUpdateToken(path, Principal{ID: "codex-local", Role: RoleAgent, Scope: Scope{WorkspaceID: "local", Repository: "evalops/room", AgentID: "codex"}})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name         string
		actor        Principal
		scope        Scope
		confirmation string
	}{
		{"non-human admin", Principal{ID: "automation", Role: RoleAdmin}, Scope{WorkspaceID: "local", Repository: "evalops/platform", AgentID: "codex"}, "APPROVE"},
		{"wrong confirmation", human, Scope{WorkspaceID: "local", Repository: "evalops/platform", AgentID: "codex"}, "approve"},
		{"wildcard repository", human, Scope{WorkspaceID: "local", Repository: "evalops/**", AgentID: "codex"}, "APPROVE"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := RotateAgentScope(path, tt.actor, "codex-local", tt.scope, tt.confirmation); err == nil {
				t.Fatal("rotation succeeded")
			}
			registry, err := LoadRegistry(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := registry.Authenticate(token); err != nil {
				t.Fatalf("rejected rotation revoked token: %v", err)
			}
			if len(registry.CredentialMutationReceipts()) != 0 {
				t.Fatal("rejected rotation persisted a receipt")
			}
		})
	}
}

func TestLoadRegistryRejectsInvalidFiles(t *testing.T) {
	validDigest := strings.Repeat("a", 64)
	tests := []struct {
		name string
		body any
	}{
		{"unsupported version", map[string]any{"version": 2, "credentials": []any{}}},
		{"unknown field", map[string]any{"version": 1, "credentials": []any{}, "extra": true}},
		{"duplicate id", map[string]any{"version": 1, "credentials": []any{
			map[string]any{"id": "same", "role": "admin", "token_sha256": validDigest},
			map[string]any{"id": "same", "role": "admin", "token_sha256": validDigest},
		}}},
		{"bad digest", map[string]any{"version": 1, "credentials": []any{
			map[string]any{"id": "admin", "role": "admin", "token_sha256": "plaintext"},
		}}},
		{"agent missing scope", map[string]any{"version": 1, "credentials": []any{
			map[string]any{"id": "agent", "role": "agent", "token_sha256": validDigest},
		}}},
		{"agent invalid hook provider", map[string]any{"version": 1, "credentials": []any{
			map[string]any{"id": "agent", "role": "agent", "token_sha256": validDigest, "workspace_id": "w", "repository": "r", "agent_id": "a", "hook_provider": "untrusted"},
		}}},
		{"agent combines hook provider and MCP proxy", map[string]any{"version": 1, "credentials": []any{
			map[string]any{"id": "agent", "role": "agent", "token_sha256": validDigest, "workspace_id": "w", "repository": "r", "agent_id": "a", "hook_provider": "codex", "mcp_proxy": true},
		}}},
		{"admin has scope", map[string]any{"version": 1, "credentials": []any{
			map[string]any{"id": "admin", "role": "admin", "token_sha256": validDigest, "workspace_id": "w"},
		}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "credentials.json")
			data, _ := json.Marshal(tt.body)
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadRegistry(path); err == nil {
				t.Fatal("LoadRegistry succeeded for invalid registry")
			}
		})
	}
}

func TestLoadRegistryRejectsPermissiveMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"credentials":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRegistry(path); err == nil {
		t.Fatal("LoadRegistry accepted group/world-readable credentials")
	}
}

func TestExtractBearer(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer room_client_secret")
	if got, err := ExtractBearer(req); err != nil || got != "room_client_secret" {
		t.Fatalf("ExtractBearer = %q, %v", got, err)
	}
	for _, value := range []string{"", "Basic abc", "Bearer", "Bearer one two"} {
		req.Header.Set("Authorization", value)
		if _, err := ExtractBearer(req); err != ErrUnauthenticated {
			t.Errorf("header %q error = %v", value, err)
		}
	}
}

func TestContextHelpers(t *testing.T) {
	want := Principal{ID: "operator", Role: RoleAdmin}
	ctx := WithPrincipal(context.Background(), want)
	got, ok := PrincipalFromContext(ctx)
	if !ok || got != want {
		t.Fatalf("PrincipalFromContext = %#v, %v", got, ok)
	}
	if _, ok := PrincipalFromContext(context.Background()); ok {
		t.Fatal("empty context contained a principal")
	}
}

func TestAuthenticationMiddlewareUsesSafeUnauthorizedResponse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	token, err := IssueOrUpdateToken(path, Principal{ID: "operator", Role: RoleAdmin})
	if err != nil {
		t.Fatal(err)
	}
	registry, _ := LoadRegistry(path)
	var called bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		principal, ok := PrincipalFromContext(r.Context())
		if !ok || principal.ID != "operator" {
			t.Fatal("authenticated principal missing from context")
		}
		w.WriteHeader(http.StatusNoContent)
	})
	handler := registry.Middleware(next)

	bad := httptest.NewRequest(http.MethodGet, "/", nil)
	bad.Header.Set("Authorization", "Bearer room_operator_wrong")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, bad)
	if recorder.Code != http.StatusUnauthorized || called {
		t.Fatalf("invalid request status=%d called=%v", recorder.Code, called)
	}
	if got := recorder.Body.String(); got != "unauthorized\n" {
		t.Fatalf("unsafe unauthorized body %q", got)
	}
	if got := recorder.Header().Get("WWW-Authenticate"); got != `Bearer realm="room"` {
		t.Fatalf("WWW-Authenticate = %q", got)
	}

	good := httptest.NewRequest(http.MethodGet, "/", nil)
	good.Header.Set("Authorization", "Bearer "+token)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, good)
	if recorder.Code != http.StatusNoContent || !called {
		t.Fatalf("valid request status=%d called=%v", recorder.Code, called)
	}
}

func TestAuthorizationMiddlewareEnforcesRoleAndExactAgentScope(t *testing.T) {
	agent := Principal{ID: "runner", Role: RoleAgent, Scope: Scope{WorkspaceID: "w1", Repository: "repo1", AgentID: "a1"}}
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })

	tests := []struct {
		name      string
		handler   http.Handler
		principal Principal
		want      int
	}{
		{"role allowed", RequireRole(RoleAgent)(ok), agent, http.StatusNoContent},
		{"role denied", RequireRole(RoleAdmin)(ok), agent, http.StatusForbidden},
		{"any role allowed", RequireAnyRole(RoleAdmin, RoleAgent)(ok), agent, http.StatusNoContent},
		{"scope allowed", RequireAgentScope(Scope{WorkspaceID: "w1", Repository: "repo1", AgentID: "a1"})(ok), agent, http.StatusNoContent},
		{"workspace mismatch", RequireAgentScope(Scope{WorkspaceID: "w2", Repository: "repo1", AgentID: "a1"})(ok), agent, http.StatusForbidden},
		{"repository mismatch", RequireAgentScope(Scope{WorkspaceID: "w1", Repository: "repo2", AgentID: "a1"})(ok), agent, http.StatusForbidden},
		{"agent mismatch", RequireAgentScope(Scope{WorkspaceID: "w1", Repository: "repo1", AgentID: "a2"})(ok), agent, http.StatusForbidden},
		{"missing principal", RequireRole(RoleAgent)(ok), Principal{}, http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.principal.ID != "" {
				req = req.WithContext(WithPrincipal(req.Context(), tt.principal))
			}
			recorder := httptest.NewRecorder()
			tt.handler.ServeHTTP(recorder, req)
			if recorder.Code != tt.want {
				t.Fatalf("status = %d, want %d", recorder.Code, tt.want)
			}
			if tt.want == http.StatusForbidden && recorder.Body.String() != "forbidden\n" {
				t.Fatalf("unsafe forbidden body %q", recorder.Body.String())
			}
		})
	}
}
