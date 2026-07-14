package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	roomv1 "github.com/haasonsaas/room/gen/go/room/v1"
	"github.com/haasonsaas/room/internal/auth"
	"github.com/haasonsaas/room/internal/config"
)

func TestHookFilePathsIncludesToolInputFilePath(t *testing.T) {
	paths := hookFilePaths(map[string]any{
		"tool_input": map[string]any{
			"file_path": "src/api.rs",
		},
	})

	if len(paths) != 1 || paths[0] != "src/api.rs" {
		t.Fatalf("paths = %v, want [src/api.rs]", paths)
	}
}

func TestPromptIndeterminateBlocks(t *testing.T) {
	output := captureJSON(t, func() error {
		return writeHookDecision("prompt", &roomv1.EvaluationResult{Decision: roomv1.Decision_DECISION_INDETERMINATE})
	})
	if output["decision"] != "block" {
		t.Fatalf("output = %#v", output)
	}
}

func TestPostToolFailureFailsClosedWithLifecycleNeutralBlock(t *testing.T) {
	t.Setenv("ROOM_HOOK_FAIL_OPEN", "false")
	output := captureJSON(t, func() error { return hookFailure("post-tool", errors.New("offline")) })
	if output["decision"] != "block" {
		t.Fatalf("output = %#v", output)
	}
	if _, leaked := output["hookSpecificOutput"]; leaked {
		t.Fatalf("post-tool failure emitted PreToolUse payload: %#v", output)
	}
}

func captureJSON(t *testing.T, run func() error) map[string]any {
	t.Helper()
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stdout
	os.Stdout = write
	err = run()
	_ = write.Close()
	os.Stdout = original
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	var output map[string]any
	if err := json.NewDecoder(read).Decode(&output); err != nil {
		t.Fatal(err)
	}
	return output
}

func TestTypedMCPInvocationDoesNotInferFromDisplayToolName(t *testing.T) {
	if invocation, ok := typedMCPInvocation(map[string]any{"tool_name": "mcp__github__create_issue"}); ok || invocation != nil {
		t.Fatal("ordinary display tool name must not be classified as MCP identity")
	}
}

func TestMCPPreToolFailsClosedWithoutTypedMetadata(t *testing.T) {
	t.Setenv("ROOM_HOOK_FAIL_OPEN", "false")
	output := captureJSON(t, func() error {
		handled, err := enforceMCPPreTool(context.Background(), nil, &roomv1.EvaluationContext{}, map[string]any{"tool_name": "opaque-display-name"})
		if !handled {
			t.Fatal("missing MCP metadata was not handled")
		}
		return err
	})
	hookOutput, ok := output["hookSpecificOutput"].(map[string]any)
	if !ok || hookOutput["permissionDecision"] != "deny" {
		t.Fatalf("output = %#v, want pre-tool denial", output)
	}
}

func TestTypedMCPInvocationUsesExplicitContract(t *testing.T) {
	invocation, ok := typedMCPInvocation(map[string]any{"room_mcp_invocation": map[string]any{
		"provider": "codex", "provider_tool_id": "opaque-123", "identity_assurance": "config_bound",
	}})
	if !ok {
		t.Fatal("typed invocation not recognized")
	}
	if invocation.GetProvider() != roomv1.HookProvider_HOOK_PROVIDER_CODEX || invocation.GetProviderToolId() != "opaque-123" || invocation.GetIdentityAssurance() != roomv1.IdentityAssurance_IDENTITY_ASSURANCE_CONFIG_BOUND {
		t.Fatalf("invocation = %+v", invocation)
	}
}

func TestUniqueNonEmptyDeduplicatesHookFiles(t *testing.T) {
	got := uniqueNonEmpty([]string{"src/api.rs", "", " src/api.rs ", "src/lib.rs"})
	want := []string{"src/api.rs", "src/lib.rs"}
	if len(got) != len(want) {
		t.Fatalf("paths = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("paths = %v, want %v", got, want)
		}
	}
}

func TestIssueTokenPersistsTrustedTransportCapabilities(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want auth.Scope
	}{
		{
			name: "configured hook provider",
			args: []string{"issue", "--id", "hook-agent", "--role", "agent", "--workspace", "w", "--repository", "r", "--agent", "a", "--hook-provider", "codex"},
			want: auth.Scope{WorkspaceID: "w", Repository: "r", AgentID: "a", HookProvider: auth.HookProviderCodex},
		},
		{
			name: "MCP proxy",
			args: []string{"issue", "--id", "proxy-agent", "--role", "agent", "--workspace", "w", "--repository", "r", "--agent", "a", "--mcp-proxy"},
			want: auth.Scope{WorkspaceID: "w", Repository: "r", AgentID: "a", HookProvider: auth.HookProviderNone, MCPProxy: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			credentialPath := filepath.Join(dir, "credentials.json")
			tokenPath := filepath.Join(dir, "token")
			args := append(append([]string(nil), tt.args...), "--output", tokenPath)
			if err := issueToken(config.Config{CredentialFile: credentialPath}, args); err != nil {
				t.Fatalf("issue token: %v", err)
			}
			token, err := os.ReadFile(tokenPath)
			if err != nil {
				t.Fatalf("read token: %v", err)
			}
			registry, err := auth.LoadRegistry(credentialPath)
			if err != nil {
				t.Fatalf("load registry: %v", err)
			}
			principal, err := registry.Authenticate(strings.TrimSpace(string(token)))
			if err != nil {
				t.Fatalf("authenticate token: %v", err)
			}
			if principal.Scope != tt.want {
				t.Fatalf("scope = %#v, want %#v", principal.Scope, tt.want)
			}
		})
	}
}

func TestReconnectDelayIsBoundedExponential(t *testing.T) {
	for attempt := 0; attempt <= 8; attempt++ {
		got := reconnectDelay(attempt)
		capped := attempt
		if capped > 5 {
			capped = 5
		}
		maximum := time.Second << capped
		if got < maximum/2 || got > maximum {
			t.Fatalf("attempt %d delay = %s, want [%s,%s]", attempt, got, maximum/2, maximum)
		}
	}
}
