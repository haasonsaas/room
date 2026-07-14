package compliance

import (
	"testing"

	roomv1 "github.com/haasonsaas/room/gen/go/room/v1"
	"google.golang.org/protobuf/proto"
)

func TestEvaluateRejectsUnknownIdentityWhenConfigured(t *testing.T) {
	policy := allowlistPolicy(selector("filesystem", "read_file"))
	policy.DenyUnknownIdentity = true

	for _, assurance := range []roomv1.IdentityAssurance{
		roomv1.IdentityAssurance_IDENTITY_ASSURANCE_UNSPECIFIED,
		roomv1.IdentityAssurance_IDENTITY_ASSURANCE_UNVERIFIED,
		roomv1.IdentityAssurance(99),
	} {
		decision := Evaluate(policy, directInvocation("filesystem", "read_file", assurance))
		assertDecision(t, decision, false, ReasonIdentityUnknown, nil)
	}
}

func TestEvaluateAllowsPolicyEvaluationForTrustedIdentity(t *testing.T) {
	policy := allowlistPolicy(selector("filesystem", "read_file"))
	policy.DenyUnknownIdentity = true

	for _, assurance := range []roomv1.IdentityAssurance{
		roomv1.IdentityAssurance_IDENTITY_ASSURANCE_CONFIG_BOUND,
		roomv1.IdentityAssurance_IDENTITY_ASSURANCE_TRANSPORT_VERIFIED,
	} {
		decision := Evaluate(policy, directInvocation("filesystem", "read_file", assurance))
		assertDecision(t, decision, true, ReasonAllowlistMatch, selector("filesystem", "read_file"))
	}
}

func TestEvaluateUnknownIdentityFollowsPolicyFlag(t *testing.T) {
	policy := allowlistPolicy(selector("filesystem", "read_file"))
	policy.DenyUnknownIdentity = false

	decision := Evaluate(policy, directInvocation("filesystem", "read_file", roomv1.IdentityAssurance_IDENTITY_ASSURANCE_UNVERIFIED))
	assertDecision(t, decision, true, ReasonAllowlistMatch, selector("filesystem", "read_file"))
}

func TestEvaluateBindsOpaqueProviderToolID(t *testing.T) {
	policy := allowlistPolicy(selector("github", "create_pull_request"))
	policy.ProviderBindings = []*roomv1.ProviderToolBinding{{
		Provider:       roomv1.HookProvider_HOOK_PROVIDER_CLAUDE_CODE,
		ProviderToolId: "opaque-7f0a",
		ServerId:       "github",
		ToolName:       "create_pull_request",
	}}
	invocation := &roomv1.McpInvocation{
		Provider:          roomv1.HookProvider_HOOK_PROVIDER_CLAUDE_CODE,
		ProviderToolId:    "opaque-7f0a",
		IdentityAssurance: roomv1.IdentityAssurance_IDENTITY_ASSURANCE_CONFIG_BOUND,
	}

	decision := Evaluate(policy, invocation)
	assertDecision(t, decision, true, ReasonAllowlistMatch, selector("github", "create_pull_request"))
}

func TestEvaluateRejectsMissingProviderBindingWithoutParsingID(t *testing.T) {
	policy := allowlistPolicy(selector("github", "create_pull_request"))
	invocation := &roomv1.McpInvocation{
		Provider:          roomv1.HookProvider_HOOK_PROVIDER_CLAUDE_CODE,
		ProviderToolId:    "github__create_pull_request",
		IdentityAssurance: roomv1.IdentityAssurance_IDENTITY_ASSURANCE_CONFIG_BOUND,
	}

	decision := Evaluate(policy, invocation)
	assertDecision(t, decision, false, ReasonProviderBindingMissing, nil)
}

func TestEvaluateRejectsForgedCanonicalIdentity(t *testing.T) {
	policy := allowlistPolicy(selector("github", "create_pull_request"))
	policy.ProviderBindings = []*roomv1.ProviderToolBinding{{
		Provider:       roomv1.HookProvider_HOOK_PROVIDER_CODEX,
		ProviderToolId: "opaque-safe-tool",
		ServerId:       "github",
		ToolName:       "create_pull_request",
	}}
	invocation := &roomv1.McpInvocation{
		Provider:          roomv1.HookProvider_HOOK_PROVIDER_CODEX,
		ProviderToolId:    "opaque-safe-tool",
		ServerId:          "shell",
		ToolName:          "execute",
		IdentityAssurance: roomv1.IdentityAssurance_IDENTITY_ASSURANCE_CONFIG_BOUND,
	}

	decision := Evaluate(policy, invocation)
	assertDecision(t, decision, false, ReasonProviderBindingConflict, nil)
}

func TestEvaluateBindingIsScopedToProvider(t *testing.T) {
	policy := allowlistPolicy(selector("github", "create_pull_request"))
	policy.ProviderBindings = []*roomv1.ProviderToolBinding{{
		Provider:       roomv1.HookProvider_HOOK_PROVIDER_CODEX,
		ProviderToolId: "shared-looking-id",
		ServerId:       "github",
		ToolName:       "create_pull_request",
	}}
	invocation := &roomv1.McpInvocation{
		Provider:          roomv1.HookProvider_HOOK_PROVIDER_CURSOR,
		ProviderToolId:    "shared-looking-id",
		IdentityAssurance: roomv1.IdentityAssurance_IDENTITY_ASSURANCE_CONFIG_BOUND,
	}

	decision := Evaluate(policy, invocation)
	assertDecision(t, decision, false, ReasonProviderBindingMissing, nil)
}

func TestEvaluateRequiresBindingForProviderHook(t *testing.T) {
	policy := allowlistPolicy(selector("github", "create_pull_request"))
	invocation := &roomv1.McpInvocation{
		Provider:          roomv1.HookProvider_HOOK_PROVIDER_CURSOR,
		ServerId:          "github",
		ToolName:          "create_pull_request",
		IdentityAssurance: roomv1.IdentityAssurance_IDENTITY_ASSURANCE_CONFIG_BOUND,
	}

	decision := Evaluate(policy, invocation)
	assertDecision(t, decision, false, ReasonProviderBindingMissing, nil)
}

func TestEvaluateAllowlistExactAndWildcardSelectors(t *testing.T) {
	tests := []struct {
		name     string
		selector *roomv1.McpToolSelector
		server   string
		tool     string
		allowed  bool
	}{
		{name: "exact", selector: selector("github", "get_issue"), server: "github", tool: "get_issue", allowed: true},
		{name: "server wildcard", selector: selector("*", "get_issue"), server: "github", tool: "get_issue", allowed: true},
		{name: "tool wildcard", selector: selector("github", "*"), server: "github", tool: "delete_repo", allowed: true},
		{name: "global wildcard", selector: selector("*", "*"), server: "anything", tool: "anything", allowed: true},
		{name: "unknown tool", selector: selector("github", "get_issue"), server: "github", tool: "unknown", allowed: false},
		{name: "empty is not wildcard", selector: selector("github", ""), server: "github", tool: "get_issue", allowed: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := Evaluate(allowlistPolicy(tt.selector), trustedProxyInvocation(tt.server, tt.tool))
			if tt.allowed {
				assertDecision(t, decision, true, ReasonAllowlistMatch, tt.selector)
			} else {
				assertDecision(t, decision, false, ReasonAllowlistNoMatch, nil)
			}
		})
	}
}

func TestEvaluateBlocklistExactAndWildcardSelectors(t *testing.T) {
	tests := []struct {
		name     string
		selector *roomv1.McpToolSelector
		server   string
		tool     string
		blocked  bool
	}{
		{name: "exact", selector: selector("shell", "execute"), server: "shell", tool: "execute", blocked: true},
		{name: "server wildcard", selector: selector("*", "execute"), server: "shell", tool: "execute", blocked: true},
		{name: "tool wildcard", selector: selector("shell", "*"), server: "shell", tool: "read", blocked: true},
		{name: "global wildcard", selector: selector("*", "*"), server: "safe", tool: "read", blocked: true},
		{name: "not listed", selector: selector("shell", "execute"), server: "github", tool: "get_issue", blocked: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &roomv1.McpCompliancePolicy{
				Mode:      roomv1.McpComplianceMode_MCP_COMPLIANCE_MODE_BLOCKLIST,
				Selectors: []*roomv1.McpToolSelector{tt.selector},
			}
			decision := Evaluate(policy, trustedProxyInvocation(tt.server, tt.tool))
			if tt.blocked {
				assertDecision(t, decision, false, ReasonBlocklistMatch, tt.selector)
			} else {
				assertDecision(t, decision, true, ReasonBlocklistNoMatch, nil)
			}
		})
	}
}

func TestEvaluateReturnsMostSpecificMatchedSelector(t *testing.T) {
	policy := allowlistPolicy(
		selector("*", "*"),
		selector("github", "*"),
		selector("github", "get_issue"),
	)

	decision := Evaluate(policy, trustedProxyInvocation("github", "get_issue"))
	assertDecision(t, decision, true, ReasonAllowlistMatch, selector("github", "get_issue"))
}

func TestEvaluateIgnoresDisplayAndEndpointStrings(t *testing.T) {
	policy := allowlistPolicy(selector("github", "get_issue"))
	first := trustedProxyInvocation("github", "get_issue")
	first.Transport = "friendly github get_issue label"
	first.Endpoint = "https://example.invalid/shell/execute"
	second := proto.Clone(first).(*roomv1.McpInvocation)
	second.Transport = "totally different display copy"
	second.Endpoint = "stdio://delete-everything"

	want := Evaluate(policy, first)
	got := Evaluate(policy, second)
	if !proto.Equal(got, want) {
		t.Fatalf("display strings changed decision: got %v, want %v", got, want)
	}
}

func TestEvaluateRejectsMissingCanonicalTool(t *testing.T) {
	decision := Evaluate(allowlistPolicy(selector("github", "*")), trustedProxyInvocation("github", ""))
	assertDecision(t, decision, false, ReasonInvocationInvalid, nil)
}

func TestEvaluateDisabledAndInvalidModes(t *testing.T) {
	disabled := &roomv1.McpCompliancePolicy{Mode: roomv1.McpComplianceMode_MCP_COMPLIANCE_MODE_DISABLED}
	assertDecision(t, Evaluate(disabled, &roomv1.McpInvocation{}), true, ReasonPolicyDisabled, nil)
	assertDecision(t, Evaluate(nil, trustedProxyInvocation("github", "get_issue")), false, ReasonPolicyInvalid, nil)
	assertDecision(t, Evaluate(&roomv1.McpCompliancePolicy{}, trustedProxyInvocation("github", "get_issue")), false, ReasonPolicyInvalid, nil)
}

func allowlistPolicy(selectors ...*roomv1.McpToolSelector) *roomv1.McpCompliancePolicy {
	return &roomv1.McpCompliancePolicy{
		Mode:      roomv1.McpComplianceMode_MCP_COMPLIANCE_MODE_ALLOWLIST,
		Selectors: selectors,
	}
}

func selector(server, tool string) *roomv1.McpToolSelector {
	return &roomv1.McpToolSelector{ServerId: server, ToolName: tool}
}

func directInvocation(server, tool string, assurance roomv1.IdentityAssurance) *roomv1.McpInvocation {
	return &roomv1.McpInvocation{
		ServerId:          server,
		ToolName:          tool,
		Provider:          roomv1.HookProvider_HOOK_PROVIDER_MCP_PROXY,
		IdentityAssurance: assurance,
	}
}

func trustedProxyInvocation(server, tool string) *roomv1.McpInvocation {
	return directInvocation(server, tool, roomv1.IdentityAssurance_IDENTITY_ASSURANCE_TRANSPORT_VERIFIED)
}

func assertDecision(t *testing.T, got *roomv1.McpInvocationDecision, allowed bool, reason string, matched *roomv1.McpToolSelector) {
	t.Helper()
	if got == nil {
		t.Fatal("Evaluate returned nil")
	}
	if got.Allowed != allowed || got.ReasonCode != reason || !proto.Equal(got.MatchedSelector, matched) {
		t.Fatalf("decision = %+v, want allowed=%v reason=%q selector=%v", got, allowed, reason, matched)
	}
}
