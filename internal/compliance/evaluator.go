// Package compliance evaluates typed MCP invocation policy.
package compliance

import roomv1 "github.com/haasonsaas/room/gen/go/room/v1"

const (
	ReasonPolicyDisabled          = "mcp_policy_disabled"
	ReasonPolicyInvalid           = "mcp_policy_invalid"
	ReasonIdentityUnknown         = "mcp_identity_unknown"
	ReasonProviderBindingMissing  = "mcp_provider_binding_missing"
	ReasonProviderBindingConflict = "mcp_provider_binding_conflict"
	ReasonInvocationInvalid       = "mcp_invocation_invalid"
	ReasonAllowlistMatch          = "mcp_allowlist_match"
	ReasonAllowlistNoMatch        = "mcp_allowlist_no_match"
	ReasonBlocklistMatch          = "mcp_blocklist_match"
	ReasonBlocklistNoMatch        = "mcp_blocklist_no_match"
)

// Evaluate returns a deterministic decision derived only from typed invocation
// identity, explicit provider bindings, and policy selectors.
func Evaluate(policy *roomv1.McpCompliancePolicy, invocation *roomv1.McpInvocation) *roomv1.McpInvocationDecision {
	if policy == nil {
		return decision(false, ReasonPolicyInvalid, nil)
	}

	switch policy.GetMode() {
	case roomv1.McpComplianceMode_MCP_COMPLIANCE_MODE_DISABLED:
		return decision(true, ReasonPolicyDisabled, nil)
	case roomv1.McpComplianceMode_MCP_COMPLIANCE_MODE_ALLOWLIST,
		roomv1.McpComplianceMode_MCP_COMPLIANCE_MODE_BLOCKLIST:
		// Continue below.
	default:
		return decision(false, ReasonPolicyInvalid, nil)
	}

	if invocation == nil {
		return decision(false, ReasonInvocationInvalid, nil)
	}
	if !trustedIdentity(invocation.GetIdentityAssurance()) && policy.GetDenyUnknownIdentity() {
		return decision(false, ReasonIdentityUnknown, nil)
	}

	serverID, toolName, reason := canonicalTool(policy, invocation)
	if reason != "" {
		return decision(false, reason, nil)
	}
	if serverID == "" || toolName == "" {
		return decision(false, ReasonInvocationInvalid, nil)
	}

	matched := bestMatch(policy.GetSelectors(), serverID, toolName)
	switch policy.GetMode() {
	case roomv1.McpComplianceMode_MCP_COMPLIANCE_MODE_ALLOWLIST:
		if matched == nil {
			return decision(false, ReasonAllowlistNoMatch, nil)
		}
		return decision(true, ReasonAllowlistMatch, matched)
	case roomv1.McpComplianceMode_MCP_COMPLIANCE_MODE_BLOCKLIST:
		if matched != nil {
			return decision(false, ReasonBlocklistMatch, matched)
		}
		return decision(true, ReasonBlocklistNoMatch, nil)
	default:
		return decision(false, ReasonPolicyInvalid, nil)
	}
}

func trustedIdentity(assurance roomv1.IdentityAssurance) bool {
	return assurance == roomv1.IdentityAssurance_IDENTITY_ASSURANCE_CONFIG_BOUND ||
		assurance == roomv1.IdentityAssurance_IDENTITY_ASSURANCE_TRANSPORT_VERIFIED
}

func canonicalTool(policy *roomv1.McpCompliancePolicy, invocation *roomv1.McpInvocation) (string, string, string) {
	providerToolID := invocation.GetProviderToolId()
	if providerToolID == "" {
		if requiresProviderBinding(invocation.GetProvider()) {
			return "", "", ReasonProviderBindingMissing
		}
		return invocation.GetServerId(), invocation.GetToolName(), ""
	}

	for _, binding := range policy.GetProviderBindings() {
		if binding == nil || binding.GetProvider() != invocation.GetProvider() || binding.GetProviderToolId() != providerToolID {
			continue
		}
		if binding.GetServerId() == "" || binding.GetToolName() == "" {
			return "", "", ReasonProviderBindingMissing
		}
		if (invocation.GetServerId() != "" && invocation.GetServerId() != binding.GetServerId()) ||
			(invocation.GetToolName() != "" && invocation.GetToolName() != binding.GetToolName()) {
			return "", "", ReasonProviderBindingConflict
		}
		return binding.GetServerId(), binding.GetToolName(), ""
	}

	return "", "", ReasonProviderBindingMissing
}

func requiresProviderBinding(provider roomv1.HookProvider) bool {
	return provider != roomv1.HookProvider_HOOK_PROVIDER_UNSPECIFIED &&
		provider != roomv1.HookProvider_HOOK_PROVIDER_MCP_PROXY
}

func bestMatch(selectors []*roomv1.McpToolSelector, serverID, toolName string) *roomv1.McpToolSelector {
	var best *roomv1.McpToolSelector
	bestSpecificity := -1
	for _, selector := range selectors {
		if selector == nil || !selectorPartMatches(selector.GetServerId(), serverID) || !selectorPartMatches(selector.GetToolName(), toolName) {
			continue
		}
		specificity := 0
		if selector.GetServerId() != "*" {
			specificity++
		}
		if selector.GetToolName() != "*" {
			specificity++
		}
		if specificity > bestSpecificity {
			best = selector
			bestSpecificity = specificity
		}
	}
	return best
}

func selectorPartMatches(selector, actual string) bool {
	return selector == "*" || (selector != "" && selector == actual)
}

func decision(allowed bool, reason string, matched *roomv1.McpToolSelector) *roomv1.McpInvocationDecision {
	return &roomv1.McpInvocationDecision{
		Allowed:         allowed,
		ReasonCode:      reason,
		MatchedSelector: matched,
	}
}
