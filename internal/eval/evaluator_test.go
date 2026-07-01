package eval

import (
	"testing"

	roomv1 "github.com/haasonsaas/room/gen/go/room/v1"
)

func TestTenantPlanWithoutOrgScopeDenied(t *testing.T) {
	rules := []*roomv1.Rule{
		{
			Id:       "tenant-org-scope-required",
			Title:    "Tenant data must be organization scoped",
			Severity: roomv1.Severity_SEVERITY_CRITICAL,
			Enabled:  true,
			Checks: []*roomv1.RuleCheck{
				{Kind: roomv1.CheckKind_CHECK_KIND_HEURISTIC, Expression: "touches_tenant_data_without_scope"},
			},
		},
	}

	result := Evaluate(rules, nil, &roomv1.EvaluationInput{
		Plan: "Add a customer endpoint that queries projects from the database.",
	})

	if result.GetDecision() != roomv1.Decision_DECISION_DENY {
		t.Fatalf("decision = %s, want deny", result.GetDecision())
	}
	if len(result.GetMatches()) != 1 {
		t.Fatalf("matches = %d, want 1", len(result.GetMatches()))
	}
}

func TestTenantPlanWithOrgScopeAllowed(t *testing.T) {
	rules := []*roomv1.Rule{
		{
			Id:       "tenant-org-scope-required",
			Title:    "Tenant data must be organization scoped",
			Severity: roomv1.Severity_SEVERITY_CRITICAL,
			Enabled:  true,
			Checks: []*roomv1.RuleCheck{
				{Kind: roomv1.CheckKind_CHECK_KIND_HEURISTIC, Expression: "touches_tenant_data_without_scope"},
			},
		},
	}

	result := Evaluate(rules, nil, &roomv1.EvaluationInput{
		Plan: "Add a customer endpoint that queries projects with organization_id from authenticated context and adds a cross-org denial test.",
	})

	if result.GetDecision() != roomv1.Decision_DECISION_ALLOW {
		t.Fatalf("decision = %s, want allow", result.GetDecision())
	}
}
