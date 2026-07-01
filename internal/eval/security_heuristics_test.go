package eval

import (
	"testing"

	roomv1 "github.com/haasonsaas/room/gen/go/room/v1"
)

func TestSecurityHeuristicsCatchUnsafePatterns(t *testing.T) {
	tests := []struct {
		name       string
		expression string
		plan       string
	}{
		{
			name:       "missing auth context",
			expression: "protected_handler_without_auth_context",
			plan:       "Add a protected admin endpoint that returns invoices from the database.",
		},
		{
			name:       "unsafe sql construction",
			expression: "unsafe_sql_construction",
			plan:       "Build a query by concatenating user input into SELECT * FROM projects WHERE name = ' + q.",
		},
		{
			name:       "ssrf without allowlist",
			expression: "external_fetch_without_allowlist",
			plan:       "Fetch a user supplied URL with http.Get and return the response.",
		},
		{
			name:       "missing audit for privilege change",
			expression: "privilege_change_without_audit",
			plan:       "Add role assignment so admins can grant owner permissions to users.",
		},
		{
			name:       "webhook without signature verification",
			expression: "webhook_without_signature_verification",
			plan:       "Add a public webhook endpoint that processes provider events.",
		},
		{
			name:       "password storage without hashing",
			expression: "password_storage_without_hashing",
			plan:       "Store user passwords in the account database during signup.",
		},
		{
			name:       "public sensitive endpoint without rate limiting",
			expression: "public_sensitive_endpoint_without_rate_limit",
			plan:       "Add a public password reset endpoint that sends login tokens.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules := []*roomv1.Rule{{
				Id:       tt.expression,
				Title:    tt.name,
				Severity: roomv1.Severity_SEVERITY_HIGH,
				Enabled:  true,
				Checks: []*roomv1.RuleCheck{
					{Kind: roomv1.CheckKind_CHECK_KIND_HEURISTIC, Expression: tt.expression},
				},
			}}
			result := Evaluate(rules, nil, &roomv1.EvaluationInput{Plan: tt.plan})
			if result.GetDecision() != roomv1.Decision_DECISION_NEEDS_CHANGES {
				t.Fatalf("decision = %s, want needs_changes", result.GetDecision())
			}
		})
	}
}
