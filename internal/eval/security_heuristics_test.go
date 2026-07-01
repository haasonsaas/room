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
		{
			name:       "rust unsafe without safety rationale",
			expression: "rust_unsafe_without_safety_rationale",
			plan:       "Add Rust code in src/ffi.rs with unsafe fn parse_ptr(ptr: *const u8) { unsafe { *ptr }; }.",
		},
		{
			name:       "rust unwrap in request path",
			expression: "rust_unwrap_or_expect_in_request_path",
			plan:       "Update the axum API handler to parse the request body with payload.user_id.parse::<Uuid>().unwrap().",
		},
		{
			name:       "rust command with user input",
			expression: "rust_command_with_user_input",
			plan:       "In a Rust upload endpoint, pass the request filename into std::process::Command::new(\"convert\").arg(filename).output().",
		},
		{
			name:       "rust weak rng for secret",
			expression: "rust_weak_rng_for_secret",
			plan:       "Generate password reset tokens in Rust with rand::thread_rng and store them on the session.",
		},
		{
			name:       "rust path traversal without canonicalize",
			expression: "rust_path_traversal_without_canonicalize",
			plan:       "Build a Rust download handler that takes a user supplied filename and uses PathBuf::push before tokio::fs::read.",
		},
		{
			name:       "rust panic in library api",
			expression: "rust_panic_in_library_or_api",
			plan:       "Add a Rust library API for billing calculations and call panic!(\"invalid state\") on bad input.",
		},
		{
			name:       "rust std mutex across await",
			expression: "rust_std_mutex_across_await",
			plan:       "In an async Rust axum service, lock a std::sync::Mutex and then call client.fetch().await while the guard is held.",
		},
		{
			name:       "rust serde external input missing deny unknown fields",
			expression: "rust_serde_external_input_missing_deny_unknown_fields",
			plan:       "Create a Rust webhook JSON payload struct with #[derive(Deserialize)] using serde for external input.",
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

func TestTenantScopeHeuristicIgnoresPlainHandlers(t *testing.T) {
	rules := []*roomv1.Rule{{
		Id:       "tenant-org-scope-required",
		Title:    "Tenant data must be organization scoped",
		Severity: roomv1.Severity_SEVERITY_CRITICAL,
		Enabled:  true,
		Checks: []*roomv1.RuleCheck{
			{Kind: roomv1.CheckKind_CHECK_KIND_HEURISTIC, Expression: "touches_tenant_data_without_scope"},
		},
	}}

	result := Evaluate(rules, nil, &roomv1.EvaluationInput{
		Plan: "Add a Rust upload handler that shells out to convert a filename.",
	})
	if result.GetDecision() != roomv1.Decision_DECISION_ALLOW {
		t.Fatalf("decision = %s, want allow; matches = %v", result.GetDecision(), result.GetMatches())
	}
}
