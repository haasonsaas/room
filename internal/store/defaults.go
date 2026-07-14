package store

import (
	roomv1 "github.com/haasonsaas/room/gen/go/room/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type builtinRule struct {
	id, title, description string
	severity               roomv1.Severity
	signal                 roomv1.SignalKind
	tags, paths            []string
	evidence, remediation  []string
}

var builtins = []builtinRule{
	{"tenant-org-scope-required", "Tenant data must be organization scoped", "Tenant-owned data access without a trusted organization or workspace boundary is prohibited.", roomv1.Severity_SEVERITY_CRITICAL, roomv1.SignalKind_SIGNAL_KIND_TENANT_ACCESS_WITHOUT_TRUSTED_SCOPE, []string{"security", "tenancy", "authorization"}, []string{"internal/**", "app/**", "src/**", "services/**"}, []string{"scope originates from authenticated context", "cross-organization denial test"}, []string{"use an organization-scoped repository or service"}},
	{"no-secret-literals", "Do not commit secret literals", "Secret literals must not enter source or configuration artifacts.", roomv1.Severity_SEVERITY_CRITICAL, roomv1.SignalKind_SIGNAL_KIND_SECRET_LITERAL, []string{"security", "secrets"}, nil, []string{"secret comes from the approved secret path"}, []string{"remove and rotate the credential"}},
	{"destructive-actions-need-approval", "Destructive operations require explicit approval", "Destructive tool actions require a durable approval receipt.", roomv1.Severity_SEVERITY_HIGH, roomv1.SignalKind_SIGNAL_KIND_DESTRUCTIVE_OPERATION, []string{"safety", "operations"}, nil, []string{"approval receipt identifies actor and operation"}, []string{"request approval or use a read-only operation"}},
	{"protected-handlers-require-auth-context", "Protected handlers must load auth context", "Protected access without a verified principal is prohibited.", roomv1.Severity_SEVERITY_HIGH, roomv1.SignalKind_SIGNAL_KIND_PROTECTED_ACCESS_WITHOUT_AUTH_CONTEXT, []string{"security", "authorization", "api"}, []string{"app/**", "src/**", "internal/**", "services/**"}, []string{"unauthenticated request coverage"}, []string{"derive authorization from trusted middleware"}},
	{"sql-must-be-parameterized", "SQL must be parameterized", "Untrusted input must not participate in dynamic SQL construction.", roomv1.Severity_SEVERITY_HIGH, roomv1.SignalKind_SIGNAL_KIND_DYNAMIC_SQL_WITH_UNTRUSTED_INPUT, []string{"security", "database", "injection"}, nil, []string{"query values are bound parameters"}, []string{"use parameters or a typed query builder"}},
	{"external-fetches-require-allowlist", "External fetches require destination policy", "Untrusted outbound destinations must be validated against network policy.", roomv1.Severity_SEVERITY_HIGH, roomv1.SignalKind_SIGNAL_KIND_UNTRUSTED_OUTBOUND_DESTINATION, []string{"security", "ssrf", "network"}, nil, []string{"destination validation blocks private networks"}, []string{"use a policy-enforced outbound client"}},
	{"privilege-changes-require-audit", "Privilege changes require audit events", "Privilege mutations without a durable audit event are prohibited.", roomv1.Severity_SEVERITY_HIGH, roomv1.SignalKind_SIGNAL_KIND_PRIVILEGE_MUTATION_WITHOUT_AUDIT, []string{"security", "audit", "authorization"}, nil, []string{"audit records actor, subject, action, and time"}, []string{"record the event atomically with the mutation"}},
	{"webhooks-require-signature-verification", "Webhooks require signature verification", "Unsigned external webhook payloads must not be trusted.", roomv1.Severity_SEVERITY_HIGH, roomv1.SignalKind_SIGNAL_KIND_UNSIGNED_WEBHOOK, []string{"security", "webhook"}, nil, []string{"signature is verified before processing"}, []string{"verify the provider signature over the raw payload"}},
	{"passwords-must-be-hashed", "Passwords must be hashed before storage", "Password persistence requires a dedicated password KDF.", roomv1.Severity_SEVERITY_CRITICAL, roomv1.SignalKind_SIGNAL_KIND_PASSWORD_PERSISTENCE_WITHOUT_KDF, []string{"security", "auth", "passwords"}, nil, []string{"approved KDF configuration"}, []string{"use Argon2, scrypt, bcrypt, or PBKDF2"}},
	{"sensitive-public-endpoints-need-rate-limits", "Sensitive public endpoints need rate limits", "Public credential flows require abuse controls.", roomv1.Severity_SEVERITY_HIGH, roomv1.SignalKind_SIGNAL_KIND_PUBLIC_CREDENTIAL_FLOW_WITHOUT_RATE_LIMIT, []string{"security", "abuse", "auth"}, nil, []string{"rate limit is enforced before sensitive work"}, []string{"add per-principal and per-network throttling"}},
	{"rust-unsafe-requires-safety-rationale", "Rust unsafe code requires a safety contract", "Unsafe Rust requires an explicit, analyzer-verifiable safety contract.", roomv1.Severity_SEVERITY_HIGH, roomv1.SignalKind_SIGNAL_KIND_RUST_UNSAFE_WITHOUT_SAFETY_CONTRACT, []string{"security", "rust", "unsafe"}, []string{"**/*.rs"}, []string{"safety invariant is documented and tested"}, []string{"remove unsafe or document its invariant"}},
	{"rust-request-paths-must-not-unwrap", "Rust request paths must not panic", "Request handling must return typed errors rather than panic.", roomv1.Severity_SEVERITY_HIGH, roomv1.SignalKind_SIGNAL_KIND_RUST_PANIC_IN_REQUEST_PATH, []string{"security", "rust", "availability"}, []string{"**/*.rs"}, []string{"failure path returns a typed error"}, []string{"replace unwrap or expect with error propagation"}},
	{"rust-command-exec-requires-allowlist", "Rust command execution requires typed arguments", "Untrusted arguments must not reach process execution.", roomv1.Severity_SEVERITY_HIGH, roomv1.SignalKind_SIGNAL_KIND_RUST_COMMAND_WITH_UNTRUSTED_ARGUMENT, []string{"security", "rust", "command-injection"}, []string{"**/*.rs"}, []string{"command and arguments come from typed allowlists"}, []string{"map input to fixed command arguments"}},
	{"rust-secrets-require-crypto-rng", "Rust secrets require cryptographic randomness", "Security-sensitive values require a cryptographic RNG.", roomv1.Severity_SEVERITY_CRITICAL, roomv1.SignalKind_SIGNAL_KIND_RUST_WEAK_RNG_FOR_SECRET, []string{"security", "rust", "crypto"}, []string{"**/*.rs"}, []string{"cryptographic RNG provenance"}, []string{"use OsRng or the platform CSPRNG"}},
	{"rust-paths-must-be-canonicalized", "Rust user paths must remain within a trusted root", "Untrusted paths require canonical containment checks.", roomv1.Severity_SEVERITY_HIGH, roomv1.SignalKind_SIGNAL_KIND_RUST_UNTRUSTED_PATH, []string{"security", "rust", "path-traversal"}, []string{"**/*.rs"}, []string{"canonical path remains under the trusted root"}, []string{"canonicalize and enforce containment"}},
	{"rust-library-api-must-not-panic", "Rust library and API code must not panic", "Library and API inputs must not trigger panic paths.", roomv1.Severity_SEVERITY_HIGH, roomv1.SignalKind_SIGNAL_KIND_RUST_PANIC_IN_LIBRARY_API, []string{"security", "rust", "availability"}, []string{"**/*.rs"}, []string{"invalid input returns a typed error"}, []string{"replace panic placeholders with typed errors"}},
	{"rust-no-std-mutex-across-await", "Rust async code must not hold blocking locks across await", "Blocking synchronization must not span an await point.", roomv1.Severity_SEVERITY_HIGH, roomv1.SignalKind_SIGNAL_KIND_RUST_BLOCKING_LOCK_ACROSS_AWAIT, []string{"security", "rust", "async"}, []string{"**/*.rs"}, []string{"lock lifetime ends before await"}, []string{"narrow the critical section or use an async-aware primitive"}},
	{"rust-serde-external-input-deny-unknown-fields", "Rust external input requires schema validation", "External deserialization requires an explicit closed schema or validator.", roomv1.Severity_SEVERITY_HIGH, roomv1.SignalKind_SIGNAL_KIND_RUST_UNVALIDATED_EXTERNAL_DESERIALIZATION, []string{"security", "rust", "serde"}, []string{"**/*.rs"}, []string{"external input is validated against a closed schema"}, []string{"deny unknown fields or validate explicitly"}},
}

func defaultRules() []*roomv1.Rule {
	now := timestamppb.Now()
	rules := make([]*roomv1.Rule, 0, len(builtins))
	for _, spec := range builtins {
		rules = append(rules, &roomv1.Rule{Id: spec.id, Title: spec.title, Description: spec.description, Severity: spec.severity, Tags: spec.tags, Scope: &roomv1.RuleScope{Paths: spec.paths}, Triggers: []*roomv1.SignalSelector{{Signal: spec.signal, Phases: []roomv1.AnalysisPhase{roomv1.AnalysisPhase_ANALYSIS_PHASE_PLAN, roomv1.AnalysisPhase_ANALYSIS_PHASE_DIFF}, MinimumConfidenceBasisPoints: 8000}}, RequiredCoverage: []roomv1.SignalKind{spec.signal}, RequiredEvidence: spec.evidence, Remediation: spec.remediation, Enabled: true, Owner: "room", CreatedAt: now, UpdatedAt: now})
	}
	return rules
}

var legacySignals = map[string]roomv1.SignalKind{
	"touches_tenant_data_without_scope":                     roomv1.SignalKind_SIGNAL_KIND_TENANT_ACCESS_WITHOUT_TRUSTED_SCOPE,
	"protected_handler_without_auth_context":                roomv1.SignalKind_SIGNAL_KIND_PROTECTED_ACCESS_WITHOUT_AUTH_CONTEXT,
	"secret_literal":                                        roomv1.SignalKind_SIGNAL_KIND_SECRET_LITERAL,
	"unsafe_sql_construction":                               roomv1.SignalKind_SIGNAL_KIND_DYNAMIC_SQL_WITH_UNTRUSTED_INPUT,
	"external_fetch_without_allowlist":                      roomv1.SignalKind_SIGNAL_KIND_UNTRUSTED_OUTBOUND_DESTINATION,
	"privilege_change_without_audit":                        roomv1.SignalKind_SIGNAL_KIND_PRIVILEGE_MUTATION_WITHOUT_AUDIT,
	"webhook_without_signature_verification":                roomv1.SignalKind_SIGNAL_KIND_UNSIGNED_WEBHOOK,
	"password_storage_without_hashing":                      roomv1.SignalKind_SIGNAL_KIND_PASSWORD_PERSISTENCE_WITHOUT_KDF,
	"public_sensitive_endpoint_without_rate_limit":          roomv1.SignalKind_SIGNAL_KIND_PUBLIC_CREDENTIAL_FLOW_WITHOUT_RATE_LIMIT,
	"destructive_shell":                                     roomv1.SignalKind_SIGNAL_KIND_DESTRUCTIVE_OPERATION,
	"rust_unsafe_without_safety_rationale":                  roomv1.SignalKind_SIGNAL_KIND_RUST_UNSAFE_WITHOUT_SAFETY_CONTRACT,
	"rust_unwrap_or_expect_in_request_path":                 roomv1.SignalKind_SIGNAL_KIND_RUST_PANIC_IN_REQUEST_PATH,
	"rust_command_with_user_input":                          roomv1.SignalKind_SIGNAL_KIND_RUST_COMMAND_WITH_UNTRUSTED_ARGUMENT,
	"rust_weak_rng_for_secret":                              roomv1.SignalKind_SIGNAL_KIND_RUST_WEAK_RNG_FOR_SECRET,
	"rust_path_traversal_without_canonicalize":              roomv1.SignalKind_SIGNAL_KIND_RUST_UNTRUSTED_PATH,
	"rust_panic_in_library_or_api":                          roomv1.SignalKind_SIGNAL_KIND_RUST_PANIC_IN_LIBRARY_API,
	"rust_std_mutex_across_await":                           roomv1.SignalKind_SIGNAL_KIND_RUST_BLOCKING_LOCK_ACROSS_AWAIT,
	"rust_serde_external_input_missing_deny_unknown_fields": roomv1.SignalKind_SIGNAL_KIND_RUST_UNVALIDATED_EXTERNAL_DESERIALIZATION,
}

func migrateKnownRules(rules []*roomv1.Rule) bool {
	migrated := false
	for _, rule := range rules {
		migrated = migrateKnownRule(rule) || migrated
	}
	return migrated
}

func migrateKnownRule(rule *roomv1.Rule) bool {
	if rule == nil || len(rule.GetTriggers()) > 0 || len(rule.GetChecks()) != 1 {
		return false
	}
	check := rule.GetChecks()[0]
	signal, ok := legacySignal(check)
	if !ok {
		return false
	}
	rule.Triggers = []*roomv1.SignalSelector{{Signal: signal, Phases: []roomv1.AnalysisPhase{roomv1.AnalysisPhase_ANALYSIS_PHASE_PLAN, roomv1.AnalysisPhase_ANALYSIS_PHASE_DIFF}, MinimumConfidenceBasisPoints: 8000}}
	rule.RequiredCoverage = []roomv1.SignalKind{signal}
	rule.Checks = nil
	rule.UpdatedAt = timestamppb.Now()
	return true
}

func legacySignal(check *roomv1.RuleCheck) (roomv1.SignalKind, bool) {
	if check == nil {
		return roomv1.SignalKind_SIGNAL_KIND_UNSPECIFIED, false
	}
	if check.GetKind() == roomv1.CheckKind_CHECK_KIND_PLAN_TEXT && check.GetExpression() == "missing_any:auth,session,principal,claims" {
		return roomv1.SignalKind_SIGNAL_KIND_PROTECTED_ACCESS_WITHOUT_AUTH_CONTEXT, true
	}
	if check.GetKind() != roomv1.CheckKind_CHECK_KIND_HEURISTIC {
		return roomv1.SignalKind_SIGNAL_KIND_UNSPECIFIED, false
	}
	signal, ok := legacySignals[check.GetExpression()]
	return signal, ok
}
