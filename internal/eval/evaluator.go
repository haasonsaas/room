package eval

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	roomv1 "github.com/haasonsaas/room/gen/go/room/v1"
)

var secretPattern = regexp.MustCompile(`(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['"]?[a-z0-9_\-]{16,}`)

func Evaluate(rules []*roomv1.Rule, ruleset *roomv1.RulesetVersion, input *roomv1.EvaluationInput) *roomv1.EvaluationResult {
	if input == nil {
		input = &roomv1.EvaluationInput{}
	}
	context := input.GetContext()
	matches := make([]*roomv1.RuleMatch, 0)
	for _, rule := range rules {
		if rule == nil || !rule.GetEnabled() || !scopeMatches(rule.GetScope(), context) {
			continue
		}
		if ruleMatches(rule, input) {
			matches = append(matches, &roomv1.RuleMatch{
				RuleId:           rule.GetId(),
				Title:            rule.GetTitle(),
				Severity:         rule.GetSeverity(),
				Message:          ruleMessage(rule),
				Tags:             append([]string(nil), rule.GetTags()...),
				RequiredEvidence: append([]string(nil), rule.GetRequiredEvidence()...),
				Remediation:      append([]string(nil), rule.GetRemediation()...),
			})
		}
	}
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].Severity == matches[j].Severity {
			return matches[i].RuleId < matches[j].RuleId
		}
		return matches[i].Severity > matches[j].Severity
	})

	highest := roomv1.Severity_SEVERITY_UNSPECIFIED
	required := make([]string, 0)
	for _, match := range matches {
		if match.GetSeverity() > highest {
			highest = match.GetSeverity()
		}
		for _, evidence := range match.GetRequiredEvidence() {
			required = append(required, fmt.Sprintf("%s: %s", match.GetRuleId(), evidence))
		}
	}

	decision := roomv1.Decision_DECISION_ALLOW
	switch highest {
	case roomv1.Severity_SEVERITY_CRITICAL:
		decision = roomv1.Decision_DECISION_DENY
	case roomv1.Severity_SEVERITY_HIGH:
		decision = roomv1.Decision_DECISION_NEEDS_CHANGES
	case roomv1.Severity_SEVERITY_MEDIUM:
		decision = roomv1.Decision_DECISION_WARN
	case roomv1.Severity_SEVERITY_LOW, roomv1.Severity_SEVERITY_INFO:
		decision = roomv1.Decision_DECISION_WARN
	}

	result := &roomv1.EvaluationResult{
		Decision:        decision,
		HighestSeverity: highest,
		Matches:         matches,
		RequiredChecks:  dedupe(required),
	}
	if ruleset != nil {
		result.RulesetId = ruleset.GetId()
		result.RulesetVersion = ruleset.GetVersion()
		result.RulesetHash = ruleset.GetHash()
	}
	return result
}

func scopeMatches(scope *roomv1.RuleScope, context *roomv1.EvaluationContext) bool {
	if scope == nil || context == nil {
		return true
	}
	if !listMatches(scope.GetWorkspaces(), context.GetWorkspaceId()) {
		return false
	}
	if !listMatches(scope.GetRepositories(), context.GetRepository()) {
		return false
	}
	if !listMatchesAny(scope.GetLanguages(), context.GetLanguages()) {
		return false
	}
	if !listMatchesAny(scope.GetFrameworks(), context.GetFrameworks()) {
		return false
	}
	if !listMatches(scope.GetAgentTypes(), context.GetAgentType()) {
		return false
	}
	if len(scope.GetPaths()) == 0 {
		return true
	}
	for _, changed := range context.GetChangedFiles() {
		for _, pattern := range scope.GetPaths() {
			if globMatch(pattern, changed) {
				return true
			}
		}
	}
	return len(context.GetChangedFiles()) == 0
}

func listMatches(patterns []string, value string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, pattern := range patterns {
		if globMatch(pattern, value) {
			return true
		}
	}
	return false
}

func listMatchesAny(patterns, values []string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, value := range values {
		if listMatches(patterns, value) {
			return true
		}
	}
	return false
}

func ruleMatches(rule *roomv1.Rule, input *roomv1.EvaluationInput) bool {
	checks := rule.GetChecks()
	if len(checks) == 0 {
		return false
	}
	for _, check := range checks {
		if checkMatches(check, input) {
			return true
		}
	}
	return false
}

func checkMatches(check *roomv1.RuleCheck, input *roomv1.EvaluationInput) bool {
	if check == nil {
		return false
	}
	expression := strings.TrimSpace(check.GetExpression())
	switch check.GetKind() {
	case roomv1.CheckKind_CHECK_KIND_PLAN_TEXT:
		return textExpressionMatches(expression, input.GetPlan())
	case roomv1.CheckKind_CHECK_KIND_DIFF_TEXT:
		return textExpressionMatches(expression, input.GetDiff())
	case roomv1.CheckKind_CHECK_KIND_FILE_PATH:
		for _, changed := range input.GetContext().GetChangedFiles() {
			if textExpressionMatches(expression, changed) {
				return true
			}
			for _, glob := range check.GetFileGlobs() {
				if globMatch(glob, changed) {
					return true
				}
			}
		}
		return false
	case roomv1.CheckKind_CHECK_KIND_HEURISTIC:
		return heuristicMatches(expression, input)
	default:
		return textExpressionMatches(expression, input.GetPlan()+"\n"+input.GetDiff())
	}
}

func textExpressionMatches(expression, text string) bool {
	expression = strings.TrimSpace(expression)
	textLower := strings.ToLower(text)
	switch {
	case expression == "", expression == "always":
		return true
	case strings.HasPrefix(expression, "contains_any:"):
		for _, token := range splitCSV(strings.TrimPrefix(expression, "contains_any:")) {
			if strings.Contains(textLower, strings.ToLower(token)) {
				return true
			}
		}
		return false
	case strings.HasPrefix(expression, "missing_any:"):
		for _, token := range splitCSV(strings.TrimPrefix(expression, "missing_any:")) {
			if strings.Contains(textLower, strings.ToLower(token)) {
				return false
			}
		}
		return true
	case strings.HasPrefix(expression, "regex:"):
		re, err := regexp.Compile(strings.TrimPrefix(expression, "regex:"))
		return err == nil && re.MatchString(text)
	default:
		return strings.Contains(textLower, strings.ToLower(expression))
	}
}

func heuristicMatches(expression string, input *roomv1.EvaluationInput) bool {
	text := strings.ToLower(input.GetPlan() + "\n" + input.GetDiff())
	switch strings.TrimSpace(expression) {
	case "touches_tenant_data_without_scope":
		touchesTenantEntity := containsAny(text, "tenant", "organization", "workspace", "account", "customer", "project", "membership")
		touchesTenantData := touchesTenantEntity || (containsAny(text, "user") && containsAny(text, "database", "query", "repository", "read", "write", "insert", "update", "delete"))
		hasScope := containsAny(text, "organization_id", "workspace_id", "tenant_id", "org-scoped", "workspace-scoped", "membership", "authorize", "authorization")
		return touchesTenantData && !hasScope
	case "secret_literal":
		return secretPattern.MatchString(input.GetPlan()) || secretPattern.MatchString(input.GetDiff())
	case "destructive_shell":
		return containsAny(text, "rm -rf", "drop database", "truncate table", "terraform destroy", "kubectl delete")
	case "protected_handler_without_auth_context":
		touchesProtectedPath := containsAny(text, "protected", "admin", "private", "authenticated", "handler", "endpoint", "route", "api")
		touchesData := containsAny(text, "database", "query", "invoice", "customer", "user", "account", "project", "order", "billing")
		hasAuthContext := containsAny(text, "auth", "session", "principal", "claims", "middleware", "authorize", "authenticated context")
		return touchesProtectedPath && touchesData && !hasAuthContext
	case "unsafe_sql_construction":
		touchesSQL := containsAny(text, "select ", "insert ", "update ", "delete ", "where ", "query", "sql")
		buildsDynamically := containsAny(text, "concatenat", "string builder", "sprintf", "fmt.sprintf", "template", "`select", "' +", "\" +")
		hasParameterization := containsAny(text, "parameter", "prepared", "bind", "placeholder", "$1", "?", "sqlc", "gorm", "query builder")
		return touchesSQL && buildsDynamically && !hasParameterization
	case "external_fetch_without_allowlist":
		fetchesExternal := containsAny(text, "http.get", "fetch(", "axios", "request(", "urlopen", "net/http", "external url", "user supplied url", "user-supplied url", "webhook")
		hasAllowlist := containsAny(text, "allowlist", "allowed host", "allowed domain", "url validation", "dns pin", "block private", "ssrf")
		return fetchesExternal && !hasAllowlist
	case "privilege_change_without_audit":
		changesPrivilege := containsAny(text, "grant", "role", "permission", "owner", "admin", "privilege", "membership", "invite")
		hasAudit := containsAny(text, "audit", "event", "log", "activity", "security trail")
		return changesPrivilege && !hasAudit
	case "webhook_without_signature_verification":
		handlesWebhook := containsAny(text, "webhook", "provider event", "callback endpoint", "stripe event", "github event")
		hasSignatureCheck := containsAny(text, "signature", "hmac", "verify", "verification", "secret header", "signed payload")
		return handlesWebhook && !hasSignatureCheck
	case "password_storage_without_hashing":
		handlesPassword := containsAny(text, "password")
		storesPassword := containsAny(text, "store", "save", "database", "persist", "insert")
		hasHashing := containsAny(text, "hash", "bcrypt", "argon2", "scrypt", "pbkdf2")
		return handlesPassword && storesPassword && !hasHashing
	case "public_sensitive_endpoint_without_rate_limit":
		publicEndpoint := containsAny(text, "public", "unauthenticated", "anonymous", "login", "signup", "password reset", "reset password")
		sensitiveFlow := containsAny(text, "login", "signup", "password", "otp", "token", "magic link", "reset")
		hasRateLimit := containsAny(text, "rate limit", "ratelimit", "throttle", "quota", "abuse limit")
		return publicEndpoint && sensitiveFlow && !hasRateLimit
	case "rust_unsafe_without_safety_rationale":
		usesUnsafe := containsAny(text, "unsafe {", "unsafe fn", "unsafe impl", "unsafe trait", "unsafe extern")
		hasSafetyRationale := containsAny(text, "safety:", "safety invariant", "soundness", "invariant", "justification")
		return usesUnsafe && !hasSafetyRationale
	case "rust_unwrap_or_expect_in_request_path":
		requestPath := containsAny(text, "handler", "endpoint", "route", "api", "request", "axum", "actix", "warp", "rocket")
		usesPanicResult := containsAny(text, ".unwrap()", ".expect(")
		hasFallibleHandling := containsAny(text, "map_err", "ok_or", "context(", "thiserror", "anyhow", "return error", "propagate")
		return requestPath && usesPanicResult && !hasFallibleHandling
	case "rust_command_with_user_input":
		usesCommand := containsAny(text, "std::process::command", "tokio::process::command", "command::new", ".arg(")
		userControlled := containsAny(text, "user input", "user supplied", "user-supplied", "request", "query param", "path param", "payload", "filename", "form")
		hasAllowlist := containsAny(text, "allowlist", "allowed", "validated", "enum", "fixed args", "fixed argument", "no shell")
		return usesCommand && userControlled && !hasAllowlist
	case "rust_weak_rng_for_secret":
		weakRandom := containsAny(text, "rand::thread_rng", "rand::random", "smallrng", "fastrand")
		securitySensitive := containsAny(text, "token", "secret", "session", "password reset", "nonce", "api key", "credential")
		cryptoRandom := containsAny(text, "osrng", "rand_core::osrng", "getrandom", "ring::rand", "crypto rng", "cryptographic")
		return weakRandom && securitySensitive && !cryptoRandom
	case "rust_path_traversal_without_canonicalize":
		pathIO := containsAny(text, "pathbuf", "std::fs", "tokio::fs", "read_to_string", "file upload", "download", "filename", "user supplied path", "user-supplied path")
		userPath := containsAny(text, "user", "request", "param", "filename", "upload", "download")
		hasPathDefense := containsAny(text, "canonicalize", "starts_with", "safe base", "base dir", "sanitize", "path_clean")
		return pathIO && userPath && !hasPathDefense
	case "rust_panic_in_library_or_api":
		libraryOrAPI := containsAny(text, "library", "api", "handler", "service", "crate", "server")
		panics := containsAny(text, "panic!", "todo!", "unimplemented!", "unreachable!")
		return libraryOrAPI && panics
	case "rust_std_mutex_across_await":
		syncLock := containsAny(text, "std::sync::mutex", "std::sync::rwlock", "parking_lot::mutex", "parking_lot::rwlock")
		asyncContext := containsAny(text, "async", ".await", "tokio", "actix", "axum")
		hasSafeLocking := containsAny(text, "tokio::sync::mutex", "drop(", "release before await", "no await while locked")
		return syncLock && asyncContext && !hasSafeLocking
	case "rust_serde_external_input_missing_deny_unknown_fields":
		externalInput := containsAny(text, "api", "webhook", "request", "external input", "json", "payload")
		deserializes := containsAny(text, "serde", "deserialize", "#[derive(deserialize)]")
		hasValidation := containsAny(text, "deny_unknown_fields", "validator", "validate(", "schemars", "jsonschema")
		return externalInput && deserializes && !hasValidation
	default:
		return false
	}
}

func containsAny(text string, tokens ...string) bool {
	for _, token := range tokens {
		if strings.Contains(text, token) {
			return true
		}
	}
	return false
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func globMatch(pattern, value string) bool {
	pattern = strings.TrimSpace(pattern)
	value = strings.TrimSpace(value)
	if pattern == "" || pattern == "*" {
		return true
	}
	if ok, _ := filepath.Match(pattern, value); ok {
		return true
	}
	if strings.HasSuffix(pattern, "/**") {
		return strings.HasPrefix(value, strings.TrimSuffix(pattern, "**"))
	}
	return strings.EqualFold(pattern, value)
}

func dedupe(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func ruleMessage(rule *roomv1.Rule) string {
	if rule.GetDescription() != "" {
		return rule.GetDescription()
	}
	return rule.GetTitle()
}
