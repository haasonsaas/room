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
		touchesTenantData := containsAny(text, "tenant", "organization", "workspace", "account", "customer", "project", "user", "membership", "database", "query", "repository", "handler", "endpoint")
		hasScope := containsAny(text, "organization_id", "workspace_id", "tenant_id", "org-scoped", "workspace-scoped", "membership", "authorize", "authorization")
		return touchesTenantData && !hasScope
	case "secret_literal":
		return secretPattern.MatchString(input.GetPlan()) || secretPattern.MatchString(input.GetDiff())
	case "destructive_shell":
		return containsAny(text, "rm -rf", "drop database", "truncate table", "terraform destroy", "kubectl delete")
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
