package eval

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	roomv1 "github.com/haasonsaas/room/gen/go/room/v1"
	"google.golang.org/protobuf/proto"
)

// Policy evaluates trusted analyzer receipts. Raw prompts, plans, diffs, labels,
// titles, summaries, and rule prose are intentionally absent from this API.
type Policy struct {
	trusted   map[string]*roomv1.AnalyzerIdentity
	auditOnly bool
}

func NewPolicy(trusted []*roomv1.AnalyzerIdentity, auditOnly bool) *Policy {
	identities := make(map[string]*roomv1.AnalyzerIdentity, len(trusted))
	for _, identity := range trusted {
		if identity != nil && identity.GetId() != "" {
			identities[identity.GetId()] = proto.Clone(identity).(*roomv1.AnalyzerIdentity)
		}
	}
	return &Policy{trusted: identities, auditOnly: auditOnly}
}

func (p *Policy) Evaluate(ruleset *roomv1.RulesetVersion, context *roomv1.EvaluationContext, report *roomv1.AnalysisReport) *roomv1.EvaluationResult {
	result := &roomv1.EvaluationResult{EvaluationId: newID(), Decision: roomv1.Decision_DECISION_INDETERMINATE}
	if ruleset != nil {
		result.RulesetId = ruleset.GetId()
		result.RulesetVersion = ruleset.GetVersion()
		result.RulesetHash = ruleset.GetHash()
	}
	if report != nil {
		result.AnalysisStatus = report.GetStatus()
		if report.GetArtifact() != nil {
			result.InputSha256 = bytes.Clone(report.GetArtifact().GetSha256())
		}
		for _, receipt := range report.GetReceipts() {
			if receipt != nil {
				result.AnalyzerReceipts = append(result.AnalyzerReceipts, proto.Clone(receipt).(*roomv1.AnalyzerReceipt))
			}
		}
	}

	if ruleset == nil {
		return p.withGap(result, roomv1.SignalKind_SIGNAL_KIND_UNSPECIFIED, "no_active_ruleset", roomv1.AnalysisStatus_ANALYSIS_STATUS_UNAVAILABLE)
	}

	validReceipts, validationGaps := p.validateReport(report)
	result.Gaps = append(result.Gaps, validationGaps...)
	coverage := make(map[roomv1.SignalKind]bool)
	maxConfidence := make(map[roomv1.SignalKind]uint32)
	for _, receipt := range validReceipts {
		for _, kind := range receipt.GetCoveredSignals() {
			if kind != roomv1.SignalKind_SIGNAL_KIND_UNSPECIFIED {
				coverage[kind] = true
			}
		}
		for _, signal := range receipt.GetSignals() {
			if confidence := signal.GetConfidenceBasisPoints(); confidence > maxConfidence[signal.GetKind()] {
				maxConfidence[signal.GetKind()] = confidence
			}
		}
	}

	verifiedContext := cloneContext(context)
	if report != nil && report.GetArtifact() != nil {
		verifiedContext.ChangedFiles = append([]string(nil), report.GetArtifact().GetChangedFiles()...)
	}
	phase := roomv1.AnalysisPhase_ANALYSIS_PHASE_UNSPECIFIED
	if report != nil && report.GetArtifact() != nil {
		phase = report.GetArtifact().GetPhase()
	}

	matches := make([]*roomv1.RuleMatch, 0)
	for _, rule := range ruleset.GetRules() {
		if rule == nil || !rule.GetEnabled() || !ScopeMatches(rule.GetScope(), verifiedContext) {
			continue
		}
		if len(rule.GetTriggers()) == 0 {
			result.Gaps = append(result.Gaps, &roomv1.EvaluationGap{Status: roomv1.AnalysisStatus_ANALYSIS_STATUS_INVALID, ReasonCode: "legacy_rule_not_executable"})
			continue
		}
		required := append([]roomv1.SignalKind(nil), rule.GetRequiredCoverage()...)
		if len(required) == 0 {
			for _, trigger := range rule.GetTriggers() {
				required = append(required, trigger.GetSignal())
			}
		}
		for _, kind := range dedupeKinds(required) {
			if kind != roomv1.SignalKind_SIGNAL_KIND_UNSPECIFIED && !coverage[kind] {
				result.Gaps = append(result.Gaps, &roomv1.EvaluationGap{RequiredSignal: kind, Status: result.GetAnalysisStatus(), ReasonCode: "required_signal_not_covered"})
			}
		}
		if triggered(rule.GetTriggers(), phase, maxConfidence) {
			matches = append(matches, &roomv1.RuleMatch{
				RuleId: rule.GetId(), Title: rule.GetTitle(), Severity: rule.GetSeverity(), Message: ruleMessage(rule),
				Tags: append([]string(nil), rule.GetTags()...), RequiredEvidence: append([]string(nil), rule.GetRequiredEvidence()...), Remediation: append([]string(nil), rule.GetRemediation()...),
			})
		}
	}

	result.Gaps = dedupeGaps(result.GetGaps())
	if len(result.GetGaps()) > 0 {
		if p.auditOnly {
			result.Decision = roomv1.Decision_DECISION_WARN
		} else {
			result.Decision = roomv1.Decision_DECISION_INDETERMINATE
		}
		return result
	}

	sort.Slice(matches, func(i, j int) bool {
		if matches[i].GetSeverity() == matches[j].GetSeverity() {
			return matches[i].GetRuleId() < matches[j].GetRuleId()
		}
		return matches[i].GetSeverity() > matches[j].GetSeverity()
	})
	result.Matches = matches
	result.Decision = roomv1.Decision_DECISION_ALLOW
	for _, match := range matches {
		if match.GetSeverity() > result.GetHighestSeverity() {
			result.HighestSeverity = match.GetSeverity()
		}
		for _, evidence := range match.GetRequiredEvidence() {
			result.RequiredChecks = append(result.RequiredChecks, fmt.Sprintf("%s: %s", match.GetRuleId(), evidence))
		}
	}
	result.RequiredChecks = dedupeStrings(result.GetRequiredChecks())
	switch result.GetHighestSeverity() {
	case roomv1.Severity_SEVERITY_CRITICAL:
		result.Decision = roomv1.Decision_DECISION_DENY
	case roomv1.Severity_SEVERITY_HIGH:
		result.Decision = roomv1.Decision_DECISION_NEEDS_CHANGES
	case roomv1.Severity_SEVERITY_MEDIUM, roomv1.Severity_SEVERITY_LOW, roomv1.Severity_SEVERITY_INFO:
		result.Decision = roomv1.Decision_DECISION_WARN
	}
	return result
}

func (p *Policy) validateReport(report *roomv1.AnalysisReport) ([]*roomv1.AnalyzerReceipt, []*roomv1.EvaluationGap) {
	if report == nil || report.GetArtifact() == nil {
		return nil, []*roomv1.EvaluationGap{{Status: roomv1.AnalysisStatus_ANALYSIS_STATUS_UNAVAILABLE, ReasonCode: "analysis_report_missing"}}
	}
	if report.GetStatus() != roomv1.AnalysisStatus_ANALYSIS_STATUS_COMPLETE {
		return nil, []*roomv1.EvaluationGap{{Status: report.GetStatus(), ReasonCode: "analysis_not_complete"}}
	}
	artifact := report.GetArtifact()
	if artifact.GetPhase() == roomv1.AnalysisPhase_ANALYSIS_PHASE_UNSPECIFIED || len(artifact.GetSha256()) != sha256Size {
		return nil, []*roomv1.EvaluationGap{{Status: roomv1.AnalysisStatus_ANALYSIS_STATUS_INVALID, ReasonCode: "artifact_invalid"}}
	}
	valid := make([]*roomv1.AnalyzerReceipt, 0, len(report.GetReceipts()))
	gaps := make([]*roomv1.EvaluationGap, 0)
	for _, receipt := range report.GetReceipts() {
		if receipt == nil || receipt.GetAnalyzer() == nil {
			gaps = append(gaps, &roomv1.EvaluationGap{Status: roomv1.AnalysisStatus_ANALYSIS_STATUS_INVALID, ReasonCode: "receipt_identity_missing"})
			continue
		}
		trusted, ok := p.trusted[receipt.GetAnalyzer().GetId()]
		if !ok || !proto.Equal(trusted, receipt.GetAnalyzer()) {
			gaps = append(gaps, &roomv1.EvaluationGap{AnalyzerId: receipt.GetAnalyzer().GetId(), Status: roomv1.AnalysisStatus_ANALYSIS_STATUS_UNTRUSTED, ReasonCode: "analyzer_untrusted"})
			continue
		}
		if receipt.GetStatus() != roomv1.AnalysisStatus_ANALYSIS_STATUS_COMPLETE || !bytes.Equal(receipt.GetInputSha256(), artifact.GetSha256()) {
			gaps = append(gaps, &roomv1.EvaluationGap{AnalyzerId: trusted.GetId(), Status: receipt.GetStatus(), ReasonCode: "receipt_invalid_or_incomplete"})
			continue
		}
		covered := make(map[roomv1.SignalKind]bool, len(receipt.GetCoveredSignals()))
		for _, kind := range receipt.GetCoveredSignals() {
			covered[kind] = true
		}
		validReceipt := true
		for _, signal := range receipt.GetSignals() {
			if signal == nil || signal.GetKind() == roomv1.SignalKind_SIGNAL_KIND_UNSPECIFIED || !covered[signal.GetKind()] || signal.GetConfidenceBasisPoints() > 10000 || !proto.Equal(signal.GetAnalyzer(), trusted) {
				validReceipt = false
				break
			}
		}
		if !validReceipt {
			gaps = append(gaps, &roomv1.EvaluationGap{AnalyzerId: trusted.GetId(), Status: roomv1.AnalysisStatus_ANALYSIS_STATUS_INVALID, ReasonCode: "signal_invalid"})
			continue
		}
		valid = append(valid, receipt)
	}
	if len(valid) == 0 && len(gaps) == 0 {
		gaps = append(gaps, &roomv1.EvaluationGap{Status: roomv1.AnalysisStatus_ANALYSIS_STATUS_UNAVAILABLE, ReasonCode: "analyzer_receipt_missing"})
	}
	return valid, gaps
}

const sha256Size = 32

func (p *Policy) withGap(result *roomv1.EvaluationResult, signal roomv1.SignalKind, reason string, status roomv1.AnalysisStatus) *roomv1.EvaluationResult {
	result.Gaps = append(result.Gaps, &roomv1.EvaluationGap{RequiredSignal: signal, ReasonCode: reason, Status: status})
	if p.auditOnly {
		result.Decision = roomv1.Decision_DECISION_WARN
	}
	return result
}

func triggered(selectors []*roomv1.SignalSelector, phase roomv1.AnalysisPhase, maxConfidence map[roomv1.SignalKind]uint32) bool {
	for _, selector := range selectors {
		if selector == nil || !phaseMatches(selector.GetPhases(), phase) {
			continue
		}
		if confidence, exists := maxConfidence[selector.GetSignal()]; exists && confidence >= selector.GetMinimumConfidenceBasisPoints() {
			return true
		}
	}
	return false
}

func phaseMatches(phases []roomv1.AnalysisPhase, phase roomv1.AnalysisPhase) bool {
	if len(phases) == 0 {
		return true
	}
	for _, candidate := range phases {
		if candidate == phase {
			return true
		}
	}
	return false
}

// ScopeMatches is the canonical matcher for identity and path rule scope.
func ScopeMatches(scope *roomv1.RuleScope, context *roomv1.EvaluationContext) bool {
	if scope == nil {
		return true
	}
	if context == nil || !listMatches(scope.GetWorkspaces(), context.GetWorkspaceId()) || !listMatches(scope.GetRepositories(), context.GetRepository()) || !listMatches(scope.GetAgentTypes(), context.GetAgentType()) {
		return false
	}
	if len(scope.GetPaths()) == 0 || len(context.GetChangedFiles()) == 0 {
		return true
	}
	for _, changed := range context.GetChangedFiles() {
		for _, pattern := range scope.GetPaths() {
			if globMatch(pattern, changed) {
				return true
			}
		}
	}
	return false
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

func globMatch(pattern, value string) bool {
	pattern, value = strings.TrimSpace(pattern), strings.TrimSpace(value)
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

func cloneContext(context *roomv1.EvaluationContext) *roomv1.EvaluationContext {
	if context == nil {
		return &roomv1.EvaluationContext{}
	}
	return proto.Clone(context).(*roomv1.EvaluationContext)
}

func dedupeKinds(values []roomv1.SignalKind) []roomv1.SignalKind {
	seen := make(map[roomv1.SignalKind]bool, len(values))
	out := make([]roomv1.SignalKind, 0, len(values))
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

func dedupeStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

func dedupeGaps(values []*roomv1.EvaluationGap) []*roomv1.EvaluationGap {
	seen := make(map[string]bool, len(values))
	out := make([]*roomv1.EvaluationGap, 0, len(values))
	for _, value := range values {
		if value == nil {
			continue
		}
		key := fmt.Sprintf("%d:%s:%d:%s", value.GetRequiredSignal(), value.GetAnalyzerId(), value.GetStatus(), value.GetReasonCode())
		if !seen[key] {
			seen[key] = true
			out = append(out, value)
		}
	}
	return out
}

func ruleMessage(rule *roomv1.Rule) string {
	if rule.GetDescription() != "" {
		return rule.GetDescription()
	}
	return rule.GetTitle()
}

func newID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "evaluation"
	}
	return hex.EncodeToString(value[:])
}
