package eval

import (
	"bytes"
	"crypto/sha256"
	"testing"

	roomv1 "github.com/haasonsaas/room/gen/go/room/v1"
	"google.golang.org/protobuf/proto"
)

var testIdentity = &roomv1.AnalyzerIdentity{Id: "test.static", Version: "1", ConfigSha256: []byte("config")}

func TestPositiveSignalDrivesDecisionIndependentOfProse(t *testing.T) {
	policy := NewPolicy([]*roomv1.AnalyzerIdentity{testIdentity}, false)
	ruleset := testRuleset(roomv1.SignalKind_SIGNAL_KIND_TENANT_ACCESS_WITHOUT_TRUSTED_SCOPE, roomv1.Severity_SEVERITY_CRITICAL)
	report := completeReport(roomv1.AnalysisPhase_ANALYSIS_PHASE_PLAN, roomv1.SignalKind_SIGNAL_KIND_TENANT_ACCESS_WITHOUT_TRUSTED_SCOPE)

	first := policy.Evaluate(ruleset, &roomv1.EvaluationContext{Repository: "github.com/acme/repo"}, report)
	second := policy.Evaluate(ruleset, &roomv1.EvaluationContext{Repository: "github.com/acme/repo"}, report)

	if first.GetDecision() != roomv1.Decision_DECISION_DENY || second.GetDecision() != first.GetDecision() {
		t.Fatalf("decisions = %s, %s; want deny", first.GetDecision(), second.GetDecision())
	}
	if len(first.GetMatches()) != 1 {
		t.Fatalf("matches = %d, want 1", len(first.GetMatches()))
	}
}

func TestCompleteCoverageWithoutSignalAllows(t *testing.T) {
	policy := NewPolicy([]*roomv1.AnalyzerIdentity{testIdentity}, false)
	ruleset := testRuleset(roomv1.SignalKind_SIGNAL_KIND_SECRET_LITERAL, roomv1.Severity_SEVERITY_CRITICAL)
	report := completeReport(roomv1.AnalysisPhase_ANALYSIS_PHASE_DIFF)
	report.Receipts[0].CoveredSignals = []roomv1.SignalKind{roomv1.SignalKind_SIGNAL_KIND_SECRET_LITERAL}

	result := policy.Evaluate(ruleset, &roomv1.EvaluationContext{}, report)
	if result.GetDecision() != roomv1.Decision_DECISION_ALLOW {
		t.Fatalf("decision = %s, gaps=%v", result.GetDecision(), result.GetGaps())
	}
}

func TestRolloutStageControlsDecisionWithoutChangingMatch(t *testing.T) {
	tests := []struct {
		stage roomv1.RolloutStage
		want  roomv1.Decision
	}{
		{roomv1.RolloutStage_ROLLOUT_STAGE_SHADOW, roomv1.Decision_DECISION_ALLOW},
		{roomv1.RolloutStage_ROLLOUT_STAGE_WARN, roomv1.Decision_DECISION_WARN},
		{roomv1.RolloutStage_ROLLOUT_STAGE_BLOCK, roomv1.Decision_DECISION_DENY},
	}
	for _, tt := range tests {
		t.Run(tt.stage.String(), func(t *testing.T) {
			ruleset := testRuleset(roomv1.SignalKind_SIGNAL_KIND_REVIEW_SECURITY_BOUNDARY, roomv1.Severity_SEVERITY_CRITICAL)
			ruleset.Rules[0].RolloutStage = tt.stage
			result := NewPolicy([]*roomv1.AnalyzerIdentity{testIdentity}, false).Evaluate(ruleset, &roomv1.EvaluationContext{}, completeReport(roomv1.AnalysisPhase_ANALYSIS_PHASE_DIFF, roomv1.SignalKind_SIGNAL_KIND_REVIEW_SECURITY_BOUNDARY))
			if result.GetDecision() != tt.want || len(result.GetMatches()) != 1 || result.GetMatches()[0].GetRolloutStage() != tt.stage {
				t.Fatalf("stage=%s decision=%s matches=%+v", tt.stage, result.GetDecision(), result.GetMatches())
			}
		})
	}
}

func TestScopeMatchesLanguageAndFrameworkSelectors(t *testing.T) {
	tests := []struct {
		name    string
		scope   *roomv1.RuleScope
		context *roomv1.EvaluationContext
		want    bool
	}{
		{
			name:    "language matches",
			scope:   &roomv1.RuleScope{Languages: []string{"go"}},
			context: &roomv1.EvaluationContext{Languages: []string{"go", "sql"}},
			want:    true,
		},
		{
			name:    "language does not match",
			scope:   &roomv1.RuleScope{Languages: []string{"rust"}},
			context: &roomv1.EvaluationContext{Languages: []string{"go"}},
			want:    false,
		},
		{
			name:    "unknown language does not discard scoped rule",
			scope:   &roomv1.RuleScope{Languages: []string{"go"}},
			context: &roomv1.EvaluationContext{},
			want:    true,
		},
		{
			name:    "framework glob matches",
			scope:   &roomv1.RuleScope{Frameworks: []string{"Next*"}},
			context: &roomv1.EvaluationContext{Frameworks: []string{"NEXTJS"}},
			want:    true,
		},
		{
			name:    "all populated dimensions must match",
			scope:   &roomv1.RuleScope{Languages: []string{"typescript"}, Frameworks: []string{"react"}},
			context: &roomv1.EvaluationContext{Languages: []string{"typescript"}, Frameworks: []string{"vue"}},
			want:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ScopeMatches(tt.scope, tt.context); got != tt.want {
				t.Fatalf("ScopeMatches() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestTrustedArtifactClassificationScopesRules(t *testing.T) {
	tests := []struct {
		name       string
		scope      *roomv1.RuleScope
		languages  []string
		frameworks []string
		want       roomv1.Decision
	}{
		{name: "language match", scope: &roomv1.RuleScope{Languages: []string{"rust"}}, languages: []string{"rust"}, want: roomv1.Decision_DECISION_DENY},
		{name: "language mismatch", scope: &roomv1.RuleScope{Languages: []string{"rust"}}, languages: []string{"go"}, want: roomv1.Decision_DECISION_ALLOW},
		{name: "framework match", scope: &roomv1.RuleScope{Frameworks: []string{"react"}}, frameworks: []string{"react"}, want: roomv1.Decision_DECISION_DENY},
		{name: "framework mismatch", scope: &roomv1.RuleScope{Frameworks: []string{"react"}}, frameworks: []string{"vue"}, want: roomv1.Decision_DECISION_ALLOW},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ruleset := testRuleset(roomv1.SignalKind_SIGNAL_KIND_SECRET_LITERAL, roomv1.Severity_SEVERITY_CRITICAL)
			ruleset.Rules[0].Scope = tt.scope
			report := completeReport(roomv1.AnalysisPhase_ANALYSIS_PHASE_DIFF, roomv1.SignalKind_SIGNAL_KIND_SECRET_LITERAL)
			report.Artifact.Languages = tt.languages
			report.Artifact.Frameworks = tt.frameworks
			callerContext := &roomv1.EvaluationContext{Languages: []string{"caller-language"}, Frameworks: []string{"caller-framework"}}

			result := NewPolicy([]*roomv1.AnalyzerIdentity{testIdentity}, false).Evaluate(ruleset, callerContext, report)
			if result.GetDecision() != tt.want {
				t.Fatalf("decision = %s, want %s; matches=%+v gaps=%+v", result.GetDecision(), tt.want, result.GetMatches(), result.GetGaps())
			}
		})
	}
}

func TestMissingCoverageIsIndeterminate(t *testing.T) {
	policy := NewPolicy([]*roomv1.AnalyzerIdentity{testIdentity}, false)
	result := policy.Evaluate(testRuleset(roomv1.SignalKind_SIGNAL_KIND_SECRET_LITERAL, roomv1.Severity_SEVERITY_HIGH), &roomv1.EvaluationContext{}, completeReport(roomv1.AnalysisPhase_ANALYSIS_PHASE_DIFF))
	if result.GetDecision() != roomv1.Decision_DECISION_INDETERMINATE {
		t.Fatalf("decision = %s, want indeterminate", result.GetDecision())
	}
	if len(result.GetGaps()) == 0 {
		t.Fatal("expected coverage gap")
	}
}

func TestUntrustedAndDigestMismatchAreIndeterminate(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*roomv1.AnalysisReport)
	}{
		{"untrusted", func(r *roomv1.AnalysisReport) { r.Receipts[0].Analyzer.Id = "attacker" }},
		{"digest mismatch", func(r *roomv1.AnalysisReport) { r.Receipts[0].InputSha256 = []byte("wrong") }},
		{"partial", func(r *roomv1.AnalysisReport) { r.Receipts[0].Status = roomv1.AnalysisStatus_ANALYSIS_STATUS_PARTIAL }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := completeReport(roomv1.AnalysisPhase_ANALYSIS_PHASE_DIFF)
			report.Receipts[0].CoveredSignals = []roomv1.SignalKind{roomv1.SignalKind_SIGNAL_KIND_SECRET_LITERAL}
			tt.mutate(report)
			result := NewPolicy([]*roomv1.AnalyzerIdentity{testIdentity}, false).Evaluate(testRuleset(roomv1.SignalKind_SIGNAL_KIND_SECRET_LITERAL, roomv1.Severity_SEVERITY_HIGH), &roomv1.EvaluationContext{}, report)
			if result.GetDecision() != roomv1.Decision_DECISION_INDETERMINATE {
				t.Fatalf("decision = %s", result.GetDecision())
			}
		})
	}
}

func TestLegacyExpressionRuleFailsSafely(t *testing.T) {
	ruleset := &roomv1.RulesetVersion{Id: "r", Version: 1, Rules: []*roomv1.Rule{{Id: "legacy", Enabled: true, Checks: []*roomv1.RuleCheck{{Kind: roomv1.CheckKind_CHECK_KIND_PLAN_TEXT, Expression: "auth"}}}}}
	result := NewPolicy([]*roomv1.AnalyzerIdentity{testIdentity}, false).Evaluate(ruleset, &roomv1.EvaluationContext{}, completeReport(roomv1.AnalysisPhase_ANALYSIS_PHASE_PLAN))
	if result.GetDecision() != roomv1.Decision_DECISION_INDETERMINATE {
		t.Fatalf("decision = %s", result.GetDecision())
	}
}

func testRuleset(signal roomv1.SignalKind, severity roomv1.Severity) *roomv1.RulesetVersion {
	return &roomv1.RulesetVersion{Id: "ruleset-1", Version: 1, Hash: "hash", Rules: []*roomv1.Rule{{
		Id: "rule", Title: "Rule", Description: "display only", Enabled: true, Severity: severity,
		Triggers:         []*roomv1.SignalSelector{{Signal: signal, Phases: []roomv1.AnalysisPhase{roomv1.AnalysisPhase_ANALYSIS_PHASE_PLAN, roomv1.AnalysisPhase_ANALYSIS_PHASE_DIFF}, MinimumConfidenceBasisPoints: 8000}},
		RequiredCoverage: []roomv1.SignalKind{signal},
	}}}
}

func completeReport(phase roomv1.AnalysisPhase, signals ...roomv1.SignalKind) *roomv1.AnalysisReport {
	digest := sha256.Sum256([]byte("artifact"))
	identity := proto.Clone(testIdentity).(*roomv1.AnalyzerIdentity)
	receipt := &roomv1.AnalyzerReceipt{Analyzer: identity, Status: roomv1.AnalysisStatus_ANALYSIS_STATUS_COMPLETE, InputSha256: digest[:]}
	for _, signal := range signals {
		receipt.CoveredSignals = append(receipt.CoveredSignals, signal)
		receipt.Signals = append(receipt.Signals, &roomv1.SecuritySignal{Kind: signal, Analyzer: proto.Clone(identity).(*roomv1.AnalyzerIdentity), ConfidenceBasisPoints: 9000, Fingerprint: "finding"})
	}
	return &roomv1.AnalysisReport{ReportId: "report", Status: roomv1.AnalysisStatus_ANALYSIS_STATUS_COMPLETE, Artifact: &roomv1.ArtifactRef{Phase: phase, Sha256: bytes.Clone(digest[:])}, Receipts: []*roomv1.AnalyzerReceipt{receipt}}
}
