package intelligence

import (
	"testing"
	"time"

	roomv1 "github.com/haasonsaas/room/gen/go/room/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestInferRequiresConservativeTypedEvidence(t *testing.T) {
	now := time.Now()
	findings := []*roomv1.ReviewFinding{
		finding("accepted", roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_PROTOCOL_CONTRACT, 8200,
			outcome(roomv1.ReviewOutcomeKind_REVIEW_OUTCOME_KIND_FIX_COMMITTED, 10_000),
			adjudication("agent-a", roomv1.AdjudicationVerdict_ADJUDICATION_VERDICT_VALID_GENERALIZABLE, now)),
		finding("prose-only", roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_PROTOCOL_CONTRACT, 9900),
		finding("invalid-latest", roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_PROTOCOL_CONTRACT, 9900,
			outcome(roomv1.ReviewOutcomeKind_REVIEW_OUTCOME_KIND_FIX_COMMITTED, 10_000),
			adjudication("agent-a", roomv1.AdjudicationVerdict_ADJUDICATION_VERDICT_VALID_GENERALIZABLE, now.Add(-time.Minute)),
			adjudication("agent-a", roomv1.AdjudicationVerdict_ADJUDICATION_VERDICT_INVALID, now)),
	}
	findings[0].RequiredEvidence = []string{"contract test", "trace"}
	findings[0].Remediation = []string{"enforce the contract", "enforce the contract"}
	findings[1].Invariant = "FIXED ACCEPTED VALID" // Presentation text must never affect inference.
	findings[1].Impact = "critical merged regression"
	findings[1].RequiredEvidence = []string{"must not leak into candidate"}

	candidates, err := Infer(findings, 1, "tuner")
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 {
		t.Fatalf("got %d candidates, want 1", len(candidates))
	}
	candidate := candidates[0]
	if got := candidate.GetSourceFindingIds(); len(got) != 1 || got[0] != "accepted" {
		t.Fatalf("source finding ids = %v", got)
	}
	if candidate.GetArtifactKind() != roomv1.PolicyArtifactKind_POLICY_ARTIFACT_KIND_DETERMINISTIC_CHECK {
		t.Fatalf("artifact = %v", candidate.GetArtifactKind())
	}
	if candidate.GetProposedRule().GetEnabled() {
		t.Fatal("inferred draft rule must not be enabled")
	}
	rule := candidate.GetProposedRule()
	if rule.GetTitle() != "Review protocol contract" || rule.GetDescription() == "" {
		t.Fatalf("generated presentation = %q / %q", rule.GetTitle(), rule.GetDescription())
	}
	if len(rule.GetTriggers()) != 1 || rule.GetTriggers()[0].GetSignal() != roomv1.SignalKind_SIGNAL_KIND_REVIEW_PROTOCOL_CONTRACT {
		t.Fatalf("triggers = %v", rule.GetTriggers())
	}
	if got := rule.GetTriggers()[0].GetMinimumConfidenceBasisPoints(); got != candidate.GetMinimumConfidenceBasisPoints() {
		t.Fatalf("trigger threshold = %d, candidate threshold = %d", got, candidate.GetMinimumConfidenceBasisPoints())
	}
	if got := rule.GetTriggers()[0].GetPhases(); len(got) != 2 || got[0] != roomv1.AnalysisPhase_ANALYSIS_PHASE_PLAN || got[1] != roomv1.AnalysisPhase_ANALYSIS_PHASE_DIFF {
		t.Fatalf("trigger phases = %v", got)
	}
	if got := rule.GetRequiredCoverage(); len(got) != 1 || got[0] != roomv1.SignalKind_SIGNAL_KIND_REVIEW_PROTOCOL_CONTRACT {
		t.Fatalf("required coverage = %v", got)
	}
	if got := rule.GetRequiredEvidence(); len(got) != 2 || got[0] != "contract test" || got[1] != "trace" {
		t.Fatalf("required evidence = %v", got)
	}
	if got := rule.GetRemediation(); len(got) != 1 || got[0] != "enforce the contract" {
		t.Fatalf("remediation = %v", got)
	}
	if candidate.GetProtectedOrgPolicy() {
		t.Fatal("repository-scoped candidate marked as protected org policy")
	}
}

func TestInferUsesBroadWeightedOutcomesAndMinimumSupport(t *testing.T) {
	now := time.Now()
	accepted := finding("weighted-positive", roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_OPERATIONAL_TRUTH, 7600,
		outcome(roomv1.ReviewOutcomeKind_REVIEW_OUTCOME_KIND_FIX_COMMITTED, 10_000),
		outcome(roomv1.ReviewOutcomeKind_REVIEW_OUTCOME_KIND_REJECTED, 2_000))
	oneOff := finding("one-off", roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_OPERATIONAL_TRUTH, 9000,
		outcome(roomv1.ReviewOutcomeKind_REVIEW_OUTCOME_KIND_FIX_COMMITTED, 10_000),
		adjudication("agent", roomv1.AdjudicationVerdict_ADJUDICATION_VERDICT_VALID_ONE_OFF, now))

	candidates, err := Infer([]*roomv1.ReviewFinding{accepted, oneOff}, 2, "tuner")
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 0 {
		t.Fatalf("got %d candidates, want no candidate below support", len(candidates))
	}
	candidates, err = Infer([]*roomv1.ReviewFinding{accepted}, 1, "tuner")
	if err != nil {
		t.Fatal(err)
	}
	if got := candidates[0].GetArtifactKind(); got != roomv1.PolicyArtifactKind_POLICY_ARTIFACT_KIND_SEMANTIC_ANALYZER {
		t.Fatalf("artifact = %v", got)
	}
}

func TestInferCandidateIdentityIsStableForIdenticalContentAndRevisedForChangedEvidence(t *testing.T) {
	f := finding("accepted", roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_PROTOCOL_CONTRACT, 8200,
		outcome(roomv1.ReviewOutcomeKind_REVIEW_OUTCOME_KIND_FIX_COMMITTED, 10_000))
	f.RequiredEvidence = []string{"contract test"}
	first, err := Infer([]*roomv1.ReviewFinding{f}, 1, "first-actor")
	if err != nil {
		t.Fatal(err)
	}
	second, err := Infer([]*roomv1.ReviewFinding{f}, 1, "second-actor")
	if err != nil {
		t.Fatal(err)
	}
	if first[0].GetId() != second[0].GetId() || first[0].GetProposedRule().GetId() != second[0].GetProposedRule().GetId() {
		t.Fatalf("unstable candidate identity: %q/%q vs %q/%q", first[0].GetId(), first[0].GetProposedRule().GetId(), second[0].GetId(), second[0].GetProposedRule().GetId())
	}
	revisedFinding := proto.Clone(f).(*roomv1.ReviewFinding)
	revisedFinding.RequiredEvidence = []string{"contract test", "negative contract test"}
	revised, err := Infer([]*roomv1.ReviewFinding{revisedFinding}, 1, "first-actor")
	if err != nil {
		t.Fatal(err)
	}
	if first[0].GetId() == revised[0].GetId() {
		t.Fatal("changed evidence reused the immutable candidate revision id")
	}
	if first[0].GetProposedRule().GetId() != revised[0].GetProposedRule().GetId() {
		t.Fatalf("changed evidence broke executable rule lineage: %q != %q", first[0].GetProposedRule().GetId(), revised[0].GetProposedRule().GetId())
	}
	if revised[0].GetRolloutStage() != roomv1.RolloutStage_ROLLOUT_STAGE_DRAFT {
		t.Fatalf("revised candidate stage = %v, want draft", revised[0].GetRolloutStage())
	}

	other := finding("accepted-2", roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_SECURITY_BOUNDARY, 8200,
		outcome(roomv1.ReviewOutcomeKind_REVIEW_OUTCOME_KIND_FIX_COMMITTED, 10_000))
	third, err := Infer([]*roomv1.ReviewFinding{other}, 1, "first-actor")
	if err != nil {
		t.Fatal(err)
	}
	if first[0].GetId() == third[0].GetId() {
		t.Fatal("different typed claim kinds produced the same candidate id")
	}
}

func TestInferProtectsEveryCriticalCandidate(t *testing.T) {
	f := finding("critical", roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_SECURITY_BOUNDARY, 9100,
		outcome(roomv1.ReviewOutcomeKind_REVIEW_OUTCOME_KIND_FIX_COMMITTED, 10_000))
	f.Severity = roomv1.Severity_SEVERITY_CRITICAL
	candidates, err := Infer([]*roomv1.ReviewFinding{f}, 1, "tuner")
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 || !candidates[0].GetProtectedOrgPolicy() {
		t.Fatalf("critical candidate was not protected: %+v", candidates)
	}
}

func TestArtifactKindCoversEveryClaimKind(t *testing.T) {
	tests := map[roomv1.ReviewClaimKind]roomv1.PolicyArtifactKind{
		roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_AUTHORIZATION_BOUNDARY: roomv1.PolicyArtifactKind_POLICY_ARTIFACT_KIND_DETERMINISTIC_CHECK,
		roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_STATE_TRANSITION:       roomv1.PolicyArtifactKind_POLICY_ARTIFACT_KIND_DETERMINISTIC_CHECK,
		roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_PROTOCOL_CONTRACT:      roomv1.PolicyArtifactKind_POLICY_ARTIFACT_KIND_DETERMINISTIC_CHECK,
		roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_GUARDRAIL_COVERAGE:     roomv1.PolicyArtifactKind_POLICY_ARTIFACT_KIND_ARCHITECTURE_POLICY,
		roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_OPERATIONAL_TRUTH:      roomv1.PolicyArtifactKind_POLICY_ARTIFACT_KIND_SEMANTIC_ANALYZER,
		roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_SECURITY_BOUNDARY:      roomv1.PolicyArtifactKind_POLICY_ARTIFACT_KIND_ARCHITECTURE_POLICY,
		roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_NEGATIVE_TEST_GAP:      roomv1.PolicyArtifactKind_POLICY_ARTIFACT_KIND_DETERMINISTIC_CHECK,
	}
	for claim, want := range tests {
		got, err := ArtifactKind(claim)
		if err != nil || got != want {
			t.Errorf("ArtifactKind(%v) = %v, %v; want %v", claim, got, err, want)
		}
	}
	if _, err := ArtifactKind(roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_UNSPECIFIED); err == nil {
		t.Fatal("unspecified claim kind accepted")
	}
}

func TestClaimSignalMappingCoversEveryClaimKind(t *testing.T) {
	tests := map[roomv1.ReviewClaimKind]roomv1.SignalKind{
		roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_AUTHORIZATION_BOUNDARY: roomv1.SignalKind_SIGNAL_KIND_REVIEW_AUTHORIZATION_BOUNDARY,
		roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_STATE_TRANSITION:       roomv1.SignalKind_SIGNAL_KIND_REVIEW_STATE_TRANSITION,
		roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_PROTOCOL_CONTRACT:      roomv1.SignalKind_SIGNAL_KIND_REVIEW_PROTOCOL_CONTRACT,
		roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_GUARDRAIL_COVERAGE:     roomv1.SignalKind_SIGNAL_KIND_REVIEW_GUARDRAIL_COVERAGE,
		roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_OPERATIONAL_TRUTH:      roomv1.SignalKind_SIGNAL_KIND_REVIEW_OPERATIONAL_TRUTH,
		roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_SECURITY_BOUNDARY:      roomv1.SignalKind_SIGNAL_KIND_REVIEW_SECURITY_BOUNDARY,
		roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_NEGATIVE_TEST_GAP:      roomv1.SignalKind_SIGNAL_KIND_REVIEW_NEGATIVE_TEST_GAP,
	}
	for claim, want := range tests {
		metadata, err := claimMetadataFor(claim)
		if err != nil || metadata.signal != want || metadata.title == "" || metadata.description == "" {
			t.Errorf("claimMetadataFor(%v) = %+v, %v; signal want %v", claim, metadata, err, want)
		}
	}
}

func TestReplayClassifiesExpectedAndActualFromTypedFields(t *testing.T) {
	now := time.Now()
	candidate := &roomv1.PolicyCandidate{Id: "candidate", ClaimKind: roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_SECURITY_BOUNDARY, MinimumConfidenceBasisPoints: 8000}
	findings := []*roomv1.ReviewFinding{
		finding("tp", candidate.ClaimKind, 9000, outcome(roomv1.ReviewOutcomeKind_REVIEW_OUTCOME_KIND_FIX_COMMITTED, 10_000)),
		finding("fn", candidate.ClaimKind, 7000, outcome(roomv1.ReviewOutcomeKind_REVIEW_OUTCOME_KIND_FIX_COMMITTED, 10_000)),
		finding("fp", candidate.ClaimKind, 8500, adjudication("a", roomv1.AdjudicationVerdict_ADJUDICATION_VERDICT_INVALID, now)),
		finding("tn-other-claim", roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_PROTOCOL_CONTRACT, 9900, outcome(roomv1.ReviewOutcomeKind_REVIEW_OUTCOME_KIND_FIX_COMMITTED, 10_000)),
	}

	replay, err := Replay(candidate, findings)
	if err != nil {
		t.Fatal(err)
	}
	if replay.GetMetrics().GetTruePositiveCount() != 1 || replay.GetMetrics().GetFalsePositiveCount() != 1 || replay.GetMetrics().GetFalseNegativeCount() != 1 {
		t.Fatalf("metrics = %+v", replay.GetMetrics())
	}
	if replay.GetMetrics().GetPrecisionBasisPoints() != 5000 || replay.GetMetrics().GetRecallBasisPoints() != 5000 {
		t.Fatalf("precision/recall = %d/%d", replay.GetMetrics().GetPrecisionBasisPoints(), replay.GetMetrics().GetRecallBasisPoints())
	}
}

func TestTuneRaisesThresholdWhenReplaySupportsIt(t *testing.T) {
	candidate := &roomv1.PolicyCandidate{Id: "candidate", MinimumConfidenceBasisPoints: 7000, RolloutStage: roomv1.RolloutStage_ROLLOUT_STAGE_WARN, ProposedRule: &roomv1.Rule{Triggers: []*roomv1.SignalSelector{{MinimumConfidenceBasisPoints: 7000}}}}
	replay := replayRun("r1", "candidate",
		replayCase("positive", true, true, 9000),
		replayCase("negative", false, true, 8000),
		replayCase("negative-low", false, false, 6000))

	updated, decision, err := Tune(candidate, []*roomv1.PolicyReplayRun{replay}, "auto-tuner")
	if err != nil {
		t.Fatal(err)
	}
	if decision.GetAction() != roomv1.TuningActionKind_TUNING_ACTION_KIND_ADJUST_CONFIDENCE {
		t.Fatalf("action = %v", decision.GetAction())
	}
	if updated.GetMinimumConfidenceBasisPoints() != 9000 || decision.GetNewConfidenceBasisPoints() != 9000 {
		t.Fatalf("new threshold = %d", updated.GetMinimumConfidenceBasisPoints())
	}
	if got := updated.GetProposedRule().GetTriggers()[0].GetMinimumConfidenceBasisPoints(); got != 9000 {
		t.Fatalf("executable rule threshold = %d", got)
	}
	if candidate.GetMinimumConfidenceBasisPoints() != 7000 {
		t.Fatal("Tune mutated its input")
	}
}

func TestTuneRecommendsRollbackWhenNoViableThreshold(t *testing.T) {
	candidate := &roomv1.PolicyCandidate{Id: "candidate", MinimumConfidenceBasisPoints: 7000, RolloutStage: roomv1.RolloutStage_ROLLOUT_STAGE_WARN}
	replay := replayRun("r1", "candidate",
		replayCase("positive-low", true, false, 3000),
		replayCase("negative-high", false, true, 9500))

	updated, decision, err := Tune(candidate, []*roomv1.PolicyReplayRun{replay}, "auto-tuner")
	if err != nil {
		t.Fatal(err)
	}
	if decision.GetAction() != roomv1.TuningActionKind_TUNING_ACTION_KIND_ROLLBACK || updated.GetRolloutStage() != roomv1.RolloutStage_ROLLOUT_STAGE_ROLLED_BACK {
		t.Fatalf("action/stage = %v/%v", decision.GetAction(), updated.GetRolloutStage())
	}
}

func TestValidationRejectsUntypedOrOutOfRangeInputs(t *testing.T) {
	if _, err := Infer([]*roomv1.ReviewFinding{{Id: "bad", ConfidenceBasisPoints: 10_001}}, 1, "actor"); err == nil {
		t.Fatal("invalid finding accepted")
	}
	if _, err := Replay(&roomv1.PolicyCandidate{Id: "c", ClaimKind: roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_PROTOCOL_CONTRACT, MinimumConfidenceBasisPoints: 10_001}, nil); err == nil {
		t.Fatal("invalid candidate accepted")
	}
	if _, _, err := Tune(&roomv1.PolicyCandidate{Id: "c"}, nil, "actor"); err == nil {
		t.Fatal("empty replay set accepted")
	}
}

func finding(id string, claim roomv1.ReviewClaimKind, confidence uint32, parts ...any) *roomv1.ReviewFinding {
	f := &roomv1.ReviewFinding{Id: id, ClaimKind: claim, ConfidenceBasisPoints: confidence, Source: &roomv1.ReviewSource{Repository: "acme/repo"}, Severity: roomv1.Severity_SEVERITY_HIGH}
	for _, part := range parts {
		switch value := part.(type) {
		case *roomv1.ReviewOutcome:
			f.Outcomes = append(f.Outcomes, value)
		case *roomv1.ReviewAdjudication:
			f.Adjudications = append(f.Adjudications, value)
		}
	}
	return f
}

func outcome(kind roomv1.ReviewOutcomeKind, weight int32) *roomv1.ReviewOutcome {
	return &roomv1.ReviewOutcome{Id: kind.String(), Kind: kind, WeightBasisPoints: weight}
}

func adjudication(agent string, verdict roomv1.AdjudicationVerdict, at time.Time) *roomv1.ReviewAdjudication {
	return &roomv1.ReviewAdjudication{Id: agent + verdict.String(), AgentId: agent, Verdict: verdict, OccurredAt: timestamppb.New(at)}
}

func replayCase(id string, expected, actual bool, confidence uint32) *roomv1.ReplayCaseResult {
	return &roomv1.ReplayCaseResult{FindingId: id, ExpectedMatch: expected, ActualMatch: actual, ConfidenceBasisPoints: confidence}
}

func replayRun(id, candidateID string, cases ...*roomv1.ReplayCaseResult) *roomv1.PolicyReplayRun {
	return &roomv1.PolicyReplayRun{Id: id, PolicyCandidateId: candidateID, Cases: cases, CompletedAt: timestamppb.Now()}
}
