package store

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"testing"
	"time"

	roomv1 "github.com/haasonsaas/room/gen/go/room/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestReviewFindingPersistenceIdempotencyAndIsolation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "room.db")
	database, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	findingInput := &roomv1.ReviewFinding{
		Id: "finding-1", Source: &roomv1.ReviewSource{Repository: "evalops/room", PullRequestNumber: 42},
		ClaimKind: roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_SECURITY_BOUNDARY,
		Invariant: "authorization is derived from a trusted principal", Severity: roomv1.Severity_SEVERITY_HIGH,
		ConfidenceBasisPoints: 9000, ReviewerCostMicros: 2500, ReviewerInputTokens: 20, ReviewerOutputTokens: 10,
	}
	stored, err := database.UpsertReviewFinding(findingInput)
	if err != nil {
		t.Fatalf("upsert finding: %v", err)
	}
	if stored.GetCreatedAt() == nil || stored.GetUpdatedAt() == nil {
		t.Fatalf("server timestamps missing: %+v", stored)
	}
	if findingInput.GetCreatedAt() != nil {
		t.Fatal("upsert mutated caller input")
	}
	findingInput.Invariant = "caller mutation"
	stored.Invariant = "return mutation"
	loaded, err := database.ReviewFinding("finding-1")
	if err != nil || loaded.GetInvariant() != "authorization is derived from a trusted principal" {
		t.Fatalf("stored finding was aliased: finding=%+v err=%v", loaded, err)
	}
	retryFinding := proto.Clone(loaded).(*roomv1.ReviewFinding)
	if repeated, err := database.UpsertReviewFinding(retryFinding); err != nil || repeated.GetId() != "finding-1" {
		t.Fatalf("idempotent finding retry: finding=%+v err=%v", repeated, err)
	}
	conflictingFinding := proto.Clone(retryFinding).(*roomv1.ReviewFinding)
	conflictingFinding.Impact = "different immutable payload"
	if _, err := database.UpsertReviewFinding(conflictingFinding); err == nil {
		t.Fatal("conflicting finding id reuse was accepted")
	}

	outcome := &roomv1.ReviewOutcome{Id: "outcome-1", Kind: roomv1.ReviewOutcomeKind_REVIEW_OUTCOME_KIND_FIX_COMMITTED, ActorId: "reviewer", WeightBasisPoints: 7500}
	withOutcome, err := database.AppendReviewOutcome(loaded.GetId(), outcome)
	if err != nil {
		t.Fatalf("append outcome: %v", err)
	}
	if outcome.GetOccurredAt() != nil || len(withOutcome.GetOutcomes()) != 1 || withOutcome.GetOutcomes()[0].GetOccurredAt() == nil {
		t.Fatalf("outcome timestamp or isolation failure: input=%+v stored=%+v", outcome, withOutcome.GetOutcomes())
	}
	if repeated, err := database.AppendReviewOutcome(loaded.GetId(), outcome); err != nil || len(repeated.GetOutcomes()) != 1 {
		t.Fatalf("idempotent outcome retry: finding=%+v err=%v", repeated, err)
	}
	conflictingOutcome := proto.Clone(outcome).(*roomv1.ReviewOutcome)
	conflictingOutcome.Kind = roomv1.ReviewOutcomeKind_REVIEW_OUTCOME_KIND_REJECTED
	if _, err := database.AppendReviewOutcome(loaded.GetId(), conflictingOutcome); err == nil {
		t.Fatal("conflicting outcome id reuse was accepted")
	}

	adjudication := &roomv1.ReviewAdjudication{
		Id: "adjudication-1", Verdict: roomv1.AdjudicationVerdict_ADJUDICATION_VERDICT_VALID_GENERALIZABLE,
		AgentId: "codex", ModelId: "model-1", InputSha256: bytes.Repeat([]byte{1}, sha256.Size), ConfidenceBasisPoints: 8000,
	}
	withAdjudication, err := database.AppendReviewAdjudication(loaded.GetId(), adjudication)
	if err != nil {
		t.Fatalf("append adjudication: %v", err)
	}
	if adjudication.GetOccurredAt() != nil || len(withAdjudication.GetAdjudications()) != 1 {
		t.Fatalf("adjudication isolation failure: input=%+v stored=%+v", adjudication, withAdjudication)
	}
	if repeated, err := database.AppendReviewAdjudication(loaded.GetId(), adjudication); err != nil || len(repeated.GetAdjudications()) != 1 {
		t.Fatalf("idempotent adjudication retry: finding=%+v err=%v", repeated, err)
	}
	conflictingAdjudication := proto.Clone(adjudication).(*roomv1.ReviewAdjudication)
	conflictingAdjudication.Verdict = roomv1.AdjudicationVerdict_ADJUDICATION_VERDICT_INVALID
	if _, err := database.AppendReviewAdjudication(loaded.GetId(), conflictingAdjudication); err == nil {
		t.Fatal("conflicting adjudication id reuse was accepted")
	}

	listed, err := database.ListReviewFindings("evalops/room", roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_SECURITY_BOUNDARY, 10)
	if err != nil || len(listed) != 1 {
		t.Fatalf("list findings: count=%d err=%v", len(listed), err)
	}
	listed[0].Invariant = "list mutation"
	loaded, _ = database.ReviewFinding("finding-1")
	if loaded.GetInvariant() == "list mutation" {
		t.Fatal("listed finding aliases stored state")
	}
	assertDeterministicBlob(t, database, "review_findings", "finding_id", "finding-1", loaded)

	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	database, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	loaded, err = database.ReviewFinding("finding-1")
	if err != nil || len(loaded.GetOutcomes()) != 1 || len(loaded.GetAdjudications()) != 1 {
		t.Fatalf("finding did not survive restart: finding=%+v err=%v", loaded, err)
	}
}

func TestPolicyCandidateReplayAndTuningPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "room.db")
	database, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	candidateInput := &roomv1.PolicyCandidate{
		Id: "candidate-1", ClaimKind: roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_PROTOCOL_CONTRACT,
		ArtifactKind: roomv1.PolicyArtifactKind_POLICY_ARTIFACT_KIND_DETERMINISTIC_CHECK,
		ProposedRule: &roomv1.Rule{Id: "review-protocol-contract", Triggers: []*roomv1.SignalSelector{{Signal: roomv1.SignalKind_SIGNAL_KIND_REVIEW_PROTOCOL_CONTRACT}}, RequiredCoverage: []roomv1.SignalKind{roomv1.SignalKind_SIGNAL_KIND_REVIEW_PROTOCOL_CONTRACT}}, SourceFindingIds: []string{"finding-1"},
		Metrics:      &roomv1.PolicyMetrics{SupportCount: 4, PrecisionBasisPoints: 9000, RecallBasisPoints: 8000},
		RolloutStage: roomv1.RolloutStage_ROLLOUT_STAGE_DRAFT, MinimumConfidenceBasisPoints: 8500, CreatedBy: "inference-agent",
	}
	stored, err := database.UpsertPolicyCandidate(candidateInput)
	if err != nil {
		t.Fatalf("upsert candidate: %v", err)
	}
	if candidateInput.GetCreatedAt() != nil || stored.GetCreatedAt() == nil {
		t.Fatalf("candidate timestamp isolation failed: input=%+v stored=%+v", candidateInput, stored)
	}
	candidateInput.CreatedBy = "caller mutation"
	stored.CreatedBy = "return mutation"
	loaded, err := database.PolicyCandidate("candidate-1")
	if err != nil || loaded.GetCreatedBy() != "inference-agent" {
		t.Fatalf("candidate was aliased: candidate=%+v err=%v", loaded, err)
	}
	loaded.RolloutStage = roomv1.RolloutStage_ROLLOUT_STAGE_SHADOW
	loaded.UpdatedAt = nil
	if _, err := database.UpsertPolicyCandidate(loaded); err != nil {
		t.Fatalf("update candidate: %v", err)
	}
	shadow, err := database.ListPolicyCandidates(roomv1.RolloutStage_ROLLOUT_STAGE_SHADOW)
	if err != nil || len(shadow) != 1 {
		t.Fatalf("list candidates: count=%d err=%v", len(shadow), err)
	}

	replay := &roomv1.PolicyReplayRun{
		Id: "replay-1", PolicyCandidateId: "candidate-1",
		Cases:   []*roomv1.ReplayCaseResult{{FindingId: "finding-1", ExpectedMatch: true, ActualMatch: true, ConfidenceBasisPoints: 9000}},
		Metrics: &roomv1.PolicyMetrics{TruePositiveCount: 1, PrecisionBasisPoints: 10000, RecallBasisPoints: 10000},
	}
	if err := database.SavePolicyReplay(replay); err != nil {
		t.Fatalf("save replay: %v", err)
	}
	if replay.GetStartedAt() != nil || replay.GetCompletedAt() != nil {
		t.Fatal("save replay mutated caller input")
	}
	if err := database.SavePolicyReplay(replay); err != nil {
		t.Fatalf("idempotent replay retry: %v", err)
	}
	conflictingReplay := proto.Clone(replay).(*roomv1.PolicyReplayRun)
	conflictingReplay.Cases[0].ActualMatch = false
	if err := database.SavePolicyReplay(conflictingReplay); err == nil {
		t.Fatal("conflicting replay id reuse was accepted")
	}
	replays, err := database.ListPolicyReplays("candidate-1", 10)
	if err != nil || len(replays) != 1 || replays[0].GetCompletedAt() == nil {
		t.Fatalf("list replays: replays=%+v err=%v", replays, err)
	}

	decision := &roomv1.TuningDecision{
		Id: "tuning-1", PolicyCandidateId: "candidate-1", Action: roomv1.TuningActionKind_TUNING_ACTION_KIND_ADJUST_CONFIDENCE,
		PreviousConfidenceBasisPoints: 8500, NewConfidenceBasisPoints: 8000, EvidenceReplayIds: []string{"replay-1"}, ActorId: "tuner",
	}
	if err := database.SaveTuningDecision(decision); err != nil {
		t.Fatalf("save tuning decision: %v", err)
	}
	if decision.GetOccurredAt() != nil {
		t.Fatal("save tuning decision mutated caller input")
	}
	if err := database.SaveTuningDecision(decision); err != nil {
		t.Fatalf("idempotent tuning retry: %v", err)
	}
	conflictingDecision := proto.Clone(decision).(*roomv1.TuningDecision)
	conflictingDecision.NewConfidenceBasisPoints = 7000
	if err := database.SaveTuningDecision(conflictingDecision); err == nil {
		t.Fatal("conflicting tuning decision id reuse was accepted")
	}
	decisions, err := database.ListTuningDecisions("candidate-1", 10)
	if err != nil || len(decisions) != 1 || decisions[0].GetOccurredAt() == nil {
		t.Fatalf("list tuning decisions: decisions=%+v err=%v", decisions, err)
	}
	assertDeterministicBlob(t, database, "policy_candidates", "candidate_id", "candidate-1", shadow[0])
	assertDeterministicBlob(t, database, "policy_replay_runs", "replay_id", "replay-1", replays[0])
	assertDeterministicBlob(t, database, "tuning_decisions", "decision_id", "tuning-1", decisions[0])

	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	database, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if replays, err := database.ListPolicyReplayRuns("candidate-1", 10); err != nil || len(replays) != 1 {
		t.Fatalf("replay did not survive restart: count=%d err=%v", len(replays), err)
	}
	if decisions, err := database.ListTuningDecisions("candidate-1", 10); err != nil || len(decisions) != 1 {
		t.Fatalf("tuning decision did not survive restart: count=%d err=%v", len(decisions), err)
	}
}

func TestApplyPolicyCandidateMaterializesAndPublishesRolloutStages(t *testing.T) {
	database := candidateApplicationStore(t)
	defer database.Close()

	var previousVersion int32
	for i, stage := range []roomv1.RolloutStage{
		roomv1.RolloutStage_ROLLOUT_STAGE_SHADOW,
		roomv1.RolloutStage_ROLLOUT_STAGE_WARN,
		roomv1.RolloutStage_ROLLOUT_STAGE_BLOCK,
	} {
		current, err := database.PolicyCandidate("candidate-apply")
		if err != nil {
			t.Fatal(err)
		}
		next := nextCandidateRevision(current)
		next.RolloutStage = stage
		applied, published, err := database.ApplyPolicyCandidate(next, current.GetUpdatedAt(), nil, policyAudit("apply-stage", i, next.GetId()))
		if err != nil {
			t.Fatalf("apply %s: %v", stage, err)
		}
		if applied.GetRolloutStage() != stage || published == nil || published.GetVersion() <= previousVersion {
			t.Fatalf("stage was not published: candidate=%+v ruleset=%+v", applied, published)
		}
		assertCandidateRuleState(t, database.ListRules(true), stage, true, 8500)
		assertCandidateRuleState(t, published.GetRules(), stage, true, 8500)
		previousVersion = published.GetVersion()
	}

	current, _ := database.PolicyCandidate("candidate-apply")
	next := nextCandidateRevision(current)
	next.MinimumConfidenceBasisPoints = 8000
	publishedCandidate, published, err := database.ApplyPolicyCandidate(next, current.GetUpdatedAt(), nil, policyAudit("apply-threshold", 0, next.GetId()))
	if err != nil {
		t.Fatalf("apply active threshold change: %v", err)
	}
	if published.GetVersion() <= previousVersion || publishedCandidate.GetMinimumConfidenceBasisPoints() != 8000 {
		t.Fatalf("active threshold change was not published: candidate=%+v ruleset=%+v", publishedCandidate, published)
	}
	assertCandidateRuleState(t, published.GetRules(), roomv1.RolloutStage_ROLLOUT_STAGE_BLOCK, true, 8000)
}

func TestApplyPolicyCandidatePauseDisablesRuleInNewVersion(t *testing.T) {
	database := candidateApplicationStore(t)
	defer database.Close()
	current, _ := database.PolicyCandidate("candidate-apply")
	shadow := nextCandidateRevision(current)
	shadow.RolloutStage = roomv1.RolloutStage_ROLLOUT_STAGE_SHADOW
	_, first, err := database.ApplyPolicyCandidate(shadow, current.GetUpdatedAt(), nil, policyAudit("activate", 0, shadow.GetId()))
	if err != nil {
		t.Fatal(err)
	}
	current, _ = database.PolicyCandidate("candidate-apply")
	paused := nextCandidateRevision(current)
	paused.RolloutStage = roomv1.RolloutStage_ROLLOUT_STAGE_PAUSED
	_, disabled, err := database.ApplyPolicyCandidate(paused, current.GetUpdatedAt(), nil, policyAudit("pause", 0, paused.GetId()))
	if err != nil {
		t.Fatal(err)
	}
	if disabled == nil || disabled.GetVersion() <= first.GetVersion() {
		t.Fatalf("pause did not publish a disabling version: first=%+v disabled=%+v", first, disabled)
	}
	assertCandidateRuleState(t, database.ListRules(true), roomv1.RolloutStage_ROLLOUT_STAGE_PAUSED, false, 8500)
	assertCandidateRuleState(t, disabled.GetRules(), roomv1.RolloutStage_ROLLOUT_STAGE_PAUSED, false, 8500)
}

func TestApplyPolicyCandidateRejectsStaleCAS(t *testing.T) {
	database := candidateApplicationStore(t)
	defer database.Close()
	stale, _ := database.PolicyCandidate("candidate-apply")
	shadow := nextCandidateRevision(stale)
	shadow.RolloutStage = roomv1.RolloutStage_ROLLOUT_STAGE_SHADOW
	_, first, err := database.ApplyPolicyCandidate(shadow, stale.GetUpdatedAt(), nil, policyAudit("first", 0, shadow.GetId()))
	if err != nil {
		t.Fatal(err)
	}
	warn := nextCandidateRevision(stale)
	warn.RolloutStage = roomv1.RolloutStage_ROLLOUT_STAGE_WARN
	if _, _, err := database.ApplyPolicyCandidate(warn, stale.GetUpdatedAt(), nil, policyAudit("stale", 0, warn.GetId())); !errors.Is(err, ErrPolicyCandidateConflict) {
		t.Fatalf("stale update error = %v, want ErrPolicyCandidateConflict", err)
	}
	loaded, _ := database.PolicyCandidate("candidate-apply")
	if loaded.GetRolloutStage() != roomv1.RolloutStage_ROLLOUT_STAGE_SHADOW || database.ActiveRuleset().GetVersion() != first.GetVersion() {
		t.Fatalf("stale update changed state: candidate=%+v active=%+v", loaded, database.ActiveRuleset())
	}
}

func TestApplyPolicyCandidateAuditFailureRollsBackEverything(t *testing.T) {
	database := candidateApplicationStore(t)
	defer database.Close()
	baselineVersion := database.ActiveRuleset().GetVersion()
	baselineRuleCount := len(database.ListRules(true))
	occurredAt := timestamppb.Now()
	seedAudit := &roomv1.AuditEvent{Id: "duplicate-audit", Kind: roomv1.AuditEventKind_AUDIT_EVENT_KIND_POLICY_TRANSITIONED, OccurredAt: occurredAt, SubjectId: "first"}
	if _, err := database.AppendAudit(seedAudit); err != nil {
		t.Fatal(err)
	}
	current, _ := database.PolicyCandidate("candidate-apply")
	shadow := nextCandidateRevision(current)
	shadow.RolloutStage = roomv1.RolloutStage_ROLLOUT_STAGE_SHADOW
	decision := &roomv1.TuningDecision{Id: "rolled-back-decision", PolicyCandidateId: shadow.GetId(), Action: roomv1.TuningActionKind_TUNING_ACTION_KIND_ADJUST_CONFIDENCE, PreviousConfidenceBasisPoints: 9000, NewConfidenceBasisPoints: 8500, ActorId: "tuner"}
	badAudit := &roomv1.AuditEvent{Id: seedAudit.GetId(), Kind: seedAudit.GetKind(), OccurredAt: occurredAt, SubjectId: "different", PolicyCandidateId: shadow.GetId()}
	if _, _, err := database.ApplyPolicyCandidate(shadow, current.GetUpdatedAt(), decision, badAudit); err == nil {
		t.Fatal("conflicting audit event was accepted")
	}
	loaded, _ := database.PolicyCandidate("candidate-apply")
	decisions, err := database.ListTuningDecisions("candidate-apply", 10)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.GetRolloutStage() != roomv1.RolloutStage_ROLLOUT_STAGE_DRAFT {
		t.Fatalf("failed transaction changed candidate stage to %s", loaded.GetRolloutStage())
	}
	if active := database.ActiveRuleset(); active.GetVersion() != baselineVersion {
		t.Fatalf("failed transaction changed active version from %d to %d", baselineVersion, active.GetVersion())
	}
	rules := database.ListRules(true)
	if len(rules) != baselineRuleCount {
		t.Fatalf("failed transaction changed draft rule count from %d to %d", baselineRuleCount, len(rules))
	}
	if hasRule(rules, "candidate-rule") {
		t.Fatal("failed transaction materialized the candidate rule")
	}
	if len(decisions) != 0 {
		t.Fatalf("failed transaction persisted tuning decisions: %+v", decisions)
	}
}

func TestApplyPolicyCandidatePersistsTuningDecisionAtomically(t *testing.T) {
	database := candidateApplicationStore(t)
	defer database.Close()
	current, _ := database.PolicyCandidate("candidate-apply")
	next := nextCandidateRevision(current)
	next.RolloutStage = roomv1.RolloutStage_ROLLOUT_STAGE_SHADOW
	next.MinimumConfidenceBasisPoints = 8000
	decision := &roomv1.TuningDecision{Id: "atomic-decision", PolicyCandidateId: next.GetId(), Action: roomv1.TuningActionKind_TUNING_ACTION_KIND_ADJUST_CONFIDENCE, PreviousConfidenceBasisPoints: 8500, NewConfidenceBasisPoints: 8000, ActorId: "tuner"}
	applied, published, err := database.ApplyPolicyCandidate(next, current.GetUpdatedAt(), decision, policyAudit("tune", 0, next.GetId()))
	if err != nil {
		t.Fatal(err)
	}
	decisions, err := database.ListTuningDecisions(next.GetId(), 10)
	if err != nil || len(decisions) != 1 || decisions[0].GetId() != decision.GetId() || decisions[0].GetOccurredAt() == nil {
		t.Fatalf("tuning decision missing: decisions=%+v err=%v", decisions, err)
	}
	if decision.GetOccurredAt() != nil || applied.GetMinimumConfidenceBasisPoints() != 8000 || published == nil {
		t.Fatalf("atomic apply or caller isolation failed: decision=%+v candidate=%+v ruleset=%+v", decision, applied, published)
	}
}

func TestAuditedIntelligenceMutationsRollbackOnAuditConflict(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *Store, *roomv1.AuditEvent) error
		assert func(*testing.T, *Store)
	}{
		{
			name: "upsert finding",
			mutate: func(t *testing.T, database *Store, audit *roomv1.AuditEvent) error {
				_, err := database.UpsertReviewFindingAudited(validAtomicFinding("atomic-finding"), audit)
				return err
			},
			assert: func(t *testing.T, database *Store) {
				finding, err := database.ReviewFinding("atomic-finding")
				if err != nil || finding != nil {
					t.Fatalf("finding mutation was not rolled back: finding=%+v err=%v", finding, err)
				}
			},
		},
		{
			name: "append outcome",
			mutate: func(t *testing.T, database *Store, audit *roomv1.AuditEvent) error {
				if _, err := database.UpsertReviewFinding(validAtomicFinding("outcome-finding")); err != nil {
					t.Fatal(err)
				}
				_, err := database.AppendReviewOutcomeAudited("outcome-finding", &roomv1.ReviewOutcome{Id: "atomic-outcome", Kind: roomv1.ReviewOutcomeKind_REVIEW_OUTCOME_KIND_FIX_COMMITTED, ActorId: "reviewer"}, audit)
				return err
			},
			assert: func(t *testing.T, database *Store) {
				finding, err := database.ReviewFinding("outcome-finding")
				if err != nil || len(finding.GetOutcomes()) != 0 {
					t.Fatalf("outcome mutation was not rolled back: finding=%+v err=%v", finding, err)
				}
			},
		},
		{
			name: "append adjudication",
			mutate: func(t *testing.T, database *Store, audit *roomv1.AuditEvent) error {
				if _, err := database.UpsertReviewFinding(validAtomicFinding("adjudication-finding")); err != nil {
					t.Fatal(err)
				}
				_, err := database.AppendReviewAdjudicationAudited("adjudication-finding", &roomv1.ReviewAdjudication{Id: "atomic-adjudication", Verdict: roomv1.AdjudicationVerdict_ADJUDICATION_VERDICT_VALID_GENERALIZABLE, AgentId: "agent", ModelId: "model", InputSha256: bytes.Repeat([]byte{1}, sha256.Size)}, audit)
				return err
			},
			assert: func(t *testing.T, database *Store) {
				finding, err := database.ReviewFinding("adjudication-finding")
				if err != nil || len(finding.GetAdjudications()) != 0 {
					t.Fatalf("adjudication mutation was not rolled back: finding=%+v err=%v", finding, err)
				}
			},
		},
		{
			name: "upsert candidate",
			mutate: func(t *testing.T, database *Store, audit *roomv1.AuditEvent) error {
				_, err := database.UpsertPolicyCandidateAudited(validAtomicCandidate("atomic-candidate", "atomic-rule"), audit)
				return err
			},
			assert: func(t *testing.T, database *Store) {
				candidate, err := database.PolicyCandidate("atomic-candidate")
				if err != nil || candidate != nil {
					t.Fatalf("candidate mutation was not rolled back: candidate=%+v err=%v", candidate, err)
				}
			},
		},
		{
			name: "save replay",
			mutate: func(t *testing.T, database *Store, audit *roomv1.AuditEvent) error {
				return database.SavePolicyReplayAudited(&roomv1.PolicyReplayRun{Id: "atomic-replay", PolicyCandidateId: "candidate"}, audit)
			},
			assert: func(t *testing.T, database *Store) {
				replays, err := database.ListPolicyReplays("candidate", 10)
				if err != nil || len(replays) != 0 {
					t.Fatalf("replay mutation was not rolled back: replays=%+v err=%v", replays, err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			database, err := Open(filepath.Join(t.TempDir(), "room.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close()
			occurredAt := timestamppb.Now()
			seed := &roomv1.AuditEvent{Id: "audit-conflict", Kind: roomv1.AuditEventKind_AUDIT_EVENT_KIND_POLICY_UPDATED, OccurredAt: occurredAt, SubjectId: "original"}
			if _, err := database.AppendAudit(seed); err != nil {
				t.Fatal(err)
			}
			conflict := &roomv1.AuditEvent{Id: seed.GetId(), Kind: seed.GetKind(), OccurredAt: occurredAt, SubjectId: "different"}
			if err := test.mutate(t, database, conflict); err == nil {
				t.Fatal("conflicting audit event was accepted")
			}
			test.assert(t, database)
		})
	}
}

func TestApplyPolicyCandidateSupersedesActiveRevisionForStableRule(t *testing.T) {
	database, err := Open(filepath.Join(t.TempDir(), "room.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	first, err := database.UpsertPolicyCandidate(validAtomicCandidate("revision-1", "stable-rule"))
	if err != nil {
		t.Fatal(err)
	}
	firstActive := nextCandidateRevision(first)
	firstActive.RolloutStage = roomv1.RolloutStage_ROLLOUT_STAGE_SHADOW
	if _, _, err := database.ApplyPolicyCandidate(firstActive, first.GetUpdatedAt(), nil, policyAudit("activate-first", 0, first.GetId())); err != nil {
		t.Fatal(err)
	}
	second, err := database.UpsertPolicyCandidate(validAtomicCandidate("revision-2", "stable-rule"))
	if err != nil {
		t.Fatal(err)
	}
	secondActive := nextCandidateRevision(second)
	secondActive.RolloutStage = roomv1.RolloutStage_ROLLOUT_STAGE_WARN
	_, published, err := database.ApplyPolicyCandidate(secondActive, second.GetUpdatedAt(), nil, policyAudit("activate-second", 0, second.GetId()))
	if err != nil {
		t.Fatal(err)
	}
	retired, _ := database.PolicyCandidate(first.GetId())
	replacement, _ := database.PolicyCandidate(second.GetId())
	if retired.GetRolloutStage() != roomv1.RolloutStage_ROLLOUT_STAGE_ROLLED_BACK {
		t.Fatalf("prior revision stage = %s, want ROLLED_BACK", retired.GetRolloutStage())
	}
	if replacement.GetRolloutStage() != roomv1.RolloutStage_ROLLOUT_STAGE_WARN {
		t.Fatalf("replacement stage = %s, want WARN", replacement.GetRolloutStage())
	}
	for _, rule := range published.GetRules() {
		if rule.GetId() == "stable-rule" {
			if !rule.GetEnabled() || rule.GetRolloutStage() != roomv1.RolloutStage_ROLLOUT_STAGE_WARN {
				t.Fatalf("replacement rule was not active: %+v", rule)
			}
			return
		}
	}
	t.Fatal("stable replacement rule was not published")
}

func TestUpsertPolicyCandidatesAuditedRollsBackOnLateAuditConflict(t *testing.T) {
	database, err := Open(filepath.Join(t.TempDir(), "room.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	occurredAt := timestamppb.Now()
	seed := &roomv1.AuditEvent{Id: "late-conflict", Kind: roomv1.AuditEventKind_AUDIT_EVENT_KIND_POLICY_INFERRED, OccurredAt: occurredAt, SubjectId: "existing"}
	if _, err := database.AppendAudit(seed); err != nil {
		t.Fatal(err)
	}
	candidates := []*roomv1.PolicyCandidate{
		validAtomicCandidate("batch-candidate-1", "batch-rule-1"),
		validAtomicCandidate("batch-candidate-2", "batch-rule-2"),
	}
	audits := []*roomv1.AuditEvent{
		{Id: "batch-audit-1", Kind: roomv1.AuditEventKind_AUDIT_EVENT_KIND_POLICY_INFERRED, SubjectId: "inference-agent", PolicyCandidateId: candidates[0].GetId()},
		{Id: seed.GetId(), Kind: seed.GetKind(), OccurredAt: occurredAt, SubjectId: "different", PolicyCandidateId: candidates[1].GetId()},
	}
	if _, err := database.UpsertPolicyCandidatesAudited(candidates, audits); err == nil {
		t.Fatal("late conflicting audit was accepted")
	}
	for _, candidate := range candidates {
		stored, err := database.PolicyCandidate(candidate.GetId())
		if err != nil || stored != nil {
			t.Fatalf("candidate %q escaped rolled-back batch: candidate=%+v err=%v", candidate.GetId(), stored, err)
		}
	}
	firstAudit, err := database.AuditEvent(audits[0].GetId())
	if err != nil || firstAudit != nil {
		t.Fatalf("earlier aligned audit escaped rolled-back batch: audit=%+v err=%v", firstAudit, err)
	}
}

func TestUpsertPolicyCandidatesAuditedRejectsMisalignedBatch(t *testing.T) {
	database, err := Open(filepath.Join(t.TempDir(), "room.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.UpsertPolicyCandidatesAudited([]*roomv1.PolicyCandidate{validAtomicCandidate("candidate", "rule")}, nil); err == nil {
		t.Fatal("candidate and audit length mismatch was accepted")
	}
}

func TestReviewIntelligenceValidationBounds(t *testing.T) {
	database, err := Open(filepath.Join(t.TempDir(), "room.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	invalidFinding := &roomv1.ReviewFinding{Id: "finding", Source: &roomv1.ReviewSource{Repository: "repo"}, ClaimKind: roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_SECURITY_BOUNDARY, Severity: roomv1.Severity_SEVERITY_HIGH, ConfidenceBasisPoints: 10001}
	if _, err := database.UpsertReviewFinding(invalidFinding); err == nil {
		t.Fatal("out-of-range finding confidence was accepted")
	}
	invalidCandidate := &roomv1.PolicyCandidate{Id: "candidate", ClaimKind: roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_SECURITY_BOUNDARY, ArtifactKind: roomv1.PolicyArtifactKind_POLICY_ARTIFACT_KIND_DETERMINISTIC_CHECK, RolloutStage: roomv1.RolloutStage_ROLLOUT_STAGE_DRAFT, MinimumConfidenceBasisPoints: 10001}
	if _, err := database.UpsertPolicyCandidate(invalidCandidate); err == nil {
		t.Fatal("out-of-range candidate confidence was accepted")
	}
	if err := database.SaveTuningDecision(&roomv1.TuningDecision{Id: "", PolicyCandidateId: "candidate", Action: roomv1.TuningActionKind_TUNING_ACTION_KIND_ROLLBACK, ActorId: "actor"}); err == nil {
		t.Fatal("missing tuning decision id was accepted")
	}
}

func TestReviewIntelligenceReadsRejectCorruption(t *testing.T) {
	tests := []struct {
		name    string
		corrupt func(*testing.T, *Store)
		read    func(*Store) error
	}{
		{
			name: "finding point digest",
			corrupt: func(t *testing.T, database *Store) {
				execCorruption(t, database, `UPDATE review_findings SET payload_sha256 = ? WHERE finding_id = ?`, bytes.Repeat([]byte{0}, sha256.Size), "finding-1")
			},
			read: func(database *Store) error { _, err := database.ReviewFinding("finding-1"); return err },
		},
		{
			name: "finding list index",
			corrupt: func(t *testing.T, database *Store) {
				execCorruption(t, database, `UPDATE review_findings SET repository = ? WHERE finding_id = ?`, "other/repo", "finding-1")
			},
			read: func(database *Store) error {
				_, err := database.ListReviewFindings("other/repo", roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_UNSPECIFIED, 10)
				return err
			},
		},
		{
			name: "candidate point digest",
			corrupt: func(t *testing.T, database *Store) {
				execCorruption(t, database, `UPDATE policy_candidates SET payload_sha256 = ? WHERE candidate_id = ?`, bytes.Repeat([]byte{0}, sha256.Size), "candidate-1")
			},
			read: func(database *Store) error { _, err := database.PolicyCandidate("candidate-1"); return err },
		},
		{
			name: "candidate list index",
			corrupt: func(t *testing.T, database *Store) {
				execCorruption(t, database, `UPDATE policy_candidates SET rollout_stage = ? WHERE candidate_id = ?`, int32(roomv1.RolloutStage_ROLLOUT_STAGE_SHADOW), "candidate-1")
			},
			read: func(database *Store) error {
				_, err := database.ListPolicyCandidates(roomv1.RolloutStage_ROLLOUT_STAGE_SHADOW)
				return err
			},
		},
		{
			name: "replay point digest",
			corrupt: func(t *testing.T, database *Store) {
				execCorruption(t, database, `UPDATE policy_replay_runs SET payload_sha256 = ? WHERE replay_id = ?`, bytes.Repeat([]byte{0}, sha256.Size), "replay-1")
			},
			read: func(database *Store) error { return database.SavePolicyReplay(validReplay()) },
		},
		{
			name: "replay list index",
			corrupt: func(t *testing.T, database *Store) {
				execCorruption(t, database, `UPDATE policy_replay_runs SET policy_candidate_id = ? WHERE replay_id = ?`, "candidate-2", "replay-1")
			},
			read: func(database *Store) error { _, err := database.ListPolicyReplays("candidate-2", 10); return err },
		},
		{
			name: "tuning point digest",
			corrupt: func(t *testing.T, database *Store) {
				execCorruption(t, database, `UPDATE tuning_decisions SET payload_sha256 = ? WHERE decision_id = ?`, bytes.Repeat([]byte{0}, sha256.Size), "tuning-1")
			},
			read: func(database *Store) error { return database.SaveTuningDecision(validTuningDecision()) },
		},
		{
			name: "tuning list index",
			corrupt: func(t *testing.T, database *Store) {
				execCorruption(t, database, `UPDATE tuning_decisions SET policy_candidate_id = ? WHERE decision_id = ?`, "candidate-2", "tuning-1")
			},
			read: func(database *Store) error { _, err := database.ListTuningDecisions("candidate-2", 10); return err },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			database := seededIntelligenceStore(t)
			defer database.Close()
			test.corrupt(t, database)
			if err := test.read(database); err == nil {
				t.Fatal("corrupted record was accepted")
			}
		})
	}
}

func candidateApplicationStore(t *testing.T) *Store {
	t.Helper()
	database, err := Open(filepath.Join(t.TempDir(), "room.db"))
	if err != nil {
		t.Fatal(err)
	}
	candidate := &roomv1.PolicyCandidate{
		Id:           "candidate-apply",
		ClaimKind:    roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_SECURITY_BOUNDARY,
		ArtifactKind: roomv1.PolicyArtifactKind_POLICY_ARTIFACT_KIND_DETERMINISTIC_CHECK,
		ProposedRule: &roomv1.Rule{
			Id:               "candidate-rule",
			Triggers:         []*roomv1.SignalSelector{{Signal: roomv1.SignalKind_SIGNAL_KIND_REVIEW_SECURITY_BOUNDARY, MinimumConfidenceBasisPoints: 8500}},
			RequiredCoverage: []roomv1.SignalKind{roomv1.SignalKind_SIGNAL_KIND_REVIEW_SECURITY_BOUNDARY},
		},
		RolloutStage:                 roomv1.RolloutStage_ROLLOUT_STAGE_DRAFT,
		MinimumConfidenceBasisPoints: 8500,
		CreatedBy:                    "policy-agent",
	}
	if _, err := database.UpsertPolicyCandidate(candidate); err != nil {
		database.Close()
		t.Fatal(err)
	}
	return database
}

func validAtomicFinding(id string) *roomv1.ReviewFinding {
	return &roomv1.ReviewFinding{
		Id:                    id,
		Source:                &roomv1.ReviewSource{Repository: "atomic/repo"},
		ClaimKind:             roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_SECURITY_BOUNDARY,
		Invariant:             "trusted scope is required",
		Severity:              roomv1.Severity_SEVERITY_HIGH,
		ConfidenceBasisPoints: 9000,
	}
}

func validAtomicCandidate(id, ruleID string) *roomv1.PolicyCandidate {
	return &roomv1.PolicyCandidate{
		Id:           id,
		ClaimKind:    roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_SECURITY_BOUNDARY,
		ArtifactKind: roomv1.PolicyArtifactKind_POLICY_ARTIFACT_KIND_DETERMINISTIC_CHECK,
		ProposedRule: &roomv1.Rule{
			Id:               ruleID,
			Triggers:         []*roomv1.SignalSelector{{Signal: roomv1.SignalKind_SIGNAL_KIND_REVIEW_SECURITY_BOUNDARY, MinimumConfidenceBasisPoints: 8500}},
			RequiredCoverage: []roomv1.SignalKind{roomv1.SignalKind_SIGNAL_KIND_REVIEW_SECURITY_BOUNDARY},
		},
		RolloutStage:                 roomv1.RolloutStage_ROLLOUT_STAGE_DRAFT,
		MinimumConfidenceBasisPoints: 8500,
		CreatedBy:                    "policy-agent",
	}
}

func nextCandidateRevision(candidate *roomv1.PolicyCandidate) *roomv1.PolicyCandidate {
	next := proto.Clone(candidate).(*roomv1.PolicyCandidate)
	next.UpdatedAt = timestamppb.New(candidate.GetUpdatedAt().AsTime().Add(time.Nanosecond))
	return next
}

func policyAudit(prefix string, sequence int, candidateID string) *roomv1.AuditEvent {
	return &roomv1.AuditEvent{
		Id:                prefix + "-" + string(rune('a'+sequence)),
		Kind:              roomv1.AuditEventKind_AUDIT_EVENT_KIND_POLICY_TRANSITIONED,
		SubjectId:         "policy-agent",
		PolicyCandidateId: candidateID,
	}
}

func assertCandidateRuleState(t *testing.T, rules []*roomv1.Rule, stage roomv1.RolloutStage, enabled bool, confidence uint32) {
	t.Helper()
	for _, rule := range rules {
		if rule.GetId() != "candidate-rule" {
			continue
		}
		if rule.GetRolloutStage() != stage || rule.GetEnabled() != enabled || len(rule.GetTriggers()) != 1 || rule.GetTriggers()[0].GetMinimumConfidenceBasisPoints() != confidence {
			t.Fatalf("candidate rule state mismatch: %+v", rule)
		}
		return
	}
	t.Fatalf("candidate rule not found in %+v", rules)
}

func hasRule(rules []*roomv1.Rule, id string) bool {
	for _, rule := range rules {
		if rule.GetId() == id {
			return true
		}
	}
	return false
}

func seededIntelligenceStore(t *testing.T) *Store {
	t.Helper()
	database, err := Open(filepath.Join(t.TempDir(), "room.db"))
	if err != nil {
		t.Fatal(err)
	}
	finding := &roomv1.ReviewFinding{
		Id: "finding-1", Source: &roomv1.ReviewSource{Repository: "evalops/room"},
		ClaimKind: roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_SECURITY_BOUNDARY,
		Severity:  roomv1.Severity_SEVERITY_HIGH, ConfidenceBasisPoints: 9000,
	}
	if _, err := database.UpsertReviewFinding(finding); err != nil {
		t.Fatalf("seed finding: %v", err)
	}
	candidate := &roomv1.PolicyCandidate{
		Id: "candidate-1", ClaimKind: roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_SECURITY_BOUNDARY,
		ArtifactKind: roomv1.PolicyArtifactKind_POLICY_ARTIFACT_KIND_DETERMINISTIC_CHECK,
		ProposedRule: &roomv1.Rule{
			Id: "learned-security", Enabled: false,
			Triggers:         []*roomv1.SignalSelector{{Signal: roomv1.SignalKind_SIGNAL_KIND_REVIEW_SECURITY_BOUNDARY, MinimumConfidenceBasisPoints: 9000}},
			RequiredCoverage: []roomv1.SignalKind{roomv1.SignalKind_SIGNAL_KIND_REVIEW_SECURITY_BOUNDARY},
		},
		RolloutStage: roomv1.RolloutStage_ROLLOUT_STAGE_DRAFT, MinimumConfidenceBasisPoints: 9000,
	}
	if _, err := database.UpsertPolicyCandidate(candidate); err != nil {
		t.Fatalf("seed candidate: %v", err)
	}
	if err := database.SavePolicyReplay(validReplay()); err != nil {
		t.Fatalf("seed replay: %v", err)
	}
	if err := database.SaveTuningDecision(validTuningDecision()); err != nil {
		t.Fatalf("seed tuning decision: %v", err)
	}
	return database
}

func validReplay() *roomv1.PolicyReplayRun {
	return &roomv1.PolicyReplayRun{Id: "replay-1", PolicyCandidateId: "candidate-1", Cases: []*roomv1.ReplayCaseResult{{FindingId: "finding-1", ExpectedMatch: true, ActualMatch: true, ConfidenceBasisPoints: 9000}}}
}

func validTuningDecision() *roomv1.TuningDecision {
	return &roomv1.TuningDecision{Id: "tuning-1", PolicyCandidateId: "candidate-1", Action: roomv1.TuningActionKind_TUNING_ACTION_KIND_ADJUST_CONFIDENCE, PreviousConfidenceBasisPoints: 9000, NewConfidenceBasisPoints: 8500, ActorId: "tuner"}
}

func execCorruption(t *testing.T, database *Store, query string, args ...any) {
	t.Helper()
	if _, err := database.db.Exec(query, args...); err != nil {
		t.Fatalf("corrupt stored record: %v", err)
	}
}

func assertDeterministicBlob(t *testing.T, database *Store, table, idColumn, id string, message proto.Message) {
	t.Helper()
	var payload, digest []byte
	if err := database.db.QueryRow(`SELECT payload, payload_sha256 FROM `+table+` WHERE `+idColumn+` = ?`, id).Scan(&payload, &digest); err != nil {
		t.Fatalf("read %s blob: %v", table, err)
	}
	wantPayload, wantDigest, err := deterministicPayload(message)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, wantPayload) || !bytes.Equal(digest, wantDigest) {
		t.Fatalf("%s payload is not deterministic or digest-protected", table)
	}
}
