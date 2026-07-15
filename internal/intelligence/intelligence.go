// Package intelligence derives policy candidates and replay/tuning decisions
// exclusively from typed review-control-plane fields.
package intelligence

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	roomv1 "github.com/haasonsaas/room/gen/go/room/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	maxBasisPoints       = uint32(10_000)
	minimumPrecisionBPS  = uint32(8_000)
	minimumRecallBPS     = uint32(5_000)
	falsePositivePenalty = uint64(4)
)

// Infer groups findings by repository and typed claim kind and proposes a draft
// candidate for groups with enough generalizable, hard-positive support.
func Infer(findings []*roomv1.ReviewFinding, minimumSupport uint32, actorID string) ([]*roomv1.PolicyCandidate, error) {
	if minimumSupport == 0 {
		return nil, errors.New("minimum support must be greater than zero")
	}
	if actorID == "" {
		return nil, errors.New("actor id is required")
	}

	type groupKey struct {
		repository string
		claim      roomv1.ReviewClaimKind
	}
	groups := make(map[groupKey][]*roomv1.ReviewFinding)
	for i, finding := range findings {
		if err := validateFinding(finding); err != nil {
			return nil, fmt.Errorf("finding %d: %w", i, err)
		}
		key := groupKey{repository: finding.GetSource().GetRepository(), claim: finding.GetClaimKind()}
		groups[key] = append(groups[key], finding)
	}

	keys := make([]groupKey, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].repository != keys[j].repository {
			return keys[i].repository < keys[j].repository
		}
		return keys[i].claim < keys[j].claim
	})

	result := make([]*roomv1.PolicyCandidate, 0, len(keys))
	for _, key := range keys {
		group := groups[key]
		accepted := make([]*roomv1.ReviewFinding, 0, len(group))
		for _, finding := range group {
			if expectedMatch(finding) {
				accepted = append(accepted, finding)
			}
		}
		if uint32(len(accepted)) < minimumSupport {
			continue
		}

		metadata, err := claimMetadataFor(key.claim)
		if err != nil {
			return nil, err
		}
		threshold := medianConfidence(accepted)
		sourceFindingIDs := findingIDs(accepted)
		severity := maximumSeverity(accepted)
		requiredEvidence := aggregateStrings(accepted, func(finding *roomv1.ReviewFinding) []string { return finding.GetRequiredEvidence() })
		remediation := aggregateStrings(accepted, func(finding *roomv1.ReviewFinding) []string { return finding.GetRemediation() })
		candidateID, err := policyRevisionID(key.repository, key.claim, sourceFindingIDs, threshold, metadata.artifact, severity, requiredEvidence, remediation)
		if err != nil {
			return nil, err
		}
		ruleID, err := stableRuleID(key.repository, key.claim)
		if err != nil {
			return nil, err
		}
		now := timestamppb.Now()
		candidate := &roomv1.PolicyCandidate{
			Id:                           candidateID,
			ClaimKind:                    key.claim,
			ArtifactKind:                 metadata.artifact,
			SourceFindingIds:             sourceFindingIDs,
			RolloutStage:                 roomv1.RolloutStage_ROLLOUT_STAGE_DRAFT,
			MinimumConfidenceBasisPoints: threshold,
			CreatedBy:                    actorID,
			CreatedAt:                    now,
			UpdatedAt:                    now,
			ProposedRule: &roomv1.Rule{
				Id:          ruleID,
				Title:       metadata.title,
				Description: metadata.description,
				Severity:    severity,
				Scope:       &roomv1.RuleScope{Repositories: []string{key.repository}},
				Triggers: []*roomv1.SignalSelector{{
					Signal:                       metadata.signal,
					Phases:                       []roomv1.AnalysisPhase{roomv1.AnalysisPhase_ANALYSIS_PHASE_PLAN, roomv1.AnalysisPhase_ANALYSIS_PHASE_DIFF},
					MinimumConfidenceBasisPoints: threshold,
				}},
				RequiredCoverage: []roomv1.SignalKind{metadata.signal},
				RequiredEvidence: requiredEvidence,
				Remediation:      remediation,
				Enabled:          false,
				Owner:            actorID,
				CreatedAt:        now,
				UpdatedAt:        now,
			},
		}
		candidate.ProtectedOrgPolicy = severity == roomv1.Severity_SEVERITY_CRITICAL
		cases := classify(candidate, group)
		candidate.Metrics = metricsFromCases(cases)
		candidate.Metrics.SupportCount = uint32(len(group))
		candidate.Metrics.AcceptedCount = uint32(len(accepted))
		candidate.Metrics.RejectedCount = uint32(len(group) - len(accepted))
		for _, finding := range accepted {
			if finding.GetConfidenceBasisPoints() >= threshold {
				candidate.Metrics.EstimatedReviewerCostAvoidedMicros += finding.GetReviewerCostMicros()
				candidate.Metrics.EstimatedReviewerTokensAvoided += finding.GetReviewerInputTokens() + finding.GetReviewerOutputTokens()
			}
		}
		result = append(result, candidate)
	}
	return result, nil
}

// ArtifactKind selects the implementation boundary from the typed claim kind.
func ArtifactKind(claim roomv1.ReviewClaimKind) (roomv1.PolicyArtifactKind, error) {
	metadata, err := claimMetadataFor(claim)
	return metadata.artifact, err
}

type claimMetadata struct {
	artifact    roomv1.PolicyArtifactKind
	signal      roomv1.SignalKind
	title       string
	description string
}

func claimMetadataFor(claim roomv1.ReviewClaimKind) (claimMetadata, error) {
	metadata := map[roomv1.ReviewClaimKind]claimMetadata{
		roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_AUTHORIZATION_BOUNDARY: {
			artifact:    roomv1.PolicyArtifactKind_POLICY_ARTIFACT_KIND_DETERMINISTIC_CHECK,
			signal:      roomv1.SignalKind_SIGNAL_KIND_REVIEW_AUTHORIZATION_BOUNDARY,
			title:       "Review authorization boundary",
			description: "Require typed analyzer evidence for review findings about authorization boundaries.",
		},
		roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_STATE_TRANSITION: {
			artifact:    roomv1.PolicyArtifactKind_POLICY_ARTIFACT_KIND_DETERMINISTIC_CHECK,
			signal:      roomv1.SignalKind_SIGNAL_KIND_REVIEW_STATE_TRANSITION,
			title:       "Review state transition",
			description: "Require typed analyzer evidence for review findings about state transitions.",
		},
		roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_PROTOCOL_CONTRACT: {
			artifact:    roomv1.PolicyArtifactKind_POLICY_ARTIFACT_KIND_DETERMINISTIC_CHECK,
			signal:      roomv1.SignalKind_SIGNAL_KIND_REVIEW_PROTOCOL_CONTRACT,
			title:       "Review protocol contract",
			description: "Require typed analyzer evidence for review findings about protocol contracts.",
		},
		roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_GUARDRAIL_COVERAGE: {
			artifact:    roomv1.PolicyArtifactKind_POLICY_ARTIFACT_KIND_ARCHITECTURE_POLICY,
			signal:      roomv1.SignalKind_SIGNAL_KIND_REVIEW_GUARDRAIL_COVERAGE,
			title:       "Review guardrail coverage",
			description: "Require typed analyzer evidence for review findings about guardrail coverage.",
		},
		roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_OPERATIONAL_TRUTH: {
			artifact:    roomv1.PolicyArtifactKind_POLICY_ARTIFACT_KIND_SEMANTIC_ANALYZER,
			signal:      roomv1.SignalKind_SIGNAL_KIND_REVIEW_OPERATIONAL_TRUTH,
			title:       "Review operational truth",
			description: "Require typed analyzer evidence for review findings about operational behavior.",
		},
		roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_SECURITY_BOUNDARY: {
			artifact:    roomv1.PolicyArtifactKind_POLICY_ARTIFACT_KIND_ARCHITECTURE_POLICY,
			signal:      roomv1.SignalKind_SIGNAL_KIND_REVIEW_SECURITY_BOUNDARY,
			title:       "Review security boundary",
			description: "Require typed analyzer evidence for review findings about security boundaries.",
		},
		roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_NEGATIVE_TEST_GAP: {
			artifact:    roomv1.PolicyArtifactKind_POLICY_ARTIFACT_KIND_DETERMINISTIC_CHECK,
			signal:      roomv1.SignalKind_SIGNAL_KIND_REVIEW_NEGATIVE_TEST_GAP,
			title:       "Review negative-test gap",
			description: "Require typed analyzer evidence for review findings about negative-test gaps.",
		},
	}
	value, ok := metadata[claim]
	if !ok {
		return claimMetadata{}, fmt.Errorf("unsupported review claim kind %v", claim)
	}
	return value, nil
}

// Replay evaluates the candidate's typed claim and confidence threshold over a
// finding corpus. Expected labels come from typed outcomes/adjudications only.
func Replay(candidate *roomv1.PolicyCandidate, findings []*roomv1.ReviewFinding) (*roomv1.PolicyReplayRun, error) {
	if err := validateCandidate(candidate, true); err != nil {
		return nil, err
	}
	for i, finding := range findings {
		if err := validateFinding(finding); err != nil {
			return nil, fmt.Errorf("finding %d: %w", i, err)
		}
	}
	id, err := newID("replay")
	if err != nil {
		return nil, err
	}
	now := timestamppb.Now()
	cases := classify(candidate, findings)
	candidateDigest, err := CandidateDigest(candidate)
	if err != nil {
		return nil, err
	}
	return &roomv1.PolicyReplayRun{
		Id:                    id,
		PolicyCandidateId:     candidate.GetId(),
		Cases:                 cases,
		Metrics:               metricsFromCases(cases),
		StartedAt:             now,
		CompletedAt:           now,
		PolicyCandidateSha256: candidateDigest,
	}, nil
}

// CandidateDigest binds replay evidence to the exact candidate revision that
// produced it, preventing stale evidence from approving a later policy.
func CandidateDigest(candidate *roomv1.PolicyCandidate) ([]byte, error) {
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(candidate)
	if err != nil {
		return nil, fmt.Errorf("marshal policy candidate: %w", err)
	}
	digest := sha256.Sum256(payload)
	return digest[:], nil
}

// Tune selects a confidence threshold from observed replay confidences. False
// positives carry a fourfold penalty. If no threshold reaches the conservative
// precision and recall floors, Tune recommends rollback and marks the returned
// clone rolled back.
func Tune(candidate *roomv1.PolicyCandidate, replays []*roomv1.PolicyReplayRun, actorID string) (*roomv1.PolicyCandidate, *roomv1.TuningDecision, error) {
	if err := validateCandidate(candidate, false); err != nil {
		return nil, nil, err
	}
	if actorID == "" {
		return nil, nil, errors.New("actor id is required")
	}
	if len(replays) == 0 {
		return nil, nil, errors.New("at least one replay is required")
	}

	latestCases := make(map[string]timedCase)
	replayIDs := make([]string, 0, len(replays))
	seenReplayIDs := make(map[string]struct{}, len(replays))
	for replayIndex, replay := range replays {
		if replay == nil || replay.GetId() == "" {
			return nil, nil, fmt.Errorf("replay %d: id is required", replayIndex)
		}
		if replay.GetPolicyCandidateId() != candidate.GetId() {
			return nil, nil, fmt.Errorf("replay %q belongs to candidate %q", replay.GetId(), replay.GetPolicyCandidateId())
		}
		if err := validateTimestamp(replay.GetCompletedAt()); err != nil {
			return nil, nil, fmt.Errorf("replay %q completed_at: %w", replay.GetId(), err)
		}
		if _, ok := seenReplayIDs[replay.GetId()]; !ok {
			seenReplayIDs[replay.GetId()] = struct{}{}
			replayIDs = append(replayIDs, replay.GetId())
		}
		completed := timestampTime(replay.GetCompletedAt())
		for caseIndex, replayCase := range replay.GetCases() {
			if replayCase == nil || replayCase.GetFindingId() == "" {
				return nil, nil, fmt.Errorf("replay %q case %d: finding id is required", replay.GetId(), caseIndex)
			}
			if replayCase.GetConfidenceBasisPoints() > maxBasisPoints {
				return nil, nil, fmt.Errorf("replay %q case %q: confidence exceeds 10000", replay.GetId(), replayCase.GetFindingId())
			}
			current, exists := latestCases[replayCase.GetFindingId()]
			if !exists || !completed.Before(current.completed) {
				latestCases[replayCase.GetFindingId()] = timedCase{value: replayCase, completed: completed}
			}
		}
	}
	if len(latestCases) == 0 {
		return nil, nil, errors.New("replays contain no cases")
	}
	sort.Strings(replayIDs)

	cases := make([]*roomv1.ReplayCaseResult, 0, len(latestCases))
	thresholdSet := map[uint32]struct{}{candidate.GetMinimumConfidenceBasisPoints(): {}}
	for _, replayCase := range latestCases {
		cases = append(cases, replayCase.value)
		thresholdSet[replayCase.value.GetConfidenceBasisPoints()] = struct{}{}
	}
	thresholds := make([]uint32, 0, len(thresholdSet))
	for threshold := range thresholdSet {
		thresholds = append(thresholds, threshold)
	}
	sort.Slice(thresholds, func(i, j int) bool { return thresholds[i] < thresholds[j] })

	bestThreshold := thresholds[0]
	bestMetrics := metricsAtThreshold(cases, bestThreshold)
	for _, threshold := range thresholds[1:] {
		metrics := metricsAtThreshold(cases, threshold)
		if betterMetrics(metrics, threshold, bestMetrics, bestThreshold) {
			bestThreshold, bestMetrics = threshold, metrics
		}
	}

	updated := proto.Clone(candidate).(*roomv1.PolicyCandidate)
	now := timestamppb.Now()
	updated.UpdatedAt = now
	updated.Metrics = bestMetrics
	decisionID, err := newID("tuning")
	if err != nil {
		return nil, nil, err
	}
	decision := &roomv1.TuningDecision{
		Id:                            decisionID,
		PolicyCandidateId:             candidate.GetId(),
		PreviousConfidenceBasisPoints: candidate.GetMinimumConfidenceBasisPoints(),
		NewConfidenceBasisPoints:      candidate.GetMinimumConfidenceBasisPoints(),
		EvidenceReplayIds:             replayIDs,
		ActorId:                       actorID,
		OccurredAt:                    now,
	}
	if viable(bestMetrics) {
		updated.MinimumConfidenceBasisPoints = bestThreshold
		for _, trigger := range updated.GetProposedRule().GetTriggers() {
			trigger.MinimumConfidenceBasisPoints = bestThreshold
		}
		decision.Action = roomv1.TuningActionKind_TUNING_ACTION_KIND_ADJUST_CONFIDENCE
		decision.NewConfidenceBasisPoints = bestThreshold
	} else {
		updated.RolloutStage = roomv1.RolloutStage_ROLLOUT_STAGE_ROLLED_BACK
		decision.Action = roomv1.TuningActionKind_TUNING_ACTION_KIND_ROLLBACK
	}
	return updated, decision, nil
}

type timedCase struct {
	value     *roomv1.ReplayCaseResult
	completed time.Time
}

func validateFinding(finding *roomv1.ReviewFinding) error {
	if finding == nil {
		return errors.New("finding is required")
	}
	if finding.GetId() == "" {
		return errors.New("id is required")
	}
	if finding.GetSource() == nil || finding.GetSource().GetRepository() == "" {
		return errors.New("source repository is required")
	}
	if _, err := ArtifactKind(finding.GetClaimKind()); err != nil {
		return err
	}
	if finding.GetConfidenceBasisPoints() > maxBasisPoints {
		return errors.New("confidence exceeds 10000")
	}
	for i, outcome := range finding.GetOutcomes() {
		if outcome == nil || outcome.GetKind() == roomv1.ReviewOutcomeKind_REVIEW_OUTCOME_KIND_UNSPECIFIED {
			return fmt.Errorf("outcome %d: typed kind is required", i)
		}
		if outcome.GetWeightBasisPoints() < 0 || outcome.GetWeightBasisPoints() > int32(maxBasisPoints) {
			return fmt.Errorf("outcome %d: weight must be between 0 and 10000", i)
		}
	}
	for i, adjudication := range finding.GetAdjudications() {
		if adjudication == nil || adjudication.GetAgentId() == "" || adjudication.GetVerdict() == roomv1.AdjudicationVerdict_ADJUDICATION_VERDICT_UNSPECIFIED {
			return fmt.Errorf("adjudication %d: agent and typed verdict are required", i)
		}
		if adjudication.GetConfidenceBasisPoints() > maxBasisPoints {
			return fmt.Errorf("adjudication %d: confidence exceeds 10000", i)
		}
		if err := validateTimestamp(adjudication.GetOccurredAt()); err != nil {
			return fmt.Errorf("adjudication %d occurred_at: %w", i, err)
		}
	}
	return nil
}

func validateCandidate(candidate *roomv1.PolicyCandidate, requireClaim bool) error {
	if candidate == nil || candidate.GetId() == "" {
		return errors.New("candidate id is required")
	}
	if candidate.GetMinimumConfidenceBasisPoints() > maxBasisPoints {
		return errors.New("candidate confidence exceeds 10000")
	}
	if requireClaim {
		if _, err := ArtifactKind(candidate.GetClaimKind()); err != nil {
			return err
		}
	}
	return nil
}

func expectedMatch(finding *roomv1.ReviewFinding) bool {
	latest := make(map[string]*roomv1.ReviewAdjudication)
	for _, adjudication := range finding.GetAdjudications() {
		current, ok := latest[adjudication.GetAgentId()]
		if !ok || !timestampTime(adjudication.GetOccurredAt()).Before(timestampTime(current.GetOccurredAt())) {
			latest[adjudication.GetAgentId()] = adjudication
		}
	}
	hasGeneralizable := false
	for _, adjudication := range latest {
		switch adjudication.GetVerdict() {
		case roomv1.AdjudicationVerdict_ADJUDICATION_VERDICT_INVALID,
			roomv1.AdjudicationVerdict_ADJUDICATION_VERDICT_VALID_ONE_OFF:
			return false
		case roomv1.AdjudicationVerdict_ADJUDICATION_VERDICT_VALID_GENERALIZABLE:
			hasGeneralizable = true
		}
	}
	if hasGeneralizable {
		return true
	}

	hardPositive := false
	var score int64
	for _, outcome := range finding.GetOutcomes() {
		weight := int64(outcome.GetWeightBasisPoints())
		if weight == 0 {
			weight = int64(maxBasisPoints)
		}
		switch outcome.GetKind() {
		case roomv1.ReviewOutcomeKind_REVIEW_OUTCOME_KIND_FIX_COMMITTED,
			roomv1.ReviewOutcomeKind_REVIEW_OUTCOME_KIND_THREAD_RESOLVED:
			hardPositive = true
			score += weight
		case roomv1.ReviewOutcomeKind_REVIEW_OUTCOME_KIND_MERGED:
			score += weight / 2
		case roomv1.ReviewOutcomeKind_REVIEW_OUTCOME_KIND_POSITIVE_REACTION:
			score += weight / 4
		case roomv1.ReviewOutcomeKind_REVIEW_OUTCOME_KIND_REJECTED,
			roomv1.ReviewOutcomeKind_REVIEW_OUTCOME_KIND_REVERTED,
			roomv1.ReviewOutcomeKind_REVIEW_OUTCOME_KIND_REGRESSION:
			score -= weight
		case roomv1.ReviewOutcomeKind_REVIEW_OUTCOME_KIND_NEGATIVE_REACTION:
			score -= weight / 4
		}
	}
	return hardPositive && score > 0
}

func classify(candidate *roomv1.PolicyCandidate, findings []*roomv1.ReviewFinding) []*roomv1.ReplayCaseResult {
	cases := make([]*roomv1.ReplayCaseResult, 0, len(findings))
	for _, finding := range findings {
		sameClaim := finding.GetClaimKind() == candidate.GetClaimKind()
		cases = append(cases, &roomv1.ReplayCaseResult{
			FindingId:             finding.GetId(),
			ExpectedMatch:         sameClaim && expectedMatch(finding),
			ActualMatch:           sameClaim && finding.GetConfidenceBasisPoints() >= candidate.GetMinimumConfidenceBasisPoints(),
			ConfidenceBasisPoints: finding.GetConfidenceBasisPoints(),
		})
	}
	return cases
}

func metricsFromCases(cases []*roomv1.ReplayCaseResult) *roomv1.PolicyMetrics {
	metrics := &roomv1.PolicyMetrics{SupportCount: uint32(len(cases))}
	for _, replayCase := range cases {
		if replayCase.GetExpectedMatch() {
			metrics.AcceptedCount++
		} else {
			metrics.RejectedCount++
		}
		switch {
		case replayCase.GetExpectedMatch() && replayCase.GetActualMatch():
			metrics.TruePositiveCount++
		case !replayCase.GetExpectedMatch() && replayCase.GetActualMatch():
			metrics.FalsePositiveCount++
		case replayCase.GetExpectedMatch() && !replayCase.GetActualMatch():
			metrics.FalseNegativeCount++
		}
	}
	metrics.PrecisionBasisPoints = ratioBPS(metrics.TruePositiveCount, metrics.TruePositiveCount+metrics.FalsePositiveCount)
	metrics.RecallBasisPoints = ratioBPS(metrics.TruePositiveCount, metrics.TruePositiveCount+metrics.FalseNegativeCount)
	return metrics
}

func metricsAtThreshold(cases []*roomv1.ReplayCaseResult, threshold uint32) *roomv1.PolicyMetrics {
	reclassified := make([]*roomv1.ReplayCaseResult, 0, len(cases))
	for _, replayCase := range cases {
		reclassified = append(reclassified, &roomv1.ReplayCaseResult{
			FindingId:             replayCase.GetFindingId(),
			ExpectedMatch:         replayCase.GetExpectedMatch(),
			ActualMatch:           replayCase.GetConfidenceBasisPoints() >= threshold,
			ConfidenceBasisPoints: replayCase.GetConfidenceBasisPoints(),
		})
	}
	return metricsFromCases(reclassified)
}

func betterMetrics(candidate *roomv1.PolicyMetrics, candidateThreshold uint32, current *roomv1.PolicyMetrics, currentThreshold uint32) bool {
	candidateCost := falsePositivePenalty*uint64(candidate.GetFalsePositiveCount()) + uint64(candidate.GetFalseNegativeCount())
	currentCost := falsePositivePenalty*uint64(current.GetFalsePositiveCount()) + uint64(current.GetFalseNegativeCount())
	if candidateCost != currentCost {
		return candidateCost < currentCost
	}
	if candidate.GetTruePositiveCount() != current.GetTruePositiveCount() {
		return candidate.GetTruePositiveCount() > current.GetTruePositiveCount()
	}
	return candidateThreshold > currentThreshold
}

func viable(metrics *roomv1.PolicyMetrics) bool {
	return metrics.GetAcceptedCount() > 0 &&
		metrics.GetPrecisionBasisPoints() >= minimumPrecisionBPS &&
		metrics.GetRecallBasisPoints() >= minimumRecallBPS
}

func medianConfidence(findings []*roomv1.ReviewFinding) uint32 {
	values := make([]uint32, 0, len(findings))
	for _, finding := range findings {
		values = append(values, finding.GetConfidenceBasisPoints())
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	return values[len(values)/2]
}

func findingIDs(findings []*roomv1.ReviewFinding) []string {
	ids := make([]string, 0, len(findings))
	for _, finding := range findings {
		ids = append(ids, finding.GetId())
	}
	sort.Strings(ids)
	return ids
}

func aggregateStrings(findings []*roomv1.ReviewFinding, values func(*roomv1.ReviewFinding) []string) []string {
	set := make(map[string]struct{})
	for _, finding := range findings {
		for _, value := range values(finding) {
			if value != "" {
				set[value] = struct{}{}
			}
		}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func maximumSeverity(findings []*roomv1.ReviewFinding) roomv1.Severity {
	severity := roomv1.Severity_SEVERITY_UNSPECIFIED
	for _, finding := range findings {
		if finding.GetSeverity() > severity {
			severity = finding.GetSeverity()
		}
	}
	return severity
}

func ratioBPS(numerator, denominator uint32) uint32 {
	if denominator == 0 {
		return 0
	}
	return uint32((uint64(numerator)*uint64(maxBasisPoints) + uint64(denominator)/2) / uint64(denominator))
}

func validateTimestamp(value *timestamppb.Timestamp) error {
	if value == nil {
		return nil
	}
	return value.CheckValid()
}

func timestampTime(value *timestamppb.Timestamp) time.Time {
	if value == nil {
		return time.Time{}
	}
	return value.AsTime()
}

func newID(prefix string) (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate %s id: %w", prefix, err)
	}
	return prefix + "-" + hex.EncodeToString(value[:]), nil
}

func policyRevisionID(repository string, claim roomv1.ReviewClaimKind, findingIDs []string, threshold uint32, artifact roomv1.PolicyArtifactKind, severity roomv1.Severity, requiredEvidence, remediation []string) (string, error) {
	canonical := &roomv1.PolicyCandidate{
		ClaimKind:                    claim,
		ArtifactKind:                 artifact,
		SourceFindingIds:             append([]string(nil), findingIDs...),
		MinimumConfidenceBasisPoints: threshold,
		ProposedRule: &roomv1.Rule{
			Severity:         severity,
			Scope:            &roomv1.RuleScope{Repositories: []string{repository}},
			RequiredEvidence: append([]string(nil), requiredEvidence...),
			Remediation:      append([]string(nil), remediation...),
		},
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("marshal policy revision identity: %w", err)
	}
	digest := sha256.Sum256(payload)
	return "policy-" + hex.EncodeToString(digest[:16]), nil
}

func stableRuleID(repository string, claim roomv1.ReviewClaimKind) (string, error) {
	canonical := &roomv1.PolicyCandidate{
		ClaimKind: claim,
		ProposedRule: &roomv1.Rule{
			Scope: &roomv1.RuleScope{Repositories: []string{repository}},
		},
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("marshal policy rule identity: %w", err)
	}
	digest := sha256.Sum256(payload)
	return "learned-rule-" + hex.EncodeToString(digest[:16]), nil
}
