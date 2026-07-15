package review

import (
	"bytes"
	"encoding/hex"
	"errors"

	roomv1 "github.com/haasonsaas/room/gen/go/room/v1"
)

type Compiler struct {
	registry *Registry
}

func NewCompiler(registry *Registry) (*Compiler, error) {
	if registry == nil {
		return nil, errors.New("review verifier registry is required")
	}
	return &Compiler{registry: registry}, nil
}

func (c *Compiler) Compile(hypothesis *roomv1.ReviewHypothesis, receipt *roomv1.ReviewVerificationReceipt) (*roomv1.ReviewCompilationResult, error) {
	if hypothesis == nil {
		return compilation(roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_INVALID, roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_MALFORMED_CONTRACT), nil
	}
	if receipt == nil {
		return compilation(roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_INDETERMINATE, roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_VERIFIER_UNAVAILABLE), nil
	}

	canonicalHypothesis, err := normalizedHypothesis(hypothesis)
	if err != nil {
		return compilation(roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_INVALID, roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_MALFORMED_CONTRACT), nil
	}
	hypothesisDigest, err := HypothesisDigest(canonicalHypothesis)
	if err != nil {
		return nil, err
	}
	hypothesisID := hex.EncodeToString(hypothesisDigest)
	if canonicalHypothesis.GetId() != "" && canonicalHypothesis.GetId() != hypothesisID {
		return compilation(roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_INVALID, roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_HYPOTHESIS_DIGEST_MISMATCH), nil
	}

	trusted, reason := c.registry.Resolve(receipt.GetVerifier())
	if reason != roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_UNSPECIFIED {
		return compilation(roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_INVALID, reason), nil
	}
	if trusted.GetKind() != roomv1.ReviewVerifierKind_REVIEW_VERIFIER_KIND_DETERMINISTIC {
		return compilation(roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_INVALID, roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_NONDETERMINISTIC_VERIFIER), nil
	}
	if !coversClaim(trusted.GetCoveredClaims(), canonicalHypothesis.GetClaimKind()) {
		return compilation(roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_INDETERMINATE, roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_CLAIM_NOT_COVERED), nil
	}
	if !bytes.Equal(receipt.GetHypothesisSha256(), hypothesisDigest) {
		return compilation(roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_INVALID, roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_HYPOTHESIS_DIGEST_MISMATCH), nil
	}
	if !bytes.Equal(receipt.GetArtifactSha256(), canonicalHypothesis.GetArtifactSha256()) {
		return compilation(roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_INVALID, roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_ARTIFACT_DIGEST_MISMATCH), nil
	}
	if !bytes.Equal(receipt.GetImpactSliceSha256(), canonicalHypothesis.GetImpactSliceSha256()) {
		return compilation(roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_INVALID, roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_IMPACT_SLICE_DIGEST_MISMATCH), nil
	}
	executionDigest, err := ExecutionInputDigest(hypothesisDigest, canonicalHypothesis.GetArtifactSha256(), canonicalHypothesis.GetImpactSliceSha256(), trusted)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(receipt.GetExecutionInputSha256(), executionDigest) {
		return compilation(roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_INVALID, roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_EXECUTION_INPUT_DIGEST_MISMATCH), nil
	}
	canonicalAuthorityEvidence, err := canonicalEvidence(receipt.GetEvidence())
	if err != nil {
		return compilation(roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_INVALID, roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_EVIDENCE_INVALID), nil
	}
	if !validVerificationStatus(receipt.GetStatus()) || !validVerificationReason(receipt.GetReason()) {
		return compilation(roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_INVALID, roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_MALFORMED_CONTRACT), nil
	}
	if err := validateTimestamp(receipt.GetCompletedAt(), "verification completed_at"); err != nil {
		return compilation(roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_INVALID, roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_MALFORMED_CONTRACT), nil
	}
	canonicalReceipt, err := canonicalReceipt(receipt)
	if err != nil {
		return compilation(roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_INVALID, roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_MALFORMED_CONTRACT), nil
	}
	receiptDigest, err := ReceiptDigest(canonicalReceipt)
	if err != nil {
		return nil, err
	}
	receiptID := hex.EncodeToString(receiptDigest)
	if receipt.GetId() != "" && receipt.GetId() != receiptID {
		return compilation(roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_INVALID, roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_MALFORMED_CONTRACT), nil
	}

	switch receipt.GetStatus() {
	case roomv1.ReviewVerificationStatus_REVIEW_VERIFICATION_STATUS_VERIFIED:
		if receipt.GetReason() != roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_UNSPECIFIED {
			return compilation(roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_INVALID, roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_MALFORMED_CONTRACT), nil
		}
		if len(canonicalAuthorityEvidence) == 0 {
			return compilation(roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_INVALID, roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_EVIDENCE_INVALID), nil
		}
	case roomv1.ReviewVerificationStatus_REVIEW_VERIFICATION_STATUS_REJECTED:
		if receipt.GetReason() != roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_HYPOTHESIS_REJECTED {
			return compilation(roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_INVALID, roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_MALFORMED_CONTRACT), nil
		}
		return compilation(roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_REJECTED, receipt.GetReason()), nil
	case roomv1.ReviewVerificationStatus_REVIEW_VERIFICATION_STATUS_INDETERMINATE:
		if !operationalReason(receipt.GetReason()) {
			return compilation(roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_INVALID, roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_MALFORMED_CONTRACT), nil
		}
		return compilation(roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_INDETERMINATE, receipt.GetReason()), nil
	default:
		return compilation(roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_INVALID, roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_MALFORMED_CONTRACT), nil
	}

	evidenceSetDigest, err := EvidenceSetDigest(canonicalAuthorityEvidence)
	if err != nil {
		return nil, err
	}
	findingID, err := VerifiedFindingID(hypothesisDigest, trusted, evidenceSetDigest)
	if err != nil {
		return nil, err
	}
	canonicalHypothesis.Id = hypothesisID
	canonicalReceipt.Id = receiptID
	return &roomv1.ReviewCompilationResult{
		Status: roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_VERIFIED,
		Finding: &roomv1.VerifiedReviewFinding{
			Id:                findingID,
			Hypothesis:        canonicalHypothesis,
			Receipt:           canonicalReceipt,
			EvidenceSetSha256: evidenceSetDigest,
		},
	}, nil
}

func compilation(status roomv1.ReviewCompilationStatus, reason roomv1.ReviewVerificationReason) *roomv1.ReviewCompilationResult {
	return &roomv1.ReviewCompilationResult{Status: status, Reason: reason}
}

func coversClaim(values []roomv1.ReviewClaimKind, claim roomv1.ReviewClaimKind) bool {
	for _, value := range values {
		if value == claim {
			return true
		}
	}
	return false
}

func validVerificationStatus(value roomv1.ReviewVerificationStatus) bool {
	_, ok := roomv1.ReviewVerificationStatus_name[int32(value)]
	return ok && value != roomv1.ReviewVerificationStatus_REVIEW_VERIFICATION_STATUS_UNSPECIFIED
}

func validVerificationReason(value roomv1.ReviewVerificationReason) bool {
	_, ok := roomv1.ReviewVerificationReason_name[int32(value)]
	return ok
}

func operationalReason(value roomv1.ReviewVerificationReason) bool {
	switch value {
	case roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_VERIFIER_UNAVAILABLE,
		roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_VERIFIER_TIMEOUT,
		roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_CONFLICTING_RESULTS:
		return true
	default:
		return false
	}
}
