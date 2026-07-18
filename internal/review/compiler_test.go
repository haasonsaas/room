package review

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	roomv1 "github.com/haasonsaas/room/gen/go/room/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestHypothesisDigestCanonicalAndImmutable(t *testing.T) {
	hypothesis := canonicalTestHypothesis()
	original := proto.Clone(hypothesis).(*roomv1.ReviewHypothesis)
	first, err := HypothesisDigest(hypothesis)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != sha256.Size {
		t.Fatalf("digest length = %d", len(first))
	}
	if !proto.Equal(hypothesis, original) {
		t.Fatal("HypothesisDigest mutated its input")
	}

	reordered := proto.Clone(hypothesis).(*roomv1.ReviewHypothesis)
	slices.Reverse(reordered.AffectedPaths)
	slices.Reverse(reordered.AffectedLocations)
	second, err := HypothesisDigest(reordered)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("set ordering changed hypothesis digest")
	}

	presentation := proto.Clone(hypothesis).(*roomv1.ReviewHypothesis)
	presentation.Id = "caller-copy"
	presentation.Invariant = "rewritten explanation"
	presentation.Impact = "rewritten impact"
	presentation.Remediation = []string{"different remediation"}
	presentation.Severity = roomv1.Severity_SEVERITY_LOW
	presentation.ConfidenceBasisPoints = 1
	presentation.CreatedAt = timestamppb.New(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	presentationDigest, err := HypothesisDigest(presentation)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, presentationDigest) {
		t.Fatal("presentation metadata changed hypothesis digest")
	}

	ordered := proto.Clone(hypothesis).(*roomv1.ReviewHypothesis)
	slices.Reverse(ordered.Preconditions)
	orderedDigest, err := HypothesisDigest(ordered)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, orderedDigest) {
		t.Fatal("precondition order did not change hypothesis digest")
	}
	ordered = proto.Clone(hypothesis).(*roomv1.ReviewHypothesis)
	slices.Reverse(ordered.CausalPath)
	orderedDigest, err = HypothesisDigest(ordered)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, orderedDigest) {
		t.Fatal("causal-path order did not change hypothesis digest")
	}
}

func TestHypothesisDigestRejectsInvalidAuthorityFields(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*roomv1.ReviewHypothesis)
	}{
		{name: "nil source", mutate: func(h *roomv1.ReviewHypothesis) { h.Source = nil }},
		{name: "blank repository", mutate: func(h *roomv1.ReviewHypothesis) { h.Source.Repository = " " }},
		{name: "blank head", mutate: func(h *roomv1.ReviewHypothesis) { h.Source.HeadSha = "" }},
		{name: "unknown claim", mutate: func(h *roomv1.ReviewHypothesis) { h.ClaimKind = roomv1.ReviewClaimKind(99) }},
		{name: "short artifact", mutate: func(h *roomv1.ReviewHypothesis) { h.ArtifactSha256 = []byte{1} }},
		{name: "short impact slice", mutate: func(h *roomv1.ReviewHypothesis) { h.ImpactSliceSha256 = []byte{1} }},
		{name: "absolute path", mutate: func(h *roomv1.ReviewHypothesis) { h.AffectedPaths = []string{"/etc/passwd"} }},
		{name: "traversal path", mutate: func(h *roomv1.ReviewHypothesis) { h.AffectedPaths = []string{"../secret"} }},
		{name: "internal traversal path", mutate: func(h *roomv1.ReviewHypothesis) { h.AffectedPaths = []string{"api/../secret"} }},
		{name: "invalid location", mutate: func(h *roomv1.ReviewHypothesis) { h.AffectedLocations[0].EndLine = 1 }},
		{name: "missing producer", mutate: func(h *roomv1.ReviewHypothesis) { h.Producer = nil }},
		{name: "short producer config", mutate: func(h *roomv1.ReviewHypothesis) { h.Producer.ConfigSha256 = []byte{1} }},
		{name: "short producer tool", mutate: func(h *roomv1.ReviewHypothesis) { h.Producer.ToolSha256 = []byte{1} }},
		{name: "unknown severity", mutate: func(h *roomv1.ReviewHypothesis) { h.Severity = roomv1.Severity(99) }},
		{name: "confidence overflow", mutate: func(h *roomv1.ReviewHypothesis) { h.ConfidenceBasisPoints = 10001 }},
		{name: "missing timestamp", mutate: func(h *roomv1.ReviewHypothesis) { h.CreatedAt = nil }},
		{name: "invalid timestamp", mutate: func(h *roomv1.ReviewHypothesis) { h.CreatedAt = &timestamppb.Timestamp{Seconds: 253402300800} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := canonicalTestHypothesis()
			test.mutate(value)
			if _, err := HypothesisDigest(value); err == nil {
				t.Fatal("HypothesisDigest() error = nil, want error")
			}
		})
	}
}

func TestEvidenceSetDigestCanonicalAndValidated(t *testing.T) {
	evidence := canonicalTestEvidence()
	original := cloneEvidence(evidence)
	first, err := EvidenceSetDigest(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != sha256.Size || !equalEvidence(evidence, original) {
		t.Fatal("EvidenceSetDigest returned invalid digest or mutated input")
	}

	reordered := cloneEvidence(evidence)
	slices.Reverse(reordered)
	reordered = append(reordered, proto.Clone(reordered[0]).(*roomv1.ReviewEvidenceRef))
	second, err := EvidenceSetDigest(reordered)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("ordering or exact duplicate changed evidence digest")
	}

	presentation := cloneEvidence(evidence)
	presentation[0].Description = "rewritten explanation"
	second, err = EvidenceSetDigest(presentation)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("presentation description changed evidence digest")
	}

	for _, test := range []struct {
		name   string
		values func() []*roomv1.ReviewEvidenceRef
	}{
		{name: "nil", values: func() []*roomv1.ReviewEvidenceRef { return []*roomv1.ReviewEvidenceRef{nil} }},
		{name: "missing id", values: func() []*roomv1.ReviewEvidenceRef { v := canonicalTestEvidence(); v[0].Id = ""; return v }},
		{name: "unknown kind", values: func() []*roomv1.ReviewEvidenceRef {
			v := canonicalTestEvidence()
			v[0].Kind = roomv1.ReviewEvidenceKind(99)
			return v
		}},
		{name: "short digest", values: func() []*roomv1.ReviewEvidenceRef {
			v := canonicalTestEvidence()
			v[0].ContentSha256 = []byte{1}
			return v
		}},
		{name: "source without location", values: func() []*roomv1.ReviewEvidenceRef { v := canonicalTestEvidence(); v[0].Location = nil; return v }},
		{name: "command without command", values: func() []*roomv1.ReviewEvidenceRef { v := canonicalTestEvidence(); v[1].Command = ""; return v }},
		{name: "location traversal", values: func() []*roomv1.ReviewEvidenceRef {
			v := canonicalTestEvidence()
			v[0].Location.FilePath = "../secret"
			return v
		}},
		{name: "conflicting duplicate", values: func() []*roomv1.ReviewEvidenceRef {
			v := canonicalTestEvidence()
			conflict := proto.Clone(v[0]).(*roomv1.ReviewEvidenceRef)
			conflict.ContentSha256 = digestByte(0x99)
			return append(v, conflict)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := EvidenceSetDigest(test.values()); err == nil {
				t.Fatal("EvidenceSetDigest() error = nil, want error")
			}
		})
	}
}

func TestExecutionAndReceiptDigests(t *testing.T) {
	hypothesis := canonicalTestHypothesis()
	hypothesisDigest, err := HypothesisDigest(hypothesis)
	if err != nil {
		t.Fatal(err)
	}
	verifierIdentity := canonicalTestVerifier()
	execution, err := ExecutionInputDigest(hypothesisDigest, hypothesis.GetArtifactSha256(), hypothesis.GetImpactSliceSha256(), verifierIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if len(execution) != sha256.Size {
		t.Fatalf("execution digest length = %d", len(execution))
	}
	reorderedVerifier := proto.Clone(verifierIdentity).(*roomv1.ReviewVerifierIdentity)
	slices.Reverse(reorderedVerifier.CoveredClaims)
	reorderedExecution, err := ExecutionInputDigest(hypothesisDigest, hypothesis.GetArtifactSha256(), hypothesis.GetImpactSliceSha256(), reorderedVerifier)
	if err != nil || !bytes.Equal(execution, reorderedExecution) {
		t.Fatalf("reordered execution digest = %x, %v", reorderedExecution, err)
	}
	if _, err := ExecutionInputDigest([]byte{1}, hypothesis.GetArtifactSha256(), hypothesis.GetImpactSliceSha256(), verifierIdentity); err == nil {
		t.Fatal("short hypothesis digest accepted")
	}

	receipt := canonicalTestReceipt(hypothesisDigest, execution)
	original := proto.Clone(receipt).(*roomv1.ReviewVerificationReceipt)
	receiptDigest, err := ReceiptDigest(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if len(receiptDigest) != sha256.Size || !proto.Equal(receipt, original) {
		t.Fatal("ReceiptDigest returned invalid digest or mutated input")
	}
	receipt.Id = "caller-id"
	slices.Reverse(receipt.Evidence)
	reorderedReceiptDigest, err := ReceiptDigest(receipt)
	if err != nil || !bytes.Equal(receiptDigest, reorderedReceiptDigest) {
		t.Fatalf("receipt canonicalization changed digest: %x, %v", reorderedReceiptDigest, err)
	}

	evidenceDigest, err := EvidenceSetDigest(receipt.GetEvidence())
	if err != nil {
		t.Fatal(err)
	}
	findingID, err := VerifiedFindingID(hypothesisDigest, verifierIdentity, evidenceDigest)
	if err != nil {
		t.Fatal(err)
	}
	if len(findingID) != sha256.Size*2 {
		t.Fatalf("finding id length = %d", len(findingID))
	}
	if _, err := hex.DecodeString(findingID); err != nil {
		t.Fatalf("finding id is not lowercase hex: %q", findingID)
	}
}

func TestGoldenAuthorizationBoundary(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "authorization_boundary.json"))
	if err != nil {
		t.Fatal(err)
	}
	var golden struct {
		Hypothesis string `json:"hypothesis_sha256"`
		Evidence   string `json:"evidence_set_sha256"`
		Execution  string `json:"execution_input_sha256"`
		Receipt    string `json:"receipt_sha256"`
		Finding    string `json:"finding_id"`
	}
	if err := json.Unmarshal(data, &golden); err != nil {
		t.Fatal(err)
	}
	hypothesis := canonicalTestHypothesis()
	hypothesisDigest, err := HypothesisDigest(hypothesis)
	if err != nil {
		t.Fatal(err)
	}
	verifierIdentity := canonicalTestVerifier()
	executionDigest, err := ExecutionInputDigest(hypothesisDigest, hypothesis.GetArtifactSha256(), hypothesis.GetImpactSliceSha256(), verifierIdentity)
	if err != nil {
		t.Fatal(err)
	}
	receipt := canonicalTestReceipt(hypothesisDigest, executionDigest)
	evidenceDigest, err := EvidenceSetDigest(receipt.GetEvidence())
	if err != nil {
		t.Fatal(err)
	}
	receiptDigest, err := ReceiptDigest(receipt)
	if err != nil {
		t.Fatal(err)
	}
	findingID, err := VerifiedFindingID(hypothesisDigest, verifierIdentity, evidenceDigest)
	if err != nil {
		t.Fatal(err)
	}
	actual := []string{hex.EncodeToString(hypothesisDigest), hex.EncodeToString(evidenceDigest), hex.EncodeToString(executionDigest), hex.EncodeToString(receiptDigest), findingID}
	expected := []string{golden.Hypothesis, golden.Evidence, golden.Execution, golden.Receipt, golden.Finding}
	if !slices.Equal(actual, expected) {
		t.Fatalf("golden digests = %v, want %v", actual, expected)
	}
}

func TestCompilerVerifiedFinding(t *testing.T) {
	hypothesis, receipt, compiler := compilerFixture(t)
	originalHypothesis := proto.Clone(hypothesis).(*roomv1.ReviewHypothesis)
	originalReceipt := proto.Clone(receipt).(*roomv1.ReviewVerificationReceipt)
	expectedEvidenceDigest, err := EvidenceSetDigest(receipt.GetEvidence())
	if err != nil {
		t.Fatal(err)
	}

	result, err := compiler.Compile(hypothesis, receipt)
	if err != nil {
		t.Fatal(err)
	}
	if result.GetStatus() != roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_VERIFIED {
		t.Fatalf("status = %s", result.GetStatus())
	}
	if result.GetReason() != roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_UNSPECIFIED {
		t.Fatalf("reason = %s", result.GetReason())
	}
	finding := result.GetFinding()
	if finding == nil || len(finding.GetId()) != sha256.Size*2 {
		t.Fatalf("finding = %+v", finding)
	}
	if !bytes.Equal(finding.GetEvidenceSetSha256(), expectedEvidenceDigest) {
		t.Fatal("evidence digest mismatch")
	}
	if finding.GetHypothesis().GetInvariant() != hypothesis.GetInvariant() || finding.GetReceipt().GetEvidence()[0].GetDescription() == "" {
		t.Fatal("verified finding discarded presentation provenance")
	}
	if finding.GetHypothesis().GetId() == "" || finding.GetReceipt().GetId() == "" {
		t.Fatal("canonical hypothesis or receipt id is missing")
	}
	if !proto.Equal(hypothesis, originalHypothesis) || !proto.Equal(receipt, originalReceipt) {
		t.Fatal("Compile mutated its inputs")
	}

	presentation := proto.Clone(hypothesis).(*roomv1.ReviewHypothesis)
	presentation.Invariant = "same structured claim, clearer explanation"
	presentation.Impact = "clearer impact"
	presentation.Remediation = []string{"clearer remediation"}
	presentation.ConfidenceBasisPoints = 8000
	presentationResult, err := compiler.Compile(presentation, receipt)
	if err != nil || presentationResult.GetStatus() != roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_VERIFIED {
		t.Fatalf("presentation-only compile = %+v, %v", presentationResult, err)
	}
	if presentationResult.GetFinding().GetId() != finding.GetId() {
		t.Fatal("presentation-only rewrite changed finding identity")
	}

	identified := proto.Clone(hypothesis).(*roomv1.ReviewHypothesis)
	identified.Id = finding.GetHypothesis().GetId()
	identifiedReceipt := proto.Clone(receipt).(*roomv1.ReviewVerificationReceipt)
	identifiedReceipt.Id = finding.GetReceipt().GetId()
	identifiedResult, err := compiler.Compile(identified, identifiedReceipt)
	if err != nil || identifiedResult.GetStatus() != roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_VERIFIED {
		t.Fatalf("canonical caller ids compile = %+v, %v", identifiedResult, err)
	}
}

func TestCompilerRejectsBrokenBindings(t *testing.T) {
	for _, test := range []struct {
		name   string
		setup  func(*testing.T, *roomv1.ReviewHypothesis, *roomv1.ReviewVerificationReceipt) *Compiler
		mutate func(*roomv1.ReviewHypothesis, *roomv1.ReviewVerificationReceipt)
		status roomv1.ReviewCompilationStatus
		reason roomv1.ReviewVerificationReason
	}{
		{name: "unknown verifier", mutate: func(_ *roomv1.ReviewHypothesis, r *roomv1.ReviewVerificationReceipt) {
			r.Verifier.Analyzer.Id = "unknown"
		}, status: roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_INVALID, reason: roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_UNTRUSTED_VERIFIER},
		{name: "version mismatch", mutate: func(_ *roomv1.ReviewHypothesis, r *roomv1.ReviewVerificationReceipt) {
			r.Verifier.Analyzer.Version = "2"
		}, status: roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_INVALID, reason: roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_VERIFIER_IDENTITY_MISMATCH},
		{name: "config mismatch", mutate: func(_ *roomv1.ReviewHypothesis, r *roomv1.ReviewVerificationReceipt) {
			r.Verifier.Analyzer.ConfigSha256 = digestByte(0x88)
		}, status: roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_INVALID, reason: roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_VERIFIER_IDENTITY_MISMATCH},
		{name: "kind mismatch", mutate: func(_ *roomv1.ReviewHypothesis, r *roomv1.ReviewVerificationReceipt) {
			r.Verifier.Kind = roomv1.ReviewVerifierKind_REVIEW_VERIFIER_KIND_SEMANTIC_SCOUT
		}, status: roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_INVALID, reason: roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_VERIFIER_IDENTITY_MISMATCH},
		{name: "coverage mismatch", mutate: func(_ *roomv1.ReviewHypothesis, r *roomv1.ReviewVerificationReceipt) {
			r.Verifier.CoveredClaims = r.Verifier.CoveredClaims[:1]
		}, status: roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_INVALID, reason: roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_VERIFIER_IDENTITY_MISMATCH},
		{name: "trusted semantic scout", setup: semanticCompiler, status: roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_INVALID, reason: roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_NONDETERMINISTIC_VERIFIER},
		{name: "claim not covered", setup: uncoveredCompiler, status: roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_INDETERMINATE, reason: roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_CLAIM_NOT_COVERED},
		{name: "hypothesis digest", mutate: func(_ *roomv1.ReviewHypothesis, r *roomv1.ReviewVerificationReceipt) {
			r.HypothesisSha256 = digestByte(0x77)
		}, status: roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_INVALID, reason: roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_HYPOTHESIS_DIGEST_MISMATCH},
		{name: "caller hypothesis id", mutate: func(h *roomv1.ReviewHypothesis, _ *roomv1.ReviewVerificationReceipt) { h.Id = "wrong" }, status: roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_INVALID, reason: roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_HYPOTHESIS_DIGEST_MISMATCH},
		{name: "artifact digest", mutate: func(_ *roomv1.ReviewHypothesis, r *roomv1.ReviewVerificationReceipt) {
			r.ArtifactSha256 = digestByte(0x77)
		}, status: roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_INVALID, reason: roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_ARTIFACT_DIGEST_MISMATCH},
		{name: "impact slice digest", mutate: func(_ *roomv1.ReviewHypothesis, r *roomv1.ReviewVerificationReceipt) {
			r.ImpactSliceSha256 = digestByte(0x77)
		}, status: roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_INVALID, reason: roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_IMPACT_SLICE_DIGEST_MISMATCH},
		{name: "execution input digest", mutate: func(_ *roomv1.ReviewHypothesis, r *roomv1.ReviewVerificationReceipt) {
			r.ExecutionInputSha256 = digestByte(0x77)
		}, status: roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_INVALID, reason: roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_EXECUTION_INPUT_DIGEST_MISMATCH},
		{name: "execution input missing", mutate: func(_ *roomv1.ReviewHypothesis, r *roomv1.ReviewVerificationReceipt) { r.ExecutionInputSha256 = nil }, status: roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_INVALID, reason: roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_EXECUTION_INPUT_DIGEST_MISMATCH},
		{name: "evidence invalid", mutate: func(_ *roomv1.ReviewHypothesis, r *roomv1.ReviewVerificationReceipt) {
			r.Evidence[0].ContentSha256 = nil
		}, status: roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_INVALID, reason: roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_EVIDENCE_INVALID},
	} {
		t.Run(test.name, func(t *testing.T) {
			hypothesis, receipt, compiler := compilerFixture(t)
			if test.setup != nil {
				compiler = test.setup(t, hypothesis, receipt)
			}
			if test.mutate != nil {
				test.mutate(hypothesis, receipt)
			}
			result, err := compiler.Compile(hypothesis, receipt)
			if err != nil {
				t.Fatal(err)
			}
			if result.GetStatus() != test.status || result.GetReason() != test.reason || result.GetFinding() != nil {
				t.Fatalf("Compile() = %+v, want status=%s reason=%s no finding", result, test.status, test.reason)
			}
		})
	}
}

func TestCompilerStatusContracts(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*roomv1.ReviewVerificationReceipt)
		status roomv1.ReviewCompilationStatus
		reason roomv1.ReviewVerificationReason
	}{
		{name: "verified without evidence", mutate: func(r *roomv1.ReviewVerificationReceipt) { r.Evidence = nil }, status: roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_INVALID, reason: roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_EVIDENCE_INVALID},
		{name: "verified with reason", mutate: func(r *roomv1.ReviewVerificationReceipt) {
			r.Reason = roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_VERIFIER_TIMEOUT
		}, status: roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_INVALID, reason: roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_MALFORMED_CONTRACT},
		{name: "rejected", mutate: func(r *roomv1.ReviewVerificationReceipt) {
			r.Status = roomv1.ReviewVerificationStatus_REVIEW_VERIFICATION_STATUS_REJECTED
			r.Reason = roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_HYPOTHESIS_REJECTED
			r.Evidence = nil
		}, status: roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_REJECTED, reason: roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_HYPOTHESIS_REJECTED},
		{name: "rejected wrong reason", mutate: func(r *roomv1.ReviewVerificationReceipt) {
			r.Status = roomv1.ReviewVerificationStatus_REVIEW_VERIFICATION_STATUS_REJECTED
			r.Reason = roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_VERIFIER_TIMEOUT
		}, status: roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_INVALID, reason: roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_MALFORMED_CONTRACT},
		{name: "unavailable", mutate: func(r *roomv1.ReviewVerificationReceipt) {
			r.Status = roomv1.ReviewVerificationStatus_REVIEW_VERIFICATION_STATUS_INDETERMINATE
			r.Reason = roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_VERIFIER_UNAVAILABLE
			r.Evidence = nil
		}, status: roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_INDETERMINATE, reason: roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_VERIFIER_UNAVAILABLE},
		{name: "timeout", mutate: func(r *roomv1.ReviewVerificationReceipt) {
			r.Status = roomv1.ReviewVerificationStatus_REVIEW_VERIFICATION_STATUS_INDETERMINATE
			r.Reason = roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_VERIFIER_TIMEOUT
			r.Evidence = nil
		}, status: roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_INDETERMINATE, reason: roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_VERIFIER_TIMEOUT},
		{name: "conflict", mutate: func(r *roomv1.ReviewVerificationReceipt) {
			r.Status = roomv1.ReviewVerificationStatus_REVIEW_VERIFICATION_STATUS_INDETERMINATE
			r.Reason = roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_CONFLICTING_RESULTS
			r.Evidence = nil
		}, status: roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_INDETERMINATE, reason: roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_CONFLICTING_RESULTS},
		{name: "indeterminate wrong reason", mutate: func(r *roomv1.ReviewVerificationReceipt) {
			r.Status = roomv1.ReviewVerificationStatus_REVIEW_VERIFICATION_STATUS_INDETERMINATE
			r.Reason = roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_HYPOTHESIS_REJECTED
		}, status: roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_INVALID, reason: roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_MALFORMED_CONTRACT},
		{name: "unknown status", mutate: func(r *roomv1.ReviewVerificationReceipt) { r.Status = roomv1.ReviewVerificationStatus(99) }, status: roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_INVALID, reason: roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_MALFORMED_CONTRACT},
		{name: "unknown reason", mutate: func(r *roomv1.ReviewVerificationReceipt) { r.Reason = roomv1.ReviewVerificationReason(99) }, status: roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_INVALID, reason: roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_MALFORMED_CONTRACT},
		{name: "caller receipt id mismatch", mutate: func(r *roomv1.ReviewVerificationReceipt) { r.Id = "wrong" }, status: roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_INVALID, reason: roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_MALFORMED_CONTRACT},
	} {
		t.Run(test.name, func(t *testing.T) {
			hypothesis, receipt, compiler := compilerFixture(t)
			test.mutate(receipt)
			result, err := compiler.Compile(hypothesis, receipt)
			if err != nil {
				t.Fatal(err)
			}
			if result.GetStatus() != test.status || result.GetReason() != test.reason || result.GetFinding() != nil {
				t.Fatalf("Compile() = %+v, want status=%s reason=%s no finding", result, test.status, test.reason)
			}
		})
	}
}

func TestCompilerMissingInputs(t *testing.T) {
	_, receipt, compiler := compilerFixture(t)
	result, err := compiler.Compile(nil, receipt)
	if err != nil || result.GetStatus() != roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_INVALID || result.GetReason() != roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_MALFORMED_CONTRACT {
		t.Fatalf("nil hypothesis result = %+v, err = %v", result, err)
	}
	hypothesis, _, compiler := compilerFixture(t)
	result, err = compiler.Compile(hypothesis, nil)
	if err != nil || result.GetStatus() != roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_INDETERMINATE || result.GetReason() != roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_VERIFIER_UNAVAILABLE {
		t.Fatalf("nil receipt result = %+v, err = %v", result, err)
	}
	if _, err := NewCompiler(nil); err == nil {
		t.Fatal("NewCompiler(nil) error = nil")
	}
}

func compilerFixture(t *testing.T) (*roomv1.ReviewHypothesis, *roomv1.ReviewVerificationReceipt, *Compiler) {
	t.Helper()
	hypothesis := canonicalTestHypothesis()
	hypothesisDigest, err := HypothesisDigest(hypothesis)
	if err != nil {
		t.Fatal(err)
	}
	verifierIdentity := canonicalTestVerifier()
	executionDigest, err := ExecutionInputDigest(hypothesisDigest, hypothesis.GetArtifactSha256(), hypothesis.GetImpactSliceSha256(), verifierIdentity)
	if err != nil {
		t.Fatal(err)
	}
	receipt := canonicalTestReceipt(hypothesisDigest, executionDigest)
	registry, err := NewRegistry(verifierIdentity)
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := NewCompiler(registry)
	if err != nil {
		t.Fatal(err)
	}
	return hypothesis, receipt, compiler
}

func semanticCompiler(t *testing.T, hypothesis *roomv1.ReviewHypothesis, receipt *roomv1.ReviewVerificationReceipt) *Compiler {
	t.Helper()
	semantic := proto.Clone(receipt.GetVerifier()).(*roomv1.ReviewVerifierIdentity)
	semantic.Kind = roomv1.ReviewVerifierKind_REVIEW_VERIFIER_KIND_SEMANTIC_SCOUT
	receipt.Verifier = semantic
	hypothesisDigest, err := HypothesisDigest(hypothesis)
	if err != nil {
		t.Fatal(err)
	}
	receipt.ExecutionInputSha256, err = ExecutionInputDigest(hypothesisDigest, hypothesis.GetArtifactSha256(), hypothesis.GetImpactSliceSha256(), semantic)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry(semantic)
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := NewCompiler(registry)
	if err != nil {
		t.Fatal(err)
	}
	return compiler
}

func uncoveredCompiler(t *testing.T, hypothesis *roomv1.ReviewHypothesis, receipt *roomv1.ReviewVerificationReceipt) *Compiler {
	t.Helper()
	uncovered := verifier("evalops.authorization-verifier", roomv1.ReviewVerifierKind_REVIEW_VERIFIER_KIND_DETERMINISTIC, roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_SECURITY_BOUNDARY)
	receipt.Verifier = proto.Clone(uncovered).(*roomv1.ReviewVerifierIdentity)
	hypothesisDigest, err := HypothesisDigest(hypothesis)
	if err != nil {
		t.Fatal(err)
	}
	receipt.ExecutionInputSha256, err = ExecutionInputDigest(hypothesisDigest, hypothesis.GetArtifactSha256(), hypothesis.GetImpactSliceSha256(), uncovered)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry(uncovered)
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := NewCompiler(registry)
	if err != nil {
		t.Fatal(err)
	}
	return compiler
}

func canonicalTestHypothesis() *roomv1.ReviewHypothesis {
	return &roomv1.ReviewHypothesis{
		Source:                &roomv1.ReviewSource{Repository: "evalops/platform", PullRequestNumber: 4597, HeadSha: "0123456789abcdef", ReviewCommentId: "comment-1", ReviewerId: "scout", Provider: "fixture"},
		ClaimKind:             roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_AUTHORIZATION_BOUNDARY,
		ArtifactSha256:        digestByte(0x21),
		ImpactSliceSha256:     digestByte(0x31),
		AffectedPaths:         []string{"internal/tenant/store.go", "api/handler.go"},
		AffectedLocations:     []*roomv1.SourceLocation{{FilePath: "internal/tenant/store.go", StartLine: 40, EndLine: 44}, {FilePath: "api/handler.go", StartLine: 12, EndLine: 18}},
		Invariant:             "tenant scope comes from authenticated context",
		Preconditions:         []string{"request is unauthenticated", "caller supplies tenant_id"},
		CausalPath:            []string{"handler reads tenant_id", "store queries tenant rows"},
		Impact:                "cross-tenant data access",
		Remediation:           []string{"bind tenant scope to the authenticated principal"},
		Producer:              &roomv1.AnalyzerIdentity{Id: "evalops.review-scout", Version: "1", ConfigSha256: digestByte(0x41)},
		Severity:              roomv1.Severity_SEVERITY_CRITICAL,
		ConfidenceBasisPoints: 9300,
		CreatedAt:             timestamppb.New(time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)),
	}
}

func canonicalTestVerifier() *roomv1.ReviewVerifierIdentity {
	return verifier(
		"evalops.authorization-verifier",
		roomv1.ReviewVerifierKind_REVIEW_VERIFIER_KIND_DETERMINISTIC,
		roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_SECURITY_BOUNDARY,
		roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_AUTHORIZATION_BOUNDARY,
	)
}

func canonicalTestEvidence() []*roomv1.ReviewEvidenceRef {
	return []*roomv1.ReviewEvidenceRef{
		{Id: "source-handler", Kind: roomv1.ReviewEvidenceKind_REVIEW_EVIDENCE_KIND_SOURCE_LOCATION, ContentSha256: digestByte(0x51), Location: &roomv1.SourceLocation{FilePath: "api/handler.go", StartLine: 12, EndLine: 18}, Description: "caller-supplied tenant scope"},
		{Id: "negative-test", Kind: roomv1.ReviewEvidenceKind_REVIEW_EVIDENCE_KIND_COMMAND_RESULT, ContentSha256: digestByte(0x61), Command: "go test ./internal/tenant -run TestRejectsCallerTenant -count=1", Description: "negative authorization test"},
	}
}

func canonicalTestReceipt(hypothesisDigest, executionDigest []byte) *roomv1.ReviewVerificationReceipt {
	hypothesis := canonicalTestHypothesis()
	return &roomv1.ReviewVerificationReceipt{
		Verifier:             canonicalTestVerifier(),
		HypothesisSha256:     bytes.Clone(hypothesisDigest),
		ArtifactSha256:       bytes.Clone(hypothesis.GetArtifactSha256()),
		ImpactSliceSha256:    bytes.Clone(hypothesis.GetImpactSliceSha256()),
		ExecutionInputSha256: bytes.Clone(executionDigest),
		Status:               roomv1.ReviewVerificationStatus_REVIEW_VERIFICATION_STATUS_VERIFIED,
		Evidence:             canonicalTestEvidence(),
		CompletedAt:          timestamppb.New(time.Date(2026, 7, 14, 12, 1, 0, 0, time.UTC)),
	}
}

func digestByte(value byte) []byte { return bytes.Repeat([]byte{value}, sha256.Size) }

func cloneEvidence(values []*roomv1.ReviewEvidenceRef) []*roomv1.ReviewEvidenceRef {
	result := make([]*roomv1.ReviewEvidenceRef, len(values))
	for i, value := range values {
		result[i] = proto.Clone(value).(*roomv1.ReviewEvidenceRef)
	}
	return result
}

func equalEvidence(left, right []*roomv1.ReviewEvidenceRef) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if !proto.Equal(left[i], right[i]) {
			return false
		}
	}
	return true
}
