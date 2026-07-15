package review

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"

	roomv1 "github.com/haasonsaas/room/gen/go/room/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	hypothesisDomain = "room.review.hypothesis.v1"
	evidenceDomain   = "room.review.evidence-set.v1"
	executionDomain  = "room.review.execution-input.v1"
	receiptDomain    = "room.review.receipt.v1"
	findingDomain    = "room.review.finding.v1"
)

var deterministicMarshal = proto.MarshalOptions{Deterministic: true}

func HypothesisDigest(value *roomv1.ReviewHypothesis) ([]byte, error) {
	canonical, err := canonicalHypothesis(value)
	if err != nil {
		return nil, err
	}
	return digestMessage(hypothesisDomain, canonical)
}

func EvidenceSetDigest(values []*roomv1.ReviewEvidenceRef) ([]byte, error) {
	canonical, err := canonicalEvidence(values)
	if err != nil {
		return nil, err
	}
	container := &roomv1.ReviewVerificationReceipt{Evidence: canonical}
	return digestMessage(evidenceDomain, container)
}

func ExecutionInputDigest(hypothesisDigest, artifactDigest, impactSliceDigest []byte, verifier *roomv1.ReviewVerifierIdentity) ([]byte, error) {
	if err := validateDigest(hypothesisDigest, "hypothesis"); err != nil {
		return nil, err
	}
	if err := validateDigest(artifactDigest, "artifact"); err != nil {
		return nil, err
	}
	if err := validateDigest(impactSliceDigest, "impact slice"); err != nil {
		return nil, err
	}
	canonical, err := canonicalVerifier(verifier, false)
	if err != nil {
		return nil, err
	}
	verifierBytes, err := deterministicMarshal.Marshal(canonical)
	if err != nil {
		return nil, err
	}
	return digestBytes(executionDomain, hypothesisDigest, artifactDigest, impactSliceDigest, verifierBytes), nil
}

func ReceiptDigest(value *roomv1.ReviewVerificationReceipt) ([]byte, error) {
	canonical, err := canonicalReceipt(value)
	if err != nil {
		return nil, err
	}
	return digestMessage(receiptDomain, canonical)
}

func VerifiedFindingID(hypothesisDigest []byte, verifier *roomv1.ReviewVerifierIdentity, evidenceSetDigest []byte) (string, error) {
	if err := validateDigest(hypothesisDigest, "hypothesis"); err != nil {
		return "", err
	}
	if err := validateDigest(evidenceSetDigest, "evidence set"); err != nil {
		return "", err
	}
	canonical, err := canonicalVerifier(verifier, false)
	if err != nil {
		return "", err
	}
	verifierBytes, err := deterministicMarshal.Marshal(canonical)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(digestBytes(findingDomain, hypothesisDigest, verifierBytes, evidenceSetDigest)), nil
}

func canonicalHypothesis(value *roomv1.ReviewHypothesis) (*roomv1.ReviewHypothesis, error) {
	copyValue, err := normalizedHypothesis(value)
	if err != nil {
		return nil, err
	}
	copyValue.Id = ""
	copyValue.Source.ReviewCommentId = ""
	copyValue.Source.ReviewerId = ""
	copyValue.Source.Provider = ""
	copyValue.Invariant = ""
	copyValue.Impact = ""
	copyValue.Remediation = nil
	copyValue.Severity = roomv1.Severity_SEVERITY_UNSPECIFIED
	copyValue.ConfidenceBasisPoints = 0
	copyValue.CreatedAt = nil
	return copyValue, nil
}

func normalizedHypothesis(value *roomv1.ReviewHypothesis) (*roomv1.ReviewHypothesis, error) {
	if value == nil {
		return nil, errors.New("hypothesis is required")
	}
	copyValue := proto.Clone(value).(*roomv1.ReviewHypothesis)
	if copyValue.GetSource() == nil {
		return nil, errors.New("hypothesis source is required")
	}
	copyValue.Source.Repository = strings.TrimSpace(copyValue.Source.GetRepository())
	copyValue.Source.HeadSha = strings.TrimSpace(copyValue.Source.GetHeadSha())
	if copyValue.Source.GetRepository() == "" {
		return nil, errors.New("hypothesis source repository is required")
	}
	if copyValue.Source.GetHeadSha() == "" {
		return nil, errors.New("hypothesis source head SHA is required")
	}
	if _, ok := roomv1.ReviewClaimKind_name[int32(copyValue.GetClaimKind())]; !ok || copyValue.GetClaimKind() == roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_UNSPECIFIED {
		return nil, errors.New("hypothesis claim kind is required")
	}
	if err := validateDigest(copyValue.GetArtifactSha256(), "artifact"); err != nil {
		return nil, err
	}
	if err := validateDigest(copyValue.GetImpactSliceSha256(), "impact slice"); err != nil {
		return nil, err
	}
	paths, err := canonicalPaths(copyValue.GetAffectedPaths())
	if err != nil {
		return nil, fmt.Errorf("affected paths: %w", err)
	}
	copyValue.AffectedPaths = paths
	locations, err := canonicalLocations(copyValue.GetAffectedLocations())
	if err != nil {
		return nil, fmt.Errorf("affected locations: %w", err)
	}
	copyValue.AffectedLocations = locations
	producer, err := canonicalAnalyzer(copyValue.GetProducer())
	if err != nil {
		return nil, fmt.Errorf("producer: %w", err)
	}
	copyValue.Producer = producer
	if _, ok := roomv1.Severity_name[int32(copyValue.GetSeverity())]; !ok || copyValue.GetSeverity() == roomv1.Severity_SEVERITY_UNSPECIFIED {
		return nil, errors.New("hypothesis severity is required")
	}
	if copyValue.GetConfidenceBasisPoints() > 10000 {
		return nil, errors.New("hypothesis confidence exceeds 10000 basis points")
	}
	if err := validateTimestamp(copyValue.GetCreatedAt(), "hypothesis created_at"); err != nil {
		return nil, err
	}
	for index, condition := range copyValue.GetPreconditions() {
		copyValue.Preconditions[index] = strings.TrimSpace(condition)
		if copyValue.Preconditions[index] == "" {
			return nil, fmt.Errorf("hypothesis precondition %d is blank", index)
		}
	}
	for index, step := range copyValue.GetCausalPath() {
		copyValue.CausalPath[index] = strings.TrimSpace(step)
		if copyValue.CausalPath[index] == "" {
			return nil, fmt.Errorf("hypothesis causal path step %d is blank", index)
		}
	}

	return copyValue, nil
}

func canonicalReceipt(value *roomv1.ReviewVerificationReceipt) (*roomv1.ReviewVerificationReceipt, error) {
	if value == nil {
		return nil, errors.New("verification receipt is required")
	}
	copyValue := proto.Clone(value).(*roomv1.ReviewVerificationReceipt)
	verifier, err := canonicalVerifier(copyValue.GetVerifier(), false)
	if err != nil {
		return nil, fmt.Errorf("verifier: %w", err)
	}
	copyValue.Verifier = verifier
	if err := validateDigest(copyValue.GetHypothesisSha256(), "hypothesis"); err != nil {
		return nil, err
	}
	if err := validateDigest(copyValue.GetArtifactSha256(), "artifact"); err != nil {
		return nil, err
	}
	if err := validateDigest(copyValue.GetImpactSliceSha256(), "impact slice"); err != nil {
		return nil, err
	}
	if err := validateDigest(copyValue.GetExecutionInputSha256(), "execution input"); err != nil {
		return nil, err
	}
	if _, ok := roomv1.ReviewVerificationStatus_name[int32(copyValue.GetStatus())]; !ok || copyValue.GetStatus() == roomv1.ReviewVerificationStatus_REVIEW_VERIFICATION_STATUS_UNSPECIFIED {
		return nil, errors.New("verification status is required")
	}
	if _, ok := roomv1.ReviewVerificationReason_name[int32(copyValue.GetReason())]; !ok {
		return nil, errors.New("verification reason is invalid")
	}
	evidence, err := normalizedEvidence(copyValue.GetEvidence(), false)
	if err != nil {
		return nil, err
	}
	copyValue.Evidence = evidence
	if err := validateTimestamp(copyValue.GetCompletedAt(), "verification completed_at"); err != nil {
		return nil, err
	}
	copyValue.Id = ""
	return copyValue, nil
}

func canonicalEvidence(values []*roomv1.ReviewEvidenceRef) ([]*roomv1.ReviewEvidenceRef, error) {
	return normalizedEvidence(values, true)
}

func normalizedEvidence(values []*roomv1.ReviewEvidenceRef, excludeDescription bool) ([]*roomv1.ReviewEvidenceRef, error) {
	byID := make(map[string]*roomv1.ReviewEvidenceRef, len(values))
	for index, value := range values {
		if value == nil {
			return nil, fmt.Errorf("evidence %d is required", index)
		}
		copyValue := proto.Clone(value).(*roomv1.ReviewEvidenceRef)
		copyValue.Id = strings.TrimSpace(copyValue.GetId())
		if copyValue.GetId() == "" {
			return nil, fmt.Errorf("evidence %d id is required", index)
		}
		if _, ok := roomv1.ReviewEvidenceKind_name[int32(copyValue.GetKind())]; !ok || copyValue.GetKind() == roomv1.ReviewEvidenceKind_REVIEW_EVIDENCE_KIND_UNSPECIFIED {
			return nil, fmt.Errorf("evidence %q kind is required", copyValue.GetId())
		}
		if err := validateDigest(copyValue.GetContentSha256(), "evidence content"); err != nil {
			return nil, fmt.Errorf("evidence %q: %w", copyValue.GetId(), err)
		}
		if copyValue.GetLocation() != nil {
			location, err := canonicalLocation(copyValue.GetLocation())
			if err != nil {
				return nil, fmt.Errorf("evidence %q location: %w", copyValue.GetId(), err)
			}
			copyValue.Location = location
		}
		copyValue.Command = strings.TrimSpace(copyValue.GetCommand())
		switch copyValue.GetKind() {
		case roomv1.ReviewEvidenceKind_REVIEW_EVIDENCE_KIND_SOURCE_LOCATION:
			if copyValue.GetLocation() == nil {
				return nil, fmt.Errorf("evidence %q source location is required", copyValue.GetId())
			}
		case roomv1.ReviewEvidenceKind_REVIEW_EVIDENCE_KIND_COMMAND_RESULT:
			if copyValue.GetCommand() == "" {
				return nil, fmt.Errorf("evidence %q command is required", copyValue.GetId())
			}
		}
		copyValue.Description = strings.TrimSpace(copyValue.GetDescription())
		if excludeDescription {
			copyValue.Description = ""
		}
		if previous := byID[copyValue.GetId()]; previous != nil {
			if !proto.Equal(previous, copyValue) {
				return nil, fmt.Errorf("evidence id %q is reused with conflicting content", copyValue.GetId())
			}
			continue
		}
		byID[copyValue.GetId()] = copyValue
	}
	result := make([]*roomv1.ReviewEvidenceRef, 0, len(byID))
	for _, value := range byID {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].GetId() < result[j].GetId() })
	return result, nil
}

func canonicalAnalyzer(value *roomv1.AnalyzerIdentity) (*roomv1.AnalyzerIdentity, error) {
	if value == nil {
		return nil, errors.New("identity is required")
	}
	copyValue := proto.Clone(value).(*roomv1.AnalyzerIdentity)
	copyValue.Id = strings.TrimSpace(copyValue.GetId())
	copyValue.Version = strings.TrimSpace(copyValue.GetVersion())
	if copyValue.GetId() == "" || copyValue.GetVersion() == "" {
		return nil, errors.New("identity id and version are required")
	}
	if err := validateDigest(copyValue.GetConfigSha256(), "identity config"); err != nil {
		return nil, err
	}
	return copyValue, nil
}

func canonicalPaths(values []string) ([]string, error) {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		canonical, err := canonicalPath(value)
		if err != nil {
			return nil, err
		}
		seen[canonical] = struct{}{}
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result, nil
}

func canonicalLocations(values []*roomv1.SourceLocation) ([]*roomv1.SourceLocation, error) {
	byKey := make(map[string]*roomv1.SourceLocation, len(values))
	for index, value := range values {
		location, err := canonicalLocation(value)
		if err != nil {
			return nil, fmt.Errorf("location %d: %w", index, err)
		}
		key := fmt.Sprintf("%s:%010d:%010d", location.GetFilePath(), location.GetStartLine(), location.GetEndLine())
		byKey[key] = location
	}
	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]*roomv1.SourceLocation, 0, len(keys))
	for _, key := range keys {
		result = append(result, byKey[key])
	}
	return result, nil
}

func canonicalLocation(value *roomv1.SourceLocation) (*roomv1.SourceLocation, error) {
	if value == nil {
		return nil, errors.New("source location is required")
	}
	copyValue := proto.Clone(value).(*roomv1.SourceLocation)
	canonical, err := canonicalPath(copyValue.GetFilePath())
	if err != nil {
		return nil, err
	}
	copyValue.FilePath = canonical
	if copyValue.GetStartLine() <= 0 || copyValue.GetEndLine() < copyValue.GetStartLine() {
		return nil, errors.New("source location line range is invalid")
	}
	return copyValue, nil
}

func canonicalPath(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.Contains(value, "\\") || path.IsAbs(value) {
		return "", errors.New("repository-relative slash path is required")
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == ".." {
			return "", errors.New("repository path traversal is forbidden")
		}
	}
	canonical := path.Clean(value)
	if canonical == "." || canonical == ".." || strings.HasPrefix(canonical, "../") {
		return "", errors.New("repository path traversal is forbidden")
	}
	return canonical, nil
}

func validateDigest(value []byte, label string) error {
	if len(value) != sha256.Size {
		return fmt.Errorf("%s digest must be SHA-256", label)
	}
	return nil
}

func validateTimestamp(value *timestamppb.Timestamp, label string) error {
	if value == nil {
		return fmt.Errorf("%s is required", label)
	}
	if err := value.CheckValid(); err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	return nil
}

func digestMessage(domain string, message proto.Message) ([]byte, error) {
	payload, err := deterministicMarshal.Marshal(message)
	if err != nil {
		return nil, err
	}
	return digestBytes(domain, payload), nil
}

func digestBytes(domain string, values ...[]byte) []byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte(domain))
	_, _ = hash.Write([]byte{0})
	for _, value := range values {
		_, _ = hash.Write(value)
	}
	return hash.Sum(nil)
}
