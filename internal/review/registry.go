package review

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"strings"

	roomv1 "github.com/haasonsaas/room/gen/go/room/v1"
	"google.golang.org/protobuf/proto"
)

type Registry struct {
	byID map[string]*roomv1.ReviewVerifierIdentity
}

func NewRegistry(values ...*roomv1.ReviewVerifierIdentity) (*Registry, error) {
	registry := &Registry{byID: make(map[string]*roomv1.ReviewVerifierIdentity, len(values))}
	for index, value := range values {
		canonical, err := canonicalVerifier(value, true)
		if err != nil {
			return nil, fmt.Errorf("verifier %d: %w", index, err)
		}
		id := canonical.GetAnalyzer().GetId()
		if _, exists := registry.byID[id]; exists {
			return nil, fmt.Errorf("verifier id %q is duplicated", id)
		}
		registry.byID[id] = canonical
	}
	return registry, nil
}

func (r *Registry) Resolve(identity *roomv1.ReviewVerifierIdentity) (*roomv1.ReviewVerifierIdentity, roomv1.ReviewVerificationReason) {
	if r == nil || identity == nil || identity.GetAnalyzer() == nil {
		return nil, roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_UNTRUSTED_VERIFIER
	}
	trusted := r.byID[strings.TrimSpace(identity.GetAnalyzer().GetId())]
	if trusted == nil {
		return nil, roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_UNTRUSTED_VERIFIER
	}
	candidate, err := canonicalVerifier(identity, false)
	if err != nil || !proto.Equal(trusted, candidate) {
		return nil, roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_VERIFIER_IDENTITY_MISMATCH
	}
	return proto.Clone(trusted).(*roomv1.ReviewVerifierIdentity), roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_UNSPECIFIED
}

func canonicalVerifier(value *roomv1.ReviewVerifierIdentity, rejectDuplicateCoverage bool) (*roomv1.ReviewVerifierIdentity, error) {
	if value == nil || value.GetAnalyzer() == nil {
		return nil, errors.New("identity is required")
	}
	copyValue := proto.Clone(value).(*roomv1.ReviewVerifierIdentity)
	copyValue.Analyzer.Id = strings.TrimSpace(copyValue.Analyzer.GetId())
	copyValue.Analyzer.Version = strings.TrimSpace(copyValue.Analyzer.GetVersion())
	if copyValue.Analyzer.GetId() == "" {
		return nil, errors.New("analyzer id is required")
	}
	if copyValue.Analyzer.GetVersion() == "" {
		return nil, errors.New("analyzer version is required")
	}
	if len(copyValue.Analyzer.GetConfigSha256()) != sha256.Size {
		return nil, errors.New("analyzer config digest must be SHA-256")
	}
	if _, ok := roomv1.ReviewVerifierKind_name[int32(copyValue.GetKind())]; !ok || copyValue.GetKind() == roomv1.ReviewVerifierKind_REVIEW_VERIFIER_KIND_UNSPECIFIED {
		return nil, errors.New("verifier kind is required")
	}
	if len(copyValue.GetCoveredClaims()) == 0 {
		return nil, errors.New("covered claims are required")
	}
	seen := make(map[roomv1.ReviewClaimKind]struct{}, len(copyValue.GetCoveredClaims()))
	for _, claim := range copyValue.GetCoveredClaims() {
		if _, ok := roomv1.ReviewClaimKind_name[int32(claim)]; !ok || claim == roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_UNSPECIFIED {
			return nil, errors.New("covered claim kind is invalid")
		}
		if _, exists := seen[claim]; exists && rejectDuplicateCoverage {
			return nil, fmt.Errorf("covered claim %s is duplicated", claim)
		}
		seen[claim] = struct{}{}
	}
	copyValue.CoveredClaims = copyValue.CoveredClaims[:0]
	for claim := range seen {
		copyValue.CoveredClaims = append(copyValue.CoveredClaims, claim)
	}
	sort.Slice(copyValue.CoveredClaims, func(i, j int) bool { return copyValue.CoveredClaims[i] < copyValue.CoveredClaims[j] })
	return copyValue, nil
}
