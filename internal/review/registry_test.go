package review

import (
	"bytes"
	"crypto/sha256"
	"testing"

	roomv1 "github.com/haasonsaas/room/gen/go/room/v1"
	"google.golang.org/protobuf/proto"
)

func TestRegistryConstruction(t *testing.T) {
	validDeterministic := verifier("deterministic", roomv1.ReviewVerifierKind_REVIEW_VERIFIER_KIND_DETERMINISTIC, roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_AUTHORIZATION_BOUNDARY)
	validSemantic := verifier("semantic", roomv1.ReviewVerifierKind_REVIEW_VERIFIER_KIND_SEMANTIC_SCOUT, roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_PROTOCOL_CONTRACT)
	for _, test := range []struct {
		name   string
		values []*roomv1.ReviewVerifierIdentity
		valid  bool
	}{
		{name: "deterministic", values: []*roomv1.ReviewVerifierIdentity{validDeterministic}, valid: true},
		{name: "semantic identity", values: []*roomv1.ReviewVerifierIdentity{validSemantic}, valid: true},
		{name: "multiple", values: []*roomv1.ReviewVerifierIdentity{validDeterministic, validSemantic}, valid: true},
		{name: "nil identity", values: []*roomv1.ReviewVerifierIdentity{nil}},
		{name: "missing analyzer", values: []*roomv1.ReviewVerifierIdentity{{Kind: roomv1.ReviewVerifierKind_REVIEW_VERIFIER_KIND_DETERMINISTIC, CoveredClaims: []roomv1.ReviewClaimKind{roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_AUTHORIZATION_BOUNDARY}}}},
		{name: "missing id", values: []*roomv1.ReviewVerifierIdentity{mutateVerifier(validDeterministic, func(v *roomv1.ReviewVerifierIdentity) { v.Analyzer.Id = "" })}},
		{name: "missing version", values: []*roomv1.ReviewVerifierIdentity{mutateVerifier(validDeterministic, func(v *roomv1.ReviewVerifierIdentity) { v.Analyzer.Version = "" })}},
		{name: "short config digest", values: []*roomv1.ReviewVerifierIdentity{mutateVerifier(validDeterministic, func(v *roomv1.ReviewVerifierIdentity) { v.Analyzer.ConfigSha256 = []byte{1} })}},
		{name: "short tool digest", values: []*roomv1.ReviewVerifierIdentity{mutateVerifier(validDeterministic, func(v *roomv1.ReviewVerifierIdentity) { v.Analyzer.ToolSha256 = []byte{1} })}},
		{name: "unknown kind", values: []*roomv1.ReviewVerifierIdentity{mutateVerifier(validDeterministic, func(v *roomv1.ReviewVerifierIdentity) { v.Kind = roomv1.ReviewVerifierKind(99) })}},
		{name: "empty coverage", values: []*roomv1.ReviewVerifierIdentity{mutateVerifier(validDeterministic, func(v *roomv1.ReviewVerifierIdentity) { v.CoveredClaims = nil })}},
		{name: "unspecified coverage", values: []*roomv1.ReviewVerifierIdentity{mutateVerifier(validDeterministic, func(v *roomv1.ReviewVerifierIdentity) {
			v.CoveredClaims = []roomv1.ReviewClaimKind{roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_UNSPECIFIED}
		})}},
		{name: "unknown coverage", values: []*roomv1.ReviewVerifierIdentity{mutateVerifier(validDeterministic, func(v *roomv1.ReviewVerifierIdentity) {
			v.CoveredClaims = []roomv1.ReviewClaimKind{roomv1.ReviewClaimKind(99)}
		})}},
		{name: "duplicate coverage", values: []*roomv1.ReviewVerifierIdentity{mutateVerifier(validDeterministic, func(v *roomv1.ReviewVerifierIdentity) { v.CoveredClaims = append(v.CoveredClaims, v.CoveredClaims[0]) })}},
		{name: "duplicate id", values: []*roomv1.ReviewVerifierIdentity{validDeterministic, proto.Clone(validDeterministic).(*roomv1.ReviewVerifierIdentity)}},
		{name: "conflicting duplicate id", values: []*roomv1.ReviewVerifierIdentity{validDeterministic, mutateVerifier(validDeterministic, func(v *roomv1.ReviewVerifierIdentity) { v.Analyzer.Version = "2" })}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewRegistry(test.values...)
			if test.valid && err != nil {
				t.Fatalf("NewRegistry() error = %v", err)
			}
			if !test.valid && err == nil {
				t.Fatal("NewRegistry() error = nil, want error")
			}
		})
	}
}

func TestRegistryResolveExactIdentity(t *testing.T) {
	trusted := verifier(
		"deterministic",
		roomv1.ReviewVerifierKind_REVIEW_VERIFIER_KIND_DETERMINISTIC,
		roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_PROTOCOL_CONTRACT,
		roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_AUTHORIZATION_BOUNDARY,
	)
	registry, err := NewRegistry(trusted)
	if err != nil {
		t.Fatal(err)
	}

	reordered := proto.Clone(trusted).(*roomv1.ReviewVerifierIdentity)
	reordered.CoveredClaims[0], reordered.CoveredClaims[1] = reordered.CoveredClaims[1], reordered.CoveredClaims[0]
	resolved, reason := registry.Resolve(reordered)
	if reason != roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_UNSPECIFIED {
		t.Fatalf("Resolve() reason = %s", reason)
	}
	if resolved == nil || resolved.GetAnalyzer().GetId() != "deterministic" {
		t.Fatalf("Resolve() = %+v", resolved)
	}

	for _, test := range []struct {
		name   string
		value  *roomv1.ReviewVerifierIdentity
		reason roomv1.ReviewVerificationReason
	}{
		{name: "unknown", value: verifier("unknown", roomv1.ReviewVerifierKind_REVIEW_VERIFIER_KIND_DETERMINISTIC, roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_AUTHORIZATION_BOUNDARY), reason: roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_UNTRUSTED_VERIFIER},
		{name: "missing", value: nil, reason: roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_UNTRUSTED_VERIFIER},
		{name: "version", value: mutateVerifier(trusted, func(v *roomv1.ReviewVerifierIdentity) { v.Analyzer.Version = "2" }), reason: roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_VERIFIER_IDENTITY_MISMATCH},
		{name: "config", value: mutateVerifier(trusted, func(v *roomv1.ReviewVerifierIdentity) {
			v.Analyzer.ConfigSha256 = bytes.Repeat([]byte{0x22}, sha256.Size)
		}), reason: roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_VERIFIER_IDENTITY_MISMATCH},
		{name: "kind", value: mutateVerifier(trusted, func(v *roomv1.ReviewVerifierIdentity) {
			v.Kind = roomv1.ReviewVerifierKind_REVIEW_VERIFIER_KIND_SEMANTIC_SCOUT
		}), reason: roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_VERIFIER_IDENTITY_MISMATCH},
		{name: "coverage", value: mutateVerifier(trusted, func(v *roomv1.ReviewVerifierIdentity) { v.CoveredClaims = v.CoveredClaims[:1] }), reason: roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_VERIFIER_IDENTITY_MISMATCH},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, reason := registry.Resolve(test.value)
			if got != nil || reason != test.reason {
				t.Fatalf("Resolve() = (%+v, %s), want (nil, %s)", got, reason, test.reason)
			}
		})
	}
}

func TestRegistryDoesNotExposeMutableState(t *testing.T) {
	input := verifier("deterministic", roomv1.ReviewVerifierKind_REVIEW_VERIFIER_KIND_DETERMINISTIC, roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_AUTHORIZATION_BOUNDARY)
	registry, err := NewRegistry(input)
	if err != nil {
		t.Fatal(err)
	}
	input.Analyzer.Version = "mutated"

	lookup := verifier("deterministic", roomv1.ReviewVerifierKind_REVIEW_VERIFIER_KIND_DETERMINISTIC, roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_AUTHORIZATION_BOUNDARY)
	first, reason := registry.Resolve(lookup)
	if reason != roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_UNSPECIFIED {
		t.Fatalf("first resolve reason = %s", reason)
	}
	first.Analyzer.Version = "mutated return"
	second, reason := registry.Resolve(lookup)
	if reason != roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_UNSPECIFIED || second.GetAnalyzer().GetVersion() != "1" {
		t.Fatalf("second resolve = (%+v, %s)", second, reason)
	}
}

func verifier(id string, kind roomv1.ReviewVerifierKind, claims ...roomv1.ReviewClaimKind) *roomv1.ReviewVerifierIdentity {
	return &roomv1.ReviewVerifierIdentity{
		Analyzer:      &roomv1.AnalyzerIdentity{Id: id, Version: "1", ConfigSha256: bytes.Repeat([]byte{0x11}, sha256.Size)},
		Kind:          kind,
		CoveredClaims: claims,
	}
}

func mutateVerifier(value *roomv1.ReviewVerifierIdentity, mutate func(*roomv1.ReviewVerifierIdentity)) *roomv1.ReviewVerifierIdentity {
	copyValue := proto.Clone(value).(*roomv1.ReviewVerifierIdentity)
	mutate(copyValue)
	return copyValue
}
