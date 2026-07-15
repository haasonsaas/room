# Review Evidence Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the typed, deterministic authority boundary that turns a review hypothesis into a verifier-backed finding without changing active policy behavior.

**Architecture:** Extend Room's Protobuf contract with review-specific evidence and verification records, then implement an immutable verifier registry and a pure compiler under `internal/review`. The compiler canonicalizes cloned inputs, validates exact trust/artifact/evidence bindings, and returns typed verified, rejected, indeterminate, or invalid results; no persistence, external processes, or policy integration are added in this slice.

**Tech Stack:** Go 1.26, Protobuf v3, `google.golang.org/protobuf`, Buf v2, standard-library SHA-256 and path handling.

## Global Constraints

- Model or scout output alone must never produce a verified finding.
- Only an exact trusted verifier tuple with `DETERMINISTIC` kind and matching claim coverage is eligible.
- Missing, stale, malformed, uncovered, untrusted, or mismatched verification fails closed as a typed non-verified result.
- Existing analyzer receipts, review-finding ingestion, policy evaluation, persistence, and rollout behavior remain unchanged.
- No repository command execution, semantic scout invocation, persistence, serving, or new blocking policy is included.
- Stable identities use deterministic Protobuf serialization, SHA-256, lowercase hexadecimal IDs, and domain separation.
- All input messages are cloned; compiler and registry APIs do not mutate caller-owned Protobuf values.

---

## File map

- `proto/room/v1/rules.proto`: public enums and messages for hypotheses, evidence, verifier trust, receipts, findings, and compile results.
- `gen/go/room/v1/rules.pb.go`: generated Go types; never edited by hand.
- `gen/go/room/v1/roomv1connect/rules.connect.go`: regenerated service bindings; expected to be semantically unchanged because no RPC is added.
- `internal/review/registry.go`: immutable trusted-verifier construction and exact lookup.
- `internal/review/canonical.go`: input cloning, normalization, deterministic marshaling, and domain-separated digests.
- `internal/review/compiler.go`: ordered contract validation and typed compilation outcome.
- `internal/review/registry_test.go`: registry validation and immutability coverage.
- `internal/review/compiler_test.go`: success, fail-closed, evidence, status, identity, and mutation regression tests.
- `internal/review/testdata/authorization_boundary.json`: human-readable canonical fixture inputs and expected digests.
- `docs/architecture.md`: relationship between existing analyzer receipts and review verifier receipts.

### Task 1: Add the typed review-verification contract

**Files:**
- Modify: `proto/room/v1/rules.proto`
- Regenerate: `gen/go/room/v1/rules.pb.go`
- Regenerate: `gen/go/room/v1/roomv1connect/rules.connect.go`

**Interfaces:**
- Consumes: existing `ReviewClaimKind`, `ReviewSource`, `SourceLocation`, `AnalyzerIdentity`, and `Severity`.
- Produces: `ReviewHypothesis`, `ReviewEvidenceRef`, `ReviewVerifierIdentity`, `ReviewVerificationReceipt`, `VerifiedReviewFinding`, and `ReviewCompilationResult` plus their typed enums.

- [ ] **Step 1: Add the enums after `ReviewClaimKind`**

```proto
enum ReviewEvidenceKind {
  REVIEW_EVIDENCE_KIND_UNSPECIFIED = 0;
  REVIEW_EVIDENCE_KIND_SOURCE_LOCATION = 1;
  REVIEW_EVIDENCE_KIND_SYMBOL_TRACE = 2;
  REVIEW_EVIDENCE_KIND_CONTRACT = 3;
  REVIEW_EVIDENCE_KIND_COMMAND_RESULT = 4;
  REVIEW_EVIDENCE_KIND_REPLAY_FIXTURE = 5;
  REVIEW_EVIDENCE_KIND_GENERATED_PROVENANCE = 6;
}

enum ReviewVerifierKind {
  REVIEW_VERIFIER_KIND_UNSPECIFIED = 0;
  REVIEW_VERIFIER_KIND_DETERMINISTIC = 1;
  REVIEW_VERIFIER_KIND_SEMANTIC_SCOUT = 2;
}

enum ReviewVerificationStatus {
  REVIEW_VERIFICATION_STATUS_UNSPECIFIED = 0;
  REVIEW_VERIFICATION_STATUS_VERIFIED = 1;
  REVIEW_VERIFICATION_STATUS_REJECTED = 2;
  REVIEW_VERIFICATION_STATUS_INDETERMINATE = 3;
}

enum ReviewVerificationReason {
  REVIEW_VERIFICATION_REASON_UNSPECIFIED = 0;
  REVIEW_VERIFICATION_REASON_UNTRUSTED_VERIFIER = 1;
  REVIEW_VERIFICATION_REASON_VERIFIER_IDENTITY_MISMATCH = 2;
  REVIEW_VERIFICATION_REASON_CLAIM_NOT_COVERED = 3;
  REVIEW_VERIFICATION_REASON_NONDETERMINISTIC_VERIFIER = 4;
  REVIEW_VERIFICATION_REASON_HYPOTHESIS_DIGEST_MISMATCH = 5;
  REVIEW_VERIFICATION_REASON_ARTIFACT_DIGEST_MISMATCH = 6;
  REVIEW_VERIFICATION_REASON_IMPACT_SLICE_DIGEST_MISMATCH = 7;
  REVIEW_VERIFICATION_REASON_EXECUTION_INPUT_DIGEST_MISMATCH = 8;
  REVIEW_VERIFICATION_REASON_EVIDENCE_INVALID = 9;
  REVIEW_VERIFICATION_REASON_HYPOTHESIS_REJECTED = 10;
  REVIEW_VERIFICATION_REASON_VERIFIER_UNAVAILABLE = 11;
  REVIEW_VERIFICATION_REASON_VERIFIER_TIMEOUT = 12;
  REVIEW_VERIFICATION_REASON_CONFLICTING_RESULTS = 13;
  REVIEW_VERIFICATION_REASON_MALFORMED_CONTRACT = 14;
}

enum ReviewCompilationStatus {
  REVIEW_COMPILATION_STATUS_UNSPECIFIED = 0;
  REVIEW_COMPILATION_STATUS_VERIFIED = 1;
  REVIEW_COMPILATION_STATUS_REJECTED = 2;
  REVIEW_COMPILATION_STATUS_INDETERMINATE = 3;
  REVIEW_COMPILATION_STATUS_INVALID = 4;
}
```

- [ ] **Step 2: Add the messages immediately after `ReviewFinding`**

```proto
message ReviewHypothesis {
  string id = 1;
  ReviewSource source = 2;
  ReviewClaimKind claim_kind = 3;
  bytes artifact_sha256 = 4;
  bytes impact_slice_sha256 = 5;
  repeated string affected_paths = 6;
  repeated SourceLocation affected_locations = 7;
  string invariant = 8;
  repeated string preconditions = 9;
  repeated string causal_path = 10;
  string impact = 11;
  repeated string remediation = 12;
  AnalyzerIdentity producer = 13;
  Severity severity = 14;
  uint32 confidence_basis_points = 15;
  google.protobuf.Timestamp created_at = 16;
}

message ReviewEvidenceRef {
  string id = 1;
  ReviewEvidenceKind kind = 2;
  bytes content_sha256 = 3;
  SourceLocation location = 4;
  string command = 5;
  string description = 6;
}

message ReviewVerifierIdentity {
  AnalyzerIdentity analyzer = 1;
  ReviewVerifierKind kind = 2;
  repeated ReviewClaimKind covered_claims = 3;
}

message ReviewVerificationReceipt {
  string id = 1;
  ReviewVerifierIdentity verifier = 2;
  bytes hypothesis_sha256 = 3;
  bytes artifact_sha256 = 4;
  bytes impact_slice_sha256 = 5;
  bytes execution_input_sha256 = 6;
  ReviewVerificationStatus status = 7;
  ReviewVerificationReason reason = 8;
  repeated ReviewEvidenceRef evidence = 9;
  google.protobuf.Timestamp completed_at = 10;
}

message VerifiedReviewFinding {
  string id = 1;
  ReviewHypothesis hypothesis = 2;
  ReviewVerificationReceipt receipt = 3;
  bytes evidence_set_sha256 = 4;
}

message ReviewCompilationResult {
  ReviewCompilationStatus status = 1;
  ReviewVerificationReason reason = 2;
  VerifiedReviewFinding finding = 3;
}
```

- [ ] **Step 3: Lint the contract before generation**

Run: `buf lint`

Expected: exit 0. If Buf requires enum-prefix or field naming adjustments, preserve the exact semantic names above while following the repository's existing Protobuf lint convention.

- [ ] **Step 4: Regenerate checked-in Go bindings**

Run: `buf generate`

Expected: `gen/go/room/v1/rules.pb.go` changes; Connect output is unchanged or contains generator-only metadata changes.

- [ ] **Step 5: Prove the generated API exists**

Run: `go test ./gen/go/room/v1/...`

Expected: PASS.

- [ ] **Step 6: Commit the contract**

```bash
git add proto/room/v1/rules.proto gen/go/room/v1/rules.pb.go gen/go/room/v1/roomv1connect/rules.connect.go
git commit -m "feat: add review verification contract"
```

### Task 2: Implement the immutable trusted-verifier registry

**Files:**
- Create: `internal/review/registry.go`
- Create: `internal/review/registry_test.go`

**Interfaces:**
- Consumes: `*roomv1.ReviewVerifierIdentity` generated in Task 1.
- Produces: `NewRegistry(values ...*roomv1.ReviewVerifierIdentity) (*Registry, error)` and `Resolve(identity *roomv1.ReviewVerifierIdentity) (*roomv1.ReviewVerifierIdentity, roomv1.ReviewVerificationReason)`.

- [ ] **Step 1: Write registry construction and lookup tests**

Create table-driven tests covering valid deterministic and semantic identities, missing ID/version/config digest, unknown kind, empty/unspecified/duplicate coverage, conflicting duplicate ID, exact lookup, version/config/kind/coverage mismatch, and returned-value mutation. Use this shared fixture:

```go
func verifier(id string, kind roomv1.ReviewVerifierKind, claims ...roomv1.ReviewClaimKind) *roomv1.ReviewVerifierIdentity {
    return &roomv1.ReviewVerifierIdentity{
        Analyzer: &roomv1.AnalyzerIdentity{Id: id, Version: "1", ConfigSha256: bytes.Repeat([]byte{0x11}, sha256.Size)},
        Kind: kind,
        CoveredClaims: claims,
    }
}
```

Assert mismatched exact identities resolve to `REVIEW_VERIFICATION_REASON_VERIFIER_IDENTITY_MISMATCH`, unknown IDs resolve to `REVIEW_VERIFICATION_REASON_UNTRUSTED_VERIFIER`, and registry-returned clones cannot mutate later resolutions.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/review -run 'TestRegistry' -count=1`

Expected: FAIL because `NewRegistry` and `Resolve` do not exist.

- [ ] **Step 3: Implement `Registry` with exact immutable identity matching**

Use a private `map[string]*roomv1.ReviewVerifierIdentity`, clone every accepted input with `proto.Clone`, sort coverage in the stored clone, and compare lookups with `proto.Equal`. Validation must reject all invalid construction cases from Step 1. `Resolve` must never return a stored pointer.

```go
type Registry struct {
    byID map[string]*roomv1.ReviewVerifierIdentity
}

func NewRegistry(values ...*roomv1.ReviewVerifierIdentity) (*Registry, error)

func (r *Registry) Resolve(identity *roomv1.ReviewVerifierIdentity) (*roomv1.ReviewVerifierIdentity, roomv1.ReviewVerificationReason)
```

Normalize lookup coverage on a clone before equality so semantically set-like ordering does not cause a mismatch. Reject duplicates during registry construction rather than silently deduplicating coverage.

- [ ] **Step 4: Run registry tests**

Run: `go test ./internal/review -run 'TestRegistry' -count=1`

Expected: PASS.

- [ ] **Step 5: Run package race tests**

Run: `go test -race ./internal/review -run 'TestRegistry' -count=1`

Expected: PASS.

- [ ] **Step 6: Commit the registry**

```bash
git add internal/review/registry.go internal/review/registry_test.go
git commit -m "feat: add trusted review verifier registry"
```

### Task 3: Implement canonical review identities

**Files:**
- Create: `internal/review/canonical.go`
- Create: `internal/review/compiler_test.go`
- Create: `internal/review/testdata/authorization_boundary.json`

**Interfaces:**
- Consumes: generated review messages and registry identities.
- Produces: `HypothesisDigest`, `EvidenceSetDigest`, `ReceiptDigest`, and private canonicalization helpers used by the compiler.

- [ ] **Step 1: Write failing canonicalization and golden-fixture tests**

Define fixed hypothesis, verifier, receipt, and evidence fixtures using constant SHA-256 byte patterns and fixed UTC timestamps. Tests must assert:

```go
first, err := HypothesisDigest(hypothesis)
if err != nil { t.Fatal(err) }
reordered := proto.Clone(hypothesis).(*roomv1.ReviewHypothesis)
slices.Reverse(reordered.AffectedPaths)
slices.Reverse(reordered.AffectedLocations)
second, err := HypothesisDigest(reordered)
if err != nil { t.Fatal(err) }
if !bytes.Equal(first, second) { t.Fatal("set ordering changed hypothesis digest") }
if !proto.Equal(hypothesis, original) { t.Fatal("digest mutated input") }
```

Also assert that ordered `Preconditions` and `CausalPath` changes alter the hypothesis digest; exact duplicate evidence is normalized; conflicting reuse of an evidence ID fails; absolute paths, `..` traversal, invalid line ranges, missing 32-byte digests, and unknown evidence kinds fail; and every returned digest is exactly 32 bytes.

The JSON testdata file records the fixed repository/head, claim kind, paths, locations, verifier tuple, evidence IDs/content hashes, and the expected lowercase hex digests produced after the implementation is stable. Tests load it with `encoding/json` and compare hypothesis, evidence-set, execution-input, receipt, and finding digests.

- [ ] **Step 2: Run the canonical tests to verify they fail**

Run: `go test ./internal/review -run 'Test(Hypothesis|Evidence|Golden)' -count=1`

Expected: FAIL because digest helpers do not exist.

- [ ] **Step 3: Implement pure canonicalization**

Implement domain-separated hashing with deterministic Protobuf serialization:

```go
var deterministicMarshal = proto.MarshalOptions{Deterministic: true}

func digest(domain string, message proto.Message) ([]byte, error) {
    payload, err := deterministicMarshal.Marshal(message)
    if err != nil { return nil, err }
    sum := sha256.New()
    _, _ = sum.Write([]byte(domain))
    _, _ = sum.Write([]byte{0})
    _, _ = sum.Write(payload)
    return sum.Sum(nil), nil
}
```

Implement these exported signatures:

```go
func HypothesisDigest(value *roomv1.ReviewHypothesis) ([]byte, error)
func EvidenceSetDigest(values []*roomv1.ReviewEvidenceRef) ([]byte, error)
func ExecutionInputDigest(hypothesisDigest, artifactDigest, impactSliceDigest []byte, verifier *roomv1.ReviewVerifierIdentity) ([]byte, error)
func ReceiptDigest(value *roomv1.ReviewVerificationReceipt) ([]byte, error)
func VerifiedFindingID(hypothesisDigest []byte, verifier *roomv1.ReviewVerifierIdentity, evidenceSetDigest []byte) (string, error)
```

Canonicalization clones messages, clears caller/computed IDs and timestamps where required by the design, excludes invariant/impact/remediation/confidence presentation fields from the hypothesis authority projection, validates 32-byte digests and enum membership, normalizes repository-relative slash paths with `path.Clean`, rejects absolute/traversing paths, sorts set-like paths/locations/evidence, removes byte-for-byte exact duplicate evidence, and rejects same-ID conflicting evidence. Preserve ordered preconditions and causal-path steps in the hypothesis authority projection. Use domains `room.review.hypothesis.v1`, `room.review.evidence-set.v1`, `room.review.execution-input.v1`, and `room.review.receipt.v1` exactly.

- [ ] **Step 4: Run canonical tests and record the golden digests**

Run: `UPDATE_GOLDEN=1 go test ./internal/review -run TestGoldenAuthorizationBoundary -count=1`

Expected: FAIL with a deliberate test message that prints the five computed values only through the test's explicit golden-update branch. Apply the printed values to `internal/review/testdata/authorization_boundary.json` with `apply_patch`, remove the temporary update branch, then rerun without `UPDATE_GOLDEN` and expect PASS. The test must not write the fixture itself.

- [ ] **Step 5: Verify canonical identities are stable**

Run: `go test ./internal/review -run 'Test(Hypothesis|Evidence|Golden)' -count=20`

Expected: PASS for all 20 repetitions.

- [ ] **Step 6: Commit canonical identities**

```bash
git add internal/review/canonical.go internal/review/compiler_test.go internal/review/testdata/authorization_boundary.json
git commit -m "feat: add canonical review evidence identities"
```

### Task 4: Compile verifier receipts into typed outcomes

**Files:**
- Create: `internal/review/compiler.go`
- Modify: `internal/review/compiler_test.go`
- Modify: `docs/architecture.md`

**Interfaces:**
- Consumes: `Registry.Resolve`, `HypothesisDigest`, `EvidenceSetDigest`, and `ReceiptDigest`.
- Produces: `NewCompiler(registry *Registry) (*Compiler, error)` and `Compile(hypothesis *roomv1.ReviewHypothesis, receipt *roomv1.ReviewVerificationReceipt) (*roomv1.ReviewCompilationResult, error)`.

- [ ] **Step 1: Write a successful compilation test**

Construct a trusted deterministic verifier for `REVIEW_CLAIM_KIND_AUTHORIZATION_BOUNDARY`, a canonical hypothesis, and a `VERIFIED` receipt with two typed evidence references. Assert:

```go
result, err := compiler.Compile(hypothesis, receipt)
if err != nil { t.Fatal(err) }
if result.GetStatus() != roomv1.ReviewCompilationStatus_REVIEW_COMPILATION_STATUS_VERIFIED { t.Fatalf("status = %s", result.GetStatus()) }
if result.GetReason() != roomv1.ReviewVerificationReason_REVIEW_VERIFICATION_REASON_UNSPECIFIED { t.Fatalf("reason = %s", result.GetReason()) }
if result.GetFinding() == nil || len(result.GetFinding().GetId()) != 64 { t.Fatal("stable finding missing") }
if !bytes.Equal(result.GetFinding().GetEvidenceSetSha256(), expectedEvidenceDigest) { t.Fatal("evidence digest mismatch") }
if !proto.Equal(hypothesis, originalHypothesis) || !proto.Equal(receipt, originalReceipt) { t.Fatal("compile mutated inputs") }
```

- [ ] **Step 2: Write table-driven fail-closed binding tests**

Each case mutates exactly one field and asserts the precise non-verified status/reason with `Finding == nil`:

- unknown verifier ID → `INVALID` / `UNTRUSTED_VERIFIER`;
- version, config, kind, or coverage mismatch → `INVALID` / `VERIFIER_IDENTITY_MISMATCH`;
- trusted semantic scout → `INVALID` / `NONDETERMINISTIC_VERIFIER`;
- claim absent from coverage → `INDETERMINATE` / `CLAIM_NOT_COVERED`;
- hypothesis digest mismatch → `INVALID` / `HYPOTHESIS_DIGEST_MISMATCH`;
- artifact mismatch → `INVALID` / `ARTIFACT_DIGEST_MISMATCH`;
- impact-slice mismatch → `INVALID` / `IMPACT_SLICE_DIGEST_MISMATCH`;
- execution input missing or not SHA-256 → `INVALID` / `EXECUTION_INPUT_DIGEST_MISMATCH`;
- missing/invalid evidence → `INVALID` / `EVIDENCE_INVALID`.

- [ ] **Step 3: Write status-contract tests**

Assert:

- `VERIFIED` requires evidence and an unspecified reason;
- `REJECTED` requires `HYPOTHESIS_REJECTED`, returns `REJECTED`, and no finding;
- `INDETERMINATE` accepts only operational reasons (`VERIFIER_UNAVAILABLE`, `VERIFIER_TIMEOUT`, `CONFLICTING_RESULTS`), returns `INDETERMINATE`, and no finding;
- unspecified/unknown statuses and invalid reason combinations return `INVALID` / `MALFORMED_CONTRACT`;
- caller-supplied receipt and finding IDs are empty or must match compiler-computed lowercase hex IDs.

- [ ] **Step 4: Run compiler tests to verify they fail**

Run: `go test ./internal/review -run 'TestCompiler' -count=1`

Expected: FAIL because `Compiler` does not exist.

- [ ] **Step 5: Implement ordered compilation**

```go
type Compiler struct { registry *Registry }

func NewCompiler(registry *Registry) (*Compiler, error) {
    if registry == nil { return nil, errors.New("review verifier registry is required") }
    return &Compiler{registry: registry}, nil
}

func (c *Compiler) Compile(h *roomv1.ReviewHypothesis, r *roomv1.ReviewVerificationReceipt) (*roomv1.ReviewCompilationResult, error)
```

Follow the specification's nine validation steps in order. Expected trust, binding, evidence, and status failures return `ReviewCompilationResult` with a typed status/reason and nil Go error. Only deterministic marshaling or impossible internal invariant failures return a Go error.

For verified results, clone canonical values, set the canonical receipt ID to lowercase hex of `ReceiptDigest`, and compute the finding ID as:

```go
sum := sha256.New()
_, _ = sum.Write([]byte("room.review.finding.v1"))
_, _ = sum.Write([]byte{0})
_, _ = sum.Write(hypothesisDigest)
verifierBytes, err := deterministicMarshal.Marshal(canonicalVerifier)
if err != nil { return nil, err }
_, _ = sum.Write(verifierBytes)
_, _ = sum.Write(evidenceSetDigest)
findingID := hex.EncodeToString(sum.Sum(nil))
```

The compiler must never branch on `Invariant`, `Impact`, `Remediation`, `Description`, or other presentation prose.

- [ ] **Step 6: Run all review package tests**

Run: `go test ./internal/review -count=1`

Expected: PASS.

- [ ] **Step 7: Document the authority boundary**

Append to the review-intelligence section of `docs/architecture.md`:

```markdown
Review discovery and review authority are separate. A scout or reviewer may emit
a typed `ReviewHypothesis`, but it remains advisory until an exact trusted
deterministic verifier returns a receipt bound to the hypothesis, repository
artifact, impact slice, execution input, declared claim coverage, and
content-addressed evidence. The pure review compiler returns verified, rejected,
indeterminate, or invalid; only a verified finding is eligible for later policy
integration. Model identity, confidence, agreement, and presentation prose never
grant verifier authority.
```

- [ ] **Step 8: Run focused race and vet checks**

Run: `go test -race ./internal/review -count=1 && go vet ./internal/review`

Expected: PASS.

- [ ] **Step 9: Commit the compiler**

```bash
git add internal/review/compiler.go internal/review/compiler_test.go docs/architecture.md
git commit -m "feat: compile verified review evidence"
```

### Task 5: Verify, guard, and prepare Slice 1 for merge

**Files:**
- Inspect: all files changed since `origin/main`
- Modify only if a verification failure identifies a causal defect.

**Interfaces:**
- Consumes: the complete Slice 1 diff.
- Produces: clean generated code, passing repository checks, Room `allow`, and a merge-ready branch.

- [ ] **Step 1: Verify formatting and generated-code consistency**

Run:

```bash
gofmt -w internal/review/*.go
buf lint
buf generate
git diff --check
git status --short
```

Expected: Go files are formatted; Buf passes; generation introduces no uncommitted generated-code drift beyond intentional source edits.

- [ ] **Step 2: Run the complete relevant check set**

Run:

```bash
go test ./...
go test -race ./...
go vet ./...
```

Expected: all commands PASS. If a pre-existing failure appears, demonstrate it on `origin/main` before classifying it as pre-existing.

- [ ] **Step 3: Review the exact branch diff**

Run:

```bash
git diff --stat origin/main...HEAD
git diff --check origin/main...HEAD
git status --short
```

Expected: only the design, plan, contract, generated bindings, review package, fixture, and architecture documentation are changed; the worktree is clean after any final verification commit.

- [ ] **Step 4: Run Room's required final diff analysis**

Call `room_check_diff` with the complete `origin/main...HEAD` diff and all changed files.

Expected: `analysis_status=complete`, `decision=allow`, and `blocking=false`. Any `deny`, `needs_changes`, or `indeterminate` is blocking: fix the causal issue and rerun the complete relevant checks and Room analysis.

- [ ] **Step 5: Commit any verification-only correction**

If Step 1 changed formatting or generated output:

```bash
git add internal/review gen/go/room/v1 proto/room/v1 docs
git commit -m "chore: finalize review evidence foundation"
```

If there is no diff, do not create an empty commit.

- [ ] **Step 6: Push, open the PR, and merge only after GitHub checks pass**

```bash
git push -u origin feat/evidence-review-foundation
gh pr create --base main --head feat/evidence-review-foundation --title "Add review evidence authority foundation" --body-file /tmp/room-review-evidence-pr.md
gh pr checks --watch <PR_NUMBER>
gh pr merge <PR_NUMBER> --merge --delete-branch
```

The PR body must summarize the two-plane authority boundary, enumerate verification, state that no policy behavior is activated, and include the Room audit/evaluation IDs. Address concrete review feedback with tests and rerun Room after every material diff revision. Never bypass required checks or use force push.
