# Review Evidence Foundation

**Parent design:** [Evidence-Compiled Review System](2026-07-14-evidence-compiled-review-design.md)

**Slice:** 1 of 5

## Goal

Add the typed contract and pure authority compiler that separates an advisory review hypothesis from a verifier-backed finding. The implementation must make it impossible for model output alone to become blocking evidence, while preserving Room's existing analyzer, review-intelligence, policy, and rollout behavior.

## Scope

This slice includes:

- Protobuf contracts for review hypotheses, evidence references, verifier identity and coverage, verification receipts, typed rejection/gap reasons, and verified findings.
- A deterministic Go package that canonicalizes inputs, validates trust and exact bindings, and compiles a verification result.
- An explicit in-memory trusted-verifier registry used by the compiler.
- Stable SHA-256 identities for hypotheses, evidence sets, receipts, and verified findings.
- Exhaustive unit tests and replay fixtures for authority transitions.
- Architecture and contract documentation.

This slice deliberately excludes:

- Running repository commands or external verifier processes.
- Building repository impact graphs.
- Invoking models or semantic scouts.
- Persisting or serving verified findings.
- Activating new blocking policy or changing existing evaluation decisions.
- Learning or promoting policy candidates from verified findings.

## Existing contracts reused

Room already has two adjacent systems:

1. `AnalyzerReceipt` binds a trusted analyzer identity to an artifact digest and typed `SignalKind` coverage.
2. `ReviewFinding` stores a typed claim plus outcomes and adjudications for candidate inference.

The new contract follows the analyzer trust pattern but does not overload `AnalyzerReceipt`. Security signals and review claims have different taxonomies and lifecycles. Existing `ReviewFinding` remains the durable intelligence record; later integration will project a `VerifiedReviewFinding` into that record without letting presentation fields classify it.

No existing field changes meaning in this slice.

## Typed contract

### `ReviewHypothesis`

A scout- or human-proposed claim. Required authority bindings are:

- typed `ReviewClaimKind`;
- authenticated `ReviewSource` with repository and head SHA;
- artifact SHA-256;
- impact-slice SHA-256;
- canonical affected paths and optional typed source locations;
- invariant, preconditions, causal path, impact, and remediation as presentation fields;
- producer identity and configuration digest;
- creation timestamp.

Room computes the hypothesis ID from deterministic serialization of the authority-bearing fields. Caller-provided IDs are either empty or must match the computed value.

### `ReviewEvidenceRef`

Evidence has a typed kind, a stable logical name, a SHA-256 content digest, and an optional source location or command/test identifier. Initial kinds are:

- source location;
- symbol or call-path trace;
- schema or protocol contract;
- command or test result;
- replay or mutation fixture;
- generated-artifact provenance.

Presentation text is optional and is excluded from authority classification. Every accepted reference must have a content digest. Duplicate logical identities or digests with conflicting payloads are invalid.

### `ReviewVerifierIdentity`

A verifier is trusted by an exact tuple:

- ID;
- version;
- configuration SHA-256;
- verifier kind;
- covered `ReviewClaimKind` values.

The only verifier kind eligible to authorize a verified finding in this slice is `DETERMINISTIC`. `SEMANTIC_SCOUT` identities may be recorded as hypothesis producers but cannot authorize blocking evidence.

### `ReviewVerificationReceipt`

A receipt binds:

- the exact verifier identity;
- hypothesis SHA-256;
- repository artifact SHA-256;
- impact-slice SHA-256;
- typed verification status;
- evidence references;
- execution-input SHA-256;
- completion timestamp;
- typed reason code for rejected or indeterminate results.

Statuses are `VERIFIED`, `REJECTED`, and `INDETERMINATE`. `VERIFIED` requires non-empty evidence and no failure reason. `REJECTED` or `INDETERMINATE` requires a typed reason and cannot produce a verified finding.

### `VerifiedReviewFinding`

A successful compile result contains the canonical hypothesis, canonical receipt, stable finding ID, and the evidence-set SHA-256. It is an authority record, not yet an active policy decision. Later slices may persist it and present it to existing scoped policy.

### Typed compile result

The compiler always returns a typed result rather than using an error for an expected verification outcome:

- `VERIFIED`: an eligible `VerifiedReviewFinding` exists.
- `REJECTED`: the verifier deterministically disproved or invalidated the hypothesis.
- `INDETERMINATE`: authority could not be established.
- `INVALID`: the contract or trust binding is malformed.

Programming or serialization failures remain Go errors. This keeps operational failures distinct from review outcomes.

## Authority compiler

The package API is intentionally pure:

```go
type Compiler struct {
    registry Registry
}

func (c *Compiler) Compile(
    hypothesis *roomv1.ReviewHypothesis,
    receipt *roomv1.ReviewVerificationReceipt,
) (*roomv1.ReviewCompilationResult, error)
```

Compilation performs these checks in order:

1. Validate required typed fields, enum values, timestamps, SHA-256 lengths, normalized paths, and confidence ranges.
2. Deterministically canonicalize set-like fields and reject conflicting duplicates.
3. Recompute and compare the hypothesis digest.
4. Resolve the verifier from the registry by exact identity tuple.
5. Require deterministic verifier kind and coverage for the hypothesis claim kind.
6. Require exact hypothesis, artifact, impact-slice, and execution-input bindings.
7. Validate status-specific fields and evidence.
8. Compute the evidence-set, receipt, and verified-finding digests.
9. Return a typed result without mutating inputs or external state.

The compiler does not inspect invariant or remediation prose to choose a claim kind, verifier, severity, or outcome.

## Canonicalization and stable identity

All digests use deterministic Protobuf serialization after normalization. Authority-bearing repeated fields that are semantically sets—affected paths, locations, coverage, and evidence references—are sorted by stable typed keys. Ordered causal paths and preconditions preserve their input order because order can be semantically meaningful.

Timestamps and presentation-only text are excluded from stable finding identity so rerunning the same deterministic claim does not create a new logical finding. They remain in the stored receipt digest for audit integrity.

Stable identities are domain-separated:

```text
room.review.hypothesis.v1 || deterministic-proto(authority fields)
room.review.evidence-set.v1 || deterministic-proto(canonical evidence)
room.review.receipt.v1 || deterministic-proto(full receipt)
room.review.finding.v1 || hypothesis digest || verifier tuple || evidence-set digest
```

IDs use lowercase hexadecimal SHA-256. Domain separation prevents a digest from one record class being reused as another.

## Registry behavior

The initial registry is immutable after construction. It rejects:

- blank IDs or versions;
- missing or non-SHA-256 configuration digests;
- unspecified verifier kinds;
- unspecified or duplicate claim coverage;
- conflicting entries for the same ID;
- semantic scouts registered as deterministic verifiers.

Lookup requires complete identity equality. ID-only trust is forbidden. Runtime configuration and persistence are deferred until the execution adapter slice; the pure constructor is sufficient to make trust behavior testable now.

## Error and gap taxonomy

Typed reason codes must cover at least:

- untrusted verifier;
- verifier identity or configuration mismatch;
- claim kind not covered;
- nondeterministic verifier;
- hypothesis digest mismatch;
- artifact digest mismatch;
- impact-slice digest mismatch;
- execution-input digest mismatch;
- evidence missing or invalid;
- verifier rejected hypothesis;
- verifier unavailable or timed out;
- conflicting deterministic results;
- malformed contract.

Reasons are enums. User-facing messages may be generated from them, but message text is never parsed back into behavior.

## Compatibility and migration

- Existing analyzer and policy APIs remain unchanged.
- Existing `ReviewFinding` ingestion and intelligence behavior remain unchanged.
- Protobuf additions use new field numbers and enum values only.
- Generated Go and Connect code are regenerated and checked into the repository.
- No SQLite migration is required because this slice adds no persistence.

Later integration must treat legacy review findings without a verified authority record as advisory historical evidence, not retroactively verified findings.

## Test strategy

### Successful authority

- A trusted deterministic verifier with exact coverage compiles a valid hypothesis and evidence set.
- Equivalent set ordering produces the same stable identities.
- Input messages are not mutated.
- Deterministic serialization produces byte-for-byte stable fixture digests.

### Fail-closed bindings

Table-driven tests cover untrusted ID, version mismatch, configuration mismatch, uncovered claim kind, semantic verifier kind, and every hypothesis/artifact/slice/execution digest mismatch. None may produce a verified finding.

### Status behavior

- `VERIFIED` without evidence is invalid.
- `VERIFIED` with a failure reason is invalid.
- `REJECTED` and `INDETERMINATE` return their typed status and no finding.
- Unknown enum values are invalid.

### Evidence validation

Tests cover missing digests, invalid locations, path traversal, conflicting duplicate IDs, duplicate evidence normalization, and presentation-text changes that do not alter authority classification.

### Regression fixture

Check in a small deterministic fixture representing a cross-file authorization-boundary claim. It includes canonical hypothesis, verifier, evidence, and expected digests. This becomes the compatibility anchor for later execution and persistence slices.

### Repository verification

Run:

```bash
buf lint
buf generate
git diff --exit-code -- '*.pb.go'
go test ./...
go test -race ./...
go vet ./...
```

The generated-code cleanliness check is run after generation against the committed source state during final verification.

## Delivery criteria

This slice is done when:

- the contracts and compiler implement the authority boundary above;
- all success, rejection, invalid, and indeterminate paths are covered by deterministic tests;
- existing behavior and tests remain intact;
- documentation explains how the new receipt relates to existing analyzer receipts;
- Room approves the implementation plan and final diff;
- repository checks and GitHub review pass;
- the change is merged without activating new blocking policy.
