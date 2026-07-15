# Evidence-Compiled Review System

**Status:** Approved for phased implementation

**Product boundary:** Room is a plugin and self-hosted guardrail control plane for coding agents. It is not a code-review company or an autonomous policy owner.

## Objective

Make high-quality engineering review repeatable across EvalOps repositories by combining broad semantic discovery with deterministic evidence and policy enforcement. Room should catch consequential defects that conventional linters miss—authorization and tenancy drift, protocol violations, migration semantics, state-machine failures, cross-file contract drift, operational hazards, and missing negative tests—without allowing model confidence or persuasive prose to become blocking authority.

The system optimizes for four properties:

1. **Broad discovery.** Semantic scouts can search for novel, cross-file failure modes.
2. **Evidence-deterministic blocking.** A blocking result is reproducible from immutable inputs, an explicitly trusted verifier, and typed evidence.
3. **Human-controlled policy.** Organization-wide blocking policy remains subject to Room's existing scoped credential, confirmation, rollout, and audit boundaries.
4. **Compounding coverage.** Repeated valid findings become candidate deterministic checks, evaluated against historical cases before staged rollout.

## Non-goals

- Style, naming, formatting, or preference enforcement.
- Treating model agreement, model confidence, or reviewer reputation as proof.
- Automatically publishing or promoting protected organization-wide blocking policy.
- Replacing repository-native tests, linters, type checkers, or CI.
- Claiming deterministic discovery. Discovery quality is measured statistically; only the evidence and authority path is deterministic.

## Design principles

### Two-plane authority model

Room separates discovery from authority.

```text
repository artifact + impact slice
              |
              v
    semantic discovery plane
   (structured hypotheses only)
              |
              v
      verifier registry ------ trusted config + claim coverage
              |                              |
              v                              v
     typed verifier receipt + immutable evidence references
              |
              v
        authority compiler
              |
              v
  advisory finding / verified finding / indeterminate
              |
              v
 existing scoped policy + rollout + human confirmation + audit
```

Semantic scouts may propose hypotheses and rank them. They may not mint trusted verifier identities, claim coverage they do not have, or convert an indeterminate result into an allow or a block. The authority compiler accepts only exact bindings to the repository artifact, hypothesis, verifier identity/version/configuration, and evidence digests.

### Evidence, not explanation

Prose fields remain presentation data. Authority derives from typed fields:

- repository and head SHA;
- artifact digest and bounded input slice;
- typed claim kind;
- trusted verifier identity, version, and configuration digest;
- declared claim coverage;
- verification status;
- typed evidence references and their digests;
- stable canonical finding identity.

An explanation can help a human understand a finding, but it cannot change the finding's authority.

### Fail closed at authority boundaries

No failed authority binding is silently accepted as verified. Missing, unavailable, timed-out, conflicting, or uncovered verification is `indeterminate`; malformed, untrusted, stale, or mismatched contracts are `invalid`. Existing policy decides how a non-verified result affects a caller; the review subsystem does not invent fallback authority.

## Phased architecture

### Slice 1: typed evidence and verifier foundation

Introduce the contracts and pure validation/compiler layer that distinguish hypotheses from verified findings. This slice adds no repository command execution and does not activate new blocking policy. Its detailed design is in [Review Evidence Foundation](2026-07-14-review-evidence-foundation-design.md).

### Slice 2: repository impact compiler

Produce a deterministic, digest-addressed evidence slice from a repository change. The compiler will map changed symbols and schemas to callers, implementations, tests, migrations, generated artifacts, deployment configuration, and repository contracts. Every included edge carries its source and digest. Unknown or budget-truncated edges are explicit gaps.

Initial adapters should favor repository-native, deterministic sources:

- Git diff and merge-base metadata;
- language parser and symbol-index output;
- package/module dependency graphs;
- database migration and schema metadata;
- generated-file provenance;
- CI, deployment, and runtime configuration;
- repository review contracts and test manifests.

### Slice 3: semantic scout protocol and evaluation harness

Run one or more advisory scouts over the same bounded impact slice. Scouts emit only the typed hypothesis contract. A council may improve recall or rank hypotheses, but votes and confidence remain advisory.

Discovery changes ship only with a versioned evaluation corpus and measured:

- recall by claim kind;
- false-positive rate and reviewer acceptance;
- cost and latency distributions;
- calibration by confidence bucket;
- disagreement and verifier-yield rates;
- regressions against previously caught cases.

Scout prompts, model identities, tool availability, slice digests, and outputs are recorded for replay. No statistical target changes the deterministic authority boundary.

### Slice 4: finding-to-check learning loop

Compile repeated, adjudicated, verified finding classes into draft policy artifacts. Prefer deterministic checks when a stable predicate and fixture can be synthesized. Otherwise produce a semantic-analyzer candidate or a documented one-off invariant.

Each candidate carries:

- source finding and evidence identities;
- generated positive, negative, and mutation fixtures;
- replay metrics and known blind spots;
- expected runtime and operational cost;
- rollout state from draft through shadow and warn;
- an explicit human-controlled transition for protected blocking policy.

This extends Room's current candidate/replay/tuning machinery. It does not create a parallel policy lifecycle.

### Slice 5: lifecycle and control-plane integration

Surface evidence chains, gaps, replay results, and learned-check provenance in hooks, MCP responses, and the control plane. A user should be able to answer:

- What invariant is claimed to fail?
- What exact repository state was reviewed?
- Which deterministic verifier established it?
- What evidence can I reproduce?
- Which policy decision used the result?
- Which prior findings taught Room this check?
- Who confirmed or changed organization-wide enforcement?

## Core data flow

1. Room authenticates repository and actor scope from the credential, never caller text.
2. The impact compiler binds a repository artifact and emits a digest-addressed slice plus explicit gaps.
3. Scouts emit typed hypotheses bound to that slice.
4. Registered verifiers evaluate hypotheses within declared claim coverage.
5. The authority compiler validates receipts and evidence, then emits a verified finding, a rejection, or an indeterminate result.
6. Existing policy evaluates eligible verified findings and analyzer signals under scoped rollout rules.
7. Room persists the complete provenance and decision audit.
8. Outcomes and adjudications feed the existing intelligence system; eligible repeated findings may become draft checks.

## Security and trust boundaries

- Repository, organization, agent, and actor scope come only from authenticated credentials and server-owned repository state.
- Verifier trust is an exact tuple of ID, version, configuration digest, deterministic kind, and claim coverage.
- A scout cannot self-identify as a trusted verifier.
- Evidence references are content-addressed and validated; unbound URLs or prose citations do not authorize blocking.
- Receipts bind the precise hypothesis and artifact. Reusing a receipt on another head or configuration fails validation.
- Time, network access, randomness, and ambient filesystem state are excluded from deterministic verifier inputs unless materialized and hashed into the artifact.
- Organization-wide blocking, pause, rollback, and emergency controls retain Room's existing credential-backed human confirmation and audit workflow.

## Failure behavior

- Impact graph incomplete: emit explicit gaps; uncovered hypotheses are advisory or indeterminate.
- Scout unavailable: preserve deterministic checks and report discovery coverage loss.
- Verifier unavailable or timed out: indeterminate for its declared coverage.
- Receipt mismatch or malformed evidence: reject the receipt and record a typed reason.
- Conflicting verifier results: no blocking authority until policy-defined deterministic precedence resolves them; default is indeterminate.
- Storage or audit failure: fail the mutation atomically.

## Delivery and merge strategy

Each slice is a separate, reviewable change with its own detailed design, implementation plan, Room plan/diff approvals, regression tests, and repository verification. A slice must merge before dependent slices begin. This keeps the authority boundary independently auditable and prevents an unfinished discovery system from gaining enforcement power.

## Success criteria

The program is complete when Room can review an EvalOps repository change end-to-end, discover consequential cross-file hypotheses, prove eligible findings with replayable verifier evidence, enforce only according to scoped policy, learn candidate checks from adjudicated history, and show the complete provenance in the control plane—with deterministic regression fixtures covering every authority transition.
