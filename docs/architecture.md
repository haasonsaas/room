# Architecture

Room separates authority, analysis, and policy evaluation.

```text
admin credential -> rule/MCP policy publication -> immutable scoped ruleset
agent credential -> raw plan or diff -> trusted analyzer -> typed receipt
typed receipt + verified credential scope + ruleset -> decision -> SQLite audit
typed MCP identity + MCP policy -> decision -> SQLite audit
typed review claim + durable outcomes/adjudication -> candidate -> replay -> staged rollout
```

The authenticated agent credential is authoritative for workspace, repository,
agent, and subject identity. Caller-supplied identity fields are overwritten.
Returned rulesets include that authorized scope and a scope-specific hash, so a
cache from one credential cannot masquerade as another scope.

The analyzer is the only component that receives raw plans and diffs. The policy
engine accepts fixed `SignalKind` values, analyzer identity/config digests,
coverage receipts, artifact hashes, analyzer-stamped language/framework
classification, and confidence values. Caller-supplied classification cannot
narrow scoped rules. Missing, partial, invalid, or untrusted analysis produces
`INDETERMINATE`, not an implicit allow.

MCP governance likewise consumes typed identity. Direct proxies can provide
transport-verified server/tool identity; hook adapters must use explicit provider
bindings. Room never splits or interprets display names such as
`mcp__server__tool`.

Review intelligence follows the same boundary. Presentation fields such as the
review comment, invariant explanation, title, and remediation copy are never
used to classify a finding. Inference groups explicit `ReviewClaimKind` values;
labels come from typed outcome events and immutable agent adjudications. A fix
or resolution is the conservative positive floor, weighted outcomes broaden the
evidence, and the latest adjudication per agent can accept, reject, or mark a
finding as one-off. Policy artifact selection and replay behavior are determined
by typed enums and confidence thresholds.

Candidates are drafts, not active rules. Historical replay records a confusion
matrix and estimated reviewer cost/token savings. Autonomous tuning may adjust
the threshold or roll back an unhealthy candidate. Rollout is an explicit state
machine, and the service enforces the human-only boundary for protected
organization-wide blocking policy transitions and emergency controls. The
boundary is credential-backed: an admin token must be issued with the explicit
`human_operator` capability, and the mutation must carry a separate typed
confirmation. A request boolean alone cannot manufacture human authority.

SQLite stores protobuf snapshots and append-only audit rows. WAL mode, private
file permissions, idempotent event IDs, and payload digests provide durable local
operation. Existing JSON stores are preserved as `.legacy.json`, migrated once,
and known legacy heuristic rules are converted to typed signal rules.
Review findings, candidates, replay runs, and tuning decisions live in dedicated
indexed tables as deterministic protobuf payloads with SHA-256 digests; outcome
and adjudication additions are validated and persisted through typed store APIs.

Review discovery and review authority are separate. A scout or reviewer may emit
a typed `ReviewHypothesis`, but it remains advisory until an exact trusted
deterministic verifier returns a receipt bound to the hypothesis, repository
artifact, impact slice, execution input, declared claim coverage, and
content-addressed evidence. The pure review compiler returns verified, rejected,
indeterminate, or invalid; only a verified finding is eligible for later policy
integration. Model identity, confidence, agreement, and presentation prose never
grant verifier authority.
