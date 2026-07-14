# Architecture

Room separates authority, analysis, and policy evaluation.

```text
admin credential -> rule/MCP policy publication -> immutable scoped ruleset
agent credential -> raw plan or diff -> trusted analyzer -> typed receipt
typed receipt + verified credential scope + ruleset -> decision -> SQLite audit
typed MCP identity + MCP policy -> decision -> SQLite audit
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

SQLite stores protobuf snapshots and append-only audit rows. WAL mode, private
file permissions, idempotent event IDs, and payload digests provide durable local
operation. Existing JSON stores are preserved as `.legacy.json`, migrated once,
and known legacy heuristic rules are converted to typed signal rules.
