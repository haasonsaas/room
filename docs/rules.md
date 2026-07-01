# Rules

Rules are ordinary protobuf messages and can be managed through
`RuleAdminService`.

The bundled dashboard at `http://localhost:8787` can create, update, delete,
preview, and publish rules without a separate frontend build.

Minimal JSON payload for `CreateRule`:

```json
{
  "rule": {
    "id": "tenant-org-scope-required",
    "title": "Tenant data must be organization scoped",
    "description": "Tenant reads and writes must derive organization scope from trusted auth context.",
    "severity": "SEVERITY_CRITICAL",
    "tags": ["security", "tenancy"],
    "enabled": true,
    "checks": [
      {
        "kind": "CHECK_KIND_HEURISTIC",
        "expression": "touches_tenant_data_without_scope"
      }
    ],
    "requiredEvidence": [
      "organization_id/workspace_id comes from authenticated context",
      "query filters by organization/workspace",
      "cross-organization denial test is present"
    ],
    "remediation": [
      "use an org-scoped repository/helper",
      "reject request-body organization ids unless membership is verified"
    ]
  }
}
```

Publish after edits:

```bash
curl \
  -H 'content-type: application/json' \
  -d '{"author":"you","notes":"tighten tenant rules"}' \
  http://localhost:8787/room.v1.RuleAdminService/PublishRuleset
```

## Bundled Rust rules

New Room stores publish the generic security rules plus Rust-specific guardrails:

- `rust-unsafe-requires-safety-rationale`: flags unsafe Rust without a nearby safety rationale.
- `rust-request-paths-must-not-unwrap`: flags `unwrap` or `expect` in handlers, routes, and API request paths.
- `rust-command-exec-requires-allowlist`: flags process execution that passes request-controlled arguments without an allowlist.
- `rust-secrets-require-crypto-rng`: flags token, nonce, session, password-reset, and API-key generation that uses non-cryptographic randomness.
- `rust-paths-must-be-canonicalized`: flags user-controlled file paths without canonicalization and trusted-base checks.
- `rust-library-api-must-not-panic`: flags `panic!`, `todo!`, `unimplemented!`, and `unreachable!` in library, service, and API code paths.
- `rust-no-std-mutex-across-await`: flags blocking mutex/RwLock usage across async await points.
- `rust-serde-external-input-deny-unknown-fields`: flags external JSON payload deserialization without `deny_unknown_fields` or explicit validation.

Each of these rules uses a `CHECK_KIND_HEURISTIC` expression, so the dashboard
can edit severity, tags, evidence, and remediation without changing code.
