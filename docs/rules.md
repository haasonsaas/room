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
