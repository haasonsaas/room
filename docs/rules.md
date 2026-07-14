# Rules and MCP policy

Rules select typed analyzer signals. Room converts the exact legacy v1 check
identifiers it previously shipped into typed signals during import or update;
unknown/free-form checks are rejected rather than executed as text policy.

Minimal `CreateRule` JSON:

```json
{
  "rule": {
    "id": "auth-context-required",
    "title": "Protected handlers require auth context",
    "description": "Protected access without a verified principal is prohibited.",
    "severity": "SEVERITY_HIGH",
    "tags": ["security", "authorization"],
    "enabled": true,
    "scope": { "paths": ["app/**", "internal/**", "src/**"] },
    "triggers": [{
      "signal": "SIGNAL_KIND_PROTECTED_ACCESS_WITHOUT_AUTH_CONTEXT",
      "phases": ["ANALYSIS_PHASE_PLAN", "ANALYSIS_PHASE_DIFF"],
      "minimumConfidenceBasisPoints": 8000
    }],
    "requiredCoverage": ["SIGNAL_KIND_PROTECTED_ACCESS_WITHOUT_AUTH_CONTEXT"],
    "requiredEvidence": ["unauthenticated request coverage"],
    "remediation": ["derive authorization from trusted middleware"]
  }
}
```

Admin API calls require an admin bearer token:

```bash
curl -H "Authorization: Bearer $(cat .room/admin.token)" \
  -H 'content-type: application/json' \
  -d '{"author":"you","notes":"publish typed rules"}' \
  http://127.0.0.1:8787/room.v1.RuleAdminService/PublishRuleset
```

The MCP policy supports disabled, allowlist, and blocklist modes. Its default is
an empty allowlist with unknown identities denied. Selectors match exact
`server_id`/`tool_name` values or a whole-field `*`; provider bindings map one
opaque provider tool ID to one canonical server/tool identity. Duplicate
selectors and bindings are rejected.

Every policy update, ruleset publication/rollback, evaluation, and MCP decision
is written to the audit log. Admins can query it through `ListAuditEvents` or
`GET /api/audit`.
