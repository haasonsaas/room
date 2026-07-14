# Agent hooks

Room exposes one authenticated runner:

```bash
roomctl hook prompt
roomctl hook pre-tool
roomctl hook pre-mcp
roomctl hook post-tool
```

Set `ROOM_TOKEN_FILE` to a private agent-token file. The credential fixes the
workspace, repository, and agent identity; hook payloads cannot change them.
Issue hook credentials with an explicit provider binding, for example
`roomctl token issue ... --hook-provider codex`. A direct verified MCP proxy uses
the mutually exclusive `--mcp-proxy` capability.

Hooks fail closed when Room or its analyzer is unavailable, or when a result is
indeterminate. Emergency fail-open behavior requires an explicit opt-out:

```bash
ROOM_HOOK_FAIL_OPEN=true
```

The bundled Claude and Codex templates cover prompt and built-in edit/shell
lifecycle events. They do not claim MCP interception: provider hooks do not
emit Room's typed MCP envelope by themselves.

## Typed MCP hook metadata

Register `pre-tool` only for non-MCP tool matchers. A trusted provider adapter or
verified proxy may invoke `pre-mcp` for MCP events; it requires
`room_mcp_invocation` and fails closed when the typed object is absent. The
bundled generic hook templates cannot manufacture that identity and therefore
do not advertise MCP governance. This explicit boundary prevents an
unclassified pre-tool event from being mislabeled as verified MCP traffic.

A pre-tool payload may include a `room_mcp_invocation` object with the typed
fields `provider_tool_id`, `server_id`, `tool_name`, `transport`, and `endpoint`.
Room ignores caller-supplied provider and assurance values: those come from the
credential's `--hook-provider` or `--mcp-proxy` capability. Provider/tool
bindings must already exist in the Room MCP policy. Provider display text and
ordinary `tool_name` fields are not parsed to infer MCP identity.

For the strongest guarantee, route MCP through a proxy that calls
`EvaluateMcpInvocation` with transport-verified identity. Room provides the
typed enforcement endpoint and `--mcp-proxy` credential capability; the proxy
itself remains an integration owned by the MCP deployment.
