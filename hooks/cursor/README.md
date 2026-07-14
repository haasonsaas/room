# Cursor Hook Integration

Room exposes the same command runner for Cursor:

```bash
roomctl hook prompt
roomctl hook pre-tool
roomctl hook pre-mcp
roomctl hook post-tool
```

Recommended setup:

1. Run `roomd`.
2. Run `room-mcp` and register it as a Cursor MCP server.
3. Configure Cursor hooks to call the command matching the lifecycle event:
   - prompt/user-message event: `roomctl hook prompt`
   - before built-in edit/shell execution: `roomctl hook pre-tool`
   - when a trusted adapter supplies typed `room_mcp_invocation`, before MCP
     execution: `roomctl hook pre-mcp`
   - after edit/tool execution: `roomctl hook post-tool`

The hook runner accepts JSON on stdin and emits either additional context or a
blocking decision. If your Cursor version expects a different output shape, keep
the command invocation and adapt only `cmd/roomctl`.

The generic Cursor hook does not infer MCP identity from a displayed tool name.
Use `pre-mcp` only behind a trusted adapter, or enforce MCP through a verified
proxy calling Room's typed `EvaluateMcpInvocation` endpoint.
