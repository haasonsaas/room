# Agent Hooks

Room uses one hook runner for all agent surfaces:

```bash
roomctl hook prompt
roomctl hook pre-tool
roomctl hook post-tool
```

The runner accepts the agent hook payload on stdin, forwards it to Room, and
prints a hook decision shape accepted by Codex and Claude Code for blocking
tool calls or injecting additional context.

## Claude Code

Claude Code supports `PreToolUse`, `PostToolUse`, and `UserPromptSubmit`
hooks. Project-level hooks live in `.claude/settings.json`.

Use `hooks/claude/settings.json` as a starting point.

## Codex

Codex supports repo-local `.codex/hooks.json` and inline `config.toml` hooks.
Use `/hooks` in Codex to review and trust changed command hooks.

Use `hooks/codex/hooks.json` as a starting point.

## Cursor

Cursor supports hooks and MCP. The exact hook management surface can vary by
Cursor release and plan, so Room ships a generic command runner plus
`hooks/cursor/README.md`. Configure Cursor to call `roomctl hook prompt`,
`roomctl hook pre-tool`, and `roomctl hook post-tool` from the matching Cursor
events, and register `room-mcp` as the MCP server.

## Fail-open vs fail-closed

Default:

```bash
ROOM_HOOK_FAIL_CLOSED=false
```

Strict mode:

```bash
ROOM_HOOK_FAIL_CLOSED=true
```

Strict mode denies pre-tool calls when Room is unavailable.

