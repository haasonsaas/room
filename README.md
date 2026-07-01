# Room

Room is a standalone guardrail control plane for coding agents.

It gives teams a central place to define secure-coding rules, publish immutable
ruleset versions, and expose those rules to Cursor, Claude Code, Codex, and other
MCP-capable agents before they make implementation choices.

## What it includes

- ConnectRPC + Protobuf API for rule administration and agent consumption.
- A local MCP sidecar with `room_get_rules`, `room_analyze_plan`, and `room_check_diff`.
- A small dashboard at `/` for previewing active rules and publishing versions.
- Hook runner support through `roomctl hook`.
- Example hook templates for Claude Code, Codex, and Cursor-style command hooks.
- A starter security ruleset for tenant scoping, secrets, and destructive actions.

## Run locally

```bash
go run ./cmd/roomd
```

Open `http://localhost:8787`.

Run the MCP sidecar in a second terminal:

```bash
ROOM_ADDR=:8788 ROOM_SERVER_URL=http://localhost:8787 go run ./cmd/room-mcp
```

Register the MCP endpoint with your agent as `http://localhost:8788/mcp`.

## Hook runner

`roomctl` reads hook JSON on stdin and evaluates it against the active Room
ruleset:

```bash
go install ./cmd/roomctl
roomctl hook pre-tool < hook-payload.json
roomctl hook post-tool < hook-payload.json
roomctl hook prompt < hook-payload.json
```

By default hooks fail open if Room is unavailable. Set
`ROOM_HOOK_FAIL_CLOSED=true` to deny when the control plane cannot be reached.

## ConnectRPC services

The core protobuf lives in `proto/room/v1/rules.proto`.

- `RuleAdminService`: create/update/delete/list rules, preview, publish, rollback.
- `AgentRulesService`: get/watch active rulesets, evaluate plans/diffs, report results.

Generate code after proto changes:

```bash
PATH="$HOME/go/bin:$PATH" buf generate
```

## Rule expression MVP

Room currently supports these simple rule expressions:

- `contains_any:a,b,c`
- `missing_any:a,b,c`
- `regex:<pattern>`
- `always`
- heuristics:
  - `touches_tenant_data_without_scope`
  - `secret_literal`
  - `destructive_shell`

The intent is to keep the public MVP deterministic and easy to audit, then add
Semgrep, AST, and policy-engine integrations behind the same protobuf contract.

## Repository status

This is an early standalone scaffold. The API shape is intentionally small and
versioned so the dashboard, MCP server, and hooks can evolve without coupling to
any existing internal platform.

