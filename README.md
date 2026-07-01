# Room

Room is a standalone guardrail control plane for coding agents.

It gives teams a central place to define secure-coding rules, publish immutable
ruleset versions, and expose those rules to Cursor, Claude Code, Codex, and other
MCP-capable agents before they make implementation choices.

## What it includes

- ConnectRPC + Protobuf API for rule administration and agent consumption.
- A local MCP sidecar with `room_get_rules`, `room_analyze_plan`, and `room_check_diff`.
- A small dashboard at `/` for creating, editing, deleting, previewing, and publishing rules.
- Hook runner support through `roomctl hook`.
- Example hook templates for Claude Code, Codex, and Cursor-style command hooks.
- A starter security ruleset for tenant scoping, auth context, secrets, SQL injection, SSRF, auditability, Rust safety, and destructive actions.

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

Smoke-test the MCP endpoint with a real MCP client:

```bash
go run ./cmd/room-mcp-call \
  -endpoint http://localhost:8788/mcp \
  -plan "Add a customer endpoint that queries projects from the database."
```

## Hook runner

`roomctl` reads hook JSON on stdin and evaluates it against the active Room
ruleset. It fetches the active ruleset, stores it in a local cache, and falls
back to that cache if Room is unavailable.

```bash
go install ./cmd/roomctl
roomctl sync-rules
roomctl watch-rules
roomctl hook pre-tool < hook-payload.json
roomctl hook post-tool < hook-payload.json
roomctl hook prompt < hook-payload.json
```

The default cache path is `${XDG_CACHE_HOME:-~/.cache}/room/ruleset.json`.
Override it with `ROOM_CACHE_FILE`.

Use `watch-rules` for long-running sidecars that should keep the cache updated
as new rulesets are published.

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
  - `protected_handler_without_auth_context`
  - `unsafe_sql_construction`
  - `external_fetch_without_allowlist`
  - `privilege_change_without_audit`
  - `webhook_without_signature_verification`
  - `password_storage_without_hashing`
  - `public_sensitive_endpoint_without_rate_limit`
  - `rust_unsafe_without_safety_rationale`
  - `rust_unwrap_or_expect_in_request_path`
  - `rust_command_with_user_input`
  - `rust_weak_rng_for_secret`
  - `rust_path_traversal_without_canonicalize`
  - `rust_panic_in_library_or_api`
  - `rust_std_mutex_across_await`
  - `rust_serde_external_input_missing_deny_unknown_fields`

## Bundled Rust guardrails

Fresh Room stores publish these Rust rules by default:

- `rust-unsafe-requires-safety-rationale`
- `rust-request-paths-must-not-unwrap`
- `rust-command-exec-requires-allowlist`
- `rust-secrets-require-crypto-rng`
- `rust-paths-must-be-canonicalized`
- `rust-library-api-must-not-panic`
- `rust-no-std-mutex-across-await`
- `rust-serde-external-input-deny-unknown-fields`

The intent is to keep the public MVP deterministic and easy to audit, then add
Semgrep, AST, and policy-engine integrations behind the same protobuf contract.

## Repository status

This is an early standalone scaffold. The API shape is intentionally small and
versioned so the dashboard, MCP server, and hooks can evolve without coupling to
any existing internal platform.
