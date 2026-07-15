# Room

Room is a self-hosted guardrail control plane for coding agents. It publishes
immutable, scoped rulesets; evaluates trusted analyzer receipts; governs typed
MCP identities; and records durable audit events.

## What it includes

- ConnectRPC and Protobuf admin/agent APIs.
- Three focused MCP tools: `room_get_rules`, `room_analyze_plan`, and `room_check_diff`.
- Scoped opaque bearer credentials with separate admin and agent roles.
- A strict external-analyzer boundary: policy never classifies prompt, plan, diff, title, or display text.
- SQLite persistence for ruleset versions, MCP policy, and append-only audit events.
- A review-intelligence catalog that turns typed review claims and durable outcomes into replayed, staged policy candidates.
- Lifecycle hooks that fail closed unless `ROOM_HOOK_FAIL_OPEN=true` is explicitly set.

## Local setup

Create an admin credential and a repository-scoped agent credential. Tokens are
shown once; the credential registry stores only SHA-256 digests.

```bash
go run ./cmd/roomctl token issue \
  --id local-admin --role admin --human-operator --output .room/admin.token

go run ./cmd/roomctl token issue \
  --id review-automation --role reviewer --output .room/reviewer.token

go run ./cmd/roomctl token issue \
  --id local-agent --role agent \
  --workspace local --repository haasonsaas/room --agent codex \
  --output .room/agent.token
```

Configure a trusted analyzer executable, then start Room:

```bash
ROOM_ANALYZER_EXECUTABLE=/absolute/path/to/analyzer \
ROOM_ANALYZER_ID=company.security-analyzer \
ROOM_ANALYZER_VERSION=1 \
ROOM_ANALYZER_COVERED_SIGNALS='["SIGNAL_KIND_RUST_UNSAFE_WITHOUT_SAFETY_CONTRACT"]' \
go run ./cmd/roomd
```

Without an analyzer, evaluations return `INDETERMINATE`; enforcement callers
block that result. For local development only, authentication may be disabled on
a loopback listener with `ROOM_AUTH_MODE=disabled`.

Open `http://127.0.0.1:8787` and paste the admin token into the in-memory token
field. The dashboard never persists tokens.

The Rules catalog includes learned candidates beside authored rules. Review
findings are ingested with a typed claim kind, source identity, confidence, and
cost metadata. Fixes, resolutions, reactions, merges, reverts, regressions, and
agent adjudications are recorded as separate durable evidence. Room can then
infer candidates, replay them over the stored corpus, tune their confidence
threshold, and advance them through draft, shadow, warn, and block stages.
Protected organization-wide blocking policies always require explicit human
approval; pause and rollback remain available as emergency controls.
Review automation should use the least-privilege `reviewer` credential. It can
ingest evidence, infer, replay, tune, and advance eligible non-protected staged
policies, but it cannot directly edit or publish arbitrary rulesets, change MCP
trust policy, or exercise human-only controls.

Run the MCP sidecar separately:

```bash
ROOM_SERVER_URL=http://127.0.0.1:8787 \
go run ./cmd/room-mcp
```

It listens at `http://127.0.0.1:8788/mcp` by default. MCP callers must send the
same scoped agent bearer credential; the sidecar validates and forwards each
request's credential, and binds MCP sessions to that principal. `room-mcp-call`
reads `ROOM_TOKEN_FILE` for the caller.

## Hooks and CLI

```bash
ROOM_TOKEN_FILE=.room/agent.token go run ./cmd/roomctl rules
ROOM_TOKEN_FILE=.room/agent.token go run ./cmd/roomctl hook pre-tool < hook.json
ROOM_TOKEN_FILE=.room/admin.token go run ./cmd/roomctl publish
```

The ruleset cache is a private, scoped advisory cache. Evaluations are performed
by Room and do not fall back to legacy local text heuristics when the server is
unavailable.

Credential registry changes are loaded live. Reissuing an ID revokes its old
token without restarting `roomd` or `room-mcp`.

See [architecture](docs/architecture.md), [analyzer contract](docs/analyzer.md),
[rules](docs/rules.md), and [hooks](docs/hooks.md).

## Development

```bash
buf lint
buf generate
go test ./...
go test -race ./...
go vet ./...
```
