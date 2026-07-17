# Room

Room is a self-hosted guardrail control plane for coding agents. It publishes
immutable, scoped rulesets; evaluates trusted analyzer receipts; governs typed
MCP identities; and records durable audit events.

## What it includes

- ConnectRPC and Protobuf admin/agent APIs.
- Four focused MCP tools: `room_get_rules`, `room_analyze_plan`, `room_check_diff`, and `room_open_policy_control`.
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

Install [Semgrep Community Edition](https://semgrep.dev/docs/getting-started/),
build the Linux adapter, and configure the repository it may scan:

```bash
go build -o ~/.local/bin/room-semgrep ./cmd/room-semgrep

ROOM_ANALYZER_EXECUTABLE="$HOME/.local/bin/room-semgrep" \
ROOM_ANALYZER_ARGS='["--semgrep-core","/absolute/path/to/semgrep-core","--config","/absolute/path/to/room/analyzers/semgrep/room.yml","--repository-root","/absolute/path/to/repository","--covered-signal","SIGNAL_KIND_DYNAMIC_SQL_WITH_UNTRUSTED_INPUT"]' \
ROOM_ANALYZER_CONFIG_FILE=/absolute/path/to/room/analyzers/semgrep/room.yml \
ROOM_ANALYZER_ID=room.semgrep \
ROOM_ANALYZER_VERSION=1 \
ROOM_ANALYZER_COVERED_SIGNALS='["SIGNAL_KIND_DYNAMIC_SQL_WITH_UNTRUSTED_INPUT"]' \
go run ./cmd/roomd
```

The included rule detects Go HTTP input that reaches SQL query text. The
adapter invokes the OSS `semgrep-core` binary directly so core parser and rule
skips remain visible. It snapshots regular changed files beneath
`--repository-root` and emits findings only when their source range intersects
an added diff line. Plan evaluation remains indeterminate because Semgrep
requires source files.

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
All blocking policies require an authenticated human operator and explicit
approval; pause and rollback remain human-only emergency controls.
Review automation should use the least-privilege `reviewer` credential. It can
ingest evidence, infer, replay, tune, and advance eligible non-protected staged
policies, but it cannot directly edit or publish arbitrary rulesets, change MCP
trust policy, or exercise human-only controls.

Run the MCP sidecar separately:

```bash
ROOM_SERVER_URL=http://127.0.0.1:8787 \
ROOM_CONTROL_PLANE_URL=http://127.0.0.1:8787 \
go run ./cmd/room-mcp
```

It listens at `http://127.0.0.1:8788/mcp` by default. MCP callers must send the
same scoped agent bearer credential; the sidecar validates and forwards each
request's credential, and binds MCP sessions to that principal. `room-mcp-call`
reads `ROOM_TOKEN_FILE` for the caller.

Room uses MCP elicitation only from typed evaluation state. A blocking
evaluation with required checks, evidence, remediation, or analyzer gaps can
offer a closed-choice form (`revise`, `run_required_checks`,
`provide_evidence`, or `open_control_plane`). Allow decisions and blocking
decisions without a typed next-step contract do not elicit. Accept, decline,
cancel, unsupported-client, and error outcomes are written to the append-only
audit log and bound to the original evaluation and authenticated agent scope.

`room_open_policy_control` uses URL-mode elicitation for the human-only block,
pause, and rollback controls. Its inputs are a candidate ID, target rollout
stage, and the candidate's expected `updated_at` value. The sidecar creates the
URL only from `ROOM_CONTROL_PLANE_URL`, verifies candidate scope and freshness,
and audits both the offer and result. Opening the dashboard selects the
candidate and Rollout tab but never changes policy. The actual transition still
requires the dashboard's human-operator credential, confirmation, and
compare-and-swap checks. Do not put credentials in the control-plane URL.

For Codex, keep general approvals locked down while allowing the user to review
MCP elicitations:

```toml
approval_policy = { granular = { sandbox_approval = false, rules = false, mcp_elicitations = true, request_permissions = false, skill_approval = false } }
approvals_reviewer = "user"
```

For reliable native Codex tool discovery, prefer the `room-mcp-stdio` entrypoint
through a Codex plugin. It reads the agent token from a private
`ROOM_TOKEN_FILE`, so the Codex GUI process does not need to inherit a bearer
token environment variable. Because the stdio server is Codex's direct MCP
peer, Room form and URL elicitations render in the native Codex UI.

```bash
go build -o ~/.local/bin/room-mcp-stdio ./cmd/room-mcp-stdio
```

The plugin MCP entry should invoke that binary with `ROOM_TOKEN_FILE`,
`ROOM_SERVER_URL`, and `ROOM_CONTROL_PLANE_URL` in its non-secret environment.
After installing or updating the plugin, start a new Codex task so its MCP tool
catalog is rebuilt from the plugin.

## Hooks and CLI

```bash
ROOM_TOKEN_FILE=.room/agent.token go run ./cmd/roomctl rules
ROOM_TOKEN_FILE=.room/agent.token go run ./cmd/roomctl hook pre-tool < hook.json
ROOM_TOKEN_FILE=.room/admin.token go run ./cmd/roomctl publish
```

The ruleset cache is a private, scoped advisory cache. Evaluations are performed
by Room and do not fall back to legacy local text heuristics when the server is
unavailable.

Credential registry changes are loaded live. Existing IDs cannot be reissued
through the bootstrap command; scope changes require the authenticated,
human-confirmed dashboard workflow, which rotates the token and records the
mutation receipt atomically without restarting `roomd` or `room-mcp`.

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
