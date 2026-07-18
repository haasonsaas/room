# Analyzer contract

Room launches one explicitly configured absolute executable without a shell.
The request is strict JSON on stdin and contains the analysis phase, base64 JSON
content bytes, changed files, working directory, and SHA-256 digests for the
input, the analyzer configuration, and—when `ROOM_ANALYZER_TOOL_FILE` is
set—the tool binary. The
executable must return exactly one JSON object on stdout; unknown or trailing
fields are rejected. The working directory is caller-supplied and must be
restricted by analyzers that read files.

The response declares the same phase and input digest, a status, complete
covered-signal names, and zero or more typed signals. It may also declare
`languages` and `frameworks` detected from the analyzed artifact. Room validates,
normalizes, deduplicates, and stamps those classifications onto the artifact;
policy uses them only when the report contains a valid receipt from the configured
analyzer. Agent-supplied classification cannot narrow a rule's scope. Every signal
has a stable fingerprint, a confidence from 0–10000, and optional typed
location/evidence hashes. Room—not the provider—stamps the configured analyzer
ID, version, configuration digest, and tool-binary digest onto accepted
receipts.

For `COMPLETE`, all signals configured for the analyzer must be present in
`covered_signals`, even when no finding exists. Process failure, digest mismatch,
unknown fields, incomplete coverage, undeclared signals, invalid locations, or
unconfigured signal names produce an explicit failed/invalid/unavailable report.
Policy then returns `INDETERMINATE` unless audit-only mode was deliberately set.

Configuration:

```bash
ROOM_ANALYZER_EXECUTABLE=/absolute/path/to/analyzer
ROOM_ANALYZER_ARGS='["--format","room-v1"]'
ROOM_ANALYZER_COVERED_SIGNALS='["SIGNAL_KIND_RUST_UNSAFE_WITHOUT_SAFETY_CONTRACT","SIGNAL_KIND_RUST_PANIC_IN_REQUEST_PATH"]'
ROOM_ANALYZER_CONFIG_FILE=/path/to/analyzer-config
ROOM_ANALYZER_TOOL_FILE=/path/to/scanner-binary   # optional; SHA-256 bound into receipts
ROOM_ANALYZER_ID=company.security-analyzer
ROOM_ANALYZER_VERSION=1
ROOM_ANALYZER_TIMEOUT=30s
```

`ROOM_WRITE_TIMEOUT` and every caller's `ROOM_CLIENT_TIMEOUT` must exceed the
analyzer timeout by more than five seconds. Defaults are 60 seconds for server
writes and 45 seconds for clients, leaving room for RPC and audit persistence
around the 30-second analyzer budget. `room-mcp` also requires its write timeout
to exceed its upstream client timeout by more than five seconds.

Coverage is mandatory and uses exact `SignalKind` enum names. This prevents a
specialized analyzer from being treated as authoritative for checks it does not
implement. Rules that require signals outside the configured coverage evaluate
as indeterminate.

## Semgrep adapter

`cmd/room-semgrep` runs Semgrep Community Edition against files named by a
unified diff. It requires three absolute paths:

- `--semgrep-core`: the `semgrep-core` executable included with Semgrep CE.
- `--config`: local rules file.
- `--repository-root`: the one repository eligible for scanning. It must match
  the request working directory after resolving symlinks.

The Linux adapter opens the repository once and uses `openat2` to confine target
reads beneath it. Target symlinks, special files, files larger than 64 MiB,
renames, binary patches, and malformed or incomplete unified diffs produce a
failed receipt. The adapter invokes `semgrep-core` with explicit snapshotted
targets, strict rule validation, disabled timeouts, and no ignore-file target
discovery. Any core parser error, target skip, or rule skip fails the receipt.
Registry configuration URLs are not accepted.

Each policy-bearing Semgrep rule must provide these metadata fields:

```yaml
metadata:
  room_signal: SIGNAL_KIND_DYNAMIC_SQL_WITH_UNTRUSTED_INPUT
  room_confidence_basis_points: 9000
```

Rules are authored as YAML fragments under `analyzers/semgrep/rules`, with one
rule per file. After editing a fragment, run `go generate ./analyzers/semgrep`
and commit the regenerated `analyzers/semgrep/room.yml`. That generated regular
file remains the production input passed to `cmd/room-semgrep`; Room SHA-256
binds its exact bytes as `ROOM_ANALYZER_CONFIG_FILE`.

Pass every metadata signal through a repeated `--covered-signal` argument and
list the same signals in `ROOM_ANALYZER_COVERED_SIGNALS`. A finding that names an
undeclared signal or an invalid confidence produces a failed receipt. Findings
without `room_signal` metadata are ignored.

The bundled rules provide these coverage claims:

| Signal | Language | Detection |
| --- | --- | --- |
| `SIGNAL_KIND_SECRET_LITERAL` | Go, Rust | String literals matching GitHub, OpenAI, or Slack token formats |
| `SIGNAL_KIND_DYNAMIC_SQL_WITH_UNTRUSTED_INPUT` | Go | Query, form, header, or path input reaching `database/sql` query text |
| `SIGNAL_KIND_UNTRUSTED_OUTBOUND_DESTINATION` | Go | Query, form, header, or path input reaching a package-level `net/http` request URL |
| `SIGNAL_KIND_RUST_PANIC_IN_REQUEST_PATH` | Rust | Hyper-style request URI or headers and Actix request values reaching `unwrap`, `expect`, or `panic` |
| `SIGNAL_KIND_RUST_COMMAND_WITH_UNTRUSTED_ARGUMENT` | Rust | Process environment/arguments and Hyper- or Actix-style request values reaching `Command::new`, `arg`, or `args` |
| `SIGNAL_KIND_RUST_WEAK_RNG_FOR_SECRET` | Rust | Secret-like assignments derived from `fastrand` module/`Rng`, `rand::rngs::SmallRng`, `oorandom::{Rand32,Rand64}`, or `nanorand::{WyRand,Pcg64}` |
| `SIGNAL_KIND_RUST_UNTRUSTED_PATH` | Rust | Process or request values reaching standard or Tokio filesystem reads, writes, metadata, creation, deletion, copy, or rename operations |
| `SIGNAL_KIND_RUST_BLOCKING_LOCK_ACROSS_AWAIT` | Rust | `lock`/`read`/`write` bindings using `unwrap` or `expect`, and `blocking_lock`/`blocking_read`/`blocking_write` bindings, followed by await without a matched explicit drop |

These rules model the listed source and sink families, not every framework API
or validation function. The adapter uses Semgrep's private core interface and
is pinned and integration-tested against `semgrep-core` 1.139.0. For taint
rules, a finding is retained when the added lines intersect either the reported
sink or a source/intermediate location in the core's dataflow trace.

The bundled Semgrep rules do not claim
`SIGNAL_KIND_RUST_UNSAFE_WITHOUT_SAFETY_CONTRACT`,
`SIGNAL_KIND_RUST_PANIC_IN_LIBRARY_API`, or
`SIGNAL_KIND_RUST_UNVALIDATED_EXTERNAL_DESERIALIZATION`. The current rules do
not model safety-comment absence, public-library API boundaries, or validation
across definitions.

```bash
go build -o ~/.local/bin/room-semgrep ./cmd/room-semgrep

ROOM_ANALYZER_EXECUTABLE="$HOME/.local/bin/room-semgrep"
ROOM_ANALYZER_ARGS='["--semgrep-core","/absolute/path/to/semgrep-core","--config","/absolute/path/to/room/analyzers/semgrep/room.yml","--repository-root","/srv/repos/my-repository","--covered-signal","SIGNAL_KIND_SECRET_LITERAL","--covered-signal","SIGNAL_KIND_DYNAMIC_SQL_WITH_UNTRUSTED_INPUT","--covered-signal","SIGNAL_KIND_UNTRUSTED_OUTBOUND_DESTINATION","--covered-signal","SIGNAL_KIND_RUST_PANIC_IN_REQUEST_PATH","--covered-signal","SIGNAL_KIND_RUST_COMMAND_WITH_UNTRUSTED_ARGUMENT","--covered-signal","SIGNAL_KIND_RUST_WEAK_RNG_FOR_SECRET","--covered-signal","SIGNAL_KIND_RUST_UNTRUSTED_PATH","--covered-signal","SIGNAL_KIND_RUST_BLOCKING_LOCK_ACROSS_AWAIT"]'
ROOM_ANALYZER_CONFIG_FILE=/absolute/path/to/room/analyzers/semgrep/room.yml
ROOM_ANALYZER_TOOL_FILE=/absolute/path/to/semgrep-core
ROOM_ANALYZER_COVERED_SIGNALS='["SIGNAL_KIND_SECRET_LITERAL","SIGNAL_KIND_DYNAMIC_SQL_WITH_UNTRUSTED_INPUT","SIGNAL_KIND_UNTRUSTED_OUTBOUND_DESTINATION","SIGNAL_KIND_RUST_PANIC_IN_REQUEST_PATH","SIGNAL_KIND_RUST_COMMAND_WITH_UNTRUSTED_ARGUMENT","SIGNAL_KIND_RUST_WEAK_RNG_FOR_SECRET","SIGNAL_KIND_RUST_UNTRUSTED_PATH","SIGNAL_KIND_RUST_BLOCKING_LOCK_ACROSS_AWAIT"]'
ROOM_ANALYZER_ID=room.semgrep
ROOM_ANALYZER_VERSION=1
```

`ROOM_ANALYZER_CONFIG_FILE` binds the rules file contents to Room's analyzer
identity, and `ROOM_ANALYZER_TOOL_FILE` binds the `semgrep-core` binary the
same way. The setting is optional in the analyzer contract, but the stock
`room-semgrep` adapter requires it: without a digest, every diff request fails
with `tool_digest_mismatch`. The adapter resolves the tool path at
startup—pipx-style symlinked installs work—hashes the resolved binary once,
and re-resolves it on every diff request; a binary that changed since startup
also fails with `tool_digest_mismatch`. Restart the adapter after upgrading
`semgrep-core`.
The adapter returns `PARTIAL` for plan analysis and does not claim signal
coverage for plans.
