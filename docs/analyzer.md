# Analyzer contract

Room launches one explicitly configured absolute executable without a shell.
The request is strict JSON on stdin and contains the analysis phase, base64 JSON
content bytes, changed files, working directory, and SHA-256 input digest. The
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
ID, version, and configuration digest onto accepted receipts.

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

Pass every metadata signal through a repeated `--covered-signal` argument and
list the same signals in `ROOM_ANALYZER_COVERED_SIGNALS`. A finding that names an
undeclared signal or an invalid confidence produces a failed receipt. Findings
without `room_signal` metadata are ignored.

```bash
go build -o ~/.local/bin/room-semgrep ./cmd/room-semgrep

ROOM_ANALYZER_EXECUTABLE="$HOME/.local/bin/room-semgrep"
ROOM_ANALYZER_ARGS='["--semgrep-core","/absolute/path/to/semgrep-core","--config","/absolute/path/to/room/analyzers/semgrep/room.yml","--repository-root","/srv/repos/my-repository","--covered-signal","SIGNAL_KIND_DYNAMIC_SQL_WITH_UNTRUSTED_INPUT"]'
ROOM_ANALYZER_CONFIG_FILE=/absolute/path/to/room/analyzers/semgrep/room.yml
ROOM_ANALYZER_COVERED_SIGNALS='["SIGNAL_KIND_DYNAMIC_SQL_WITH_UNTRUSTED_INPUT"]'
ROOM_ANALYZER_ID=room.semgrep
ROOM_ANALYZER_VERSION=1
```

`ROOM_ANALYZER_CONFIG_FILE` binds the rules file contents to Room's analyzer
identity. Update `ROOM_ANALYZER_VERSION` when the `semgrep-core` binary changes.
The adapter returns `PARTIAL` for plan analysis and does not claim signal
coverage for plans.
