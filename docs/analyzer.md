# Analyzer contract

Room launches one explicitly configured absolute executable without a shell.
The request is strict JSON on stdin and contains the analysis phase, base64 JSON
content bytes, changed files, and the SHA-256 input digest. The executable must
return exactly one JSON object on stdout; unknown or trailing fields are rejected.

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
