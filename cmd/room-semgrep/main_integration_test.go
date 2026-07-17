//go:build semgrep_integration

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var integrationSignals = []string{
	"SIGNAL_KIND_SECRET_LITERAL",
	"SIGNAL_KIND_DYNAMIC_SQL_WITH_UNTRUSTED_INPUT",
	"SIGNAL_KIND_UNTRUSTED_OUTBOUND_DESTINATION",
	"SIGNAL_KIND_RUST_PANIC_IN_REQUEST_PATH",
	"SIGNAL_KIND_RUST_COMMAND_WITH_UNTRUSTED_ARGUMENT",
	"SIGNAL_KIND_RUST_WEAK_RNG_FOR_SECRET",
	"SIGNAL_KIND_RUST_UNTRUSTED_PATH",
	"SIGNAL_KIND_RUST_BLOCKING_LOCK_ACROSS_AWAIT",
}

func TestSemgrepCoreIntegration(t *testing.T) {
	core, config := integrationPaths(t)
	tests := []struct {
		name, path, source, signal string
	}{
		{
			name:   "secret literal",
			path:   "credentials.go",
			source: "package demo\nconst token = \"ghp_" + strings.Repeat("a", 36) + "\"\n",
			signal: "SIGNAL_KIND_SECRET_LITERAL",
		},
		{
			name:   "Rust secret literal",
			path:   "credentials.rs",
			source: "const TOKEN: &str = \"xoxb-" + strings.Repeat("a", 24) + "\";\n",
			signal: "SIGNAL_KIND_SECRET_LITERAL",
		},
		{
			name: "dynamic SQL ignores nosem",
			path: "query.go",
			source: `package demo
import ("database/sql"; "net/http")
func handler(db *sql.DB, r *http.Request) {
	query := r.FormValue("query")
	db.Query(query) // nosem
}
`,
			signal: "SIGNAL_KIND_DYNAMIC_SQL_WITH_UNTRUSTED_INPUT",
		},
		{
			name: "untrusted outbound destination",
			path: "fetch.go",
			source: `package demo
import "net/http"
func handler(r *http.Request) {
	target := r.Header.Get("X-Callback-URL")
	http.Get(target)
}
`,
			signal: "SIGNAL_KIND_UNTRUSTED_OUTBOUND_DESTINATION",
		},
		{
			name: "Rust command argument",
			path: "command.rs",
			source: `use std::process::Command;
fn main() {
	let arg = std::env::args().nth(1).unwrap();
	Command::new("tool").arg(arg).status();
}
`,
			signal: "SIGNAL_KIND_RUST_COMMAND_WITH_UNTRUSTED_ARGUMENT",
		},
		{
			name: "Rust request path command argument",
			path: "request_command.rs",
			source: `use std::process::Command;
fn handler(request: Request) {
	let arg = request.uri().path();
	Command::new("tool").arg(arg).status();
}
`,
			signal: "SIGNAL_KIND_RUST_COMMAND_WITH_UNTRUSTED_ARGUMENT",
		},
		{
			name: "Rust request input panic",
			path: "request_panic.rs",
			source: `fn handler(request: Request) {
	let value = request.headers().get("x-value");
	value.expect("required header");
}
`,
			signal: "SIGNAL_KIND_RUST_PANIC_IN_REQUEST_PATH",
		},
		{
			name: "Rust untrusted filesystem path",
			path: "untrusted_path.rs",
			source: `fn main() {
	let path = std::env::args_os().nth(1).unwrap();
	std::fs::read_to_string(path).unwrap();
}
`,
			signal: "SIGNAL_KIND_RUST_UNTRUSTED_PATH",
		},
		{
			name: "Rust blocking lock across await",
			path: "blocking_lock.rs",
			source: `async fn update(lock: Lock) {
	let guard = lock.lock().unwrap();
	work().await;
	consume(guard);
}
`,
			signal: "SIGNAL_KIND_RUST_BLOCKING_LOCK_ACROSS_AWAIT",
		},
		{
			name: "Rust weak RNG for secret",
			path: "weak_rng.rs",
			source: `fn issue() {
	let mut rng = rand::rngs::SmallRng::seed_from_u64(7);
	let api_key = rng.gen::<u64>();
}
`,
			signal: "SIGNAL_KIND_RUST_WEAK_RNG_FOR_SECRET",
		},
		{
			name: "Rust Actix request panic",
			path: "actix_panic.rs",
			source: `fn handler(request: HttpRequest) {
	let value = request.match_info().get("account");
	value.unwrap();
}
`,
			signal: "SIGNAL_KIND_RUST_PANIC_IN_REQUEST_PATH",
		},
		{
			name: "Rust request path reaches Tokio filesystem",
			path: "tokio_path.rs",
			source: `async fn handler(request: Request) {
	let path = request.uri().path();
	tokio::fs::read(path).await;
}
`,
			signal: "SIGNAL_KIND_RUST_UNTRUSTED_PATH",
		},
		{
			name: "Rust blocking write guard across await",
			path: "blocking_write.rs",
			source: `async fn update(lock: Lock) {
	let guard = lock.write().unwrap();
	work().await;
	consume(guard);
}
`,
			signal: "SIGNAL_KIND_RUST_BLOCKING_LOCK_ACROSS_AWAIT",
		},
		{
			name: "Rust fastrand secret",
			path: "fastrand_secret.rs",
			source: `fn issue() {
	let session_token = fastrand::u64(..);
}
`,
			signal: "SIGNAL_KIND_RUST_WEAK_RNG_FOR_SECRET",
		},
		{
			name: "Rust fastrand instance secret",
			path: "fastrand_instance.rs",
			source: `fn issue() {
	let mut rng = fastrand::Rng::new();
	let session_token = rng.u64(..);
}
`,
			signal: "SIGNAL_KIND_RUST_WEAK_RNG_FOR_SECRET",
		},
		{
			name: "Rust imported SmallRng secret",
			path: "imported_small_rng.rs",
			source: `use rand::rngs::SmallRng;
fn issue() {
	let mut rng = SmallRng::seed_from_u64(7);
	let api_key = rng.gen::<u64>();
}
`,
			signal: "SIGNAL_KIND_RUST_WEAK_RNG_FOR_SECRET",
		},
		{
			name: "Rust oorandom secret",
			path: "oorandom_secret.rs",
			source: `fn issue() {
	let mut rng = oorandom::Rand64::new(7);
	let nonce = rng.rand_u64();
}
`,
			signal: "SIGNAL_KIND_RUST_WEAK_RNG_FOR_SECRET",
		},
		{
			name: "Rust nanorand WyRand secret",
			path: "nanorand_secret.rs",
			source: `fn issue() {
	let mut rng = nanorand::WyRand::new();
	let session_token = rng.generate::<u64>();
}
`,
			signal: "SIGNAL_KIND_RUST_WEAK_RNG_FOR_SECRET",
		},
		{
			name: "Rust mutable process command builder",
			path: "command_builder.rs",
			source: `fn run() {
	let value = std::env::var("COMMAND_ARG").unwrap();
	let mut command = std::process::Command::new("tool");
	command.arg(value);
}
`,
			signal: "SIGNAL_KIND_RUST_COMMAND_WITH_UNTRUSTED_ARGUMENT",
		},
		{
			name: "Rust untrusted process executable",
			path: "command_program.rs",
			source: `fn run() {
	let program = std::env::var("PROGRAM").unwrap();
	std::process::Command::new(program);
}
`,
			signal: "SIGNAL_KIND_RUST_COMMAND_WITH_UNTRUSTED_ARGUMENT",
		},
		{
			name: "Rust Tokio process command builder",
			path: "tokio_command.rs",
			source: `fn run() {
	let value = std::env::var("COMMAND_ARG").unwrap();
	let mut command = tokio::process::Command::new("tool");
	command.arg(value);
}
`,
			signal: "SIGNAL_KIND_RUST_COMMAND_WITH_UNTRUSTED_ARGUMENT",
		},
		{
			name: "Rust imported std File path",
			path: "imported_file.rs",
			source: `use std::fs::File;
fn load() {
	let path = std::env::args_os().nth(1).unwrap();
	File::open(path);
}
`,
			signal: "SIGNAL_KIND_RUST_UNTRUSTED_PATH",
		},
		{
			name: "Rust aliased std fs path",
			path: "aliased_fs.rs",
			source: `use std::fs as filesystem;
fn load() {
	let path = std::env::args_os().nth(1).unwrap();
	filesystem::read(path);
}
`,
			signal: "SIGNAL_KIND_RUST_UNTRUSTED_PATH",
		},
		{
			name: "Rust tainted explicit panic",
			path: "explicit_panic.rs",
			source: `fn handler(request: Request) {
	let account = request.uri().path();
	panic!("invalid account: {}", account);
}
`,
			signal: "SIGNAL_KIND_RUST_PANIC_IN_REQUEST_PATH",
		},
		{
			name: "Rust blocking lock API across await",
			path: "blocking_api.rs",
			source: `async fn update(lock: Lock) {
	let mut guard = lock.blocking_lock();
	work().await;
	consume(&mut guard);
}
`,
			signal: "SIGNAL_KIND_RUST_BLOCKING_LOCK_ACROSS_AWAIT",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := t.TempDir()
			if err := os.WriteFile(filepath.Join(repository, test.path), []byte(test.source), 0o600); err != nil {
				t.Fatal(err)
			}
			adapter, err := newAdapter(core, config, repository, append([]string(nil), integrationSignals...))
			if err != nil {
				t.Fatal(err)
			}
			response := adapter.analyze(t.Context(), requestFor(repository, config, newFileDiff(test.path, test.source)))
			if response.Status != completeStatus {
				t.Fatalf("response = %+v", response)
			}
			if len(response.Signals) != 1 || response.Signals[0].Kind != test.signal {
				t.Fatalf("signals = %+v", response.Signals)
			}
		})
	}
}

func TestSemgrepCoreIntegrationCleanScan(t *testing.T) {
	core, config := integrationPaths(t)
	tests := []struct {
		name, path, source string
	}{
		{
			name: "credential-shaped comment and ordinary string",
			path: "strings.go",
			source: `package demo
// ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
const explanation = "this ordinary string is deliberately longer than a credential"
`,
		},
		{
			name: "parameterized SQL and fixed outbound destination",
			path: "safe.go",
			source: `package demo
import ("database/sql"; "net/http")
func safe(db *sql.DB, r *http.Request) {
	value := r.FormValue("value")
	db.Query("SELECT * FROM records WHERE value = ?", value)
	http.Get("https://example.com/health")
}
`,
		},
		{
			name: "fixed Rust command argument",
			path: "safe.rs",
			source: `use std::process::Command;
fn main() {
	Command::new("tool").arg("status").status();
}
`,
		},
		{
			name: "fallible Rust request parsing",
			path: "fallible_request.rs",
			source: `fn handler(request: Request) -> Result<&Header, Error> {
	let value = request.headers().get("x-value").ok_or(Error::MissingHeader)?;
	Ok(value)
}
`,
		},
		{
			name: "fixed Rust filesystem path",
			path: "fixed_path.rs",
			source: `fn load() {
	std::fs::read_to_string("config/default.toml").unwrap();
}
`,
		},
		{
			name: "Rust blocking guard dropped before await",
			path: "dropped_guard.rs",
			source: `async fn update(lock: Lock) {
	let guard = lock.lock().unwrap();
	consume(&guard);
	drop(guard);
	work().await;
}
`,
		},
		{
			name: "Rust CSPRNG secret and non-secret fast RNG",
			path: "safe_rng.rs",
			source: `fn values(mut os_rng: rand::rngs::OsRng) {
	let session_token = os_rng.next_u64();
	let retry_jitter = fastrand::u64(..);
}
`,
		},
		{
			name: "Rust clap argument is not process execution",
			path: "clap.rs",
			source: `fn configure(request: Request, command: clap::Command) {
	let name = request.uri().path();
	command.arg(name);
}
`,
		},
		{
			name: "Rust custom open method is not filesystem access",
			path: "custom_open.rs",
			source: `fn handler(request: Request, archive: Archive) {
	let member = request.uri().path();
	archive.open(member);
}
`,
		},
		{
			name: "Rust nanorand ChaCha is a CSPRNG",
			path: "nanorand_chacha.rs",
			source: `fn issue() {
	let mut rng = nanorand::ChaCha::new();
	let session_token = rng.generate::<u64>();
}
`,
		},
		{
			name: "Rust clap command constructor is not process execution",
			path: "clap_constructor.rs",
			source: `fn configure(request: Request) {
	let name = request.uri().path();
	clap::Command::new(name);
}
`,
		},
		{
			name: "Rust local fs module is not std fs",
			path: "local_fs.rs",
			source: `mod fs { fn read(path: &str) {} }
fn handler(request: Request) {
	let member = request.uri().path();
	fs::read(member);
}
`,
		},
		{
			name: "Rust custom File is not std File",
			path: "custom_file.rs",
			source: `struct File;
impl File { fn open(path: &str) {} }
fn handler(request: Request) {
	let member = request.uri().path();
	File::open(member);
}
`,
		},
		{
			name: "Rust response body is not request input",
			path: "response_body.rs",
			source: `fn render(response: Response) {
	let body = response.body();
	body.unwrap();
}
`,
		},
		{
			name: "Rust blocking lock dropped with qualified drop",
			path: "qualified_drop.rs",
			source: `async fn update(lock: Lock) {
	let mut guard = lock.blocking_lock();
	consume(&mut guard);
	std::mem::drop(guard);
	work().await;
}
`,
		},
		{
			name: "Rust blocking lock dropped with core drop",
			path: "core_drop.rs",
			source: `async fn update(lock: Lock) {
	let guard = lock.lock().expect("lock");
	consume(&guard);
	core::mem::drop(guard);
	work().await;
}
`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := t.TempDir()
			if err := os.WriteFile(filepath.Join(repository, test.path), []byte(test.source), 0o600); err != nil {
				t.Fatal(err)
			}
			adapter, err := newAdapter(core, config, repository, append([]string(nil), integrationSignals...))
			if err != nil {
				t.Fatal(err)
			}
			response := adapter.analyze(t.Context(), requestFor(repository, config, newFileDiff(test.path, test.source)))
			if response.Status != completeStatus || len(response.Signals) != 0 {
				t.Fatalf("response = %+v", response)
			}
		})
	}
}

func TestSemgrepCoreIntegrationFiltersUnchangedFindings(t *testing.T) {
	core, config := integrationPaths(t)
	repository := t.TempDir()
	source := `package demo
import ("database/sql"; "net/http")
func handler(db *sql.DB, r *http.Request) {
	first := r.FormValue("first")
	db.Query(first)
	second := r.FormValue("second")
	db.Query(second)
}
`
	if err := os.WriteFile(filepath.Join(repository, "query.go"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	adapter, err := newAdapter(core, config, repository, append([]string(nil), integrationSignals...))
	if err != nil {
		t.Fatal(err)
	}
	diff := []byte("diff --git a/query.go b/query.go\n--- a/query.go\n+++ b/query.go\n@@ -6,0 +7 @@\n+\tdb.Query(second)\n")
	response := adapter.analyze(t.Context(), requestFor(repository, config, diff))
	if response.Status != completeStatus || len(response.Signals) != 1 {
		t.Fatalf("response = %+v", response)
	}
	if response.Signals[0].Kind != "SIGNAL_KIND_DYNAMIC_SQL_WITH_UNTRUSTED_INPUT" || response.Signals[0].Location.StartLine != 7 {
		t.Fatalf("signals = %+v", response.Signals)
	}
}

func TestSemgrepCoreIntegrationIncludesAddedSources(t *testing.T) {
	core, config := integrationPaths(t)
	tests := []struct {
		name, source, signal  string
		addedLine, resultLine int
	}{
		{
			name: "command source",
			source: `fn handler(request: Request) {
	let value = request.uri().path();
	std::process::Command::new("tool").arg(value);
}
`,
			signal:     "SIGNAL_KIND_RUST_COMMAND_WITH_UNTRUSTED_ARGUMENT",
			addedLine:  2,
			resultLine: 3,
		},
		{
			name: "panic source",
			source: `fn handler(request: Request) {
	let value = request.headers().get("x-value");
	value.expect("required");
}
`,
			signal:     "SIGNAL_KIND_RUST_PANIC_IN_REQUEST_PATH",
			addedLine:  2,
			resultLine: 3,
		},
		{
			name: "filesystem source",
			source: `fn handler(request: Request) {
	let path = request.uri().path();
	std::fs::read(path);
}
`,
			signal:     "SIGNAL_KIND_RUST_UNTRUSTED_PATH",
			addedLine:  2,
			resultLine: 3,
		},
		{
			name: "RNG source",
			source: `fn issue() {
	let random = fastrand::u64(..);
	let session_token = random;
}
`,
			signal:     "SIGNAL_KIND_RUST_WEAK_RNG_FOR_SECRET",
			addedLine:  2,
			resultLine: 3,
		},
		{
			name: "blocking lock acquisition",
			source: `async fn update(lock: Lock) {
	let guard = lock.lock().unwrap();
	work().await;
	consume(guard);
}
`,
			signal:     "SIGNAL_KIND_RUST_BLOCKING_LOCK_ACROSS_AWAIT",
			addedLine:  2,
			resultLine: 2,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := t.TempDir()
			path := "source_only.rs"
			if err := os.WriteFile(filepath.Join(repository, path), []byte(test.source), 0o600); err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(strings.TrimSuffix(test.source, "\n"), "\n")
			diff := []byte(fmt.Sprintf("diff --git a/%s b/%s\n--- a/%s\n+++ b/%s\n@@ -%d,0 +%d @@\n+%s\n", path, path, path, path, test.addedLine-1, test.addedLine, lines[test.addedLine-1]))
			adapter, err := newAdapter(core, config, repository, append([]string(nil), integrationSignals...))
			if err != nil {
				t.Fatal(err)
			}
			response := adapter.analyze(t.Context(), requestFor(repository, config, diff))
			if response.Status != completeStatus || len(response.Signals) != 1 || response.Signals[0].Kind != test.signal || response.Signals[0].Location.StartLine != int32(test.resultLine) {
				t.Fatalf("response = %+v", response)
			}
		})
	}
}

func TestSemgrepCoreIntegrationRejectsInvalidRule(t *testing.T) {
	core, _ := integrationPaths(t)
	repository := t.TempDir()
	source := "package demo\nconst value = 1\n"
	if err := os.WriteFile(filepath.Join(repository, "main.go"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(t.TempDir(), "invalid.yml")
	rules := `rules:
  - id: room.invalid
    message: Invalid test rule.
    severity: ERROR
    languages: [go]
    metadata:
      room_signal: SIGNAL_KIND_DYNAMIC_SQL_WITH_UNTRUSTED_INPUT
      room_confidence_basis_points: 9000
    pattern: "("
`
	if err := os.WriteFile(config, []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}
	adapter, err := newAdapter(core, config, repository, []string{"SIGNAL_KIND_DYNAMIC_SQL_WITH_UNTRUSTED_INPUT"})
	if err != nil {
		t.Fatal(err)
	}
	response := adapter.analyze(t.Context(), requestFor(repository, config, newFileDiff("main.go", source)))
	if response.Status != failedStatus || response.FailureCode != "semgrep_report_invalid" {
		t.Fatalf("response = %+v", response)
	}
}

func TestSemgrepCoreIntegrationFailsClosedForUnsupportedLanguage(t *testing.T) {
	core, config := integrationPaths(t)
	repository := t.TempDir()
	source := "ghp_" + strings.Repeat("a", 36) + "\n"
	if err := os.WriteFile(filepath.Join(repository, "credentials.txt"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	adapter, err := newAdapter(core, config, repository, append([]string(nil), integrationSignals...))
	if err != nil {
		t.Fatal(err)
	}
	response := adapter.analyze(t.Context(), requestFor(repository, config, newFileDiff("credentials.txt", source)))
	if response.Status != failedStatus || response.FailureCode != "semgrep_targets_incomplete" {
		t.Fatalf("response = %+v", response)
	}
}

func integrationPaths(t *testing.T) (string, string) {
	t.Helper()
	core := os.Getenv("ROOM_SEMGREP_CORE")
	if core == "" {
		t.Fatal("ROOM_SEMGREP_CORE is required")
	}
	core, err := filepath.Abs(core)
	if err != nil {
		t.Fatal(err)
	}
	version, err := exec.Command(core, "-version").CombinedOutput()
	if err != nil || strings.TrimSpace(string(version)) != "semgrep-core version: "+semgrepCoreVersion {
		t.Fatalf("semgrep-core version = %q, error = %v", version, err)
	}
	config, err := filepath.Abs(filepath.Join("..", "..", "analyzers", "semgrep", "room.yml"))
	if err != nil {
		t.Fatal(err)
	}
	return core, config
}

func newFileDiff(path, source string) []byte {
	lines := strings.Split(strings.TrimSuffix(source, "\n"), "\n")
	var diff strings.Builder
	fmt.Fprintf(&diff, "diff --git a/%s b/%s\n--- /dev/null\n+++ b/%s\n@@ -0,0 +1,%d @@\n", path, path, path, len(lines))
	for _, line := range lines {
		diff.WriteByte('+')
		diff.WriteString(line)
		diff.WriteByte('\n')
	}
	return []byte(diff.String())
}
