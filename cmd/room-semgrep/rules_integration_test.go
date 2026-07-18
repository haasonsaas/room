//go:build semgrep_integration

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
			response := adapter.analyze(t.Context(), requestFor(repository, config, core, newFileDiff(test.path, test.source)))
			if response.Status != completeStatus {
				t.Fatalf("response = %+v", response)
			}
			if len(response.Signals) != 1 || response.Signals[0].Kind != test.signal {
				t.Fatalf("signals = %+v", response.Signals)
			}
		})
	}
}
