//go:build semgrep_integration

package main

import (
	"os"
	"path/filepath"
	"testing"
)

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
			response := adapter.analyze(t.Context(), requestFor(repository, config, core, newFileDiff(test.path, test.source)))
			if response.Status != completeStatus || len(response.Signals) != 0 {
				t.Fatalf("response = %+v", response)
			}
		})
	}
}
