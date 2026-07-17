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
	"SIGNAL_KIND_RUST_COMMAND_WITH_UNTRUSTED_ARGUMENT",
}

const semgrepCoreVersion = "1.139.0"

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
			name: "Rust request header command argument",
			path: "request_command.rs",
			source: `use std::process::Command;
fn handler(request: Request) {
	let arg = request.headers().get("x-command").unwrap();
	Command::new("tool").arg(arg).status();
}
`,
			signal: "SIGNAL_KIND_RUST_COMMAND_WITH_UNTRUSTED_ARGUMENT",
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
