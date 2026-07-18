//go:build semgrep_integration

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
	response := adapter.analyze(t.Context(), requestFor(repository, config, core, diff))
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
			response := adapter.analyze(t.Context(), requestFor(repository, config, core, diff))
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
	response := adapter.analyze(t.Context(), requestFor(repository, config, core, newFileDiff("main.go", source)))
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
	response := adapter.analyze(t.Context(), requestFor(repository, config, core, newFileDiff("credentials.txt", source)))
	if response.Status != failedStatus || response.FailureCode != "semgrep_targets_incomplete" {
		t.Fatalf("response = %+v", response)
	}
}
