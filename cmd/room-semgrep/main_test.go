package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const sqlSignal = "SIGNAL_KIND_DYNAMIC_SQL_WITH_UNTRUSTED_INPUT"

const testRules = `rules:
  - id: room.test
    metadata:
      room_signal: SIGNAL_KIND_DYNAMIC_SQL_WITH_UNTRUSTED_INPUT
      room_confidence_basis_points: 9000
`

func TestAdapterMapsSemgrepMetadataAndFiltersToAddedLines(t *testing.T) {
	_, repository := workspace(t)
	if err := os.WriteFile(filepath.Join(repository, "handler.go"), []byte(strings.Repeat("\n", 7)+"db.Query(query)\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	report := `{
  "version":"1.139.0",
  "errors":[],
  "paths":{"scanned":["handler.go"],"skipped":[]},
  "skipped_rules":[],
  "results":[
    {"check_id":"old","path":"handler.go","start":{"line":3},"end":{"line":3},"extra":{"metadata":{"room_signal":"SIGNAL_KIND_DYNAMIC_SQL_WITH_UNTRUSTED_INPUT","room_confidence_basis_points":9000}}},
    {"check_id":"new","path":"handler.go","start":{"line":8},"end":{"line":8},"extra":{"metadata":{"room_signal":"SIGNAL_KIND_DYNAMIC_SQL_WITH_UNTRUSTED_INPUT","room_confidence_basis_points":9000}}}
  ]
}`
	semgrep := fakeSemgrep(t, report, 0)
	config := writeFile(t, "rules.yml", testRules)
	adapter, err := newAdapter(semgrep, config, repository, []string{sqlSignal})
	if err != nil {
		t.Fatal(err)
	}
	diff := []byte("diff --git a/handler.go b/handler.go\n--- a/handler.go\n+++ b/handler.go\n@@ -7,0 +8 @@\n+db.Query(query)\n")
	response := adapter.analyze(t.Context(), requestFor(repository, config, semgrep, diff))

	if response.Status != completeStatus || fmt.Sprint(response.CoveredSignals) != "["+sqlSignal+"]" {
		t.Fatalf("response = %+v", response)
	}
	if len(response.Signals) != 1 || response.Signals[0].Kind != sqlSignal || response.Signals[0].Location.FilePath != "handler.go" || response.Signals[0].Location.StartLine != 8 || response.Signals[0].ConfidenceBasisPoints != 9000 {
		t.Fatalf("signals = %+v", response.Signals)
	}
	if response.Signals[0].Fingerprint == "" || len(response.Signals[0].EvidenceSHA256) != 64 {
		t.Fatalf("signal lacks receipt hashes: %+v", response.Signals[0])
	}
}

func TestAdapterFiltersAgainstSemgrepDataflowTrace(t *testing.T) {
	_, repository := workspace(t)
	source := "fn handler() {\n\tlet query = input();\n\tdb.Query(query);\n}\n"
	if err := os.WriteFile(filepath.Join(repository, "handler.go"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	report := `{
  "version":"1.139.0",
  "errors":[],
  "paths":{"scanned":["handler.go"],"skipped":[]},
  "skipped_rules":[],
  "results":[{"check_id":"taint","path":"handler.go","start":{"line":3},"end":{"line":3},"extra":{
    "metadata":{"room_signal":"SIGNAL_KIND_DYNAMIC_SQL_WITH_UNTRUSTED_INPUT","room_confidence_basis_points":9000},
    "dataflow_trace":{
      "taint_source":["CliLoc",[{"path":"handler.go","start":{"line":2},"end":{"line":2}},"input()"]],
      "intermediate_vars":[],
      "taint_sink":["CliLoc",[{"path":"handler.go","start":{"line":3},"end":{"line":3}},"query"]]
    }
  }}]
}`
	config := writeFile(t, "rules.yml", testRules)
	semgrep := fakeSemgrep(t, report, 0)
	adapter, err := newAdapter(semgrep, config, repository, []string{sqlSignal})
	if err != nil {
		t.Fatal(err)
	}

	diff := []byte("diff --git a/handler.go b/handler.go\n--- a/handler.go\n+++ b/handler.go\n@@ -1,0 +2 @@\n+\tlet query = input();\n")
	response := adapter.analyze(t.Context(), requestFor(repository, config, semgrep, diff))
	if response.Status != completeStatus || len(response.Signals) != 1 || response.Signals[0].Location.StartLine != 3 {
		t.Fatalf("source-intersection response = %+v", response)
	}

	diff = []byte("diff --git a/handler.go b/handler.go\n--- a/handler.go\n+++ b/handler.go\n@@ -0,0 +1 @@\n+fn handler() {\n")
	response = adapter.analyze(t.Context(), requestFor(repository, config, semgrep, diff))
	if response.Status != completeStatus || len(response.Signals) != 0 {
		t.Fatalf("non-intersection response = %+v", response)
	}
}

func TestAdapterRejectsInvalidSemgrepRanges(t *testing.T) {
	tests := []struct {
		name, resultEnd, tracePath string
		traceLine                  int
	}{
		{name: "result beyond file", resultEnd: "9223372036854775807", tracePath: "handler.go", traceLine: 2},
		{name: "trace beyond file", resultEnd: "3", tracePath: "handler.go", traceLine: 999},
		{name: "trace outside target", resultEnd: "3", tracePath: "../handler.go", traceLine: 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, repository := workspace(t)
			source := "fn handler() {\n\tlet query = input();\n\tdb.Query(query);\n}\n"
			if err := os.WriteFile(filepath.Join(repository, "handler.go"), []byte(source), 0o600); err != nil {
				t.Fatal(err)
			}
			report := fmt.Sprintf(`{
  "version":"1.139.0","errors":[],"paths":{"scanned":["handler.go"],"skipped":[]},"skipped_rules":[],
  "results":[{"check_id":"taint","path":"handler.go","start":{"line":3},"end":{"line":%s},"extra":{
    "metadata":{"room_signal":"SIGNAL_KIND_DYNAMIC_SQL_WITH_UNTRUSTED_INPUT","room_confidence_basis_points":9000},
    "dataflow_trace":{
      "taint_source":["CliLoc",[{"path":%q,"start":{"line":%d},"end":{"line":%d}},"input()"]],
      "intermediate_vars":[],
      "taint_sink":["CliLoc",[{"path":"handler.go","start":{"line":3},"end":{"line":3}},"query"]]
    }
  }}]}`, test.resultEnd, test.tracePath, test.traceLine, test.traceLine)
			config := writeFile(t, "rules.yml", testRules)
			semgrep := fakeSemgrep(t, report, 0)
			adapter, err := newAdapter(semgrep, config, repository, []string{sqlSignal})
			if err != nil {
				t.Fatal(err)
			}
			diff := []byte("diff --git a/handler.go b/handler.go\n--- a/handler.go\n+++ b/handler.go\n@@ -1,0 +2 @@\n+\tlet query = input();\n")
			response := adapter.analyze(t.Context(), requestFor(repository, config, semgrep, diff))
			if response.Status != failedStatus || response.FailureCode != "semgrep_result_invalid" {
				t.Fatalf("response = %+v", response)
			}
		})
	}
}

func TestAdapterReturnsPartialForPlansWithoutRunningSemgrep(t *testing.T) {
	root, repository := workspace(t)
	config := writeFile(t, "rules.yml", testRules)
	adapter, err := newAdapter(fakeTool(t), config, root, []string{sqlSignal})
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("Build a query endpoint")
	response := adapter.analyze(t.Context(), requestForPhase(repository, content, "ANALYSIS_PHASE_PLAN"))
	if response.Status != partialStatus || response.FailureCode != "semgrep_requires_diff" || len(response.CoveredSignals) != 0 {
		t.Fatalf("response = %+v", response)
	}
}

func TestAdapterRejectsWorkspaceOutsideConfiguredRoot(t *testing.T) {
	_, repository := workspace(t)
	outside := t.TempDir()
	config := writeFile(t, "rules.yml", testRules)
	diff := []byte("diff --git a/main.go b/main.go\n--- a/main.go\n+++ b/main.go\n@@ -0,0 +1 @@\n+package main\n")
	if err := os.WriteFile(filepath.Join(outside, "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tool := fakeTool(t)
	adapter, err := newAdapter(tool, config, repository, []string{sqlSignal})
	if err != nil {
		t.Fatal(err)
	}
	response := adapter.analyze(t.Context(), requestFor(outside, config, tool, diff))
	if response.Status != failedStatus || response.FailureCode != "snapshot_invalid" {
		t.Fatalf("response = %+v", response)
	}
}

func TestAddedLinesTreatsSourceBeginningWithPlusAsHunkContent(t *testing.T) {
	diff := []byte("diff --git a/value.go b/value.go\n--- a/value.go\n+++ b/value.go\n@@ -0,0 +1 @@\n+++counter\n")
	artifact, err := parseDiff(diff)
	if err != nil {
		t.Fatal(err)
	}
	if !artifact.added["value.go"][1] {
		t.Fatalf("added lines = %+v", artifact.added)
	}
}

func TestAdapterRejectsMalformedSemgrepResult(t *testing.T) {
	_, repository := workspace(t)
	if err := os.WriteFile(filepath.Join(repository, "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	semgrep := fakeSemgrep(t, `{"version":"1.139.0","errors":[],"paths":{"scanned":["main.go"],"skipped":[]},"skipped_rules":[],"results":[{"check_id":"bad","path":"main.go","start":{"line":0},"end":{"line":0}}]}`, 0)
	config := writeFile(t, "rules.yml", testRules)
	adapter, err := newAdapter(semgrep, config, repository, []string{sqlSignal})
	if err != nil {
		t.Fatal(err)
	}
	diff := []byte("diff --git a/main.go b/main.go\n--- a/main.go\n+++ b/main.go\n@@ -0,0 +1 @@\n+package main\n")
	response := adapter.analyze(t.Context(), requestFor(repository, config, semgrep, diff))
	if response.Status != failedStatus || response.FailureCode != "semgrep_result_invalid" {
		t.Fatalf("response = %+v", response)
	}
}

func TestAdapterFailsClosedForIncompleteOrSkippedScans(t *testing.T) {
	tests := []struct {
		name, report, code string
	}{
		{"version mismatch", `{"version":"1.139.1","errors":[],"paths":{"scanned":["main.go"],"skipped":[]},"skipped_rules":[],"results":[]}`, "semgrep_report_invalid"},
		{"target missing", `{"version":"1.139.0","errors":[],"paths":{"scanned":[],"skipped":[]},"skipped_rules":[],"results":[]}`, "semgrep_targets_incomplete"},
		{"target skipped", `{"version":"1.139.0","errors":[],"paths":{"scanned":["main.go"],"skipped":[{"path":"main.go"}]},"skipped_rules":[],"results":[]}`, "semgrep_report_invalid"},
		{"scan error", `{"version":"1.139.0","errors":[{"message":"parse failed"}],"paths":{"scanned":["main.go"],"skipped":[]},"skipped_rules":[],"results":[]}`, "semgrep_report_invalid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, repository := workspace(t)
			if err := os.WriteFile(filepath.Join(repository, "main.go"), []byte("package main\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			config := writeFile(t, "rules.yml", testRules)
			semgrep := fakeSemgrep(t, tt.report, 0)
			adapter, err := newAdapter(semgrep, config, repository, []string{sqlSignal})
			if err != nil {
				t.Fatal(err)
			}
			diff := []byte("diff --git a/main.go b/main.go\n--- /dev/null\n+++ b/main.go\n@@ -0,0 +1 @@\n+package main\n")
			response := adapter.analyze(t.Context(), requestFor(repository, config, semgrep, diff))
			if response.Status != failedStatus || response.FailureCode != tt.code {
				t.Fatalf("response = %+v", response)
			}
		})
	}
}

func TestAdapterBindsConfigAndSourcePostimage(t *testing.T) {
	_, repository := workspace(t)
	if err := os.WriteFile(filepath.Join(repository, "main.go"), []byte("package changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := writeFile(t, "rules.yml", testRules)
	tool := fakeTool(t)
	adapter, err := newAdapter(tool, config, repository, []string{sqlSignal})
	if err != nil {
		t.Fatal(err)
	}
	diff := []byte("diff --git a/main.go b/main.go\n--- /dev/null\n+++ b/main.go\n@@ -0,0 +1 @@\n+package main\n")
	response := adapter.analyze(t.Context(), requestFor(repository, config, tool, diff))
	if response.FailureCode != "snapshot_invalid" {
		t.Fatalf("source mismatch response = %+v", response)
	}

	deletion := []byte("diff --git a/old.go b/old.go\n--- a/old.go\n+++ /dev/null\n@@ -1 +0,0 @@\n-package old\n")
	request := requestFor(repository, config, tool, deletion)
	if err := os.WriteFile(config, []byte(testRules+"# changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	response = adapter.analyze(t.Context(), request)
	if response.FailureCode != "config_digest_mismatch" {
		t.Fatalf("config mismatch response = %+v", response)
	}
}

func TestAdapterBindsToolDigest(t *testing.T) {
	_, repository := workspace(t)
	if err := os.WriteFile(filepath.Join(repository, "handler.go"), []byte(strings.Repeat("\n", 7)+"db.Query(query)\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	report := `{
  "version":"1.139.0",
  "errors":[],
  "paths":{"scanned":["handler.go"],"skipped":[]},
  "skipped_rules":[],
  "results":[
    {"check_id":"old","path":"handler.go","start":{"line":3},"end":{"line":3},"extra":{"metadata":{"room_signal":"SIGNAL_KIND_DYNAMIC_SQL_WITH_UNTRUSTED_INPUT","room_confidence_basis_points":9000}}},
    {"check_id":"new","path":"handler.go","start":{"line":8},"end":{"line":8},"extra":{"metadata":{"room_signal":"SIGNAL_KIND_DYNAMIC_SQL_WITH_UNTRUSTED_INPUT","room_confidence_basis_points":9000}}}
  ]
}`
	semgrep := fakeSemgrep(t, report, 0)
	config := writeFile(t, "rules.yml", testRules)
	adapter, err := newAdapter(semgrep, config, repository, []string{sqlSignal})
	if err != nil {
		t.Fatal(err)
	}
	diff := []byte("diff --git a/handler.go b/handler.go\n--- a/handler.go\n+++ b/handler.go\n@@ -7,0 +8 @@\n+db.Query(query)\n")
	request := requestFor(repository, config, semgrep, diff)

	request.ToolSHA256 = ""
	if response := adapter.analyze(t.Context(), request); response.Status != failedStatus || response.FailureCode != "tool_digest_mismatch" {
		t.Fatalf("empty tool digest response = %+v", response)
	}
	other := sha256.Sum256([]byte("other-binary"))
	request.ToolSHA256 = hex.EncodeToString(other[:])
	if response := adapter.analyze(t.Context(), request); response.Status != failedStatus || response.FailureCode != "tool_digest_mismatch" {
		t.Fatalf("wrong tool digest response = %+v", response)
	}
}

func TestAdapterRejectsSymlinkTargets(t *testing.T) {
	_, repository := workspace(t)
	realFile := filepath.Join(repository, "real.go")
	if err := os.WriteFile(realFile, []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realFile, filepath.Join(repository, "main.go")); err != nil {
		t.Fatal(err)
	}
	config := writeFile(t, "rules.yml", testRules)
	tool := fakeTool(t)
	adapter, err := newAdapter(tool, config, repository, []string{sqlSignal})
	if err != nil {
		t.Fatal(err)
	}
	diff := []byte("diff --git a/main.go b/main.go\n--- /dev/null\n+++ b/main.go\n@@ -0,0 +1 @@\n+package main\n")
	if response := adapter.analyze(t.Context(), requestFor(repository, config, tool, diff)); response.FailureCode != "snapshot_invalid" {
		t.Fatalf("response = %+v", response)
	}
}

func TestAdapterKillsSemgrepProcessGroup(t *testing.T) {
	_, repository := workspace(t)
	if err := os.WriteFile(filepath.Join(repository, "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	semgrep := writeExecutable(t, "semgrep", "#!/bin/sh\nsleep 60 &\necho $! > '"+pidFile+"'\nwait\n")
	config := writeFile(t, "rules.yml", testRules)
	adapter, err := newAdapter(semgrep, config, repository, []string{sqlSignal})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	diff := []byte("diff --git a/main.go b/main.go\n--- /dev/null\n+++ b/main.go\n@@ -0,0 +1 @@\n+package main\n")
	response := adapter.analyze(ctx, requestFor(repository, config, semgrep, diff))
	if response.Status != failedStatus || response.FailureCode != "semgrep_failed" {
		t.Fatalf("response = %+v", response)
	}
	assertProcessDies(t, pidFile)
}

func assertProcessDies(t *testing.T, pidFile string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var pid int
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(pidFile)
		if err == nil {
			pid, err = strconv.Atoi(strings.TrimSpace(string(data)))
			if err == nil && pid > 0 {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if pid <= 0 {
		t.Fatal("child pid was not recorded")
	}
	for time.Now().Before(deadline) {
		if err := syscall.Kill(pid, 0); err == syscall.ESRCH {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("process %d survived the group kill", pid)
}

func TestAdapterRejectsSymlinkedConfig(t *testing.T) {
	_, repository := workspace(t)
	target := writeFile(t, "real-rules.yml", testRules)
	linked := filepath.Join(t.TempDir(), "rules.yml")
	if err := os.Symlink(target, linked); err != nil {
		t.Fatal(err)
	}
	if _, err := newAdapter(fakeTool(t), linked, repository, []string{sqlSignal}); err == nil {
		t.Fatal("expected symlinked config to be rejected")
	}
}

func TestAdapterBindsSymlinkedToolToRegularTarget(t *testing.T) {
	_, repository := workspace(t)
	config := writeFile(t, "rules.yml", testRules)
	linked := filepath.Join(t.TempDir(), "semgrep-core")
	if err := os.Symlink(fakeTool(t), linked); err != nil {
		t.Fatal(err)
	}
	if _, err := newAdapter(linked, config, repository, []string{sqlSignal}); err != nil {
		t.Fatalf("symlink to a regular tool must be accepted: %v", err)
	}
	dangling := filepath.Join(t.TempDir(), "dangling-core")
	if err := os.Symlink(filepath.Join(t.TempDir(), "missing"), dangling); err != nil {
		t.Fatal(err)
	}
	if _, err := newAdapter(dangling, config, repository, []string{sqlSignal}); err == nil {
		t.Fatal("expected dangling symlink to be rejected")
	}
}

func TestAdapterFailsClosedWhenConfigBecomesSymlink(t *testing.T) {
	_, repository := workspace(t)
	if err := os.WriteFile(filepath.Join(repository, "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := writeFile(t, "rules.yml", testRules)
	tool := fakeTool(t)
	adapter, err := newAdapter(tool, config, repository, []string{sqlSignal})
	if err != nil {
		t.Fatal(err)
	}
	request := requestFor(repository, config, tool, []byte("diff --git a/main.go b/main.go\n--- /dev/null\n+++ b/main.go\n@@ -0,0 +1 @@\n+package main\n"))
	target := writeFile(t, "same-rules.yml", testRules)
	if err := os.Remove(config); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, config); err != nil {
		t.Fatal(err)
	}
	if response := adapter.analyze(t.Context(), request); response.FailureCode != "config_digest_mismatch" {
		t.Fatalf("response = %+v", response)
	}
}

func TestAdapterFailsClosedWhenToolChanges(t *testing.T) {
	_, repository := workspace(t)
	if err := os.WriteFile(filepath.Join(repository, "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tool := fakeTool(t)
	config := writeFile(t, "rules.yml", testRules)
	adapter, err := newAdapter(tool, config, repository, []string{sqlSignal})
	if err != nil {
		t.Fatal(err)
	}
	request := requestFor(repository, config, tool, []byte("diff --git a/main.go b/main.go\n--- /dev/null\n+++ b/main.go\n@@ -0,0 +1 @@\n+package main\n"))
	if err := os.WriteFile(tool, []byte("#!/bin/sh\nexit 2\n# changed\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if response := adapter.analyze(t.Context(), request); response.Status != failedStatus || response.FailureCode != "tool_digest_mismatch" {
		t.Fatalf("response = %+v", response)
	}
}

func TestAdapterRejectsUnimplementedCoverageAndTraversalDiff(t *testing.T) {
	_, repository := workspace(t)
	emptyConfig := writeFile(t, "empty.yml", "rules: []\n")
	if _, err := newAdapter(fakeTool(t), emptyConfig, repository, []string{sqlSignal}); err == nil {
		t.Fatal("expected empty ruleset to be rejected")
	}
	diff := []byte("diff --git a/x b/x\n--- a/../../x\n+++ /dev/null\n@@ -1 +0,0 @@\n-secret\n")
	if _, err := parseDiff(diff); err == nil {
		t.Fatal("expected traversal diff to be rejected")
	}
}

func TestSemgrepTraceRanges(t *testing.T) {
	trace := []byte(`{"taint_source":["CliLoc",[{"path":"main.rs","start":{"line":2},"end":{"line":3}},"source"]],"intermediate_vars":[{"location":{"path":"main.rs","start":{"line":4},"end":{"line":4}},"content":"value"}],"taint_sink":["CliLoc",[{"path":"main.rs","start":{"line":5},"end":{"line":5}},"sink"]]}`)
	ranges, err := semgrepTraceRanges(trace)
	if err != nil {
		t.Fatal(err)
	}
	want := []semgrepTraceRange{{Path: "main.rs", Start: 2, End: 3}, {Path: "main.rs", Start: 4, End: 4}, {Path: "main.rs", Start: 5, End: 5}}
	if fmt.Sprint(ranges) != fmt.Sprint(want) {
		t.Fatalf("ranges = %+v, want %+v", ranges, want)
	}
	nested := []byte(`{"taint_source":["CliCall",[[{"path":"main.rs","start":{"line":1},"end":{"line":1}},"call"],[],["CliLoc",[{"path":"main.rs","start":{"line":2},"end":{"line":2}},"source"]]]],"taint_sink":["CliLoc",[{"path":"main.rs","start":{"line":3},"end":{"line":3}},"sink"]]}`)
	ranges, err = semgrepTraceRanges(nested)
	if err != nil || len(ranges) != 3 {
		t.Fatalf("nested ranges = %+v, error = %v", ranges, err)
	}

	for _, invalid := range []string{
		`null`,
		`"trace"`,
		`{}`,
		`{"taint_source":[],"taint_sink":[]}`,
		`{"taint_source":["Unknown",[]],"taint_sink":["CliLoc",[{"path":"main.rs","start":{"line":1},"end":{"line":1}},"sink"]]}`,
		`{"taint_source":["CliCall",[]],"taint_sink":["CliLoc",[{"path":"main.rs","start":{"line":1},"end":{"line":1}},"sink"]]}`,
		`{"taint_source":["CliLoc",[{"path":"main.rs","start":{"line":0},"end":{"line":1}},"source"]],"taint_sink":["CliLoc",[{"path":"main.rs","start":{"line":1},"end":{"line":1}},"sink"]]}`,
		`{"taint_source":["CliLoc",[{"path":"main.rs","start":{"line":2},"end":{"line":1}},"source"]],"taint_sink":["CliLoc",[{"path":"main.rs","start":{"line":1},"end":{"line":1}},"sink"]]}`,
		`{"taint_source":["CliLoc",[{"path":"main.rs","start":{"line":"2"},"end":{"line":2}},"source"]],"taint_sink":["CliLoc",[{"path":"main.rs","start":{"line":1},"end":{"line":1}},"sink"]]}`,
		`{} {}`,
	} {
		if _, err := semgrepTraceRanges([]byte(invalid)); err == nil {
			t.Fatalf("expected invalid trace %q to fail", invalid)
		}
	}
}

func workspace(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	repository := filepath.Join(root, "repo")
	if err := os.Mkdir(repository, 0o700); err != nil {
		t.Fatal(err)
	}
	return root, repository
}

func requestFor(repository, config, semgrepCore string, content []byte) analyzerRequest {
	request := requestForPhase(repository, content, "ANALYSIS_PHASE_DIFF")
	configData, _ := os.ReadFile(config)
	configDigest := sha256.Sum256(configData)
	request.ConfigSHA256 = hex.EncodeToString(configDigest[:])
	toolData, _ := os.ReadFile(semgrepCore)
	toolDigest := sha256.Sum256(toolData)
	request.ToolSHA256 = hex.EncodeToString(toolDigest[:])
	return request
}

func requestForPhase(repository string, content []byte, phase string) analyzerRequest {
	digest := sha256.Sum256(content)
	return analyzerRequest{Phase: phase, Content: content, WorkingDirectory: repository, InputSHA256: hex.EncodeToString(digest[:])}
}

func fakeSemgrep(t *testing.T, report string, exitCode int) string {
	t.Helper()
	return writeExecutable(t, "semgrep", fmt.Sprintf("#!/bin/sh\nprintf '%%s' '%s'\nexit %d\n", report, exitCode))
}

func fakeTool(t *testing.T) string {
	t.Helper()
	return writeExecutable(t, "semgrep-core", "#!/bin/sh\nexit 1\n")
}

func writeExecutable(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunEmitsStrictProviderJSON(t *testing.T) {
	_, repository := workspace(t)
	content := []byte("plan")
	request := requestForPhase(repository, content, "ANALYSIS_PHASE_PLAN")
	encoded, _ := json.Marshal(request)
	var stdout, stderr bytes.Buffer
	config := writeFile(t, "rules.yml", testRules)
	args := []string{"--semgrep-core", fakeTool(t), "--config", config, "--repository-root", repository, "--covered-signal", sqlSignal}
	if code := run(args, bytes.NewReader(encoded), &stdout, &stderr); code != 0 {
		t.Fatalf("run exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"status":"ANALYSIS_STATUS_PARTIAL"`) {
		t.Fatalf("stdout = %s", stdout.String())
	}
}
