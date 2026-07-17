package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	response := adapter.analyze(t.Context(), requestFor(repository, config, diff))

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

func TestAdapterReturnsPartialForPlansWithoutRunningSemgrep(t *testing.T) {
	root, repository := workspace(t)
	config := writeFile(t, "rules.yml", testRules)
	adapter, err := newAdapter("/missing/semgrep", config, root, []string{sqlSignal})
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
	adapter, err := newAdapter("/missing/semgrep", config, repository, []string{sqlSignal})
	if err != nil {
		t.Fatal(err)
	}
	response := adapter.analyze(t.Context(), requestFor(outside, config, diff))
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
	semgrep := fakeSemgrep(t, `{"version":"1","errors":[],"paths":{"scanned":["main.go"],"skipped":[]},"skipped_rules":[],"results":[{"check_id":"bad","path":"main.go","start":{"line":0},"end":{"line":0}}]}`, 0)
	config := writeFile(t, "rules.yml", testRules)
	adapter, err := newAdapter(semgrep, config, repository, []string{sqlSignal})
	if err != nil {
		t.Fatal(err)
	}
	diff := []byte("diff --git a/main.go b/main.go\n--- a/main.go\n+++ b/main.go\n@@ -0,0 +1 @@\n+package main\n")
	response := adapter.analyze(t.Context(), requestFor(repository, config, diff))
	if response.Status != failedStatus || response.FailureCode != "semgrep_result_invalid" {
		t.Fatalf("response = %+v", response)
	}
}

func TestAdapterFailsClosedForIncompleteOrSkippedScans(t *testing.T) {
	tests := []struct {
		name, report, code string
	}{
		{"target missing", `{"version":"1","errors":[],"paths":{"scanned":[],"skipped":[]},"skipped_rules":[],"results":[]}`, "semgrep_targets_incomplete"},
		{"target skipped", `{"version":"1","errors":[],"paths":{"scanned":["main.go"],"skipped":[{"path":"main.go"}]},"skipped_rules":[],"results":[]}`, "semgrep_report_invalid"},
		{"scan error", `{"version":"1","errors":[{"message":"parse failed"}],"paths":{"scanned":["main.go"],"skipped":[]},"skipped_rules":[],"results":[]}`, "semgrep_report_invalid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, repository := workspace(t)
			if err := os.WriteFile(filepath.Join(repository, "main.go"), []byte("package main\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			config := writeFile(t, "rules.yml", testRules)
			adapter, err := newAdapter(fakeSemgrep(t, tt.report, 0), config, repository, []string{sqlSignal})
			if err != nil {
				t.Fatal(err)
			}
			diff := []byte("diff --git a/main.go b/main.go\n--- /dev/null\n+++ b/main.go\n@@ -0,0 +1 @@\n+package main\n")
			response := adapter.analyze(t.Context(), requestFor(repository, config, diff))
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
	adapter, err := newAdapter("/missing/semgrep", config, repository, []string{sqlSignal})
	if err != nil {
		t.Fatal(err)
	}
	diff := []byte("diff --git a/main.go b/main.go\n--- /dev/null\n+++ b/main.go\n@@ -0,0 +1 @@\n+package main\n")
	response := adapter.analyze(t.Context(), requestFor(repository, config, diff))
	if response.FailureCode != "snapshot_invalid" {
		t.Fatalf("source mismatch response = %+v", response)
	}

	deletion := []byte("diff --git a/old.go b/old.go\n--- a/old.go\n+++ /dev/null\n@@ -1 +0,0 @@\n-package old\n")
	request := requestFor(repository, config, deletion)
	if err := os.WriteFile(config, []byte(testRules+"# changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	response = adapter.analyze(t.Context(), request)
	if response.FailureCode != "config_digest_mismatch" {
		t.Fatalf("config mismatch response = %+v", response)
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
	adapter, err := newAdapter("/missing/semgrep", config, repository, []string{sqlSignal})
	if err != nil {
		t.Fatal(err)
	}
	diff := []byte("diff --git a/main.go b/main.go\n--- /dev/null\n+++ b/main.go\n@@ -0,0 +1 @@\n+package main\n")
	if response := adapter.analyze(t.Context(), requestFor(repository, config, diff)); response.FailureCode != "snapshot_invalid" {
		t.Fatalf("response = %+v", response)
	}
}

func TestAdapterRejectsUnimplementedCoverageAndTraversalDiff(t *testing.T) {
	_, repository := workspace(t)
	emptyConfig := writeFile(t, "empty.yml", "rules: []\n")
	if _, err := newAdapter("/missing/semgrep", emptyConfig, repository, []string{sqlSignal}); err == nil {
		t.Fatal("expected empty ruleset to be rejected")
	}
	diff := []byte("diff --git a/x b/x\n--- a/../../x\n+++ /dev/null\n@@ -1 +0,0 @@\n-secret\n")
	if _, err := parseDiff(diff); err == nil {
		t.Fatal("expected traversal diff to be rejected")
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

func requestFor(repository, config string, content []byte) analyzerRequest {
	request := requestForPhase(repository, content, "ANALYSIS_PHASE_DIFF")
	configData, _ := os.ReadFile(config)
	configDigest := sha256.Sum256(configData)
	request.ConfigSHA256 = hex.EncodeToString(configDigest[:])
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
	args := []string{"--semgrep-core", "/missing/semgrep-core", "--config", config, "--repository-root", repository, "--covered-signal", sqlSignal}
	if code := run(args, bytes.NewReader(encoded), &stdout, &stderr); code != 0 {
		t.Fatalf("run exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"status":"ANALYSIS_STATUS_PARTIAL"`) {
		t.Fatalf("stdout = %s", stdout.String())
	}
}
