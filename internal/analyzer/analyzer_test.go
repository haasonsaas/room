package analyzer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	roomv1 "github.com/haasonsaas/room/gen/go/room/v1"
)

const secretSignal = roomv1.SignalKind_SIGNAL_KIND_SECRET_LITERAL

func TestExternalAnalyzerStampsTrustedIdentityAndArtifact(t *testing.T) {
	input := Input{Phase: roomv1.AnalysisPhase_ANALYSIS_PHASE_DIFF, Content: []byte("diff bytes"), ChangedFiles: []string{"api.go"}}
	digest := sha256.Sum256(input.Content)
	executable := writeProvider(t, fmt.Sprintf(`{
  "phase":"ANALYSIS_PHASE_DIFF",
  "status":"ANALYSIS_STATUS_COMPLETE",
  "languages":[" Go ","SQL"],
  "frameworks":["ConnectRPC"],
  "covered_signals":["SIGNAL_KIND_SECRET_LITERAL"],
  "signals":[{
    "kind":"SIGNAL_KIND_SECRET_LITERAL",
    "fingerprint":"secret-1",
    "location":{"file_path":"api.go","start_line":4,"end_line":4},
    "confidence_basis_points":9500,
    "evidence_sha256":"%s"
  }],
  "input_sha256":"%s"
}`, hex.EncodeToString(digest[:]), hex.EncodeToString(digest[:])))

	analyzer, err := NewExternal(Config{
		ID: "semgrep", Version: "1.2.3", Executable: executable,
		Args: []string{"--mode", "room"}, Config: []byte("rules-v4"), CoveredSignals: []roomv1.SignalKind{secretSignal},
	})
	if err != nil {
		t.Fatal(err)
	}
	report := analyzer.Analyze(context.Background(), input)

	if report.GetStatus() != roomv1.AnalysisStatus_ANALYSIS_STATUS_COMPLETE {
		t.Fatalf("status = %s", report.GetStatus())
	}
	if got := report.GetArtifact().GetSha256(); string(got) != string(digest[:]) {
		t.Fatalf("artifact digest = %x", got)
	}
	if got := report.GetArtifact().GetPhase(); got != input.Phase {
		t.Fatalf("phase = %s", got)
	}
	if fmt.Sprint(report.GetArtifact().GetLanguages()) != "[go sql]" || fmt.Sprint(report.GetArtifact().GetFrameworks()) != "[connectrpc]" {
		t.Fatalf("artifact classification = languages %v frameworks %v", report.GetArtifact().GetLanguages(), report.GetArtifact().GetFrameworks())
	}
	receipt := report.GetReceipts()[0]
	wantConfigDigest := sha256.Sum256([]byte("rules-v4"))
	if receipt.GetAnalyzer().GetId() != "semgrep" || receipt.GetAnalyzer().GetVersion() != "1.2.3" {
		t.Fatalf("identity = %+v", receipt.GetAnalyzer())
	}
	if string(receipt.GetAnalyzer().GetConfigSha256()) != string(wantConfigDigest[:]) {
		t.Fatalf("config digest = %x", receipt.GetAnalyzer().GetConfigSha256())
	}
	if string(receipt.GetInputSha256()) != string(digest[:]) {
		t.Fatalf("input digest = %x", receipt.GetInputSha256())
	}
	if got := receipt.GetSignals()[0].GetAnalyzer(); got.GetId() != "semgrep" || string(got.GetConfigSha256()) != string(wantConfigDigest[:]) {
		t.Fatalf("signal identity = %+v", got)
	}
}

func TestExternalAnalyzerRejectsInvalidProviderReceipts(t *testing.T) {
	input := Input{Phase: roomv1.AnalysisPhase_ANALYSIS_PHASE_PLAN, Content: []byte("plan")}
	digest := sha256.Sum256(input.Content)
	validDigest := hex.EncodeToString(digest[:])
	tests := []struct{ name, body, code string }{
		{"wrong stage", fmt.Sprintf(`{"phase":"ANALYSIS_PHASE_DIFF","status":"ANALYSIS_STATUS_COMPLETE","covered_signals":["SIGNAL_KIND_SECRET_LITERAL"],"input_sha256":%q}`, validDigest), "stage_mismatch"},
		{"wrong digest", `{"phase":"ANALYSIS_PHASE_PLAN","status":"ANALYSIS_STATUS_COMPLETE","covered_signals":["SIGNAL_KIND_SECRET_LITERAL"],"input_sha256":"0000000000000000000000000000000000000000000000000000000000000000"}`, "input_digest_mismatch"},
		{"missing coverage", fmt.Sprintf(`{"phase":"ANALYSIS_PHASE_PLAN","status":"ANALYSIS_STATUS_COMPLETE","covered_signals":[],"input_sha256":%q}`, validDigest), "coverage_incomplete"},
		{"invalid confidence", fmt.Sprintf(`{"phase":"ANALYSIS_PHASE_PLAN","status":"ANALYSIS_STATUS_COMPLETE","covered_signals":["SIGNAL_KIND_SECRET_LITERAL"],"signals":[{"kind":"SIGNAL_KIND_SECRET_LITERAL","fingerprint":"x","confidence_basis_points":10001}],"input_sha256":%q}`, validDigest), "confidence_invalid"},
		{"unstamped identity", fmt.Sprintf(`{"phase":"ANALYSIS_PHASE_PLAN","status":"ANALYSIS_STATUS_COMPLETE","covered_signals":["SIGNAL_KIND_SECRET_LITERAL"],"analyzer":{"id":"attacker"},"input_sha256":%q}`, validDigest), "provider_output_invalid"},
		{"unknown signal", fmt.Sprintf(`{"phase":"ANALYSIS_PHASE_PLAN","status":"ANALYSIS_STATUS_COMPLETE","covered_signals":["SIGNAL_KIND_NOT_REAL"],"input_sha256":%q}`, validDigest), "provider_output_invalid"},
		{"invalid classification", fmt.Sprintf(`{"phase":"ANALYSIS_PHASE_PLAN","status":"ANALYSIS_STATUS_COMPLETE","languages":["go"," GO "],"covered_signals":["SIGNAL_KIND_SECRET_LITERAL"],"input_sha256":%q}`, validDigest), "classification_invalid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executable := writeProvider(t, tt.body)
			a, err := NewExternal(Config{ID: "trusted", Version: "1", Executable: executable, CoveredSignals: []roomv1.SignalKind{secretSignal}})
			if err != nil {
				t.Fatal(err)
			}
			report := a.Analyze(context.Background(), input)
			if report.GetStatus() != roomv1.AnalysisStatus_ANALYSIS_STATUS_INVALID {
				t.Fatalf("status = %s", report.GetStatus())
			}
			receipt := report.GetReceipts()[0]
			if receipt.GetFailureCode() != tt.code {
				t.Fatalf("failure code = %q, want %q", receipt.GetFailureCode(), tt.code)
			}
			if receipt.GetAnalyzer().GetId() != "trusted" {
				t.Fatalf("identity not stamped: %+v", receipt.GetAnalyzer())
			}
		})
	}
}

func TestExternalAnalyzerUnavailableIsFailSafe(t *testing.T) {
	executable := writeProvider(t, `{}`)
	a, err := NewExternal(Config{ID: "ast", Version: "2", Executable: executable, CoveredSignals: []roomv1.SignalKind{secretSignal}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(executable); err != nil {
		t.Fatal(err)
	}
	report := a.Analyze(context.Background(), Input{Phase: roomv1.AnalysisPhase_ANALYSIS_PHASE_PLAN, Content: []byte("auth allowlist parameterized")})
	if report.GetStatus() != roomv1.AnalysisStatus_ANALYSIS_STATUS_UNAVAILABLE {
		t.Fatalf("status = %s", report.GetStatus())
	}
	receipt := report.GetReceipts()[0]
	if receipt.GetFailureCode() != "provider_unavailable" {
		t.Fatalf("failure code = %q", receipt.GetFailureCode())
	}
	if len(receipt.GetSignals()) != 0 {
		t.Fatalf("unavailable provider emitted signals: %+v", receipt.GetSignals())
	}
}

func TestExternalAnalyzerHasExecutionDeadline(t *testing.T) {
	executable := filepath.Join(t.TempDir(), "slow-analyzer")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nexec sleep 2\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	a, err := NewExternal(Config{ID: "slow", Version: "1", Executable: executable, Timeout: 20 * time.Millisecond, CoveredSignals: []roomv1.SignalKind{secretSignal}})
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	report := a.Analyze(context.Background(), Input{Phase: roomv1.AnalysisPhase_ANALYSIS_PHASE_PLAN})
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("analyzer deadline took %s", elapsed)
	}
	if report.GetStatus() != roomv1.AnalysisStatus_ANALYSIS_STATUS_FAILED || report.GetReceipts()[0].GetFailureCode() != "provider_failed" {
		t.Fatalf("report = %+v", report)
	}
}

func TestExternalAnalyzerRejectsAndDrainsOversizedProviderOutput(t *testing.T) {
	executable := filepath.Join(t.TempDir(), "large-provider")
	contents := "#!/bin/sh\ncat >/dev/null\ndd if=/dev/zero bs=65536 count=32 2>/dev/null\n"
	if err := os.WriteFile(executable, []byte(contents), 0o700); err != nil {
		t.Fatal(err)
	}
	a, err := NewExternal(Config{ID: "bounded", Version: "1", Executable: executable, MaxOutputBytes: 64, CoveredSignals: []roomv1.SignalKind{secretSignal}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	report := a.Analyze(ctx, Input{Phase: roomv1.AnalysisPhase_ANALYSIS_PHASE_PLAN, Content: []byte("plan")})
	if ctx.Err() != nil {
		t.Fatalf("provider stdout was not drained: %v", ctx.Err())
	}
	if report.GetStatus() != roomv1.AnalysisStatus_ANALYSIS_STATUS_INVALID {
		t.Fatalf("status = %s", report.GetStatus())
	}
	if got := report.GetReceipts()[0].GetFailureCode(); got != "provider_output_too_large" {
		t.Fatalf("failure code = %q", got)
	}
}

func TestNewExternalDefaultsAndValidatesOutputLimit(t *testing.T) {
	executable := writeProvider(t, `{}`)
	a, err := NewExternal(Config{ID: "bounded", Version: "1", Executable: executable, CoveredSignals: []roomv1.SignalKind{secretSignal}})
	if err != nil {
		t.Fatal(err)
	}
	if got := a.(*externalAnalyzer).maxOutputBytes; got != 1<<20 {
		t.Fatalf("default max output bytes = %d", got)
	}
	if _, err := NewExternal(Config{ID: "bounded", Version: "1", Executable: executable, MaxOutputBytes: -1, CoveredSignals: []roomv1.SignalKind{secretSignal}}); err == nil {
		t.Fatal("expected negative output limit to be rejected")
	}
}

func TestExternalAnalyzerUsesJSONStdinAndLiteralArguments(t *testing.T) {
	input := Input{Phase: roomv1.AnalysisPhase_ANALYSIS_PHASE_PLAN, Content: []byte("binary\x00artifact"), ChangedFiles: []string{"one.go", "two.go"}}
	digest := sha256.Sum256(input.Content)
	temp := t.TempDir()
	capture := filepath.Join(temp, "request.json")
	injected := filepath.Join(temp, "must-not-exist")
	literalArgument := "; touch " + injected
	response := fmt.Sprintf(`{"phase":"ANALYSIS_PHASE_PLAN","status":"ANALYSIS_STATUS_COMPLETE","covered_signals":["SIGNAL_KIND_SECRET_LITERAL"],"input_sha256":%q}`, hex.EncodeToString(digest[:]))
	executable := filepath.Join(temp, "capture-provider")
	script := fmt.Sprintf("#!/bin/sh\n[ \"$1\" = '%s' ] || exit 42\ncat > '%s'\nprintf '%%s' '%s'\n", literalArgument, capture, response)
	if err := os.WriteFile(executable, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	a, err := NewExternal(Config{ID: "boundary", Version: "1", Executable: executable, Args: []string{literalArgument}, CoveredSignals: []roomv1.SignalKind{secretSignal}})
	if err != nil {
		t.Fatal(err)
	}
	if got := a.Analyze(context.Background(), input).GetStatus(); got != roomv1.AnalysisStatus_ANALYSIS_STATUS_COMPLETE {
		t.Fatalf("status = %s", got)
	}
	if _, err := os.Stat(injected); !os.IsNotExist(err) {
		t.Fatalf("argument was shell interpreted; stat error = %v", err)
	}
	captured, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	var request providerRequest
	if err := json.Unmarshal(captured, &request); err != nil {
		t.Fatalf("request is not JSON: %v", err)
	}
	if request.Phase != input.Phase.String() || string(request.Content) != string(input.Content) || request.InputSHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("request = %+v", request)
	}
	if fmt.Sprint(request.ChangedFiles) != fmt.Sprint(input.ChangedFiles) {
		t.Fatalf("changed files = %v", request.ChangedFiles)
	}
}

func TestNewExternalRejectsUnsafeOrIncompleteConfiguration(t *testing.T) {
	tests := []struct {
		name   string
		config Config
	}{
		{"missing id", Config{Version: "1", Executable: "/bin/echo", CoveredSignals: []roomv1.SignalKind{secretSignal}}},
		{"relative executable", Config{ID: "x", Version: "1", Executable: "bin/analyzer", CoveredSignals: []roomv1.SignalKind{secretSignal}}},
		{"no coverage", Config{ID: "x", Version: "1", Executable: "/bin/echo"}},
		{"unspecified coverage", Config{ID: "x", Version: "1", Executable: "/bin/echo", CoveredSignals: []roomv1.SignalKind{roomv1.SignalKind_SIGNAL_KIND_UNSPECIFIED}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewExternal(tt.config); err == nil {
				t.Fatal("expected configuration error")
			}
		})
	}
}

func writeProvider(t *testing.T, response string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "provider")
	contents := "#!/bin/sh\n[ \"$1\" = \"--mode\" ] || [ $# -eq 0 ] || exit 42\n[ \"$2\" = \"room\" ] || [ $# -eq 0 ] || exit 42\ncat >/dev/null\nprintf '%s' '" + response + "'\n"
	if err := os.WriteFile(path, []byte(contents), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}
