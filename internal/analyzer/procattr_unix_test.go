//go:build unix

package analyzer

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	roomv1 "github.com/haasonsaas/room/gen/go/room/v1"
)

func TestExternalAnalyzerKillsProviderProcessGroup(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	executable := filepath.Join(t.TempDir(), "group-provider")
	script := "#!/bin/sh\nsleep 60 &\necho $! > '" + pidFile + "'\nwait\n"
	if err := os.WriteFile(executable, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	a, err := NewExternal(Config{ID: "group", Version: "1", Executable: executable, Timeout: 100 * time.Millisecond, CoveredSignals: []roomv1.SignalKind{secretSignal}})
	if err != nil {
		t.Fatal(err)
	}
	report := a.Analyze(context.Background(), Input{Phase: roomv1.AnalysisPhase_ANALYSIS_PHASE_PLAN})
	if report.GetStatus() != roomv1.AnalysisStatus_ANALYSIS_STATUS_FAILED || report.GetReceipts()[0].GetFailureCode() != "provider_failed" {
		t.Fatalf("report = %+v", report)
	}
	assertProcessGroupDies(t, pidFile)
}

func assertProcessGroupDies(t *testing.T, pidFile string) {
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
