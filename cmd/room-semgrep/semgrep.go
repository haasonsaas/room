package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"syscall"
)

type semgrepReport struct {
	Version      string             `json:"version"`
	Results      *[]semgrepResult   `json:"results"`
	Errors       *[]json.RawMessage `json:"errors"`
	Paths        *semgrepPaths      `json:"paths"`
	SkippedRules *[]json.RawMessage `json:"skipped_rules"`
}

type semgrepPaths struct {
	Scanned *[]string          `json:"scanned"`
	Skipped *[]json.RawMessage `json:"skipped"`
}

type semgrepResult struct {
	CheckID string `json:"check_id"`
	Path    string `json:"path"`
	Start   struct {
		Line int `json:"line"`
	} `json:"start"`
	End struct {
		Line int `json:"line"`
	} `json:"end"`
	Extra struct {
		Metadata      map[string]any  `json:"metadata"`
		DataflowTrace json.RawMessage `json:"dataflow_trace"`
	} `json:"extra"`
}

func (a *adapter) scan(ctx context.Context, snapshot snapshot) (semgrepReport, string, string) {
	args := []string{"-json_nodots", "-strict", "-rules", snapshot.config, "-targets", snapshot.targetsFile, "-j", "1", "-timeout", "0", "-timeout_threshold", "0", "-max_memory", "0"}
	command := exec.CommandContext(ctx, a.semgrepCore, args...)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		if err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
			return err
		}
		return nil
	}
	command.Dir = snapshot.directory
	var stdout, stderr limitedBuffer
	stdout.limit, stderr.limit = maxOutputBytes, 1<<20
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		var execError *exec.Error
		if errors.As(err, &execError) || errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
			return semgrepReport{}, unavailableStatus, "semgrep_unavailable"
		}
		return semgrepReport{}, failedStatus, "semgrep_failed"
	}
	if stdout.overflow {
		return semgrepReport{}, failedStatus, "semgrep_output_too_large"
	}
	var report semgrepReport
	decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	if err := decoder.Decode(&report); err != nil || !validReportShape(report) {
		return semgrepReport{}, failedStatus, "semgrep_report_invalid"
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return semgrepReport{}, failedStatus, "semgrep_report_invalid"
	}
	if !sameTargets(snapshot.directory, snapshot.targets, *report.Paths.Scanned) {
		return semgrepReport{}, failedStatus, "semgrep_targets_incomplete"
	}
	return report, "", ""
}

func validReportShape(report semgrepReport) bool {
	return report.Version == semgrepCoreVersion && report.Results != nil && report.Errors != nil && len(*report.Errors) == 0 &&
		report.Paths != nil && report.Paths.Scanned != nil && (report.Paths.Skipped == nil || len(*report.Paths.Skipped) == 0) &&
		report.SkippedRules != nil && len(*report.SkippedRules) == 0
}

func sameTargets(directory string, expected, scanned []string) bool {
	normalized := make([]string, 0, len(scanned))
	for _, path := range scanned {
		path, err := normalizedResultPath(directory, path)
		if err != nil {
			return false
		}
		normalized = append(normalized, path)
	}
	sort.Strings(normalized)
	return fmt.Sprint(expected) == fmt.Sprint(normalized)
}

type limitedBuffer struct {
	bytes.Buffer
	limit    int
	overflow bool
}

func (buffer *limitedBuffer) Write(value []byte) (int, error) {
	written := len(value)
	remaining := buffer.limit - buffer.Len()
	if remaining <= 0 {
		buffer.overflow = true
		return written, nil
	}
	if len(value) > remaining {
		value = value[:remaining]
		buffer.overflow = true
	}
	_, _ = buffer.Buffer.Write(value)
	return written, nil
}
