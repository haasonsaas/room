package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	roomv1 "github.com/haasonsaas/room/gen/go/room/v1"
	"go.yaml.in/yaml/v3"
)

type adapter struct {
	semgrepCore    string
	config         string
	repositoryRoot string
	covered        []string
	coveredSet     map[string]bool
	tool           toolBinding
}

func newAdapter(semgrepCore, config, repositoryRoot string, covered []string) (*adapter, error) {
	for name, value := range map[string]string{"semgrep-core executable": semgrepCore, "Semgrep config": config, "repository root": repositoryRoot} {
		if value == "" || !filepath.IsAbs(value) {
			return nil, fmt.Errorf("%s must be an absolute path", name)
		}
	}
	rootInfo, err := os.Stat(repositoryRoot)
	if err != nil || !rootInfo.IsDir() {
		return nil, errors.New("repository root must be a directory")
	}
	if len(covered) == 0 {
		return nil, errors.New("at least one --covered-signal is required")
	}
	coveredSet := make(map[string]bool, len(covered))
	for _, signal := range covered {
		value, known := roomv1.SignalKind_value[signal]
		if !known || roomv1.SignalKind(value) == roomv1.SignalKind_SIGNAL_KIND_UNSPECIFIED || coveredSet[signal] {
			return nil, fmt.Errorf("invalid or duplicate covered signal %q", signal)
		}
		coveredSet[signal] = true
	}
	configData, err := readRegularFile(config)
	if err != nil {
		return nil, errors.New("Semgrep config must be a regular file")
	}
	if err := validateRuleCoverage(configData, coveredSet); err != nil {
		return nil, err
	}
	resolvedCore, err := filepath.EvalSymlinks(semgrepCore)
	if err != nil {
		return nil, errors.New("semgrep-core executable cannot be resolved")
	}
	tool, err := hashToolBinary(resolvedCore)
	if err != nil {
		return nil, fmt.Errorf("semgrep-core executable must resolve to a regular file: %w", err)
	}
	sort.Strings(covered)
	return &adapter{semgrepCore: semgrepCore, config: config, repositoryRoot: repositoryRoot, covered: covered, coveredSet: coveredSet, tool: tool}, nil
}

// toolMatches reports whether the binary the semgrep-core path currently
// resolves to is still the startup-pinned binary with the expected digest.
func (a *adapter) toolMatches(expected string) bool {
	resolved, err := filepath.EvalSymlinks(a.semgrepCore)
	if err != nil {
		return false
	}
	return a.tool.matches(resolved, expected)
}

func validateRuleCoverage(config []byte, covered map[string]bool) error {
	var document struct {
		Rules []struct {
			ID       string         `yaml:"id"`
			Metadata map[string]any `yaml:"metadata"`
		} `yaml:"rules"`
	}
	if err := yaml.Unmarshal(config, &document); err != nil {
		return errors.New("Semgrep config is not valid YAML")
	}
	implemented := make(map[string]bool, len(covered))
	ruleIDs := make(map[string]bool, len(document.Rules))
	for _, rule := range document.Rules {
		if rule.ID == "" || ruleIDs[rule.ID] {
			return errors.New("Semgrep rules must have unique non-empty IDs")
		}
		ruleIDs[rule.ID] = true
		rawSignal, policyBearing := rule.Metadata["room_signal"]
		if !policyBearing {
			continue
		}
		signal, ok := rawSignal.(string)
		if !ok || !covered[signal] {
			return fmt.Errorf("Semgrep rule %q has an invalid or undeclared room_signal", rule.ID)
		}
		confidence, ok := yamlConfidence(rule.Metadata["room_confidence_basis_points"])
		if !ok || confidence == 0 || confidence > 10000 {
			return fmt.Errorf("Semgrep rule %q has invalid Room confidence", rule.ID)
		}
		implemented[signal] = true
	}
	for signal := range covered {
		if !implemented[signal] {
			return fmt.Errorf("Semgrep config has no rule for covered signal %q", signal)
		}
	}
	return nil
}

func yamlConfidence(value any) (uint32, bool) {
	switch value := value.(type) {
	case int:
		return uint32(value), value >= 0
	case uint32:
		return value, true
	case uint64:
		return uint32(value), value <= uint64(^uint32(0))
	default:
		return 0, false
	}
}

func (a *adapter) analyze(ctx context.Context, request analyzerRequest) analyzerResponse {
	digest := sha256.Sum256(request.Content)
	inputDigest := hex.EncodeToString(digest[:])
	response := analyzerResponse{Phase: request.Phase, Status: failedStatus, CoveredSignals: []string{}, InputSHA256: inputDigest}
	if !strings.EqualFold(request.InputSHA256, inputDigest) {
		response.FailureCode = "input_digest_mismatch"
		return response
	}
	if request.Phase == "ANALYSIS_PHASE_PLAN" {
		response.Status = partialStatus
		response.FailureCode = "semgrep_requires_diff"
		return response
	}
	if request.Phase != "ANALYSIS_PHASE_DIFF" {
		response.FailureCode = "input_phase_invalid"
		return response
	}

	artifact, err := parseDiff(request.Content)
	if err != nil {
		response.FailureCode = "diff_invalid"
		return response
	}
	if !a.configMatches(request.ConfigSHA256) {
		response.FailureCode = "config_digest_mismatch"
		return response
	}
	if !a.toolMatches(request.ToolSHA256) {
		response.FailureCode = "tool_digest_mismatch"
		return response
	}
	snapshot, err := a.createSnapshot(request, artifact)
	if err != nil {
		response.FailureCode = "snapshot_invalid"
		return response
	}
	defer os.RemoveAll(filepath.Dir(snapshot.directory))
	report, status, failure := a.scan(ctx, snapshot)
	if failure != "" {
		response.Status, response.FailureCode = status, failure
		return response
	}
	if len(artifact.added) == 0 {
		if len(*report.Results) != 0 {
			response.FailureCode = "semgrep_result_invalid"
			return response
		}
		response.Status = completeStatus
		response.ChangedFiles = artifact.paths()
		response.CoveredSignals = append([]string(nil), a.covered...)
		return response
	}
	response.Status = completeStatus
	response.ChangedFiles = artifact.paths()
	response.CoveredSignals = append([]string(nil), a.covered...)
	for _, result := range *report.Results {
		if result.CheckID == "" || result.Path == "" || result.Start.Line < 1 || result.End.Line < result.Start.Line {
			return failed(response, "semgrep_result_invalid")
		}
		path, err := normalizedResultPath(snapshot.directory, result.Path)
		if err != nil {
			return failed(response, "semgrep_result_invalid")
		}
		if index := sort.SearchStrings(snapshot.targets, path); index >= len(snapshot.targets) || snapshot.targets[index] != path {
			return failed(response, "semgrep_result_invalid")
		}
		if result.End.Line > snapshot.lineCounts[path] {
			return failed(response, "semgrep_result_invalid")
		}
		intersects := rangeIntersects(artifact.added[path], result.Start.Line, result.End.Line)
		if len(result.Extra.DataflowTrace) != 0 {
			traceRanges, err := semgrepTraceRanges(result.Extra.DataflowTrace)
			if err != nil {
				return failed(response, "semgrep_result_invalid")
			}
			for _, traceRange := range traceRanges {
				tracePath, err := normalizedResultPath(snapshot.directory, traceRange.Path)
				if err != nil {
					return failed(response, "semgrep_result_invalid")
				}
				if index := sort.SearchStrings(snapshot.targets, tracePath); index >= len(snapshot.targets) || snapshot.targets[index] != tracePath {
					return failed(response, "semgrep_result_invalid")
				}
				if traceRange.End > snapshot.lineCounts[tracePath] {
					return failed(response, "semgrep_result_invalid")
				}
				intersects = intersects || rangeIntersects(artifact.added[tracePath], traceRange.Start, traceRange.End)
			}
		}
		if !intersects {
			continue
		}
		rawSignal, present := result.Extra.Metadata["room_signal"]
		if !present {
			continue
		}
		signal, ok := rawSignal.(string)
		if !ok || signal == "" {
			return failed(response, "semgrep_signal_invalid")
		}
		if !a.coveredSet[signal] {
			return failed(response, "semgrep_signal_not_covered")
		}
		confidence, ok := metadataConfidence(result.Extra.Metadata)
		if !ok {
			return failed(response, "semgrep_confidence_invalid")
		}
		evidence, err := evidenceDigest(snapshot.directory, path, result.Start.Line, result.End.Line)
		if err != nil {
			return failed(response, "semgrep_result_invalid")
		}
		fingerprint := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%s:%x", signal, result.CheckID, path, evidence)))
		response.Signals = append(response.Signals, analyzerSignal{
			Kind: signal, Fingerprint: hex.EncodeToString(fingerprint[:]),
			Location:              sourceLocation{FilePath: path, StartLine: int32(result.Start.Line), EndLine: int32(result.End.Line)},
			ConfidenceBasisPoints: confidence, EvidenceSHA256: hex.EncodeToString(evidence[:]),
		})
	}
	sort.Slice(response.Signals, func(i, j int) bool { return response.Signals[i].Fingerprint < response.Signals[j].Fingerprint })
	return response
}

func failed(response analyzerResponse, code string) analyzerResponse {
	response.Status, response.CoveredSignals, response.Signals, response.FailureCode = failedStatus, []string{}, nil, code
	return response
}

func (a *adapter) configMatches(expected string) bool {
	config, err := readRegularFile(a.config)
	if err != nil {
		return false
	}
	digest := sha256.Sum256(config)
	return strings.EqualFold(expected, hex.EncodeToString(digest[:]))
}
