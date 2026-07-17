package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	roomv1 "github.com/haasonsaas/room/gen/go/room/v1"
	"go.yaml.in/yaml/v3"
	"golang.org/x/sys/unix"
)

const (
	completeStatus     = "ANALYSIS_STATUS_COMPLETE"
	partialStatus      = "ANALYSIS_STATUS_PARTIAL"
	failedStatus       = "ANALYSIS_STATUS_FAILED"
	unavailableStatus  = "ANALYSIS_STATUS_UNAVAILABLE"
	maxOutputBytes     = 16 << 20
	semgrepCoreVersion = "1.139.0"
)

var hunkHeader = regexp.MustCompile(`^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?: .*)?$`)

type stringList []string

func (values *stringList) String() string { return strings.Join(*values, ",") }
func (values *stringList) Set(value string) error {
	*values = append(*values, value)
	return nil
}

type analyzerRequest struct {
	Phase            string   `json:"phase"`
	Content          []byte   `json:"content"`
	ChangedFiles     []string `json:"changed_files,omitempty"`
	WorkingDirectory string   `json:"working_directory,omitempty"`
	ConfigSHA256     string   `json:"config_sha256"`
	InputSHA256      string   `json:"input_sha256"`
}

type analyzerResponse struct {
	Phase          string           `json:"phase"`
	Status         string           `json:"status"`
	ChangedFiles   []string         `json:"changed_files,omitempty"`
	CoveredSignals []string         `json:"covered_signals"`
	Signals        []analyzerSignal `json:"signals,omitempty"`
	FailureCode    string           `json:"failure_code,omitempty"`
	InputSHA256    string           `json:"input_sha256"`
}

type analyzerSignal struct {
	Kind                  string         `json:"kind"`
	Fingerprint           string         `json:"fingerprint"`
	Location              sourceLocation `json:"location"`
	ConfidenceBasisPoints uint32         `json:"confidence_basis_points"`
	EvidenceSHA256        string         `json:"evidence_sha256"`
}

type sourceLocation struct {
	FilePath  string `json:"file_path"`
	StartLine int32  `json:"start_line"`
	EndLine   int32  `json:"end_line"`
}

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

type semgrepTraceRange struct {
	Path       string
	Start, End int
}

type diffArtifact struct {
	added     map[string]map[int]bool
	expected  map[string]map[int]string
	files     map[string]bool
	deleted   map[string]bool
	postimage map[string]bool
}

func (artifact diffArtifact) paths() []string {
	paths := make([]string, 0, len(artifact.files))
	for path := range artifact.files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

type snapshot struct {
	directory   string
	config      string
	targetsFile string
	targets     []string
	lineCounts  map[string]int
}

type adapter struct {
	semgrepCore    string
	config         string
	repositoryRoot string
	covered        []string
	coveredSet     map[string]bool
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("room-semgrep", flag.ContinueOnError)
	flags.SetOutput(stderr)
	semgrepCore := flags.String("semgrep-core", "", "absolute path to the semgrep-core executable")
	config := flags.String("config", "", "absolute path to one local Semgrep rules file")
	repositoryRoot := flags.String("repository-root", "", "absolute repository checkout that Semgrep may scan")
	var covered stringList
	flags.Var(&covered, "covered-signal", "Room SignalKind covered by the configured rules; repeat for each signal")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	adapter, err := newAdapter(*semgrepCore, *config, *repositoryRoot, covered)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	request, err := decodeRequest(stdin)
	if err != nil {
		fmt.Fprintln(stderr, "decode Room analyzer request:", err)
		return 1
	}
	response := adapter.analyze(context.Background(), request)
	if err := json.NewEncoder(stdout).Encode(response); err != nil {
		fmt.Fprintln(stderr, "encode Room analyzer response:", err)
		return 1
	}
	return 0
}

func newAdapter(semgrepCore, config, repositoryRoot string, covered []string) (*adapter, error) {
	for name, value := range map[string]string{"semgrep-core executable": semgrepCore, "Semgrep config": config, "repository root": repositoryRoot} {
		if value == "" || !filepath.IsAbs(value) {
			return nil, fmt.Errorf("%s must be an absolute path", name)
		}
	}
	configInfo, err := os.Stat(config)
	if err != nil || !configInfo.Mode().IsRegular() {
		return nil, errors.New("Semgrep config must be a regular file")
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
	configData, err := os.ReadFile(config)
	if err != nil {
		return nil, errors.New("read Semgrep config")
	}
	if err := validateRuleCoverage(configData, coveredSet); err != nil {
		return nil, err
	}
	sort.Strings(covered)
	return &adapter{semgrepCore: semgrepCore, config: config, repositoryRoot: repositoryRoot, covered: covered, coveredSet: coveredSet}, nil
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

func decodeRequest(input io.Reader) (analyzerRequest, error) {
	var request analyzerRequest
	decoder := json.NewDecoder(io.LimitReader(input, 8<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return request, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return request, errors.New("request must contain exactly one JSON object")
	}
	return request, nil
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

func semgrepTraceRanges(data []byte) ([]semgrepTraceRange, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("dataflow trace must contain one JSON value")
	}
	trace, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("dataflow trace must be an object")
	}
	source, hasSource := trace["taint_source"]
	sink, hasSink := trace["taint_sink"]
	if !hasSource || !hasSink {
		return nil, errors.New("dataflow trace must contain source and sink")
	}
	ranges := make([]semgrepTraceRange, 0, 3)
	if err := collectSemgrepCallTrace(source, &ranges); err != nil {
		return nil, err
	}
	if intermediate, present := trace["intermediate_vars"]; present {
		values, ok := intermediate.([]any)
		if !ok {
			return nil, errors.New("dataflow trace intermediates must be an array")
		}
		for _, value := range values {
			if err := collectSemgrepIntermediate(value, &ranges); err != nil {
				return nil, err
			}
		}
	}
	if err := collectSemgrepCallTrace(sink, &ranges); err != nil {
		return nil, err
	}
	return ranges, nil
}

func collectSemgrepCallTrace(value any, ranges *[]semgrepTraceRange) error {
	variant, ok := value.([]any)
	if !ok || len(variant) != 2 {
		return errors.New("invalid dataflow call trace")
	}
	kind, ok := variant[0].(string)
	if !ok {
		return errors.New("invalid dataflow call trace kind")
	}
	switch kind {
	case "CliLoc":
		return collectSemgrepLocAndContent(variant[1], ranges)
	case "CliCall":
		call, ok := variant[1].([]any)
		if !ok || len(call) != 3 {
			return errors.New("invalid dataflow call")
		}
		if err := collectSemgrepLocAndContent(call[0], ranges); err != nil {
			return err
		}
		intermediates, ok := call[1].([]any)
		if !ok {
			return errors.New("invalid call intermediates")
		}
		for _, intermediate := range intermediates {
			if err := collectSemgrepIntermediate(intermediate, ranges); err != nil {
				return err
			}
		}
		return collectSemgrepCallTrace(call[2], ranges)
	default:
		return errors.New("unknown dataflow call trace kind")
	}
}

func collectSemgrepLocAndContent(value any, ranges *[]semgrepTraceRange) error {
	locationAndContent, ok := value.([]any)
	if !ok || len(locationAndContent) != 2 {
		return errors.New("invalid dataflow location and content")
	}
	if _, ok := locationAndContent[1].(string); !ok {
		return errors.New("invalid dataflow location content")
	}
	return collectSemgrepLocation(locationAndContent[0], ranges)
}

func collectSemgrepIntermediate(value any, ranges *[]semgrepTraceRange) error {
	intermediate, ok := value.(map[string]any)
	if !ok {
		return errors.New("invalid dataflow intermediate")
	}
	if _, ok := intermediate["content"].(string); !ok {
		return errors.New("invalid dataflow intermediate content")
	}
	return collectSemgrepLocation(intermediate["location"], ranges)
}

func collectSemgrepLocation(value any, ranges *[]semgrepTraceRange) error {
	location, ok := value.(map[string]any)
	if !ok {
		return errors.New("invalid dataflow location")
	}
	path, pathOK := location["path"].(string)
	start, startOK := semgrepTraceLine(location["start"])
	end, endOK := semgrepTraceLine(location["end"])
	if !pathOK || !startOK || !endOK || path == "" || start < 1 || end < start {
		return errors.New("invalid dataflow trace location")
	}
	*ranges = append(*ranges, semgrepTraceRange{Path: path, Start: start, End: end})
	return nil
}

func semgrepTraceLine(value any) (int, bool) {
	position, ok := value.(map[string]any)
	if !ok {
		return 0, false
	}
	line, ok := position["line"].(json.Number)
	if !ok {
		return 0, false
	}
	parsed, err := strconv.Atoi(string(line))
	return parsed, err == nil
}

func failed(response analyzerResponse, code string) analyzerResponse {
	response.Status, response.CoveredSignals, response.Signals, response.FailureCode = failedStatus, []string{}, nil, code
	return response
}

func (a *adapter) configMatches(expected string) bool {
	config, err := os.ReadFile(a.config)
	if err != nil {
		return false
	}
	digest := sha256.Sum256(config)
	return strings.EqualFold(expected, hex.EncodeToString(digest[:]))
}

func (a *adapter) createSnapshot(request analyzerRequest, artifact diffArtifact) (snapshot, error) {
	root, err := filepath.EvalSymlinks(a.repositoryRoot)
	if err != nil {
		return snapshot{}, err
	}
	workingDirectory, err := filepath.EvalSymlinks(request.WorkingDirectory)
	if err != nil {
		return snapshot{}, errors.New("working directory does not match repository root")
	}
	rootFD, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return snapshot{}, errors.New("repository root cannot be opened safely")
	}
	defer unix.Close(rootFD)
	workingFD, err := unix.Open(workingDirectory, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return snapshot{}, errors.New("working directory cannot be opened safely")
	}
	defer unix.Close(workingFD)
	var rootStat, workingStat unix.Stat_t
	if unix.Fstat(rootFD, &rootStat) != nil || unix.Fstat(workingFD, &workingStat) != nil || rootStat.Dev != workingStat.Dev || rootStat.Ino != workingStat.Ino {
		return snapshot{}, errors.New("working directory does not match repository root")
	}
	config, err := os.ReadFile(a.config)
	if err != nil {
		return snapshot{}, err
	}
	configDigest := sha256.Sum256(config)
	if !strings.EqualFold(request.ConfigSHA256, hex.EncodeToString(configDigest[:])) {
		return snapshot{}, errors.New("Semgrep config digest changed")
	}
	temporary, err := os.MkdirTemp("", "room-semgrep-*")
	if err != nil {
		return snapshot{}, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(temporary)
		}
	}()
	repository := filepath.Join(temporary, "repository")
	if err := os.Mkdir(repository, 0o700); err != nil {
		return snapshot{}, err
	}
	configPath := filepath.Join(temporary, "rules.yml")
	if err := os.WriteFile(configPath, config, 0o600); err != nil {
		return snapshot{}, err
	}
	for path := range artifact.deleted {
		if err := requireMissingBeneath(rootFD, path); err != nil {
			return snapshot{}, err
		}
	}
	postimages := make(map[string][]byte, len(artifact.postimage))
	for path := range artifact.postimage {
		data, err := readRegularBeneath(rootFD, path)
		if err != nil {
			return snapshot{}, err
		}
		if err := verifyPostimage(data, artifact.expected[path]); err != nil {
			return snapshot{}, err
		}
		postimages[path] = data
	}
	targets := make([]string, 0, len(artifact.added))
	lineCounts := make(map[string]int, len(artifact.added))
	for path := range artifact.added {
		if !validRelativePath(path) {
			return snapshot{}, errors.New("diff path is invalid")
		}
		destination := filepath.Join(repository, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
			return snapshot{}, err
		}
		postimage := postimages[path]
		if err := os.WriteFile(destination, postimage, 0o600); err != nil {
			return snapshot{}, err
		}
		lineCounts[path] = bytes.Count(postimage, []byte{'\n'})
		if len(postimage) > 0 && postimage[len(postimage)-1] != '\n' {
			lineCounts[path]++
		}
		targets = append(targets, path)
	}
	sort.Strings(targets)
	targetsPath := filepath.Join(temporary, "targets.json")
	targetManifest := []any{"Scanning_roots", map[string]any{
		"root_paths": targets,
		"targeting_conf": map[string]any{
			"exclude": []string{}, "max_target_bytes": 0,
			"respect_gitignore": false, "respect_semgrepignore_files": false,
			"always_select_explicit_targets": true, "explicit_targets": targets,
			"force_novcs_project": true, "exclude_minified_files": false,
		},
	}}
	targetJSON, err := json.Marshal(targetManifest)
	if err != nil {
		return snapshot{}, err
	}
	if err := os.WriteFile(targetsPath, targetJSON, 0o600); err != nil {
		return snapshot{}, err
	}
	cleanup = false
	return snapshot{directory: repository, config: configPath, targetsFile: targetsPath, targets: targets, lineCounts: lineCounts}, nil
}

func readRegularBeneath(rootFD int, path string) ([]byte, error) {
	fileFD, err := unix.Openat2(rootFD, filepath.FromSlash(path), &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return nil, errors.New("diff target cannot be opened safely")
	}
	file := os.NewFile(uintptr(fileFD), path)
	defer file.Close()
	var before, after unix.Stat_t
	if err := unix.Fstat(fileFD, &before); err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Size < 0 || before.Size > 64<<20 {
		return nil, errors.New("diff target must be a regular file of at most 64 MiB")
	}
	data, err := io.ReadAll(io.LimitReader(file, before.Size+1))
	if err != nil || int64(len(data)) != before.Size {
		return nil, errors.New("diff target changed while being read")
	}
	if err := unix.Fstat(fileFD, &after); err != nil || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return nil, errors.New("diff target changed while being read")
	}
	return data, nil
}

func requireMissingBeneath(rootFD int, path string) error {
	fileFD, err := unix.Openat2(rootFD, filepath.FromSlash(path), &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
	})
	if err == nil {
		_ = unix.Close(fileFD)
		return errors.New("deleted diff target still exists")
	}
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	return errors.New("deleted diff target cannot be verified safely")
}

func (a *adapter) scan(ctx context.Context, snapshot snapshot) (semgrepReport, string, string) {
	args := []string{"-json_nodots", "-strict", "-rules", snapshot.config, "-targets", snapshot.targetsFile, "-j", "1", "-timeout", "0", "-timeout_threshold", "0", "-max_memory", "0"}
	command := exec.CommandContext(ctx, a.semgrepCore, args...)
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

func parseDiff(diff []byte) (diffArtifact, error) {
	artifact := diffArtifact{added: make(map[string]map[int]bool), expected: make(map[string]map[int]string), files: make(map[string]bool), deleted: make(map[string]bool), postimage: make(map[string]bool)}
	if len(diff) == 0 {
		return artifact, nil
	}
	path, oldPath, sectionPath, newLine := "", "", "", 0
	oldRemaining, newRemaining := 0, 0
	inHunk, sawSection, sawOld, sawTarget, sawHunk := false, false, false, false, false
	for _, raw := range bytes.Split(diff, []byte("\n")) {
		line := string(raw)
		if inHunk && oldRemaining == 0 && newRemaining == 0 {
			inHunk = false
		}
		if !inHunk {
			if strings.HasPrefix(line, "diff --git ") {
				if sawSection && !sawHunk {
					return diffArtifact{}, errors.New("diff section has no hunks")
				}
				fields := strings.Fields(line)
				if len(fields) != 4 {
					return diffArtifact{}, errors.New("diff header is invalid")
				}
				oldHeaderPath, oldOK := parseSidePath(fields[2], "a/")
				newHeaderPath, newOK := parseSidePath(fields[3], "b/")
				if !oldOK || !newOK || oldHeaderPath != newHeaderPath {
					return diffArtifact{}, errors.New("renames and malformed diff headers are unsupported")
				}
				path, oldPath, sectionPath, sawOld, sawTarget, sawHunk = "", "", oldHeaderPath, false, false, false
				sawSection = true
				continue
			}
			if strings.HasPrefix(line, "--- ") {
				if !sawSection || sawOld {
					return diffArtifact{}, errors.New("source header is invalid")
				}
				oldPath, _ = parseSidePath(strings.TrimPrefix(line, "--- "), "a/")
				if oldPath == "" && line != "--- /dev/null" {
					return diffArtifact{}, errors.New("source path is invalid")
				}
				if oldPath != "" && oldPath != sectionPath {
					return diffArtifact{}, errors.New("source path does not match diff header")
				}
				sawOld = true
				continue
			}
			if strings.HasPrefix(line, "+++ ") {
				if !sawOld || sawTarget {
					return diffArtifact{}, errors.New("target header is invalid")
				}
				targetDeleted := line == "+++ /dev/null"
				path, _ = parseSidePath(strings.TrimPrefix(line, "+++ "), "b/")
				sawTarget = true
				if path == "" && line != "+++ /dev/null" {
					return diffArtifact{}, errors.New("target path is invalid")
				}
				if path == "" {
					path = oldPath
				}
				if path != sectionPath || (oldPath == "" && targetDeleted) {
					return diffArtifact{}, errors.New("target path does not match diff header")
				}
				if !validRelativePath(path) || artifact.files[path] {
					return diffArtifact{}, errors.New("target path is invalid or duplicated")
				}
				artifact.files[path] = true
				if targetDeleted {
					artifact.deleted[path] = true
				} else {
					artifact.postimage[path] = true
				}
				continue
			}
			if match := hunkHeader.FindStringSubmatch(line); match != nil {
				if !sawTarget {
					return diffArtifact{}, errors.New("hunk has no target")
				}
				var err error
				oldRemaining, err = hunkCount(match[2])
				if err != nil {
					return diffArtifact{}, errors.New("hunk count is invalid")
				}
				newLine, err = strconv.Atoi(match[3])
				if err != nil {
					return diffArtifact{}, errors.New("hunk line is invalid")
				}
				newRemaining, err = hunkCount(match[4])
				if err != nil {
					return diffArtifact{}, errors.New("hunk count is invalid")
				}
				inHunk, sawHunk = true, true
				continue
			}
			if line == "" || strings.HasPrefix(line, "index ") || strings.HasPrefix(line, "new file mode ") || strings.HasPrefix(line, "deleted file mode ") || strings.HasPrefix(line, "old mode ") || strings.HasPrefix(line, "new mode ") {
				continue
			}
			return diffArtifact{}, errors.New("unexpected diff content")
		}
		if line == `\ No newline at end of file` {
			continue
		}
		if line == "" {
			return diffArtifact{}, errors.New("truncated hunk")
		}
		switch line[0] {
		case ' ':
			if oldRemaining == 0 || newRemaining == 0 || path == "" {
				return diffArtifact{}, errors.New("invalid context line")
			}
			setExpected(artifact.expected, path, newLine, line[1:])
			oldRemaining--
			newRemaining--
			newLine++
		case '+':
			if newRemaining == 0 || path == "" {
				return diffArtifact{}, errors.New("invalid added line")
			}
			setExpected(artifact.expected, path, newLine, line[1:])
			if artifact.added[path] == nil {
				artifact.added[path] = make(map[int]bool)
			}
			artifact.added[path][newLine] = true
			newRemaining--
			newLine++
		case '-':
			if oldRemaining == 0 {
				return diffArtifact{}, errors.New("invalid removed line")
			}
			oldRemaining--
		default:
			return diffArtifact{}, errors.New("invalid hunk line")
		}
	}
	if inHunk && (oldRemaining != 0 || newRemaining != 0) {
		return diffArtifact{}, errors.New("truncated hunk")
	}
	if !sawHunk || !sawSection {
		return diffArtifact{}, errors.New("no unified diff hunks")
	}
	return artifact, nil
}

func hunkCount(value string) (int, error) {
	if value == "" {
		return 1, nil
	}
	count, err := strconv.Atoi(value)
	return count, err
}

func setExpected(expected map[string]map[int]string, path string, line int, content string) {
	if expected[path] == nil {
		expected[path] = make(map[int]string)
	}
	expected[path][line] = content
}

func verifyPostimage(data []byte, expected map[int]string) error {
	lines := bytes.Split(data, []byte("\n"))
	for line, content := range expected {
		if line < 1 || line > len(lines) || string(lines[line-1]) != content {
			return errors.New("diff does not match repository postimage")
		}
	}
	return nil
}

func parseSidePath(value, prefix string) (string, bool) {
	value = strings.SplitN(value, "\t", 2)[0]
	if !strings.HasPrefix(value, prefix) || strings.HasPrefix(value, `"`) || strings.TrimSpace(value) != value {
		return "", false
	}
	path := strings.TrimPrefix(value, prefix)
	return path, validRelativePath(path)
}

func validRelativePath(path string) bool {
	clean := filepath.ToSlash(filepath.Clean(path))
	return path != "" && !filepath.IsAbs(path) && clean == path && clean != ".." && !strings.HasPrefix(clean, "../")
}

func normalizedResultPath(directory, path string) (string, error) {
	if filepath.IsAbs(path) {
		relative, err := filepath.Rel(directory, path)
		if err != nil || strings.HasPrefix(filepath.ToSlash(relative), "../") {
			return "", errors.New("result path outside snapshot")
		}
		path = relative
	}
	path = filepath.ToSlash(filepath.Clean(path))
	if !validRelativePath(path) {
		return "", errors.New("result path invalid")
	}
	return path, nil
}

func rangeIntersects(lines map[int]bool, start, end int) bool {
	if start < 1 || end < start {
		return false
	}
	for line := range lines {
		if line >= start && line <= end {
			return true
		}
	}
	return false
}

func evidenceDigest(directory, path string, start, end int) ([sha256.Size]byte, error) {
	data, err := os.ReadFile(filepath.Join(directory, filepath.FromSlash(path)))
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	lines := bytes.Split(data, []byte("\n"))
	if start < 1 || end < start || end > len(lines) {
		return [sha256.Size]byte{}, errors.New("finding range outside target")
	}
	return sha256.Sum256(bytes.Join(lines[start-1:end], []byte("\n"))), nil
}

func metadataConfidence(metadata map[string]any) (uint32, bool) {
	value, ok := metadata["room_confidence_basis_points"]
	if !ok {
		return 0, false
	}
	var confidence uint64
	switch typed := value.(type) {
	case float64:
		if typed < 0 || typed != float64(uint64(typed)) {
			return 0, false
		}
		confidence = uint64(typed)
	case string:
		parsed, err := strconv.ParseUint(typed, 10, 32)
		if err != nil {
			return 0, false
		}
		confidence = parsed
	default:
		return 0, false
	}
	return uint32(confidence), confidence > 0 && confidence <= 10_000
}
