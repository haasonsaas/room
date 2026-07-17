// Package analyzer runs trusted, configured analyzers and converts their
// untrusted process output into identity-bound analysis reports.
package analyzer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	roomv1 "github.com/haasonsaas/room/gen/go/room/v1"
	"google.golang.org/protobuf/proto"
)

const defaultMaxOutputBytes int64 = 1 << 20
const defaultTimeout = 30 * time.Second

// Input is the complete artifact passed to an analyzer.
type Input struct {
	Phase            roomv1.AnalysisPhase
	Content          []byte
	ChangedFiles     []string
	WorkingDirectory string
}

// Config identifies and launches one analyzer. Args are passed directly to the
// executable; they are never interpreted by a shell.
type Config struct {
	ID             string
	Version        string
	Executable     string
	Args           []string
	Config         []byte
	CoveredSignals []roomv1.SignalKind
	MaxOutputBytes int64
	Timeout        time.Duration
}

// Analyzer produces an explicit report for every attempt, including failures.
type Analyzer interface {
	Analyze(context.Context, Input) *roomv1.AnalysisReport
	Identity() *roomv1.AnalyzerIdentity
}

type externalAnalyzer struct {
	config         Config
	identity       *roomv1.AnalyzerIdentity
	coverage       map[roomv1.SignalKind]struct{}
	maxOutputBytes int64
	timeout        time.Duration
}

func (a *externalAnalyzer) Identity() *roomv1.AnalyzerIdentity { return cloneIdentity(a.identity) }

// NewExternal constructs a provider backed by one absolute executable path.
func NewExternal(config Config) (Analyzer, error) {
	if strings.TrimSpace(config.ID) == "" || strings.TrimSpace(config.Version) == "" {
		return nil, errors.New("analyzer id and version are required")
	}
	if config.Executable == "" || !filepath.IsAbs(config.Executable) {
		return nil, errors.New("analyzer executable must be an absolute path")
	}
	if len(config.CoveredSignals) == 0 {
		return nil, errors.New("analyzer coverage is required")
	}
	if config.MaxOutputBytes < 0 {
		return nil, errors.New("analyzer max output bytes must be positive")
	}
	if config.Timeout < 0 {
		return nil, errors.New("analyzer timeout must be positive")
	}
	maxOutputBytes := config.MaxOutputBytes
	if maxOutputBytes == 0 {
		maxOutputBytes = defaultMaxOutputBytes
	}
	timeout := config.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	coverage := make(map[roomv1.SignalKind]struct{}, len(config.CoveredSignals))
	for _, signal := range config.CoveredSignals {
		if !knownSignal(signal) {
			return nil, fmt.Errorf("invalid covered signal %d", signal)
		}
		if _, duplicate := coverage[signal]; duplicate {
			return nil, fmt.Errorf("duplicate covered signal %s", signal)
		}
		coverage[signal] = struct{}{}
	}
	configDigest := sha256.Sum256(config.Config)
	config.Args = append([]string(nil), config.Args...)
	config.Config = append([]byte(nil), config.Config...)
	config.CoveredSignals = append([]roomv1.SignalKind(nil), config.CoveredSignals...)
	return &externalAnalyzer{
		config:         config,
		identity:       &roomv1.AnalyzerIdentity{Id: config.ID, Version: config.Version, ConfigSha256: configDigest[:]},
		coverage:       coverage,
		maxOutputBytes: maxOutputBytes,
		timeout:        timeout,
	}, nil
}

// boundedDrainWriter retains at most limit bytes while acknowledging every
// write so the child can finish even after its output has exceeded the limit.
type boundedDrainWriter struct {
	buffer   bytes.Buffer
	limit    int64
	overflow bool
}

func (w *boundedDrainWriter) Write(data []byte) (int, error) {
	written := len(data)
	remaining := w.limit - int64(w.buffer.Len())
	if remaining <= 0 {
		if len(data) > 0 {
			w.overflow = true
		}
		return written, nil
	}
	keep := len(data)
	if int64(keep) > remaining {
		keep = int(remaining)
		w.overflow = true
	}
	_, _ = w.buffer.Write(data[:keep])
	return written, nil
}

func (w *boundedDrainWriter) Bytes() []byte { return w.buffer.Bytes() }

type providerRequest struct {
	Phase            string   `json:"phase"`
	Content          []byte   `json:"content"`
	ChangedFiles     []string `json:"changed_files,omitempty"`
	WorkingDirectory string   `json:"working_directory,omitempty"`
	ConfigSHA256     string   `json:"config_sha256"`
	InputSHA256      string   `json:"input_sha256"`
}

type providerResponse struct {
	Phase          string           `json:"phase"`
	Status         string           `json:"status"`
	ChangedFiles   []string         `json:"changed_files,omitempty"`
	Languages      []string         `json:"languages,omitempty"`
	Frameworks     []string         `json:"frameworks,omitempty"`
	CoveredSignals []string         `json:"covered_signals"`
	Signals        []providerSignal `json:"signals,omitempty"`
	FailureCode    string           `json:"failure_code,omitempty"`
	InputSHA256    string           `json:"input_sha256"`
}

type providerSignal struct {
	Kind                  string            `json:"kind"`
	Fingerprint           string            `json:"fingerprint"`
	Location              *providerLocation `json:"location,omitempty"`
	ConfidenceBasisPoints uint32            `json:"confidence_basis_points"`
	EvidenceSHA256        string            `json:"evidence_sha256,omitempty"`
}

type providerLocation struct {
	FilePath  string `json:"file_path"`
	StartLine int32  `json:"start_line"`
	EndLine   int32  `json:"end_line"`
}

func (a *externalAnalyzer) Analyze(ctx context.Context, input Input) *roomv1.AnalysisReport {
	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()
	digest := sha256.Sum256(input.Content)
	report := &roomv1.AnalysisReport{
		ReportId: fmt.Sprintf("%s:%x", a.config.ID, digest[:12]),
		Artifact: &roomv1.ArtifactRef{Phase: input.Phase, Sha256: digest[:], ChangedFiles: append([]string(nil), input.ChangedFiles...)},
	}
	if input.Phase != roomv1.AnalysisPhase_ANALYSIS_PHASE_PLAN && input.Phase != roomv1.AnalysisPhase_ANALYSIS_PHASE_DIFF {
		return a.failure(report, roomv1.AnalysisStatus_ANALYSIS_STATUS_INVALID, "input_stage_invalid", digest[:])
	}

	request := providerRequest{
		Phase: input.Phase.String(), Content: input.Content,
		ChangedFiles: append([]string(nil), input.ChangedFiles...), WorkingDirectory: input.WorkingDirectory,
		ConfigSHA256: hex.EncodeToString(a.identity.GetConfigSha256()), InputSHA256: hex.EncodeToString(digest[:]),
	}
	requestJSON, err := json.Marshal(request)
	if err != nil {
		return a.failure(report, roomv1.AnalysisStatus_ANALYSIS_STATUS_FAILED, "request_encoding_failed", digest[:])
	}
	command := exec.CommandContext(ctx, a.config.Executable, a.config.Args...)
	command.Stdin = bytes.NewReader(requestJSON)
	stdout := boundedDrainWriter{limit: a.maxOutputBytes}
	command.Stdout = &stdout
	runErr := command.Run()
	if stdout.overflow {
		return a.failure(report, roomv1.AnalysisStatus_ANALYSIS_STATUS_INVALID, "provider_output_too_large", digest[:])
	}
	if runErr != nil {
		status, code := roomv1.AnalysisStatus_ANALYSIS_STATUS_FAILED, "provider_failed"
		var execError *exec.Error
		if errors.As(runErr, &execError) || errors.Is(runErr, exec.ErrNotFound) || errors.Is(runErr, os.ErrNotExist) {
			status, code = roomv1.AnalysisStatus_ANALYSIS_STATUS_UNAVAILABLE, "provider_unavailable"
		}
		return a.failure(report, status, code, digest[:])
	}

	response, code := decodeProviderResponse(stdout.Bytes())
	if code != "" {
		return a.failure(report, roomv1.AnalysisStatus_ANALYSIS_STATUS_INVALID, code, digest[:])
	}
	receipt, code := a.validateResponse(response, input.Phase, digest[:])
	if code != "" {
		return a.failure(report, roomv1.AnalysisStatus_ANALYSIS_STATUS_INVALID, code, digest[:])
	}
	languages, code := normalizeClassifications(response.Languages)
	if code != "" {
		return a.failure(report, roomv1.AnalysisStatus_ANALYSIS_STATUS_INVALID, code, digest[:])
	}
	frameworks, code := normalizeClassifications(response.Frameworks)
	if code != "" {
		return a.failure(report, roomv1.AnalysisStatus_ANALYSIS_STATUS_INVALID, code, digest[:])
	}
	changedFiles, code := normalizeChangedFiles(response.ChangedFiles)
	if code != "" {
		return a.failure(report, roomv1.AnalysisStatus_ANALYSIS_STATUS_INVALID, code, digest[:])
	}
	report.Artifact.ChangedFiles = changedFiles
	report.Artifact.Languages = languages
	report.Artifact.Frameworks = frameworks
	report.Status = receipt.Status
	report.Receipts = []*roomv1.AnalyzerReceipt{receipt}
	return report
}

func normalizeClassifications(values []string) ([]string, string) {
	if len(values) == 0 {
		return nil, ""
	}
	normalized := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, raw := range values {
		value := strings.ToLower(strings.TrimSpace(raw))
		if value == "" || len(value) > 128 || strings.ContainsAny(value, "\x00\r\n") {
			return nil, "classification_invalid"
		}
		if _, duplicate := seen[value]; duplicate {
			return nil, "classification_invalid"
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	sort.Strings(normalized)
	return normalized, ""
}

func normalizeChangedFiles(values []string) ([]string, string) {
	normalized := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, raw := range values {
		value := filepath.ToSlash(filepath.Clean(raw))
		if raw == "" || filepath.IsAbs(raw) || value != raw || value == "." || value == ".." || strings.HasPrefix(value, "../") || strings.ContainsAny(value, "\x00\r\n") {
			return nil, "changed_files_invalid"
		}
		if _, duplicate := seen[value]; duplicate {
			return nil, "changed_files_invalid"
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	sort.Strings(normalized)
	return normalized, ""
}

func decodeProviderResponse(output []byte) (providerResponse, string) {
	var response providerResponse
	decoder := json.NewDecoder(bytes.NewReader(output))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		return response, "provider_output_invalid"
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return response, "provider_output_invalid"
	}
	return response, ""
}

func (a *externalAnalyzer) validateResponse(response providerResponse, phase roomv1.AnalysisPhase, digest []byte) (*roomv1.AnalyzerReceipt, string) {
	if response.Phase != phase.String() {
		return nil, "stage_mismatch"
	}
	providedDigest, err := decodeDigest(response.InputSHA256)
	if err != nil || !bytes.Equal(providedDigest, digest) {
		return nil, "input_digest_mismatch"
	}
	status, ok := analysisStatus(response.Status)
	if !ok || status == roomv1.AnalysisStatus_ANALYSIS_STATUS_INVALID || status == roomv1.AnalysisStatus_ANALYSIS_STATUS_UNTRUSTED {
		return nil, "status_invalid"
	}

	covered := make([]roomv1.SignalKind, 0, len(response.CoveredSignals))
	seen := make(map[roomv1.SignalKind]struct{}, len(response.CoveredSignals))
	for _, name := range response.CoveredSignals {
		signal, ok := signalKind(name)
		if !ok {
			return nil, "provider_output_invalid"
		}
		if _, configured := a.coverage[signal]; !configured {
			return nil, "coverage_unconfigured"
		}
		if _, duplicate := seen[signal]; duplicate {
			return nil, "coverage_duplicate"
		}
		seen[signal] = struct{}{}
		covered = append(covered, signal)
	}
	if status == roomv1.AnalysisStatus_ANALYSIS_STATUS_COMPLETE {
		for required := range a.coverage {
			if _, ok := seen[required]; !ok {
				return nil, "coverage_incomplete"
			}
		}
	}

	signals := make([]*roomv1.SecuritySignal, 0, len(response.Signals))
	for _, raw := range response.Signals {
		kind, ok := signalKind(raw.Kind)
		if !ok {
			return nil, "provider_output_invalid"
		}
		if _, declared := seen[kind]; !declared {
			return nil, "signal_not_covered"
		}
		if raw.ConfidenceBasisPoints == 0 || raw.ConfidenceBasisPoints > 10_000 {
			return nil, "confidence_invalid"
		}
		if strings.TrimSpace(raw.Fingerprint) == "" {
			return nil, "fingerprint_invalid"
		}
		var evidence []byte
		if raw.EvidenceSHA256 != "" {
			var err error
			evidence, err = decodeDigest(raw.EvidenceSHA256)
			if err != nil {
				return nil, "evidence_digest_invalid"
			}
		}
		signal := &roomv1.SecuritySignal{
			Kind: kind, Fingerprint: raw.Fingerprint, Analyzer: cloneIdentity(a.identity),
			ConfidenceBasisPoints: raw.ConfidenceBasisPoints, EvidenceSha256: evidence,
		}
		if raw.Location != nil {
			if raw.Location.StartLine < 0 || raw.Location.EndLine < raw.Location.StartLine {
				return nil, "location_invalid"
			}
			signal.Location = &roomv1.SourceLocation{FilePath: raw.Location.FilePath, StartLine: raw.Location.StartLine, EndLine: raw.Location.EndLine}
		}
		signals = append(signals, signal)
	}
	sort.Slice(covered, func(i, j int) bool { return covered[i] < covered[j] })
	return &roomv1.AnalyzerReceipt{
		Analyzer: cloneIdentity(a.identity), Status: status, CoveredSignals: covered,
		Signals: signals, FailureCode: response.FailureCode, InputSha256: append([]byte(nil), digest...),
	}, ""
}

func (a *externalAnalyzer) failure(report *roomv1.AnalysisReport, status roomv1.AnalysisStatus, code string, digest []byte) *roomv1.AnalysisReport {
	report.Status = status
	report.Receipts = []*roomv1.AnalyzerReceipt{{
		Analyzer: cloneIdentity(a.identity), Status: status, CoveredSignals: nil,
		FailureCode: code, InputSha256: append([]byte(nil), digest...),
	}}
	return report
}

func cloneIdentity(identity *roomv1.AnalyzerIdentity) *roomv1.AnalyzerIdentity {
	return proto.Clone(identity).(*roomv1.AnalyzerIdentity)
}

func decodeDigest(value string) ([]byte, error) {
	digest, err := hex.DecodeString(value)
	if err != nil || len(digest) != sha256.Size {
		return nil, errors.New("digest must be a SHA-256 hex value")
	}
	return digest, nil
}

func knownSignal(signal roomv1.SignalKind) bool {
	_, ok := roomv1.SignalKind_name[int32(signal)]
	return ok && signal != roomv1.SignalKind_SIGNAL_KIND_UNSPECIFIED
}

func signalKind(name string) (roomv1.SignalKind, bool) {
	value, ok := roomv1.SignalKind_value[name]
	signal := roomv1.SignalKind(value)
	return signal, ok && knownSignal(signal)
}

func analysisStatus(name string) (roomv1.AnalysisStatus, bool) {
	value, ok := roomv1.AnalysisStatus_value[name]
	status := roomv1.AnalysisStatus(value)
	return status, ok && status != roomv1.AnalysisStatus_ANALYSIS_STATUS_UNSPECIFIED
}
