package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	completeStatus     = "ANALYSIS_STATUS_COMPLETE"
	partialStatus      = "ANALYSIS_STATUS_PARTIAL"
	failedStatus       = "ANALYSIS_STATUS_FAILED"
	unavailableStatus  = "ANALYSIS_STATUS_UNAVAILABLE"
	maxOutputBytes     = 16 << 20
	semgrepCoreVersion = "1.139.0"
)

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
	ToolSHA256       string   `json:"tool_sha256,omitempty"`
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
