package mcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	roomv1 "github.com/haasonsaas/room/gen/go/room/v1"
	"github.com/haasonsaas/room/internal/agentclient"
	roomauth "github.com/haasonsaas/room/internal/auth"
	mcpauth "github.com/modelcontextprotocol/go-sdk/auth"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const agentScope = "agent"

type Handler struct {
	client          *agentclient.Client
	controlPlaneURL string
}

func NewHandler(serverURL string) http.Handler {
	return NewHandlerWithTimeout(serverURL, 45*time.Second)
}

func NewHandlerWithControlPlaneURL(serverURL, controlPlaneURL string) http.Handler {
	return NewHandlerWithControlPlaneURLAndTimeout(serverURL, controlPlaneURL, 45*time.Second)
}

func NewAuthenticatedHandler(serverURL string, authenticator roomauth.Authenticator) http.Handler {
	return NewAuthenticatedHandlerWithTimeout(serverURL, authenticator, 45*time.Second)
}

func NewHandlerWithTimeout(serverURL string, timeout time.Duration) http.Handler {
	return newStreamableHandler(serverURL, serverURL, timeout)
}

func NewHandlerWithControlPlaneURLAndTimeout(serverURL, controlPlaneURL string, timeout time.Duration) http.Handler {
	return newStreamableHandler(serverURL, controlPlaneURL, timeout)
}

func NewAuthenticatedHandlerWithTimeout(serverURL string, authenticator roomauth.Authenticator, timeout time.Duration) http.Handler {
	return NewAuthenticatedHandlerWithControlPlaneURLAndTimeout(serverURL, serverURL, authenticator, timeout)
}

func NewAuthenticatedHandlerWithControlPlaneURLAndTimeout(serverURL, controlPlaneURL string, authenticator roomauth.Authenticator, timeout time.Duration) http.Handler {
	verifier := func(_ context.Context, token string, _ *http.Request) (*mcpauth.TokenInfo, error) {
		if authenticator == nil {
			return nil, mcpauth.ErrInvalidToken
		}
		principal, err := authenticator.Authenticate(token)
		if err != nil || principal.ID == "" {
			return nil, mcpauth.ErrInvalidToken
		}
		return &mcpauth.TokenInfo{
			Scopes:     []string{string(principal.Role)},
			Expiration: time.Date(9999, time.December, 31, 23, 59, 59, 0, time.UTC),
			UserID:     principal.ID,
		}, nil
	}
	return mcpauth.RequireBearerToken(verifier, &mcpauth.RequireBearerTokenOptions{Scopes: []string{agentScope}})(newStreamableHandler(serverURL, controlPlaneURL, timeout))
}

func newStreamableHandler(serverURL, controlPlaneURL string, timeout time.Duration) http.Handler {
	serverURL = strings.TrimRight(serverURL, "/")
	controlPlaneURL = strings.TrimRight(controlPlaneURL, "/")
	return mcpsdk.NewStreamableHTTPHandler(func(request *http.Request) *mcpsdk.Server {
		requestToken, _ := roomauth.ExtractBearer(request)
		h := &Handler{client: agentclient.NewAuthenticatedWithTimeout(serverURL, agentclient.DefaultCachePath(), requestToken, timeout), controlPlaneURL: controlPlaneURL}
		return h.server()
	}, nil)
}

func (h *Handler) server() *mcpsdk.Server {
	server := mcpsdk.NewServer(&mcpsdk.Implementation{
		Name:    "room",
		Version: "dev",
	}, &mcpsdk.ServerOptions{
		Instructions: "Room provides coding-agent security guardrails. Call room_analyze_plan before implementation choices and room_check_diff after edits.",
	})

	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        "room_get_rules",
		Description: "Fetch the active Room ruleset for this repository and agent context.",
	}, h.getRules)

	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        "room_analyze_plan",
		Description: "Analyze an intended implementation plan against the active security ruleset before writing code.",
	}, h.analyzePlan)

	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        "room_check_diff",
		Description: "Analyze a proposed or completed diff against the active security ruleset.",
	}, h.checkDiff)

	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        "room_open_policy_control",
		Description: "Open the authenticated Room control plane for a human-only block, pause, or rollback action. This tool never mutates policy.",
	}, h.openPolicyControl)

	return server
}

type ruleInput struct {
	CWD          string   `json:"cwd,omitempty" jsonschema:"Current working directory"`
	ChangedFiles []string `json:"changed_files,omitempty" jsonschema:"Files the agent expects to change"`
}

type planInput struct {
	ruleInput
	Plan string `json:"plan" jsonschema:"required,The implementation plan or decision the coding agent is about to make"`
}

type diffInput struct {
	ruleInput
	Diff string `json:"diff" jsonschema:"required,Unified diff or patch text to evaluate"`
}

type policyControlInput struct {
	CandidateID        string `json:"candidate_id" jsonschema:"required,Immutable policy candidate revision ID"`
	TargetRolloutStage string `json:"target_rollout_stage" jsonschema:"required,Human-only target: block, paused, or rolled_back"`
	ExpectedUpdatedAt  string `json:"expected_updated_at" jsonschema:"required,RFC3339 candidate updated_at used for optimistic concurrency"`
}

type toolOutput struct {
	Decision          string                    `json:"decision,omitempty"`
	Blocking          bool                      `json:"blocking"`
	HighestSeverity   string                    `json:"highest_severity,omitempty"`
	Summary           string                    `json:"summary"`
	Matches           []matchOutput             `json:"matches,omitempty"`
	RequiredChecks    []string                  `json:"required_checks,omitempty"`
	AnalysisStatus    string                    `json:"analysis_status,omitempty"`
	Gaps              []gapOutput               `json:"gaps,omitempty"`
	AnalyzerReceipts  []analyzerReceiptOutput   `json:"analyzer_receipts,omitempty"`
	AuditEventID      string                    `json:"audit_event_id,omitempty"`
	EvaluationID      string                    `json:"evaluation_id,omitempty"`
	InputSHA256       string                    `json:"input_sha256,omitempty"`
	RulesetID         string                    `json:"ruleset_id,omitempty"`
	RulesetVersion    int32                     `json:"ruleset_version,omitempty"`
	RulesetHash       string                    `json:"ruleset_hash,omitempty"`
	SourceHash        string                    `json:"source_hash,omitempty"`
	AuthorizedScope   *authorizationScopeOutput `json:"authorized_scope,omitempty"`
	RulesetProvenance *rulesetProvenanceOutput  `json:"ruleset_provenance,omitempty"`
	RuleCount         int                       `json:"rule_count,omitempty"`
	Rules             []ruleOutput              `json:"rules,omitempty"`
	Elicitation       *elicitationOutput        `json:"elicitation,omitempty"`
}

type elicitationOutput struct {
	Required          bool   `json:"required"`
	Mode              string `json:"mode"`
	Purpose           string `json:"purpose"`
	Action            string `json:"action"`
	Resolution        string `json:"resolution,omitempty"`
	HandoffURL        string `json:"handoff_url,omitempty"`
	AuditEventID      string `json:"audit_event_id,omitempty"`
	OfferAuditEventID string `json:"offer_audit_event_id,omitempty"`
	ElicitationID     string `json:"elicitation_id"`
}

type matchOutput struct {
	RuleID           string   `json:"rule_id"`
	Title            string   `json:"title"`
	Severity         string   `json:"severity"`
	Message          string   `json:"message"`
	Tags             []string `json:"tags,omitempty"`
	RequiredEvidence []string `json:"required_evidence,omitempty"`
	Remediation      []string `json:"remediation,omitempty"`
}

type ruleOutput struct {
	ID               string                 `json:"id"`
	Title            string                 `json:"title"`
	Description      string                 `json:"description,omitempty"`
	Severity         string                 `json:"severity"`
	Tags             []string               `json:"tags,omitempty"`
	Scope            *ruleScopeOutput       `json:"scope,omitempty"`
	Triggers         []signalSelectorOutput `json:"triggers,omitempty"`
	RequiredCoverage []string               `json:"required_coverage,omitempty"`
	RequiredEvidence []string               `json:"required_evidence,omitempty"`
	Remediation      []string               `json:"remediation,omitempty"`
}

type rulesetProvenanceOutput struct {
	Source   string `json:"source"`
	Stale    bool   `json:"stale"`
	CachedAt string `json:"cached_at,omitempty"`
	Warning  string `json:"warning,omitempty"`
}

type authorizationScopeOutput struct {
	CredentialID string `json:"credential_id,omitempty"`
	SubjectID    string `json:"subject_id,omitempty"`
	WorkspaceID  string `json:"workspace_id,omitempty"`
	Repository   string `json:"repository,omitempty"`
	AgentType    string `json:"agent_type,omitempty"`
}

type ruleScopeOutput struct {
	Workspaces   []string `json:"workspaces,omitempty"`
	Repositories []string `json:"repositories,omitempty"`
	Languages    []string `json:"languages,omitempty"`
	Frameworks   []string `json:"frameworks,omitempty"`
	Paths        []string `json:"paths,omitempty"`
	AgentTypes   []string `json:"agent_types,omitempty"`
}

type signalSelectorOutput struct {
	Signal                       string   `json:"signal"`
	Phases                       []string `json:"phases,omitempty"`
	MinimumConfidenceBasisPoints uint32   `json:"minimum_confidence_basis_points"`
}

type gapOutput struct {
	RequiredSignal string `json:"required_signal"`
	AnalyzerID     string `json:"analyzer_id,omitempty"`
	Status         string `json:"status"`
	ReasonCode     string `json:"reason_code,omitempty"`
}

type analyzerIdentityOutput struct {
	ID           string `json:"id,omitempty"`
	Version      string `json:"version,omitempty"`
	ConfigSHA256 string `json:"config_sha256,omitempty"`
}

type sourceLocationOutput struct {
	FilePath  string `json:"file_path,omitempty"`
	StartLine int32  `json:"start_line,omitempty"`
	EndLine   int32  `json:"end_line,omitempty"`
}

type securitySignalOutput struct {
	Kind                  string                  `json:"kind"`
	Fingerprint           string                  `json:"fingerprint,omitempty"`
	Analyzer              *analyzerIdentityOutput `json:"analyzer,omitempty"`
	Location              *sourceLocationOutput   `json:"location,omitempty"`
	ConfidenceBasisPoints uint32                  `json:"confidence_basis_points"`
	EvidenceSHA256        string                  `json:"evidence_sha256,omitempty"`
}

type analyzerReceiptOutput struct {
	Analyzer       *analyzerIdentityOutput `json:"analyzer,omitempty"`
	Status         string                  `json:"status"`
	CoveredSignals []string                `json:"covered_signals,omitempty"`
	Signals        []securitySignalOutput  `json:"signals,omitempty"`
	FailureCode    string                  `json:"failure_code,omitempty"`
	InputSHA256    string                  `json:"input_sha256,omitempty"`
}

func (h *Handler) getRules(ctx context.Context, _ *mcpsdk.CallToolRequest, input ruleInput) (*mcpsdk.CallToolResult, toolOutput, error) {
	ruleset, provenance, err := h.client.ActiveRulesetWithProvenance(ctx, input.context())
	if err != nil {
		return nil, toolOutput{}, err
	}
	output := rulesetOutput(ruleset, provenance)
	return textResult(output.Summary), output, nil
}

func (h *Handler) analyzePlan(ctx context.Context, request *mcpsdk.CallToolRequest, input planInput) (*mcpsdk.CallToolResult, toolOutput, error) {
	result, err := h.client.EvaluatePlan(ctx, &roomv1.EvaluationInput{Context: input.context(), Plan: input.Plan})
	if err != nil {
		return nil, toolOutput{}, err
	}
	output := evaluationOutput(result)
	if err := h.elicitEvaluationResolution(ctx, request, result, &output); err != nil {
		return nil, toolOutput{}, err
	}
	return textResult(output.Summary), output, nil
}

func (h *Handler) checkDiff(ctx context.Context, request *mcpsdk.CallToolRequest, input diffInput) (*mcpsdk.CallToolResult, toolOutput, error) {
	result, err := h.client.EvaluateDiff(ctx, &roomv1.EvaluationInput{Context: input.context(), Diff: input.Diff})
	if err != nil {
		return nil, toolOutput{}, err
	}
	output := evaluationOutput(result)
	if err := h.elicitEvaluationResolution(ctx, request, result, &output); err != nil {
		return nil, toolOutput{}, err
	}
	return textResult(output.Summary), output, nil
}

func (h *Handler) openPolicyControl(ctx context.Context, request *mcpsdk.CallToolRequest, input policyControlInput) (*mcpsdk.CallToolResult, toolOutput, error) {
	stage := rolloutStage(input.TargetRolloutStage)
	if stage == roomv1.RolloutStage_ROLLOUT_STAGE_UNSPECIFIED {
		return nil, toolOutput{}, errors.New("target_rollout_stage must be block, paused, or rolled_back")
	}
	expected, err := time.Parse(time.RFC3339Nano, input.ExpectedUpdatedAt)
	if err != nil {
		return nil, toolOutput{}, errors.New("expected_updated_at must be RFC3339")
	}
	id, err := elicitationID()
	if err != nil {
		return nil, toolOutput{}, err
	}
	handoffURL, err := policyControlURL(h.controlPlaneURL, input.CandidateID, input.TargetRolloutStage)
	if err != nil {
		return nil, toolOutput{}, err
	}
	receipt := &roomv1.McpElicitationReceipt{Id: id, PolicyCandidateId: input.CandidateID, Mode: roomv1.McpElicitationMode_MCP_ELICITATION_MODE_URL, Purpose: roomv1.McpElicitationPurpose_MCP_ELICITATION_PURPOSE_POLICY_CONTROL, TargetRolloutStage: stage, ExpectedCandidateUpdatedAt: timestamppb.New(expected)}
	elicitation := &elicitationOutput{Required: true, Mode: "url", Purpose: "policy_control", ElicitationID: id, HandoffURL: handoffURL}
	output := toolOutput{Summary: "Room policy control requires an authenticated human operator. Opening the URL does not mutate policy.", Elicitation: elicitation}
	if !supportsURLElicitation(request) {
		receipt.Action = roomv1.McpElicitationAction_MCP_ELICITATION_ACTION_UNSUPPORTED
		elicitation.Action = "unsupported"
		if err := h.persistElicitation(ctx, receipt, elicitation); err != nil {
			return nil, toolOutput{}, err
		}
		return textResult(output.Summary), output, nil
	}
	offered := proto.Clone(receipt).(*roomv1.McpElicitationReceipt)
	offered.Action = roomv1.McpElicitationAction_MCP_ELICITATION_ACTION_OFFERED
	offerOutput := &elicitationOutput{}
	if err := h.persistElicitation(ctx, offered, offerOutput); err != nil {
		return nil, toolOutput{}, err
	}
	elicitation.OfferAuditEventID = offerOutput.AuditEventID
	receipt.OfferAuditEventId = offerOutput.AuditEventID
	response, elicitErr := request.Session.Elicit(ctx, &mcpsdk.ElicitParams{Mode: "url", Message: "Open Room to complete this human-only policy action with an authenticated human-operator credential.", URL: handoffURL, ElicitationID: id})
	if elicitErr != nil || response == nil {
		receipt.Action = roomv1.McpElicitationAction_MCP_ELICITATION_ACTION_ERROR
		elicitation.Action = "error"
	} else {
		receipt.Action, elicitation.Action = elicitationAction(response.Action)
	}
	if err := h.persistElicitation(ctx, receipt, elicitation); err != nil {
		return nil, toolOutput{}, err
	}
	return textResult(output.Summary), output, nil
}

func (h *Handler) elicitEvaluationResolution(ctx context.Context, request *mcpsdk.CallToolRequest, result *roomv1.EvaluationResult, output *toolOutput) error {
	if !requiresEvaluationResolution(result) {
		return nil
	}
	id, err := elicitationID()
	if err != nil {
		return err
	}
	receipt := &roomv1.McpElicitationReceipt{
		Id: id, EvaluationId: result.GetEvaluationId(), EvaluationAuditEventId: result.GetAuditEventId(),
		Mode:    roomv1.McpElicitationMode_MCP_ELICITATION_MODE_FORM,
		Purpose: roomv1.McpElicitationPurpose_MCP_ELICITATION_PURPOSE_EVALUATION_RESOLUTION,
	}
	elicitation := &elicitationOutput{Required: true, Mode: "form", Purpose: "evaluation_resolution", ElicitationID: id}
	output.Elicitation = elicitation
	if !supportsFormElicitation(request) {
		receipt.Action = roomv1.McpElicitationAction_MCP_ELICITATION_ACTION_UNSUPPORTED
		elicitation.Action = "unsupported"
		return h.persistElicitation(ctx, receipt, elicitation)
	}
	offered := proto.Clone(receipt).(*roomv1.McpElicitationReceipt)
	offered.Action = roomv1.McpElicitationAction_MCP_ELICITATION_ACTION_OFFERED
	offerOutput := &elicitationOutput{}
	if err := h.persistElicitation(ctx, offered, offerOutput); err != nil {
		return err
	}
	elicitation.OfferAuditEventID = offerOutput.AuditEventID
	receipt.OfferAuditEventId = offerOutput.AuditEventID
	response, elicitErr := request.Session.Elicit(ctx, &mcpsdk.ElicitParams{
		Mode:    "form",
		Message: "Room requires a typed next step before this evaluation can be resolved.",
		RequestedSchema: map[string]any{
			"type":                 "object",
			"additionalProperties": false,
			"properties": map[string]any{
				"resolution": map[string]any{"type": "string", "title": "Resolution", "enum": []string{"revise", "run_required_checks", "provide_evidence", "open_control_plane"}},
			},
			"required": []string{"resolution"},
		},
	})
	if elicitErr != nil || response == nil {
		receipt.Action = roomv1.McpElicitationAction_MCP_ELICITATION_ACTION_ERROR
		elicitation.Action = "error"
		if err := h.persistElicitation(ctx, receipt, elicitation); err != nil {
			return err
		}
		return nil
	}
	receipt.Action, elicitation.Action = elicitationAction(response.Action)
	if receipt.GetAction() == roomv1.McpElicitationAction_MCP_ELICITATION_ACTION_ACCEPT {
		resolution, ok := response.Content["resolution"].(string)
		if !ok {
			receipt.Action = roomv1.McpElicitationAction_MCP_ELICITATION_ACTION_ERROR
			elicitation.Action = "error"
		} else {
			receipt.Resolution = resolutionAction(resolution)
			if receipt.GetResolution() == roomv1.McpResolutionAction_MCP_RESOLUTION_ACTION_UNSPECIFIED {
				receipt.Action = roomv1.McpElicitationAction_MCP_ELICITATION_ACTION_ERROR
				elicitation.Action = "error"
			} else {
				elicitation.Resolution = resolution
			}
		}
	}
	return h.persistElicitation(ctx, receipt, elicitation)
}

func requiresEvaluationResolution(result *roomv1.EvaluationResult) bool {
	if result == nil {
		return false
	}
	switch result.GetDecision() {
	case roomv1.Decision_DECISION_NEEDS_CHANGES, roomv1.Decision_DECISION_DENY, roomv1.Decision_DECISION_INDETERMINATE:
	default:
		return false
	}
	if len(result.GetRequiredChecks()) > 0 || len(result.GetGaps()) > 0 {
		return true
	}
	for _, match := range result.GetMatches() {
		if len(match.GetRequiredEvidence()) > 0 || len(match.GetRemediation()) > 0 {
			return true
		}
	}
	return false
}

func supportsFormElicitation(request *mcpsdk.CallToolRequest) bool {
	if request == nil || request.Session == nil || request.Session.InitializeParams() == nil || request.Session.InitializeParams().Capabilities == nil {
		return false
	}
	capability := request.Session.InitializeParams().Capabilities.Elicitation
	return capability != nil && (capability.Form != nil || (capability.Form == nil && capability.URL == nil))
}

func supportsURLElicitation(request *mcpsdk.CallToolRequest) bool {
	if request == nil || request.Session == nil || request.Session.InitializeParams() == nil || request.Session.InitializeParams().Capabilities == nil {
		return false
	}
	capability := request.Session.InitializeParams().Capabilities.Elicitation
	return capability != nil && capability.URL != nil
}

func rolloutStage(value string) roomv1.RolloutStage {
	switch value {
	case "block":
		return roomv1.RolloutStage_ROLLOUT_STAGE_BLOCK
	case "paused":
		return roomv1.RolloutStage_ROLLOUT_STAGE_PAUSED
	case "rolled_back":
		return roomv1.RolloutStage_ROLLOUT_STAGE_ROLLED_BACK
	default:
		return roomv1.RolloutStage_ROLLOUT_STAGE_UNSPECIFIED
	}
}

func policyControlURL(base, candidateID, target string) (string, error) {
	parsed, err := url.Parse(base)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", errors.New("control plane URL is invalid")
	}
	parsed.Fragment = url.Values{"candidate": []string{candidateID}, "tab": []string{"rollout"}, "target": []string{target}}.Encode()
	return parsed.String(), nil
}

func elicitationAction(action string) (roomv1.McpElicitationAction, string) {
	switch action {
	case "accept":
		return roomv1.McpElicitationAction_MCP_ELICITATION_ACTION_ACCEPT, action
	case "decline":
		return roomv1.McpElicitationAction_MCP_ELICITATION_ACTION_DECLINE, action
	case "cancel":
		return roomv1.McpElicitationAction_MCP_ELICITATION_ACTION_CANCEL, action
	default:
		return roomv1.McpElicitationAction_MCP_ELICITATION_ACTION_ERROR, "error"
	}
}

func resolutionAction(value string) roomv1.McpResolutionAction {
	switch value {
	case "revise":
		return roomv1.McpResolutionAction_MCP_RESOLUTION_ACTION_REVISE
	case "run_required_checks":
		return roomv1.McpResolutionAction_MCP_RESOLUTION_ACTION_RUN_REQUIRED_CHECKS
	case "provide_evidence":
		return roomv1.McpResolutionAction_MCP_RESOLUTION_ACTION_PROVIDE_EVIDENCE
	case "open_control_plane":
		return roomv1.McpResolutionAction_MCP_RESOLUTION_ACTION_OPEN_CONTROL_PLANE
	default:
		return roomv1.McpResolutionAction_MCP_RESOLUTION_ACTION_UNSPECIFIED
	}
}

func (h *Handler) persistElicitation(ctx context.Context, receipt *roomv1.McpElicitationReceipt, output *elicitationOutput) error {
	auditID, err := h.client.RecordMcpElicitation(ctx, receipt)
	if err != nil {
		return err
	}
	output.AuditEventID = auditID
	return nil
}

func elicitationID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate elicitation id: %w", err)
	}
	return "elicitation-" + hex.EncodeToString(value), nil
}

func (i ruleInput) context() *roomv1.EvaluationContext {
	return &roomv1.EvaluationContext{
		Cwd:          i.CWD,
		ChangedFiles: append([]string(nil), i.ChangedFiles...),
	}
}

func rulesetOutput(ruleset *roomv1.RulesetVersion, provenance agentclient.RulesetProvenance) toolOutput {
	if ruleset == nil {
		return toolOutput{Summary: "Room has no active ruleset."}
	}
	rules := make([]ruleOutput, 0, len(ruleset.GetRules()))
	for _, rule := range ruleset.GetRules() {
		rules = append(rules, ruleOutput{
			ID:               rule.GetId(),
			Title:            rule.GetTitle(),
			Description:      rule.GetDescription(),
			Severity:         severityString(rule.GetSeverity()),
			Tags:             append([]string(nil), rule.GetTags()...),
			Scope:            ruleScope(rule.GetScope()),
			Triggers:         signalSelectors(rule.GetTriggers()),
			RequiredCoverage: signalKinds(rule.GetRequiredCoverage()),
			RequiredEvidence: append([]string(nil), rule.GetRequiredEvidence()...),
			Remediation:      append([]string(nil), rule.GetRemediation()...),
		})
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	provenanceOutput := rulesetProvenance(provenance)
	summary := fmt.Sprintf("Room active ruleset %s v%d contains %d rule(s).", ruleset.GetId(), ruleset.GetVersion(), len(rules))
	if provenance.Stale {
		summary = fmt.Sprintf("Room cached advisory ruleset %s v%d contains %d rule(s); live server state was unavailable.", ruleset.GetId(), ruleset.GetVersion(), len(rules))
	}
	if provenance.Warning != "" {
		summary += " Warning: " + provenance.Warning + "."
	}
	if !provenance.CachedAt.IsZero() {
		summary += " Cached at " + provenance.CachedAt.UTC().Format(time.RFC3339Nano) + "."
	}
	return toolOutput{
		Blocking:          false,
		Summary:           summary,
		RulesetID:         ruleset.GetId(),
		RulesetVersion:    ruleset.GetVersion(),
		RulesetHash:       ruleset.GetHash(),
		SourceHash:        ruleset.GetSourceHash(),
		AuthorizedScope:   authorizationScope(ruleset.GetAuthorizedScope()),
		RulesetProvenance: &provenanceOutput,
		RuleCount:         len(rules),
		Rules:             rules,
	}
}

func evaluationOutput(result *roomv1.EvaluationResult) toolOutput {
	if result == nil {
		return toolOutput{Decision: "indeterminate", Blocking: true, Summary: "Room decision: indeterminate. No evaluation result was returned."}
	}
	matches := make([]matchOutput, 0, len(result.GetMatches()))
	for _, match := range result.GetMatches() {
		matches = append(matches, matchOutput{
			RuleID:           match.GetRuleId(),
			Title:            match.GetTitle(),
			Severity:         severityString(match.GetSeverity()),
			Message:          match.GetMessage(),
			Tags:             append([]string(nil), match.GetTags()...),
			RequiredEvidence: append([]string(nil), match.GetRequiredEvidence()...),
			Remediation:      append([]string(nil), match.GetRemediation()...),
		})
	}
	decision := decisionString(result.GetDecision())
	output := toolOutput{
		Decision: decision,
		Blocking: result.GetDecision() == roomv1.Decision_DECISION_DENY ||
			result.GetDecision() == roomv1.Decision_DECISION_NEEDS_CHANGES ||
			result.GetDecision() == roomv1.Decision_DECISION_INDETERMINATE,
		HighestSeverity:  severityString(result.GetHighestSeverity()),
		Matches:          matches,
		RequiredChecks:   append([]string(nil), result.GetRequiredChecks()...),
		AnalysisStatus:   analysisStatusString(result.GetAnalysisStatus()),
		Gaps:             gaps(result.GetGaps()),
		AnalyzerReceipts: analyzerReceipts(result.GetAnalyzerReceipts()),
		AuditEventID:     result.GetAuditEventId(),
		EvaluationID:     result.GetEvaluationId(),
		InputSHA256:      hex.EncodeToString(result.GetInputSha256()),
		RulesetID:        result.GetRulesetId(),
		RulesetVersion:   result.GetRulesetVersion(),
		RulesetHash:      result.GetRulesetHash(),
	}
	output.Summary = summarizeEvaluation(output)
	return output
}

func summarizeEvaluation(output toolOutput) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Room decision: %s", output.Decision)
	if output.HighestSeverity != "" && output.HighestSeverity != "unspecified" {
		fmt.Fprintf(&b, " (%s)", output.HighestSeverity)
	}
	if output.RulesetVersion > 0 {
		fmt.Fprintf(&b, " using ruleset v%d", output.RulesetVersion)
	}
	b.WriteString(".")
	if output.AnalysisStatus != "" && output.AnalysisStatus != "unspecified" {
		fmt.Fprintf(&b, " Analysis status: %s.", output.AnalysisStatus)
	}
	if len(output.Matches) == 0 {
		if len(output.Gaps) > 0 {
			b.WriteString(" No rule-match conclusion was possible.")
		} else {
			b.WriteString(" No guardrails matched.")
		}
	} else {
		fmt.Fprintf(&b, " Matched %d rule(s):", len(output.Matches))
		for _, match := range output.Matches {
			fmt.Fprintf(&b, "\n- %s [%s]: %s", match.RuleID, match.Severity, match.Message)
		}
	}
	if len(output.RequiredChecks) > 0 {
		b.WriteString("\nRequired evidence:")
		for _, check := range output.RequiredChecks {
			fmt.Fprintf(&b, "\n- %s", check)
		}
	}
	if len(output.Gaps) > 0 {
		b.WriteString("\nAnalysis gaps:")
		for _, gap := range output.Gaps {
			fmt.Fprintf(&b, "\n- %s: %s", gap.RequiredSignal, gap.ReasonCode)
			if gap.AnalyzerID != "" {
				fmt.Fprintf(&b, " (analyzer %s, status %s)", gap.AnalyzerID, gap.Status)
			}
		}
	}
	if len(output.AnalyzerReceipts) > 0 {
		b.WriteString("\nAnalyzer receipts:")
		for _, receipt := range output.AnalyzerReceipts {
			analyzerID := "unknown"
			if receipt.Analyzer != nil && receipt.Analyzer.ID != "" {
				analyzerID = receipt.Analyzer.ID
			}
			fmt.Fprintf(&b, "\n- %s: %s", analyzerID, receipt.Status)
			if receipt.FailureCode != "" {
				fmt.Fprintf(&b, " (%s)", receipt.FailureCode)
			}
		}
	}
	if output.AuditEventID != "" {
		fmt.Fprintf(&b, "\nAudit event: %s", output.AuditEventID)
	}
	if output.EvaluationID != "" {
		fmt.Fprintf(&b, "\nEvaluation: %s", output.EvaluationID)
	}
	return b.String()
}

func rulesetProvenance(value agentclient.RulesetProvenance) rulesetProvenanceOutput {
	output := rulesetProvenanceOutput{Source: string(value.Source), Stale: value.Stale, Warning: value.Warning}
	if !value.CachedAt.IsZero() {
		output.CachedAt = value.CachedAt.UTC().Format(time.RFC3339Nano)
	}
	return output
}

func authorizationScope(scope *roomv1.AuthorizationScope) *authorizationScopeOutput {
	if scope == nil {
		return nil
	}
	return &authorizationScopeOutput{CredentialID: scope.GetCredentialId(), SubjectID: scope.GetSubjectId(), WorkspaceID: scope.GetWorkspaceId(), Repository: scope.GetRepository(), AgentType: scope.GetAgentType()}
}

func ruleScope(scope *roomv1.RuleScope) *ruleScopeOutput {
	if scope == nil {
		return nil
	}
	return &ruleScopeOutput{
		Workspaces: append([]string(nil), scope.GetWorkspaces()...), Repositories: append([]string(nil), scope.GetRepositories()...),
		Languages: append([]string(nil), scope.GetLanguages()...), Frameworks: append([]string(nil), scope.GetFrameworks()...),
		Paths: append([]string(nil), scope.GetPaths()...), AgentTypes: append([]string(nil), scope.GetAgentTypes()...),
	}
}

func signalSelectors(selectors []*roomv1.SignalSelector) []signalSelectorOutput {
	output := make([]signalSelectorOutput, 0, len(selectors))
	for _, selector := range selectors {
		if selector == nil {
			continue
		}
		phases := make([]string, 0, len(selector.GetPhases()))
		for _, phase := range selector.GetPhases() {
			phases = append(phases, analysisPhaseString(phase))
		}
		output = append(output, signalSelectorOutput{Signal: signalKindString(selector.GetSignal()), Phases: phases, MinimumConfidenceBasisPoints: selector.GetMinimumConfidenceBasisPoints()})
	}
	return output
}

func signalKinds(values []roomv1.SignalKind) []string {
	output := make([]string, 0, len(values))
	for _, value := range values {
		output = append(output, signalKindString(value))
	}
	return output
}

func gaps(values []*roomv1.EvaluationGap) []gapOutput {
	output := make([]gapOutput, 0, len(values))
	for _, gap := range values {
		if gap == nil {
			continue
		}
		output = append(output, gapOutput{RequiredSignal: signalKindString(gap.GetRequiredSignal()), AnalyzerID: gap.GetAnalyzerId(), Status: analysisStatusString(gap.GetStatus()), ReasonCode: gap.GetReasonCode()})
	}
	return output
}

func analyzerReceipts(values []*roomv1.AnalyzerReceipt) []analyzerReceiptOutput {
	output := make([]analyzerReceiptOutput, 0, len(values))
	for _, receipt := range values {
		if receipt == nil {
			continue
		}
		signals := make([]securitySignalOutput, 0, len(receipt.GetSignals()))
		for _, signal := range receipt.GetSignals() {
			if signal == nil {
				continue
			}
			signals = append(signals, securitySignalOutput{Kind: signalKindString(signal.GetKind()), Fingerprint: signal.GetFingerprint(), Analyzer: analyzerIdentity(signal.GetAnalyzer()), Location: sourceLocation(signal.GetLocation()), ConfidenceBasisPoints: signal.GetConfidenceBasisPoints(), EvidenceSHA256: hex.EncodeToString(signal.GetEvidenceSha256())})
		}
		output = append(output, analyzerReceiptOutput{Analyzer: analyzerIdentity(receipt.GetAnalyzer()), Status: analysisStatusString(receipt.GetStatus()), CoveredSignals: signalKinds(receipt.GetCoveredSignals()), Signals: signals, FailureCode: receipt.GetFailureCode(), InputSHA256: hex.EncodeToString(receipt.GetInputSha256())})
	}
	return output
}

func analyzerIdentity(identity *roomv1.AnalyzerIdentity) *analyzerIdentityOutput {
	if identity == nil {
		return nil
	}
	return &analyzerIdentityOutput{ID: identity.GetId(), Version: identity.GetVersion(), ConfigSHA256: hex.EncodeToString(identity.GetConfigSha256())}
}

func sourceLocation(location *roomv1.SourceLocation) *sourceLocationOutput {
	if location == nil {
		return nil
	}
	return &sourceLocationOutput{FilePath: location.GetFilePath(), StartLine: location.GetStartLine(), EndLine: location.GetEndLine()}
}

func analysisStatusString(status roomv1.AnalysisStatus) string {
	return strings.ToLower(strings.TrimPrefix(status.String(), "ANALYSIS_STATUS_"))
}

func analysisPhaseString(phase roomv1.AnalysisPhase) string {
	return strings.ToLower(strings.TrimPrefix(phase.String(), "ANALYSIS_PHASE_"))
}

func signalKindString(kind roomv1.SignalKind) string {
	return strings.ToLower(strings.TrimPrefix(kind.String(), "SIGNAL_KIND_"))
}

func textResult(text string) *mcpsdk.CallToolResult {
	return &mcpsdk.CallToolResult{
		Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: text}},
	}
}

func decisionString(decision roomv1.Decision) string {
	switch decision {
	case roomv1.Decision_DECISION_ALLOW:
		return "allow"
	case roomv1.Decision_DECISION_WARN:
		return "warn"
	case roomv1.Decision_DECISION_NEEDS_CHANGES:
		return "needs_changes"
	case roomv1.Decision_DECISION_DENY:
		return "deny"
	case roomv1.Decision_DECISION_INDETERMINATE:
		return "indeterminate"
	default:
		return "unspecified"
	}
}

func severityString(severity roomv1.Severity) string {
	switch severity {
	case roomv1.Severity_SEVERITY_INFO:
		return "info"
	case roomv1.Severity_SEVERITY_LOW:
		return "low"
	case roomv1.Severity_SEVERITY_MEDIUM:
		return "medium"
	case roomv1.Severity_SEVERITY_HIGH:
		return "high"
	case roomv1.Severity_SEVERITY_CRITICAL:
		return "critical"
	default:
		return "unspecified"
	}
}
