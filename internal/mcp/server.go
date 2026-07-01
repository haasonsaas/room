package mcp

import (
	"context"
	"net/http"
	"strings"

	"connectrpc.com/connect"
	roomv1 "github.com/haasonsaas/room/gen/go/room/v1"
	"github.com/haasonsaas/room/gen/go/room/v1/roomv1connect"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type Handler struct {
	client roomv1connect.AgentRulesServiceClient
}

func NewHandler(serverURL string) http.Handler {
	h := &Handler{
		client: roomv1connect.NewAgentRulesServiceClient(http.DefaultClient, strings.TrimRight(serverURL, "/")),
	}
	return mcpsdk.NewStreamableHTTPHandler(func(_ *http.Request) *mcpsdk.Server {
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

	return server
}

type ruleInput struct {
	WorkspaceID  string   `json:"workspace_id,omitempty" jsonschema:"Workspace or organization identifier"`
	Repository   string   `json:"repository,omitempty" jsonschema:"Repository name or slug"`
	AgentType    string   `json:"agent_type,omitempty" jsonschema:"Coding agent type, such as codex, claude-code, cursor"`
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

type toolOutput struct {
	JSON string `json:"json"`
}

func (h *Handler) getRules(ctx context.Context, _ *mcpsdk.CallToolRequest, input ruleInput) (*mcpsdk.CallToolResult, toolOutput, error) {
	resp, err := h.client.GetActiveRuleset(ctx, connect.NewRequest(&roomv1.AgentRulesServiceGetActiveRulesetRequest{Context: input.context()}))
	if err != nil {
		return nil, toolOutput{}, err
	}
	return nil, marshal(resp.Msg), nil
}

func (h *Handler) analyzePlan(ctx context.Context, _ *mcpsdk.CallToolRequest, input planInput) (*mcpsdk.CallToolResult, toolOutput, error) {
	resp, err := h.client.EvaluatePlan(ctx, connect.NewRequest(&roomv1.EvaluatePlanRequest{
		Input: &roomv1.EvaluationInput{Context: input.context(), Plan: input.Plan},
	}))
	if err != nil {
		return nil, toolOutput{}, err
	}
	return nil, marshal(resp.Msg), nil
}

func (h *Handler) checkDiff(ctx context.Context, _ *mcpsdk.CallToolRequest, input diffInput) (*mcpsdk.CallToolResult, toolOutput, error) {
	resp, err := h.client.EvaluateDiff(ctx, connect.NewRequest(&roomv1.EvaluateDiffRequest{
		Input: &roomv1.EvaluationInput{Context: input.context(), Diff: input.Diff},
	}))
	if err != nil {
		return nil, toolOutput{}, err
	}
	return nil, marshal(resp.Msg), nil
}

func (i ruleInput) context() *roomv1.EvaluationContext {
	return &roomv1.EvaluationContext{
		WorkspaceId:  i.WorkspaceID,
		Repository:   i.Repository,
		AgentType:    i.AgentType,
		Cwd:          i.CWD,
		ChangedFiles: append([]string(nil), i.ChangedFiles...),
	}
}

func marshal(msg any) toolOutput {
	if pm, ok := msg.(proto.Message); ok {
		data, err := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(pm)
		if err == nil {
			return toolOutput{JSON: string(data)}
		}
	}
	return toolOutput{JSON: "{}"}
}
