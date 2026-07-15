package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"connectrpc.com/connect"
	roomv1 "github.com/haasonsaas/room/gen/go/room/v1"
	"github.com/haasonsaas/room/gen/go/room/v1/roomv1connect"
	"github.com/haasonsaas/room/internal/agentclient"
	"github.com/haasonsaas/room/internal/auth"
	"github.com/haasonsaas/room/internal/config"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usage()
	}
	cfg := config.Load()
	if args[0] == "token" {
		return issueToken(cfg, args[1:])
	}
	if args[0] != "watch-rules" {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.ClientTimeout)
		defer cancel()
	}
	if err := cfg.ValidateClient(); err != nil {
		return err
	}
	var token string
	var err error
	if !cfg.AuthDisabled {
		token, err = config.LoadToken(cfg.TokenFile)
		if err != nil {
			return fmt.Errorf("load Room token: %w", err)
		}
	}
	httpClient := auth.NewHTTPClientWithTimeout(token, cfg.ClientTimeout)
	client := agentclient.NewAuthenticatedWithTimeout(cfg.ServerURL, agentclient.DefaultCachePath(), token, cfg.ClientTimeout)
	serverURL := strings.TrimRight(cfg.ServerURL, "/")
	rawAgent := roomv1connect.NewAgentRulesServiceClient(httpClient, serverURL)
	admin := roomv1connect.NewRuleAdminServiceClient(httpClient, serverURL)

	switch args[0] {
	case "rules", "sync-rules":
		ruleset, err := client.ActiveRuleset(ctx, &roomv1.EvaluationContext{})
		if err != nil {
			return err
		}
		return printProto(&roomv1.AgentRulesServiceGetActiveRulesetResponse{Ruleset: ruleset})
	case "watch-rules":
		return watchRules(ctx, rawAgent, client)
	case "publish":
		resp, err := admin.PublishRuleset(ctx, connect.NewRequest(&roomv1.PublishRulesetRequest{Author: "roomctl", Notes: "Published from roomctl"}))
		if err != nil {
			return err
		}
		return printProto(resp.Msg)
	case "hook":
		return runHook(ctx, client, rawAgent, args[1:])
	default:
		return usage()
	}
}

func usage() error {
	return fmt.Errorf("usage: roomctl rules | sync-rules | watch-rules | publish | hook <prompt|pre-tool|pre-mcp|post-tool> | token issue --id ID --role admin|reviewer|agent [--human-operator] [--workspace ID --repository REPO --agent ID] [--hook-provider none|claude_code|codex|cursor | --mcp-proxy]")
}

func issueToken(cfg config.Config, args []string) error {
	if len(args) == 0 || args[0] != "issue" {
		return usage()
	}
	set := flag.NewFlagSet("token issue", flag.ContinueOnError)
	id := set.String("id", "", "credential id")
	role := set.String("role", "agent", "admin, reviewer, or agent")
	workspace := set.String("workspace", "", "exact workspace scope")
	repository := set.String("repository", "", "exact repository scope")
	agent := set.String("agent", "", "exact agent identity")
	hookProvider := set.String("hook-provider", string(auth.HookProviderNone), "trusted hook provider: none, claude_code, codex, or cursor")
	mcpProxy := set.Bool("mcp-proxy", false, "authorize a trusted MCP proxy transport")
	humanOperator := set.Bool("human-operator", false, "authorize human-exclusive protected controls (admin only)")
	output := set.String("output", "", "private file for the one-time token")
	if err := set.Parse(args[1:]); err != nil {
		return err
	}
	principal := auth.Principal{ID: *id, Role: auth.Role(*role), Scope: auth.Scope{WorkspaceID: *workspace, Repository: *repository, AgentID: *agent, HookProvider: auth.HookProvider(*hookProvider), MCPProxy: *mcpProxy}, HumanOperator: *humanOperator}
	token, err := auth.IssueOrUpdateToken(cfg.CredentialFile, principal)
	if err != nil {
		return err
	}
	if *output == "" {
		fmt.Println(token)
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(*output), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(*output, []byte(token+"\n"), 0o600); err != nil {
		return err
	}
	return os.Chmod(*output, 0o600)
}

func watchRules(ctx context.Context, service roomv1connect.AgentRulesServiceClient, client *agentclient.Client) error {
	attempt := 0
	for {
		err := watchRulesOnce(ctx, service, client)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		fmt.Fprintln(os.Stderr, "roomctl watch-rules reconnecting:", err)
		delay := reconnectDelay(attempt)
		if attempt < 5 {
			attempt++
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func reconnectDelay(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	if attempt > 5 {
		attempt = 5
	}
	maximum := time.Second << attempt
	var sample [1]byte
	_, _ = rand.Read(sample[:])
	return maximum/2 + time.Duration(sample[0])*maximum/(2*255)
}

func watchRulesOnce(ctx context.Context, service roomv1connect.AgentRulesServiceClient, client *agentclient.Client) error {
	currentVersion := int32(0)
	if cached, err := agentclient.LoadRuleset(client.CachePath()); err == nil && cached != nil {
		currentVersion = cached.GetVersion()
	}
	stream, err := service.WatchRuleset(ctx, connect.NewRequest(&roomv1.WatchRulesetRequest{CurrentVersion: currentVersion}))
	if err != nil {
		return err
	}
	for stream.Receive() {
		ruleset := stream.Msg().GetRuleset()
		if ruleset == nil {
			continue
		}
		if err := client.ValidateRuleset(ruleset); err != nil {
			return err
		}
		if err := agentclient.SaveRuleset(client.CachePath(), ruleset); err != nil {
			return err
		}
		if err := printProto(&roomv1.AgentRulesServiceGetActiveRulesetResponse{Ruleset: ruleset}); err != nil {
			return err
		}
	}
	return stream.Err()
}

func runHook(ctx context.Context, client *agentclient.Client, service roomv1connect.AgentRulesServiceClient, args []string) error {
	if len(args) == 0 {
		return usage()
	}
	raw, _ := io.ReadAll(os.Stdin)
	payload := map[string]any{}
	_ = json.Unmarshal(raw, &payload)
	input := evaluationInput(payload, raw)

	var result *roomv1.EvaluationResult
	switch args[0] {
	case "prompt", "pre-tool", "pre-mcp":
		if args[0] == "pre-mcp" {
			handled, err := enforceMCPPreTool(ctx, service, input.GetContext(), payload)
			if err != nil || handled {
				return err
			}
		}
		var err error
		result, err = client.EvaluatePlan(ctx, input)
		if err != nil {
			return hookFailure(args[0], err)
		}
	case "post-tool":
		diff := gitDiff()
		if diff != "" {
			input.Diff = diff
		}
		var err error
		result, err = client.EvaluateDiff(ctx, input)
		if err != nil {
			return hookFailure(args[0], err)
		}
	default:
		return usage()
	}
	return writeHookDecision(args[0], result)
}

func enforceMCPPreTool(ctx context.Context, service roomv1connect.AgentRulesServiceClient, contextInfo *roomv1.EvaluationContext, payload map[string]any) (bool, error) {
	invocation, ok := typedMCPInvocation(payload)
	if !ok {
		return true, hookFailure("pre-mcp", errors.New("typed room_mcp_invocation metadata is required for MCP hooks"))
	}
	response, err := service.EvaluateMcpInvocation(ctx, connect.NewRequest(&roomv1.EvaluateMcpInvocationRequest{Context: contextInfo, Invocation: invocation}))
	if err != nil {
		return true, hookFailure("pre-tool", err)
	}
	if response.Msg.GetDecision().GetAllowed() {
		return false, nil
	}
	return true, writeJSON(map[string]any{"hookSpecificOutput": map[string]any{
		"hookEventName": "PreToolUse", "permissionDecision": "deny",
		"permissionDecisionReason": "Room MCP policy: " + response.Msg.GetDecision().GetReasonCode(),
	}})
}

func typedMCPInvocation(payload map[string]any) (*roomv1.McpInvocation, bool) {
	raw, ok := payload["room_mcp_invocation"].(map[string]any)
	if !ok {
		return nil, false
	}
	provider := map[string]roomv1.HookProvider{
		"claude_code": roomv1.HookProvider_HOOK_PROVIDER_CLAUDE_CODE,
		"codex":       roomv1.HookProvider_HOOK_PROVIDER_CODEX,
		"cursor":      roomv1.HookProvider_HOOK_PROVIDER_CURSOR,
		"mcp_proxy":   roomv1.HookProvider_HOOK_PROVIDER_MCP_PROXY,
	}[stringField(raw, "provider")]
	assurance := map[string]roomv1.IdentityAssurance{
		"config_bound":       roomv1.IdentityAssurance_IDENTITY_ASSURANCE_CONFIG_BOUND,
		"transport_verified": roomv1.IdentityAssurance_IDENTITY_ASSURANCE_TRANSPORT_VERIFIED,
	}[stringField(raw, "identity_assurance")]
	return &roomv1.McpInvocation{ServerId: stringField(raw, "server_id"), ToolName: stringField(raw, "tool_name"), Transport: stringField(raw, "transport"), Endpoint: stringField(raw, "endpoint"), Provider: provider, ProviderToolId: stringField(raw, "provider_tool_id"), IdentityAssurance: assurance}, true
}

func evaluationInput(payload map[string]any, raw []byte) *roomv1.EvaluationInput {
	event := stringField(payload, "hook_event_name")
	cwd := stringField(payload, "cwd")
	toolName := stringField(payload, "tool_name")
	prompt := stringField(payload, "prompt")
	toolInput := payload["tool_input"]
	toolJSON, _ := json.Marshal(toolInput)
	plan := strings.TrimSpace(strings.Join([]string{
		"hook_event=" + event,
		"tool_name=" + toolName,
		"prompt=" + prompt,
		"tool_input=" + string(toolJSON),
		"raw=" + string(raw),
	}, "\n"))
	return &roomv1.EvaluationInput{
		Context: &roomv1.EvaluationContext{
			Repository:   repositoryName(),
			AgentType:    agentType(),
			Cwd:          cwd,
			ChangedFiles: hookChangedFiles(payload),
		},
		Plan: plan,
		Diff: gitDiff(),
	}
}

func hookChangedFiles(payload map[string]any) []string {
	files := gitChangedFiles()
	files = append(files, hookFilePaths(payload)...)
	return uniqueNonEmpty(files)
}

func hookFilePaths(payload map[string]any) []string {
	files := make([]string, 0, 2)
	addPath := func(value any) {
		path, ok := value.(string)
		if ok && strings.TrimSpace(path) != "" {
			files = append(files, path)
		}
	}
	addFromMap := func(value any) {
		fields, ok := value.(map[string]any)
		if !ok {
			return
		}
		for _, key := range []string{"file_path", "path", "file"} {
			addPath(fields[key])
		}
		if values, ok := fields["files"].([]any); ok {
			for _, value := range values {
				addPath(value)
			}
		}
	}

	addFromMap(payload)
	addFromMap(payload["tool_input"])
	return files
}

func uniqueNonEmpty(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func writeHookDecision(kind string, result *roomv1.EvaluationResult) error {
	if result == nil {
		return hookFailure(kind, errors.New("Room returned an empty evaluation"))
	}
	if result.GetDecision() == roomv1.Decision_DECISION_ALLOW {
		return nil
	}
	reason := summarize(result)
	blocking := result.GetDecision() == roomv1.Decision_DECISION_DENY ||
		result.GetDecision() == roomv1.Decision_DECISION_NEEDS_CHANGES ||
		result.GetDecision() == roomv1.Decision_DECISION_INDETERMINATE
	switch kind {
	case "pre-tool", "pre-mcp":
		if blocking {
			return writeJSON(map[string]any{
				"hookSpecificOutput": map[string]any{
					"hookEventName":              "PreToolUse",
					"permissionDecision":         "deny",
					"permissionDecisionReason":   reason,
					"roomRulesetVersion":         result.GetRulesetVersion(),
					"roomRulesetHash":            result.GetRulesetHash(),
					"roomHighestMatchedSeverity": result.GetHighestSeverity().String(),
				},
			})
		}
		return writeAdditionalContext("PreToolUse", reason)
	case "post-tool":
		if blocking {
			return writeJSON(map[string]any{
				"decision": "block",
				"reason":   reason,
				"hookSpecificOutput": map[string]any{
					"hookEventName":     "PostToolUse",
					"additionalContext": reason,
				},
			})
		}
		return writeAdditionalContext("PostToolUse", reason)
	case "prompt":
		if blocking {
			return writeJSON(map[string]any{"decision": "block", "reason": reason})
		}
		return writeAdditionalContext("UserPromptSubmit", reason)
	default:
		return usage()
	}
}

func writeAdditionalContext(event, message string) error {
	return writeJSON(map[string]any{
		"hookSpecificOutput": map[string]any{
			"hookEventName":     event,
			"additionalContext": message,
		},
	})
}

func summarize(result *roomv1.EvaluationResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Room decision %s; matched %d rule(s).", result.GetDecision(), len(result.GetMatches()))
	for _, match := range result.GetMatches() {
		fmt.Fprintf(&b, "\n- %s [%s]: %s", match.GetRuleId(), match.GetSeverity().String(), match.GetMessage())
	}
	if len(result.GetRequiredChecks()) > 0 {
		b.WriteString("\nRequired evidence:")
		for _, check := range result.GetRequiredChecks() {
			fmt.Fprintf(&b, "\n- %s", check)
		}
	}
	for _, gap := range result.GetGaps() {
		fmt.Fprintf(&b, "\n- analysis gap: %s", gap.GetReasonCode())
	}
	return b.String()
}

func hookFailure(kind string, err error) error {
	if !strings.EqualFold(os.Getenv("ROOM_HOOK_FAIL_OPEN"), "true") {
		reason := "Room unavailable (fail closed): " + err.Error()
		if kind != "pre-tool" && kind != "pre-mcp" {
			return writeJSON(map[string]any{"decision": "block", "reason": reason})
		}
		return writeJSON(map[string]any{
			"hookSpecificOutput": map[string]any{
				"hookEventName":            "PreToolUse",
				"permissionDecision":       "deny",
				"permissionDecisionReason": reason,
			},
		})
	}
	fmt.Fprintln(os.Stderr, "room hook fail-open warning:", err)
	return nil
}

func writeJSON(value any) error {
	return json.NewEncoder(os.Stdout).Encode(value)
}

func printProto(msg proto.Message) error {
	data, err := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(msg)
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func stringField(payload map[string]any, key string) string {
	value, _ := payload[key].(string)
	return value
}

func gitDiff() string {
	out, err := exec.Command("git", "diff", "--no-ext-diff").Output()
	if err != nil {
		return ""
	}
	return string(out)
}

func gitChangedFiles() []string {
	out, err := exec.Command("git", "diff", "--name-only").Output()
	if err != nil {
		return nil
	}
	lines := bytes.Split(bytes.TrimSpace(out), []byte("\n"))
	files := make([]string, 0, len(lines))
	for _, line := range lines {
		if len(line) > 0 {
			files = append(files, string(line))
		}
	}
	return files
}

func repositoryName() string {
	out, err := exec.Command("git", "config", "--get", "remote.origin.url").Output()
	if err != nil {
		wd, _ := os.Getwd()
		return wd
	}
	return strings.TrimSpace(string(out))
}

func agentType() string {
	if value := os.Getenv("ROOM_AGENT_TYPE"); value != "" {
		return value
	}
	return "coding-agent"
}
