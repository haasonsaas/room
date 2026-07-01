package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"connectrpc.com/connect"
	roomv1 "github.com/haasonsaas/room/gen/go/room/v1"
	"github.com/haasonsaas/room/gen/go/room/v1/roomv1connect"
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
	client := roomv1connect.NewAgentRulesServiceClient(http.DefaultClient, strings.TrimRight(cfg.ServerURL, "/"))
	admin := roomv1connect.NewRuleAdminServiceClient(http.DefaultClient, strings.TrimRight(cfg.ServerURL, "/"))

	switch args[0] {
	case "rules":
		resp, err := client.GetActiveRuleset(ctx, connect.NewRequest(&roomv1.AgentRulesServiceGetActiveRulesetRequest{}))
		if err != nil {
			return err
		}
		return printProto(resp.Msg)
	case "publish":
		resp, err := admin.PublishRuleset(ctx, connect.NewRequest(&roomv1.PublishRulesetRequest{Author: "roomctl", Notes: "Published from roomctl"}))
		if err != nil {
			return err
		}
		return printProto(resp.Msg)
	case "hook":
		return runHook(ctx, client, args[1:])
	default:
		return usage()
	}
}

func usage() error {
	return fmt.Errorf("usage: roomctl rules | publish | hook <prompt|pre-tool|post-tool>")
}

func runHook(ctx context.Context, client roomv1connect.AgentRulesServiceClient, args []string) error {
	if len(args) == 0 {
		return usage()
	}
	raw, _ := io.ReadAll(os.Stdin)
	payload := map[string]any{}
	_ = json.Unmarshal(raw, &payload)
	input := evaluationInput(payload, raw)

	var result *roomv1.EvaluationResult
	switch args[0] {
	case "prompt", "pre-tool":
		resp, err := client.EvaluatePlan(ctx, connect.NewRequest(&roomv1.EvaluatePlanRequest{Input: input}))
		if err != nil {
			return hookFailure(err)
		}
		result = resp.Msg.GetResult()
	case "post-tool":
		diff := gitDiff()
		if diff != "" {
			input.Diff = diff
		}
		resp, err := client.EvaluateDiff(ctx, connect.NewRequest(&roomv1.EvaluateDiffRequest{Input: input}))
		if err != nil {
			return hookFailure(err)
		}
		result = resp.Msg.GetResult()
	default:
		return usage()
	}
	return writeHookDecision(args[0], result)
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
			ChangedFiles: gitChangedFiles(),
		},
		Plan: plan,
		Diff: gitDiff(),
	}
}

func writeHookDecision(kind string, result *roomv1.EvaluationResult) error {
	if result == nil || result.GetDecision() == roomv1.Decision_DECISION_ALLOW {
		return nil
	}
	reason := summarize(result)
	switch kind {
	case "pre-tool":
		if result.GetHighestSeverity() >= roomv1.Severity_SEVERITY_HIGH {
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
		if result.GetHighestSeverity() >= roomv1.Severity_SEVERITY_HIGH {
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
	default:
		return writeAdditionalContext("UserPromptSubmit", reason)
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
	fmt.Fprintf(&b, "Room guardrails matched %d rule(s).", len(result.GetMatches()))
	for _, match := range result.GetMatches() {
		fmt.Fprintf(&b, "\n- %s [%s]: %s", match.GetRuleId(), match.GetSeverity().String(), match.GetMessage())
	}
	if len(result.GetRequiredChecks()) > 0 {
		b.WriteString("\nRequired evidence:")
		for _, check := range result.GetRequiredChecks() {
			fmt.Fprintf(&b, "\n- %s", check)
		}
	}
	return b.String()
}

func hookFailure(err error) error {
	if strings.EqualFold(os.Getenv("ROOM_HOOK_FAIL_CLOSED"), "true") {
		_ = writeJSON(map[string]any{
			"hookSpecificOutput": map[string]any{
				"hookEventName":            "PreToolUse",
				"permissionDecision":       "deny",
				"permissionDecisionReason": "Room unavailable and ROOM_HOOK_FAIL_CLOSED=true: " + err.Error(),
			},
		})
		return nil
	}
	fmt.Fprintln(os.Stderr, "room hook warning:", err)
	return nil
}

func writeJSON(value any) error {
	return json.NewEncoder(os.Stdout).Encode(value)
}

func printProto(msg any) error {
	if pm, ok := msg.(proto.Message); ok {
		data, err := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(pm)
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil
	}
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
