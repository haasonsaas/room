package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	roomauth "github.com/haasonsaas/room/internal/auth"
	"github.com/haasonsaas/room/internal/config"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	endpoint := flag.String("endpoint", envOr("ROOM_MCP_URL", "http://localhost:8788/mcp"), "Room MCP endpoint")
	tool := flag.String("tool", "room_analyze_plan", "MCP tool to call")
	plan := flag.String("plan", "", "Plan text for room_analyze_plan")
	diff := flag.String("diff", "", "Diff text for room_check_diff")
	listOnly := flag.Bool("list", false, "List MCP tools and exit")
	flag.Parse()

	if err := run(context.Background(), *endpoint, *tool, *plan, *diff, *listOnly); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, endpoint, tool, plan, diff string, listOnly bool) error {
	client := mcpsdk.NewClient(&mcpsdk.Implementation{Name: "room-mcp-call", Version: "dev"}, nil)
	httpClient := http.DefaultClient
	cfg := config.Load()
	if err := cfg.ValidateClient(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.ClientTimeout)
	defer cancel()
	if !cfg.AuthDisabled {
		token, tokenErr := config.LoadToken(cfg.TokenFile)
		if tokenErr != nil {
			return fmt.Errorf("load Room token: %w", tokenErr)
		}
		httpClient = roomauth.NewHTTPClientWithTimeout(token, cfg.ClientTimeout)
	}
	session, err := client.Connect(ctx, &mcpsdk.StreamableClientTransport{Endpoint: endpoint, HTTPClient: httpClient}, nil)
	if err != nil {
		return fmt.Errorf("connect to %s: %w", endpoint, err)
	}
	defer session.Close()

	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		return fmt.Errorf("list tools: %w", err)
	}
	fmt.Println("tools:")
	for _, item := range tools.Tools {
		fmt.Printf("- %s: %s\n", item.Name, item.Description)
	}
	if listOnly {
		return nil
	}

	args := map[string]any{}
	switch tool {
	case "room_analyze_plan":
		if strings.TrimSpace(plan) == "" {
			data, _ := io.ReadAll(os.Stdin)
			plan = string(data)
		}
		args["plan"] = plan
	case "room_check_diff":
		if strings.TrimSpace(diff) == "" {
			data, _ := io.ReadAll(os.Stdin)
			diff = string(data)
		}
		args["diff"] = diff
	}

	result, err := session.CallTool(ctx, &mcpsdk.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		return fmt.Errorf("call %s: %w", tool, err)
	}
	for _, content := range result.Content {
		if text, ok := content.(*mcpsdk.TextContent); ok {
			fmt.Println("text:")
			fmt.Println(text.Text)
		}
	}
	if result.StructuredContent != nil {
		data, err := json.MarshalIndent(result.StructuredContent, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal structured content: %w", err)
		}
		fmt.Println("structured:")
		fmt.Println(string(data))
	}
	return nil
}

func envOr(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}
