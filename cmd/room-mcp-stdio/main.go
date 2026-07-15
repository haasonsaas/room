package main

import (
	"context"
	"fmt"
	"os"

	"github.com/haasonsaas/room/internal/config"
	roommcp "github.com/haasonsaas/room/internal/mcp"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	if err := run(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	cfg := config.Load()
	if err := cfg.ValidateClient(); err != nil {
		return fmt.Errorf("invalid upstream configuration: %w", err)
	}
	if err := cfg.ValidateMCPServer(); err != nil {
		return fmt.Errorf("invalid MCP configuration: %w", err)
	}
	token, err := config.LoadToken(cfg.TokenFile)
	if err != nil {
		return fmt.Errorf("load Room token: %w", err)
	}
	server := roommcp.NewServerWithTokenAndTimeout(cfg.ServerURL, cfg.ControlPlaneURL, token, cfg.ClientTimeout)
	if err := server.Run(ctx, &mcpsdk.StdioTransport{}); err != nil {
		return fmt.Errorf("serve Room MCP over stdio: %w", err)
	}
	return nil
}
