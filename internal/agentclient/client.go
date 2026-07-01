package agentclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"connectrpc.com/connect"
	roomv1 "github.com/haasonsaas/room/gen/go/room/v1"
	"github.com/haasonsaas/room/gen/go/room/v1/roomv1connect"
	"github.com/haasonsaas/room/internal/eval"
	"google.golang.org/protobuf/encoding/protojson"
)

type Client struct {
	service  roomv1connect.AgentRulesServiceClient
	cache    string
	server   string
	lastWarn error
}

func New(serverURL, cachePath string) *Client {
	serverURL = strings.TrimRight(strings.TrimSpace(serverURL), "/")
	if serverURL == "" {
		serverURL = "http://localhost:8787"
	}
	if cachePath == "" {
		cachePath = DefaultCachePath()
	}
	return &Client{
		service: roomv1connect.NewAgentRulesServiceClient(http.DefaultClient, serverURL),
		cache:   cachePath,
		server:  serverURL,
	}
}

func DefaultCachePath() string {
	if value := strings.TrimSpace(os.Getenv("ROOM_CACHE_FILE")); value != "" {
		return value
	}
	dir, err := os.UserCacheDir()
	if err != nil || dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".cache")
	}
	return filepath.Join(dir, "room", "ruleset.json")
}

func (c *Client) ActiveRuleset(ctx context.Context, contextInfo *roomv1.EvaluationContext) (*roomv1.RulesetVersion, error) {
	resp, err := c.service.GetActiveRuleset(ctx, connect.NewRequest(&roomv1.AgentRulesServiceGetActiveRulesetRequest{Context: contextInfo}))
	if err == nil && resp.Msg.GetRuleset() != nil {
		ruleset := resp.Msg.GetRuleset()
		if saveErr := SaveRuleset(c.cache, ruleset); saveErr != nil {
			return ruleset, saveErr
		}
		c.lastWarn = nil
		return ruleset, nil
	}
	c.lastWarn = err
	cached, cacheErr := LoadRuleset(c.cache)
	if cacheErr == nil && cached != nil {
		return cached, nil
	}
	if err != nil {
		return nil, fmt.Errorf("fetch active ruleset from %s: %w", c.server, err)
	}
	return nil, cacheErr
}

func (c *Client) EvaluatePlan(ctx context.Context, input *roomv1.EvaluationInput) (*roomv1.EvaluationResult, error) {
	return c.evaluate(ctx, input)
}

func (c *Client) EvaluateDiff(ctx context.Context, input *roomv1.EvaluationInput) (*roomv1.EvaluationResult, error) {
	return c.evaluate(ctx, input)
}

func (c *Client) LastWarning() error {
	return c.lastWarn
}

func (c *Client) evaluate(ctx context.Context, input *roomv1.EvaluationInput) (*roomv1.EvaluationResult, error) {
	if input == nil {
		input = &roomv1.EvaluationInput{}
	}
	ruleset, err := c.ActiveRuleset(ctx, input.GetContext())
	if err != nil {
		return nil, err
	}
	return eval.Evaluate(ruleset.GetRules(), ruleset, input), nil
}

func SaveRuleset(path string, ruleset *roomv1.RulesetVersion) error {
	if ruleset == nil {
		return errors.New("ruleset is required")
	}
	if path == "" {
		return errors.New("cache path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(ruleset)
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func LoadRuleset(path string) (*roomv1.RulesetVersion, error) {
	if path == "" {
		return nil, errors.New("cache path is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var ruleset roomv1.RulesetVersion
	if err := protojson.Unmarshal(data, &ruleset); err != nil {
		return nil, err
	}
	return &ruleset, nil
}
