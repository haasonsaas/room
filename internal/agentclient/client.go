package agentclient

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"connectrpc.com/connect"
	roomv1 "github.com/haasonsaas/room/gen/go/room/v1"
	"github.com/haasonsaas/room/gen/go/room/v1/roomv1connect"
	"github.com/haasonsaas/room/internal/auth"
	"google.golang.org/protobuf/encoding/protojson"
)

type Client struct {
	service      roomv1connect.AgentRulesServiceClient
	cache        string
	server       string
	credentialID string
}

type RulesetSource string

const (
	RulesetSourceServer RulesetSource = "server"
	RulesetSourceCache  RulesetSource = "cache"
)

type RulesetProvenance struct {
	Source   RulesetSource
	Stale    bool
	CachedAt time.Time
	Warning  string
}

func New(serverURL, cachePath string) *Client {
	return NewAuthenticated(serverURL, cachePath, "")
}

// NewAuthenticated creates a client whose bearer credential is applied to
// every Connect request. Credentials are never persisted in the rules cache.
func NewAuthenticated(serverURL, cachePath, token string) *Client {
	return NewAuthenticatedWithTimeout(serverURL, cachePath, token, 45*time.Second)
}

func NewAuthenticatedWithTimeout(serverURL, cachePath, token string, timeout time.Duration) *Client {
	serverURL = strings.TrimRight(strings.TrimSpace(serverURL), "/")
	if serverURL == "" {
		serverURL = "http://localhost:8787"
	}
	if cachePath == "" {
		cachePath = DefaultCachePath()
	}
	credentialID, authenticated := auth.TokenCredentialID(token)
	if authenticated {
		cachePath = scopedCachePath(cachePath, token)
	}
	httpClient := auth.NewHTTPClientWithTimeout(token, timeout)
	return &Client{
		service:      roomv1connect.NewAgentRulesServiceClient(httpClient, serverURL),
		cache:        cachePath,
		server:       serverURL,
		credentialID: credentialID,
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
	ruleset, _, err := c.ActiveRulesetWithProvenance(ctx, contextInfo)
	return ruleset, err
}

func (c *Client) ActiveRulesetWithProvenance(ctx context.Context, contextInfo *roomv1.EvaluationContext) (*roomv1.RulesetVersion, RulesetProvenance, error) {
	resp, err := c.service.GetActiveRuleset(ctx, connect.NewRequest(&roomv1.AgentRulesServiceGetActiveRulesetRequest{Context: contextInfo}))
	if err == nil && resp.Msg.GetRuleset() != nil {
		ruleset := resp.Msg.GetRuleset()
		if scopeErr := c.validateScope(ruleset); scopeErr != nil {
			return nil, RulesetProvenance{}, scopeErr
		}
		provenance := RulesetProvenance{Source: RulesetSourceServer}
		if saveErr := SaveRuleset(c.cache, ruleset); saveErr != nil {
			provenance.Warning = "live ruleset returned but advisory cache update failed"
		}
		return ruleset, provenance, nil
	}
	cached, cacheErr := LoadRuleset(c.cache)
	if cacheErr == nil && cached != nil {
		if scopeErr := c.validateScope(cached); scopeErr != nil {
			return nil, RulesetProvenance{}, scopeErr
		}
		provenance := RulesetProvenance{Source: RulesetSourceCache, Stale: true, Warning: "server unavailable; using scoped advisory cache"}
		if info, statErr := os.Stat(c.cache); statErr == nil {
			provenance.CachedAt = info.ModTime()
		}
		return cached, provenance, nil
	}
	if err != nil {
		return nil, RulesetProvenance{}, fmt.Errorf("fetch active ruleset from %s: %w", c.server, err)
	}
	return nil, RulesetProvenance{}, cacheErr
}

func (c *Client) EvaluatePlan(ctx context.Context, input *roomv1.EvaluationInput) (*roomv1.EvaluationResult, error) {
	if input == nil {
		input = &roomv1.EvaluationInput{}
	}
	resp, err := c.service.EvaluatePlan(ctx, connect.NewRequest(&roomv1.EvaluatePlanRequest{Input: input}))
	if err != nil {
		return nil, fmt.Errorf("evaluate plan at %s: %w", c.server, err)
	}
	return resp.Msg.GetResult(), nil
}

func (c *Client) EvaluateDiff(ctx context.Context, input *roomv1.EvaluationInput) (*roomv1.EvaluationResult, error) {
	if input == nil {
		input = &roomv1.EvaluationInput{}
	}
	resp, err := c.service.EvaluateDiff(ctx, connect.NewRequest(&roomv1.EvaluateDiffRequest{Input: input}))
	if err != nil {
		return nil, fmt.Errorf("evaluate diff at %s: %w", c.server, err)
	}
	return resp.Msg.GetResult(), nil
}

func (c *Client) RecordMcpElicitation(ctx context.Context, receipt *roomv1.McpElicitationReceipt) (string, error) {
	if receipt == nil {
		return "", errors.New("MCP elicitation receipt is required")
	}
	resp, err := c.service.RecordMcpElicitation(ctx, connect.NewRequest(&roomv1.RecordMcpElicitationRequest{Receipt: receipt}))
	if err != nil {
		return "", fmt.Errorf("record MCP elicitation at %s: %w", c.server, err)
	}
	if resp.Msg.GetAuditEventId() == "" {
		return "", errors.New("MCP elicitation audit id is required")
	}
	return resp.Msg.GetAuditEventId(), nil
}

func (c *Client) CachePath() string { return c.cache }

func (c *Client) ValidateRuleset(ruleset *roomv1.RulesetVersion) error {
	return c.validateScope(ruleset)
}

func (c *Client) validateScope(ruleset *roomv1.RulesetVersion) error {
	if c.credentialID == "" {
		return nil
	}
	if ruleset.GetAuthorizedScope().GetCredentialId() != c.credentialID {
		return errors.New("ruleset authorized scope does not match agent credential")
	}
	return nil
}

func scopedCachePath(path, token string) string {
	digest := sha256.Sum256([]byte(token))
	extension := filepath.Ext(path)
	base := strings.TrimSuffix(filepath.Base(path), extension)
	return filepath.Join(filepath.Dir(path), fmt.Sprintf("%s-%x%s", base, digest[:8], extension))
}

func SaveRuleset(path string, ruleset *roomv1.RulesetVersion) error {
	if ruleset == nil {
		return errors.New("ruleset is required")
	}
	if path == "" {
		return errors.New("cache path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(ruleset)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
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
