package config

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Addr                 string
	MCPAddr              string
	DataFile             string
	ServerURL            string
	ControlPlaneURL      string
	CredentialFile       string
	AuthDisabled         bool
	TokenFile            string
	AnalyzerID           string
	AnalyzerVersion      string
	AnalyzerExecutable   string
	AnalyzerArgs         []string
	AnalyzerArgsValid    bool
	AnalyzerSignals      []string
	AnalyzerSignalsValid bool
	AnalyzerConfigFile   string
	AnalyzerTimeout      time.Duration
	AnalyzerTimeoutValid bool
	AuditOnly            bool
	TLSCertFile          string
	TLSKeyFile           string
	ReadTimeout          time.Duration
	WriteTimeout         time.Duration
	IdleTimeout          time.Duration
	ClientTimeout        time.Duration
	MaxBodyBytes         int64
	commonParseErrors    []string
	clientParseErrors    []string
	serverParseErrors    []string
	daemonParseErrors    []string
}

func Load() Config {
	serverURL := envOr("ROOM_SERVER_URL", "http://127.0.0.1:8787")
	analyzerArgs, analyzerArgsValid := jsonStringSlice(os.Getenv("ROOM_ANALYZER_ARGS"))
	analyzerSignals, analyzerSignalsValid := jsonStringSlice(os.Getenv("ROOM_ANALYZER_COVERED_SIGNALS"))
	analyzerTimeout, analyzerTimeoutValid := envDuration("ROOM_ANALYZER_TIMEOUT", 30*time.Second)
	authDisabled, authModeValid := authMode(os.Getenv("ROOM_AUTH_MODE"))
	auditOnly, auditOnlyValid := envBool("ROOM_AUDIT_ONLY", false)
	readTimeout, readTimeoutValid := envDuration("ROOM_READ_TIMEOUT", 15*time.Second)
	writeTimeout, writeTimeoutValid := envDuration("ROOM_WRITE_TIMEOUT", 60*time.Second)
	idleTimeout, idleTimeoutValid := envDuration("ROOM_IDLE_TIMEOUT", 60*time.Second)
	clientTimeout, clientTimeoutValid := envDuration("ROOM_CLIENT_TIMEOUT", 45*time.Second)
	maxBodyBytes, maxBodyBytesValid := envInt64("ROOM_MAX_BODY_BYTES", 4<<20)
	cfg := Config{
		Addr:                 envOr("ROOM_ADDR", "127.0.0.1:8787"),
		MCPAddr:              envOr("ROOM_MCP_ADDR", "127.0.0.1:8788"),
		DataFile:             envOr("ROOM_DATA_FILE", "room-data.json"),
		ServerURL:            serverURL,
		ControlPlaneURL:      envOr("ROOM_CONTROL_PLANE_URL", serverURL),
		CredentialFile:       envOr("ROOM_CREDENTIAL_FILE", "room-credentials.json"),
		AuthDisabled:         authDisabled,
		TokenFile:            strings.TrimSpace(os.Getenv("ROOM_TOKEN_FILE")),
		AnalyzerID:           envOr("ROOM_ANALYZER_ID", "room.external"),
		AnalyzerVersion:      envOr("ROOM_ANALYZER_VERSION", "1"),
		AnalyzerExecutable:   strings.TrimSpace(os.Getenv("ROOM_ANALYZER_EXECUTABLE")),
		AnalyzerArgs:         analyzerArgs,
		AnalyzerArgsValid:    analyzerArgsValid,
		AnalyzerSignals:      analyzerSignals,
		AnalyzerSignalsValid: analyzerSignalsValid,
		AnalyzerConfigFile:   strings.TrimSpace(os.Getenv("ROOM_ANALYZER_CONFIG_FILE")),
		AnalyzerTimeout:      analyzerTimeout,
		AnalyzerTimeoutValid: analyzerTimeoutValid,
		AuditOnly:            auditOnly,
		TLSCertFile:          strings.TrimSpace(os.Getenv("ROOM_TLS_CERT_FILE")),
		TLSKeyFile:           strings.TrimSpace(os.Getenv("ROOM_TLS_KEY_FILE")),
		ReadTimeout:          readTimeout,
		WriteTimeout:         writeTimeout,
		IdleTimeout:          idleTimeout,
		ClientTimeout:        clientTimeout,
		MaxBodyBytes:         maxBodyBytes,
	}
	if !authModeValid {
		cfg.commonParseErrors = append(cfg.commonParseErrors, "ROOM_AUTH_MODE must be required or disabled")
	}
	if !readTimeoutValid {
		cfg.serverParseErrors = append(cfg.serverParseErrors, "ROOM_READ_TIMEOUT must be a duration")
	}
	if !writeTimeoutValid {
		cfg.serverParseErrors = append(cfg.serverParseErrors, "ROOM_WRITE_TIMEOUT must be a duration")
	}
	if !idleTimeoutValid {
		cfg.serverParseErrors = append(cfg.serverParseErrors, "ROOM_IDLE_TIMEOUT must be a duration")
	}
	if !maxBodyBytesValid {
		cfg.serverParseErrors = append(cfg.serverParseErrors, "ROOM_MAX_BODY_BYTES must be an integer")
	}
	if !clientTimeoutValid {
		cfg.clientParseErrors = append(cfg.clientParseErrors, "ROOM_CLIENT_TIMEOUT must be a duration")
	}
	if !auditOnlyValid {
		cfg.daemonParseErrors = append(cfg.daemonParseErrors, "ROOM_AUDIT_ONLY must be a boolean")
	}
	return cfg
}

func (c Config) ValidateServer() error {
	return c.ValidateServerAt(c.Addr)
}

func (c Config) ValidateServerAt(address string) error {
	if len(c.commonParseErrors) > 0 {
		return errors.New(strings.Join(c.commonParseErrors, "; "))
	}
	if len(c.serverParseErrors) > 0 {
		return errors.New(strings.Join(c.serverParseErrors, "; "))
	}
	if c.AuthDisabled && !isLoopbackAddress(address) {
		return errors.New("ROOM_AUTH_MODE=disabled is permitted only on a loopback listener")
	}
	if !c.AuthDisabled && !isLoopbackAddress(address) && (c.TLSCertFile == "" || c.TLSKeyFile == "") {
		return errors.New("non-loopback authenticated listeners require ROOM_TLS_CERT_FILE and ROOM_TLS_KEY_FILE")
	}
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		return errors.New("both TLS certificate and key are required")
	}
	if c.MaxBodyBytes <= 0 || c.ReadTimeout <= 0 || c.WriteTimeout <= 0 || c.IdleTimeout <= 0 {
		return errors.New("server limits and timeouts must be positive")
	}
	return nil
}

func (c Config) ValidateDaemon() error {
	if len(c.daemonParseErrors) > 0 {
		return errors.New(strings.Join(c.daemonParseErrors, "; "))
	}
	if c.AnalyzerExecutable != "" && c.WriteTimeout <= c.AnalyzerTimeout+5*time.Second {
		return errors.New("ROOM_WRITE_TIMEOUT must exceed ROOM_ANALYZER_TIMEOUT by more than 5s")
	}
	return nil
}

func (c Config) ValidateMCPServer() error {
	if c.WriteTimeout <= c.ClientTimeout+5*time.Second {
		return errors.New("ROOM_WRITE_TIMEOUT must exceed ROOM_CLIENT_TIMEOUT by more than 5s for room-mcp")
	}
	parsed, err := url.Parse(c.ControlPlaneURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return errors.New("ROOM_CONTROL_PLANE_URL must be an absolute URL")
	}
	if parsed.User != nil {
		return errors.New("ROOM_CONTROL_PLANE_URL must not contain userinfo")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("ROOM_CONTROL_PLANE_URL must not contain a query or fragment")
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname())) {
		return errors.New("ROOM_CONTROL_PLANE_URL must use HTTPS unless it targets loopback")
	}
	return nil
}

func (c Config) ValidateAnalyzer() error {
	if c.AnalyzerExecutable != "" && !c.AnalyzerArgsValid {
		return errors.New("ROOM_ANALYZER_ARGS must be a JSON array of strings")
	}
	if c.AnalyzerExecutable != "" && (!c.AnalyzerSignalsValid || len(c.AnalyzerSignals) == 0) {
		return errors.New("ROOM_ANALYZER_COVERED_SIGNALS must be a non-empty JSON array of signal enum names")
	}
	if c.AnalyzerExecutable != "" && (!c.AnalyzerTimeoutValid || c.AnalyzerTimeout <= 0) {
		return errors.New("ROOM_ANALYZER_TIMEOUT must be a positive duration")
	}
	return nil
}

func (c Config) ValidateClient() error {
	if len(c.commonParseErrors) > 0 {
		return errors.New(strings.Join(c.commonParseErrors, "; "))
	}
	if len(c.clientParseErrors) > 0 {
		return errors.New(strings.Join(c.clientParseErrors, "; "))
	}
	if c.ClientTimeout <= 0 {
		return errors.New("ROOM_CLIENT_TIMEOUT must be positive")
	}
	if c.ClientTimeout <= c.AnalyzerTimeout+5*time.Second {
		return errors.New("ROOM_CLIENT_TIMEOUT must exceed ROOM_ANALYZER_TIMEOUT by more than 5s")
	}
	parsed, err := url.Parse(c.ServerURL)
	if err != nil || parsed.Host == "" {
		return errors.New("ROOM_SERVER_URL must be an absolute URL")
	}
	if !c.AuthDisabled && parsed.Scheme != "https" && !isLoopbackHost(parsed.Hostname()) {
		return errors.New("authenticated remote Room URLs must use HTTPS")
	}
	return nil
}

func LoadToken(path string) (string, error) {
	if value := strings.TrimSpace(os.Getenv("ROOM_TOKEN")); value != "" {
		return value, nil
	}
	if strings.TrimSpace(path) == "" {
		return "", errors.New("ROOM_TOKEN_FILE or ROOM_TOKEN is required")
	}
	return LoadTokenFile(path)
}

func LoadTokenFile(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("ROOM_TOKEN_FILE is required")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("token file must be a private regular file")
	}
	data, err := io.ReadAll(file)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", errors.New("token file is empty")
	}
	return token, nil
}

func isLoopbackAddress(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	return isLoopbackHost(host)
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func jsonStringSlice(value string) ([]string, bool) {
	if strings.TrimSpace(value) == "" {
		return nil, true
	}
	var values []string
	if err := json.Unmarshal([]byte(value), &values); err != nil {
		return nil, false
	}
	return values, true
}

func envOr(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func authMode(value string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "required":
		return false, true
	case "disabled":
		return true, true
	default:
		return false, false
	}
}

func envBool(key string, fallback bool) (bool, bool) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback, true
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback, false
	}
	return parsed, true
}

func envDuration(key string, fallback time.Duration) (time.Duration, bool) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback, true
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback, false
	}
	return parsed, true
}

func envInt64(key string, fallback int64) (int64, bool) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback, true
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return fallback, false
	}
	return parsed, true
}
