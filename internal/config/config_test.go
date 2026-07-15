package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func validConfig() Config {
	return Config{Addr: "127.0.0.1:8787", ServerURL: "http://127.0.0.1:8787", ControlPlaneURL: "http://127.0.0.1:8787", AuthDisabled: true, AnalyzerArgsValid: true, AnalyzerSignalsValid: true, AnalyzerSignals: []string{"SIGNAL_KIND_RUST_UNSAFE_WITHOUT_SAFETY_CONTRACT"}, AnalyzerTimeout: time.Second, AnalyzerTimeoutValid: true, ReadTimeout: time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: time.Second, ClientTimeout: 10 * time.Second, MaxBodyBytes: 1024}
}

func TestValidateServerRequiresExplicitAnalyzerCoverage(t *testing.T) {
	cfg := validConfig()
	cfg.AnalyzerExecutable = "/bin/analyzer"
	cfg.AnalyzerSignals = nil
	if err := cfg.ValidateAnalyzer(); err == nil {
		t.Fatal("expected missing analyzer coverage rejection")
	}
}

func TestLoadParsesAnalyzerCoverage(t *testing.T) {
	t.Setenv("ROOM_ANALYZER_COVERED_SIGNALS", `["SIGNAL_KIND_RUST_UNSAFE_WITHOUT_SAFETY_CONTRACT"]`)
	cfg := Load()
	if !cfg.AnalyzerSignalsValid || len(cfg.AnalyzerSignals) != 1 || cfg.AnalyzerSignals[0] != "SIGNAL_KIND_RUST_UNSAFE_WITHOUT_SAFETY_CONTRACT" {
		t.Fatalf("analyzer signals = %#v, valid = %v", cfg.AnalyzerSignals, cfg.AnalyzerSignalsValid)
	}
}

func TestLoadRetainsLegacyDefaultStorePath(t *testing.T) {
	t.Setenv("ROOM_DATA_FILE", "")
	if got := Load().DataFile; got != "room-data.json" {
		t.Fatalf("default data file = %q, want room-data.json for in-place upgrade", got)
	}
}

func TestValidateServerRejectsMalformedAnalyzerArgs(t *testing.T) {
	cfg := validConfig()
	cfg.AnalyzerExecutable = "/bin/analyzer"
	cfg.AnalyzerArgsValid = false
	if err := cfg.ValidateAnalyzer(); err == nil {
		t.Fatal("expected malformed analyzer arguments rejection")
	}
}

func TestListenerValidationIgnoresAnalyzerOnlySettings(t *testing.T) {
	cfg := validConfig()
	cfg.AnalyzerExecutable = "/bin/analyzer"
	cfg.AnalyzerArgsValid = false
	cfg.AnalyzerSignalsValid = false
	cfg.AnalyzerSignals = nil
	if err := cfg.ValidateServerAt("127.0.0.1:8788"); err != nil {
		t.Fatalf("listener validation rejected analyzer-only settings: %v", err)
	}
}

func TestValidateServerRejectsUnauthenticatedNonLoopback(t *testing.T) {
	cfg := validConfig()
	cfg.Addr = "0.0.0.0:8787"
	if err := cfg.ValidateServer(); err == nil {
		t.Fatal("expected unauthenticated non-loopback listener rejection")
	}
}

func TestValidateClientRequiresHTTPSForRemoteAuth(t *testing.T) {
	cfg := validConfig()
	cfg.AuthDisabled = false
	cfg.ServerURL = "http://room.example.test"
	if err := cfg.ValidateClient(); err == nil {
		t.Fatal("expected remote HTTP rejection")
	}
}

func TestLoadRejectsMalformedServerReliabilitySettings(t *testing.T) {
	for _, key := range []string{"ROOM_AUTH_MODE", "ROOM_READ_TIMEOUT", "ROOM_WRITE_TIMEOUT", "ROOM_IDLE_TIMEOUT", "ROOM_MAX_BODY_BYTES"} {
		t.Run(key, func(t *testing.T) {
			for _, clear := range []string{"ROOM_AUTH_MODE", "ROOM_READ_TIMEOUT", "ROOM_WRITE_TIMEOUT", "ROOM_IDLE_TIMEOUT", "ROOM_MAX_BODY_BYTES"} {
				t.Setenv(clear, "")
			}
			t.Setenv(key, "not-valid")
			if err := Load().ValidateServer(); err == nil {
				t.Fatalf("expected malformed %s to fail", key)
			}
		})
	}
}

func TestLoadRejectsMalformedClientTimeout(t *testing.T) {
	t.Setenv("ROOM_CLIENT_TIMEOUT", "not-valid")
	if err := Load().ValidateClient(); err == nil {
		t.Fatal("expected malformed ROOM_CLIENT_TIMEOUT to fail")
	}
}

func TestValidateDeadlineOrdering(t *testing.T) {
	cfg := validConfig()
	cfg.AnalyzerExecutable = "/bin/analyzer"
	cfg.AnalyzerTimeout = 10 * time.Second
	cfg.WriteTimeout = 15 * time.Second
	if err := cfg.ValidateDaemon(); err == nil {
		t.Fatal("expected server deadline without analyzer overhead to fail")
	}
	cfg.ClientTimeout = 15 * time.Second
	if err := cfg.ValidateClient(); err == nil {
		t.Fatal("expected client deadline without analyzer overhead to fail")
	}
	cfg.ClientTimeout = 20 * time.Second
	cfg.WriteTimeout = 25 * time.Second
	if err := cfg.ValidateMCPServer(); err == nil {
		t.Fatal("expected MCP write deadline without client overhead to fail")
	}
}

func TestValidateMCPServerRequiresSecureFixedControlPlaneURL(t *testing.T) {
	for name, raw := range map[string]string{
		"remote HTTP": "http://room.example.test",
		"userinfo":    "https://user:secret@room.example.test",
		"relative":    "/control-plane",
	} {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig()
			cfg.WriteTimeout = 20 * time.Second
			cfg.ControlPlaneURL = raw
			if err := cfg.ValidateMCPServer(); err == nil {
				t.Fatalf("expected control plane URL %q to be rejected", raw)
			}
		})
	}
	cfg := validConfig()
	cfg.WriteTimeout = 20 * time.Second
	cfg.ControlPlaneURL = "https://room.example.test/control"
	if err := cfg.ValidateMCPServer(); err != nil {
		t.Fatalf("secure control plane URL rejected: %v", err)
	}
}

func TestValidateMCPControlPlaneIgnoresHTTPWriteDeadline(t *testing.T) {
	t.Setenv("ROOM_CLIENT_TIMEOUT", "10m")
	cfg := Load()
	if err := cfg.ValidateMCPControlPlane(); err != nil {
		t.Fatalf("stdio-appropriate MCP validation rejected long client timeout: %v", err)
	}
	if err := cfg.ValidateMCPServer(); err == nil {
		t.Fatal("expected HTTP MCP validation to preserve write deadline ordering")
	}
}

func TestLoadDefaultsControlPlaneURLToServerURL(t *testing.T) {
	t.Setenv("ROOM_SERVER_URL", "http://127.0.0.1:9876")
	t.Setenv("ROOM_CONTROL_PLANE_URL", "")
	if got := Load().ControlPlaneURL; got != "http://127.0.0.1:9876" {
		t.Fatalf("control plane URL = %q", got)
	}
}

func TestLoadRejectsMalformedAuditOnly(t *testing.T) {
	t.Setenv("ROOM_AUDIT_ONLY", "not-valid")
	if err := Load().ValidateDaemon(); err == nil {
		t.Fatal("expected malformed ROOM_AUDIT_ONLY to fail")
	}
}

func TestLoadTokenRequiresPrivateFile(t *testing.T) {
	t.Setenv("ROOM_TOKEN", "")
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("secret\n"), 0o644); err != nil {
		t.Fatalf("write token: %v", err)
	}
	if _, err := LoadToken(path); err == nil {
		t.Fatal("expected public token file rejection")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("chmod token: %v", err)
	}
	if token, err := LoadToken(path); err != nil || token != "secret" {
		t.Fatalf("token = %q, err = %v", token, err)
	}
}

func TestLoadTokenFileIgnoresRoomToken(t *testing.T) {
	t.Setenv("ROOM_TOKEN", "inherited-token")
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("file-token\n"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}

	token, err := LoadTokenFile(path)
	if err != nil {
		t.Fatalf("load token file: %v", err)
	}
	if token != "file-token" {
		t.Fatalf("token = %q, want file-token", token)
	}
}
