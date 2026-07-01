package store

import (
	"path/filepath"
	"testing"
)

func TestOpenPublishesRustDefaultRules(t *testing.T) {
	ruleStore, err := Open(filepath.Join(t.TempDir(), "room.json"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	ruleset := ruleStore.ActiveRuleset()
	if ruleset == nil {
		t.Fatal("active ruleset is nil")
	}

	want := []string{
		"rust-unsafe-requires-safety-rationale",
		"rust-request-paths-must-not-unwrap",
		"rust-command-exec-requires-allowlist",
		"rust-secrets-require-crypto-rng",
		"rust-paths-must-be-canonicalized",
		"rust-library-api-must-not-panic",
		"rust-no-std-mutex-across-await",
		"rust-serde-external-input-deny-unknown-fields",
	}
	seen := make(map[string]bool, len(ruleset.GetRules()))
	for _, rule := range ruleset.GetRules() {
		seen[rule.GetId()] = true
	}
	for _, id := range want {
		if !seen[id] {
			t.Fatalf("default ruleset missing %s", id)
		}
	}
}
