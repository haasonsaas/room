package auth

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

func TestFileAuthenticatorReloadsRotatedCredential(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	principal := Principal{ID: "runner", Role: RoleAgent, Scope: Scope{WorkspaceID: "w", Repository: "r", AgentID: "a"}}
	oldToken, err := IssueOrUpdateToken(path, principal)
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err := NewFileAuthenticator(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authenticator.Authenticate(oldToken); err != nil {
		t.Fatalf("initial token: %v", err)
	}
	human := Principal{ID: "human", Role: RoleAdmin, HumanOperator: true}
	if _, err := IssueOrUpdateToken(path, human); err != nil {
		t.Fatal(err)
	}
	newToken, _, err := RotateAgentScope(path, human, principal.ID, principal.Scope, "APPROVE")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authenticator.Authenticate(newToken); err != nil {
		t.Fatalf("rotated token: %v", err)
	}
	if _, err := authenticator.Authenticate(oldToken); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("old token error = %v, want unauthenticated", err)
	}
}

func TestFileAuthenticatorRetainsLastKnownGoodRegistry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	principal := Principal{ID: "operator", Role: RoleAdmin}
	token, err := IssueOrUpdateToken(path, principal)
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err := NewFileAuthenticator(path)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, []byte(`{"version":1,"credentials":[`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := authenticator.Authenticate(token); err != nil || got != principal {
		t.Fatalf("malformed reload principal = %#v, err = %v", got, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if got, err := authenticator.Authenticate(token); err != nil || got != principal {
		t.Fatalf("unreadable reload principal = %#v, err = %v", got, err)
	}
}

func TestNewFileAuthenticatorRequiresValidInitialRegistry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	if _, err := NewFileAuthenticator(path); err == nil {
		t.Fatal("missing initial registry accepted")
	}
	if err := os.WriteFile(path, []byte(`{"version":2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileAuthenticator(path); err == nil {
		t.Fatal("invalid initial registry accepted")
	}
}

func TestConcurrentIssuancePreservesBothCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	lock, err := os.OpenFile(registryLockPath(path), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}

	principals := []Principal{
		{ID: "runner-one", Role: RoleAgent, Scope: Scope{WorkspaceID: "w", Repository: "r", AgentID: "a1"}},
		{ID: "runner-two", Role: RoleAgent, Scope: Scope{WorkspaceID: "w", Repository: "r", AgentID: "a2"}},
	}
	tokens := make([]string, len(principals))
	errorsByIndex := make([]error, len(principals))
	started := make(chan struct{}, len(principals))
	var wait sync.WaitGroup
	for index, principal := range principals {
		wait.Add(1)
		go func() {
			defer wait.Done()
			started <- struct{}{}
			tokens[index], errorsByIndex[index] = IssueOrUpdateToken(path, principal)
		}()
	}
	for range principals {
		<-started
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	wait.Wait()

	registry, err := LoadRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	for index, token := range tokens {
		if errorsByIndex[index] != nil {
			t.Fatalf("issue %d: %v", index, errorsByIndex[index])
		}
		if got, err := registry.Authenticate(token); err != nil || got != principals[index] {
			t.Fatalf("credential %d principal = %#v, err = %v", index, got, err)
		}
	}
}
