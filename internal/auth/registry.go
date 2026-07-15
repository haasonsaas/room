package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

const registryVersion = 1

var credentialIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,127}$`)

type registryFile struct {
	Version             int                         `json:"version"`
	Credentials         []credentialFile            `json:"credentials"`
	CredentialMutations []CredentialMutationReceipt `json:"credential_mutations,omitempty"`
}

// CredentialMutationReceipt is persisted in the same atomic replacement as
// the credential mutation it records.
type CredentialMutationReceipt struct {
	ID           string    `json:"id"`
	ActorID      string    `json:"actor_id"`
	CredentialID string    `json:"credential_id"`
	Action       string    `json:"action"`
	OccurredAt   time.Time `json:"occurred_at"`
	OldScope     Scope     `json:"old_scope"`
	NewScope     Scope     `json:"new_scope"`
}

type credentialFile struct {
	ID            string `json:"id"`
	Role          Role   `json:"role"`
	TokenSHA256   string `json:"token_sha256"`
	HumanOperator bool   `json:"human_operator,omitempty"`
	Scope
}

type credential struct {
	principal Principal
	idDigest  [sha256.Size]byte
	digest    [sha256.Size]byte
}

// Registry is an immutable, validated in-memory credential registry.
type Registry struct {
	credentials []credential
	mutations   []CredentialMutationReceipt
}

// FileAuthenticator reloads a validated registry before every authentication.
// A failed reload retains the last known-good registry.
type FileAuthenticator struct {
	path    string
	current atomic.Pointer[Registry]
}

// NewFileAuthenticator requires a valid initial registry before serving traffic.
func NewFileAuthenticator(path string) (*FileAuthenticator, error) {
	registry, err := LoadRegistry(path)
	if err != nil {
		return nil, err
	}
	authenticator := &FileAuthenticator{path: path}
	authenticator.current.Store(registry)
	return authenticator, nil
}

// Authenticate reloads a complete valid registry and otherwise uses the last known-good one.
func (a *FileAuthenticator) Authenticate(token string) (Principal, error) {
	if a == nil {
		return Principal{}, ErrUnauthenticated
	}
	if registry, err := LoadRegistry(a.path); err == nil {
		a.current.Store(registry)
	}
	registry := a.current.Load()
	if registry == nil {
		return Principal{}, ErrUnauthenticated
	}
	return registry.Authenticate(token)
}

// Middleware authenticates a request against the reloadable registry.
func (a *FileAuthenticator) Middleware(next http.Handler) http.Handler { return Middleware(a, next) }

// LoadRegistry reads and validates a registry that is not group/world accessible.
func LoadRegistry(path string) (*Registry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open credential registry: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat credential registry: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("credential registry must be a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("credential registry must not be accessible by group or others")
	}
	return decodeRegistry(file)
}

func decodeRegistry(reader io.Reader) (*Registry, error) {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	var stored registryFile
	if err := decoder.Decode(&stored); err != nil {
		return nil, fmt.Errorf("decode credential registry: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, err
	}
	if stored.Version != registryVersion {
		return nil, fmt.Errorf("unsupported credential registry version %d", stored.Version)
	}
	registry := &Registry{credentials: make([]credential, 0, len(stored.Credentials)), mutations: append([]CredentialMutationReceipt(nil), stored.CredentialMutations...)}
	seen := make(map[string]struct{}, len(stored.Credentials))
	for index, item := range stored.Credentials {
		if _, exists := seen[item.ID]; exists {
			return nil, fmt.Errorf("credential %d duplicates id %q", index, item.ID)
		}
		seen[item.ID] = struct{}{}
		principal := Principal{ID: item.ID, Role: item.Role, Scope: item.Scope, HumanOperator: item.HumanOperator}
		if err := validatePrincipal(principal); err != nil {
			return nil, fmt.Errorf("credential %d: %w", index, err)
		}
		digestBytes, err := hex.DecodeString(item.TokenSHA256)
		if err != nil || len(digestBytes) != sha256.Size {
			return nil, fmt.Errorf("credential %d has invalid SHA-256 digest", index)
		}
		var digest [sha256.Size]byte
		copy(digest[:], digestBytes)
		registry.credentials = append(registry.credentials, credential{
			principal: principal,
			idDigest:  sha256.Sum256([]byte(principal.ID)),
			digest:    digest,
		})
	}
	return registry, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("credential registry contains trailing JSON")
		}
		return fmt.Errorf("decode credential registry: %w", err)
	}
	return nil
}

// Authenticate validates an opaque token and returns its typed principal.
func (r *Registry) Authenticate(token string) (Principal, error) {
	id, secret, ok := parseToken(token)
	if !ok || r == nil {
		return Principal{}, ErrUnauthenticated
	}
	providedDigest := sha256.Sum256([]byte(token))
	providedID := sha256.Sum256([]byte(id))
	var matched int
	var principal Principal
	for _, candidate := range r.credentials {
		idMatch := subtle.ConstantTimeCompare(providedID[:], candidate.idDigest[:])
		digestMatch := subtle.ConstantTimeCompare(providedDigest[:], candidate.digest[:])
		if idMatch&digestMatch == 1 {
			matched = 1
			principal = candidate.principal
		}
	}
	clear(secret)
	if matched != 1 {
		return Principal{}, ErrUnauthenticated
	}
	return principal, nil
}

func parseToken(token string) (string, []byte, bool) {
	remainder, ok := strings.CutPrefix(token, "room_")
	if !ok {
		return "", nil, false
	}
	id, encodedSecret, ok := strings.Cut(remainder, "_")
	if !ok || id == "" {
		return "", nil, false
	}
	if !credentialIDPattern.MatchString(id) || encodedSecret == "" {
		return "", nil, false
	}
	secret, err := base64.RawURLEncoding.DecodeString(encodedSecret)
	if err != nil || len(secret) != 32 {
		clear(secret)
		return "", nil, false
	}
	return id, secret, true
}

// IssueOrUpdateToken bootstraps a new credential. Existing IDs must use an
// authenticated, audited rotation workflow.
// The returned plaintext token is never persisted and should be displayed only once.
func IssueOrUpdateToken(path string, principal Principal) (string, error) {
	if err := validatePrincipal(principal); err != nil {
		return "", err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	token := "room_" + principal.ID + "_" + base64.RawURLEncoding.EncodeToString(secret)
	clear(secret)
	digest := sha256.Sum256([]byte(token))
	lock, err := lockRegistry(path)
	if err != nil {
		return "", err
	}
	defer unlockRegistry(lock)

	stored := registryFile{Version: registryVersion, Credentials: []credentialFile{}}
	registry, err := LoadRegistry(path)
	if err == nil {
		stored.CredentialMutations = append([]CredentialMutationReceipt(nil), registry.mutations...)
		stored.Credentials = make([]credentialFile, 0, len(registry.credentials)+1)
		for _, existing := range registry.credentials {
			if existing.principal.ID == principal.ID {
				return "", errors.New("credential already exists; use an authenticated audited rotation workflow")
			}
			stored.Credentials = append(stored.Credentials, credentialFile{
				ID: existing.principal.ID, Role: existing.principal.Role,
				TokenSHA256: hex.EncodeToString(existing.digest[:]), Scope: existing.principal.Scope, HumanOperator: existing.principal.HumanOperator,
			})
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	stored.Credentials = append(stored.Credentials, credentialFile{
		ID: principal.ID, Role: principal.Role, TokenSHA256: hex.EncodeToString(digest[:]), Scope: principal.Scope, HumanOperator: principal.HumanOperator,
	})
	sort.Slice(stored.Credentials, func(i, j int) bool { return stored.Credentials[i].ID < stored.Credentials[j].ID })
	if err := writeRegistryAtomic(path, stored); err != nil {
		return "", err
	}
	return token, nil
}

// RotateAgentScope replaces an existing agent token and records the human
// approval and exact scope change in the same durable registry write.
func RotateAgentScope(path string, actor Principal, credentialID string, newScope Scope, confirmation string) (string, CredentialMutationReceipt, error) {
	if actor.Role != RoleAdmin || !actor.HumanOperator || actor.LocalAuth {
		return "", CredentialMutationReceipt{}, errors.New("authenticated human-operator credential required")
	}
	if confirmation != "APPROVE" {
		return "", CredentialMutationReceipt{}, errors.New("explicit APPROVE confirmation required")
	}
	if strings.ContainsAny(newScope.WorkspaceID+newScope.Repository+newScope.AgentID, "*?[") {
		return "", CredentialMutationReceipt{}, errors.New("credential scope must identify one exact workspace, repository, and agent")
	}
	lock, err := lockRegistry(path)
	if err != nil {
		return "", CredentialMutationReceipt{}, err
	}
	defer unlockRegistry(lock)
	registry, err := LoadRegistry(path)
	if err != nil {
		return "", CredentialMutationReceipt{}, err
	}
	var subject Principal
	for _, existing := range registry.credentials {
		if existing.principal.ID == credentialID {
			subject = existing.principal
			break
		}
	}
	if subject.ID == "" || subject.Role != RoleAgent {
		return "", CredentialMutationReceipt{}, errors.New("existing agent credential required")
	}
	newScope.HookProvider = subject.Scope.HookProvider
	newScope.MCPProxy = subject.Scope.MCPProxy
	updated := subject
	updated.Scope = newScope
	if err := validatePrincipal(updated); err != nil {
		return "", CredentialMutationReceipt{}, err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", CredentialMutationReceipt{}, fmt.Errorf("generate token: %w", err)
	}
	token := "room_" + updated.ID + "_" + base64.RawURLEncoding.EncodeToString(secret)
	clear(secret)
	digest := sha256.Sum256([]byte(token))
	receiptBytes := make([]byte, 16)
	if _, err := rand.Read(receiptBytes); err != nil {
		return "", CredentialMutationReceipt{}, fmt.Errorf("generate receipt id: %w", err)
	}
	receipt := CredentialMutationReceipt{ID: hex.EncodeToString(receiptBytes), ActorID: actor.ID, CredentialID: updated.ID, Action: "rotate_agent_scope", OccurredAt: time.Now().UTC(), OldScope: subject.Scope, NewScope: updated.Scope}
	stored := registryFile{Version: registryVersion, Credentials: make([]credentialFile, 0, len(registry.credentials)), CredentialMutations: append(append([]CredentialMutationReceipt(nil), registry.mutations...), receipt)}
	for _, existing := range registry.credentials {
		principal := existing.principal
		tokenDigest := existing.digest
		if principal.ID == updated.ID {
			principal = updated
			tokenDigest = digest
		}
		stored.Credentials = append(stored.Credentials, credentialFile{ID: principal.ID, Role: principal.Role, TokenSHA256: hex.EncodeToString(tokenDigest[:]), Scope: principal.Scope, HumanOperator: principal.HumanOperator})
	}
	if err := writeRegistryAtomic(path, stored); err != nil {
		return "", CredentialMutationReceipt{}, err
	}
	return token, receipt, nil
}

// CredentialMutationReceipts returns a copy of the registry's durable receipts.
func (r *Registry) CredentialMutationReceipts() []CredentialMutationReceipt {
	if r == nil {
		return nil
	}
	return append([]CredentialMutationReceipt(nil), r.mutations...)
}

// RotateAgentScope applies the audited scope rotation to a reloadable registry.
func (a *FileAuthenticator) RotateAgentScope(actor Principal, credentialID string, scope Scope, confirmation string) (string, CredentialMutationReceipt, error) {
	return RotateAgentScope(a.path, actor, credentialID, scope, confirmation)
}

func validatePrincipal(principal Principal) error {
	if !credentialIDPattern.MatchString(principal.ID) {
		return errors.New("credential id must use letters, digits, dots, or hyphens")
	}
	switch principal.Role {
	case RoleAdmin:
		if principal.Scope != (Scope{}) {
			return errors.New("admin credential must not have agent scope")
		}
	case RoleAgent:
		if principal.HumanOperator {
			return errors.New("agent credential cannot be a human operator")
		}
		if principal.Scope.WorkspaceID == "" || principal.Scope.Repository == "" || principal.Scope.AgentID == "" {
			return errors.New("agent credential requires exact workspace, repository, and agent scope")
		}
		switch principal.Scope.HookProvider {
		case "", HookProviderNone, HookProviderClaudeCode, HookProviderCodex, HookProviderCursor:
		default:
			return errors.New("agent credential has invalid hook provider")
		}
		if principal.Scope.MCPProxy && principal.Scope.HookProvider != "" && principal.Scope.HookProvider != HookProviderNone {
			return errors.New("MCP proxy credential cannot also bind a hook provider")
		}
	case RoleReviewer:
		if principal.Scope != (Scope{}) || principal.HumanOperator {
			return errors.New("reviewer credential cannot have agent scope or human-operator authority")
		}
	default:
		return fmt.Errorf("unsupported credential role %q", principal.Role)
	}
	return nil
}

func registryLockPath(path string) string { return path + ".lock" }

func lockRegistry(path string) (*os.File, error) {
	lock, err := os.OpenFile(registryLockPath(path), os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open credential registry lock: %w", err)
	}
	if err := lock.Chmod(0o600); err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("secure credential registry lock: %w", err)
	}
	info, err := lock.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = lock.Close()
		if err != nil {
			return nil, fmt.Errorf("stat credential registry lock: %w", err)
		}
		return nil, errors.New("credential registry lock must be a regular file")
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("lock credential registry: %w", err)
	}
	return lock, nil
}

func unlockRegistry(lock *os.File) {
	_ = unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	_ = lock.Close()
}

func writeRegistryAtomic(path string, stored registryFile) (returnErr error) {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".room-credentials-*")
	if err != nil {
		return fmt.Errorf("create temporary credential registry: %w", err)
	}
	temporaryName := temporary.Name()
	defer func() {
		_ = temporary.Close()
		if returnErr != nil {
			_ = os.Remove(temporaryName)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("secure temporary credential registry: %w", err)
	}
	encoder := json.NewEncoder(temporary)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(stored); err != nil {
		return fmt.Errorf("encode credential registry: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync credential registry: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close credential registry: %w", err)
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return fmt.Errorf("replace credential registry: %w", err)
	}
	dir, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open credential registry directory: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync credential registry directory: %w", err)
	}
	return nil
}
