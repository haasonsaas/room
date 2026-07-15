// Package auth authenticates Room callers using scoped, opaque bearer tokens.
package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
)

// ErrUnauthenticated intentionally provides no detail about credential failures.
var ErrUnauthenticated = errors.New("unauthenticated")

// TokenCredentialID returns the non-secret credential identifier embedded in a
// syntactically valid Room token. It does not authenticate the token.
func TokenCredentialID(token string) (string, bool) {
	id, secret, ok := parseToken(strings.TrimSpace(token))
	clear(secret)
	return id, ok
}

// Role identifies the authority granted to a credential.
type Role string

const (
	RoleAdmin    Role = "admin"
	RoleAgent    Role = "agent"
	RoleReviewer Role = "reviewer"
)

type HookProvider string

const (
	HookProviderNone       HookProvider = "none"
	HookProviderClaudeCode HookProvider = "claude_code"
	HookProviderCodex      HookProvider = "codex"
	HookProviderCursor     HookProvider = "cursor"
)

// Scope binds an agent credential to exactly one execution identity.
type Scope struct {
	WorkspaceID  string       `json:"workspace_id,omitempty"`
	Repository   string       `json:"repository,omitempty"`
	AgentID      string       `json:"agent_id,omitempty"`
	HookProvider HookProvider `json:"hook_provider,omitempty"`
	MCPProxy     bool         `json:"mcp_proxy,omitempty"`
}

// Principal is the typed identity established by successful authentication.
type Principal struct {
	ID            string
	Role          Role
	Scope         Scope
	HumanOperator bool
	// LocalAuth is trusted server metadata set only by the loopback-only,
	// authentication-disabled middleware. It is never populated from a token.
	LocalAuth bool
}

type principalContextKey struct{}

// Authenticator validates an opaque token and returns its typed principal.
type Authenticator interface {
	Authenticate(string) (Principal, error)
}

// WithPrincipal returns a context carrying an authenticated principal.
func WithPrincipal(ctx context.Context, principal Principal) context.Context {
	return context.WithValue(ctx, principalContextKey{}, principal)
}

// PrincipalFromContext retrieves an authenticated principal.
func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(principalContextKey{}).(Principal)
	return principal, ok
}

// ExtractBearer returns a bearer token without logging or reflecting it.
func ExtractBearer(r *http.Request) (string, error) {
	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", ErrUnauthenticated
	}
	return parts[1], nil
}

// Middleware authenticates requests and adds their principal to the context.
func Middleware(authenticator Authenticator, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		token, err := ExtractBearer(request)
		if err != nil || authenticator == nil {
			writeUnauthorized(w)
			return
		}
		principal, err := authenticator.Authenticate(token)
		if err != nil {
			writeUnauthorized(w)
			return
		}
		next.ServeHTTP(w, request.WithContext(WithPrincipal(request.Context(), principal)))
	})
}

// Middleware authenticates a request against this registry.
func (r *Registry) Middleware(next http.Handler) http.Handler { return Middleware(r, next) }

// RequireRole permits only a principal with the requested role.
func RequireRole(role Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal, ok := PrincipalFromContext(r.Context())
			if !ok {
				writeUnauthorized(w)
				return
			}
			if subtle.ConstantTimeCompare([]byte(principal.Role), []byte(role)) != 1 {
				writeForbidden(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAnyRole permits a principal with one of the explicitly listed roles.
func RequireAnyRole(roles ...Role) func(http.Handler) http.Handler {
	allowed := append([]Role(nil), roles...)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal, ok := PrincipalFromContext(r.Context())
			if !ok {
				writeUnauthorized(w)
				return
			}
			for _, role := range allowed {
				if subtle.ConstantTimeCompare([]byte(principal.Role), []byte(role)) == 1 {
					next.ServeHTTP(w, r)
					return
				}
			}
			writeForbidden(w)
		})
	}
}

// RequireAgentScope permits only an agent token with an exact scope match.
func RequireAgentScope(scope Scope) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal, ok := PrincipalFromContext(r.Context())
			if !ok {
				writeUnauthorized(w)
				return
			}
			if principal.Role != RoleAgent || principal.Scope != scope {
				writeForbidden(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="room"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

func writeForbidden(w http.ResponseWriter) {
	http.Error(w, "forbidden", http.StatusForbidden)
}
