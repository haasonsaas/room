package server

import (
	"embed"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"connectrpc.com/connect"
	"connectrpc.com/grpcreflect"
	roomv1 "github.com/haasonsaas/room/gen/go/room/v1"
	"github.com/haasonsaas/room/gen/go/room/v1/roomv1connect"
	"github.com/haasonsaas/room/internal/app"
	"github.com/haasonsaas/room/internal/auth"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

//go:embed static/index.html
var webFS embed.FS

type options struct {
	authenticator auth.Authenticator
	localAuth     bool
	maxBodyBytes  int64
}

type Option func(*options)

func WithRegistry(registry *auth.Registry) Option { return WithAuthenticator(registry) }
func WithAuthenticator(authenticator auth.Authenticator) Option {
	return func(o *options) { o.authenticator = authenticator }
}
func WithLocalAuth() Option               { return func(o *options) { o.localAuth = true } }
func WithMaxBodyBytes(value int64) Option { return func(o *options) { o.maxBodyBytes = value } }

func New(service *app.Service, optionValues ...Option) http.Handler {
	settings := options{maxBodyBytes: 4 << 20}
	for _, option := range optionValues {
		option(&settings)
	}
	dashboard, dashboardErr := webFS.ReadFile("static/index.html")
	mux := http.NewServeMux()
	readLimit := connect.WithReadMaxBytes(int(settings.maxBodyBytes))
	adminPath, adminHandler := roomv1connect.NewRuleAdminServiceHandler(service.Admin(), readLimit)
	agentPath, agentHandler := roomv1connect.NewAgentRulesServiceHandler(service.Agent(), readLimit)
	mux.Handle(adminPath, protectedRolesHandler(settings, []auth.Role{auth.RoleAdmin, auth.RoleReviewer}, adminHandler))
	mux.Handle(agentPath, protectedHandler(settings, auth.RoleAgent, agentHandler))
	reflector := grpcreflect.NewStaticReflector(roomv1connect.RuleAdminServiceName, roomv1connect.AgentRulesServiceName)
	reflectionPath, reflectionHandler := grpcreflect.NewHandlerV1(reflector)
	reflectionAlphaPath, reflectionAlphaHandler := grpcreflect.NewHandlerV1Alpha(reflector)
	mux.Handle(reflectionPath, protectedHandler(settings, auth.RoleAdmin, reflectionHandler))
	mux.Handle(reflectionAlphaPath, protectedHandler(settings, auth.RoleAdmin, reflectionAlphaHandler))

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if dashboardErr != nil {
			http.Error(w, "dashboard unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(dashboard)
	})
	mux.Handle("/api/rules", protectedHandler(settings, auth.RoleAdmin, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			resp, err := service.ListRules(r.Context(), connect.NewRequest(&roomv1.ListRulesRequest{IncludeDisabled: true}))
			writeProtoJSON(w, message(resp), err)
		case http.MethodPost:
			var msg roomv1.CreateRuleRequest
			if err := readProtoJSON(w, r, &msg, settings.maxBodyBytes); err != nil {
				writeError(w, err)
				return
			}
			resp, err := service.CreateRule(r.Context(), connect.NewRequest(&msg))
			writeProtoJSON(w, message(resp), err)
		case http.MethodPut:
			var msg roomv1.UpdateRuleRequest
			if err := readProtoJSON(w, r, &msg, settings.maxBodyBytes); err != nil {
				writeError(w, err)
				return
			}
			resp, err := service.UpdateRule(r.Context(), connect.NewRequest(&msg))
			writeProtoJSON(w, message(resp), err)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})))
	mux.Handle("/api/rules/", protectedHandler(settings, auth.RoleAdmin, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ruleID := strings.TrimPrefix(r.URL.Path, "/api/rules/")
		if ruleID == "" {
			http.Error(w, "rule id is required", http.StatusBadRequest)
			return
		}
		resp, err := service.DeleteRule(r.Context(), connect.NewRequest(&roomv1.DeleteRuleRequest{RuleId: ruleID}))
		writeProtoJSON(w, message(resp), err)
	})))
	mux.Handle("/api/publish", protectedHandler(settings, auth.RoleAdmin, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		resp, err := service.PublishRuleset(r.Context(), connect.NewRequest(&roomv1.PublishRulesetRequest{Author: "dashboard", Notes: "Published from Room dashboard"}))
		writeProtoJSON(w, message(resp), err)
	})))
	mux.Handle("/api/evaluate", protectedHandler(settings, auth.RoleAgent, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			Phase roomv1.AnalysisPhase `json:"phase"`
			Plan  string               `json:"plan"`
			Diff  string               `json:"diff"`
		}
		if err := readJSON(w, r, &body, settings.maxBodyBytes); err != nil {
			writeError(w, err)
			return
		}
		request := &roomv1.EvaluationInput{Phase: body.Phase, Plan: body.Plan, Diff: body.Diff}
		switch body.Phase {
		case roomv1.AnalysisPhase_ANALYSIS_PHASE_DIFF:
			resp, err := service.EvaluateDiff(r.Context(), connect.NewRequest(&roomv1.EvaluateDiffRequest{Input: request}))
			writeProtoJSON(w, message(resp), err)
		case roomv1.AnalysisPhase_ANALYSIS_PHASE_PLAN:
			resp, err := service.EvaluatePlan(r.Context(), connect.NewRequest(&roomv1.EvaluatePlanRequest{Input: request}))
			writeProtoJSON(w, message(resp), err)
		default:
			writeError(w, connect.NewError(connect.CodeInvalidArgument, errors.New("evaluation phase must be plan or diff")))
		}
	})))
	mux.Handle("/api/mcp-policy", protectedHandler(settings, auth.RoleAdmin, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			resp, err := service.GetMcpPolicy(r.Context(), connect.NewRequest(&roomv1.GetMcpPolicyRequest{}))
			writeProtoJSON(w, message(resp), err)
		case http.MethodPut:
			var msg roomv1.UpdateMcpPolicyRequest
			if err := readProtoJSON(w, r, &msg, settings.maxBodyBytes); err != nil {
				writeError(w, err)
				return
			}
			resp, err := service.UpdateMcpPolicy(r.Context(), connect.NewRequest(&msg))
			writeProtoJSON(w, message(resp), err)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})))
	mux.Handle("/api/audit", protectedHandler(settings, auth.RoleAdmin, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		resp, err := service.ListAuditEvents(r.Context(), connect.NewRequest(&roomv1.ListAuditEventsRequest{Limit: 100}))
		writeProtoJSON(w, message(resp), err)
	})))
	mux.Handle("/api/review-findings", protectedRolesHandler(settings, []auth.Role{auth.RoleAdmin, auth.RoleReviewer}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			claimKind := roomv1.ReviewClaimKind_REVIEW_CLAIM_KIND_UNSPECIFIED
			if raw := r.URL.Query().Get("claim_kind"); raw != "" {
				if value, ok := roomv1.ReviewClaimKind_value[raw]; ok {
					claimKind = roomv1.ReviewClaimKind(value)
				} else {
					writeError(w, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid claim_kind")))
					return
				}
			}
			resp, err := service.ListReviewFindings(r.Context(), connect.NewRequest(&roomv1.ListReviewFindingsRequest{Repository: r.URL.Query().Get("repository"), ClaimKind: claimKind, Limit: 500}))
			writeProtoJSON(w, message(resp), err)
		case http.MethodPost:
			var msg roomv1.IngestReviewFindingRequest
			if err := readProtoJSON(w, r, &msg, settings.maxBodyBytes); err != nil {
				writeError(w, err)
				return
			}
			resp, err := service.IngestReviewFinding(r.Context(), connect.NewRequest(&msg))
			writeProtoJSON(w, message(resp), err)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})))
	mux.Handle("/api/review-findings/", protectedRolesHandler(settings, []auth.Role{auth.RoleAdmin, auth.RoleReviewer}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/review-findings/"), "/"), "/")
		if r.Method != http.MethodPost || len(parts) != 2 || parts[0] == "" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		switch parts[1] {
		case "outcomes":
			var msg roomv1.RecordReviewOutcomeRequest
			if err := readProtoJSON(w, r, &msg, settings.maxBodyBytes); err != nil {
				writeError(w, err)
				return
			}
			msg.FindingId = parts[0]
			resp, err := service.RecordReviewOutcome(r.Context(), connect.NewRequest(&msg))
			writeProtoJSON(w, message(resp), err)
		case "adjudications":
			var msg roomv1.AdjudicateReviewFindingRequest
			if err := readProtoJSON(w, r, &msg, settings.maxBodyBytes); err != nil {
				writeError(w, err)
				return
			}
			msg.FindingId = parts[0]
			resp, err := service.AdjudicateReviewFinding(r.Context(), connect.NewRequest(&msg))
			writeProtoJSON(w, message(resp), err)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	})))
	mux.Handle("/api/policy-infer", protectedRolesHandler(settings, []auth.Role{auth.RoleAdmin, auth.RoleReviewer}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var msg roomv1.InferPolicyCandidatesRequest
		if err := readProtoJSON(w, r, &msg, settings.maxBodyBytes); err != nil {
			writeError(w, err)
			return
		}
		resp, err := service.InferPolicyCandidates(r.Context(), connect.NewRequest(&msg))
		writeProtoJSON(w, message(resp), err)
	})))
	mux.Handle("/api/policy-candidates", protectedRolesHandler(settings, []auth.Role{auth.RoleAdmin, auth.RoleReviewer}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		resp, err := service.ListPolicyCandidates(r.Context(), connect.NewRequest(&roomv1.ListPolicyCandidatesRequest{}))
		writeProtoJSON(w, message(resp), err)
	})))
	mux.Handle("/api/policy-candidates/", protectedRolesHandler(settings, []auth.Role{auth.RoleAdmin, auth.RoleReviewer}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/policy-candidates/"), "/"), "/")
		if r.Method != http.MethodPost || len(parts) != 2 || parts[0] == "" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		switch parts[1] {
		case "replay":
			resp, err := service.RunPolicyReplay(r.Context(), connect.NewRequest(&roomv1.RunPolicyReplayRequest{PolicyCandidateId: parts[0]}))
			writeProtoJSON(w, message(resp), err)
		case "tune":
			var msg roomv1.TunePolicyCandidateRequest
			if err := readProtoJSON(w, r, &msg, settings.maxBodyBytes); err != nil {
				writeError(w, err)
				return
			}
			msg.PolicyCandidateId = parts[0]
			resp, err := service.TunePolicyCandidate(r.Context(), connect.NewRequest(&msg))
			writeProtoJSON(w, message(resp), err)
		case "transition":
			var msg roomv1.TransitionPolicyCandidateRequest
			if err := readProtoJSON(w, r, &msg, settings.maxBodyBytes); err != nil {
				writeError(w, err)
				return
			}
			msg.PolicyCandidateId = parts[0]
			resp, err := service.TransitionPolicyCandidate(r.Context(), connect.NewRequest(&msg))
			writeProtoJSON(w, message(resp), err)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	})))
	return securityHeaders(mux)
}

func protectedHandler(settings options, role auth.Role, next http.Handler) http.Handler {
	roleRequired := auth.RequireRole(role)(next)
	if settings.authenticator != nil {
		return auth.Middleware(settings.authenticator, roleRequired)
	}
	if settings.localAuth {
		return localPrincipalMiddleware(role, roleRequired)
	}
	return rejectProtectedHandler()
}

func protectedRolesHandler(settings options, roles []auth.Role, next http.Handler) http.Handler {
	rolesRequired := auth.RequireAnyRole(roles...)(next)
	if settings.authenticator != nil {
		return auth.Middleware(settings.authenticator, rolesRequired)
	}
	if settings.localAuth {
		return localPrincipalMiddleware(auth.RoleAdmin, rolesRequired)
	}
	return rejectProtectedHandler()
}

func localPrincipalMiddleware(role auth.Role, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal := auth.Principal{ID: "local-admin", Role: role, HumanOperator: true}
		if role == auth.RoleAgent {
			principal = auth.Principal{ID: "local-agent", Role: auth.RoleAgent, Scope: auth.Scope{WorkspaceID: "local", Repository: "local", AgentID: "local-agent"}}
		}
		next.ServeHTTP(w, r.WithContext(auth.WithPrincipal(r.Context(), principal)))
	})
}

func rejectProtectedHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="room"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'")
		next.ServeHTTP(w, r)
	})
}

func message[T any](response *connect.Response[T]) *T {
	if response == nil {
		return nil
	}
	return response.Msg
}

func writeProtoJSON(w http.ResponseWriter, value proto.Message, err error) {
	if err != nil {
		writeError(w, err)
		return
	}
	if value == nil {
		http.Error(w, "empty response", http.StatusInternalServerError)
		return
	}
	data, marshalErr := protojson.MarshalOptions{UseProtoNames: false, UseEnumNumbers: true}.Marshal(value)
	if marshalErr != nil {
		http.Error(w, "encode response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
}

func writeError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	var connectErr *connect.Error
	if errors.As(err, &connectErr) {
		switch connectErr.Code() {
		case connect.CodeUnauthenticated:
			status = http.StatusUnauthorized
		case connect.CodePermissionDenied:
			status = http.StatusForbidden
		case connect.CodeInvalidArgument:
			status = http.StatusBadRequest
		case connect.CodeNotFound:
			status = http.StatusNotFound
		case connect.CodeFailedPrecondition:
			status = http.StatusPreconditionFailed
		case connect.CodeAborted:
			status = http.StatusConflict
		}
	}
	if errors.Is(err, errBodyTooLarge) {
		status = http.StatusRequestEntityTooLarge
	}
	http.Error(w, http.StatusText(status), status)
}

var errBodyTooLarge = errors.New("request body too large")

func readProtoJSON(w http.ResponseWriter, r *http.Request, value proto.Message, limit int64) error {
	defer r.Body.Close()
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	data, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return errBodyTooLarge
		}
		return connect.NewError(connect.CodeInvalidArgument, err)
	}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(data, value); err != nil {
		return connect.NewError(connect.CodeInvalidArgument, err)
	}
	return nil
}

func readJSON(w http.ResponseWriter, r *http.Request, value any, limit int64) error {
	defer r.Body.Close()
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return errBodyTooLarge
		}
		return connect.NewError(connect.CodeInvalidArgument, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("trailing JSON"))
	}
	return nil
}
