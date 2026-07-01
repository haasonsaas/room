package server

import (
	"embed"
	"encoding/json"
	"net/http"

	"connectrpc.com/connect"
	"connectrpc.com/grpcreflect"
	roomv1 "github.com/haasonsaas/room/gen/go/room/v1"
	"github.com/haasonsaas/room/gen/go/room/v1/roomv1connect"
	"github.com/haasonsaas/room/internal/app"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

//go:embed static/index.html
var webFS embed.FS

func New(service *app.Service) http.Handler {
	mux := http.NewServeMux()
	opts := []connect.HandlerOption{}

	adminPath, adminHandler := roomv1connect.NewRuleAdminServiceHandler(service.Admin(), opts...)
	agentPath, agentHandler := roomv1connect.NewAgentRulesServiceHandler(service.Agent(), opts...)
	mux.Handle(adminPath, adminHandler)
	mux.Handle(agentPath, agentHandler)

	reflector := grpcreflect.NewStaticReflector(
		roomv1connect.RuleAdminServiceName,
		roomv1connect.AgentRulesServiceName,
	)
	mux.Handle(grpcreflect.NewHandlerV1(reflector))
	mux.Handle(grpcreflect.NewHandlerV1Alpha(reflector))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		data, err := webFS.ReadFile("static/index.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(data)
	})

	mux.HandleFunc("/api/rules", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		resp, err := service.ListRules(r.Context(), connect.NewRequest(&roomv1.ListRulesRequest{IncludeDisabled: true}))
		writeProtoJSON(w, resp.Msg, err)
	})

	mux.HandleFunc("/api/publish", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		resp, err := service.PublishRuleset(r.Context(), connect.NewRequest(&roomv1.PublishRulesetRequest{Author: "dashboard", Notes: "Published from Room dashboard"}))
		writeProtoJSON(w, resp.Msg, err)
	})

	mux.HandleFunc("/api/evaluate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			Plan string `json:"plan"`
			Diff string `json:"diff"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp, err := service.EvaluatePlan(r.Context(), connect.NewRequest(&roomv1.EvaluatePlanRequest{
			Input: &roomv1.EvaluationInput{Plan: body.Plan, Diff: body.Diff},
		}))
		writeProtoJSON(w, resp.Msg, err)
	})

	return mux
}

func writeJSON(w http.ResponseWriter, value any, err error) {
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func writeProtoJSON(w http.ResponseWriter, value proto.Message, err error) {
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data, err := protojson.MarshalOptions{UseProtoNames: false, UseEnumNumbers: true}.Marshal(value)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
}
