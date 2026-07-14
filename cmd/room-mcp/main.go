package main

import (
	"log"
	"net/http"

	"github.com/haasonsaas/room/internal/auth"
	"github.com/haasonsaas/room/internal/config"
	roommcp "github.com/haasonsaas/room/internal/mcp"
)

func main() {
	cfg := config.Load()
	if err := cfg.ValidateServerAt(cfg.MCPAddr); err != nil {
		log.Fatalf("invalid configuration: %v", err)
	}
	if err := cfg.ValidateClient(); err != nil {
		log.Fatalf("invalid upstream configuration: %v", err)
	}
	if err := cfg.ValidateMCPServer(); err != nil {
		log.Fatalf("invalid MCP deadline configuration: %v", err)
	}
	mux := http.NewServeMux()
	var handler http.Handler
	if cfg.AuthDisabled {
		handler = roommcp.NewHandlerWithTimeout(cfg.ServerURL, cfg.ClientTimeout)
	} else {
		authenticator, loadErr := auth.NewFileAuthenticator(cfg.CredentialFile)
		if loadErr != nil {
			log.Fatalf("load credential authenticator: %v", loadErr)
		}
		handler = roommcp.NewAuthenticatedHandlerWithTimeout(cfg.ServerURL, authenticator, cfg.ClientTimeout)
	}
	mux.Handle("/mcp", handler)
	httpServer := &http.Server{Addr: cfg.MCPAddr, Handler: mux, ReadTimeout: cfg.ReadTimeout, WriteTimeout: cfg.WriteTimeout, IdleTimeout: cfg.IdleTimeout}
	log.Printf("room-mcp listening on %s and forwarding to %s", cfg.MCPAddr, cfg.ServerURL)
	if cfg.TLSCertFile != "" {
		err := httpServer.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		err := httpServer.ListenAndServe()
		if err != nil {
			log.Fatal(err)
		}
	}
}
