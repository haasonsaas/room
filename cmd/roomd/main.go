package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	roomv1 "github.com/haasonsaas/room/gen/go/room/v1"
	"github.com/haasonsaas/room/internal/analyzer"
	"github.com/haasonsaas/room/internal/app"
	"github.com/haasonsaas/room/internal/auth"
	"github.com/haasonsaas/room/internal/config"
	"github.com/haasonsaas/room/internal/server"
	"github.com/haasonsaas/room/internal/store"
)

func main() {
	cfg := config.Load()
	if err := cfg.ValidateServer(); err != nil {
		log.Fatalf("invalid configuration: %v", err)
	}
	if err := cfg.ValidateAnalyzer(); err != nil {
		log.Fatalf("invalid analyzer configuration: %v", err)
	}
	if err := cfg.ValidateDaemon(); err != nil {
		log.Fatalf("invalid daemon configuration: %v", err)
	}
	ruleStore, err := store.Open(cfg.DataFile)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer ruleStore.Close()
	appOptions := []app.Option{app.WithAuditOnly(cfg.AuditOnly)}
	if cfg.AnalyzerExecutable != "" {
		coveredSignals, parseErr := parseSignals(cfg.AnalyzerSignals)
		if parseErr != nil {
			log.Fatalf("configure analyzer coverage: %v", parseErr)
		}
		var analyzerConfig []byte
		if cfg.AnalyzerConfigFile != "" {
			analyzerConfig, err = os.ReadFile(cfg.AnalyzerConfigFile)
			if err != nil {
				log.Fatalf("read analyzer config: %v", err)
			}
		}
		provider, buildErr := analyzer.NewExternal(analyzer.Config{
			ID: cfg.AnalyzerID, Version: cfg.AnalyzerVersion, Executable: cfg.AnalyzerExecutable,
			Args: cfg.AnalyzerArgs, Config: analyzerConfig, CoveredSignals: coveredSignals, Timeout: cfg.AnalyzerTimeout,
		})
		if buildErr != nil {
			log.Fatalf("configure analyzer: %v", buildErr)
		}
		appOptions = append(appOptions, app.WithAnalyzer(provider))
	}
	svc := app.New(ruleStore, appOptions...)
	serverOptions := []server.Option{server.WithMaxBodyBytes(cfg.MaxBodyBytes)}
	if cfg.AuthDisabled {
		serverOptions = append(serverOptions, server.WithLocalAuth())
	} else {
		authenticator, loadErr := auth.NewFileAuthenticator(cfg.CredentialFile)
		if loadErr != nil {
			log.Fatalf("load credential registry: %v", loadErr)
		}
		serverOptions = append(serverOptions, server.WithAuthenticator(authenticator))
	}
	httpServer := &http.Server{
		Addr: cfg.Addr, Handler: server.New(svc, serverOptions...),
		ReadTimeout: cfg.ReadTimeout, WriteTimeout: cfg.WriteTimeout, IdleTimeout: cfg.IdleTimeout,
	}
	log.Printf("roomd listening on %s", cfg.Addr)
	if cfg.TLSCertFile != "" {
		err = httpServer.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
	} else {
		err = httpServer.ListenAndServe()
	}
	if err != nil {
		log.Fatal(err)
	}
}

func parseSignals(names []string) ([]roomv1.SignalKind, error) {
	values := make([]roomv1.SignalKind, 0, len(names))
	seen := make(map[roomv1.SignalKind]struct{}, len(names))
	for _, name := range names {
		number, ok := roomv1.SignalKind_value[name]
		kind := roomv1.SignalKind(number)
		if !ok || kind == roomv1.SignalKind_SIGNAL_KIND_UNSPECIFIED {
			return nil, fmt.Errorf("unknown signal %q", name)
		}
		if _, duplicate := seen[kind]; duplicate {
			return nil, fmt.Errorf("duplicate signal %q", name)
		}
		seen[kind] = struct{}{}
		values = append(values, kind)
	}
	return values, nil
}
