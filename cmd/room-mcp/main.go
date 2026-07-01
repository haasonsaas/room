package main

import (
	"log"
	"net/http"

	"github.com/haasonsaas/room/internal/config"
	roommcp "github.com/haasonsaas/room/internal/mcp"
)

func main() {
	cfg := config.Load()
	mux := http.NewServeMux()
	mux.Handle("/mcp", roommcp.NewHandler(cfg.ServerURL))
	log.Printf("room-mcp listening on %s and forwarding to %s", cfg.Addr, cfg.ServerURL)
	if err := http.ListenAndServe(cfg.Addr, mux); err != nil {
		log.Fatal(err)
	}
}
