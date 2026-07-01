package main

import (
	"log"
	"net/http"

	"github.com/haasonsaas/room/internal/app"
	"github.com/haasonsaas/room/internal/config"
	"github.com/haasonsaas/room/internal/server"
	"github.com/haasonsaas/room/internal/store"
)

func main() {
	cfg := config.Load()
	ruleStore, err := store.Open(cfg.DataFile)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	svc := app.New(ruleStore)
	log.Printf("roomd listening on %s", cfg.Addr)
	if err := http.ListenAndServe(cfg.Addr, server.New(svc)); err != nil {
		log.Fatal(err)
	}
}
