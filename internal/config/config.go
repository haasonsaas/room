package config

import (
	"os"
	"strings"
)

type Config struct {
	Addr      string
	DataFile  string
	ServerURL string
}

func Load() Config {
	return Config{
		Addr:      envOr("ROOM_ADDR", ":8787"),
		DataFile:  envOr("ROOM_DATA_FILE", "room-data.json"),
		ServerURL: envOr("ROOM_SERVER_URL", "http://localhost:8787"),
	}
}

func envOr(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}
