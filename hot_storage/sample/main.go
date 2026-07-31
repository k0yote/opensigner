package main

import (
	"flag"
	"fmt"
	"os"

	"log/slog"
)

func main() {
	// No flags are defined. Parsing exists so that an unrecognised argument -- a
	// stale runbook still invoking the removed -migrate-shares, say -- exits with
	// a clear error instead of silently starting a server that was not asked for.
	flag.Parse()

	if err := validateConfig(); err != nil {
		fmt.Printf("invalid configuration: %v\n", err)
		os.Exit(1)
	}

	if err := initEncryptionKey(); err != nil {
		slog.Error(fmt.Sprintf("Failed to initialize encryption: %v", err))
		os.Exit(1)
	}

	err := initDB()
	if err != nil {
		slog.Error(fmt.Sprintf("Failed to initialize DB: %v", err))
		os.Exit(1)
	}

	slog.Info("DB initialized")

	host := os.Getenv("HOST")
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	addr := fmt.Sprintf("%s:%s", host, port)
	slog.Info(fmt.Sprintf("Server running on %s", addr))
	listenAndServe(addr)
}
