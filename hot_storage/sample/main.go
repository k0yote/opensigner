package main

import (
	"fmt"
	"os"

	"log/slog"
)

func main() {
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

	// Refuse to boot against a share store this release cannot read. Surfacing
	// the incompatibility at deploy time is recoverable; discovering it as a
	// decrypt failure during wallet recovery is not.
	if err := assertSharesAreBound(); err != nil {
		slog.Error(fmt.Sprintf("startup check failed: %v", err))
		os.Exit(1)
	}

	host := os.Getenv("HOST")
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	addr := fmt.Sprintf("%s:%s", host, port)
	slog.Info(fmt.Sprintf("Server running on %s", addr))
	listenAndServe(addr)
}
