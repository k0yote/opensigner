package main

import (
	"flag"
	"fmt"
	"os"

	"log/slog"
)

// migrateShares is set by -migrate-shares. It re-wraps stored shares so each is
// bound to its device row, then exits without serving traffic.
var migrateShares bool

func main() {
	flag.BoolVar(&migrateShares, "migrate-shares", false,
		"re-wrap stored shares so each is bound to its device row, then exit")
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

	// Operator-invoked rather than automatic: it rewrites every device row, and
	// the result is only readable by a binary that understands the bound format.
	if migrateShares {
		if err := migrateSharesToBound(); err != nil {
			slog.Error(fmt.Sprintf("share migration failed: %v", err))
			os.Exit(1)
		}
		return
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
