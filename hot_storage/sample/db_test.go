package main

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

// A revoked secondary device keeps its row (so GET /v2/devices can list it) but
// its share is cleared (HOT-1). The startup check that rejects legacy, unbound
// shares must not count those rows, or the service crash-loops after the first
// revocation.
func TestAssertSharesAreBoundIgnoresRevokedRows(t *testing.T) {
	setupHandlerTest(t)
	now := time.Now()
	rows := []Device{
		{ID: uuid.NewString(), Share: boundSharePrefix + "ciphertext", IsPrimary: true, SignerId: "signer-1"},
		{ID: uuid.NewString(), Share: "", SignerId: "signer-1", RevokedAt: &now},
	}
	if err := db.Create(&rows).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := assertSharesAreBound(); err != nil {
		t.Fatalf("revoked rows must not fail the startup check: %v", err)
	}
}

func TestAssertSharesAreBoundRejectsLegacyShares(t *testing.T) {
	setupHandlerTest(t)
	if err := db.Create(&Device{ID: uuid.NewString(), Share: "legacy-ciphertext", SignerId: "signer-1"}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := assertSharesAreBound(); err == nil {
		t.Fatal("a live legacy share must fail the startup check")
	}
}
