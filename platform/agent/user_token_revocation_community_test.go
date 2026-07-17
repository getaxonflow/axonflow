//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"database/sql"
	"testing"

	_ "github.com/lib/pq"
)

// TestWireUserTokenRevocation_CommunityIsNoOp pins that decide-plane
// revocation enforcement is Enterprise-only: in a community build,
// identity.NewDBRevocationStore returns ErrEnterpriseOnly even for a non-nil
// db, so the checker stays unset and validateUserToken never enforces
// revocation. (Build-tagged !enterprise because the enterprise build WOULD
// wire the store from a non-nil db.)
func TestWireUserTokenRevocation_CommunityIsNoOp(t *testing.T) {
	prev := userTokenRevocations
	t.Cleanup(func() { userTokenRevocations = prev })
	userTokenRevocations = nil

	// A non-nil pool (never actually dialed) so wireUserTokenRevocation
	// reaches the NewDBRevocationStore call rather than short-circuiting on
	// the nil-db guard.
	db, err := sql.Open("postgres", "postgres://localhost:1/none?sslmode=disable")
	if err != nil {
		t.Fatalf("open placeholder db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	wireUserTokenRevocation(db)
	if userTokenRevocations != nil {
		t.Fatal("community build must leave decide-plane revocation unset (Enterprise-only)")
	}
}
