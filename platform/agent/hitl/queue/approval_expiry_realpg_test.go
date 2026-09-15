// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package queue

// Real-Postgres proof for #4254: ApprovalExpiry reads a queue row's expiry, and
// whether the queue has already expired it, under the organization's scope, as
// the application role, with FORCE ROW LEVEL SECURITY in effect. A row another
// organization owns and a row that does not exist both read as no row - never
// as a read error, which the approve path refuses on.
//
// Skips cleanly when Docker is unavailable (CI unit lane).

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"

	"axonflow/platform/testutil"
)

func TestApprovalExpiryReadsTheRowUnderTheOrgScope_RealPostgres(t *testing.T) {
	testutil.SkipIfNoDocker(t)
	pg := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	pg.RunMigration(t, hitlQueueRLSDDL)
	ctx := context.Background()

	pendingID, expiredID := uuid.New(), uuid.New()
	expiresAt := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	later := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	if _, err := pg.DB.Exec(`
		INSERT INTO hitl_approval_queue (request_id, org_id, tenant_id, original_query, status, expires_at)
		VALUES ($1, 'org-a', 'tenant-1', 'step-1', 'pending', $2),
		       ($3, 'org-a', 'tenant-1', 'step-2', 'expired', $4)`, pendingID, expiresAt, expiredID, later); err != nil {
		t.Fatalf("seed: %v", err)
	}

	appDB, err := sql.Open("postgres", appRoleDSN(t, pg.URL, "axonflow_app_role", "apppass"))
	if err != nil {
		t.Fatalf("open app-role connection: %v", err)
	}
	t.Cleanup(func() { _ = appDB.Close() })
	appDB.SetMaxOpenConns(1)

	var role string
	if err := appDB.QueryRow("SELECT current_user").Scan(&role); err != nil || role != "axonflow_app_role" {
		t.Fatalf("PREMISE: connected as %q (%v), not axonflow_app_role, so RLS would not be measured", role, err)
	}

	got, expired, found, err := ApprovalExpiry(ctx, appDB, "org-a", pendingID)
	if err != nil || !found || expired || !got.Equal(expiresAt) {
		t.Fatalf("the owning org read (%s, expired=%v, found=%v, %v), want (%s, false, true, nil)", got, expired, found, err, expiresAt)
	}
	// The status is read, not the timestamp alone: this row's expiry is still
	// ahead, and the queue has expired it.
	if got, expired, found, err := ApprovalExpiry(ctx, appDB, "org-a", expiredID); err != nil || !found || !expired || !got.Equal(later) {
		t.Errorf("a row the queue expired read (%s, expired=%v, found=%v, %v), want (%s, true, true, nil)", got, expired, found, err, later)
	}
	if _, _, found, err := ApprovalExpiry(ctx, appDB, "org-b", pendingID); err != nil || found {
		t.Errorf("another org read found=%v err=%v, want no row and no error: RLS hides the row", found, err)
	}
	if _, _, found, err := ApprovalExpiry(ctx, appDB, "org-a", uuid.New()); err != nil || found {
		t.Errorf("an unknown id read found=%v err=%v, want no row and no error", found, err)
	}
	if _, _, _, err := ApprovalExpiry(ctx, appDB, "", pendingID); err == nil {
		t.Error("an empty org read returned no error; the table's RLS refuses it")
	}
}
