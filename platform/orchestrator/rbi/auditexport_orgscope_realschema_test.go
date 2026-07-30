// Copyright 2026 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package rbi

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

// applyRBIAuditExportSchema layers migration 303 (the cloud-storage columns the
// audit-export repository writes: download_url / storage_type / storage_key) on
// top of the 301 baseline applied by applyRBISchema. Without it the real
// repository's INSERT fails on a missing column — which would make this suite
// skip past its own fixture and certify nothing.
func applyRBIAuditExportSchema(t *testing.T) *sql.DB {
	t.Helper()
	db := applyRBISchema(t)
	const mig = "../../../migrations/industry/banking/303_audit_export_cloud_storage.sql"
	b, err := os.ReadFile(mig)
	if err != nil {
		t.Fatalf("read %s: %v", mig, err)
	}
	if _, err := db.Exec(string(b)); err != nil {
		t.Fatalf("apply RBI migration 303: %v", err)
	}
	return db
}

// TestAuditExport_RealSchema_QueryParamCannotSelectAnotherOrg is the #3066 C3-3
// isolation proof with NO repository mock anywhere in the loop: the real
// gorilla/mux router run.go registers → the real AuditExportHandler → the real
// AuditExportService → PostgresAuditExportRepository → the REAL migrated
// rbi_audit_exports table (migration 301).
//
// CONNECTION ROLE, stated explicitly: applyRBISchema hands back the
// testcontainer MASTER (superuser) DSN, so the RLS policy migration 301 enables
// on rbi_audit_exports (`rbi_audit_exports_isolation … USING (org_id =
// get_current_org_id())`) is BYPASSED for this connection. That is deliberate
// and is what makes the test able to see the defect at all: with RLS active a
// missing application-level org binding shows up as zero rows, and the leak
// would be masked rather than proven. It also matches production for this
// module — the RBI repositories never wrap a query in WithOrgScope and never
// SET app.current_org_id, so `get_current_org_id()` is NULL on a real
// deployment and the RLS predicate is doing no work either way. Application-
// level scoping is the entire boundary here; see the PR body.
func TestAuditExport_RealSchema_QueryParamCannotSelectAnotherOrg(t *testing.T) {
	db := applyRBIAuditExportSchema(t) // skips unless TEST_PG_INTEGRATION=1

	var role string
	if err := db.QueryRow("SELECT current_user").Scan(&role); err != nil {
		t.Fatalf("query current_user: %v", err)
	}
	t.Logf("connected as %q (superuser ⇒ RLS bypassed by design, see the doc comment)", role)

	repo := NewPostgresAuditExportRepository(db)
	svc := NewAuditExportService(repo, nil, nil, nil, nil, nil, t.TempDir(), nil)
	module := &RBIModule{
		AuditService:      svc,
		AuditHandler:      NewAuditExportHandler(svc),
		RegistryHandler:   NewAISystemRegistryHandler(&MockAISystemRegistryService{}),
		ValidationHandler: NewModelValidationHandler(&MockModelValidationService{}),
		IncidentHandler:   NewAIIncidentHandler(&MockAIIncidentService{}),
		KillSwitchHandler: NewKillSwitchHandler(NewMockKillSwitchService()),
		BoardHandler:      NewBoardReportHandler(NewMockBoardReportServiceForHandlers()),
	}
	r := mux.NewRouter()
	module.RegisterRoutesWithMux(r)

	// Seed BOTH orgs through the real POST handler. Without a victim row there
	// is nothing to leak and the isolation assertions are vacuous; without an
	// attacker row the "still reads its own" direction is untested.
	attackerExport := seedExport(t, r, orgAttacker, "attacker's own export")
	victimExport := seedExport(t, r, orgVictim, "VICTIM-SENTINEL-do-not-leak")

	// The fixture must actually be two distinct rows in the real table.
	var seeded int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM rbi_audit_exports WHERE org_id IN ($1, $2)`,
		orgAttacker, orgVictim).Scan(&seeded); err != nil {
		t.Fatalf("count seeded rows: %v", err)
	}
	if seeded != 2 {
		t.Fatalf("fixture is not what the test assumes: %d rows in rbi_audit_exports, want 2", seeded)
	}

	t.Run("list is bound to the header, not the query param", func(t *testing.T) {
		rr := do(t, r, http.MethodGet, "/api/v1/rbi/audit-exports?org_id="+orgVictim, orgAttacker)
		if rr.Code != http.StatusOK {
			t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
		}
		body := rr.Body.String()
		if strings.Contains(body, victimExport) || strings.Contains(body, "VICTIM-SENTINEL") {
			t.Errorf("CROSS-TENANT READ against the real table: %s", body)
		}
		if !strings.Contains(body, attackerExport) {
			t.Errorf("own export missing — scope collapsed instead of binding: %s", body)
		}
		var resp ListAuditExportsResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.Total != 1 {
			t.Errorf("total = %d, want exactly the caller's own 1 row", resp.Total)
		}
	})

	t.Run("get by id is bound to the header", func(t *testing.T) {
		rr := do(t, r, http.MethodGet,
			"/api/v1/rbi/audit-exports/"+victimExport+"?org_id="+orgVictim, orgAttacker)
		if rr.Code != http.StatusNotFound {
			t.Errorf("CROSS-TENANT READ: want 404, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("delete cannot destroy the victim's row", func(t *testing.T) {
		rr := do(t, r, http.MethodDelete,
			"/api/v1/rbi/audit-exports/"+victimExport+"?org_id="+orgVictim, orgAttacker)
		if rr.Code != http.StatusNotFound {
			t.Errorf("CROSS-TENANT DELETE: want 404, got %d: %s", rr.Code, rr.Body.String())
		}
		// Assert survival in the TABLE, not merely through the API.
		var alive int
		if err := db.QueryRow(
			`SELECT COUNT(*) FROM rbi_audit_exports WHERE id = $1 AND org_id = $2`,
			victimExport, orgVictim).Scan(&alive); err != nil {
			t.Fatalf("survival check: %v", err)
		}
		if alive != 1 {
			t.Errorf("CROSS-TENANT DELETE: victim's row is gone from rbi_audit_exports")
		}
	})

	t.Run("no authenticated org is 401 and touches nothing", func(t *testing.T) {
		rr := do(t, r, http.MethodDelete,
			"/api/v1/rbi/audit-exports/"+victimExport+"?org_id="+orgVictim, "")
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("want 401, got %d: %s", rr.Code, rr.Body.String())
		}
		var alive int
		if err := db.QueryRow(
			`SELECT COUNT(*) FROM rbi_audit_exports WHERE id = $1`, victimExport).Scan(&alive); err != nil {
			t.Fatalf("survival check: %v", err)
		}
		if alive != 1 {
			t.Errorf("unauthenticated DELETE destroyed the row")
		}
	})

	t.Run("own row is still deletable", func(t *testing.T) {
		rr := do(t, r, http.MethodDelete, "/api/v1/rbi/audit-exports/"+attackerExport, orgAttacker)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("want 204, got %d: %s", rr.Code, rr.Body.String())
		}
		var alive int
		if err := db.QueryRow(
			`SELECT COUNT(*) FROM rbi_audit_exports WHERE id = $1`, attackerExport).Scan(&alive); err != nil {
			t.Fatalf("post-delete check: %v", err)
		}
		if alive != 0 {
			t.Errorf("own row survived its own DELETE — the positive direction is broken")
		}
	})
}
