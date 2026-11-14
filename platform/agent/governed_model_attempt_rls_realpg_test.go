// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"database/sql"
	"os"
	"testing"
)

// TestGovernedModelAttemptRLSCompositeTenant is the live-PostgreSQL mutation
// gate for the durable paid-attempt journal. The same organization may contain
// multiple tenants; insert, select and update must all require both keys.
func TestGovernedModelAttemptRLSCompositeTenant(t *testing.T) {
	if os.Getenv("TEST_PG_INTEGRATION") != "1" {
		t.Skip("TEST_PG_INTEGRATION=1 not set")
	}
	dsn, cleanup := startCountTestPostgres(t)
	t.Cleanup(cleanup)
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`DO $$ BEGIN
		IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='axonflow_app_role') THEN
			CREATE ROLE axonflow_app_role NOLOGIN;
		END IF;
	END $$`); err != nil {
		t.Fatalf("create app role: %v", err)
	}
	body, err := os.ReadFile("../../migrations/core/195_governed_model_attempt_journal.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(string(body)); err != nil {
		t.Fatalf("apply migration: %v", err)
	}
	if _, err := db.Exec(string(body)); err != nil {
		t.Fatalf("replay migration: %v", err)
	}
	if _, err := db.Exec("GRANT axonflow_app_role TO CURRENT_USER"); err != nil {
		t.Fatal(err)
	}

	withScope := func(orgID, tenantID string, fn func(*sql.Tx) error) error {
		tx, err := db.BeginTx(context.Background(), nil)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.Exec("SET LOCAL ROLE axonflow_app_role"); err != nil {
			return err
		}
		if _, err := tx.Exec("SELECT set_config('app.current_org_id',$1,true)", orgID); err != nil {
			return err
		}
		if _, err := tx.Exec("SELECT set_config('app.current_tenant_id',$1,true)", tenantID); err != nil {
			return err
		}
		if err := fn(tx); err != nil {
			return err
		}
		return tx.Commit()
	}
	insert := `INSERT INTO governed_model_attempts
		(request_id,org_id,tenant_id,trace_id,module,case_id,evidence_version,investigation_key,status)
		VALUES ('11111111-1111-4111-8111-111111111111',$1,$2,repeat('a',32),'payment_exception',
		'case-a',repeat('b',64),repeat('c',64),'forwarding')`
	if err := withScope("org-a", "tenant-a", func(tx *sql.Tx) error {
		_, err := tx.Exec(insert, "org-a", "tenant-a")
		return err
	}); err != nil {
		t.Fatalf("same-tenant insert: %v", err)
	}
	if err := withScope("org-a", "tenant-b", func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO governed_model_attempts
			(request_id,org_id,tenant_id,trace_id,module,case_id,evidence_version,investigation_key,status)
			VALUES ('22222222-2222-4222-8222-222222222222','org-a','tenant-a',repeat('d',32),
			'payment_exception','case-b',repeat('e',64),repeat('f',64),'forwarding')`)
		return err
	}); err == nil {
		t.Fatal("cross-tenant insert unexpectedly passed RLS WITH CHECK")
	}
	if err := withScope("org-a", "tenant-b", func(tx *sql.Tx) error {
		var count int
		if err := tx.QueryRow("SELECT COUNT(*) FROM governed_model_attempts").Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			t.Fatalf("cross-tenant select exposed %d rows", count)
		}
		result, err := tx.Exec("UPDATE governed_model_attempts SET status='outcome_unknown'")
		if err != nil {
			return err
		}
		rows, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if rows != 0 {
			t.Fatalf("cross-tenant update changed %d rows", rows)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
