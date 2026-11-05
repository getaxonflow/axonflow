// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"os"
	"strings"
	"testing"

	"github.com/lib/pq"

	"axonflow/platform/testutil"
)

func TestMigration204DownCannotLoseHiddenCheckoutBindings_RealPostgres(t *testing.T) {
	testutil.SkipIfNoDocker(t)
	pc := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	db := pc.DB
	for _, statement := range []string{
		`CREATE ROLE erasure_down_owner NOLOGIN`,
		`CREATE TABLE tenant_deletion_log (tenant_id TEXT NOT NULL,
			expired_checkout_binding_hashes TEXT[] NOT NULL DEFAULT '{}'::TEXT[])`,
		`INSERT INTO tenant_deletion_log VALUES ('cs_erased', ARRAY['binding-present'])`,
		`ALTER TABLE tenant_deletion_log OWNER TO erasure_down_owner`,
		`ALTER TABLE tenant_deletion_log ENABLE ROW LEVEL SECURITY`,
		`ALTER TABLE tenant_deletion_log FORCE ROW LEVEL SECURITY`,
		`CREATE POLICY tenant_deletion_log_hosted_org ON tenant_deletion_log
			USING (tenant_id = current_setting('app.current_org_id', true))`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	down, err := os.ReadFile("../../migrations/community-saas/204_erased_checkout_expiry_bindings_down.sql")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`SET LOCAL ROLE erasure_down_owner`); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	_, err = tx.Exec(string(down))
	_ = tx.Rollback()
	if err == nil || !strings.Contains(err.Error(), "requires a BYPASSRLS role") {
		t.Fatalf("FORCE-RLS-hidden binding permitted rollback: %v", err)
	}
	var bindings []string
	if err := db.QueryRow(`SELECT expired_checkout_binding_hashes FROM tenant_deletion_log
		WHERE tenant_id='cs_erased'`).Scan(pq.Array(&bindings)); err != nil || len(bindings) != 1 {
		t.Fatalf("erasure binding was lost: %v %v", bindings, err)
	}
	if _, err := db.Exec(`UPDATE tenant_deletion_log SET expired_checkout_binding_hashes='{}'::TEXT[]`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(string(down)); err != nil {
		t.Fatalf("empty receipt should permit privileged rollback: %v", err)
	}
	var columnExists bool
	if err := db.QueryRow(`SELECT EXISTS (
		SELECT 1 FROM information_schema.columns
		 WHERE table_name='tenant_deletion_log' AND column_name='expired_checkout_binding_hashes')`).Scan(&columnExists); err != nil || columnExists {
		t.Fatalf("empty rollback did not drop column: exists=%v err=%v", columnExists, err)
	}
}
