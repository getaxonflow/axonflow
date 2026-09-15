// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Real-Postgres proof for migration 178 (#4047): the typed-authoring tables
// hold organization-root rows only.
//
// Three pins, each against the real posture the migration's own header argues
// from - FORCE ROW LEVEL SECURITY, the application role, and a transaction the
// file wraps itself in:
//
//	Pin 1 - the schema refuses a system-root row on all three tables, written by
//	        the APPLICATION ROLE inside the organization scope authoringstore
//	        uses, and refuses it with the ROOT constraint rather than with
//	        row-level security. The same rows under the organization root are
//	        the control.
//	Pin 2 - a deployment at 177 already holding a system-root row fails 178 BY
//	        NAME and nothing changes: the rolled-back transaction leaves the old
//	        constraints standing and the row in place. After the removal the down
//	        file documents, 178 applies.
//	Pin 3 - the self-verification is load-bearing: 178 with one constraint left
//	        admitting the system root is refused by its own check before COMMIT.
//
// Gated on TEST_PG_INTEGRATION=1 through approletest.

import (
	"database/sql"
	"os"
	"strings"
	"testing"

	"axonflow/platform/agent/approletest"
)

const mig178Path = "../../migrations/core/178_typed_authoring_organization_root_only.sql"

var mig178Tables = []string{"typed_policy_artifacts", "typed_policy_activations", "typed_policy_signing_keys"}

func mig178Open(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// ONE CONNECTION: set_config and an aborted transaction are session state,
	// and a pool would hand the next statement a different session.
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func mig178SQL(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(mig178Path)
	if err != nil {
		t.Fatalf("read %s: %v", mig178Path, err)
	}
	return string(raw)
}

// mig178Insert writes one row per table under root, each in its own
// transaction scoped to org the way authoringstore scopes one, and returns each
// insert's error.
func mig178Insert(db *sql.DB, org, root string) map[string]error {
	stmts := map[string]string{
		"typed_policy_signing_keys": `INSERT INTO typed_policy_signing_keys (org_id, root, key_id, public_key, authorized_by)
			VALUES ($1, $2, 'mig178-key', decode(repeat('ab', 32), 'hex'), 'mig178')`,
		"typed_policy_artifacts": `INSERT INTO typed_policy_artifacts (org_id, root, digest, source_digest, document_id, document_version, key_id, artifact)
			VALUES ($1, $2, 'sha256:mig178', 'sha256:mig178-source', 'mig178', 1, 'mig178-key', '{}'::jsonb)`,
		"typed_policy_activations": `INSERT INTO typed_policy_activations (org_id, root, seq, kind, digest, document_id, document_version, actor, activated_at)
			VALUES ($1, $2, 1, 'promote', 'sha256:mig178', 'mig178', 1, 'User::portal:probe@example.com', NOW())`,
	}
	out := map[string]error{}
	for _, table := range mig178Tables {
		stmt := stmts[table]
		out[table] = func() error {
			tx, err := db.Begin()
			if err != nil {
				return err
			}
			defer func() { _ = tx.Rollback() }()
			if _, err := tx.Exec(`SELECT set_config('app.current_org_id', $1, true)`, org); err != nil {
				return err
			}
			if _, err := tx.Exec(stmt, org, root); err != nil {
				return err
			}
			return tx.Commit()
		}()
	}
	return out
}

func mig178ConstraintDef(t *testing.T, db *sql.DB, table string) string {
	t.Helper()
	var def string
	if err := db.QueryRow(`SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = $1`, table+"_root_chk").Scan(&def); err != nil {
		t.Fatalf("read %s_root_chk: %v", table, err)
	}
	return def
}

func TestMigration178_TheSchemaRefusesASystemRootRow(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")
	app := mig178Open(t, env.AppRoleDSN)
	master := mig178Open(t, env.MasterDSN)

	for _, table := range mig178Tables {
		def := mig178ConstraintDef(t, master, table)
		if strings.Contains(def, "system") || !strings.Contains(def, "organization") {
			t.Fatalf("after the full chain %s_root_chk is %s; migration 178 did not narrow it", table, def)
		}
	}

	refused := mig178Insert(app, "org-178", "system")
	for _, table := range mig178Tables {
		err := refused[table]
		if err == nil {
			t.Fatalf("the application role wrote a system-root row into %s", table)
		}
		// THE ROOT CONSTRAINT, NOT ROW-LEVEL SECURITY: a refusal from the
		// org-isolation policy would say nothing about the root.
		if !strings.Contains(err.Error(), table+"_root_chk") {
			t.Fatalf("the system-root row in %s was refused, but not by %s_root_chk: %v", table, table, err)
		}
	}

	// THE CONTROL: the same rows under the organization root, same role, same
	// scope, are admitted - so the refusals above are about the root alone.
	for table, err := range mig178Insert(app, "org-178", "organization") {
		if err != nil {
			t.Fatalf("the organization-root control row was refused in %s, so the refusal above proves nothing: %v", table, err)
		}
	}
}

func TestMigration178_AnExistingSystemRootRowRefusesTheMigrationAndChangesNothing(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	// A HISTORICAL SCHEMA IS THIS TEST'S PREMISE: a deployment at 177 that
	// already holds a system-root row, which only 178's constraint would
	// refuse. That is what SetupAtVersion exists for.
	env := approletest.SetupAtVersion(t, "../../migrations/core", 177)
	master := mig178Open(t, env.MasterDSN)

	if _, err := master.Exec(`INSERT INTO typed_policy_signing_keys (org_id, root, key_id, public_key, authorized_by)
		VALUES ('org-178', 'system', 'planted-system-key', decode(repeat('cd', 32), 'hex'), 'planted')`); err != nil {
		t.Fatalf("planting the system-root row at 177: %v", err)
	}

	err := func() error { _, err := master.Exec(mig178SQL(t)); return err }()
	_, _ = master.Exec("ROLLBACK")
	if err == nil {
		t.Fatal("migration 178 applied over a system-root signing key; it must refuse rather than keep or remove it silently")
	}
	const named = "migration 178: typed_policy_signing_keys holds at least one row whose root is not organization"
	if !strings.Contains(err.Error(), named) {
		t.Fatalf("migration 178 failed, but not with its own named refusal: %v", err)
	}

	// NOTHING CHANGED. The artifacts table's ALTER ran BEFORE the refusal, so
	// its constraint still admitting the system root proves the whole file
	// rolled back rather than applying the tables it reached first.
	for _, table := range mig178Tables {
		if def := mig178ConstraintDef(t, master, table); !strings.Contains(def, "system") {
			t.Fatalf("after the refused migration %s_root_chk is %s; the refusal must leave every table as it was", table, def)
		}
	}
	var rows int
	if err := master.QueryRow(`SELECT count(*) FROM typed_policy_signing_keys WHERE root = 'system'`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("the refused migration left %d system-root key row(s); the row is evidence and must not be touched", rows)
	}

	// THE DOCUMENTED REMOVAL, then the migration applies.
	for _, stmt := range []string{
		`ALTER TABLE typed_policy_signing_keys DISABLE TRIGGER typed_policy_signing_keys_revoke_only`,
		`DELETE FROM typed_policy_signing_keys WHERE root <> 'organization'`,
		`ALTER TABLE typed_policy_signing_keys ENABLE TRIGGER typed_policy_signing_keys_revoke_only`,
	} {
		if _, err := master.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	if _, err := master.Exec(mig178SQL(t)); err != nil {
		t.Fatalf("migration 178 did not apply after the reviewed row was removed: %v", err)
	}
	for _, table := range mig178Tables {
		if def := mig178ConstraintDef(t, master, table); strings.Contains(def, "system") {
			t.Fatalf("after applying, %s_root_chk is still %s", table, def)
		}
	}
}

func TestMigration178_TheSelfVerificationIsLoadBearing(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	// Same historical premise: 178 has not run yet.
	env := approletest.SetupAtVersion(t, "../../migrations/core", 177)
	master := mig178Open(t, env.MasterDSN)

	const narrowed = "ADD CONSTRAINT typed_policy_signing_keys_root_chk CHECK (root = 'organization');"
	const widened = "ADD CONSTRAINT typed_policy_signing_keys_root_chk CHECK (root IN ('system', 'organization'));"
	src := mig178SQL(t)
	mutant := strings.Replace(src, narrowed, widened, 1)
	if mutant == src {
		t.Fatalf("the migration no longer contains %q, so this mutant changes nothing and proves nothing", narrowed)
	}

	err := func() error { _, err := master.Exec(mutant); return err }()
	_, _ = master.Exec("ROLLBACK")
	if err == nil {
		t.Fatal("migration 178 with one constraint still admitting the system root committed; its self-verification checked nothing")
	}
	if !strings.Contains(err.Error(), "migration 178 self-verification") {
		t.Fatalf("the mutant was refused, but not by the self-verification: %v", err)
	}
	if def := mig178ConstraintDef(t, master, "typed_policy_artifacts"); !strings.Contains(def, "system") {
		t.Fatalf("the refused mutant left typed_policy_artifacts_root_chk as %s; the file must roll back whole", def)
	}
}
