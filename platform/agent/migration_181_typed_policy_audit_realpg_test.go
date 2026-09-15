// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Real-Postgres proof for migration 181 (PRD v11 §1.12): the typed-policy
// audit table's schema holds the event shape its header argues, and its
// self-verification is load-bearing.
//
//	Pin 1 - written by the APPLICATION ROLE inside an organization scope, each
//	        malformed row is refused by the constraint that names its defect,
//	        a row for another organization is refused by row-level security,
//	        and well-formed publish, promote and rollback rows are the control.
//	Pin 2 - the down file removes the table and its trigger function, and the
//	        file re-applies after it.
//	Pin 3 - the self-verification is load-bearing: 181 without FORCE ROW LEVEL
//	        SECURITY, or with the root constraint widened, is refused by its own
//	        check before COMMIT, and nothing is left behind.
//
// Gated on TEST_PG_INTEGRATION=1 through approletest.

import (
	"database/sql"
	"os"
	"strings"
	"testing"

	"axonflow/platform/agent/approletest"
)

const (
	mig181Path     = "../../migrations/core/181_typed_policy_audit.sql"
	mig181DownPath = "../../migrations/core/181_typed_policy_audit_down.sql"
	mig181Org      = "org-181"
)

func mig181SQL(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(raw)
}

// mig181Insert writes one row in its own transaction, scoped to scope the way
// authoringstore scopes one, and returns the insert's error.
func mig181Insert(db *sql.DB, scope, values string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SELECT set_config('app.current_org_id', $1, true)`, scope); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO typed_policy_audit
		(org_id, root, action, digest, activation_seq, previous_digest, document_id, document_version,
		 actor, approvers, self_approved, reason, occurred_at) VALUES ` + values); err != nil {
		return err
	}
	return tx.Commit()
}

func mig181Present(t *testing.T, db *sql.DB) bool {
	t.Helper()
	var present bool
	if err := db.QueryRow(`SELECT to_regclass('typed_policy_audit') IS NOT NULL`).Scan(&present); err != nil {
		t.Fatal(err)
	}
	return present
}

func TestMigration181_TheSchemaRefusesEveryMalformedRow(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")
	// mig178Open is the one-connection opener: set_config and an aborted
	// transaction are session state.
	app := mig178Open(t, env.AppRoleDSN)

	const actor = `'User::portal:alice@example.com'`
	refused := []struct {
		name, values, by string
	}{
		{"a system-root row",
			`('` + mig181Org + `', 'system', 'publish', 'sha256:r1', 0, '', 'm181', 1, ` + actor + `, '[]', false, '', NOW())`,
			"typed_policy_audit_root_chk"},
		{"a publish carrying an activation sequence",
			`('` + mig181Org + `', 'organization', 'publish', 'sha256:r2', 1, '', 'm181', 1, ` + actor + `, '[]', false, '', NOW())`,
			"typed_policy_audit_event_shape_chk"},
		{"an activation with no sequence",
			`('` + mig181Org + `', 'organization', 'promote', 'sha256:r3', 0, '', 'm181', 1, ` + actor + `, '[]', false, '', NOW())`,
			"typed_policy_audit_event_shape_chk"},
		{"an activation carrying approvers",
			`('` + mig181Org + `', 'organization', 'promote', 'sha256:r4', 1, '', 'm181', 1, ` + actor + `, '["User::portal:bob@example.com"]', false, '', NOW())`,
			"typed_policy_audit_approval_on_publish_chk"},
		{"a self-approval with no approver",
			`('` + mig181Org + `', 'organization', 'publish', 'sha256:r5', 0, '', 'm181', 1, ` + actor + `, '[]', true, '', NOW())`,
			"typed_policy_audit_self_approval_chk"},
		{"a rollback with no reason",
			`('` + mig181Org + `', 'organization', 'rollback', 'sha256:r6', 2, 'sha256:r5', 'm181', 1, ` + actor + `, '[]', false, '', NOW())`,
			"typed_policy_audit_rollback_reason_chk"},
		{"a row for another organization",
			`('org-other', 'organization', 'publish', 'sha256:r7', 0, '', 'm181', 1, ` + actor + `, '[]', false, '', NOW())`,
			"row-level security"},
	}
	for _, c := range refused {
		t.Run(c.name, func(t *testing.T) {
			err := mig181Insert(app, mig181Org, c.values)
			if err == nil {
				t.Fatalf("the application role wrote %s", c.name)
			}
			if !strings.Contains(err.Error(), c.by) {
				t.Fatalf("%s was refused, but not by %s: %v", c.name, c.by, err)
			}
		})
	}

	// THE CONTROL: well-formed rows, same role, same scope, are admitted - so
	// every refusal above is about its own defect.
	for _, values := range []string{
		`('` + mig181Org + `', 'organization', 'publish', 'sha256:c1', 0, '', 'm181', 1, ` + actor + `, '["User::portal:alice@example.com"]', true, '', NOW())`,
		`('` + mig181Org + `', 'organization', 'promote', 'sha256:c1', 1, '', 'm181', 1, 'User::portal:bob@example.com', '[]', false, '', NOW())`,
		`('` + mig181Org + `', 'organization', 'rollback', 'sha256:c1', 2, 'sha256:c0', 'm181', 1, 'User::portal:bob@example.com', '[]', false, 'reverted', NOW())`,
	} {
		if err := mig181Insert(app, mig181Org, values); err != nil {
			t.Fatalf("a well-formed control row was refused, so the refusals above prove nothing: %v", err)
		}
	}
}

func TestMigration181_TheDownFileRemovesItAndTheFileReapplies(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")
	master := mig178Open(t, env.MasterDSN)

	if _, err := master.Exec(mig181SQL(t, mig181DownPath)); err != nil {
		t.Fatalf("applying 181's down file: %v", err)
	}
	if mig181Present(t, master) {
		t.Fatal("typed_policy_audit survived 181's down file")
	}
	var fns int
	if err := master.QueryRow(`SELECT COUNT(*) FROM pg_proc WHERE proname = 'typed_policy_audit_append_only'`).Scan(&fns); err != nil {
		t.Fatal(err)
	}
	if fns != 0 {
		t.Fatal("typed_policy_audit_append_only() survived 181's down file")
	}
	if _, err := master.Exec(mig181SQL(t, mig181Path)); err != nil {
		t.Fatalf("181 did not re-apply after its down file: %v", err)
	}
	if !mig181Present(t, master) {
		t.Fatal("181 re-applied and typed_policy_audit does not exist")
	}
}

func TestMigration181_TheSelfVerificationIsLoadBearing(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	for _, m := range []struct {
		name, from, to, says string
	}{
		{"FORCE row-level security dropped",
			"ALTER TABLE typed_policy_audit FORCE  ROW LEVEL SECURITY;\n", "",
			"does not have ENABLE + FORCE ROW LEVEL SECURITY"},
		{"the root constraint widened",
			"CHECK (root = 'organization')", "CHECK (root IN ('system', 'organization'))",
			"not organization-only"},
	} {
		t.Run(m.name, func(t *testing.T) {
			// A HISTORICAL SCHEMA IS THE PREMISE: 181 has not run yet.
			env := approletest.SetupAtVersion(t, "../../migrations/core", 179)
			master := mig178Open(t, env.MasterDSN)
			src := mig181SQL(t, mig181Path)
			mutant := strings.Replace(src, m.from, m.to, 1)
			if mutant == src {
				t.Fatalf("the migration no longer contains %q, so this mutant changes nothing and proves nothing", m.from)
			}
			err := func() error { _, err := master.Exec(mutant); return err }()
			_, _ = master.Exec("ROLLBACK")
			if err == nil {
				t.Fatalf("migration 181 with %s committed; its self-verification checked nothing", m.name)
			}
			if !strings.Contains(err.Error(), "migration 181 self-verification") || !strings.Contains(err.Error(), m.says) {
				t.Fatalf("the mutant was refused, but not by the self-verification's own check: %v", err)
			}
			if mig181Present(t, master) {
				t.Fatal("the refused mutant left typed_policy_audit behind; the file must roll back whole")
			}
		})
	}
}
