// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Real-Postgres proof for migration 184 (PRD v11 §1.15): a withdrawal is an
// activation kind and an audited action, each carrying a reason, and the file
// is safe to re-apply and to take down over a ledger that already holds one.
//
//	Pin 1 - written by the APPLICATION ROLE inside an organization scope, a
//	        withdraw entry with a reason is admitted to the ledger and to the
//	        audit table, one with no reason is refused by the constraint that
//	        names that defect, and promote and rollback rows are the control.
//	Pin 2 - re-applying 184 over a ledger that holds a withdraw entry succeeds
//	        and keeps it: the file is idempotent.
//	Pin 3 - the down file keeps every withdraw entry and refuses a NEW one (its
//	        narrow CHECKs return NOT VALID), a promotion still records, and 184
//	        re-applies after it.
//	Pin 4 - the self-verification is load-bearing: 184 with the ledger's kind
//	        left narrow is refused by its own check, and nothing changes.
//
// Gated on TEST_PG_INTEGRATION=1 through approletest.

import (
	"database/sql"
	"strings"
	"testing"

	"axonflow/platform/agent/approletest"
)

const (
	mig184Path     = "../../migrations/core/184_typed_policy_withdraw.sql"
	mig184DownPath = "../../migrations/core/184_typed_policy_withdraw_down.sql"
	mig184Org      = "org-184"
	mig184Actor    = `'User::portal:bob@example.com'`
)

// mig184InsertActivation writes one ledger entry in its own transaction,
// scoped to scope the way authoringstore scopes one, and returns its error.
func mig184InsertActivation(db *sql.DB, scope, values string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SELECT set_config('app.current_org_id', $1, true)`, scope); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO typed_policy_activations
		(org_id, root, seq, kind, digest, previous_digest, document_id, document_version, actor, activated_at, reason)
		VALUES ` + values); err != nil {
		return err
	}
	return tx.Commit()
}

// mig184Ledger is the organization's ledger as kind@seq, oldest first, read by
// the master role so row-level security does not hide an entry.
func mig184Ledger(t *testing.T, db *sql.DB) string {
	t.Helper()
	rows, err := db.Query(`SELECT kind || '@' || seq FROM typed_policy_activations WHERE org_id = $1 ORDER BY seq`, mig184Org)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return strings.Join(out, ",")
}

// mig184Entry is one ledger row's VALUES tuple.
func mig184Entry(seq, kind, digest, prev, reason string) string {
	return `('` + mig184Org + `', 'organization', ` + seq + `, '` + kind + `', '` + digest + `', '` + prev +
		`', 'm184', 1, ` + mig184Actor + `, NOW(), '` + reason + `')`
}

// mig184AuditEntry is one typed_policy_audit row's VALUES tuple, in
// mig181Insert's column order.
func mig184AuditEntry(action, seq, reason string) string {
	return `('` + mig184Org + `', 'organization', '` + action + `', 'sha256:tpl', ` + seq +
		`, 'sha256:d1', 'shipped-organization-template', 1, ` + mig184Actor + `, '[]', false, '` + reason + `', NOW())`
}

func TestMigration184_AWithdrawalIsAdmittedWithAReasonAndRefusedWithout(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")
	app := mig178Open(t, env.AppRoleDSN)

	// THE CONTROL: the ledger's existing kinds are unchanged.
	if err := mig184InsertActivation(app, mig184Org, mig184Entry("1", "promote", "sha256:d1", "", "")); err != nil {
		t.Fatalf("a promotion was refused, so nothing below is about withdrawal: %v", err)
	}
	if err := mig184InsertActivation(app, mig184Org, mig184Entry("2", "withdraw", "sha256:tpl", "sha256:d1", "")); err == nil ||
		!strings.Contains(err.Error(), "typed_policy_activations_withdraw_reason_chk") {
		t.Fatalf("a withdrawal with no reason was not refused by typed_policy_activations_withdraw_reason_chk: %v", err)
	}
	if err := mig184InsertActivation(app, mig184Org, mig184Entry("2", "withdraw", "sha256:tpl", "sha256:d1", "back to the shipped set")); err != nil {
		t.Fatalf("a withdrawal with a reason was refused: %v", err)
	}
	if err := mig184InsertActivation(app, mig184Org, mig184Entry("3", "rollback", "sha256:d1", "sha256:tpl", "reinstated")); err != nil {
		t.Fatalf("a rollback after a withdrawal was refused: %v", err)
	}

	if err := mig181Insert(app, mig184Org, mig184AuditEntry("withdraw", "2", "")); err == nil ||
		!strings.Contains(err.Error(), "typed_policy_audit_withdraw_reason_chk") {
		t.Fatalf("an audit row for a withdrawal with no reason was not refused by typed_policy_audit_withdraw_reason_chk: %v", err)
	}
	if err := mig181Insert(app, mig184Org, mig184AuditEntry("withdraw", "2", "back to the shipped set")); err != nil {
		t.Fatalf("an audit row for a withdrawal with a reason was refused: %v", err)
	}
}

func TestMigration184_ReapplyingOverAWithdrawalIsIdempotent(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")
	master := mig178Open(t, env.MasterDSN)
	app := mig178Open(t, env.AppRoleDSN)
	for _, e := range []string{
		mig184Entry("1", "promote", "sha256:d1", "", ""),
		mig184Entry("2", "withdraw", "sha256:tpl", "sha256:d1", "back to the shipped set"),
	} {
		if err := mig184InsertActivation(app, mig184Org, e); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := master.Exec(mig181SQL(t, mig184Path)); err != nil {
		t.Fatalf("184 did not re-apply over a ledger holding a withdrawal: %v", err)
	}
	if got := mig184Ledger(t, master); got != "promote@1,withdraw@2" {
		t.Fatalf("the ledger after re-applying 184 is %q; want the entries it held", got)
	}
}

func TestMigration184_TheDownKeepsTheHistoryAndRefusesANewWithdrawal(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")
	master := mig178Open(t, env.MasterDSN)
	app := mig178Open(t, env.AppRoleDSN)
	for _, e := range []string{
		mig184Entry("1", "promote", "sha256:d1", "", ""),
		mig184Entry("2", "withdraw", "sha256:tpl", "sha256:d1", "back to the shipped set"),
	} {
		if err := mig184InsertActivation(app, mig184Org, e); err != nil {
			t.Fatal(err)
		}
	}
	if err := mig181Insert(app, mig184Org, mig184AuditEntry("withdraw", "2", "back to the shipped set")); err != nil {
		t.Fatal(err)
	}

	if _, err := master.Exec(mig181SQL(t, mig184DownPath)); err != nil {
		t.Fatalf("184's down file did not apply over a ledger holding a withdrawal: %v", err)
	}
	if got := mig184Ledger(t, master); got != "promote@1,withdraw@2" {
		t.Fatalf("the ledger after 184's down is %q; the down must keep the history", got)
	}
	var audits int
	if err := master.QueryRow(`SELECT COUNT(*) FROM typed_policy_audit WHERE org_id = $1 AND action = 'withdraw'`, mig184Org).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("the audit table holds %d withdraw rows after 184's down (err %v); want the 1 it held", audits, err)
	}
	if err := mig184InsertActivation(app, mig184Org, mig184Entry("3", "withdraw", "sha256:tpl", "sha256:tpl", "again")); err == nil ||
		!strings.Contains(err.Error(), "typed_policy_activations_kind_chk") {
		t.Fatalf("a NEW withdrawal after 184's down was not refused by typed_policy_activations_kind_chk: %v", err)
	}
	if err := mig181Insert(app, mig184Org, mig184AuditEntry("withdraw", "3", "again")); err == nil ||
		!strings.Contains(err.Error(), "typed_policy_audit_action_chk") {
		t.Fatalf("a NEW withdraw audit row after 184's down was not refused by typed_policy_audit_action_chk: %v", err)
	}
	// THE CONTROL: a promotion still records, chained onto the withdrawal.
	if err := mig184InsertActivation(app, mig184Org, mig184Entry("3", "promote", "sha256:d2", "sha256:tpl", "")); err != nil {
		t.Fatalf("a promotion after 184's down was refused, so the refusal above is not about withdrawal: %v", err)
	}
	if _, err := master.Exec(mig181SQL(t, mig184Path)); err != nil {
		t.Fatalf("184 did not re-apply after its down file: %v", err)
	}
}

func TestMigration184_TheSelfVerificationIsLoadBearing(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	// A HISTORICAL SCHEMA IS THE PREMISE: 184 has not run yet.
	env := approletest.SetupAtVersion(t, "../../migrations/core", 183)
	master := mig178Open(t, env.MasterDSN)
	src := mig181SQL(t, mig184Path)
	const from, to = "CHECK (kind IN ('promote', 'rollback', 'withdraw'))", "CHECK (kind IN ('promote', 'rollback'))"
	mutant := strings.Replace(src, from, to, 1)
	if mutant == src {
		t.Fatalf("the migration no longer contains %q, so this mutant changes nothing and proves nothing", from)
	}
	err := func() error { _, err := master.Exec(mutant); return err }()
	_, _ = master.Exec("ROLLBACK")
	if err == nil || !strings.Contains(err.Error(), "migration 184 self-verification") {
		t.Fatalf("migration 184 with the ledger's kind left narrow was not refused by its own check: %v", err)
	}
	var reasonChecks int
	if err := master.QueryRow(`SELECT COUNT(*) FROM pg_catalog.pg_constraint
		WHERE conname IN ('typed_policy_activations_withdraw_reason_chk', 'typed_policy_audit_withdraw_reason_chk')`).Scan(&reasonChecks); err != nil {
		t.Fatal(err)
	}
	if reasonChecks != 0 {
		t.Fatalf("the refused mutant left %d withdraw-reason constraint(s) behind; the file must roll back whole", reasonChecks)
	}
}
