// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/lib/pq"

	"axonflow/platform/shared/legacyfreeze"
)

// TestImportBulkSurfacesTheFreezeInsteadOfStringifyingIt drives the REAL
// accumulate logic, which is the half R3 round 1 found untested.
//
// # What the earlier test could not see
//
// The handler test stubbed PolicyServicer and returned a bare wrapped
// *pq.Error - a shape ImportBulk never emits for a row failure. So the mutant
// "delete the import call site" died because the site is wired, while the real
// error could never reach it. The double certified the bug.
//
// # What ImportBulk actually did
//
// Every row failure became a STRING in response.Errors and the closure returned
// nil, so:
//
//   - the *pq.Error was destroyed by the %v, and errors.As downstream saw
//     nothing to classify;
//   - rls.WithOrgScope reached tx.Commit() on a connection already in
//     aborted-transaction state, and lib/pq answered ErrInFailedTransaction
//     (conn.go:33) - an errors.New wrapping nothing, carrying no SQLSTATE;
//   - handleImport fell through to a bare 500 for a write path that was retired.
//
// # What this test can and cannot prove, stated rather than implied
//
// sqlmock returns whatever it is scripted to return, so it CANNOT reproduce
// Postgres putting the connection into an aborted state - a mock that answered
// ErrInFailedTransaction on Commit would do so because I told it to, which
// proves my plumbing and not the database's behaviour. That is the same
// mock-certifies-the-semantics shape that produced the defect this test exists
// for.
//
// So this asserts the half a mock can honestly carry: given a frozen write, the
// error that leaves ImportBulk is the *pq.Error itself and not a string - which
// is exactly what the handler needs to answer 409. That the classifier
// recognises a REALLY frozen table is asserted against Postgres in
// rls_blind_reads_3039_approle_test.go and pr_c2_orchestrator_withorgscope_test.go,
// and the route's 409 is asserted through the gateway by the import leg in
// runtime-e2e/3039_rls_blind_reads.
func TestImportBulkSurfacesTheFreezeInsteadOfStringifyingIt(t *testing.T) {
	// The error Postgres raises once core/172 has revoked the write. createPolicyTx
	// wraps it with %w ("failed to insert policy: %w"); updatePolicyTx returns it
	// bare. Both stay classifiable, which is the property under test.
	frozen := func() *pq.Error {
		return &pq.Error{Code: "42501", Message: `permission denied for table dynamic_policies`}
	}

	newRepo := func(t *testing.T) (*PolicyRepository, sqlmock.Sqlmock) {
		t.Helper()
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("sqlmock: %v", err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return NewPolicyRepository(db), mock
	}

	policies := []CreatePolicyRequest{{
		Name:       "rt4010-import-probe",
		Type:       "content",
		Conditions: []PolicyCondition{{Field: "query", Operator: "contains", Value: "x"}},
		Actions:    []PolicyAction{{Type: "block"}},
	}}

	// rls.WithOrgScope opens the transaction and sets the org GUC before the
	// closure runs, so every script below begins with these two.
	openScope := func(mock sqlmock.Sqlmock) {
		mock.ExpectBegin()
		mock.ExpectExec(regexp.QuoteMeta("set_config")).WillReturnResult(sqlmock.NewResult(0, 0))
	}

	// findByNameTx's SELECT. A miss is sql.ErrNoRows and ONLY sql.ErrNoRows -
	// policy_api_repository.go:967 returns (nil, nil) for it and propagates
	// everything else - so the sentinel decides which arm of ImportBulk runs.
	const findByName = `SELECT policy_id, name, description`

	// The 17 columns findByNameTx scans, in order. conditions/actions are
	// unmarshalled with `_ =` so their bytes are not load-bearing here.
	existingRow := func() *sqlmock.Rows {
		now := time.Now()
		return sqlmock.NewRows([]string{
			"policy_id", "name", "description", "policy_type",
			"category", "tier",
			"conditions", "actions", "tenant_id", "org_id",
			"priority", "enabled", "version",
			"created_by", "updated_by",
			"created_at", "updated_at",
		}).AddRow(
			"p1", "rt4010-import-probe", "", "content",
			"", "tenant",
			[]byte("[]"), []byte("[]"), "t", "org",
			0, true, 1,
			"u", "u",
			now, now,
		)
	}

	t.Run("a frozen INSERT aborts the import as a classifiable *pq.Error", func(t *testing.T) {
		// THE REAL PATH, not a hand-rolled wrap. An earlier draft of this test
		// imitated createPolicyTx's `%w` in a local helper - which asserts
		// against my MODEL of production, and is the same substitution that put
		// the stub in front of this bug in the first place. sqlmock scripts the
		// statements the production code issues, so the production wrap is what
		// produces the error here.
		repo, mock := newRepo(t)
		openScope(mock)
		mock.ExpectQuery(findByName).WillReturnError(sql.ErrNoRows) // miss -> create arm
		mock.ExpectExec(regexp.QuoteMeta("INSERT INTO dynamic_policies")).WillReturnError(frozen())
		mock.ExpectRollback()

		_, err := repo.ImportBulk(context.Background(), "t", "org", policies, "skip", "importer")
		if err == nil {
			t.Fatal("ImportBulk returned no error for a frozen INSERT; before #4010 it accumulated the failure " +
				"into response.Errors as a STRING and returned nil, and the caller got a bare 500")
		}
		// The property the handler depends on: the driver error survives the
		// return path intact, through createPolicyTx's %w, through WithOrgScope
		// and through ImportBulk's own wrap. `%v` into response.Errors destroyed
		// it, which is precisely why the import route could never answer 409.
		var pqErr *pq.Error
		if !errors.As(err, &pqErr) {
			t.Fatalf("the error leaving ImportBulk is not a *pq.Error: %v", err)
		}
		if !legacyfreeze.IsFrozen(err) {
			t.Fatalf("the error leaving ImportBulk is not classifiable as the freeze: %v", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("the scripted statement sequence is not what ImportBulk issued: %v", err)
		}
	})

	t.Run("a frozen UPDATE aborts the import too", func(t *testing.T) {
		// The overwrite arm. core/172 revoked UPDATE as well as INSERT, and this
		// arm had the identical stringify - a freeze reached here by any import
		// whose policy names already exist, which is the COMMON case for a
		// re-import.
		repo, mock := newRepo(t)
		openScope(mock)
		mock.ExpectQuery(findByName).WillReturnRows(existingRow()) // hit -> overwrite arm
		mock.ExpectExec(regexp.QuoteMeta("UPDATE dynamic_policies")).WillReturnError(frozen())
		mock.ExpectRollback()

		_, err := repo.ImportBulk(context.Background(), "t", "org", policies, "overwrite", "importer")
		if err == nil {
			t.Fatal("ImportBulk returned no error for a frozen UPDATE on the overwrite arm")
		}
		if !legacyfreeze.IsFrozen(err) {
			t.Fatalf("the overwrite arm did not surface the freeze: %v", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("the scripted statement sequence is not what ImportBulk issued: %v", err)
		}
	})

	t.Run("an ordinary row failure is still accumulated, not surfaced", func(t *testing.T) {
		// THE CONTROL THAT MAKES THE TWO ABOVE MEAN SOMETHING. Without it, a fix
		// that returned EVERY row error would pass both - and would turn
		// partial-success imports, which is what this endpoint is for, into
		// all-or-nothing ones. The guard must be selective, so an unrelated
		// failure has to keep the accumulate behaviour and the nil return.
		repo, mock := newRepo(t)
		openScope(mock)
		mock.ExpectQuery(findByName).WillReturnError(errors.New("connection reset by peer"))
		mock.ExpectCommit()

		resp, err := repo.ImportBulk(context.Background(), "t", "org", policies, "skip", "importer")
		if err != nil {
			t.Fatalf("an ordinary row failure aborted the import: %v", err)
		}
		if resp == nil || len(resp.Errors) != 1 {
			t.Fatalf("the row failure was not accumulated into the response: %+v", resp)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("the scripted statement sequence is not what ImportBulk issued: %v", err)
		}
	})

	t.Run("a non-freeze WRITE failure is still accumulated", func(t *testing.T) {
		// THE CONTROL THAT PINS SELECTIVITY AT THE GUARD ITSELF. The control
		// above fails at findByNameTx, which continues at policy_api_repository.go:760
		// and never reaches the create arm - so it cannot tell a guard that
		// classifies from one that returns every write error. This one gets all
		// the way INTO createPolicyTx and fails there for an unrelated reason, so
		// mutating `legacyfreeze.IsFrozen(createErr)` to an unconditional
		// return kills it and nothing else would.
		repo, mock := newRepo(t)
		openScope(mock)
		mock.ExpectQuery(findByName).WillReturnError(sql.ErrNoRows)
		mock.ExpectExec(regexp.QuoteMeta("INSERT INTO dynamic_policies")).
			WillReturnError(&pq.Error{Code: "40P01", Message: "deadlock detected"})
		mock.ExpectCommit()

		resp, err := repo.ImportBulk(context.Background(), "t", "org", policies, "skip", "importer")
		if err != nil {
			t.Fatalf("a non-freeze write failure aborted the whole import: %v", err)
		}
		if resp == nil || len(resp.Errors) != 1 {
			t.Fatalf("the write failure was not accumulated into the response: %+v", resp)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("the scripted statement sequence is not what ImportBulk issued: %v", err)
		}
	})

	t.Run("the shape the OLD code produced is NOT classifiable", func(t *testing.T) {
		// The anti-vacuity for the cases above: if a stringified error also
		// classified, the old code would have worked and this whole finding
		// would be imaginary.
		stringified := errors.New("Error creating policy p: " + frozen().Error())
		if legacyfreeze.IsFrozen(stringified) {
			t.Fatal("a stringified error classified as the freeze")
		}
	})
}
