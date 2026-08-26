// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package execution

import (
	"context"
	"regexp"
	"strings"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

// #3442. Two things are pinned here:
//
//  1. the SHAPE of a minted execution id, and that the removed rand.Read
//     fallback (which produced a guessable `wf_<UnixNano>`) cannot come back;
//  2. the identity SEAM - a caller that already owns the run's identity hands
//     it in, and the source system's id reaches execution_history.external_id.
//
// (2) is what makes the WCP workflow and its execution projection ONE
// identifier instead of two `wf_`-prefixed strings on two operator screens.

// mintedIDShape is the shape generateExecutionID must produce: a prefix, an
// underscore, and exactly 24 lowercase hex characters (12 crypto/rand bytes).
// Anchored at both ends, so the clock-derived `<prefix>_<UnixNano>` fallback
// this issue removed cannot satisfy it - digits alone are a subset of hex, but
// a nanosecond stamp is 19 characters, not 24, and would have to grow to 24
// digits to slip through, which is roughly the year 300 billion.
var mintedIDShape = regexp.MustCompile(`^(exec|plan|wf)_[0-9a-f]{24}$`)

func TestGenerateExecutionIDShape(t *testing.T) {
	cases := []struct {
		name       string
		execType   ExecutionType
		wantPrefix string
	}{
		{"MAP", ExecutionTypeMAP, "plan_"},
		{"WCP", ExecutionTypeWCP, "wf_"},
		{"unknown", ExecutionType("something-else"), "exec_"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id := generateExecutionID(tc.execType)
			if !strings.HasPrefix(id, tc.wantPrefix) {
				t.Fatalf("generateExecutionID(%q) = %q, want prefix %q", tc.execType, id, tc.wantPrefix)
			}
			if !mintedIDShape.MatchString(id) {
				t.Fatalf("generateExecutionID(%q) = %q, want <prefix>_<24 lowercase hex> - 96 bits (#3442)", tc.execType, id)
			}
		})
	}
}

// TestGenerateExecutionIDNeverProducesTheClockFallback states the removed
// branch directly. crypto/rand.Read cannot fail on Go 1.24+ ("never returns an
// error, and always fills b entirely"), so the branch was unreachable and the
// only way it could ever have been observed is a regression that reintroduces
// it. This asserts on shape rather than trying to force an RNG failure - the
// stdlib gives no seam to force one, which is exactly why the dead branch went
// unnoticed.
func TestGenerateExecutionIDNeverProducesTheClockFallback(t *testing.T) {
	clockShaped := regexp.MustCompile(`^(exec|plan|wf)_[0-9]{15,20}$`)
	for i := 0; i < 256; i++ {
		for _, ty := range []ExecutionType{ExecutionTypeMAP, ExecutionTypeWCP, ExecutionType("x")} {
			if id := generateExecutionID(ty); clockShaped.MatchString(id) {
				t.Fatalf("generateExecutionID(%q) = %q - the guessable UnixNano fallback is back (#3442)", ty, id)
			}
		}
	}
}

func TestGenerateExecutionIDIsUnique(t *testing.T) {
	const n = 20000
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		id := generateExecutionID(ExecutionTypeWCP)
		if _, dup := seen[id]; dup {
			t.Fatalf("generateExecutionID produced a duplicate within %d draws: %q", n, id)
		}
		seen[id] = struct{}{}
	}
}

// TestStartExecutionHonoursCallerSuppliedIdentity pins the seam the WCP
// tracker rides: a caller-supplied ExecutionID is used verbatim, and is NOT
// merely accepted-then-ignored.
func TestStartExecutionHonoursCallerSuppliedIdentity(t *testing.T) {
	repo := NewMockRepository()
	tracker := NewBaseExecutionTracker(repo)

	const supplied = "wf_11111111-2222-4333-8444-555555555555"
	exec, err := tracker.StartExecution(context.Background(), CreateExecutionRequest{
		ExecutionID:   supplied,
		ExternalID:    supplied,
		ExecutionType: ExecutionTypeWCP,
		Name:          "3442 seam",
		OrgID:         "org-3442",
		TenantID:      "tenant-3442",
	})
	if err != nil {
		t.Fatalf("StartExecution: %v", err)
	}
	if exec.ExecutionID != supplied {
		t.Fatalf("ExecutionID = %q, want the caller-supplied %q", exec.ExecutionID, supplied)
	}
	if exec.ExternalID != supplied {
		t.Fatalf("ExternalID = %q, want the caller-supplied %q", exec.ExternalID, supplied)
	}

	// It must be the id the record was STORED under, not just the one echoed
	// back on the returned struct - a mismatch there would leave every later
	// lookup by this id missing.
	stored, err := repo.Get(context.Background(), supplied)
	if err != nil {
		t.Fatalf("stored execution is not retrievable by the supplied id: %v", err)
	}
	if stored.ExecutionID != supplied {
		t.Fatalf("stored ExecutionID = %q, want %q", stored.ExecutionID, supplied)
	}
}

// TestStartExecutionMintsWhenNoIdentitySupplied pins the other half: the MAP
// path and every existing caller keep their generated id, and ExternalID
// defaults to it, which is byte-for-byte what was written before #3442.
func TestStartExecutionMintsWhenNoIdentitySupplied(t *testing.T) {
	tracker := NewBaseExecutionTracker(NewMockRepository())

	exec, err := tracker.StartExecution(context.Background(), CreateExecutionRequest{
		ExecutionType: ExecutionTypeMAP,
		Name:          "3442 default",
		OrgID:         "org-3442",
		TenantID:      "tenant-3442",
	})
	if err != nil {
		t.Fatalf("StartExecution: %v", err)
	}
	if !mintedIDShape.MatchString(exec.ExecutionID) {
		t.Fatalf("ExecutionID = %q, want a minted <prefix>_<24 hex>", exec.ExecutionID)
	}
	if exec.ExternalID != exec.ExecutionID {
		t.Fatalf("ExternalID = %q, want it to default to the execution id %q", exec.ExternalID, exec.ExecutionID)
	}
}

// TestCreateWritesExternalIDColumn pins that the SOURCE id, not a copy of the
// primary key, lands in execution_history.external_id - the column migration
// core/042 documents as "Original ID from source system (plan_id or
// workflow_id)" and which the writer had been filling with exec.ExecutionID.
//
// The assertion is positional on the INSERT's third bind, because that is the
// actual defect: the old code passed the right number of arguments in the
// wrong order of meaning, which no compiler and no round-trip test can see.
func TestCreateWritesExternalIDColumn(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	const execID = "wf_aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	const sourceID = "plan_1750000000_abcdefgh"

	exec := &ExecutionStatus{
		ExecutionID:   execID,
		ExternalID:    sourceID,
		ExecutionType: ExecutionTypeMAP,
		Name:          "3442 external id",
		Status:        StatusPending,
		OrgID:         "org-3442",
		TenantID:      "tenant-3442",
	}

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).WithArgs("org-3442").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`SELECT set_config\('app.current_tenant_id', \$1, true\)`).WithArgs("tenant-3442").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`SELECT set_config\('app.tenant_id', \$1, true\)`).WithArgs("tenant-3442").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO execution_history").
		WithArgs(
			execID, exec.ExecutionType, sourceID, exec.Name, sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			exec.Status, 0, 0,
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	if err := (&PostgresRepository{db: db}).Create(context.Background(), exec); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("external_id was not bound to the source id: %v", err)
	}
}

// TestCreateFallsBackToExecutionIDForExternalID pins the compatibility half:
// execution_history.external_id is NOT NULL, so a caller that sets no
// ExternalID must still write the old value rather than an empty string.
func TestCreateFallsBackToExecutionIDForExternalID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	const execID = "exec_0123456789abcdef01234567"
	exec := &ExecutionStatus{
		ExecutionID:   execID,
		ExecutionType: ExecutionType("legacy"),
		Name:          "3442 fallback",
		Status:        StatusPending,
		OrgID:         "org-3442",
		TenantID:      "tenant-3442",
	}

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).WithArgs("org-3442").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`SELECT set_config\('app.current_tenant_id', \$1, true\)`).WithArgs("tenant-3442").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`SELECT set_config\('app.tenant_id', \$1, true\)`).WithArgs("tenant-3442").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO execution_history").
		WithArgs(
			execID, exec.ExecutionType, execID, exec.Name, sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			exec.Status, 0, 0,
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	if err := (&PostgresRepository{db: db}).Create(context.Background(), exec); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("external_id did not fall back to the execution id: %v", err)
	}
}
