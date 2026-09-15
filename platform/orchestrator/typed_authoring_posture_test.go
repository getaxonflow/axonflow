// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"

	"axonflow/platform/decision/legacycompile"
)

// expectPostureRead expects the activation dry run's read of org's recorded
// detection posture through the agent's RLS-scoped repository: BEGIN,
// set_config, the read, COMMIT.
func expectPostureRead(mock sqlmock.Sqlmock, org string, rows *sqlmock.Rows) {
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).WithArgs(org).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`FROM detection_action_overrides`).WithArgs(org).WillReturnRows(rows)
	mock.ExpectCommit()
}

// THE DRY RUN READS THE POSTURE THE ENGINE WILL FOLD (PRD v11 §1.5, #4045): a
// document is judged under the recorded posture the enforcing seam applies,
// folded through the one shared fan-out, an inert category included and
// assigning nothing.
func TestTheRouteDryRunFoldsTheOrganizationsRecordedPosture(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	expectPostureRead(mock, "org-a", sqlmock.NewRows([]string{"category", "action"}).
		AddRow("sqli", "block").AddRow("dangerous_query", "block"))
	h := &TypedAuthoringRouteHandler{db: db}
	got, err := h.recordedPosture(context.Background(), "org-a")
	if err != nil {
		t.Fatal(err)
	}
	if want := (legacycompile.CategoryActions{"security-sqli": legacycompile.ActionBlock}); !reflect.DeepEqual(got, want) {
		t.Fatalf("the recorded posture folds to %v; want %v", got, want)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// A dry run that cannot read the posture refuses, as the enforcing seam does,
// rather than judging the document under the shipped actions.
func TestTheRouteDryRunFailsClosedWhenThePostureCannotBeRead(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).WithArgs("org-a").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`FROM detection_action_overrides`).WithArgs("org-a").WillReturnError(errors.New("connection reset by peer"))
	mock.ExpectRollback()
	h := &TypedAuthoringRouteHandler{db: db}
	got, err := h.recordedPosture(context.Background(), "org-a")
	if err == nil || got != nil || !strings.Contains(err.Error(), "recorded detection posture could not be read") {
		t.Fatalf("an unreadable posture gave (%v, %v); want a refusal naming the posture", got, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// With no database nothing is recorded anywhere, as on the enforcing seam.
func TestARouteWithNoDatabaseHasNoRecordedPosture(t *testing.T) {
	h := &TypedAuthoringRouteHandler{db: nil}
	if got, err := h.recordedPosture(context.Background(), "org-a"); err != nil || got != nil {
		t.Fatalf("a route with no database read (%v, %v); want nothing recorded", got, err)
	}
}
