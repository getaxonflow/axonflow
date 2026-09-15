// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package detectionposture

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

// TestValidation pins the closed accept-sets. The load-bearing assertion is
// that there is NO governance-"off": every legal action keeps enforcement on,
// and any value outside the sets is refused, so the write path can never
// disable governance or coerce an unknown value to a weaker posture.
func TestValidation(t *testing.T) {
	for _, c := range []string{CategoryPII, CategorySQLI, CategoryDangerousQuery, CategoryDangerousCommand, CategoryObligationFallback} {
		if !ValidCategory(c) {
			t.Errorf("ValidCategory(%q) = false, want true", c)
		}
	}
	for _, bad := range []string{"", "PII", "secrets", "off", "disable", "all"} {
		if ValidCategory(bad) {
			t.Errorf("ValidCategory(%q) = true, want false", bad)
		}
	}
	for _, a := range []string{ActionBlock, ActionRedact, ActionWarn, ActionLog} {
		if !ValidAction(a) {
			t.Errorf("ValidAction(%q) = false, want true", a)
		}
	}
	for _, bad := range []string{"", "off", "disable", "allow", "none", "BLOCK", "ignore"} {
		if ValidAction(bad) {
			t.Errorf("ValidAction(%q) = true, want false: must not allow a governance-off", bad)
		}
	}
}

// --- obligation_fallback (#2958, core/144) ---

func TestObligationFallbackAcceptsOnlyBlockAndLog(t *testing.T) {
	// redact is what the seam cannot do, the reason a fallback applies at all;
	// warn has no enforcement distinct from log on this axis.
	for _, tc := range []struct {
		action string
		want   bool
	}{
		{ActionBlock, true},
		{ActionLog, true},
		{ActionRedact, false},
		{ActionWarn, false},
		{"off", false},
		{"", false},
	} {
		if got := ValidActionForCategory(CategoryObligationFallback, tc.action); got != tc.want {
			t.Errorf("ValidActionForCategory(obligation_fallback, %q) = %v, want %v", tc.action, got, tc.want)
		}
	}
}

func TestDetectorCategoriesKeepAllFourActions(t *testing.T) {
	// The narrowing applies ONLY to obligation_fallback; silently restricting a
	// detector category would break recorded posture.
	for _, category := range []string{CategoryPII, CategorySQLI, CategoryDangerousQuery, CategoryDangerousCommand} {
		for _, action := range []string{ActionBlock, ActionRedact, ActionWarn, ActionLog} {
			if !ValidActionForCategory(category, action) {
				t.Errorf("ValidActionForCategory(%q, %q) = false, want true: detector categories keep all four strengths", category, action)
			}
		}
		if got := len(ActionsForCategory(category)); got != 4 {
			t.Errorf("ActionsForCategory(%q) returned %d actions, want 4", category, got)
		}
	}
}

func TestActionsForCategoryEnumeratesTheNarrowedSet(t *testing.T) {
	got := ActionsForCategory(CategoryObligationFallback)
	if len(got) != 2 || got[0] != ActionBlock || got[1] != ActionLog {
		t.Errorf("ActionsForCategory(obligation_fallback) = %v, want [block log]: the API error must tell the caller what IS allowed", got)
	}
}

func TestCategoriesEnumeratesEveryAddressableCategory(t *testing.T) {
	got := strings.Join(Categories(), ",")
	if want := "dangerous_command,dangerous_query,obligation_fallback,pii,sqli"; got != want {
		t.Errorf("Categories() = %s, want %s", got, want)
	}
}

// jsonHas matches the admin_audit_log.details argument: a JSON object holding
// exactly the wanted key/value pairs as substrings, and nothing it forbids.
type jsonHas []string

func (j jsonHas) Match(v driver.Value) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	for _, want := range j {
		if !strings.Contains(s, want) {
			return false
		}
	}
	return true
}

func begin(t *testing.T) (*sql.Tx, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	mock.ExpectBegin()
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	return tx, mock
}

var operator = Actor{Identifier: "admin@org-a.example", IPAddress: "[2001:db8::1]:8080", UserAgent: "curl/8"}

// TestSetWritesTheOverrideAndItsAuditRowOnTheCallersTransaction is the write
// both callers share: the override with updated_by = the actor, then the
// DETECTION_POSTURE_SET row naming the same actor, org, category and action,
// both on the transaction the caller passed. Red if either statement goes, if
// either leaves the transaction, or if the actor stops reaching either row.
func TestSetWritesTheOverrideAndItsAuditRowOnTheCallersTransaction(t *testing.T) {
	tx, mock := begin(t)
	mock.ExpectExec(`INSERT INTO detection_action_overrides`).
		WithArgs("org-a", CategorySQLI, ActionBlock, "admin@org-a.example").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec(`INSERT INTO admin_audit_log`).
		WithArgs(
			AuditActionSet,
			sql.NullString{String: "org-a", Valid: true},
			"admin@org-a.example",
			jsonHas{`"category":"sqli"`, `"action":"block"`},
			sql.NullString{String: "2001:db8::1", Valid: true},
			sql.NullString{String: "curl/8", Valid: true},
			true,
			sql.NullString{},
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := Set(context.Background(), tx, "org-a", CategorySQLI, ActionBlock, operator); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("Set did not write the override and its audit row: %v", err)
	}
}

func TestDeleteClearsTheOverrideAndWritesItsAuditRow(t *testing.T) {
	tx, mock := begin(t)
	mock.ExpectExec(`DELETE FROM detection_action_overrides`).
		WithArgs("org-a", CategoryPII).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO admin_audit_log`).
		WithArgs(AuditActionDelete, sql.NullString{String: "org-a", Valid: true}, "admin@org-a.example",
			jsonHas{`"category":"pii"`}, sqlmock.AnyArg(), sqlmock.AnyArg(), true, sql.NullString{}).
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := Delete(context.Background(), tx, "org-a", CategoryPII, operator); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("Delete did not clear the override and write its audit row: %v", err)
	}
}

// TestALostAuditRowFailsTheChange: the audit row is part of the change, so a
// failed audit INSERT is returned and the caller's transaction rolls back,
// taking the override with it.
func TestALostAuditRowFailsTheChange(t *testing.T) {
	tx, mock := begin(t)
	mock.ExpectExec(`INSERT INTO detection_action_overrides`).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec(`INSERT INTO admin_audit_log`).WillReturnError(errors.New(`relation "admin_audit_log" does not exist`))

	err := Set(context.Background(), tx, "org-a", CategorySQLI, ActionBlock, operator)
	if err == nil || !strings.Contains(err.Error(), "audit DETECTION_POSTURE_SET") {
		t.Fatalf("Set = %v, want the audit failure returned so the transaction rolls back", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// TestARefusedWriteTouchesNothing: every refusal happens before the first
// statement, so a refused write leaves no half-change on the transaction.
func TestARefusedWriteTouchesNothing(t *testing.T) {
	for _, tc := range []struct {
		name, org, category, action string
		actor                       Actor
		reason                      string
	}{
		{"no organization", "", CategorySQLI, ActionBlock, operator, "organization must be non-empty"},
		{"no actor", "org-a", CategorySQLI, ActionBlock, Actor{}, "actor must be named"},
		{"unknown category", "org-a", "secrets", ActionBlock, operator, "invalid category"},
		{"governance off", "org-a", CategorySQLI, "off", operator, "not valid for category"},
		{"redact on obligation_fallback", "org-a", CategoryObligationFallback, ActionRedact, operator, "not valid for category"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx, mock := begin(t)
			err := Set(context.Background(), tx, tc.org, tc.category, tc.action, tc.actor)
			if err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("Set = %v, want a refusal naming %q", err, tc.reason)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("a refused write reached the database: %v", err)
			}
		})
	}
	if err := Set(context.Background(), nil, "org-a", CategorySQLI, ActionBlock, operator); err == nil || !strings.Contains(err.Error(), "no transaction") {
		t.Fatalf("Set with no transaction = %v, want a refusal", err)
	}
	if err := Delete(context.Background(), nil, "org-a", CategorySQLI, operator); err == nil || !strings.Contains(err.Error(), "no transaction") {
		t.Fatalf("Delete with no transaction = %v, want a refusal", err)
	}
}
