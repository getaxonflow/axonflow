// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

// TestFindActiveOverride_AllowGuard is the regression test for the security
// hardening (WS-10 R3): FindActiveOverride's SQL MUST carry the
// action_override='allow'/NULL guard so a tightening action-override
// (warn/block/redact) can never be mistaken for an ADR-044 session allow-bypass
// and silently flip a deny → allow. If a refactor drops the clause, the expected
// query regexp no longer matches and this test fails.
func TestFindActiveOverride_AllowGuard(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	// The expected query MUST include the allow-guard clause. QuoteMeta so the
	// parentheses/quotes are matched literally.
	guard := regexp.QuoteMeta("(action_override IS NULL OR action_override = 'allow')")
	expiry := time.Now().Add(time.Hour)
	mock.ExpectQuery(`SELECT id, policy_id, policy_type.*FROM policy_overrides.*` + guard).
		WithArgs("pol-1", "u@x", "tenant-1", "").
		WillReturnRows(sqlmock.NewRows(
			[]string{"id", "policy_id", "policy_type", "tool_signature", "override_reason", "expires_at"},
		).AddRow("ov-1", "pol-1", "dynamic", "", "session bypass", expiry))

	ov, err := FindActiveOverride(context.Background(), db, "tenant-1", "u@x", "pol-1", "")
	if err != nil {
		t.Fatalf("FindActiveOverride: %v", err)
	}
	if ov == nil || ov.ID != "ov-1" {
		t.Fatalf("expected allow-override ov-1, got %+v", ov)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("query did not include the allow-guard clause (or args mismatch): %v", err)
	}
}

// TestFindActiveOverride_NoRowGuardedOut proves the caller treats "no matching
// (allow) override" as no-flip: when the guarded query returns zero rows (an
// action-override exists but is filtered out by the allow-guard), FindActiveOverride
// returns (nil, nil) so ApplyOverrideToResult leaves the deny intact.
func TestFindActiveOverride_NoRowGuardedOut(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery(`FROM policy_overrides`).
		WithArgs("pol-1", "u@x", "tenant-1", "").
		WillReturnRows(sqlmock.NewRows(
			[]string{"id", "policy_id", "policy_type", "tool_signature", "override_reason", "expires_at"},
		)) // zero rows → the action-override was guarded out

	ov, err := FindActiveOverride(context.Background(), db, "tenant-1", "u@x", "pol-1", "")
	if err != nil {
		t.Fatalf("FindActiveOverride: %v", err)
	}
	if ov != nil {
		t.Fatalf("expected no active override (guarded out), got %+v", ov)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}
