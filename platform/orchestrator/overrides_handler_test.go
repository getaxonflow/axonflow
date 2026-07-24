// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gorilla/mux"
)

func TestClampOverrideTTL_ZeroUsesDefault(t *testing.T) {
	ttl, clamped, reason := clampOverrideTTL(0)
	if ttl != OverrideDefaultTTL {
		t.Errorf("zero requested: ttl = %v, want %v", ttl, OverrideDefaultTTL)
	}
	if clamped {
		t.Error("zero requested should not report clamped")
	}
	if reason != "" {
		t.Errorf("zero requested should have empty reason, got %q", reason)
	}
}

func TestClampOverrideTTL_WithinBoundsUnchanged(t *testing.T) {
	// 30 minutes = 1800 seconds, within [1min, 24h]
	ttl, clamped, reason := clampOverrideTTL(1800)
	expected := 30 * time.Minute
	if ttl != expected {
		t.Errorf("ttl = %v, want %v", ttl, expected)
	}
	if clamped {
		t.Error("within-bounds should not report clamped")
	}
	if reason != "" {
		t.Errorf("within-bounds reason = %q, want empty", reason)
	}
}

func TestClampOverrideTTL_ExceedsHardCap(t *testing.T) {
	// 30 hours, exceeds 24h cap
	ttl, clamped, reason := clampOverrideTTL(30 * 60 * 60)
	if ttl != OverrideHardCapTTL {
		t.Errorf("ttl = %v, want hard cap %v", ttl, OverrideHardCapTTL)
	}
	if !clamped {
		t.Error("exceeds-cap should report clamped")
	}
	if reason != "exceeds_hard_cap" {
		t.Errorf("reason = %q, want 'exceeds_hard_cap'", reason)
	}
}

func TestClampOverrideTTL_BelowMinimum(t *testing.T) {
	// 30 seconds, below 1min minimum
	ttl, clamped, reason := clampOverrideTTL(30)
	if ttl != OverrideMinTTL {
		t.Errorf("ttl = %v, want min %v", ttl, OverrideMinTTL)
	}
	if !clamped {
		t.Error("below-min should report clamped")
	}
	if reason != "below_minimum" {
		t.Errorf("reason = %q, want 'below_minimum'", reason)
	}
}

func TestClampOverrideTTL_ExactlyHardCap(t *testing.T) {
	ttl, clamped, _ := clampOverrideTTL(int64(OverrideHardCapTTL.Seconds()))
	if ttl != OverrideHardCapTTL {
		t.Errorf("ttl = %v, want %v", ttl, OverrideHardCapTTL)
	}
	if clamped {
		t.Error("exactly-cap should not report clamped")
	}
}

func TestClampOverrideTTL_ExactlyMin(t *testing.T) {
	ttl, clamped, _ := clampOverrideTTL(int64(OverrideMinTTL.Seconds()))
	if ttl != OverrideMinTTL {
		t.Errorf("ttl = %v, want %v", ttl, OverrideMinTTL)
	}
	if clamped {
		t.Error("exactly-min should not report clamped")
	}
}

func TestValidateCreateOverrideRequest_RequiresPolicyID(t *testing.T) {
	err := validateCreateOverrideRequest(&CreateOverrideRequest{
		PolicyType:     "static",
		OverrideReason: "need it",
	})
	if err == nil {
		t.Fatal("expected error for missing policy_id")
	}
}

func TestValidateCreateOverrideRequest_RequiresReason(t *testing.T) {
	err := validateCreateOverrideRequest(&CreateOverrideRequest{
		PolicyID:   "pol-1",
		PolicyType: "static",
	})
	if err == nil {
		t.Fatal("expected error for missing reason")
	}
}

func TestValidateCreateOverrideRequest_RejectsBlankReason(t *testing.T) {
	err := validateCreateOverrideRequest(&CreateOverrideRequest{
		PolicyID:       "pol-1",
		PolicyType:     "static",
		OverrideReason: "   ",
	})
	if err == nil {
		t.Fatal("expected error for whitespace-only reason")
	}
}

func TestValidateCreateOverrideRequest_RejectsInvalidType(t *testing.T) {
	err := validateCreateOverrideRequest(&CreateOverrideRequest{
		PolicyID:       "pol-1",
		PolicyType:     "invalid",
		OverrideReason: "need it",
	})
	if err == nil {
		t.Fatal("expected error for invalid policy_type")
	}
}

func TestValidateCreateOverrideRequest_AcceptsStatic(t *testing.T) {
	err := validateCreateOverrideRequest(&CreateOverrideRequest{
		PolicyID:       "pol-1",
		PolicyType:     "static",
		OverrideReason: "debugging",
	})
	if err != nil {
		t.Fatalf("expected no error for valid static request, got %v", err)
	}
}

func TestValidateCreateOverrideRequest_AcceptsDynamic(t *testing.T) {
	err := validateCreateOverrideRequest(&CreateOverrideRequest{
		PolicyID:       "pol-1",
		PolicyType:     "dynamic",
		OverrideReason: "debugging",
	})
	if err != nil {
		t.Fatalf("expected no error for valid dynamic request, got %v", err)
	}
}

// TestCreateOverrideHandler_RejectsMissingUserEmail locks in the ADR-044
// requirement that every override must be attributable to a user. An
// unauthenticated create (empty X-User-Email, X-User-ID) must 401 BEFORE
// any DB work, not silently produce an orphan record.
func TestCreateOverrideHandler_RejectsMissingUserEmail(t *testing.T) {
	body, _ := json.Marshal(CreateOverrideRequest{
		PolicyID:       "pol-1",
		PolicyType:     "static",
		OverrideReason: "test",
	})
	req := httptest.NewRequest("POST", "/api/v1/overrides", strings.NewReader(string(body)))
	req.Header.Set("X-Tenant-ID", "tenant-x")
	// deliberately no X-User-Email or X-User-ID

	rr := httptest.NewRecorder()
	createOverrideHandler(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("missing user identity: status = %d, want 401", rr.Code)
	}
}

// TestCreateOverrideHandler_RejectsMissingTenant locks in the requirement
// that a tenant header is required. This runs before DB work, so it's
// unit-testable without a live DB.
func TestCreateOverrideHandler_RejectsMissingTenant(t *testing.T) {
	body, _ := json.Marshal(CreateOverrideRequest{
		PolicyID:       "pol-1",
		PolicyType:     "static",
		OverrideReason: "test",
	})
	req := httptest.NewRequest("POST", "/api/v1/overrides", strings.NewReader(string(body)))
	req.Header.Set("X-User-Email", "dev@example.com")
	// deliberately no X-Tenant-ID

	rr := httptest.NewRecorder()
	createOverrideHandler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("missing tenant: status = %d, want 400", rr.Code)
	}
}

// TestRevokeOverrideHandler_RejectsMissingIdentityHeaders ensures the
// tenant + user identity checks run before any DB work. Per the security
// fix: a caller without both X-Tenant-ID and X-User-Email cannot attempt
// revocation against another tenant's overrides.
//
// Uses mux.SetURLVars to simulate mux routing in the unit test.
func TestRevokeOverrideHandler_RejectsMissingIdentityHeaders(t *testing.T) {
	mk := func(headers map[string]string) *http.Request {
		r := httptest.NewRequest("DELETE", "/api/v1/overrides/some-id", nil)
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		return mux.SetURLVars(r, map[string]string{"id": "some-id"})
	}

	// Case 1: no X-User-Email — should 401.
	rr1 := httptest.NewRecorder()
	revokeOverrideHandler(rr1, mk(map[string]string{"X-Tenant-ID": "tenant-x"}))
	if rr1.Code != http.StatusUnauthorized {
		t.Errorf("no user identity: status = %d, want 401", rr1.Code)
	}

	// Case 2: no X-Tenant-ID — should 400.
	rr2 := httptest.NewRecorder()
	revokeOverrideHandler(rr2, mk(map[string]string{"X-User-Email": "dev@example.com"}))
	if rr2.Code != http.StatusBadRequest {
		t.Errorf("no tenant: status = %d, want 400", rr2.Code)
	}
}

// TestGetOverrideHandler_RequiresTenantHeader ensures the security fix
// scoping GET by tenant. A caller without X-Tenant-ID cannot fetch an
// override (which would leak cross-tenant data).
func TestGetOverrideHandler_RequiresTenantHeader(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/overrides/some-id", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "some-id"})
	rr := httptest.NewRecorder()
	getOverrideHandler(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("no tenant: status = %d, want 400", rr.Code)
	}
}

func TestValidateCreateOverrideRequest_RejectsLongReason(t *testing.T) {
	longReason := make([]byte, OverrideReasonMaxLn+1)
	for i := range longReason {
		longReason[i] = 'x'
	}
	err := validateCreateOverrideRequest(&CreateOverrideRequest{
		PolicyID:       "pol-1",
		PolicyType:     "static",
		OverrideReason: string(longReason),
	})
	if err == nil {
		t.Fatal("expected error for reason > max length")
	}
}

// TestInvalidateCachedDeniedDecisions_Scopes locks in the #1607 cache-vs-
// override interaction: override create must purge denied workflow_steps
// cache rows for the tenant+user scope so the next idempotent step_gate
// call re-evaluates with the new override in effect.
func TestInvalidateCachedDeniedDecisions_Scopes(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	// The helper first resolves policy synonyms via two SELECT queries
	// against static_policies + dynamic_policies so cache rows that store
	// the policy name can still be matched. #3039: those lookups now run in
	// two org-scoped passes (tenant, then 'global'). Return empty rows so
	// only the caller-supplied policy_id is used as a synonym.
	for _, scope := range []string{"tenant-x", "global"} {
		mock.ExpectBegin()
		mock.ExpectExec("SELECT set_config\\('app.current_org_id', \\$1, true\\)").WithArgs(scope).WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery("SELECT policy_id, name FROM static_policies").
			WithArgs("pol-uuid", "tenant-x").
			WillReturnRows(sqlmock.NewRows([]string{"policy_id", "name"}))
		mock.ExpectQuery("SELECT '' AS policy_id, name FROM dynamic_policies").
			WithArgs("pol-uuid", "tenant-x").
			WillReturnRows(sqlmock.NewRows([]string{"policy_id", "name"}))
		mock.ExpectCommit()
	}

	mock.ExpectExec("DELETE FROM workflow_steps").
		WithArgs("tenant-x", "dev@example.com", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 3))

	invalidateCachedDeniedDecisions(context.Background(), db, "tenant-x", "dev@example.com", "pol-uuid")

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// TestInvalidateCachedDeniedDecisions_NoopWithoutScope refuses to touch the
// table when neither tenant nor user are known — guards against a
// pathological caller invalidating every other tenant's cache.
func TestInvalidateCachedDeniedDecisions_NoopWithoutScope(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	// No Expect* calls — if the helper fires any SQL, sqlmock will flag it.
	invalidateCachedDeniedDecisions(context.Background(), db, "", "", "pol-uuid")

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expected no SQL; got: %v", err)
	}
}

// TestInvalidateCachedDeniedDecisions_NoopWithoutPolicy skips work when the
// policy id is empty — the delete SQL has no way to target anything useful.
func TestInvalidateCachedDeniedDecisions_NoopWithoutPolicy(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	invalidateCachedDeniedDecisions(context.Background(), db, "tenant-x", "dev@example.com", "")

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expected no SQL; got: %v", err)
	}
}

// TestNullableUUID_ValidUUID covers the UUID-parse happy path.
func TestNullableUUID_ValidUUID(t *testing.T) {
	got := nullableUUID("550e8400-e29b-41d4-a716-446655440000")
	if !got.Valid {
		t.Error("expected Valid=true for well-formed UUID")
	}
	if got.String != "550e8400-e29b-41d4-a716-446655440000" {
		t.Errorf("String: got %q, want well-formed UUID", got.String)
	}
}

// TestNullableUUID_Empty returns an invalid NullString (= NULL in DB).
func TestNullableUUID_Empty(t *testing.T) {
	got := nullableUUID("")
	if got.Valid {
		t.Error("expected Valid=false for empty input")
	}
}

// TestNullableUUID_NonUUID exercises the community-mode slug path
// ("local-dev-org" fails uuid.Parse → NULL insert). Without this helper the
// driver would reject the insert with "invalid input syntax for type uuid".
func TestNullableUUID_NonUUID(t *testing.T) {
	got := nullableUUID("local-dev-org")
	if got.Valid {
		t.Error("expected Valid=false for non-UUID slug (must insert NULL, not error)")
	}
}
