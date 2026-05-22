//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package billing

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"axonflow/platform/agent/license"

	"github.com/DATA-DOG/go-sqlmock"
)

// setupSigningKey installs a fresh Ed25519 signing key in the env so the
// license package's Generate path can sign tokens without a real KMS hit.
func setupSigningKey(t *testing.T) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	t.Setenv("AXONFLOW_PLUGIN_CLAIMED_SIGNING_KEY", base64.StdEncoding.EncodeToString(priv.Seed()))
}

// =============================================================================
// IssueRequest.Validate — input validation
// =============================================================================

func TestIssueRequest_Validate(t *testing.T) {
	good := IssueRequest{
		TenantID:         "cs_abc",
		ClaimedByEmail:   "alice@example.com",
		StripeCustomerID: "cus_test",
		StripeSessionID:  "cs_session",
		Tier:             license.TierPro,
	}

	cases := []struct {
		name    string
		mut     func(*IssueRequest)
		wantErr string
	}{
		{"good", func(r *IssueRequest) {}, ""},
		{"missing TenantID", func(r *IssueRequest) { r.TenantID = "" }, "TenantID"},
		{"missing Email", func(r *IssueRequest) { r.ClaimedByEmail = "" }, "ClaimedByEmail"},
		// StripeCustomerID intentionally NOT validated — Stripe Payment
		// Link checkouts arrive with customer=null when customer_creation
		// is "if_required" (V1 setup). Empty value is allowed.
		{"missing SessionID", func(r *IssueRequest) { r.StripeSessionID = "" }, "StripeSessionID"},
		{"missing Tier", func(r *IssueRequest) { r.Tier = "" }, "Tier is required"},
		{"wrong Tier", func(r *IssueRequest) { r.Tier = license.TierEnterprise }, "must be Pro or Premium"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := good
			tc.mut(&r)
			err := r.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("expected nil, got %v", err)
				}
			} else {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("want error containing %q, got %v", tc.wantErr, err)
				}
			}
		})
	}
}

// =============================================================================
// IssueLicense — invalid input / nil DB
// =============================================================================

func TestIssueLicense_NilDB_Errors(t *testing.T) {
	_, err := IssueLicense(context.Background(), nil, IssueRequest{
		TenantID:         "cs_abc",
		ClaimedByEmail:   "x@y.com",
		StripeCustomerID: "cus_x",
		StripeSessionID:  "cs_s",
		Tier:             license.TierPro,
	})
	if err == nil || !strings.Contains(err.Error(), "db is nil") {
		t.Errorf("expected db-nil error, got %v", err)
	}
}

func TestIssueLicense_InvalidRequest_Errors(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()
	_, err := IssueLicense(context.Background(), db, IssueRequest{}) // empty
	if err == nil || !strings.Contains(err.Error(), "invalid IssueRequest") {
		t.Errorf("expected invalid-request error, got %v", err)
	}
}

// =============================================================================
// IssueLicense — happy path with sqlmock
// =============================================================================

func TestIssueLicense_HappyPath_RevokesPriorAndInserts(t *testing.T) {
	setupSigningKey(t)
	db, mock, _ := sqlmock.New()
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT pg_advisory_xact_lock`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT license_id::text, tenant_id, claimed_by_email, tier`).
		WithArgs("cs_session").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(`UPDATE plugin_user_licenses\s+SET revoked_at = NOW\(\)`).
		WithArgs("cs_abc", "cs_session").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`INSERT INTO plugin_user_licenses`).
		WithArgs(
			"cs_abc", "alice@example.com", "Pro",
			sqlmock.AnyArg(), // jti
			"cus_test", "cs_session",
			sqlmock.AnyArg(), // issued_at
			sqlmock.AnyArg(), // stripe_payment_intent_id (sql.NullString — Valid:false here since req omits it)
		).
		WillReturnRows(sqlmock.NewRows([]string{"license_id", "issued_at"}).
			AddRow("11111111-2222-3333-4444-555555555555", time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)))
	mock.ExpectCommit()

	result, err := IssueLicense(context.Background(), db, IssueRequest{
		TenantID:         "cs_abc",
		ClaimedByEmail:   "alice@example.com",
		StripeCustomerID: "cus_test",
		StripeSessionID:  "cs_session",
		Tier:             license.TierPro,
	})
	if err != nil {
		t.Fatalf("IssueLicense: %v", err)
	}
	if result.LicenseID == "" {
		t.Error("LicenseID should be populated")
	}
	if !strings.HasPrefix(result.Token, "AXON-") {
		t.Errorf("Token should start with AXON-, got: %s", result.Token[:30])
	}
	if result.JTI == "" {
		t.Error("JTI should be populated")
	}
	if result.TenantID != "cs_abc" {
		t.Errorf("TenantID round-trip mismatch: got %q", result.TenantID)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock expectations: %v", err)
	}
}

// TestIssueLicense_StoresPaymentIntent regression-guards #1895: when the
// caller supplies a non-empty StripePaymentIntentID, the INSERT must pass
// the value as the $8 parameter so it lands in
// plugin_user_licenses.stripe_payment_intent_id. The charge.refunded
// auto-revoke handler later looks the row up via this column; if this
// stops getting populated, every real refund silently no-ops (which is
// exactly the regression that prompted Option A).
//
// We use a sqlmock argument matcher that asserts the 8th arg is
// sql.NullString{String: "pi_test_xyz", Valid: true} — a bare equality
// check on the wrapped value would be fragile across go-sqlmock versions.
func TestIssueLicense_StoresPaymentIntent(t *testing.T) {
	setupSigningKey(t)
	db, mock, _ := sqlmock.New()
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT pg_advisory_xact_lock`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT license_id::text, tenant_id, claimed_by_email, tier`).
		WithArgs("cs_session_pi").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(`UPDATE plugin_user_licenses`).
		WithArgs("cs_abc_pi", "cs_session_pi").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`INSERT INTO plugin_user_licenses[\s\S]*stripe_payment_intent_id`).
		WithArgs(
			"cs_abc_pi", "alice@example.com", "Pro",
			sqlmock.AnyArg(), // jti
			"cus_test_pi", "cs_session_pi",
			sqlmock.AnyArg(), // issued_at
			// $8 = stripe_payment_intent_id — sqlmock unwraps the
			// driver.Valuer (sql.NullString) and matches the underlying
			// string value when Valid=true.
			"pi_test_xyz",
		).
		WillReturnRows(sqlmock.NewRows([]string{"license_id", "issued_at"}).
			AddRow("22222222-3333-4444-5555-666666666666", time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)))
	mock.ExpectCommit()

	_, err := IssueLicense(context.Background(), db, IssueRequest{
		TenantID:              "cs_abc_pi",
		ClaimedByEmail:        "alice@example.com",
		StripeCustomerID:      "cus_test_pi",
		StripeSessionID:       "cs_session_pi",
		StripePaymentIntentID: "pi_test_xyz",
		Tier:                  license.TierPro,
	})
	if err != nil {
		t.Fatalf("IssueLicense: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("INSERT didn't include stripe_payment_intent_id arg: %v", err)
	}
}

// =============================================================================
// IssueLicense — tx rollback paths
// =============================================================================

func TestIssueLicense_RevokeExecFails_RollsBack(t *testing.T) {
	setupSigningKey(t)
	db, mock, _ := sqlmock.New()
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT pg_advisory_xact_lock`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT license_id::text, tenant_id, claimed_by_email, tier`).
		WithArgs("cs_s").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(`UPDATE plugin_user_licenses`).
		WithArgs("cs_abc", "cs_s").
		WillReturnError(errors.New("connection lost"))
	mock.ExpectRollback()

	_, err := IssueLicense(context.Background(), db, IssueRequest{
		TenantID:         "cs_abc",
		ClaimedByEmail:   "x@y.com",
		StripeCustomerID: "cus_x",
		StripeSessionID:  "cs_s",
		Tier:             license.TierPro,
	})
	if err == nil || !strings.Contains(err.Error(), "revoke prior active row") {
		t.Errorf("expected revoke error, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock expectations: %v", err)
	}
}

func TestIssueLicense_InsertFails_RollsBack(t *testing.T) {
	setupSigningKey(t)
	db, mock, _ := sqlmock.New()
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT pg_advisory_xact_lock`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT license_id::text, tenant_id, claimed_by_email, tier`).
		WithArgs("cs_s").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(`UPDATE plugin_user_licenses`).
		WithArgs("cs_abc", "cs_s").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`INSERT INTO plugin_user_licenses`).
		WillReturnError(errors.New("UNIQUE constraint violation on license_token_jti"))
	mock.ExpectRollback()

	_, err := IssueLicense(context.Background(), db, IssueRequest{
		TenantID:         "cs_abc",
		ClaimedByEmail:   "x@y.com",
		StripeCustomerID: "cus_x",
		StripeSessionID:  "cs_s",
		Tier:             license.TierPro,
	})
	if err == nil || !strings.Contains(err.Error(), "insert plugin_user_licenses") {
		t.Errorf("expected insert error, got %v", err)
	}
}

func TestIssueLicense_BeginTxFails_NoSilentSwallow(t *testing.T) {
	setupSigningKey(t)
	db, mock, _ := sqlmock.New()
	defer db.Close()

	mock.ExpectBegin().WillReturnError(errors.New("database is starting up"))

	_, err := IssueLicense(context.Background(), db, IssueRequest{
		TenantID:         "cs_abc",
		ClaimedByEmail:   "x@y.com",
		StripeCustomerID: "cus_x",
		StripeSessionID:  "cs_s",
		Tier:             license.TierPro,
	})
	if err == nil || !strings.Contains(err.Error(), "begin tx") {
		t.Errorf("expected begin-tx error, got %v", err)
	}
}

// =============================================================================
// Round-trip: token issued by IssueLicense validates via the same code path
// the agent middleware (PR D) will use
// =============================================================================

func TestIssueLicense_TokenValidatesEndToEnd(t *testing.T) {
	setupSigningKey(t)
	db, mock, _ := sqlmock.New()
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT pg_advisory_xact_lock`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT license_id::text, tenant_id, claimed_by_email, tier`).
		WithArgs("cs_session").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(`UPDATE plugin_user_licenses`).WithArgs("cs_abc", "cs_session").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`INSERT INTO plugin_user_licenses`).
		WillReturnRows(sqlmock.NewRows([]string{"license_id", "issued_at"}).
			AddRow("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", time.Now().UTC()))
	mock.ExpectCommit()

	result, err := IssueLicense(context.Background(), db, IssueRequest{
		TenantID:         "cs_abc",
		ClaimedByEmail:   "alice@example.com",
		StripeCustomerID: "cus_test",
		StripeSessionID:  "cs_session",
		Tier:             license.TierPro,
	})
	if err != nil {
		t.Fatalf("IssueLicense: %v", err)
	}

	// The token IssueLicense returned must validate against the agent's
	// ValidatePluginClaimToken path. If this breaks, the whole tier system
	// is broken — billing issues tokens the agent rejects.
	payload, err := license.ValidatePluginClaimToken(result.Token)
	if err != nil {
		t.Fatalf("ValidatePluginClaimToken on freshly-issued token: %v", err)
	}
	if payload.TenantID != "cs_abc" {
		t.Errorf("token TenantID round-trip: got %q", payload.TenantID)
	}
	if payload.Email != "alice@example.com" {
		t.Errorf("token Email round-trip: got %q", payload.Email)
	}
	if payload.JTI != result.JTI {
		t.Errorf("JTI mismatch between IssueResult and decoded token: %q vs %q", result.JTI, payload.JTI)
	}
}

// =============================================================================
// IssueLicense — idempotency over StripeSessionID (GAP-2)
// =============================================================================

// TestIssueLicense_Idempotent_SameSessionReturnsSameToken proves the V1
// guarantee: if Stripe retries the same checkout.session.completed event,
// the buyer gets the SAME AXON token back, not a new one. Without this
// the buyer's first email contains a token that gets revoked seconds later
// by the webhook retry — the second email arrives with a different working
// token, but the buyer has already saved the first.
//
// Mechanism: SELECT existing row by stripe_session_id at the top of tx.
// If found, re-mint via deterministic Ed25519 signing (same JTI + IssuedAt
// + payload = same signature bytes). No revoke, no new INSERT.
func TestIssueLicense_Idempotent_SameSessionReturnsSameToken(t *testing.T) {
	setupSigningKey(t)
	db, mock, _ := sqlmock.New()
	defer db.Close()

	// Pin the issuer's clock so the token IssuedAt baked into the first
	// call matches the row.IssuedAt the SELECT mock returns on the second
	// call. Without pinning, time.Now() produces a different YYYYMMDD than
	// the fixture and the deterministic re-mint produces a byte-different
	// token. Production doesn't have this fragility — the same wall clock
	// is used at INSERT and is read back via RETURNING.
	originalIssuedAt := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	prevNow := nowFn
	nowFn = func() time.Time { return originalIssuedAt }
	t.Cleanup(func() { nowFn = prevNow })

	// First call: no existing row, normal flow
	originalJTI := ""
	originalLicenseID := "11111111-2222-3333-4444-555555555555"
	originalEmail := "alice@example.com"
	originalTenant := "cs_abc"
	originalSession := "cs_idempotent_test"

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT pg_advisory_xact_lock`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT license_id::text, tenant_id, claimed_by_email, tier`).
		WithArgs(originalSession).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(`UPDATE plugin_user_licenses`).WithArgs(originalTenant, originalSession).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`INSERT INTO plugin_user_licenses`).
		WillReturnRows(sqlmock.NewRows([]string{"license_id", "issued_at"}).
			AddRow(originalLicenseID, originalIssuedAt))
	mock.ExpectCommit()

	first, err := IssueLicense(context.Background(), db, IssueRequest{
		TenantID:         originalTenant,
		ClaimedByEmail:   originalEmail,
		StripeCustomerID: "cus_x",
		StripeSessionID:  originalSession,
		Tier:             license.TierPro,
	})
	if err != nil {
		t.Fatalf("first IssueLicense: %v", err)
	}
	originalJTI = first.JTI

	// Second call (Stripe retry): SELECT finds the existing row, no revoke,
	// no new INSERT. The re-mint path runs.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT pg_advisory_xact_lock`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT license_id::text, tenant_id, claimed_by_email, tier`).
		WithArgs(originalSession).
		WillReturnRows(sqlmock.NewRows([]string{
			"license_id", "tenant_id", "claimed_by_email", "tier",
			"license_token_jti", "issued_at",
		}).AddRow(
			originalLicenseID, originalTenant, originalEmail,
			string(license.TierPro), originalJTI, originalIssuedAt,
		))
	mock.ExpectCommit()

	second, err := IssueLicense(context.Background(), db, IssueRequest{
		TenantID:         originalTenant,
		ClaimedByEmail:   originalEmail,
		StripeCustomerID: "cus_x",
		StripeSessionID:  originalSession,
		Tier:             license.TierPro,
	})
	if err != nil {
		t.Fatalf("second IssueLicense (replay): %v", err)
	}

	// THE assertion: same token bytes back.
	if second.Token != first.Token {
		t.Errorf("idempotency violated: replay returned different token\n  first:  %s\n  second: %s",
			first.Token[:40], second.Token[:40])
	}
	if second.JTI != first.JTI {
		t.Errorf("JTI mismatch on replay: %q vs %q", first.JTI, second.JTI)
	}
	if second.LicenseID != first.LicenseID {
		t.Errorf("LicenseID mismatch on replay: %q vs %q", first.LicenseID, second.LicenseID)
	}
	if !second.IssuedAt.Equal(first.IssuedAt) {
		t.Errorf("IssuedAt mismatch on replay: %v vs %v", first.IssuedAt, second.IssuedAt)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock expectations: %v", err)
	}
}

// TestIssueLicense_NewSessionForSameTenant_IssuesFreshToken verifies that
// idempotency is scoped to stripe_session_id, NOT to tenant_id. A buyer who
// purchases a second time legitimately gets a new token; the prior token's
// row is revoked.
func TestIssueLicense_NewSessionForSameTenant_IssuesFreshToken(t *testing.T) {
	setupSigningKey(t)
	db, mock, _ := sqlmock.New()
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT pg_advisory_xact_lock`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT license_id::text, tenant_id, claimed_by_email, tier`).
		WithArgs("cs_second_purchase").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(`UPDATE plugin_user_licenses`).WithArgs("cs_abc", "cs_second_purchase").
		WillReturnResult(sqlmock.NewResult(0, 1)) // 1 prior row revoked
	mock.ExpectQuery(`INSERT INTO plugin_user_licenses`).
		WillReturnRows(sqlmock.NewRows([]string{"license_id", "issued_at"}).
			AddRow("33333333-4444-5555-6666-777777777777", time.Now().UTC()))
	mock.ExpectCommit()

	result, err := IssueLicense(context.Background(), db, IssueRequest{
		TenantID:         "cs_abc",
		ClaimedByEmail:   "alice@example.com",
		StripeCustomerID: "cus_x",
		StripeSessionID:  "cs_second_purchase",
		Tier:             license.TierPro,
	})
	if err != nil {
		t.Fatalf("IssueLicense: %v", err)
	}
	if result.LicenseID != "33333333-4444-5555-6666-777777777777" {
		t.Errorf("expected new license_id, got %q", result.LicenseID)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock expectations: %v", err)
	}
}

// TestIssueLicense_RemintRejectsNonPluginTierStored is a defense-in-depth
// check: if the stored row's tier is somehow corrupted to a non-plugin tier
// (data corruption, manual SQL, future bug), the re-mint must refuse rather
// than issue a token claiming a tier the buyer never paid for.
func TestIssueLicense_RemintRejectsNonPluginTierStored(t *testing.T) {
	setupSigningKey(t)
	db, mock, _ := sqlmock.New()
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT pg_advisory_xact_lock`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT license_id::text, tenant_id, claimed_by_email, tier`).
		WithArgs("cs_corrupt").
		WillReturnRows(sqlmock.NewRows([]string{
			"license_id", "tenant_id", "claimed_by_email", "tier",
			"license_token_jti", "issued_at",
		}).AddRow(
			"corrupt-id", "cs_abc", "alice@example.com",
			string(license.TierEnterprise), // <-- corrupted: not a plugin tier
			"some-jti", time.Now(),
		))
	mock.ExpectRollback()

	_, err := IssueLicense(context.Background(), db, IssueRequest{
		TenantID:         "cs_abc",
		ClaimedByEmail:   "alice@example.com",
		StripeCustomerID: "cus_x",
		StripeSessionID:  "cs_corrupt",
		Tier:             license.TierPro,
	})
	if err == nil || !strings.Contains(err.Error(), "not a SaaS Plugin tier") {
		t.Errorf("expected refusal on corrupt-tier row, got %v", err)
	}
}

// TestIssueLicense_PerTenantLockAcquired_BeforeIdempotencyCheck regression-
// guards the GAP-2 race fix. The concurrent-webhook scenario is:
//
//	T1: BEGIN -> lock(tenant) -> SELECT idempotency (none) -> UPDATE revoke
//	             -> INSERT row -> COMMIT (releases lock)
//	T2: BEGIN -> lock(tenant) — BLOCKS until T1 commits
//	             -> SELECT idempotency (finds T1's row) -> re-mint -> COMMIT
//
// Without the lock, T2's UPDATE could revoke T1's just-committed row before
// T2 falls through to ON CONFLICT + re-mint, returning a token whose row
// has revoked_at set — middleware would reject it.
//
// This test asserts the lock is acquired BEFORE the idempotency SELECT.
// sqlmock enforces strict expectation order; if a future refactor reorders
// or drops the lock, this test fails immediately.
func TestIssueLicense_PerTenantLockAcquired_BeforeIdempotencyCheck(t *testing.T) {
	setupSigningKey(t)
	db, mock, _ := sqlmock.New()
	defer db.Close()

	mock.ExpectBegin()
	// Lock MUST be the first statement after BEGIN.
	mock.ExpectExec(`SELECT pg_advisory_xact_lock\(hashtext\(\$1\)::bigint\)`).
		WithArgs("cs_lock_test").
		WillReturnResult(sqlmock.NewResult(0, 0))
	// THEN the idempotency check.
	mock.ExpectQuery(`SELECT license_id::text, tenant_id, claimed_by_email, tier`).
		WithArgs("cs_lock_session").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(`UPDATE plugin_user_licenses`).
		WithArgs("cs_lock_test", "cs_lock_session").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`INSERT INTO plugin_user_licenses`).
		WillReturnRows(sqlmock.NewRows([]string{"license_id", "issued_at"}).
			AddRow("lock-test-id", time.Now().UTC()))
	mock.ExpectCommit()

	_, err := IssueLicense(context.Background(), db, IssueRequest{
		TenantID:         "cs_lock_test",
		ClaimedByEmail:   "lock@example.com",
		StripeCustomerID: "cus_lock",
		StripeSessionID:  "cs_lock_session",
		Tier:             license.TierPro,
	})
	if err != nil {
		t.Fatalf("IssueLicense: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock expectations not met (lock-then-idempotency order broken): %v", err)
	}
}

// TestIssueLicense_RevokeUpdate_ExcludesNewSession is a defense-in-depth
// regression for GAP-2: even with the per-tenant lock, the UPDATE that
// revokes prior active rows must NEVER touch a row matching this session's
// stripe_session_id. The IS DISTINCT FROM clause achieves that NULL-safely.
//
// sqlmock's WithArgs check enforces both the tenant_id AND session_id args
// reach the UPDATE — if a future refactor drops the session_id arg, this
// test fails because the mock expects 2 args.
func TestIssueLicense_RevokeUpdate_ExcludesNewSession(t *testing.T) {
	setupSigningKey(t)
	db, mock, _ := sqlmock.New()
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT pg_advisory_xact_lock`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT license_id::text, tenant_id, claimed_by_email, tier`).
		WithArgs("cs_distinct_session").
		WillReturnError(sql.ErrNoRows)
	// The UPDATE MUST receive both args; the IS DISTINCT FROM clause depends
	// on the session_id parameter being passed.
	mock.ExpectExec(`UPDATE plugin_user_licenses[\s\S]*IS DISTINCT FROM`).
		WithArgs("cs_distinct_test", "cs_distinct_session").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`INSERT INTO plugin_user_licenses`).
		WillReturnRows(sqlmock.NewRows([]string{"license_id", "issued_at"}).
			AddRow("distinct-id", time.Now().UTC()))
	mock.ExpectCommit()

	_, err := IssueLicense(context.Background(), db, IssueRequest{
		TenantID:         "cs_distinct_test",
		ClaimedByEmail:   "distinct@example.com",
		StripeCustomerID: "cus_d",
		StripeSessionID:  "cs_distinct_session",
		Tier:             license.TierPro,
	})
	if err != nil {
		t.Fatalf("IssueLicense: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("UPDATE didn't include session_id arg or IS DISTINCT FROM clause: %v", err)
	}
}

// TestIssueLicense_INSERTWritesClientIDColumn is the v9 A+B integration
// guard (Epic #2230 Phase 2/4): after migration 088 added the client_id
// column on plugin_user_licenses, the INSERT path must populate it.
// Mirrors tenant_id during the v9 compat window per ADR-052 (Plugin Pro
// stays credential-scoped). Without this column write, every NEW Pro
// purchase post-merge lands with client_id=NULL.
//
// Mutation guard: the regex pins the EXACT column-list shape
// `(tenant_id, client_id, claimed_by_email,...)` with $1 reused as the
// client_id binding. Dropping client_id, reordering columns, or binding
// client_id to a different placeholder fails the test.
func TestIssueLicense_INSERTWritesClientIDColumn(t *testing.T) {
	setupSigningKey(t)
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT pg_advisory_xact_lock`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT license_id::text, tenant_id, claimed_by_email, tier`).
		WithArgs("cs_session_v9").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(`UPDATE plugin_user_licenses`).
		WithArgs("cs_abc_v9", "cs_session_v9").
		WillReturnResult(sqlmock.NewResult(0, 0))
	// Exact shape: tenant_id + client_id both present, VALUES binds $1
	// to both columns (so they always carry the same value during v9).
	mock.ExpectQuery(`INSERT INTO plugin_user_licenses\s+\(tenant_id, client_id, claimed_by_email, tier, license_token_jti,\s+stripe_customer_id, stripe_session_id, issued_at,\s+stripe_payment_intent_id\)\s+VALUES \(\$1, \$1, \$2, \$3, \$4, \$5, \$6, \$7, \$8\)`).
		WillReturnRows(sqlmock.NewRows([]string{"license_id", "issued_at"}).
			AddRow("33333333-4444-5555-6666-777777777777", time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)))
	mock.ExpectCommit()

	_, err = IssueLicense(context.Background(), db, IssueRequest{
		TenantID:         "cs_abc_v9",
		ClaimedByEmail:   "alice@example.com",
		StripeCustomerID: "cus_test_v9",
		StripeSessionID:  "cs_session_v9",
		Tier:             license.TierPro,
	})
	if err != nil {
		t.Fatalf("IssueLicense: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("INSERT shape missing v9 client_id: %v", err)
	}
}
