//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package billing

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"axonflow/platform/agent/license"

	_ "github.com/lib/pq"
)

// DB-backed integration tests for the W4 billing service. Skip without
// DATABASE_URL — same pattern as community_saas_recovery_db_test.go and
// platform/agent/plugin_claim_middleware_db_test.go.
//
// Per FEATURE_RUNTIME_COVERAGE.md methodology: TestWebhook_DB_FullRuntimePath
// is the runtime-path test for PR E. It exercises:
//   - Real Stripe-Signature HMAC verification on the wire
//   - Real httptest server boot of the webhook handler
//   - Real INSERT into plugin_user_licenses through real Postgres
//   - Real Ed25519 signing in the response token
//   - Real ValidatePluginClaimToken round-trip on the issued token
//
// Together these prove the end-to-end Stripe→token→DB→agent-validate path
// works without mocks anywhere in the chain except Stripe itself (which
// we drive directly via signed test requests).

func getTestDBForBilling(t *testing.T) *sql.DB {
	t.Helper()
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("Skipping DB integration test: DATABASE_URL not set")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("Failed to open: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("Failed to ping: %v", err)
	}

	for _, table := range []string{"community_saas_registrations", "plugin_user_licenses"} {
		var exists bool
		if err := db.QueryRow(`SELECT EXISTS (
			SELECT FROM information_schema.tables WHERE table_name = $1
		)`, table).Scan(&exists); err != nil || !exists {
			t.Skipf("Skipping: %s table not present (migration 077 not applied?)", table)
		}
	}
	return db
}

// seedRegistrationForBilling inserts the FK parent row in
// community_saas_registrations so plugin_user_licenses INSERT can satisfy
// its FK constraint. Returns nothing; cleanup is registered via t.Cleanup.
func seedRegistrationForBilling(t *testing.T, db *sql.DB, tenantID, email string) {
	t.Helper()
	expiresAt := time.Now().UTC().Add(365 * 24 * time.Hour)
	_, err := db.Exec(`
		INSERT INTO community_saas_registrations
		  (tenant_id, secret_hash, secret_prefix, org_id, label, expires_at,
		   claimed_by_email, claimed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
		ON CONFLICT (tenant_id) DO NOTHING`,
		tenantID,
		"$2a$12$dummyhashdummyhashdummyhashdummyhashdummyhashdumm",
		"12345678",
		"axonflow-saas",
		"billing-test",
		expiresAt, email,
	)
	if err != nil {
		t.Fatalf("seed registration: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM community_saas_registrations WHERE tenant_id = $1`, tenantID)
	})
}

// uniqueBillingTenantID makes per-test tenant ids so concurrent CI runs
// don't collide on the FK or UNIQUE constraints.
func uniqueBillingTenantID(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("cs_billing_%d", time.Now().UnixNano())
}

// =============================================================================
// IssueLicense — happy path end-to-end with real DB
// =============================================================================

func TestIssueLicense_DB_HappyPath(t *testing.T) {
	db := getTestDBForBilling(t)
	defer db.Close()
	setupSigningKey(t)

	tenantID := uniqueBillingTenantID(t)
	email := fmt.Sprintf("happy-%d@axonflow-test.invalid", time.Now().UnixNano())
	seedRegistrationForBilling(t, db, tenantID, email)

	req := IssueRequest{
		TenantID:         tenantID,
		ClaimedByEmail:   email,
		StripeCustomerID: "cus_db_test",
		StripeSessionID:  fmt.Sprintf("cs_session_%d", time.Now().UnixNano()),
		Tier:             license.TierPro,
	}

	result, err := IssueLicense(context.Background(), db, req)
	if err != nil {
		t.Fatalf("IssueLicense: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM plugin_user_licenses WHERE license_id = $1::uuid`, result.LicenseID)
	})

	// Token round-trip
	payload, err := license.ValidatePluginClaimToken(result.Token)
	if err != nil {
		t.Fatalf("validate token: %v", err)
	}
	if payload.TenantID != tenantID {
		t.Errorf("token TenantID: got %q want %q", payload.TenantID, tenantID)
	}

	// DB row must exist with the right shape. Per-tier limits are looked up
	// via license.GetTierLimits(row.Tier) — there is no entitlements JSONB
	// blob to inspect (dropped in migration 080 per ADR-050 §6).
	var (
		dbTier     string
		dbJTI      string
		revoked    *time.Time
		dbStripeID string
	)
	err = db.QueryRow(`
		SELECT tier, license_token_jti, revoked_at,
		       COALESCE(stripe_customer_id, '')
		  FROM plugin_user_licenses
		 WHERE license_id = $1::uuid`, result.LicenseID,
	).Scan(&dbTier, &dbJTI, &revoked, &dbStripeID)
	if err != nil {
		t.Fatalf("read back row: %v", err)
	}
	if dbTier != "Pro" {
		t.Errorf("tier: got %q", dbTier)
	}
	if dbJTI != result.JTI {
		t.Errorf("jti: db=%q result=%q", dbJTI, result.JTI)
	}
	if revoked != nil {
		t.Errorf("freshly issued row should not be revoked: %v", *revoked)
	}
	if dbStripeID != "cus_db_test" {
		t.Errorf("stripe_customer_id: got %q", dbStripeID)
	}
	// Per-tier limits resolve through the typed TierLimits struct, not a
	// row-side JSONB blob. Asserting against the canonical Pro limits
	// preserves the original test's intent (Pro = 30-day retention) while
	// matching the post-migration-080 schema.
	if got := license.GetTierLimits(license.TierPro); got.AuditRetentionDays != 30 {
		t.Errorf("ProLimits.AuditRetentionDays: got %d, want 30", got.AuditRetentionDays)
	}
	if got := license.GetTierLimits(license.TierPro); got.DailyEventQuota != 2000 {
		t.Errorf("ProLimits.DailyEventQuota: got %d, want 2000", got.DailyEventQuota)
	}
}

// =============================================================================
// IssueLicense — second checkout for same tenant revokes prior, inserts new
// =============================================================================

func TestIssueLicense_DB_SecondCheckoutRevokesPrior(t *testing.T) {
	db := getTestDBForBilling(t)
	defer db.Close()
	setupSigningKey(t)

	tenantID := uniqueBillingTenantID(t)
	email := fmt.Sprintf("second-%d@axonflow-test.invalid", time.Now().UnixNano())
	seedRegistrationForBilling(t, db, tenantID, email)

	first, err := IssueLicense(context.Background(), db, IssueRequest{
		TenantID:         tenantID,
		ClaimedByEmail:   email,
		StripeCustomerID: "cus_first",
		StripeSessionID:  "cs_session_first",
		Tier:             license.TierPro,
	})
	if err != nil {
		t.Fatalf("first IssueLicense: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM plugin_user_licenses WHERE tenant_id = $1`, tenantID)
	})

	second, err := IssueLicense(context.Background(), db, IssueRequest{
		TenantID:         tenantID,
		ClaimedByEmail:   email,
		StripeCustomerID: "cus_second",
		StripeSessionID:  "cs_session_second",
		Tier:             license.TierPro,
	})
	if err != nil {
		t.Fatalf("second IssueLicense: %v", err)
	}

	// Prior row must now be revoked
	var firstRevoked *time.Time
	if err := db.QueryRow(`SELECT revoked_at FROM plugin_user_licenses WHERE license_id = $1::uuid`,
		first.LicenseID).Scan(&firstRevoked); err != nil {
		t.Fatalf("read first row: %v", err)
	}
	if firstRevoked == nil {
		t.Error("first row should be revoked after second purchase")
	}

	// Second row must be active
	var secondRevoked *time.Time
	if err := db.QueryRow(`SELECT revoked_at FROM plugin_user_licenses WHERE license_id = $1::uuid`,
		second.LicenseID).Scan(&secondRevoked); err != nil {
		t.Fatalf("read second row: %v", err)
	}
	if secondRevoked != nil {
		t.Errorf("second row should be active, got revoked_at=%v", *secondRevoked)
	}
}

// =============================================================================
// Webhook — full runtime path: real httptest server, real signed body,
// real DB write, response token validates end-to-end
// =============================================================================

func TestWebhook_DB_FullRuntimePath(t *testing.T) {
	db := getTestDBForBilling(t)
	defer db.Close()
	setupSigningKey(t)

	tenantID := uniqueBillingTenantID(t)
	email := fmt.Sprintf("webhook-%d@axonflow-test.invalid", time.Now().UnixNano())
	seedRegistrationForBilling(t, db, tenantID, email)

	now := time.Now().UTC()
	body := stripeCheckoutEvent(tenantID, email)
	header := signRequest(t, body, now, testSigningSecret)

	h := NewWebhookHandler(db, WebhookHandlerConfig{
		SigningSecret: testSigningSecret,
		ValidityDays:  90, // Pro V1 lock per PRD_TENANT_DURABILITY_AND_CLAIM
	})
	h.now = func() time.Time { return now }

	server := httptest.NewServer(h)
	defer server.Close()

	req, err := http.NewRequest(http.MethodPost, server.URL, strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set(stripeSignatureHeader, header)
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var out struct {
		Status    string `json:"status"`
		LicenseID string `json:"license_id"`
		Token     string `json:"token"`
		JTI       string `json:"jti"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM plugin_user_licenses WHERE license_id = $1::uuid`, out.LicenseID)
	})

	if out.Status != "issued" {
		t.Errorf("status: got %q", out.Status)
	}
	if !strings.HasPrefix(out.Token, "AXON-") {
		t.Errorf("token prefix: got %q", out.Token[:20])
	}

	// The token returned by the webhook MUST validate against the same
	// path the agent middleware (PR D) calls. If this breaks, billing
	// issues tokens the agent will reject — full system regression.
	payload, err := license.ValidatePluginClaimToken(out.Token)
	if err != nil {
		t.Fatalf("ValidatePluginClaimToken on webhook-issued token: %v", err)
	}
	if payload.TenantID != tenantID {
		t.Errorf("token tenant: got %q want %q", payload.TenantID, tenantID)
	}
	if payload.JTI != out.JTI {
		t.Errorf("jti mismatch: token=%q response=%q", payload.JTI, out.JTI)
	}

	// Confirm the row exists in DB and matches what the response said
	var dbTier string
	if err := db.QueryRow(`SELECT tier FROM plugin_user_licenses WHERE license_id = $1::uuid`,
		out.LicenseID).Scan(&dbTier); err != nil {
		t.Fatalf("read row: %v", err)
	}
	if dbTier != "Pro" {
		t.Errorf("db tier: got %q", dbTier)
	}
}

// =============================================================================
// IssueLicense — idempotency over StripeSessionID against real Postgres (GAP-2)
// =============================================================================

// TestIssueLicense_DB_IdempotentReplay proves the V1 guarantee end-to-end
// against real Postgres: replaying the same checkout.session.completed
// returns the SAME AXON token bytes and creates exactly ONE row in
// plugin_user_licenses. Without migration 079's UNIQUE partial index on
// stripe_session_id + the SELECT-then-re-mint flow, this would create N
// rows with N different tokens for N retries.
func TestIssueLicense_DB_IdempotentReplay(t *testing.T) {
	db := getTestDBForBilling(t)
	defer db.Close()
	setupSigningKey(t)

	tenantID := uniqueBillingTenantID(t)
	email := fmt.Sprintf("idem-%d@axonflow-test.invalid", time.Now().UnixNano())
	sessionID := fmt.Sprintf("cs_idem_%d", time.Now().UnixNano())
	seedRegistrationForBilling(t, db, tenantID, email)

	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM plugin_user_licenses WHERE tenant_id = $1`, tenantID)
	})

	req := IssueRequest{
		TenantID:         tenantID,
		ClaimedByEmail:   email,
		StripeCustomerID: "cus_idem",
		StripeSessionID:  sessionID,
		Tier:             license.TierPro,
	}

	first, err := IssueLicense(context.Background(), db, req)
	if err != nil {
		t.Fatalf("first IssueLicense: %v", err)
	}

	// Replay 1: identical request a few hundred ms later.
	second, err := IssueLicense(context.Background(), db, req)
	if err != nil {
		t.Fatalf("second IssueLicense (replay): %v", err)
	}

	// Replay 2: again, prove the dedup is durable.
	third, err := IssueLicense(context.Background(), db, req)
	if err != nil {
		t.Fatalf("third IssueLicense (replay): %v", err)
	}

	// All three must return the SAME token bytes.
	if first.Token != second.Token || second.Token != third.Token {
		t.Errorf("idempotency violated:\n  first:  %s\n  second: %s\n  third:  %s",
			first.Token[:40], second.Token[:40], third.Token[:40])
	}
	if first.JTI != second.JTI || second.JTI != third.JTI {
		t.Errorf("JTI mismatch across replays")
	}
	if first.LicenseID != second.LicenseID || second.LicenseID != third.LicenseID {
		t.Errorf("LicenseID mismatch across replays")
	}

	// And there must be exactly ONE row in plugin_user_licenses for this tenant.
	var rowCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM plugin_user_licenses WHERE tenant_id = $1`,
		tenantID).Scan(&rowCount); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if rowCount != 1 {
		t.Errorf("expected exactly 1 row after 3 replays, got %d (idempotency leaked rows)", rowCount)
	}

	// And the re-minted token must still validate end-to-end.
	if _, err := license.ValidatePluginClaimToken(third.Token); err != nil {
		t.Errorf("re-minted token does not validate: %v", err)
	}
}

// TestIssueLicense_DB_DifferentSessionsCoexistButOneActive verifies that
// idempotency does NOT collapse separate purchases. Two different session
// IDs for the same tenant produce two rows, but only one is active (prior
// is revoked).
func TestIssueLicense_DB_DifferentSessionsCoexistButOneActive(t *testing.T) {
	db := getTestDBForBilling(t)
	defer db.Close()
	setupSigningKey(t)

	tenantID := uniqueBillingTenantID(t)
	email := fmt.Sprintf("multi-%d@axonflow-test.invalid", time.Now().UnixNano())
	seedRegistrationForBilling(t, db, tenantID, email)

	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM plugin_user_licenses WHERE tenant_id = $1`, tenantID)
	})

	first, err := IssueLicense(context.Background(), db, IssueRequest{
		TenantID:         tenantID,
		ClaimedByEmail:   email,
		StripeCustomerID: "cus_a",
		StripeSessionID:  fmt.Sprintf("cs_a_%d", time.Now().UnixNano()),
		Tier:             license.TierPro,
	})
	if err != nil {
		t.Fatalf("first: %v", err)
	}

	second, err := IssueLicense(context.Background(), db, IssueRequest{
		TenantID:         tenantID,
		ClaimedByEmail:   email,
		StripeCustomerID: "cus_b",
		StripeSessionID:  fmt.Sprintf("cs_b_%d", time.Now().UnixNano()),
		Tier:             license.TierPro,
	})
	if err != nil {
		t.Fatalf("second: %v", err)
	}

	if first.Token == second.Token {
		t.Error("different sessions must produce different tokens")
	}

	var totalRows, activeRows int
	if err := db.QueryRow(`SELECT COUNT(*) FROM plugin_user_licenses WHERE tenant_id = $1`,
		tenantID).Scan(&totalRows); err != nil {
		t.Fatalf("count total: %v", err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM plugin_user_licenses WHERE tenant_id = $1 AND revoked_at IS NULL`,
		tenantID).Scan(&activeRows); err != nil {
		t.Fatalf("count active: %v", err)
	}
	if totalRows != 2 {
		t.Errorf("expected 2 total rows, got %d", totalRows)
	}
	if activeRows != 1 {
		t.Errorf("expected exactly 1 active row, got %d", activeRows)
	}
}
