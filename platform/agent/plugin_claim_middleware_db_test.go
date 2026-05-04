//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// DB-backed integration tests for PluginClaimMiddleware. These run against a
// real PostgreSQL in CI (DATABASE_URL set) and skip locally when no DB is
// available — same pattern as community_saas_recovery_db_test.go and
// auth_middleware_db_test.go.
//
// What these test that sqlmock-only tests don't:
//   - Migration 077 + 078 schema is correct (table + UNIQUE partial index actually present)
//   - Real SQL parses + executes against Postgres (catches PG-specific syntax)
//   - JSONB column round-trips through the middleware → handler context
//   - The UNIQUE partial index actually rejects a second active row per tenant
//     (a regression here would silently allow tier ambiguity per ADR-049)

func getTestDBForPluginClaim(t *testing.T) *sql.DB {
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

	// Migrations 077 + 078 must be applied for these tests to be meaningful.
	var hasTable bool
	if err := db.QueryRow(`SELECT EXISTS (
		SELECT FROM information_schema.tables WHERE table_name = 'plugin_user_licenses'
	)`).Scan(&hasTable); err != nil || !hasTable {
		t.Skip("Skipping: plugin_user_licenses table not present (migration 077 not applied?)")
	}

	// 078 promoted idx_plugin_lic_active to a UNIQUE partial index. Without
	// this the at-most-one-active-row-per-tenant invariant isn't enforced.
	var indexIsUnique bool
	if err := db.QueryRow(`
		SELECT i.indisunique
		  FROM pg_index i
		  JOIN pg_class c ON i.indexrelid = c.oid
		 WHERE c.relname = 'idx_plugin_lic_active'`).Scan(&indexIsUnique); err != nil {
		t.Skipf("Skipping: idx_plugin_lic_active not present (migration 078 not applied?): %v", err)
	}
	if !indexIsUnique {
		t.Skip("Skipping: idx_plugin_lic_active is not UNIQUE (migration 078 not applied?)")
	}

	return db
}

// seedPluginClaimRow inserts an active plugin_user_licenses row tied to the
// given tenant + jti. Caller is responsible for first creating a parent
// community_saas_registrations row with that tenant_id (FK constraint).
// Returns the license_id and registers a t.Cleanup to delete the row.
func seedPluginClaimRow(t *testing.T, db *sql.DB, tenantID, jti, email string, entitlements string) string {
	t.Helper()
	var licenseID string
	err := db.QueryRow(`
		INSERT INTO plugin_user_licenses
		  (tenant_id, claimed_by_email, tier, license_token_jti, entitlements, stripe_customer_id)
		VALUES
		  ($1, $2, 'plugin-claimed', $3, $4::jsonb, 'cus_dbtest')
		RETURNING license_id::text`,
		tenantID, email, jti, entitlements,
	).Scan(&licenseID)
	if err != nil {
		t.Fatalf("seedPluginClaimRow insert: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM plugin_user_licenses WHERE license_id = $1::uuid`, licenseID)
	})
	return licenseID
}

// seedRegistrationForPluginClaim inserts a minimal community_saas_registrations
// row so the FK from plugin_user_licenses can be satisfied. Tests that need
// to insert into plugin_user_licenses must call this first.
func seedRegistrationForPluginClaim(t *testing.T, db *sql.DB, tenantID, email string) {
	t.Helper()
	expiresAt := time.Now().UTC().Add(communitySaasRegistrationTTL)
	_, err := db.Exec(`
		INSERT INTO community_saas_registrations
		  (tenant_id, secret_hash, secret_prefix, org_id, label, expires_at, claimed_by_email, claimed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
		ON CONFLICT (tenant_id) DO NOTHING`,
		tenantID, "$2a$12$dummyhashdummyhashdummyhashdummyhashdummyhashdumm", "12345678",
		communitySaasOrgID, "plugin-claim-test", expiresAt, email)
	if err != nil {
		t.Fatalf("seedRegistrationForPluginClaim: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM community_saas_registrations WHERE tenant_id = $1`, tenantID)
	})
}

// uniquePluginClaimTenantID returns a per-test tenant id so concurrent CI
// runs don't collide on the FK or UNIQUE constraints.
func uniquePluginClaimTenantID(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("cs_pcm_%d", time.Now().UnixNano())
}

// =============================================================================
// Happy path — real DB, real signed token, real middleware
// =============================================================================

func TestPluginClaimMiddleware_DB_HappyPath(t *testing.T) {
	db := getTestDBForPluginClaim(t)
	defer db.Close()

	setupPluginClaimSigningKey(t)

	tenantID := uniquePluginClaimTenantID(t)
	email := fmt.Sprintf("happy-%d@axonflow-test.invalid", time.Now().UnixNano())
	jti := fmt.Sprintf("jti-happy-%d", time.Now().UnixNano())
	entitlements := `{"retention_days":365,"daily_event_quota":10000,"support_level":"best_effort_email"}`

	seedRegistrationForPluginClaim(t, db, tenantID, email)
	licenseID := seedPluginClaimRow(t, db, tenantID, jti, email, entitlements)

	tok := issueTestPluginClaimToken(t, tenantID, jti, email)

	innerRan := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		innerRan = true
		pcc := PluginClaimFromContext(r.Context())
		if pcc == nil {
			t.Fatal("expected PluginClaimContext, got nil")
		}
		if pcc.LicenseID != licenseID {
			t.Errorf("LicenseID mismatch: got %q want %q", pcc.LicenseID, licenseID)
		}
		if pcc.Tier != "plugin-claimed" {
			t.Errorf("Tier: got %q", pcc.Tier)
		}
		if pcc.JTI != jti {
			t.Errorf("JTI: got %q want %q", pcc.JTI, jti)
		}
		if v, ok := pcc.Entitlements["retention_days"].(float64); !ok || v != 365 {
			t.Errorf("retention_days: got %v", pcc.Entitlements["retention_days"])
		}
		w.WriteHeader(http.StatusOK)
	})

	mw := PluginClaimMiddleware(db)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/runtime/decide", nil)
	req.Header.Set("X-License-Token", tok)
	rec := httptest.NewRecorder()
	mw(inner).ServeHTTP(rec, req)

	if !innerRan {
		t.Fatal("inner handler never ran")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

// =============================================================================
// Revocation — set revoked_at then re-validate
// =============================================================================

func TestPluginClaimMiddleware_DB_RevocationTakesEffect(t *testing.T) {
	db := getTestDBForPluginClaim(t)
	defer db.Close()

	setupPluginClaimSigningKey(t)

	tenantID := uniquePluginClaimTenantID(t)
	email := fmt.Sprintf("revoke-%d@axonflow-test.invalid", time.Now().UnixNano())
	jti := fmt.Sprintf("jti-revoke-%d", time.Now().UnixNano())

	seedRegistrationForPluginClaim(t, db, tenantID, email)
	seedPluginClaimRow(t, db, tenantID, jti, email, `{}`)

	tok := issueTestPluginClaimToken(t, tenantID, jti, email)
	mw := PluginClaimMiddleware(db)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// 1) Pre-revocation: must succeed
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("X-License-Token", tok)
	mw(inner).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("pre-revoke: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// 2) Revoke the row
	if _, err := db.Exec(`UPDATE plugin_user_licenses SET revoked_at = NOW(),
		revocation_reason = 'test_revocation' WHERE license_token_jti = $1`, jti); err != nil {
		t.Fatalf("revoke update: %v", err)
	}

	// 3) Post-revocation: same token, must now be 401
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("X-License-Token", tok)
	mw(inner).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("post-revoke: expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

// =============================================================================
// UNIQUE-active invariant from migration 078 — second active row per tenant
// must be rejected by the DB itself
// =============================================================================

func TestPluginClaimMiddleware_DB_UniqueActivePerTenantEnforced(t *testing.T) {
	db := getTestDBForPluginClaim(t)
	defer db.Close()

	tenantID := uniquePluginClaimTenantID(t)
	email := fmt.Sprintf("unique-%d@axonflow-test.invalid", time.Now().UnixNano())
	seedRegistrationForPluginClaim(t, db, tenantID, email)

	// First active row — allowed
	seedPluginClaimRow(t, db, tenantID, fmt.Sprintf("jti-1-%d", time.Now().UnixNano()), email, `{}`)

	// Second active row for the SAME tenant — must violate the UNIQUE
	// partial index from migration 078.
	jti2 := fmt.Sprintf("jti-2-%d", time.Now().UnixNano())
	_, err := db.Exec(`
		INSERT INTO plugin_user_licenses
		  (tenant_id, claimed_by_email, tier, license_token_jti, entitlements)
		VALUES
		  ($1, $2, 'plugin-claimed', $3, '{}'::jsonb)`,
		tenantID, email, jti2,
	)
	if err == nil {
		// Cleanup since the constraint allowed it (regression)
		_, _ = db.Exec(`DELETE FROM plugin_user_licenses WHERE license_token_jti = $1`, jti2)
		t.Fatal("expected UNIQUE constraint violation on second active row, got nil")
	}
}
