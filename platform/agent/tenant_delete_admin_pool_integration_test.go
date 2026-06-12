// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build enterprise

package agent

// Integration test for issue #2397 — tenant_delete.go pre-auth cascade
// DELETEs miss SET LOCAL app.current_org_id, breaking GDPR right-to-erasure
// under the v9 app_role pool.
//
// The Go-side fix lives at platform/agent/run.go in the
// RequirePlatformAdminOrFatal + OpenPlatformAdminConnection block that
// mirrors CSAAS-RECOVERY 12 lines above. This file exercises both the
// behavior under that fix and the mutation gate that proves admin-pool
// routing is load-bearing.
//
// CORRECTION to the issue body's diagnosis: DELETE under FORCE-RLS does
// NOT raise sqlstate 42501 when app.current_org_id is unset. WITH CHECK
// only fires on INSERT/UPDATE; DELETE evaluates only the USING predicate,
// and `org_id = NULL` evaluates to NULL → filtered → 0 rows silently
// affected, no error. This makes the bug WORSE than the issue described:
// the handler returns HTTP 200 with a tenant_deletion_log row indicating
// "deletion done" while the registration + usage_events rows remain on
// disk. Silent SoX-class corruption + lying GDPR Article 17 receipt.
//
//   - Admin-pool path (env.AdminDSN — axonflow_platform_admin, BYPASSRLS):
//       delete-confirm: 200 + cascade scrubs all sources + truthful log row
//       delete-request: 202 + token issued
//
//   - App-role path (env.AppRoleDSN — axonflow_app_role, NOBYPASSRLS):
//       delete-confirm: 200 (handler unaware of silent filter) BUT
//                       registration retained + usage_events retained +
//                       tenant_deletion_log row written with
//                       deleted_registrations=0 (lying receipt)
//       delete-request: 202 (anti-enum invariant) BUT no token issued —
//                       the pre-existence SELECT EXISTS on the FORCE-RLS
//                       community_saas_registrations silently filters to FALSE
//
// The mutation gate discriminates on the DSN's role, which IS the
// load-bearing distinction the fix introduces.
//
// Gating: TEST_PG_INTEGRATION=1. Skipped without docker.

import (
	"bytes"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/lib/pq"

	"axonflow/platform/agent/approletest"
)

const td2397TestEmail = "td2397-tenant-delete@axonflow-test.invalid"

// td2397Seed seeds one tenant with linked rows across the cascade target
// tables. Runs as the master (SUPERUSER → BYPASSRLS) so the FORCE RLS state
// on community_saas_registrations doesn't fight the seed. Returns the
// tenant_id; cleanup is registered via t.Cleanup.
func td2397Seed(t *testing.T, master *sql.DB) (tenantID string) {
	t.Helper()
	tenantID = communitySaasTenantPrefix + fmt.Sprintf("td2397-%d", time.Now().UnixNano())
	expiresAt := time.Now().UTC().Add(communitySaasRegistrationTTL)

	// v9 Phase 6 invariant: org_id = tenant_id = client_id for csaas rows.
	if _, err := master.Exec(`
		INSERT INTO community_saas_registrations
		(tenant_id, client_id, secret_hash, secret_prefix, org_id, label, expires_at, claimed_by_email, claimed_at)
		VALUES ($1, $1, $2, $3, $1, $4, $5, $6, NOW())`,
		tenantID, "$2a$12$dummyhashdummyhashdummyhashdummyhashdummyhashdumm", "12345678",
		"#2397-test", expiresAt, td2397TestEmail); err != nil {
		t.Fatalf("seed registrations: %v", err)
	}

	// 2 audit_logs rows so the cascade-count assertion has signal.
	for i := 0; i < 2; i++ {
		if _, err := master.Exec(`
			INSERT INTO audit_logs (id, request_id, timestamp, user_id, user_email, user_role,
				client_id, tenant_id, request_type, query, query_hash, policy_decision)
			VALUES ($1, $2, NOW(), 1, $3, 'test', 'client-x', $4, 'test', 'q', 'h', 'allowed')`,
			fmt.Sprintf("audit-2397-%d-%d", time.Now().UnixNano(), i),
			fmt.Sprintf("req-2397-%d-%d", time.Now().UnixNano(), i),
			td2397TestEmail, tenantID); err != nil {
			t.Fatalf("seed audit_logs: %v", err)
		}
	}

	if _, err := master.Exec(`
		INSERT INTO community_saas_daily_usage (tenant_id, day, req_count)
		VALUES ($1, CURRENT_DATE, 7)`, tenantID); err != nil {
		t.Fatalf("seed daily_usage: %v", err)
	}

	// usage_events.org_id has a FK to organizations.org_id (mig 081's
	// fk_usage_org). Seed the org so the FK passes; under master/SUPERUSER
	// any RLS on organizations is bypassed.
	licenseKey := "td2397-license-" + tenantID
	if _, err := master.Exec(`
		INSERT INTO organizations (org_id, name, max_nodes, tier, license_key)
		VALUES ($1, 'td2397-org', 1, 'community', $2)
		ON CONFLICT (org_id) DO NOTHING`, tenantID, licenseKey); err != nil {
		// Best-effort: in community-only schemas organizations may not exist;
		// in that case usage_events FK is also absent so the next INSERT
		// just succeeds without a parent row. Log + continue.
		t.Logf("seed organizations (may be skipped in community schema): %v", err)
	}

	// usage_events is ENABLE-RLS via mig 081. The cascade DELETE keys on
	// client_id (per mig 081's csaas-shape comment in tenant_delete.go:591).
	// For csaas, client_id IS the tenant_id by convention; usage_events has
	// no tenant_id column.
	if _, err := master.Exec(`
		INSERT INTO usage_events (client_id, org_id, event_type, created_at)
		VALUES ($1, $1, 'request', NOW())`, tenantID); err != nil {
		t.Fatalf("seed usage_events: %v", err)
	}

	t.Cleanup(func() {
		// Best-effort under the master DSN (SUPERUSER bypass). Idempotent —
		// happy-path subtests have already cleared everything by tx commit.
		for _, q := range []string{
			`DELETE FROM community_saas_registrations WHERE tenant_id = $1`,
			`DELETE FROM community_saas_deletion_tokens WHERE tenant_id = $1`,
			`DELETE FROM tenant_deletion_log WHERE tenant_id = $1`,
			`DELETE FROM audit_logs WHERE tenant_id = $1`,
			`DELETE FROM community_saas_daily_usage WHERE tenant_id = $1`,
			`DELETE FROM usage_events WHERE client_id = $1`,
			`DELETE FROM organizations WHERE org_id = $1`,
		} {
			_, _ = master.Exec(q, tenantID)
		}
	})
	return tenantID
}

// td2397IssueToken bypasses the request endpoint and writes a deletion token
// row directly under the master connection. Used by the confirm-side subtests
// so they don't depend on the request-side fix succeeding first. Returns the
// plain (unhashed) token for the caller to POST.
func td2397IssueToken(t *testing.T, master *sql.DB, tenantID, email string) string {
	t.Helper()
	plain := fmt.Sprintf("td2397-token-%d", time.Now().UnixNano())
	if _, err := master.Exec(`
		INSERT INTO community_saas_deletion_tokens (token_hash, tenant_id, email, expires_at)
		VALUES ($1, $2, $3, $4)`,
		hashTenantDeleteToken(plain), tenantID, email, time.Now().UTC().Add(1*time.Hour)); err != nil {
		t.Fatalf("issue token: %v", err)
	}
	return plain
}

// td2397HandlerOnDSN opens a fresh *sql.DB against dsn, registers the deletion
// handler on a fresh mux router, and returns both (caller closes db). The
// handler authenticates every internal tx through dsn — so AdminDSN models
// the post-fix production path and AppRoleDSN models the pre-fix path.
func td2397HandlerOnDSN(t *testing.T, dsn string) (*mux.Router, *sql.DB) {
	t.Helper()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("sql.Open %s: %v", dsn, err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		t.Fatalf("ping %s: %v", dsn, err)
	}
	r := mux.NewRouter()
	RegisterTenantDeletionHandler(r, db, &NoopTenantDeletionEmailSender{})
	return r, db
}

func td2397PostConfirm(t *testing.T, r *mux.Router, tenantID, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/api/v1/tenant/%s/delete-confirm", tenantID),
		bytes.NewBufferString(fmt.Sprintf(`{"token":%q}`, token)))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func td2397PostRequest(t *testing.T, r *mux.Router, tenantID, email string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/api/v1/tenant/%s/delete-request", tenantID),
		bytes.NewBufferString(fmt.Sprintf(`{"email":%q}`, email)))
	// Unique-per-test client IP so the in-process IP rate limiter doesn't
	// bleed between subtests when resetTenantDeleteIPTracker is missed.
	req.RemoteAddr = fmt.Sprintf("127.0.0.%d:1234", time.Now().UnixNano()%200+1)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// TestTenantDeleteAdminPoolRouting_RealPostgres is the canonical proof of
// the #2397 fix. Four subtests in two pairs (positive + mutation gate per
// endpoint).
func TestTenantDeleteAdminPoolRouting_RealPostgres(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")

	// Master = SUPERUSER, used only for seeding + post-cascade observation
	// (not for the handler).
	master, err := sql.Open("postgres", env.MasterDSN)
	if err != nil {
		t.Fatalf("master sql.Open: %v", err)
	}
	defer func() { _ = master.Close() }()
	master.SetMaxOpenConns(1)

	// Pre-flight: if a future migration unwinds FORCE on
	// community_saas_registrations OR ENABLE on usage_events, the
	// discriminator under this test degrades. Fail loud + early.
	var rlsEnabled, rlsForced bool
	if err := master.QueryRow(`
		SELECT relrowsecurity, relforcerowsecurity
		FROM pg_class
		WHERE relname = 'community_saas_registrations' AND relkind = 'r'`).
		Scan(&rlsEnabled, &rlsForced); err != nil {
		t.Fatalf("preflight pg_class lookup (community_saas_registrations): %v", err)
	}
	if !rlsEnabled || !rlsForced {
		t.Fatalf("preflight: community_saas_registrations must be ENABLE+FORCE RLS "+
			"(rls_enabled=%v, rls_forced=%v) — mig 105 not applied, test cannot "+
			"discriminate between admin pool vs app_role routing", rlsEnabled, rlsForced)
	}

	var ueEnabled bool
	if err := master.QueryRow(`
		SELECT relrowsecurity FROM pg_class
		WHERE relname = 'usage_events' AND relkind = 'r'`).Scan(&ueEnabled); err != nil {
		t.Fatalf("preflight pg_class lookup (usage_events): %v", err)
	}
	if !ueEnabled {
		t.Fatalf("preflight: usage_events must be ENABLE RLS (mig 081)")
	}

	// ==================================================================
	// Subtest 1 — delete-confirm under admin pool scrubs all 5 sources
	// ==================================================================
	t.Run("delete-confirm under admin pool scrubs all 5 sources", func(t *testing.T) {
		tenantID := td2397Seed(t, master)
		token := td2397IssueToken(t, master, tenantID, td2397TestEmail)

		r, db := td2397HandlerOnDSN(t, env.AdminDSN)
		defer func() { _ = db.Close() }()

		w := td2397PostConfirm(t, r, tenantID, token)
		if w.Code != http.StatusOK {
			t.Fatalf("admin pool delete-confirm: expected 200, got %d (body=%s)",
				w.Code, w.Body.String())
		}

		// Cascade actually removed the rows (counts observed under master).
		for _, q := range []struct{ name, query string }{
			{"registrations", `SELECT COUNT(*) FROM community_saas_registrations WHERE tenant_id = $1`},
			{"audit_logs", `SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1`},
			{"daily_usage", `SELECT COUNT(*) FROM community_saas_daily_usage WHERE tenant_id = $1`},
			{"usage_events", `SELECT COUNT(*) FROM usage_events WHERE client_id = $1`},
		} {
			var n int
			if err := master.QueryRow(q.query, tenantID).Scan(&n); err != nil {
				t.Fatalf("verify %s: %v", q.name, err)
			}
			if n != 0 {
				t.Errorf("admin pool cascade should have cleared %s; got %d rows", q.name, n)
			}
		}

		// GDPR Article-30 records-of-processing receipt is written.
		var logCount int
		if err := master.QueryRow(`
			SELECT COUNT(*) FROM tenant_deletion_log WHERE tenant_id = $1`,
			tenantID).Scan(&logCount); err != nil {
			t.Fatalf("verify deletion log: %v", err)
		}
		if logCount != 1 {
			t.Errorf("expected 1 tenant_deletion_log row, got %d", logCount)
		}
	})

	// ==================================================================
	// Subtest 2 — delete-confirm under app_role: silent partial deletion
	// (mutation gate)
	// ==================================================================
	//
	// Correction to issue #2397's diagnosis: DELETE under FORCE-RLS does NOT
	// raise 42501 when app.current_org_id is unset. WITH CHECK only fires on
	// INSERT/UPDATE — DELETE evaluates only the USING predicate. With
	// current_setting('app.current_org_id', true) returning NULL, the USING
	// predicate `org_id = NULL` evaluates to NULL → filtered → 0 rows
	// silently deleted, no error.
	//
	// Under app_role the handler therefore returns HTTP 200 — but the
	// "successful" cascade is incomplete: community_saas_registrations is
	// untouched (silent USING filter) and usage_events is untouched (same
	// reason, ENABLE-RLS). The tenant_deletion_log row IS written with
	// deleted_registrations=0 and deleted_usage_events=0 — a LYING GDPR
	// Article 17 receipt: "data has been removed" while in fact the
	// registration row still exists on disk.
	//
	// This is a worse failure mode than the issue body described (loud 500
	// cascade abort) — silent SoX-class corruption with a misleading audit
	// log. The mutation discriminator: under admin pool (subtest 1) the
	// registration is removed; under app_role (this subtest) the
	// registration remains.
	t.Run("delete-confirm under app_role: silent partial deletion + lying GDPR receipt (mutation gate)", func(t *testing.T) {
		tenantID := td2397Seed(t, master)
		token := td2397IssueToken(t, master, tenantID, td2397TestEmail)

		r, db := td2397HandlerOnDSN(t, env.AppRoleDSN)
		defer func() { _ = db.Close() }()

		w := td2397PostConfirm(t, r, tenantID, token)
		// Handler's view: success.
		if w.Code != http.StatusOK {
			t.Fatalf("app_role delete-confirm: expected 200 (handler unaware of "+
				"silent USING filter), got %d (body=%s)", w.Code, w.Body.String())
		}

		// Ground truth under master/BYPASSRLS: the registration row is STILL
		// THERE. This is the GDPR violation.
		var regCount int
		if err := master.QueryRow(`
			SELECT COUNT(*) FROM community_saas_registrations WHERE tenant_id = $1`,
			tenantID).Scan(&regCount); err != nil {
			t.Fatalf("verify registration retention: %v", err)
		}
		if regCount != 1 {
			t.Errorf("app_role mutation gate: registration should remain in DB "+
				"(silently filtered DELETE returned 0 rows); got %d", regCount)
		}

		// Same for usage_events — ENABLE-RLS via mig 081, same USING filter.
		var ueCount int
		if err := master.QueryRow(`
			SELECT COUNT(*) FROM usage_events WHERE client_id = $1`,
			tenantID).Scan(&ueCount); err != nil {
			t.Fatalf("verify usage_events retention: %v", err)
		}
		if ueCount != 1 {
			t.Errorf("app_role mutation gate: usage_events should remain in DB; got %d", ueCount)
		}

		// The lying GDPR receipt: a tenant_deletion_log row was written
		// (the tx committed) with deleted_registrations=0 and
		// deleted_usage_events=0. The presence of THIS row is the
		// SoX-grade audit-trail forgery — operator-facing evidence says
		// "deletion done" while the records remain.
		var logCount, loggedRegs, loggedUE int
		if err := master.QueryRow(`
			SELECT COUNT(*),
			       COALESCE(MAX(deleted_registrations), 0),
			       COALESCE(MAX(deleted_usage_events), 0)
			FROM tenant_deletion_log WHERE tenant_id = $1`,
			tenantID).Scan(&logCount, &loggedRegs, &loggedUE); err != nil {
			t.Fatalf("verify deletion log: %v", err)
		}
		if logCount != 1 {
			t.Errorf("app_role mutation gate: expected exactly 1 deletion log "+
				"row (tx committed), got %d", logCount)
		}
		if loggedRegs != 0 {
			t.Errorf("app_role mutation gate: deletion log should record "+
				"deleted_registrations=0 (silent USING filter); got %d", loggedRegs)
		}
		if loggedUE != 0 {
			t.Errorf("app_role mutation gate: deletion log should record "+
				"deleted_usage_events=0 (silent USING filter); got %d", loggedUE)
		}
	})

	// ==================================================================
	// Subtest 3 — delete-request under admin pool issues a token
	// ==================================================================
	t.Run("delete-request under admin pool issues a token", func(t *testing.T) {
		resetTenantDeleteIPTracker()
		tenantID := td2397Seed(t, master)

		r, db := td2397HandlerOnDSN(t, env.AdminDSN)
		defer func() { _ = db.Close() }()

		w := td2397PostRequest(t, r, tenantID, td2397TestEmail)
		if w.Code != http.StatusAccepted {
			t.Fatalf("admin pool delete-request: expected 202, got %d (body=%s)",
				w.Code, w.Body.String())
		}

		var tokenCount int
		if err := master.QueryRow(`
			SELECT COUNT(*) FROM community_saas_deletion_tokens WHERE tenant_id = $1`,
			tenantID).Scan(&tokenCount); err != nil {
			t.Fatalf("verify token count: %v", err)
		}
		if tokenCount != 1 {
			t.Errorf("admin pool delete-request should have issued exactly 1 token, got %d", tokenCount)
		}
	})

	// ==================================================================
	// Subtest 4 — delete-request under app_role silently issues no token
	// ==================================================================
	t.Run("delete-request under app_role silently issues no token (mutation gate)", func(t *testing.T) {
		resetTenantDeleteIPTracker()
		tenantID := td2397Seed(t, master)

		r, db := td2397HandlerOnDSN(t, env.AppRoleDSN)
		defer func() { _ = db.Close() }()

		w := td2397PostRequest(t, r, tenantID, td2397TestEmail)
		// Anti-enum invariant: response is ALWAYS 202. We discriminate on
		// DB state, not response code.
		if w.Code != http.StatusAccepted {
			t.Fatalf("app_role delete-request: expected 202 (anti-enum invariant), got %d", w.Code)
		}

		// Mutation signal: NO token gets written because the pre-existence
		// SELECT EXISTS at tenant_delete.go:320-326 hits the FORCE-RLS USING
		// predicate with no app.current_org_id set → returns FALSE for all
		// rows → matched=false → handler returns generic 202 without
		// inserting a token. A non-zero count means the FORCE gate unwound;
		// investigate mig 105.
		var tokenCount int
		if err := master.QueryRow(`
			SELECT COUNT(*) FROM community_saas_deletion_tokens WHERE tenant_id = $1`,
			tenantID).Scan(&tokenCount); err != nil {
			t.Fatalf("verify token absent: %v", err)
		}
		if tokenCount != 0 {
			t.Errorf("app_role delete-request mutation gate: expected 0 tokens "+
				"(handler should hit silent matched=false branch); got %d. "+
				"If non-zero the FORCE RLS gate has unwound — investigate mig 105.", tokenCount)
		}
	})
}

// TestTenantDeleteRunGoCallSiteWiring is a source-level guard against silent
// regression in run.go. The integration test exercises behavior at the
// handler input (RegisterTenantDeletionHandler) — not the wire from run.go
// to that input. Without this guard, a future refactor that drops the
// admin-pool plumbing would re-introduce #2397 without the integration test
// catching it.
//
// Mirrors the precedent at
// ee/platform/customer-portal/main_pool_app_role_test.go::TestCustomerPortalMainCallsOpenAppRoleConnection.
func TestTenantDeleteRunGoCallSiteWiring(t *testing.T) {
	body, err := os.ReadFile("run.go")
	if err != nil {
		t.Fatalf("read run.go: %v", err)
	}
	src := string(body)

	// All three load-bearing identifiers must co-occur. We don't require a
	// specific ordering — just presence — because formatters / future edits
	// may reorganize the block. The semantic claim is "the CSAAS-DELETE
	// caller invokes the admin-pool boot plumbing AND the handler is
	// registered against the resulting deleteDB."
	for _, needle := range []string{
		`RequirePlatformAdminOrFatal("CSAAS-DELETE")`,
		`OpenPlatformAdminConnection(`,
		`RegisterTenantDeletionHandler(globalRouter, deleteDB,`,
	} {
		if !strings.Contains(src, needle) {
			t.Errorf("run.go is missing the load-bearing identifier %q — "+
				"the CSAAS-DELETE admin-pool plumbing has been dropped, reverting #2397",
				needle)
		}
	}
}
