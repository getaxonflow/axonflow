// Copyright 2025-2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// v9 Follow-up A — R3 gap-closure tests (PR #2310 train).
//
// R3 hostile review of PR #2309's final committed state surfaced 5 issues.
// These tests pin the fix for each, with mutation-test discipline per
// feedback_mutation_test_to_prove_assertion_not_tautological.md.

// =============================================================================
// F1-B — buildAuthResult invariant covers BOTH AuthKinds (was MEDIUM)
// =============================================================================

// TestBuildAuthResult_SurfacesClientCredentialID_AllKinds is the structural
// fix for R3 finding F1-B. The original F1 test only exercised the Enterprise
// branch because Authenticate() mode-detects via env vars. The CommunitySaaS
// branch's ClientID assignment was unmutation-tested.
//
// Post-gap-PR both branches route through buildAuthResult, so one parametric
// test mutation-proves the invariant for every AuthKind.
//
// Mutation test: change buildAuthResult to `ClientID: client.ID` and every
// subtest fails. Tautology guard: wantClientID + wantID are distinct string
// literals; assertions use != and == against both.
func TestBuildAuthResult_SurfacesClientCredentialID_AllKinds(t *testing.T) {
	const (
		wantClientID = "api-key-creds-f1b"  // post-Fix 4: api_key_id
		wantID       = "org-from-customer"  // legacy: customer.OrganizationID
		wantOrgID    = "license-org-id-f1b" // from license payload
		wantTenant   = "tenant-f1b"
	)
	client := &Client{
		ID:       wantID,
		ClientID: wantClientID,
		TenantID: wantTenant,
		OrgID:    wantOrgID,
	}

	for _, kind := range []AuthKind{AuthKindCommunitySaaS, AuthKindEnterprise} {
		kind := kind
		t.Run(kind.String(), func(t *testing.T) {
			auth := buildAuthResult(kind, client)
			if auth == nil {
				t.Fatal("expected non-nil AuthResult")
			}
			if auth.Kind != kind {
				t.Errorf("Kind: got %s, want %s", auth.Kind, kind)
			}
			if auth.ClientID == wantID {
				t.Errorf("AuthResult.ClientID collapsed to client.ID (%q) — F1 reverted on %s branch", auth.ClientID, kind)
			}
			if auth.ClientID != wantClientID {
				t.Errorf("AuthResult.ClientID: got %q, want %q (must propagate client.ClientID per ADR-052 §5)",
					auth.ClientID, wantClientID)
			}
			if auth.OrgID != wantOrgID {
				t.Errorf("AuthResult.OrgID: got %q, want %q", auth.OrgID, wantOrgID)
			}
			if auth.TenantID != wantTenant {
				t.Errorf("AuthResult.TenantID: got %q, want %q", auth.TenantID, wantTenant)
			}
			if auth.Client != client {
				t.Errorf("AuthResult.Client pointer drift (got %p, want %p)", auth.Client, client)
			}
		})
	}
}

// =============================================================================
// F1-A — clientRequestHandler propagates client.ClientID, not client.ID, into
// ContextKeyClientID + usage_events.client_id (was HIGH)
// =============================================================================

// TestStampAuthContext_UsesClientCredentialID exercises the extracted
// helper that clientRequestHandler (run.go:1314) uses to populate the
// request context. The helper is the single point of truth — mutating its
// `client.ClientID` to `client.ID` causes the test to fail. clientRequestHandler
// at run.go:1314 calls this helper with no other field-mapping logic, so the
// helper covers the F1-A invariant end-to-end.
//
// Mutation test: change `ContextKeyClientID, client.ClientID` to `client.ID`
// in run.go::stampAuthContext and this test fails.
//
// Tautology guard: wantClientID + wantID are distinct string literals; we
// assert ClientIDFromContext == wantClientID AND != wantID.
func TestStampAuthContext_UsesClientCredentialID(t *testing.T) {
	const (
		wantClientID = "api-key-clienthandler-f1a"
		wantID       = "org-clienthandler-f1a"
		wantTenant   = "tenant-f1a"
		wantOrg      = "org-license-f1a"
	)
	client := &Client{
		ID:       wantID,
		ClientID: wantClientID,
		TenantID: wantTenant,
		OrgID:    wantOrg,
	}

	ctx := stampAuthContext(context.Background(), client, AuthKindEnterprise)

	if got := ClientIDFromContext(ctx); got != wantClientID {
		if got == wantID {
			t.Errorf("ContextKeyClientID stamped from client.ID (%q) — F1-A reverted in stampAuthContext", got)
		} else {
			t.Errorf("ContextKeyClientID: got %q, want %q (api_key_id per ADR-052 §5)", got, wantClientID)
		}
	}

	// Spot-check sibling keys so a future "cleanup" that swaps both ID and
	// ClientID can't pass this test silently.
	if got := TenantIDFromContext(ctx); got != wantTenant {
		t.Errorf("ContextKeyTenantID: got %q, want %q", got, wantTenant)
	}
	if got := OrgIDFromContext(ctx); got != wantOrg {
		t.Errorf("ContextKeyOrgID: got %q, want %q", got, wantOrg)
	}
}

// TestBuildAPICallClientID_UsesClientCredentialID exercises the extracted
// buildAPICallClientID helper that run.go's RecordAPICall path uses to
// populate usage_events.client_id. Per ADR-052 §5 this must be
// client.ClientID (api_key_id), not client.ID (legacy compat org_id).
//
// Mutation test: change `return client.ClientID` to `return client.ID`
// in run.go::buildAPICallClientID and this test fails. The test calls
// the same helper the production line calls, so mutating the helper
// affects both production and test. Tautology guard: wantClientID and
// wantID are distinct string literals; assertions cover both
// `== wantClientID` AND `!= wantID`.
func TestBuildAPICallClientID_UsesClientCredentialID(t *testing.T) {
	const (
		wantClientID = "api-key-usage-f1a"
		wantID       = "org-usage-f1a"
	)
	client := &Client{ID: wantID, ClientID: wantClientID}

	got := buildAPICallClientID(client)
	if got == wantID {
		t.Errorf("buildAPICallClientID returned client.ID (%q) — usage.APICallEvent.ClientID would carry org_id, not api_key_id (R3-F1 reverted)", got)
	}
	if got != wantClientID {
		t.Errorf("buildAPICallClientID: got %q, want %q (api_key_id per ADR-052 §5)", got, wantClientID)
	}
}

// =============================================================================
// #2319 — stampAuthContext stamps ContextKeyAuthKind (was HIGH, silent wrong-value class)
// =============================================================================

// TestStampAuthContext_StampsAuthKind pins the fix for #2319. Pre-fix
// stampAuthContext (run.go:160) stamped only TenantID/OrgID/ClientID but
// not AuthKind, while the parallel apiAuthMiddleware writer (auth.go:658-661)
// stamps all four. Any AuthKindFromContext reader downstream of
// clientRequestHandler — the sole non-middleware caller of stampAuthContext —
// got the default AuthKindEnterprise back, silently corrupting authz
// branches that key on auth kind for community / community-saas / internal-
// service callers.
//
// Mutation test: delete the new
//
//	ctx = context.WithValue(ctx, ContextKeyAuthKind, kind)
//
// line in run.go::stampAuthContext and every subtest below fails, EXCEPT
// the AuthKindEnterprise case — because AuthKindFromContext returns
// AuthKindEnterprise as the default fallback when the key is absent, so
// asserting against AuthKindEnterprise would be tautological. The
// AuthKindEnterprise subtest is included as a positive assertion only;
// the mutation-resistance comes from the three non-default kinds.
func TestStampAuthContext_StampsAuthKind(t *testing.T) {
	client := &Client{
		ID:       "client-id-2319",
		ClientID: "api-key-2319",
		TenantID: "tenant-2319",
		OrgID:    "org-2319",
	}

	// Tautology guard: AuthKindFromContext defaults to AuthKindEnterprise
	// when the key is absent (auth.go:557). To prove stampAuthContext
	// actually wrote the key, we MUST exercise at least one kind whose
	// integer value is not AuthKindEnterprise's iota slot (2). Every
	// kind != AuthKindEnterprise below proves the WithValue happened.
	cases := []struct {
		name string
		kind AuthKind
	}{
		{"community", AuthKindCommunity},              // iota 0 — also the Go zero-value for AuthKind
		{"community_saas", AuthKindCommunitySaaS},     // iota 1
		{"enterprise", AuthKindEnterprise},            // iota 2 — matches AuthKindFromContext default; positive assertion only
		{"internal_service", AuthKindInternalService}, // iota 3
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ctx := stampAuthContext(context.Background(), client, tc.kind)
			got := AuthKindFromContext(ctx)
			if got != tc.kind {
				t.Errorf("AuthKindFromContext: got %s (%d), want %s (%d) — #2319 fix reverted in stampAuthContext",
					got, got, tc.kind, tc.kind)
			}
		})
	}
}

// TestStampAuthContext_AuthKind_ReproducesHandlerCallSiteSequence replays
// the exact 2-line wiring that clientRequestHandler uses (run.go:1337 +
// 1351): `auth, _ := Authenticate(...)` immediately followed by
// `stampAuthContext(r.Context(), auth.Client, auth.Kind)`. It does NOT
// invoke clientRequestHandler itself.
//
// Purpose: complement the helper-level table test above by proving the
// kind value flowing into stampAuthContext at the production call site
// is the one Authenticate() returned, not a hardcoded literal — i.e.
// the wiring is correct, not just the helper.
//
// Why not invoke clientRequestHandler directly? Driving the full handler
// requires DB state, orchestrator URL, user JWT, tenant policies, and a
// resolved migration schema — none of which add coverage for this
// specific stamping invariant. The handler's prefix between the
// Authenticate() call and the stampAuthContext() call is exactly the
// two lines below; nothing else mutates the auth kind between them.
//
// Caveats this test does NOT cover:
//   - Middleware ordering (clientRequestHandler is not wrapped by
//     apiAuthMiddleware at run.go:1094 — confirmed by direct route
//     registration, no middleware chain).
//   - Request-lifecycle propagation via r.WithContext to downstream
//     handler calls.
//   - Any AuthKindFromContext reader bypassing both apiAuthMiddleware
//     AND stampAuthContext (the PR's R2 audit confirms today's sole
//     reader, gateway_handlers.go:394, is behind apiAuthMiddleware).
//
// Mutation: reverting the new WithValue line in stampAuthContext fails
// this test the same way it fails the table test — the kind never
// reaches the context.
func TestStampAuthContext_AuthKind_ReproducesHandlerCallSiteSequence(t *testing.T) {
	// Force community mode so Authenticate's branch 2 fires without any
	// DB / license setup.
	t.Setenv("DEPLOYMENT_MODE", "community")

	reqBody := strings.NewReader(`{"client_id":"test-client-2319","request_type":"query","query":"noop","skip_llm":true}`)
	req, err := http.NewRequest("POST", "/api/request", reqBody)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Reproduce the clientRequestHandler:1337 + :1351 2-line sequence
	// verbatim:
	//   auth, authErr := Authenticate(r, &AuthHints{ClientID: req.ClientID})
	//   ...
	//   r = r.WithContext(stampAuthContext(r.Context(), client, auth.Kind))
	auth, authErr := Authenticate(req, &AuthHints{ClientID: "test-client-2319"})
	if authErr != nil {
		t.Fatalf("Authenticate: %v", authErr.Message)
	}
	if auth.Kind != AuthKindCommunity {
		t.Fatalf("precondition: expected AuthKindCommunity from community mode, got %s", auth.Kind)
	}
	ctx := stampAuthContext(req.Context(), auth.Client, auth.Kind)

	// Post-stamp the context MUST carry the community kind. Without the
	// fix, AuthKindFromContext returns AuthKindEnterprise (the default
	// fallback in auth.go:557), so a value of AuthKindCommunity (iota 0)
	// proves the WithValue ran.
	if got := AuthKindFromContext(ctx); got != AuthKindCommunity {
		t.Errorf("post-stampAuthContext AuthKindFromContext: got %s, want %s — #2319 regression: kind not propagated through the production call-site sequence",
			got, AuthKindCommunity)
	}
}

// =============================================================================
// F2-B — Migration 094 precondition behavior against REAL Postgres (was MEDIUM)
//
// Closes Gap 1 the user named: "in a scratch worktree, revert the set_config
// line, run the migration runner against an empty test DB with a single
// non-cs_* row having empty org_id, confirm migration 094 fails with the
// new EXCEPTION (not silent stamp). Restore. Capture verbatim."
//
// Six subtests pinned to the actual narrowed precondition:
//   (A) GUC NULL + non-cs_* empty-org_id row exists → EXCEPTION fires
//       (the regression path the precondition still catches)
//   (B) GUC = 'local-dev-org' + same row → no EXCEPTION + RAISE WARNING
//       (the legitimate dev-default path; CI smoke + community-mode must work)
//   (C) GUC = 'prod-acme-corp' + same row → no EXCEPTION, NOTICE only,
//       row stamped with 'prod-acme-corp'
//   (D) GUC = 'local-dev-org' + app.deployment_kind='production' + same row
//       → EXCEPTION fires with prod-safety message (#2320). This is the
//       new branch added in this PR — distinguishes legitimate dev default
//       from prod-forgot-ORG_ID, which (B) cannot.
//   (E) GUC = 'local-dev-org' + app.deployment_kind='production' + NO seed
//       row (fresh install) → EXCEPTION still fires. R3-finding fix: the
//       brief gated the new branch on has_non_csaas_empty=TRUE; R3 caught
//       that fresh prod installs (no historical rows) slip through but
//       still poison forward via Pass-1 PREP seeding
//       organizations(org_id='local-dev-org') and future audit writes.
//   (F) GUC = NULL/unset + app.deployment_kind='production' + NO seed
//       row → EXCEPTION fires. R3 round 2 catch: helper-skipped on prod
//       with fresh schema would otherwise fall through every branch to
//       the self-heal default. Defense-in-depth — the first branch
//       above only fires on helper-skipped + has_non_csaas_empty.
//
// Gated on TEST_PG_INTEGRATION=1 so unit-test runs don't auto-spin
// containers. The CI smoke job (which has docker available) sets the env.
// Locally, run: TEST_PG_INTEGRATION=1 go test ./agent -run TestMigration094Precondition
// =============================================================================

func TestMigration094Precondition_RealPostgres(t *testing.T) {
	if os.Getenv("TEST_PG_INTEGRATION") != "1" {
		t.Skip("set TEST_PG_INTEGRATION=1 to run real-PG integration tests (requires docker)")
	}

	pgURL, cleanup := startPostgresContainer(t)
	defer cleanup()

	// Common subtest setup: open a connection, run all migrations up to
	// (but not including) 094 so the org_id columns exist on the
	// backfill-target tables. Then optionally seed ONE non-cs_* empty-org_id
	// row in audit_logs to trigger the precondition's "has_non_csaas_empty"
	// path. seedRow=false simulates a fresh install (R3 subtest E).
	prepSchema := func(t *testing.T, seedRow bool) *sql.DB {
		t.Helper()
		db, err := sql.Open("postgres", pgURL)
		if err != nil {
			t.Fatalf("sql.Open: %v", err)
		}
		// R3-F3: pin pool to 1 conn so session-level GUCs (set with
		// is_local=false) persist across the migration loop. Without
		// this, lib/pq's default pool (MaxIdleConns=2) can serve a
		// fresh backend conn for any subsequent Exec, dropping
		// app.db_password and breaking migration 028's
		// current_setting('app.db_password', false) read.
		db.SetMaxOpenConns(1)
		// Drop everything from previous subtest.
		if _, err := db.Exec(`DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
			t.Fatalf("reset schema: %v", err)
		}
		// Mirror the agent boot path: set app.db_password so migration 017's
		// dblink_exec block works (it's referenced by migration 028 too).
		// Use a dummy value — the dblink path is exercised end-to-end inside
		// migration 017 against the seed Grafana DB, which we skip here.
		//
		// Caveat: migration 028 contains literal `{{GRAFANA_PASSWORD}}`
		// template markers that the production migration runner substitutes
		// before Exec. We do NOT substitute here, so the test schema's
		// `grafana` PG user gets the literal "{{GRAFANA_PASSWORD}}" string
		// as its password. Postgres accepts this — curly braces are valid
		// in passwords. Harmless for THIS test (we never connect as
		// `grafana`), but if a future test connects as that user it must
		// either substitute first or skip migration 028 in runMigrationsRange.
		if _, err := db.Exec(`SELECT set_config('app.db_password', 'test-pass', false)`); err != nil {
			t.Fatalf("set app.db_password: %v", err)
		}
		// Run migrations 001 through 093 inclusive. The agent's migration
		// runner walks migrations/core in version order; we replicate that
		// here with a minimal loop that's enough to set up the table
		// schemas migration 094 needs.
		runMigrationsRange(t, db, 1, 93)
		// Seed one non-cs_* empty-org_id row in audit_logs. The schema
		// (migrations 059 + 089) is NOT NULL on a few cols — provide
		// reasonable values for the ones we don't care about. Skipped
		// when seedRow=false (subtest E — fresh-install case).
		if seedRow {
			if _, err := db.Exec(`
				INSERT INTO audit_logs (
					id, request_id, timestamp, user_id, user_email, user_role,
					client_id, tenant_id, org_id, request_type, query, query_hash,
					policy_decision
				) VALUES (
					'test-precondition-row-1', 'req-test-1', NOW(), 0, 'test@example',
					'unknown', 'client-test', 'tenant-not-csaas', '', 'mcp', 'test',
					'hash-test', 'allow'
				)
			`); err != nil {
				t.Fatalf("seed audit_logs: %v", err)
			}
		}
		return db
	}
	// Backwards-compat alias for the existing A/B/C/D subtests that all
	// want a seeded row.
	prepFreshSchema := func(t *testing.T) *sql.DB { return prepSchema(t, true) }

	// runMigration094 seeds the GUCs the precondition reads + executes
	// migration 094 on a fresh connection. setOrgGUC/orgGUCValue control
	// app.deployment_org_id; setKindGUC/kindGUCValue control
	// app.deployment_kind (#2320). Either may be skipped to simulate the
	// run.go-skipped-helper regression case.
	runMigration094 := func(t *testing.T, db *sql.DB, setOrgGUC bool, orgGUCValue string, setKindGUC bool, kindGUCValue string) (returnedErr error, capturedNotices []string) {
		t.Helper()
		// Use a fresh connection per subtest because GUCs persist on the
		// connection. Pin pool to 1 (R3-F3) so the set_config + migration
		// Exec land on the same backend.
		conn, err := sql.Open("postgres", pgURL)
		if err != nil {
			t.Fatalf("sql.Open conn: %v", err)
		}
		conn.SetMaxOpenConns(1)
		defer conn.Close()

		if setOrgGUC {
			if _, err := conn.Exec(
				"SELECT set_config('app.deployment_org_id', $1, false)", orgGUCValue,
			); err != nil {
				t.Fatalf("set org GUC: %v", err)
			}
		}
		if setKindGUC {
			if _, err := conn.Exec(
				"SELECT set_config('app.deployment_kind', $1, false)", kindGUCValue,
			); err != nil {
				t.Fatalf("set kind GUC: %v", err)
			}
		}
		// Read migration 094 from the worktree.
		sqlBytes, err := os.ReadFile("../../migrations/core/094_v9_org_id_backfill.sql")
		if err != nil {
			t.Fatalf("read 094 sql: %v", err)
		}
		_, err = conn.Exec(string(sqlBytes))
		return err, nil // capturing pg NOTICE/WARNING requires lib/pq listener — skipping for now
	}

	t.Run("A_GUC_unset_with_seeded_row_fires_EXCEPTION", func(t *testing.T) {
		db := prepFreshSchema(t)
		defer db.Close()
		err, _ := runMigration094(t, db, false /* don't set org GUC */, "", false /* don't set kind GUC */, "")
		if err == nil {
			t.Fatalf("expected EXCEPTION but migration 094 succeeded (silent-stamp bug returned)")
		}
		if !strings.Contains(err.Error(), "Migration 094 requires app.deployment_org_id set") {
			t.Errorf("EXCEPTION message: got %q, want substring 'Migration 094 requires app.deployment_org_id set'", err.Error())
		}
		// Verify the seed row was NOT stamped (the EXCEPTION should have
		// rolled back the whole DO block).
		var orgVal string
		if err := db.QueryRow(`SELECT org_id FROM audit_logs WHERE id='test-precondition-row-1'`).Scan(&orgVal); err != nil {
			t.Fatalf("re-read seed row: %v", err)
		}
		if orgVal != "" {
			t.Errorf("seed row.org_id post-EXCEPTION: got %q, want '' (EXCEPTION should have prevented stamp)", orgVal)
		}
	})

	t.Run("B_GUC_local_dev_org_with_seeded_row_succeeds", func(t *testing.T) {
		db := prepFreshSchema(t)
		defer db.Close()
		// Mirror docker-compose default: kind GUC unset → migration treats
		// as 'dev' → WARNING branch, not EXCEPTION.
		err, _ := runMigration094(t, db, true, "local-dev-org", false, "")
		if err != nil {
			t.Fatalf("migration 094 unexpectedly failed: %v", err)
		}
		// Pass-2 should have stamped the seed row with 'local-dev-org'.
		var orgVal string
		if err := db.QueryRow(`SELECT org_id FROM audit_logs WHERE id='test-precondition-row-1'`).Scan(&orgVal); err != nil {
			t.Fatalf("re-read seed row: %v", err)
		}
		if orgVal != "local-dev-org" {
			t.Errorf("seed row.org_id: got %q, want 'local-dev-org' (Pass-2 should have stamped from GUC)", orgVal)
		}
	})

	t.Run("C_GUC_real_value_with_seeded_row_succeeds_and_stamps", func(t *testing.T) {
		db := prepFreshSchema(t)
		defer db.Close()
		// Real-deployment shape: ORG_ID + DEPLOYMENT_KIND=production both
		// propagated end-to-end → Pass-2 stamps with caller-supplied value.
		err, _ := runMigration094(t, db, true, "prod-acme-corp", true, "production")
		if err != nil {
			t.Fatalf("migration 094 unexpectedly failed: %v", err)
		}
		var orgVal string
		if err := db.QueryRow(`SELECT org_id FROM audit_logs WHERE id='test-precondition-row-1'`).Scan(&orgVal); err != nil {
			t.Fatalf("re-read seed row: %v", err)
		}
		if orgVal != "prod-acme-corp" {
			t.Errorf("seed row.org_id: got %q, want 'prod-acme-corp' (Pass-2 should have stamped from caller-supplied GUC)", orgVal)
		}
	})

	// (D) #2320 prod-safety branch — the regression this PR closes.
	// Operator deployed to prod (DEPLOYMENT_KIND=production set by CFN)
	// but forgot to set ORG_ID env on the task def → getDeploymentOrgID()
	// fell through to its 'local-dev-org' default → without this branch
	// Pass-2 would silently stamp historical empty-org_id rows with the
	// dev sentinel.
	//
	// Mutation test: revert step 3 (remove the new EXCEPTION block from
	// migration 094) and this subtest fails — migration 094 succeeds AND
	// the seed row gets stamped with 'local-dev-org'. Captured to
	// /tmp/v9-deployment-kind-<UTC>/r2.log.
	//
	// Tautology guard: assertion uses both the EXCEPTION error path AND
	// the post-call SELECT to confirm the row was NOT stamped — both must
	// fire for "EXCEPTION blocked stamp" to hold. The error message
	// substring is also pinned to '#2320' so a future refactor that loses
	// the prod-safety branch but keeps a generic EXCEPTION trips this.
	t.Run("D_GUC_local_dev_org_with_prod_kind_fires_EXCEPTION", func(t *testing.T) {
		db := prepFreshSchema(t)
		defer db.Close()
		err, _ := runMigration094(t, db, true, "local-dev-org", true, "production")
		if err == nil {
			t.Fatalf("expected #2320 prod-safety EXCEPTION but migration 094 succeeded (the prod-forgot-ORG_ID branch is gone or unreachable)")
		}
		if !strings.Contains(err.Error(), "#2320") {
			t.Errorf("EXCEPTION message: got %q, want substring '#2320' (prod-safety branch reference)", err.Error())
		}
		if !strings.Contains(err.Error(), "prod-safety abort") {
			t.Errorf("EXCEPTION message: got %q, want substring 'prod-safety abort'", err.Error())
		}
		// Seed row must remain unstamped — the EXCEPTION rolls back the
		// surrounding DO block, and migration 094 aborts before Pass-2.
		var orgVal string
		if err := db.QueryRow(`SELECT org_id FROM audit_logs WHERE id='test-precondition-row-1'`).Scan(&orgVal); err != nil {
			t.Fatalf("re-read seed row: %v", err)
		}
		if orgVal != "" {
			t.Errorf("seed row.org_id post-#2320-EXCEPTION: got %q, want '' (EXCEPTION should have prevented Pass-2 stamp)", orgVal)
		}
	})

	// (E) #2322 R3-finding fix — fresh-install prod-forgot case.
	//
	// R3 finding (PR #2322): the brief's original gate
	// (`AND has_non_csaas_empty`) wouldn't fire on a stack where every
	// Pass-2 target table is empty/cs_*-only, even though the same
	// migration's Pass-1 PREP would still seed
	// organizations.org_id='local-dev-org' on a real prod RDS, after
	// which every subsequent audit write would accrue under the dev
	// sentinel.
	//
	// To make this case actually distinguishable from D, we need
	// has_non_csaas_empty=FALSE at migration 094 entry. In a vanilla
	// post-migrations-001-093 schema this is NOT the case — system seed
	// rows from migrations 010/014/031 (static/dynamic policies) +
	// migration 016 (service_identities) carry tenant_id='global'-style
	// values with empty org_id and trip the `tenant_id NOT LIKE 'cs_%'`
	// branch.
	//
	// So this subtest explicitly DELETEs the seed rows before invoking
	// migration 094. Tautology guard: if the conjunct is reintroduced
	// (mutation), has_non_csaas_empty=FALSE on this schema → the new
	// branch wouldn't fire → migration 094 succeeds silently → seed row
	// in organizations gets stamped with 'local-dev-org' → assertion on
	// `organizations.org_id='local-dev-org'` row count == 0 fails. The
	// R2 mutation log in /tmp/v9-deployment-kind-*/r2.log captures this
	// recipe end-to-end.
	t.Run("E_fresh_install_prod_kind_local_dev_org_fires_EXCEPTION", func(t *testing.T) {
		db := prepSchema(t, false /* no audit_logs seed */)
		defer db.Close()
		// Clear system seed rows so has_non_csaas_empty=FALSE at
		// migration 094 entry. Mirrors the R3-finding scenario.
		clearTables := []string{
			"static_policies",
			"dynamic_policies",
			"service_identities",
			"execution_history",
		}
		for _, tbl := range clearTables {
			if _, err := db.Exec(`DELETE FROM ` + tbl + ` WHERE org_id IS NULL OR org_id = ''`); err != nil {
				t.Fatalf("clear %s: %v", tbl, err)
			}
		}
		// Verify the precondition would observe has_non_csaas_empty=FALSE
		// (so the test's premise actually holds before invoking 094).
		var total int
		if err := db.QueryRow(`
			SELECT
			  (SELECT COUNT(*) FROM static_policies     WHERE (org_id IS NULL OR org_id='') AND (tenant_id IS NULL OR tenant_id NOT LIKE 'cs\_%' ESCAPE '\')) +
			  (SELECT COUNT(*) FROM dynamic_policies    WHERE (org_id IS NULL OR org_id='') AND (tenant_id IS NULL OR tenant_id NOT LIKE 'cs\_%' ESCAPE '\')) +
			  (SELECT COUNT(*) FROM service_identities  WHERE (org_id IS NULL OR org_id='') AND (tenant_id IS NULL OR tenant_id NOT LIKE 'cs\_%' ESCAPE '\')) +
			  (SELECT COUNT(*) FROM execution_history   WHERE (org_id IS NULL OR org_id='') AND (tenant_id IS NULL OR tenant_id NOT LIKE 'cs\_%' ESCAPE '\')) +
			  (SELECT COUNT(*) FROM audit_logs          WHERE (org_id IS NULL OR org_id='') AND (tenant_id IS NULL OR tenant_id NOT LIKE 'cs\_%' ESCAPE '\')) +
			  (SELECT COUNT(*) FROM mcp_query_audits    WHERE (org_id IS NULL OR org_id='') AND (tenant_id IS NULL OR tenant_id NOT LIKE 'cs\_%' ESCAPE '\')) +
			  (SELECT COUNT(*) FROM policy_evaluations  WHERE (org_id IS NULL OR org_id='') AND (tenant_id IS NULL OR tenant_id NOT LIKE 'cs\_%' ESCAPE '\')) +
			  (SELECT COUNT(*) FROM agent_audit_logs    WHERE org_id IS NULL OR org_id='') +
			  (SELECT COUNT(*) FROM llm_call_audits     WHERE org_id IS NULL OR org_id='')
		`).Scan(&total); err != nil {
			t.Fatalf("precheck has_non_csaas_empty: %v", err)
		}
		if total != 0 {
			t.Fatalf("test premise violated: %d non-cs_* empty-org_id rows remain across Pass-2 targets; subtest cannot distinguish brief-gate from R3-fix", total)
		}

		err, _ := runMigration094(t, db, true, "local-dev-org", true, "production")
		if err == nil {
			t.Fatalf("expected #2320 prod-safety EXCEPTION on fresh-install + prod-forgot, got nil (R3 conjunct-drop fix regressed)")
		}
		if !strings.Contains(err.Error(), "#2320") {
			t.Errorf("EXCEPTION message: got %q, want substring '#2320'", err.Error())
		}
		// Confirm Pass-1 PREP never executed — organizations should have
		// no row keyed on 'local-dev-org'. The EXCEPTION must roll back
		// the entire DO block.
		var localDevRows int
		if err := db.QueryRow(`SELECT COUNT(*) FROM organizations WHERE org_id='local-dev-org'`).Scan(&localDevRows); err != nil {
			t.Fatalf("count organizations post-EXCEPTION: %v", err)
		}
		if localDevRows != 0 {
			t.Errorf("organizations.org_id='local-dev-org' rows post-EXCEPTION: got %d, want 0 (Pass-1 PREP must not have run on the prod-forgot path)", localDevRows)
		}
	})

	// (F) R3 round 2 finding — helper-skipped on prod + fresh schema.
	//
	// If run.go's setMigrationSessionVars is somehow skipped on a prod
	// stack (e.g., regression in the call chain) AND there are no
	// historical non-cs_* empty-org_id rows (fresh install with seed
	// rows cleared, like subtest E), then:
	//   - app.deployment_org_id is NULL/unset.
	//   - First branch (NULL/empty + has_non_csaas_empty) doesn't fire
	//     because has_non_csaas_empty=FALSE.
	//   - Pre-fix new branch checked for org='local-dev-org' literal
	//     and missed the NULL case.
	//   - Migration would fall through to self-heal default that
	//     re-aliases deployment_org to 'local-dev-org' and Pass-1 PREP
	//     seeds organizations(org_id='local-dev-org') on prod RDS.
	// The R3 round 2 fix extends the new branch to fire on
	// (NULL OR empty OR 'local-dev-org') so it covers this case too.
	t.Run("F_helper_skipped_prod_kind_fresh_install_fires_EXCEPTION", func(t *testing.T) {
		db := prepSchema(t, false /* no audit_logs seed */)
		defer db.Close()
		for _, tbl := range []string{
			"static_policies",
			"dynamic_policies",
			"service_identities",
			"execution_history",
		} {
			if _, err := db.Exec(`DELETE FROM ` + tbl + ` WHERE org_id IS NULL OR org_id = ''`); err != nil {
				t.Fatalf("clear %s: %v", tbl, err)
			}
		}
		// kind GUC set to production, but org GUC INTENTIONALLY UNSET
		// to simulate setMigrationSessionVars-skipped regression.
		err, _ := runMigration094(t, db, false /* org GUC unset */, "", true, "production")
		if err == nil {
			t.Fatalf("expected #2320 prod-safety EXCEPTION on helper-skipped + prod + fresh, got nil (R3 round 2 fix regressed)")
		}
		if !strings.Contains(err.Error(), "#2320") {
			t.Errorf("EXCEPTION message: got %q, want substring '#2320'", err.Error())
		}
		// Same Pass-1-PREP rollback check as E.
		var localDevRows int
		if err := db.QueryRow(`SELECT COUNT(*) FROM organizations WHERE org_id='local-dev-org'`).Scan(&localDevRows); err != nil {
			t.Fatalf("count organizations post-EXCEPTION: %v", err)
		}
		if localDevRows != 0 {
			t.Errorf("organizations.org_id='local-dev-org' rows post-EXCEPTION: got %d, want 0", localDevRows)
		}
	})
}

// startPostgresContainer launches a throwaway docker postgres:15 instance,
// returns the connection URL + a cleanup func. Uses host-port-randomization
// to avoid collision with other tests.
func startPostgresContainer(t *testing.T) (string, func()) {
	t.Helper()
	containerName := fmt.Sprintf("axonflow-test-pg-%d", time.Now().UnixNano())
	out, err := exec.Command("docker", "run", "-d",
		"--name", containerName,
		"-e", "POSTGRES_PASSWORD=testpass",
		"-e", "POSTGRES_DB=axonflow_test",
		"-p", "0:5432",
		"postgres:15",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, string(out))
	}
	cleanup := func() {
		_ = exec.Command("docker", "rm", "-f", containerName).Run()
	}
	// Discover the host-side port.
	portBytes, err := exec.Command("docker", "port", containerName, "5432/tcp").CombinedOutput()
	if err != nil {
		cleanup()
		t.Fatalf("docker port: %v\n%s", err, string(portBytes))
	}
	portLine := strings.TrimSpace(strings.Split(string(portBytes), "\n")[0])
	// format: 0.0.0.0:54321
	parts := strings.Split(portLine, ":")
	if len(parts) < 2 {
		cleanup()
		t.Fatalf("unexpected docker port output: %q", portLine)
	}
	hostPort := parts[len(parts)-1]
	url := fmt.Sprintf("postgres://postgres:testpass@localhost:%s/axonflow_test?sslmode=disable", hostPort)

	// Wait for postgres to accept connections (up to 30s).
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := sql.Open("postgres", url)
		if err == nil {
			if pingErr := conn.Ping(); pingErr == nil {
				_ = conn.Close()
				return url, cleanup
			}
			_ = conn.Close()
		}
		time.Sleep(500 * time.Millisecond)
	}
	cleanup()
	t.Fatalf("postgres container did not become ready within 30s")
	return "", nil
}

// runMigrationsRange runs migrations [lo, hi] inclusive from migrations/core/
// in version order, treating each .sql file as one Exec. This is a stripped-
// down clone of run.go's migration loop — sufficient for setting up the
// schema migration 094 needs (org_id columns on audit_logs etc.).
func runMigrationsRange(t *testing.T, db *sql.DB, lo, hi int) {
	t.Helper()
	dir := "../../migrations/core"
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read migration dir: %v", err)
	}
	type mig struct {
		version int
		name    string
		path    string
	}
	var migs []mig
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") || strings.HasSuffix(e.Name(), "_down.sql") {
			continue
		}
		// Parse leading 3-digit version.
		parts := strings.SplitN(e.Name(), "_", 2)
		if len(parts) < 2 || len(parts[0]) != 3 {
			continue
		}
		var v int
		if _, err := fmt.Sscanf(parts[0], "%d", &v); err != nil {
			continue
		}
		if v < lo || v > hi {
			continue
		}
		migs = append(migs, mig{version: v, name: e.Name(), path: dir + "/" + e.Name()})
	}
	// Sort by (version, name) ascending — composite key per
	// reference_migration_runner_composite_key.md.
	for i := 0; i < len(migs); i++ {
		for j := i + 1; j < len(migs); j++ {
			if migs[i].version > migs[j].version ||
				(migs[i].version == migs[j].version && migs[i].name > migs[j].name) {
				migs[i], migs[j] = migs[j], migs[i]
			}
		}
	}
	for _, m := range migs {
		body, err := os.ReadFile(m.path)
		if err != nil {
			t.Fatalf("read %s: %v", m.path, err)
		}
		if _, err := db.Exec(string(body)); err != nil {
			t.Fatalf("apply migration %s: %v", m.name, err)
		}
	}
}
