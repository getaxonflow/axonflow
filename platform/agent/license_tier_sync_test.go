// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// #3957 item 1. These drive the promotion path through sqlmock rather than a
// real Postgres, deliberately: the property under test is what the agent
// CONCLUDES from what the database returned, and sqlmock lets a test state the
// database's answer directly instead of arranging a schema that produces it.
// The real-Postgres leg - that migration 117's helper actually lands the values
// - is `migration_117_promote_org_license_test.go`, which this does not
// replace.

import (
	"database/sql"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"encoding/json"
	"net/http"
	"net/http/httptest"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// The core/175 helper is called ONCE and reports the row it wrote, so there is
// a single statement to mock rather than an Exec plus a follow-up SELECT.
//
// ANCHORED ON THE _returning NAME AND ITS OPENING PAREN, BECAUSE sqlmock's
// ExpectQuery TAKES A REGEX (#4007 review). The bare name
// `promote_deployment_org_license` is a PREFIX of
// `promote_deployment_org_license_returning`, so as a regex it matched both -
// and these four tests then passed with the production call pointed at either
// name. That is the one mutant this change exists to prevent, and the
// on-every-PR tier could not see it: only the real-Postgres lane, which is dark
// on `main` (#3972), reds a call to the VOID forwarder. The trailing `\(`
// pins the call site rather than any mention of the identifier.
const promoteSQL = `promote_deployment_org_license_returning\(`

// resetLicenseSyncState clears the package-level status between tests.
//
// A fresh atomic.Value is assigned rather than storing a zero status, because
// an atomic.Value cannot be cleared once written and the "nothing was
// attempted" case is exactly what TestHealthOmitsLicenseSyncWhenNoneWasAttempted
// needs to observe.
func resetLicenseSyncState(t *testing.T) {
	t.Helper()
	licenseSyncState = atomic.Value{}
	licenseTierDBSyncVerified.Set(0)
	// The gauge registers lazily on first publish (#3957 F2), so the Once and
	// its target registry are package state too. Resetting them here keeps every
	// test's registration path independent of test ORDER - otherwise the first
	// test to publish would register into the process registry and no later test
	// could observe the absent state.
	licenseTierDBSyncRegisterOnce = sync.Once{}
	reg := prometheus.NewRegistry()
	licenseSyncRegisterer = reg
	t.Cleanup(func() { licenseSyncRegisterer = prometheus.DefaultRegisterer })
	licenseSyncTestRegistry = reg
}

// licenseSyncTestRegistry is the registry resetLicenseSyncState pointed the
// gauge at, so a test can gather it.
var licenseSyncTestRegistry *prometheus.Registry

// gaugeIn reports whether the licence-sync series exists in the given gatherer.
func gaugeIn(t *testing.T, g prometheus.Gatherer) bool {
	t.Helper()
	families, err := g.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, f := range families {
		if f.GetName() == "axonflow_license_tier_db_sync_verified" {
			return true
		}
	}
	return false
}

// TestTheGaugeIsAbsentUntilAPromotionIsAttempted is the test that would have
// caught F2, and it did not exist because I asserted the property in a Help
// string instead of in a test.
//
// The gauge's Help promised "Absent when no promotion was attempted". It was
// registered by `promauto` at package init, so it was NEVER absent: a process
// that published nothing still exported `… 0`, and the same Help text defines 0
// as "attempted and does not match". Every community deployment and every
// licensed one during boot exported 0, so an alert on `== 0` would fire on every
// healthy deployment - the fire-on-healthy failure this whole design is argued
// around, relocated into the instrument.
//
// A planted positive for the negative: assert the ABSENT state directly, then
// that a publish creates the series. Reverting to promauto registration makes
// the first half fail.
func TestTheGaugeIsAbsentUntilAPromotionIsAttempted(t *testing.T) {
	resetLicenseSyncState(t)

	// ABSENCE IS ASSERTED AGAINST THE DEFAULT REGISTRY, which is what /prometheus
	// exports and what an eager `promauto` registration at package init poisons.
	// The first version of this test gathered the per-test registry instead - a
	// registry nothing registers into eagerly - so it passed with the defect
	// planted and was evidence about nothing.
	if gaugeIn(t, prometheus.DefaultGatherer) {
		t.Fatal("the licence-sync gauge is registered in the DEFAULT registry before any promotion " +
			"was attempted. " +
			"Its Help says \"Absent … when no promotion was attempted at all\", but a registered " +
			"plain Gauge gathers as 0, which the same Help defines as \"attempted and they do not " +
			"match\" - so every community deployment would export a value an alert reads as a " +
			"failure (#3957 F2)")
	}

	// Attempted-and-failed: the series must now EXIST and read 0, because that
	// is a real finding an operator should alert on.
	publishLicenseSync(verifyLicenseSync(
		licenseSyncValues{Tier: "Enterprise", MaxNodes: 50},
		licenseSyncValues{}, false, nil), "org-3957")
	// PRESENCE is asserted where this test's publish actually went.
	if !gaugeIn(t, licenseSyncTestRegistry) {
		t.Error("after an attempted promotion the gauge is still absent; a real divergence would be unalertable")
	}
	if got := testutil.ToFloat64(licenseTierDBSyncVerified); got != 0 {
		t.Errorf("gauge is %v after an unverified promotion, want 0", got)
	}
}

// ---------------------------------------------------------------------------
// The comparison, as a pure function
// ---------------------------------------------------------------------------

// TestVerifyLicenseSyncNamesWhatDiverged asserts the REASON, not merely that
// the check refused. A status that says "not verified" and nothing else sends
// an operator to read a boot log for the difference, which is the state this
// change exists to end.
func TestVerifyLicenseSyncNamesWhatDiverged(t *testing.T) {
	expiry := time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)
	want := licenseSyncValues{Tier: "Enterprise", MaxNodes: 50, ExpiresAt: expiry}

	for _, tc := range []struct {
		name         string
		got          licenseSyncValues
		gotRow       bool
		execErr      error
		wantVerified bool
		reasonHas    []string
	}{
		{
			name: "the row holds the licensed values", got: want, gotRow: true, wantVerified: true,
		},
		{
			// THE #3957 SHAPE: migration 094's placeholder, untouched.
			name:      "the migration-094 Community placeholder survived the promotion",
			got:       licenseSyncValues{Tier: "Community", MaxNodes: 2, ExpiresAt: expiry},
			gotRow:    true,
			reasonHas: []string{"organizations.tier", "Community", "Enterprise"},
		},
		{
			name:      "the node cap diverges while the tier matches",
			got:       licenseSyncValues{Tier: "Enterprise", MaxNodes: 2, ExpiresAt: expiry},
			gotRow:    true,
			reasonHas: []string{"max_nodes", "2", "50"},
		},
		{
			name:      "the expiry diverges",
			got:       licenseSyncValues{Tier: "Enterprise", MaxNodes: 50, ExpiresAt: expiry.AddDate(1, 0, 0)},
			gotRow:    true,
			reasonHas: []string{"expires_at", "2028"},
		},
		{
			// A DIFFERENT PROBLEM from a wrong value, and it must read as one.
			name:      "no row at all",
			gotRow:    false,
			reasonHas: []string{"no organizations row"},
		},
		{
			name:      "the promotion call itself failed",
			got:       licenseSyncValues{Tier: "Community", MaxNodes: 2},
			gotRow:    true,
			execErr:   errors.New("function promote_deployment_org_license does not exist"),
			reasonHas: []string{"promotion call failed", "does not exist"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := verifyLicenseSync(want, tc.got, tc.gotRow, tc.execErr)
			if s.Verified != tc.wantVerified {
				t.Fatalf("Verified=%v, want %v (reason=%q)", s.Verified, tc.wantVerified, s.Reason)
			}
			if tc.wantVerified {
				if s.Reason != "" {
					t.Errorf("a verified sync carries reason %q; it must be empty", s.Reason)
				}
				return
			}
			for _, frag := range tc.reasonHas {
				if !strings.Contains(s.Reason, frag) {
					t.Errorf("reason %q does not name %q — an operator cannot act on a refusal that "+
						"does not say what diverged", s.Reason, frag)
				}
			}
		})
	}
}

// TestTheExpiryComparisonDoesNotFireOnARoundTrip is the false-alarm direction,
// and it is the one that would get this guard switched off.
//
// The licence carries a Go time.Time with NANOSECONDS; organizations.expires_at
// is a Postgres TIMESTAMP storing MICROSECONDS. A strict Equal would report a
// divergence on every healthy deployment carrying a sub-second licence expiry.
func TestTheExpiryComparisonDoesNotFireOnARoundTrip(t *testing.T) {
	licensed := time.Date(2027, 5, 6, 7, 8, 9, 123456789, time.UTC)
	roundTripped := time.Date(2027, 5, 6, 7, 8, 9, 123456000, time.UTC) // µs precision

	if !sameExpiry(licensed, roundTripped) {
		t.Error("a microsecond-truncated round trip of the SAME instant read as a divergence. This " +
			"guard would fire on every healthy deployment, and a guard that fires on healthy " +
			"deployments is one that gets switched off.")
	}
	// The other half: a genuinely different expiry must still be caught, or the
	// tolerance above is indistinguishable from not comparing at all.
	if sameExpiry(licensed, licensed.Add(48*time.Hour)) {
		t.Error("two expiries two days apart compared equal; the tolerance is not a tolerance, it is " +
			"a disabled check")
	}
	// And unbounded-versus-bounded is a divergence, not a tolerance case.
	if sameExpiry(time.Time{}, licensed) {
		t.Error("an unbounded licence compared equal to a bounded row")
	}
	if !sameExpiry(time.Time{}, time.Time{}) {
		t.Error("two unbounded expiries compared unequal")
	}
}

// ---------------------------------------------------------------------------
// The whole path, through a mocked database
// ---------------------------------------------------------------------------

func mockAgentDB(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, mock
}

// TestASilentlyNoOpPromotionIsReported is the assertion the old code could not
// make, and the reason this change is not just extra logging.
//
// migrations/core/117 wraps the whole function body in
// `IF EXISTS (... table_name = 'organizations')`. When that guard is false the
// function RETURNS SUCCESSFULLY HAVING WRITTEN NOTHING: db.Exec reports no
// error, and the previous code logged `✅ Synced licensed tier`. This drives
// exactly that — an Exec that succeeds over a row that never moved.
func TestASilentlyNoOpPromotionIsReported(t *testing.T) {
	resetLicenseSyncState(t)
	db, mock := mockAgentDB(t)

	mock.ExpectQuery(promoteSQL).
		WithArgs("org-3957", "Enterprise", 50, nil).
		WillReturnRows(sqlmock.NewRows([]string{"out_tier", "out_max_nodes", "out_expires_at"}).
			AddRow("Community", 2, nil))

	promoteDeploymentOrgTier(db, "org-3957", "Enterprise", 50, time.Time{})

	s, ok := currentLicenseSync()
	if !ok {
		t.Fatal("no license-sync status was published at all")
	}
	if s.Verified {
		t.Fatal("a promotion that returned success over an UNCHANGED row was reported as verified. " +
			"That is the exact reading the pre-#3957 code emitted a ✅ for: nothing about the Exec " +
			"result can distinguish a real write from mig-117's table-exists guard silently skipping " +
			"the INSERT, and only reading the row can.")
	}
	if !strings.Contains(s.Reason, "Community") || !strings.Contains(s.Reason, "Enterprise") {
		t.Errorf("reason %q does not name both the value found and the value licensed", s.Reason)
	}
	if got := testutil.ToFloat64(licenseTierDBSyncVerified); got != 0 {
		t.Errorf("axonflow_license_tier_db_sync_verified is %v; an unverified sync must read 0. A "+
			"gauge set from `err == nil` would read 1 here, which is #3957 item 2's defect wearing "+
			"item 1's number.", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// TestAVerifiedPromotionReadsVerified is the other half. Without it, a status
// that reported EVERY sync as unverified would satisfy the test above.
func TestAVerifiedPromotionReadsVerified(t *testing.T) {
	resetLicenseSyncState(t)
	db, mock := mockAgentDB(t)
	expiry := time.Date(2027, 3, 4, 5, 6, 7, 0, time.UTC)

	mock.ExpectQuery(promoteSQL).
		WithArgs("org-3957", "Enterprise", 50, expiry).
		WillReturnRows(sqlmock.NewRows([]string{"out_tier", "out_max_nodes", "out_expires_at"}).
			AddRow("Enterprise", 50, expiry))

	promoteDeploymentOrgTier(db, "org-3957", "Enterprise", 50, expiry)

	s, ok := currentLicenseSync()
	if !ok {
		t.Fatal("no license-sync status was published")
	}
	if !s.Verified {
		t.Fatalf("a row holding the licensed values read as unverified: %s", s.Reason)
	}
	if got := testutil.ToFloat64(licenseTierDBSyncVerified); got != 1 {
		t.Errorf("axonflow_license_tier_db_sync_verified is %v, want 1", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// TestAFailedPromotionCallIsReportedWithItsError covers the two states that
// reach the error arm, and they are NOT the same operational problem.
//
// A transient failure (deadlock, connection reset) and a schema that has not
// run core/175 both surface as an error from the one call. The second is worth
// spelling out: the pre-175 helper RETURNS VOID, so selecting columns from it
// errors rather than returning a row, and reporting that as a failed promotion
// is the correct reading of a rolled-back schema.
func TestAFailedPromotionCallIsReportedWithItsError(t *testing.T) {
	for _, tc := range []struct {
		name      string
		dbErr     error
		reasonHas string
	}{
		{"a transient failure", errors.New("deadlock detected"), "deadlock"},
		{
			"a schema without core/175, whose helper returns void",
			errors.New(`ERROR: column "out_tier" does not exist`),
			"out_tier",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetLicenseSyncState(t)
			db, mock := mockAgentDB(t)
			mock.ExpectQuery(promoteSQL).WillReturnError(tc.dbErr)

			promoteDeploymentOrgTier(db, "org-3957", "Enterprise", 50, time.Time{})

			s, ok := currentLicenseSync()
			if !ok {
				t.Fatal("no status was published for a failed call")
			}
			if s.Verified {
				t.Fatal("a promotion whose call errored was reported as verified")
			}
			if !strings.Contains(s.Reason, tc.reasonHas) {
				t.Errorf("reason %q does not carry the underlying error (%q)", s.Reason, tc.reasonHas)
			}
			if s.GotRow {
				t.Error("GotRow is true after a failed call; /health would then publish an unmeasured " +
					"database_tier")
			}
			if got := testutil.ToFloat64(licenseTierDBSyncVerified); got != 0 {
				t.Errorf("gauge is %v after a failed call, want 0", got)
			}
		})
	}
}

// TestNoRowsBackMeansTheLicensedValuesAreNotReadable pins the zero-row answer.
//
// core/175 returns no rows in two schema states and neither is a licensed
// deployment in good order: no public.organizations table at all, or a row the
// function owner cannot see. Both must read as "reached nothing" rather than as
// a row holding tier "" and 0 nodes.
func TestNoRowsBackMeansTheLicensedValuesAreNotReadable(t *testing.T) {
	resetLicenseSyncState(t)
	db, mock := mockAgentDB(t)

	mock.ExpectQuery(promoteSQL).
		WillReturnRows(sqlmock.NewRows([]string{"out_tier", "out_max_nodes", "out_expires_at"}))

	promoteDeploymentOrgTier(db, "org-3957", "Enterprise", 50, time.Time{})

	s, _ := currentLicenseSync()
	if s.Verified {
		t.Fatal("zero rows back was reported as a verified promotion")
	}
	if !strings.Contains(s.Reason, "no organizations row") {
		t.Errorf("reason %q does not say the licensed tier reached nothing", s.Reason)
	}
	if s.GotRow {
		t.Error("GotRow is true with zero rows back")
	}
	if h := licenseSyncHealth(); h != nil {
		if _, ok := h["database_tier"]; ok {
			t.Errorf("health published database_tier=%v from a row that was never read", h["database_tier"])
		}
	}
}

// ---------------------------------------------------------------------------
// What /health publishes
// ---------------------------------------------------------------------------

func TestHealthOmitsLicenseSyncWhenNoneWasAttempted(t *testing.T) {
	resetLicenseSyncState(t)
	if got := licenseSyncHealth(); got != nil {
		t.Errorf("licenseSyncHealth returned %v with no promotion attempted. Community, "+
			"community-saas and central-agent modes have no licence to sync, and reporting them as "+
			"`verified:false` would be a refusal nobody can act on.", got)
	}
}

func TestHealthReportsTheDivergenceAndOmitsUnmeasuredValues(t *testing.T) {
	resetLicenseSyncState(t)
	publishLicenseSync(verifyLicenseSync(
		licenseSyncValues{Tier: "Enterprise", MaxNodes: 50},
		licenseSyncValues{Tier: "Community", MaxNodes: 2},
		true, nil), "org-3957")

	h := licenseSyncHealth()
	if h == nil {
		t.Fatal("licenseSyncHealth returned nil after a published status")
	}
	if h["verified"] != false {
		t.Errorf("verified=%v, want false", h["verified"])
	}
	if h["licensed_tier"] != "Enterprise" || h["database_tier"] != "Community" {
		t.Errorf("health does not carry BOTH sides of the divergence: %v", h)
	}
	if h["licensed_max_nodes"] != 50 || h["database_max_nodes"] != 2 {
		t.Errorf("health does not carry both node caps: %v", h)
	}

	// A verified sync must NOT publish database_* members: they would be a
	// second copy of the licensed values, and a reader could not tell the
	// member apart from a measurement.
	resetLicenseSyncState(t)
	publishLicenseSync(verifyLicenseSync(
		licenseSyncValues{Tier: "Enterprise", MaxNodes: 50},
		licenseSyncValues{Tier: "Enterprise", MaxNodes: 50},
		true, nil), "org-3957")
	h = licenseSyncHealth()
	if _, ok := h["database_tier"]; ok {
		t.Errorf("a verified sync published database_tier: %v", h)
	}
	if _, ok := h["reason"]; ok {
		t.Errorf("a verified sync published a reason: %v", h)
	}

	// And an unread row must not publish database_* either.
	resetLicenseSyncState(t)
	publishLicenseSync(verifyLicenseSync(
		licenseSyncValues{Tier: "Enterprise", MaxNodes: 50},
		licenseSyncValues{}, false, nil), "org-3957")
	h = licenseSyncHealth()
	if _, ok := h["database_tier"]; ok {
		t.Errorf("a status with no row read published database_tier=%v; that is a value nothing "+
			"measured", h["database_tier"])
	}
}

// TestHealthResponseOmitsTheLicenseSyncKeyEntirely tests the rule THROUGH THE
// SEAM AN OPERATOR READS, which the rest of this file does not.
//
// R3 round 2 found this: every other test here asserts on
// `licenseSyncHealth()`, the PRODUCER. The rule an operator actually depends on
// is one layer up, in the handler:
//
//	if ls := licenseSyncHealth(); ls != nil { body["license_sync"] = ls }
//
// Replacing that conditional with an unconditional assignment left ALL nine
// licence-sync tests and all six health-named tests GREEN, while /health would
// emit `"license_sync": null` on every unlicensed boot - precisely the "cannot
// tell no-licence from licence-did-not-arrive" case this design exists to
// prevent. A control has to sit BELOW the seam it tests through; a nil-returning
// producer proves nothing about a handler that assigns unconditionally.
//
// Nothing covered that seam except the runtime suite, which was `unwired` until
// this PR - so the rule had never been asserted anywhere that runs.
//
// This reads the ENCODED RESPONSE, which is also strictly better than the shell
// assertion in the runtime suite: `health_field` returns the empty string both
// for an absent member and for a present-but-null one, so it cannot tell them
// apart. `json.Decode` into a map can.
func TestHealthResponseOmitsTheLicenseSyncKeyEntirely(t *testing.T) {
	resetLicenseSyncState(t)

	decodeHealth := func() map[string]interface{} {
		t.Helper()
		rec := httptest.NewRecorder()
		readinessAwareHealthHandler(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("/health returned %d, want 200", rec.Code)
		}
		var body map[string]interface{}
		if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
			t.Fatalf("decode /health body: %v", err)
		}
		return body
	}

	// NOTHING PUBLISHED: the key must be ABSENT, not present-and-null.
	body := decodeHealth()
	if v, ok := body["license_sync"]; ok {
		t.Errorf("/health carries a license_sync key (=%v) when no promotion was attempted. "+
			"A client cannot then tell \"this deployment has no licence to sync\" from \"the licence "+
			"did not reach the database\", which is the distinction this member exists to make. "+
			"The handler must omit the key, not emit null.", v)
	}

	// PUBLISHED: the key must appear, and carry the licence.
	publishLicenseSync(verifyLicenseSync(
		licenseSyncValues{Tier: "Enterprise", MaxNodes: 50},
		licenseSyncValues{Tier: "Enterprise", MaxNodes: 50}, true, nil), "org-3957")
	body = decodeHealth()
	ls, ok := body["license_sync"]
	if !ok {
		t.Fatal("/health omits license_sync after a promotion was attempted; the outcome is then unreadable by any machine")
	}
	m, ok := ls.(map[string]interface{})
	if !ok {
		t.Fatalf("license_sync is %T, want an object", ls)
	}
	if m["verified"] != true {
		t.Errorf("license_sync.verified = %v, want true", m["verified"])
	}
	if m["licensed_tier"] != "Enterprise" {
		t.Errorf("license_sync.licensed_tier = %v, want Enterprise", m["licensed_tier"])
	}
}
