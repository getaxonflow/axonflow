// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// #3957 item 1: the LICENSED tier reaches the database through exactly one
// path - `promoteDeploymentOrgTier` at boot - and until now nothing checked
// that it arrived.
//
// WHY THIS OUTRANKS THE OTHER ITEMS ON THAT AUDIT. Migration 094 seeds the
// deployment org at `tier='Community', max_nodes=2` with ON CONFLICT DO
// NOTHING. The licensed values arrive only through this call, whose failure was
// a `log.Printf` and a `return`, deliberately non-fatal. So a licensed
// Enterprise deployment whose promotion failed reads **Community, 2 nodes**
// from the database - and **absence is detectable, a plausible wrong value is
// not**.
//
// The sharp consequence is not the portal showing the wrong badge. It is
// `platform/agent/node_enforcement/monitor.go:121`, which reads
// `organizations.max_nodes` and records a LICENCE VIOLATION for every node past
// the cap. On a fully licensed deployment holding max_nodes=2, node three
// onwards is written into `node_violations` as an infringement. Also reading
// the row: the portal's licence page (`api/license.go:53`), its node pages
// (`api/nodes.go:174,275`) and its admin tier read (`api/admin.go:81`).
//
// WHAT THIS FILE ADDS: the promotion helper now REPORTS THE ROW IT WROTE, from
// inside its own SECURITY DEFINER body (migrations/core/175), and this file
// compares that with the licence - so "the write did not error" becomes "the row
// holds the licensed values". The outcome is published where a machine reads it:
// `/health`, beside the in-memory tier it can now be compared against, and a
// Prometheus gauge.
//
// The read is INSIDE the function rather than a SELECT here, and that is the
// load-bearing choice - see promoteAndReadDeploymentOrgLicense below for the
// FORCE RLS precondition it removes rather than assumes.
//
// IT IS STILL NOT FATAL, and that is deliberate: the agent's in-memory tier is
// already correct, so a transient database hiccup here must not stop a licensed
// deployment from serving. What changes is that the divergence stops being
// invisible.
//
// A SHAPE THE AUDIT DOES NOT NAME, AND THIS IS WHY IT IS NOW COVERED.
// `promote_deployment_org_license` wrapped its whole body in `IF EXISTS (SELECT
// 1 FROM information_schema.tables WHERE table_name = 'organizations')` (mig
// 117, carried forward by 142). When that guard was false the function RETURNED
// SUCCESSFULLY HAVING WRITTEN NOTHING - `db.Exec` reported no error and the old
// code logged `✅ Synced licensed tier`. A success line for a write that never
// happened is the same class as the media seeder's metric reporting
// `source="database"` on a deployment with none of the policies (#3957 item 2).
// Nothing about the Exec result could distinguish it. Core/175 makes that state
// observable - it comes back as zero rows - and qualifies the guard with
// `table_schema = 'public'`, which is the schema the INSERT actually targets.

import (
	"database/sql"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// licenseTierDBSyncVerified is 1 when the deployment org's row was READ BACK
// and holds the licensed values, 0 when it was attempted and does not.
//
// IT IS KEYED ON THE VERIFICATION, NOT ON THE CALL RETURNING. That distinction
// is the whole reason this exists: #3957 item 2 records `policySetSource`
// flipping to "database" on the first successful LOAD regardless of whether the
// SEED worked, so the metric that exists to detect a class reports healthy on a
// deployment exhibiting it. A gauge set from `err == nil` here would be the
// same defect wearing this issue's number.
//
// No labels. There is exactly one deployment org per agent process, so an
// org_id label would be a constant, and a `reason` label would put unbounded
// text into a time series - the reason belongs in /health and the boot log,
// which is where it is.
//
// IT IS REGISTERED LAZILY, ON THE FIRST PUBLISH, AND THAT IS THE WHOLE POINT.
// The first version of this used `promauto.NewGauge`, whose Help text promised
// "Absent when no promotion was attempted". **A registered plain Gauge is never
// absent.** Gathering `DefaultGatherer` in a process that published nothing
// yields `axonflow_license_tier_db_sync_verified 0` - which the same Help text
// defines as "attempted and does not match". So every community /
// community-saas / central-agent deployment, and every licensed one during
// boot, exported 0, and an alert on `== 0` would fire on every healthy
// deployment. That is exactly the fire-on-healthy failure this file argues the
// whole read-back design around (see promoteAndReadDeploymentOrgLicense), one
// layer up, in the instrument rather than the check. Found by R3, not by me.
//
// Registering on first publish makes "absent" mean what the Help says: a
// process that never attempted a promotion never registers the collector, so
// the series does not appear in `/prometheus` at all. `prometheus.Register` is
// used rather than `MustRegister` and its error is discarded deliberately - the
// sync.Once already guarantees one attempt, so the only reachable error is a
// duplicate registration from a second agent in one process (tests), where
// dropping it is correct.
//
// `testutil.ToFloat64` reads the collector directly rather than the registry,
// so the unit tests still observe the value whether or not it is registered.
var (
	licenseTierDBSyncVerified = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "axonflow_license_tier_db_sync_verified",
		Help: "1 when organizations.tier/max_nodes were read back and match the validated licence, 0 when a promotion was attempted and they do not. Absent (collector unregistered) when no promotion was attempted at all - community mode, or no licence.",
	})
	licenseTierDBSyncRegisterOnce sync.Once

	// licenseSyncRegisterer is the registry the gauge lands in. Overridden only
	// by tests, which also reset the Once - the same way resetLicenseSyncState
	// already resets licenseSyncState. It exists so a test can assert the
	// series is genuinely ABSENT before the first publish, which is the exact
	// property F2 got wrong and which no test could see while the target was
	// the process-wide default registry.
	licenseSyncRegisterer prometheus.Registerer = prometheus.DefaultRegisterer
)

// licenseSyncValues is the (tier, max_nodes, expires_at) triple the licence
// asks for and the database holds.
type licenseSyncValues struct {
	Tier      string
	MaxNodes  int
	ExpiresAt time.Time // zero means "no expiry" / SQL NULL
}

// licenseSyncStatus is the published outcome of the boot-time promotion.
type licenseSyncStatus struct {
	// Verified is true only when the row was read back and matched.
	Verified bool
	// Reason is empty when Verified; otherwise it names what diverged, in
	// terms an operator can act on.
	Reason string
	Want   licenseSyncValues
	Got    licenseSyncValues
	// GotRow is false when no organizations row could be read at all, which is
	// a different problem from a row holding the wrong values.
	GotRow bool
}

// licenseSyncState holds the last promotion outcome. Nil means no promotion was
// attempted - community / community-saas / central-agent modes, which have no
// licence to sync. `/health` OMITS the member in that case rather than emitting
// a false "unverified", following the same rule the platform-identity members
// use: a value the platform cannot determine is absent, not empty.
var licenseSyncState atomic.Value // licenseSyncStatus

// currentLicenseSync returns the recorded outcome and whether one exists.
func currentLicenseSync() (licenseSyncStatus, bool) {
	v := licenseSyncState.Load()
	if v == nil {
		return licenseSyncStatus{}, false
	}
	s, ok := v.(licenseSyncStatus)
	return s, ok
}

// licenseSyncHealth renders the outcome for /health, or nil when none was
// attempted.
func licenseSyncHealth() map[string]interface{} {
	s, ok := currentLicenseSync()
	if !ok {
		return nil
	}
	out := map[string]interface{}{
		"verified":           s.Verified,
		"licensed_tier":      s.Want.Tier,
		"licensed_max_nodes": s.Want.MaxNodes,
	}
	if !s.Verified {
		out["reason"] = s.Reason
		// The DATABASE values are reported only when a row was actually read.
		// Emitting a zero-valued pair for "could not read" would say the
		// database holds tier "" / 0 nodes, which is a claim nothing measured.
		if s.GotRow {
			out["database_tier"] = s.Got.Tier
			out["database_max_nodes"] = s.Got.MaxNodes
		}
	}
	return out
}

// sameExpiry compares two expiry instants at SECOND granularity.
//
// Not strictness for its own sake, and not laziness either: the licence carries
// a Go time.Time with NANOSECONDS and `organizations.expires_at` is a Postgres
// TIMESTAMPTZ (retyped from TIMESTAMP by mig 142) storing MICROSECONDS, so a
// round-trip cannot return the value that was sent. A strict Equal would report a divergence on a perfectly healthy
// deployment - and a guard that fires on healthy deployments is one that gets
// switched off, which is worse than not having it.
//
// Tier and max_nodes are compared EXACTLY: they are a string and an integer,
// they round-trip losslessly, and they are the two values the enforcement paths
// actually read.
func sameExpiry(a, b time.Time) bool {
	if a.IsZero() != b.IsZero() {
		return false
	}
	if a.IsZero() {
		return true
	}
	return a.UTC().Truncate(time.Second).Equal(b.UTC().Truncate(time.Second))
}

// promoteAndReadDeploymentOrgLicense promotes the row and reports what it holds
// afterwards, in ONE call to the core/175 SECURITY DEFINER helper.
//
// WHY THE READ IS NOT A SELECT HERE, which is the whole design of #3957 item 1.
//
// The obvious implementation is `SELECT promote_...()` followed by
// `SELECT tier, max_nodes, expires_at FROM organizations WHERE org_id = $1`.
// That second statement rests on a precondition nobody has established:
// `organizations` carries FORCE ROW LEVEL SECURITY (mig 103) - which binds the
// table OWNER too, not only non-owners - under a policy keyed on
// `current_setting('app.current_org_id', true)`, and this connection never sets
// that GUC (setMigrationSessionVars sets app.db_password,
// app.deployment_org_id and app.deployment_kind, and nothing else).
//
// If the precondition is false the SELECT returns ZERO ROWS on a healthy
// deployment, and the agent then reports "the licensed tier reached nothing" on
// every boot - a guard that fires on healthy deployments, which is worse than
// the silence it replaced. It cannot be settled by reading the tree: migrations
// 146, 148, 149, 151 and 165 all read `organizations` unfiltered after 103, and
// every one of them is SILENTLY SATISFIED by seeing nothing (146 loops over
// zero orgs, 149 counts zero orphans, 145 only warns). Vacuous negatives, not
// evidence.
//
// Moving the read inside the SECURITY DEFINER function removes the dependency
// instead of assuming it: whatever lets the INSERT happen lets the SELECT see
// its result, and if the owner cannot see the row then the INSERT could not
// have happened either. Zero rows back is then the honest answer rather than a
// guess about privileges.
//
// A DEPLOYMENT WITHOUT core/175 fails here, on purpose. The pre-175 helper
// RETURNS VOID, so `SELECT * FROM promote_...()` errors against it; that is
// reported as a failed promotion, which is the correct reading of a schema that
// has not run the migration. Migrations run before this call on every boot, so
// the only way to reach it is a rolled-back 175.
func promoteAndReadDeploymentOrgLicense(db *sql.DB, orgID string, want licenseSyncValues) (licenseSyncValues, bool, error) {
	// A zero ExpiresAt (no-expiry / perpetual licence) is passed as SQL NULL so
	// it matches organizations.expires_at's nullable column and the portal's
	// "NULL expires_at = unbounded" status logic (license.go).
	var expiresArg interface{}
	if !want.ExpiresAt.IsZero() {
		expiresArg = want.ExpiresAt.UTC()
	}

	var (
		tier      string
		maxNodes  int
		expiresAt sql.NullTime
	)
	err := db.QueryRow(
		// promote_deployment_org_license_RETURNING, not the bare name (#4007).
		// The bare name is 142's RETURNS VOID signature and must stay that way
		// so 142 remains re-runnable at the fully-migrated state; migration 175
		// keeps it as a forwarder and puts the row-reporting body under this
		// name. Calling the forwarder here would scan zero columns.
		"SELECT out_tier, out_max_nodes, out_expires_at FROM promote_deployment_org_license_returning($1, $2, $3, $4)",
		orgID, want.Tier, want.MaxNodes, expiresArg,
	).Scan(&tier, &maxNodes, &expiresAt)
	if err == sql.ErrNoRows {
		// The helper wrote nothing readable. Two schema states produce this and
		// neither is a licensed deployment in good order: no public.organizations
		// table at all, or a row the function owner cannot see.
		return licenseSyncValues{}, false, nil
	}
	if err != nil {
		return licenseSyncValues{}, false, err
	}
	got := licenseSyncValues{Tier: tier, MaxNodes: maxNodes}
	if expiresAt.Valid {
		got.ExpiresAt = expiresAt.Time
	}
	return got, true, nil
}

// verifyLicenseSync compares what was asked for with what the row holds and
// records the outcome. Extracted as a pure function of the two triples so its
// controls can drive it with planted values rather than by breaking a database.
func verifyLicenseSync(want, got licenseSyncValues, gotRow bool, execErr error) licenseSyncStatus {
	s := licenseSyncStatus{Want: want, Got: got, GotRow: gotRow}
	switch {
	case execErr != nil:
		s.Reason = fmt.Sprintf("the promotion call failed: %v", execErr)
		// A schema without core/175 lands here: the pre-175 helper RETURNS VOID
		// and the query below selects columns from it, so Postgres reports a
		// function-does-not-exist / wrong-form error rather than returning a
		// row. That is a real finding on a deployment expected to have run it.
	case !gotRow:
		s.Reason = "no organizations row for this deployment org, so the licensed tier reached nothing"
	case got.Tier != want.Tier:
		s.Reason = fmt.Sprintf("organizations.tier is %q and the licence is %q", got.Tier, want.Tier)
	case got.MaxNodes != want.MaxNodes:
		s.Reason = fmt.Sprintf("organizations.max_nodes is %d and the licence allows %d", got.MaxNodes, want.MaxNodes)
	case !sameExpiry(got.ExpiresAt, want.ExpiresAt):
		s.Reason = fmt.Sprintf("organizations.expires_at is %s and the licence expires %s",
			describeExpiry(got.ExpiresAt), describeExpiry(want.ExpiresAt))
	default:
		s.Verified = true
	}
	return s
}

func describeExpiry(t time.Time) string {
	if t.IsZero() {
		return "unbounded"
	}
	return t.UTC().Format(time.RFC3339)
}

// publishLicenseSync stores the outcome, sets the gauge and logs it.
//
// The gauge is registered HERE, on first publish, so that a deployment which
// never attempts a promotion never exports the series - see the collector's own
// comment for why "absent" has to be real.
func publishLicenseSync(s licenseSyncStatus, orgID string) {
	licenseSyncState.Store(s)
	licenseTierDBSyncRegisterOnce.Do(func() {
		_ = licenseSyncRegisterer.Register(licenseTierDBSyncVerified)
	})
	if s.Verified {
		licenseTierDBSyncVerified.Set(1)
		log.Printf("✅ Licensed tier verified in organizations: org=%s tier=%s max_nodes=%d (#2535, verified by read-back #3957)",
			orgID, s.Want.Tier, s.Want.MaxNodes)
		return
	}
	licenseTierDBSyncVerified.Set(0)
	// The CONSEQUENCE is named, not just the divergence. An operator reading
	// "failed to sync licensed tier" cannot tell whether it matters; one
	// reading that node three onwards will be recorded as a licence violation
	// can.
	// The cap named here is the LICENSED one (Want), not the one read back (Got).
	// Got.MaxNodes is zero in both arms that can reach this line - a failed call
	// and an unreadable row - so the old text told an operator their nodes beyond
	// ZERO would be recorded as violations. Want is known in every arm.
	log.Printf("⚠️  LICENSED TIER NOT IN THE DATABASE for org=%s: %s. "+
		"/health reports the licence correctly from memory, but every DB consumer does not: "+
		"node-limit enforcement reads organizations.max_nodes rather than the %d your licence "+
		"allows, and the portal will show the wrong tier and expiry. The next boot re-attempts "+
		"the sync; axonflow_license_tier_db_sync_verified is 0 until it succeeds (#3957)",
		orgID, s.Reason, s.Want.MaxNodes)
}
