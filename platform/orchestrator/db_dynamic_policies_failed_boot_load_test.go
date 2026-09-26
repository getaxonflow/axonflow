// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
)

// A FAILED BOOT LOAD ARMS THE SHORT RETRY (#4249 row 5714565017), AND THE CAP
// READS THE MIGRATION MARK ONCE MORE (#4249 row 5683228870).
//
// An engine whose first load fails serves the built-in defaults, which carry
// none of the shipped sys_* rows, so every governed request those rows' controls
// read is refused unknown_constraint until a load succeeds. With a database
// configured the next attempt comes on the catch-up interval, bounded by the
// same cap, instead of the ordinary one.

// failedBootEngine is catchUpEngine serving the built-in defaults with a
// database configured, as NewDatabaseDynamicPolicyEngine leaves it when its
// first load fails.
func failedBootEngine(t *testing.T) (*DatabaseDynamicPolicyEngine, sqlmock.Sqlmock) {
	t.Helper()
	engine, mock := catchUpEngine(t)
	engine.dbURL = "postgres://failed-boot-load.invalid/axonflow"
	engine.policies = loadDefaultPoliciesCache()
	engine.policySetSource = policySetSourceDefaults
	return engine, mock
}

// expectFailedLoad answers one refresh whose mark read succeeds and whose
// policies SELECT fails the way a table core/010 has not created yet does.
func expectFailedLoad(mock sqlmock.Sqlmock, applied int64, last time.Time) {
	expectMigrationMark(mock, applied, last)
	mock.ExpectQuery(refreshPoliciesQueryPattern).WillReturnError(errors.New(`pq: relation "dynamic_policies" does not exist`))
}

// allSeededGlobalRows is every shipped dynamic_policies row, keyed 'global' as
// core/153 keys them, in a stable order.
func allSeededGlobalRows(t *testing.T) []seededCatchUpRow {
	t.Helper()
	conds, err := legacycompile.SeedDynamicConditions(seedDynamicMigrations...)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, len(conds))
	for id := range conds {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	rows := make([]seededCatchUpRow, 0, len(ids))
	for _, id := range ids {
		rows = append(rows, seededCatchUpRow{id, "global"})
	}
	return rows
}

// decideProcessOver asks the /api/v1/process route for a benign query through
// the real enforcer and the real route fact producer, over the engine's own
// organization-scoped list, the rows source the seam hands the producer.
func decideProcessOver(t *testing.T, engine *DatabaseDynamicPolicyEngine) *PolicyEvaluationResult {
	t.Helper()
	previous := orchestratorEnforcerInstance.Load()
	orchestratorEnforcerInstance.Store(&orchestratorEnforcerSlot{enforcement: stepDecisionEnforcer(t)})
	t.Cleanup(func() { orchestratorEnforcerInstance.Store(previous) })
	previousFactory := newRouteRequestFactProducer
	newRouteRequestFactProducer = func() (routeFactSource, error) {
		return testFactProducerOver(t, engine), nil
	}
	resetRouteRequestFacts()
	t.Cleanup(func() {
		newRouteRequestFactProducer = previousFactory
		resetRouteRequestFacts()
	})
	h := http.Header{}
	h.Set("X-Org-ID", "org-a")
	h.Set("X-Client-ID", "client-a")
	req := OrchestratorRequest{
		RequestID: "req-failed-boot", Query: "list the open tickets", RequestType: "llm_chat",
		User:   UserContext{OrgID: "org-a", TenantID: "t1"},
		Client: ClientContext{ID: "client-a", OrgID: "org-a", TenantID: "t1"},
	}
	return decideRouteRequest(context.Background(), h, req, processRouteAction).result
}

func withheldUnknownConstraint(r *PolicyEvaluationResult) bool {
	return r != nil && !r.Allowed && slices.ContainsFunc(r.RequiredActions, func(a string) bool {
		return strings.Contains(a, string(contract.ReasonUnknownConstraint))
	})
}

// (a) THE SCHEDULE: the wait after a failed boot load is the short one.
func TestScheduleNextRefresh_AFailedBootLoadRetriesOnTheCatchUpInterval(t *testing.T) {
	_ = captureLog(t)
	for _, tc := range []struct {
		name      string
		source    string
		dbURL     string
		state     policyCacheCatchUp
		ticks     int
		wantDelay time.Duration
		wantTicks int
		wantMode  string
	}{
		{"serving the defaults with a database configured: the short wait", policySetSourceDefaults, "postgres://x", policyCacheCatchUp{}, 0, 2 * time.Second, 1, refreshModeCatchUp},
		{"serving the defaults, N-1 spent: one more", policySetSourceDefaults, "postgres://x", policyCacheCatchUp{}, 2, 2 * time.Second, 3, refreshModeCatchUp},
		{"serving the defaults, N spent: exhausted", policySetSourceDefaults, "postgres://x", policyCacheCatchUp{mode: refreshModeCatchUp}, 3, 30 * time.Second, 3, refreshModeExhausted},
		{"serving the defaults, N+1 spent: still exhausted", policySetSourceDefaults, "postgres://x", policyCacheCatchUp{mode: refreshModeExhausted}, 4, 30 * time.Second, 4, refreshModeExhausted},
		{"no database configured (Community with no DATABASE_URL): the ordinary interval, unchanged", policySetSourceDefaults, "", policyCacheCatchUp{}, 0, 30 * time.Second, 0, refreshModeSteady},
		{"a load has succeeded and no trigger holds: the ordinary interval, unchanged", policySetSourceDatabase, "postgres://x", policyCacheCatchUp{}, 0, 30 * time.Second, 0, refreshModeSteady},
		{"a load succeeded after the cap was spent: its first mark read restarts the count", policySetSourceDatabase, "postgres://x", policyCacheCatchUp{moving: true, advanced: true, markSeen: true, mode: refreshModeExhausted}, 3, 2 * time.Second, 1, refreshModeCatchUp},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine := &DatabaseDynamicPolicyEngine{cacheTimeout: 30 * time.Second, catchUpInterval: 2 * time.Second, catchUpMaxTicks: 3,
				policySetSource: tc.source, dbURL: tc.dbURL, catchUp: tc.state}
			ticks := tc.ticks
			delay := engine.scheduleNextRefresh(&ticks)
			if delay != tc.wantDelay || ticks != tc.wantTicks || engine.catchUp.mode != tc.wantMode {
				t.Fatalf("delay=%v ticks=%d mode=%q; want %v, %d, %q", delay, ticks, engine.catchUp.mode, tc.wantDelay, tc.wantTicks, tc.wantMode)
			}
			requireRefreshMode(t, tc.wantMode)
		})
	}
}

// (a) THE REFUSAL: a failed boot load serves the defaults, which withhold a
// governed request unknown_constraint and never allow it; the next successful
// load comes on the catch-up interval and the same request is then decided.
func TestAFailedBootLoadIsRetriedWithinTheCatchUpInterval(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	t.Setenv("ENVIRONMENT", "production")
	settled := time.Date(2026, 9, 15, 4, 53, 1, 0, time.UTC)

	run := func(t *testing.T, interval time.Duration) (*DatabaseDynamicPolicyEngine, *lockedBuffer, *PolicyEvaluationResult) {
		engine, mock := failedBootEngine(t)
		engine.catchUpInterval = interval
		expectFailedLoad(mock, 9, settled)                       // the boot load: core/010 not applied yet
		expectFailedLoad(mock, 9, settled)                       // the first retry: still not there
		expectMigrationMark(mock, 173, settled.Add(time.Minute)) // then every migration is in
		expectSeededPolicyRows(t, mock, allSeededGlobalRows(t)...)
		for i := 0; i < 20; i++ {
			expectMigrationMark(mock, 173, settled.Add(time.Minute))
			expectSeededPolicyRows(t, mock, allSeededGlobalRows(t)...)
		}
		logs := captureLog(t)
		if err := engine.refreshPolicies(); err == nil {
			t.Fatal("PREMISE: the boot load succeeded; it must fail as a missing table does")
		}
		if got := engine.PolicySetSource(); got != policySetSourceDefaults {
			t.Fatalf("after a failed boot load the source is %q; want %q (swap-only-on-success)", got, policySetSourceDefaults)
		}
		if r := decideProcessOver(t, engine); !withheldUnknownConstraint(r) {
			t.Fatalf("PREMISE: served the defaults, the benign request answered allowed=%v required_actions=%v; want withheld naming %s, never an allow", r.Allowed, r.RequiredActions, contract.ReasonUnknownConstraint)
		}
		startRefreshLoop(t, engine)
		time.Sleep(250 * time.Millisecond) // a dozen 20ms catch-up intervals
		return engine, logs, decideProcessOver(t, engine)
	}

	t.Run("the retry comes on the catch-up interval and the request is then decided", func(t *testing.T) {
		engine, logs, r := run(t, 20*time.Millisecond)
		if got := engine.PolicySetSource(); got != policySetSourceDatabase {
			t.Fatalf("source=%q 250ms after a failed boot load; want %q. Log:\n%s", got, policySetSourceDatabase, logs.String())
		}
		if !r.Allowed {
			t.Fatalf("after the retry loaded the shipped rows, the benign request answered allowed=false required_actions=%v; want allowed", r.RequiredActions)
		}
		entered := logLinesContaining(logs, "policy cache catch-up: refreshing every 20ms")
		if len(entered) == 0 || !strings.Contains(entered[0], "serving the built-in defaults with a database configured=true") {
			t.Fatalf("the loop did not enter the catch-up for the failed boot load: %q. Log:\n%s", entered, logs.String())
		}
	})

	t.Run("PLANTED: at the ordinary interval the defaults are still served at the same instant", func(t *testing.T) {
		engine, _, r := run(t, time.Hour)
		if got := engine.PolicySetSource(); got != policySetSourceDefaults {
			t.Fatalf("source=%q with the catch-up at the ordinary interval; the positive above would prove nothing", got)
		}
		if !withheldUnknownConstraint(r) {
			t.Fatalf("with the catch-up at the ordinary interval the request answered allowed=%v required_actions=%v; want still withheld unknown_constraint", r.Allowed, r.RequiredActions)
		}
	})
}

// (b) A LOAD THAT KEEPS FAILING IS BOUNDED: the cap's refreshes, then the
// ordinary interval as exhausted, logged once, and the defaults still served.
func TestAPermanentlyFailingLoadExhaustsAtTheCap(t *testing.T) {
	engine, mock := failedBootEngine(t)
	engine.catchUpInterval = 5 * time.Millisecond
	engine.catchUpMaxTicks = 3
	settled := time.Date(2026, 9, 15, 4, 53, 1, 0, time.UTC)
	// The boot load, the 3 retries the cap allows, and 5 more that a loop
	// without the cap would take.
	for i := 0; i < 1+3+5; i++ {
		expectFailedLoad(mock, 9, settled)
	}
	logs := captureLog(t)
	if err := engine.refreshPolicies(); err == nil {
		t.Fatal("PREMISE: the boot load succeeded")
	}
	startRefreshLoop(t, engine)

	waitForLogCount(t, logs, "Background policy refresh failed", 3, 2*time.Second)
	time.Sleep(100 * time.Millisecond) // twenty catch-up intervals
	if n := strings.Count(logs.String(), "Background policy refresh failed"); n != 3 {
		t.Fatalf("a load that keeps failing was retried %d times by the loop; want 3 (the cap), then the ordinary interval. Log:\n%s", n, logs.String())
	}
	exhausted := logLinesContaining(logs, "policy cache catch-up EXHAUSTED")
	if len(exhausted) != 1 || !strings.Contains(exhausted[0], "no successful policy load") || !strings.Contains(exhausted[0], "still serving the built-in default policies") {
		t.Fatalf("want one EXHAUSTED line naming that no load has succeeded; got %q. Log:\n%s", exhausted, logs.String())
	}
	requireRefreshMode(t, refreshModeExhausted)
	if got := engine.PolicySetSource(); got != policySetSourceDefaults {
		t.Fatalf("source=%q after every load failed; want %q", got, policySetSourceDefaults)
	}
	engine.mu.RLock()
	cached := len(engine.policies)
	engine.mu.RUnlock()
	if want := len(loadDefaultPoliciesCache()); cached != want {
		t.Fatalf("the cache holds %d entries after every load failed; want the %d built-in defaults, never an emptied cache", cached, want)
	}
}

// (c) THE CAP READS THE MARK ONCE MORE.
func TestScheduleNextRefresh_TheCapReadsTheMigrationMarkOnceMore(t *testing.T) {
	_ = captureLog(t)
	m1 := schemaMigrationMark{applied: 172, lastApplied: time.Date(2026, 9, 15, 4, 53, 0, 0, time.UTC)}
	m2 := schemaMigrationMark{applied: 173, lastApplied: m1.lastApplied.Add(29 * time.Second)}
	armed := policyCacheCatchUp{moving: true, markSeen: true, mark: m1, mode: refreshModeCatchUp}
	for _, tc := range []struct {
		name      string
		state     policyCacheCatchUp
		ticks     int
		read      schemaMigrationMark
		readErr   error
		wantReads int
		wantDelay time.Duration
		wantTicks int
		wantMode  string
		wantMark  schemaMigrationMark
	}{
		{"the mark moved since the last credited one: the count restarts", armed, 3, m2, nil, 1, 2 * time.Second, 1, refreshModeCatchUp, m2},
		{"the mark is unchanged: the trigger clears to steady", armed, 3, m1, nil, 1, 30 * time.Second, 0, refreshModeSteady, m1},
		{"the re-read fails: the cap clears the trigger as before", armed, 3, schemaMigrationMark{}, errors.New("unreadable"), 1, 30 * time.Second, 0, refreshModeSteady, m1},
		{"N-1 spent: no re-read", armed, 2, m2, nil, 0, 2 * time.Second, 3, refreshModeCatchUp, m1},
		{"already exhausted: no re-read on every ordinary refresh", policyCacheCatchUp{unkeyedRows: 1, markSeen: true, mark: m1, mode: refreshModeExhausted}, 3, m2, nil, 0, 30 * time.Second, 3, refreshModeExhausted, m1},
		{"no mark was ever credited: nothing to have moved from", policyCacheCatchUp{unkeyedRows: 1, mode: refreshModeCatchUp}, 3, m2, nil, 0, 30 * time.Second, 3, refreshModeExhausted, schemaMigrationMark{}},
		{"a load already credited an advance: no re-read", policyCacheCatchUp{moving: true, advanced: true, markSeen: true, mark: m2, mode: refreshModeCatchUp}, 3, m1, nil, 0, 2 * time.Second, 1, refreshModeCatchUp, m2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reads := 0
			engine := &DatabaseDynamicPolicyEngine{cacheTimeout: 30 * time.Second, catchUpInterval: 2 * time.Second, catchUpMaxTicks: 3, catchUp: tc.state,
				capMarkReader: func(context.Context) (schemaMigrationMark, error) { reads++; return tc.read, tc.readErr }}
			ticks := tc.ticks
			delay := engine.scheduleNextRefresh(&ticks)
			if reads != tc.wantReads || delay != tc.wantDelay || ticks != tc.wantTicks || engine.catchUp.mode != tc.wantMode || !engine.catchUp.mark.equal(tc.wantMark) {
				t.Fatalf("reads=%d delay=%v ticks=%d mode=%q mark=%+v; want %d, %v, %d, %q, %+v", reads, delay, ticks, engine.catchUp.mode, engine.catchUp.mark, tc.wantReads, tc.wantDelay, tc.wantTicks, tc.wantMode, tc.wantMark)
			}
			requireRefreshMode(t, tc.wantMode)
		})
	}
}

// (c) THE BURST ROW 5683228870 MEASURED, WITH THE RE-READ: armed at 0.4s,
// migration 173 recorded at 29.0s, 174 at 31.0s, and the load at 30.4s either
// cannot read the mark or reads it before 173's record lands. Without the
// re-read 174 waited 29.4s (pinned, as filed, where the virtual clock has no
// reader: TestScheduleNextRefresh_AMigrationInsideTheBurstIsSeenWithinTheCatchUpInterval);
// the cap's re-read at 30.4s sees 173 and 174 waits 1.4s.
func TestScheduleNextRefresh_TheCapReReadCreditsAnAdvanceTheLastShortRefreshMissed(t *testing.T) {
	_ = captureLog(t)
	for _, tc := range []struct {
		name string
		// lastLoadErr is what the load at 30.4s meets: an error, or nil for a
		// read of the mark as it stood before 173's record (the record race).
		lastLoadErr error
		reReads     bool
		wantMax     float64
		wantMin     float64
	}{
		{"the last short refresh's mark read fails; the re-read sees 173", errors.New("unreadable"), true, 2, 0},
		{"the last short refresh reads before 173's record lands; the re-read sees it", nil, true, 2, 0},
		{"PLANTED: no re-read, the burst ends at the cap (the filed residual)", errors.New("unreadable"), false, 30, 29},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorded172 := time.Date(2026, 9, 15, 4, 53, 0, 0, time.UTC)
			at := func(s float64) time.Time { return recorded172.Add(time.Duration(s * float64(time.Second))) }
			markAt := func(now float64) schemaMigrationMark {
				switch {
				case now >= 31:
					return schemaMigrationMark{applied: 174, lastApplied: at(31)}
				case now >= 29:
					return schemaMigrationMark{applied: 173, lastApplied: at(29)}
				}
				return schemaMigrationMark{applied: 172, lastApplied: recorded172}
			}
			now, ticks := 0.4, 0
			engine := &DatabaseDynamicPolicyEngine{cacheTimeout: 30 * time.Second}
			if tc.reReads {
				engine.capMarkReader = func(context.Context) (schemaMigrationMark, error) { return markAt(now), nil }
			} else {
				engine.capMarkReader = func(context.Context) (schemaMigrationMark, error) {
					return schemaMigrationMark{}, errors.New("no re-read")
				}
			}
			for i := 0; i < 200; i++ {
				mark, markErr := markAt(now), error(nil)
				if now > 30.39 && now < 30.41 {
					if tc.lastLoadErr != nil {
						mark, markErr = schemaMigrationMark{}, tc.lastLoadErr
					} else {
						mark = markAt(28.9) // read before 173's record, which lands before the cap's re-read
					}
				}
				engine.mu.Lock()
				engine.catchUp.observe(0, mark, markErr)
				engine.mu.Unlock()
				if markErr == nil && mark.applied == 174 {
					stale := now - 31
					if stale > tc.wantMax || stale < tc.wantMin {
						t.Fatalf("migration 174 waited %.1fs for a load; want %v to %vs", stale, tc.wantMin, tc.wantMax)
					}
					return
				}
				now += engine.scheduleNextRefresh(&ticks).Seconds()
			}
			t.Fatal("no load read migration 174 within 200 refreshes")
		})
	}
}

// NOTHING SERVES AN EMPTY CACHE AS AN ALLOW. Two guards stand between a failed
// load and an empty cache deciding: the swap is success-only (the cache and the
// source move only after a load succeeds, pinned by
// TestRefreshPolicies_FailedRefreshNeverDowngradesSource and the source checks
// above), and the RLS-blind zero-row refusal precedes the swap on an RLS-scoped
// pool. Even past both, an empty cache states no fact for a shipped control, so
// the anchored engine withholds the request unknown_constraint: this cell pins
// that, with the cache emptied and the source set to database as a planted
// swap-on-failure would leave it.
func TestAnEmptyCacheWithholdsAGovernedRequestAndNeverAllowsIt(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	t.Setenv("ENVIRONMENT", "production")
	engine := &DatabaseDynamicPolicyEngine{policies: map[string]interface{}{}, policySetSource: policySetSourceDatabase}
	if r := decideProcessOver(t, engine); !withheldUnknownConstraint(r) {
		t.Fatalf("an empty cache answered the benign request allowed=%v required_actions=%v; want withheld naming %s", r.Allowed, r.RequiredActions, contract.ReasonUnknownConstraint)
	}
}

// THE CAP A FAILED-LOAD BURST SPENT IS NOT CHARGED TO THE FIRST SUCCESSFUL
// LOAD'S OWN TRIGGER (#4249 row 5714565017, master's R3 round 1).
//
// The loop keeps its count of short waits at the cap while exhausted. A first
// successful load that holds an unkeyed row but whose mark read FAILED credits
// no advance of its own (observe cannot, on an unreadable mark), so without the
// reset that row's trigger would be capped the instant it arrived: exhausted
// with zero short refreshes, where an engine that had never served the defaults
// gave it the whole cap. The load that promotes the engine off the defaults
// ends the fallback burst, so the count starts again.
func TestAFirstSuccessfulLoadAfterAnExhaustedFallbackBurstGetsTheWholeCap(t *testing.T) {
	_ = captureLog(t)
	engine, mock := failedBootEngine(t)
	engine.catchUpMaxTicks = 3
	settled := time.Date(2026, 9, 15, 4, 53, 1, 0, time.UTC)
	expectFailedLoad(mock, 9, settled)
	if err := engine.refreshPolicies(); err == nil {
		t.Fatal("PREMISE: the boot load succeeded")
	}
	// The loop as an exhausted fallback burst leaves it: the cap spent on the
	// defaults trigger.
	ticks := 3
	if delay := engine.scheduleNextRefresh(&ticks); delay != engine.cacheTimeout || engine.catchUp.mode != refreshModeExhausted {
		t.Fatalf("PREMISE: delay=%v mode=%q; want the ordinary interval, exhausted", delay, engine.catchUp.mode)
	}

	// The first load that succeeds: an unkeyed row, and its mark read fails.
	mock.ExpectQuery(regexp.QuoteMeta(schemaMigrationMarkQuery)).WillReturnError(errors.New(`pq: canceling statement due to statement timeout`))
	expectPolicyRows(mock, nil)
	if err := engine.refreshPolicies(); err != nil {
		t.Fatalf("the first successful load: %v", err)
	}
	engine.mu.RLock()
	c := engine.catchUp
	engine.mu.RUnlock()
	if c.unkeyedRows != 1 || c.moving || !c.advanced {
		t.Fatalf("PREMISE: unkeyedRows=%d moving=%t advanced=%t; want 1, false (the mark read failed, so no migration trigger), true (the promotion)", c.unkeyedRows, c.moving, c.advanced)
	}
	if delay := engine.scheduleNextRefresh(&ticks); delay != policyCacheCatchUpInterval || ticks != 1 || engine.catchUp.mode != refreshModeCatchUp {
		t.Fatalf("delay=%v ticks=%d mode=%q; want %v, 1, %q: the unkeyed row's own catch-up, not the cap the fallback burst spent",
			delay, ticks, engine.catchUp.mode, policyCacheCatchUpInterval, refreshModeCatchUp)
	}
}
