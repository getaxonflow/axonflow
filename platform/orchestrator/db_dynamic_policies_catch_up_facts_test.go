// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"fmt"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
)

// THE KNOWN ISSUE, READ WHERE IT REFUSES (#4249 row 5675083076).
//
// A governed request is refused unknown_constraint when the fact producer
// states no fact for a control the engine reads. These tests load the cache the
// way a co-booted stack does, first before the migration that makes a shipped
// row govern and then after it, and read the PRODUCER over the engine's own
// organization-scoped list (ListActivePoliciesForTenant, the rows source every
// enforcing seam hands it) rather than counting cache entries. Each window has
// its planted negative: the same sequence with the catch-up interval set to the
// ordinary one, where the facts are still absent at the same instant.

// seededCatchUpRow is one shipped dynamic_policies row as the refresh SELECT
// returns it, with its conditions read from the seed migration.
type seededCatchUpRow struct {
	policyID string
	// orgID nil is SQL NULL: the row as core/031 seeds it, before core/153
	// keys it.
	orgID interface{}
}

func expectSeededPolicyRows(t *testing.T, mock sqlmock.Sqlmock, rows ...seededCatchUpRow) {
	t.Helper()
	conds, err := legacycompile.SeedDynamicConditions(seedDynamicMigrations...)
	if err != nil {
		t.Fatal(err)
	}
	out := sqlmock.NewRows([]string{"id", "name", "description", "conditions", "actions", "tenant_id", "org_id", "priority", "policy_id", "policy_type", "category", "risk_level", "allow_override", "created_at", "updated_at", "segment_id"})
	for i, r := range rows {
		c, ok := conds[r.policyID]
		if !ok {
			t.Fatalf("no seed migration read here inserts %s", r.policyID)
		}
		out.AddRow(fmt.Sprintf("00000000-0000-0000-0000-%012d", i+1), r.policyID, "", c, "[]", "global", r.orgID, 1000, r.policyID, "context_aware", "system", "high", false, nil, nil, nil)
	}
	mock.ExpectQuery(refreshPoliciesQueryPattern).WillReturnRows(out)
}

// catchUpWindow boots an engine on the first load, reads the facts, runs the
// refresh loop for a fixed wall-clock span over the later loads, and reads the
// facts again. catchUp is the catch-up interval; the engine's ordinary
// interval is an hour (catchUpEngine), so only the catch-up can bring the
// later loads in.
func catchUpWindow(t *testing.T, catchUp time.Duration, boot func(sqlmock.Sqlmock), later func(i int, mock sqlmock.Sqlmock)) (before, after contract.AttributeSet) {
	t.Helper()
	engine, mock := catchUpEngine(t)
	engine.catchUpInterval = catchUp
	boot(mock)
	for i := 0; i < 20; i++ {
		later(i, mock)
	}
	_ = captureLog(t)
	if err := engine.refreshPolicies(); err != nil {
		t.Fatalf("boot load: %v", err)
	}
	p := testFactProducerOver(t, engine)
	req := stepFactRequest("", map[string]interface{}{})
	before = produceFacts(t, p, req)
	startRefreshLoop(t, engine)
	time.Sleep(250 * time.Millisecond) // a dozen 20ms catch-up intervals
	after = produceFacts(t, p, req)
	return before, after
}

// The FIRST window: the boot load lands between core/031 and core/153, so the
// shipped row carries no org_id and applies to nobody. sys_dyn_debug_restrict
// is one of the controls the v11.0.0 tag run's refusal named.
func TestTheCatchUpStatesTheFactsOfARowKeyedAfterTheBootLoad(t *testing.T) {
	t.Setenv("ENVIRONMENT", "production")
	const control = "sys_dyn_debug_restrict"
	detector := legacycompile.DynamicContentDetectorPath(control)
	environment := legacycompile.Options{}.AttributePathFor("environment")
	settled := time.Date(2026, 9, 15, 4, 53, 1, 0, time.UTC)
	boot := func(mock sqlmock.Sqlmock) {
		expectMigrationMark(mock, 152, settled)
		expectSeededPolicyRows(t, mock, seededCatchUpRow{control, nil})
	}
	keyed := func(_ int, mock sqlmock.Sqlmock) {
		expectMigrationMark(mock, 153, settled.Add(time.Second))
		expectSeededPolicyRows(t, mock, seededCatchUpRow{control, "global"})
	}

	t.Run("with the catch-up the facts are stated within its interval", func(t *testing.T) {
		before, after := catchUpWindow(t, 20*time.Millisecond, boot, keyed)
		for _, path := range []string{detector, environment} {
			if f, stated := before[path]; stated {
				t.Fatalf("PREMISE: %s is stated (%s) from a row that applies to nobody", path, f.State)
			}
		}
		wantKnown(t, after, detector, false)
		wantKnown(t, after, environment, "production")
	})

	t.Run("PLANTED: without the catch-up they are still absent at the same instant", func(t *testing.T) {
		_, after := catchUpWindow(t, time.Hour, boot, keyed)
		for _, path := range []string{detector, environment} {
			if f, stated := after[path]; stated {
				t.Fatalf("%s is stated (%s) with the catch-up at the ordinary interval; the positive above would prove nothing", path, f.State)
			}
		}
	})
}

// The SECOND window: the boot load lands between core/153 and core/173. Every
// loaded row is keyed, so a trigger on unkeyed rows alone cannot arm; the five
// sys_media_* rows do not exist yet. What arms the catch-up is schema_migrations
// moving: the process's first read of the mark at the boot load, then an advance.
func TestTheCatchUpStatesTheFactsOfARowSeededAfterTheBootLoad(t *testing.T) {
	t.Setenv("ENVIRONMENT", "production")
	const media = "sys_media_nsfw_block"
	nsfw := legacycompile.Options{}.AttributePathFor("media.nsfw_score")
	settled := time.Date(2026, 9, 15, 4, 53, 1, 0, time.UTC)
	boot := func(mock sqlmock.Sqlmock) {
		expectMigrationMark(mock, 172, settled)
		expectSeededPolicyRows(t, mock, seededCatchUpRow{"sys_dyn_debug_restrict", "global"})
	}
	seeded := func(_ int, mock sqlmock.Sqlmock) {
		expectMigrationMark(mock, 173, settled.Add(time.Second))
		expectSeededPolicyRows(t, mock, seededCatchUpRow{"sys_dyn_debug_restrict", "global"}, seededCatchUpRow{media, "global"})
	}

	t.Run("with the catch-up the facts are stated within its interval", func(t *testing.T) {
		before, after := catchUpWindow(t, 20*time.Millisecond, boot, seeded)
		if f, stated := before[nsfw]; stated {
			t.Fatalf("PREMISE: %s is stated (%s) before %s exists", nsfw, f.State, media)
		}
		wantKnown(t, after, nsfw, float64(0))
	})

	t.Run("the boot load held no unkeyed row, so only schema_migrations could arm it", func(t *testing.T) {
		engine, mock := catchUpEngine(t)
		boot(mock)
		_ = captureLog(t)
		if err := engine.refreshPolicies(); err != nil {
			t.Fatalf("boot load: %v", err)
		}
		engine.mu.RLock()
		c := engine.catchUp
		engine.mu.RUnlock()
		if c.unkeyedRows != 0 || !c.moving || !c.armed() {
			t.Fatalf("unkeyedRows=%d moving=%t armed=%t; want 0, true, true", c.unkeyedRows, c.moving, c.armed())
		}
	})

	t.Run("PLANTED: without the catch-up they are still absent at the same instant", func(t *testing.T) {
		_, after := catchUpWindow(t, time.Hour, boot, seeded)
		if f, stated := after[nsfw]; stated {
			t.Fatalf("%s is stated (%s) with the catch-up at the ordinary interval; the positive above would prove nothing", nsfw, f.State)
		}
	})
}
