// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Real-Postgres proof for migration 188 (#3354): hitl_approval_queue's
// triggered_policy_id and triggered_policy_name hold every policy that asked.
//
//	Pin 1 - at 187 the queue's own enqueue, as the APPLICATION ROLE, of a call
//	        hold whose triggered_policy_id joins three FinCrime requirements
//	        (147 chars) and whose name joins six (292) fails "value too long"
//	        (22001): the defect. 188 applies; the table and core/025's
//	        idx_hitl_policy keep their relfilenodes (no rewrite), core/167's
//	        two partial indexes get new ones (PostgreSQL rebuilds a predicated
//	        index on any type change - the cost 188's header prices), and
//	        hitl_pending_summary's pg_get_viewdef is identical. The same
//	        enqueue then lands, and the row reads the whole joined set back.
//	Pin 2 - 188 re-applies over its own result: both columns stay TEXT, the
//	        view is unchanged.
//	Pin 3 - the down REFUSES while a row names a longer set, naming the count,
//	        and changes nothing; with that row gone it narrows both columns back
//	        to core/025's types with the view unchanged, and 188 applies again.
//
// Gated on TEST_PG_INTEGRATION=1 through approletest.

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"axonflow/platform/agent/approletest"
	"axonflow/platform/agent/hitl/queue"
	"axonflow/platform/agent/license"
)

const (
	mig188Path     = "../../migrations/core/188_hitl_triggered_policy_text.sql"
	mig188DownPath = "../../migrations/core/188_hitl_triggered_policy_text_down.sql"
	mig188Org      = "org-3354"
	mig188Tenant   = "tenant-3354"
)

// mig188Merged is how the engine names a merged approval's source: every
// demanding policy, comma-joined in canonical order. The FinCrime pack's real
// requirement ids, so the lengths are the shipped ones.
func mig188Merged(n int) string {
	ids := []string{
		"pack:fincrime:fincrime__cnp__high__value__stepup",
		"pack:fincrime:fincrime__cumulative__exposure__stepup",
		"pack:fincrime:fincrime__geo__corridor__stepup",
		"pack:fincrime:fincrime__ml__risk__stepup",
		"pack:fincrime:fincrime__payment__execution__stepup",
		"pack:fincrime:fincrime__structuring__pattern__stepup",
		"pack:fincrime:fincrime__velocity__frequency__stepup",
	}
	return strings.Join(ids[:n], ",")
}

// mig188Enqueue queues one call hold through the queue's own enqueuer, as the
// agent's request-plane hold does, naming id and name as its policies.
func mig188Enqueue(db *sql.DB, id, name string) (*queue.Row, error) {
	e := queue.NewEnqueuer(db, queue.Config{Plane: "decide", DefaultExpiry: time.Hour})
	e.SetTierProviderForTest(func(context.Context) license.Tier { return license.TierEnterprise })
	d := "sha256:" + strings.ReplaceAll(uuid.NewString(), "-", "")
	r, _, err := e.Enqueue(context.Background(), queue.Input{
		OrgID:               mig188Org,
		TenantID:            mig188Tenant,
		ClientID:            "fincrime-agent",
		UserID:              "Client::axonflow-license:fincrime-agent",
		OriginalQuery:       "decide: tool",
		RequestType:         queue.RequestTypePolicyStepUp,
		RequestContext:      map[string]interface{}{queue.ContextBindingDigest: d, "plane": "decide", "route": "decide"},
		TriggeredPolicyID:   id,
		TriggeredPolicyName: name,
		TriggerReason:       "an approval is required for payments.create_transfer on decide",
		Severity:            "high",
		ExpiresIn:           time.Hour,
		BindingHold:         &queue.BindingHold{BindingDigest: d},
	})
	return r, err
}

// mig188Relfilenodes reads the storage file of the table and of each index
// over triggered_policy_id: a changed number is a rewrite or a rebuild.
func mig188Relfilenodes(t *testing.T, db *sql.DB) map[string]int64 {
	t.Helper()
	rows, err := db.Query(`SELECT relname, relfilenode FROM pg_class
		WHERE relname IN ('hitl_approval_queue', 'idx_hitl_policy', 'idx_hitl_unconsumed_grant', 'idx_hitl_open_policy_step_up')`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]int64{}
	for rows.Next() {
		var name string
		var node int64
		if err := rows.Scan(&name, &node); err != nil {
			t.Fatal(err)
		}
		out[name] = node
	}
	if len(out) != 4 {
		t.Fatalf("PREMISE: read %d of the table and its three indexes over triggered_policy_id: %v", len(out), out)
	}
	return out
}

func mig188ViewDef(t *testing.T, db *sql.DB) string {
	t.Helper()
	var def string
	if err := db.QueryRow(`SELECT pg_get_viewdef('hitl_pending_summary'::regclass, true)`).Scan(&def); err != nil {
		t.Fatalf("hitl_pending_summary: %v", err)
	}
	return def
}

// mig188Types is "triggered_policy_id type|triggered_policy_name type".
func mig188Types(t *testing.T, db *sql.DB) string {
	t.Helper()
	var s string
	if err := db.QueryRow(`SELECT string_agg(format_type(atttypid, atttypmod), '|' ORDER BY attname)
		FROM pg_attribute WHERE attrelid = 'hitl_approval_queue'::regclass
		  AND attname IN ('triggered_policy_id', 'triggered_policy_name') AND NOT attisdropped`).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

// mig188ExecFile runs a migration file on one connection, as the runner sends
// a file: one multi-statement Exec. A file that opens its own transaction and
// then raises leaves that connection's transaction aborted, so it is rolled
// back before the connection returns to the pool.
func mig188ExecFile(t *testing.T, db *sql.DB, path string) error {
	t.Helper()
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_, err = conn.ExecContext(context.Background(), mig181SQL(t, path))
	if err != nil {
		_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
	}
	return err
}

const (
	mig188Bounded = "character varying(100)|character varying(255)"
	mig188Text    = "text|text"
)

func TestMigration188_AMergedApprovalIsQueuedWholeAndTheTableIsNotRewritten(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.SetupAtVersion(t, "../../migrations/core", 187)
	master := mig178Open(t, env.MasterDSN)
	app := mig178Open(t, env.AppRoleDSN)
	approletest.AssertCurrentUser(t, app, "axonflow_app_role")

	id, name := mig188Merged(3), mig188Merged(6)
	if len(id) <= 100 || len(name) <= 255 {
		t.Fatalf("PREMISE: the merged id is %d and the name %d chars; each must exceed core/025's bound", len(id), len(name))
	}
	if got := mig188Types(t, master); got != mig188Bounded {
		t.Fatalf("PREMISE: at 187 the columns are %q, want %q", got, mig188Bounded)
	}
	if _, err := mig188Enqueue(app, id, name); err == nil || !strings.Contains(err.Error(), "value too long") {
		t.Fatalf("at 187 a merged approval's enqueue answered %v; want the defect, value too long", err)
	}

	before, view := mig188Relfilenodes(t, master), mig188ViewDef(t, master)
	if _, err := master.Exec(mig181SQL(t, mig188Path)); err != nil {
		t.Fatalf("188 did not apply: %v", err)
	}
	after := mig188Relfilenodes(t, master)
	for _, kept := range []string{"hitl_approval_queue", "idx_hitl_policy"} {
		if after[kept] != before[kept] {
			t.Errorf("%s was rewritten by 188 (relfilenode %d -> %d); VARCHAR(n) -> TEXT is binary-coercible and must not rewrite it", kept, before[kept], after[kept])
		}
	}
	for _, rebuilt := range []string{"idx_hitl_unconsumed_grant", "idx_hitl_open_policy_step_up"} {
		if after[rebuilt] == before[rebuilt] {
			t.Errorf("%s kept its relfilenode %d: 188's header prices a rebuild of core/167's predicated indexes that did not happen - correct the header", rebuilt, before[rebuilt])
		}
	}
	if got := mig188ViewDef(t, master); got != view {
		t.Fatalf("hitl_pending_summary changed under 188:\nbefore %s\nafter  %s", view, got)
	}
	if got := mig188Types(t, master); got != mig188Text {
		t.Fatalf("after 188 the columns are %q, want %q", got, mig188Text)
	}

	r, err := mig188Enqueue(app, id, name)
	if err != nil {
		t.Fatalf("after 188 a merged approval still could not be queued: %v", err)
	}
	var gotID, gotName string
	if err := master.QueryRow(`SELECT triggered_policy_id, triggered_policy_name FROM hitl_approval_queue WHERE request_id = $1`, r.RequestID).Scan(&gotID, &gotName); err != nil {
		t.Fatal(err)
	}
	if gotID != id || gotName != name {
		t.Fatalf("the row reads id %q name %q; want the whole joined sets %q / %q", gotID, gotName, id, name)
	}
}

func TestMigration188_ReappliesOverItsOwnResult(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")
	master := mig178Open(t, env.MasterDSN)
	view := mig188ViewDef(t, master)
	if got := mig188Types(t, master); got != mig188Text {
		t.Fatalf("PREMISE: a database migrated to the latest reads %q, want %q", got, mig188Text)
	}
	if _, err := master.Exec(mig181SQL(t, mig188Path)); err != nil {
		t.Fatalf("188 did not re-apply over itself: %v", err)
	}
	if got := mig188Types(t, master); got != mig188Text {
		t.Fatalf("after a re-apply the columns are %q", got)
	}
	if got := mig188ViewDef(t, master); got != view {
		t.Fatalf("hitl_pending_summary changed under a re-apply:\nbefore %s\nafter  %s", view, got)
	}
}

func TestMigration188_TheDownRefusesToTruncateAnApprovalAndNarrowsWithoutOne(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")
	master := mig178Open(t, env.MasterDSN)
	app := mig178Open(t, env.AppRoleDSN)
	view := mig188ViewDef(t, master)

	long, err := mig188Enqueue(app, mig188Merged(3), mig188Merged(3))
	if err != nil {
		t.Fatalf("PREMISE: after 188 a merged approval queues: %v", err)
	}
	if _, err := mig188Enqueue(app, "pack:fincrime:fincrime__geo__corridor__stepup", "FinCrime: Geo Corridor Step-Up"); err != nil {
		t.Fatal(err)
	}
	err = mig188ExecFile(t, master, mig188DownPath)
	if err == nil || !strings.Contains(err.Error(), "188 down refused: 1 hitl_approval_queue row(s)") {
		t.Fatalf("the down over a merged approval answered %v; want the refusal naming the one row", err)
	}
	if got := mig188Types(t, master); got != mig188Text {
		t.Fatalf("a refused down changed the columns to %q", got)
	}

	if _, err := master.Exec(`DELETE FROM hitl_approval_queue WHERE request_id = $1`, long.RequestID); err != nil {
		t.Fatal(err)
	}
	if _, err := master.Exec(mig181SQL(t, mig188DownPath)); err != nil {
		t.Fatalf("the down over short rows only: %v", err)
	}
	if got := mig188Types(t, master); got != mig188Bounded {
		t.Fatalf("after the down the columns are %q, want core/025's %q", got, mig188Bounded)
	}
	if got := mig188ViewDef(t, master); got != view {
		t.Fatalf("hitl_pending_summary changed under the down:\nbefore %s\nafter  %s", view, got)
	}
	if _, err := master.Exec(mig181SQL(t, mig188Path)); err != nil {
		t.Fatalf("188 did not re-apply after its down: %v", err)
	}
	if got := mig188Types(t, master); got != mig188Text {
		t.Fatalf("after 188 re-applied the columns are %q", got)
	}
}
