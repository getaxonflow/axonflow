package shadow

import (
	"context"
	"encoding/json"
	"testing"

	"axonflow/platform/decision/legacycompile"
)

// fixtureWorld is one built shadow environment: a compiled report, the row
// facts the legacy model reads, a real signed-bundle engine and a corpus.
type fixtureWorld struct {
	Report *legacycompile.Report
	Rows   map[string]RowFacts
	World  *World
	Cases  []Case
	Legacy *ModelEvaluator
}

func col(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshalling fixture column: %v", err)
	}
	return b
}

func staticFixture(t *testing.T, policyID string, overrides map[string]any) legacycompile.RawRow {
	t.Helper()
	base := map[string]any{
		"id": "aaaaaaaa-0000-0000-0000-000000000001", "policy_id": policyID, "name": policyID,
		"category": "pii-us", "pattern": `\d{3}-\d{2}-\d{4}`, "severity": "high",
		"tier": "system", "tenant_id": "global", "org_id": "global",
		"priority": 100, "enabled": true,
		"phase": "request", "action_request": "block", "action_response": nil,
		"action": "block", "segment_id": nil, "version": 1,
		"metadata": map[string]any{}, "deleted_at": nil,
		"created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z",
	}
	for k, v := range overrides {
		base[k] = v
	}
	cols := map[string]json.RawMessage{}
	for k, v := range base {
		cols[k] = col(t, v)
	}
	return legacycompile.RawRow{Table: "static_policies", OrgScope: "global", Columns: cols}
}

func dynamicFixture(t *testing.T, policyID string, overrides map[string]any) legacycompile.RawRow {
	t.Helper()
	base := map[string]any{
		"id": "bbbbbbbb-0000-0000-0000-000000000001", "policy_id": policyID, "name": policyID,
		"policy_type": "context_aware", "category": "dynamic-role-access",
		"tier": "tenant", "tenant_id": "acme", "org_id": "acme",
		"priority": 50, "enabled": true, "risk_threshold": nil,
		"conditions": []map[string]any{{"field": "user.role", "operator": "equals", "value": "intern"}},
		"actions":    []map[string]any{{"type": "block", "config": map[string]any{"reason": "interns cannot"}}},
		"segment_id": nil, "metadata": map[string]any{}, "created_at": "2026-01-01T00:00:00Z",
		"version":     1,
		"description": "fixture row",
	}
	for k, v := range overrides {
		base[k] = v
	}
	cols := map[string]json.RawMessage{}
	for k, v := range base {
		cols[k] = col(t, v)
	}
	return legacycompile.RawRow{Table: "dynamic_policies", OrgScope: "acme", Columns: cols}
}

// rowFactsFrom derives the legacy model's per-row facts from the same captured
// rows the compiler read, so the two sides cannot disagree about what a row
// says. They still disagree about what it MEANS, which is the diff.
func rowFactsFrom(t *testing.T, rows []legacycompile.RawRow) map[string]RowFacts {
	t.Helper()
	out := map[string]RowFacts{}
	for _, r := range rows {
		var cols struct {
			PolicyID   string          `json:"policy_id"`
			Priority   *int            `json:"priority"`
			Category   string          `json:"category"`
			SegmentID  *string         `json:"segment_id"`
			Conditions json.RawMessage `json:"conditions"`
			Actions    json.RawMessage `json:"actions"`
			Tier       string          `json:"tier"`
			Name       string          `json:"name"`
		}
		blob, err := json.Marshal(r.Columns)
		if err != nil {
			t.Fatalf("re-marshalling fixture columns: %v", err)
		}
		if err := json.Unmarshal(blob, &cols); err != nil {
			t.Fatalf("decoding fixture columns: %v", err)
		}
		f := RowFacts{
			Category: cols.Category, Conditions: cols.Conditions,
			Actions: cols.Actions, Tier: cols.Tier, Name: cols.Name,
		}
		if cols.Priority != nil {
			f.Priority = *cols.Priority
		}
		if cols.SegmentID != nil {
			f.SegmentID = *cols.SegmentID
		}
		out[RowKey(r.Table, cols.PolicyID)] = f
	}
	return out
}

func buildWorld(t *testing.T, plane legacycompile.Plane, rows []legacycompile.RawRow, opts legacycompile.Options) fixtureWorld {
	t.Helper()
	rep, err := legacycompile.Compile(rows, opts)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	facts := rowFactsFrom(t, rows)
	w, err := NewWorld(context.Background(), rep, plane, "global")
	if err != nil {
		t.Fatalf("NewWorld(%q): %v", plane, err)
	}
	return fixtureWorld{
		Report: rep, Rows: facts, World: w,
		Cases:  BuildCorpus(rep, plane, "global", facts, opts),
		Legacy: &ModelEvaluator{Report: rep, Rows: facts, ContentTarget: legacycompile.DefaultContentTarget},
	}
}

func (f fixtureWorld) run(t *testing.T) *Run {
	t.Helper()
	run, err := Execute(context.Background(), f.Cases, f.Legacy, f.World.Engine, f.Report, f.World.BundleDigest)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	return run
}

func testOptions() legacycompile.Options {
	return legacycompile.Options{
		ApprovalPools: map[string]legacycompile.ApprovalPool{
			"*": {Quorum: 1, Eligible: []string{"Group::" + Realm + ":approvers"}},
		},
	}
}
