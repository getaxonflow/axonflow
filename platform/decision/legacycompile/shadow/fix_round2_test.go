package shadow

import (
	"context"
	"strings"
	"testing"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
)

// TestCallerSuppliableContextFieldIsDiffed is the end-to-end proof for the
// #3515 context-fallthrough fix: a `connector equals salesforce -> block` row
// - a condition the compiler used to refuse as never-firing and drop from the
// coverage denominator - must produce a corpus case and a classified
// comparison on every dynamic plane, with BOTH engines refusing the request
// when the caller supplies the context key.
//
// This is the mutation tripwire for the refusal: reverting the compiler to
// "unresolvable field, never fires" clears the row's resolved action, drops it
// from ContributesTo, and no fires case is generated - so every assertion
// below goes red, not silent.
func TestCallerSuppliableContextFieldIsDiffed(t *testing.T) {
	rows := []legacycompile.RawRow{
		dynamicFixture(t, "dyn_connector_block", map[string]any{
			"tier": "system", "tenant_id": "global", "org_id": "global",
			"conditions": []map[string]any{{"field": "connector", "operator": "equals", "value": "salesforce"}},
			"actions":    []map[string]any{{"type": "block", "config": map[string]any{"reason": "no salesforce"}}},
		}),
	}
	rows[0].OrgScope = "global"
	rep, err := legacycompile.Compile(rows, testOptions())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	run, err := RunAll(context.Background(), rep, rowFactsFrom(t, rows), testOptions())
	if err != nil {
		t.Fatalf("RunAll: %v", err)
	}

	rowKey := RowKeyFor("dynamic_policies", "dyn_connector_block")
	for _, p := range legacycompile.PlanesFor(legacycompile.SubstrateDynamic) {
		cov := run.Coverage[p]
		inDenominator := false
		for _, r := range cov.CompiledRows {
			if r == rowKey {
				inDenominator = true
			}
		}
		if !inDenominator {
			t.Fatalf("plane %q coverage does not list the connector row: %v; a caller-triggerable block is out of the denominator again",
				p, cov.CompiledRows)
		}
		for _, r := range cov.UnexercisedRows {
			if r == rowKey {
				t.Fatalf("plane %q never exercised the connector row; the fires case did not reach it", p)
			}
		}

		// The fires case must exist, and on it BOTH engines refuse: the model
		// reads the caller-forwarded key and blocks, and the compiled
		// constraint over the context-sourced path denies. Anything else is a
		// difference on the exact row the fix is about.
		found := false
		for _, rec := range run.Records {
			if rec.Plane != p || !strings.Contains(rec.CaseID, "/dynamic/dyn_connector_block/fires") {
				continue
			}
			found = true
			if rec.Legacy.Executable {
				t.Fatalf("plane %q: the legacy model permitted the fires case; production blocks a caller supplying connector=salesforce (%+v)", p, rec.Legacy)
			}
			if rec.New.Executable {
				t.Fatalf("plane %q: ADR-065 permitted the fires case; the compiled constraint did not fire (%+v)", p, rec.New)
			}
			if rec.Class != ClassMatch {
				t.Fatalf("plane %q: the fires comparison classified %q (%s); both engines refuse identically, so anything but a match means the two sides model the fallthrough differently",
					p, rec.Class, rec.Detail)
			}
			// The preserved-defect context must name #3515 so a triager sees
			// the caller-suppliable provenance on every record touching the
			// row.
			if !strings.Contains(strings.Join(rec.PreservedDefects, " "), "#3515") {
				t.Fatalf("plane %q: the comparison carries no #3515 context: %v", p, rec.PreservedDefects)
			}
		}
		if !found {
			t.Fatalf("plane %q produced no fires comparison for the connector row; the corpus does not exercise it", p)
		}
	}

	// The quiet case: the caller supplies a DIFFERENT value under the key,
	// the equals does not hold, and both engines permit. This is the
	// direction that proves the compiled condition selects on the caller's
	// value rather than firing whenever the row exists.
	for _, rec := range run.Records {
		if !strings.Contains(rec.CaseID, "/dynamic/dyn_connector_block/does_not_fire") {
			continue
		}
		if !rec.Legacy.Executable || rec.New.State != contract.StateAllow {
			t.Fatalf("the quiet case did not permit on both sides (legacy executable=%t, new state=%s); the compiled condition fires without the caller's key",
				rec.Legacy.Executable, rec.New.State)
		}
	}
}
