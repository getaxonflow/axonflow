package shadow

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"axonflow/platform/decision/legacycompile"
)

// TestRealCaptureShadowGateIsGreen runs ADR-065 gate 18 over a REAL capture
// rather than over fixtures.
//
// The fixture gate proves the harness handles the shapes somebody thought of;
// a fresh stack's seeded policy set is the shape that actually exists, and the
// first time this gate ran over one it found 91 unexplained differences the
// fixture corpus could not produce. A gate that only ever sees fixtures is a
// gate over a description of the substrate.
//
// It skips without a capture, because CI has no database in this module and a
// fabricated capture would be testing the fabrication. Produce one with
// scripts/legacy-policy-capture.sh and point AXONFLOW_LEGACY_CAPTURE_DIR at
// it; the realpg CI lane does exactly that on every PR. The skip is LOUD about
// what was not verified, so a green run cannot be read as this test having
// passed.
func TestRealCaptureShadowGateIsGreen(t *testing.T) {
	dir := os.Getenv("AXONFLOW_LEGACY_CAPTURE_DIR")
	if dir == "" {
		t.Skip("no AXONFLOW_LEGACY_CAPTURE_DIR: the shadow gate was NOT run over a real capture. " +
			"Produce one with scripts/legacy-policy-capture.sh and set the variable; " +
			"the 'Unit Tests: Enterprise-Tagged + Real-PG' CI lane runs this on every PR.")
	}

	b, err := os.ReadFile(filepath.Join(dir, "capture-owner.json"))
	if err != nil {
		t.Fatalf("reading the capture: %v", err)
	}
	var rows []legacycompile.RawRow
	if err := json.Unmarshal(b, &rows); err != nil {
		t.Fatalf("decoding the capture: %v", err)
	}
	// Anti-vacuity: a gate over zero rows passes hardest when the capture is
	// broken, and Gate itself refuses that - but refusing here too names the
	// capture rather than the run.
	if len(rows) == 0 {
		t.Fatal("the capture contains no rows; a gate over nothing proves nothing")
	}

	// The same posture the seeded substrate runs under: no levers configured,
	// one approval pool for every org. The pool is supplied because
	// require_approval rows are otherwise uncompilable BY DESIGN, and the point
	// of this run is to measure the diff, not to re-prove the refusal the
	// fixture tests already pin.
	opts := testOptions()

	rep, err := legacycompile.Compile(rows, opts)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	run, err := RunAll(context.Background(), rep, rowFactsFrom(t, rows), opts)
	if err != nil {
		t.Fatalf("RunAll: %v", err)
	}
	res := Gate(run, GateOptions{RequirePlanes: legacycompile.AllPlanes()})
	t.Logf("\n%s", res.Summary)
	if !res.Passed {
		for _, f := range res.Failures {
			t.Errorf("gate failure: %s", f)
		}
		t.Fatalf("ADR-065 gate 18 FAILED over the real %d-row capture with %d failure(s)", len(rows), len(res.Failures))
	}
}
