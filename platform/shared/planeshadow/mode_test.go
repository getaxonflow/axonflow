// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package planeshadow

import (
	"sort"
	"strings"
	"testing"

	"axonflow/platform/decision/legacycompile"
)

// TestParsePlanesRefusesTheUnimplemented pins the one plane name that must
// never be accepted.
//
// connector_execution is named by ADR-065 Phase 4 and has NO policy-evaluation
// call site anywhere in the tree. Accepting it would compile for, sample and
// COUNT a surface that does not evaluate policy - manufacturing a denominator,
// which is the one number this whole mechanism exists to make trustworthy.
func TestParsePlanesRefusesTheUnimplemented(t *testing.T) {
	if len(legacycompile.UnimplementedPlanes) == 0 {
		t.Skip("no plane is currently recorded as unimplemented")
	}
	for name := range legacycompile.UnimplementedPlanes {
		_, err := ParsePlanes(string(name))
		if err == nil {
			t.Fatalf("ParsePlanes(%q) accepted a plane with no policy-evaluation call site", name)
		}
		if !strings.Contains(err.Error(), "call site") {
			t.Fatalf("the refusal of %q does not say WHY (%v); an operator told only that the "+
				"name is invalid will look for a typo", name, err)
		}
	}
}

// TestParsePlanesIsDerivedFromTheModel pins both directions.
func TestParsePlanesIsDerivedFromTheModel(t *testing.T) {
	declared := legacycompile.AllPlanes()
	if len(declared) < 2 {
		t.Fatalf("only %d plane(s) declared; a plane list is meaningless", len(declared))
	}

	t.Run("every declared plane is accepted", func(t *testing.T) {
		for _, p := range declared {
			got, err := ParsePlanes(string(p))
			if err != nil {
				t.Errorf("ParsePlanes(%q) refused a declared plane: %v", p, err)
				continue
			}
			if !got[p] {
				t.Errorf("ParsePlanes(%q) did not select it: %v", p, got)
			}
		}
	})

	t.Run("the whole list is accepted, spaces and all", func(t *testing.T) {
		names := make([]string, 0, len(declared))
		for _, p := range declared {
			names = append(names, string(p))
		}
		sort.Strings(names)
		got, err := ParsePlanes(strings.Join(names, ", "))
		if err != nil {
			t.Fatalf("the full list was refused: %v", err)
		}
		if len(got) != len(declared) {
			t.Fatalf("the full list selected %d of %d planes", len(got), len(declared))
		}
	})

	t.Run("empty means EVERY plane, not none", func(t *testing.T) {
		got, err := ParsePlanes("")
		if err != nil || got != nil {
			t.Fatalf("ParsePlanes(\"\") = %v, %v; nil means every plane, which is the only "+
				"value that produces a complete window", got, err)
		}
		cfg := Config{Planes: nil}
		for _, p := range declared {
			if !cfg.Observes(p) {
				t.Fatalf("a nil plane set excluded %q; the zero-configuration deployment must "+
					"measure everything rather than nothing", p)
			}
		}
	})

	t.Run("case and space are normalized, as the parser documents", func(t *testing.T) {
		// The parser lower-cases and trims each field; the CFN AllowedPattern
		// offers only the canonical lowercase spellings. That narrowing is the
		// right direction and is asserted by the template pins: a value CFN
		// accepts must be one the binary accepts, never the other way round.
		got, err := ParsePlanes("  MCP , Decide ")
		if err != nil {
			t.Fatalf("a padded, mixed-case list was refused: %v", err)
		}
		if !got[legacycompile.PlaneMCP] || !got[legacycompile.PlaneDecide] {
			t.Fatalf("normalization dropped a plane: %v", got)
		}
	})

	t.Run("an undeclared plane is an error, never a silently dropped entry", func(t *testing.T) {
		for _, bad := range []string{"gateway", "mcp2", "decide,typo"} {
			if _, err := ParsePlanes(bad); err == nil {
				t.Errorf("ParsePlanes(%q) was accepted; an operator who typed it believes that "+
					"plane is being measured, and a list that dropped the typo would measure "+
					"nothing while reading as configured", bad)
			}
		}
	})

	t.Run("a list that names nothing is refused", func(t *testing.T) {
		if _, err := ParsePlanes(" , , "); err == nil {
			t.Error("a list of separators was accepted. It would select NO plane, which is a " +
				"deployment measuring nothing behind a configured-looking variable; leaving " +
				"the variable unset is how you ask for every plane.")
		}
	})
}

// TestParseSampleRateRefusesZero pins the value that would make a deployment
// believe it is measuring when it is not.
func TestParseSampleRateRefusesZero(t *testing.T) {
	for _, good := range []string{"", "1", "1.0", "0.5", "0.001"} {
		if _, err := ParseSampleRate(good); err != nil {
			t.Errorf("ParseSampleRate(%q) was refused: %v", good, err)
		}
	}
	if got, _ := ParseSampleRate(""); got != 1 {
		t.Error("an unset sampling rate did not default to 1.0")
	}
	for _, bad := range []string{"0", "0.0", "1.5", "-1", "half"} {
		if _, err := ParseSampleRate(bad); err == nil {
			t.Errorf("ParseSampleRate(%q) was accepted; a rate outside (0, 1] is either a "+
				"deployment measuring nothing or one whose denominator cannot be interpreted", bad)
		}
	}
}

// TestImplementedPlanesIsDerived pins the plane set to the compiler's model
// rather than to a copy.
//
// Two failure shapes, both silent: an invented plane reads as coverage of a
// surface that does not exist, and a missing one is an enforcement surface
// nobody diffs.
func TestImplementedPlanesIsDerived(t *testing.T) {
	got := ImplementedPlanes()
	want := legacycompile.AllPlanes()
	if len(got) != len(want) {
		t.Fatalf("ImplementedPlanes has %d entries and the compiler's model has %d; the two "+
			"have drifted and this package is measuring a different set of planes than the "+
			"one being migrated", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("plane %d differs: %q vs %q", i, got[i], want[i])
		}
	}
	for name := range legacycompile.UnimplementedPlanes {
		for _, p := range got {
			if p == name {
				t.Errorf("ImplementedPlanes includes %q, which has no policy-evaluation call "+
					"site; compiling and counting for it would manufacture a denominator", name)
			}
		}
	}
}
