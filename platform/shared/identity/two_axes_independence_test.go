// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// THE TWO-AXES INVARIANT (#3564, #3552 gap 3, #3633).
//
// The identity compatibility mode and the ADR-065 decision shadow are two
// INDEPENDENT axes that happen to be two columns of one row. Everything about
// the design rests on that independence:
//
//   - an operator shadows identity and decisions on different schedules;
//   - the identity axis's enforce transition is gated on a MEASURED window
//     (#3633), and the measurement is the identity plane's own comparison and
//     divergence volume;
//   - the decision axis has no enforcement at all before v11, and its per-plane
//     and per-organization narrowings move a different metric family.
//
// # WHY THIS IS A TEST AND NOT A COMMENT
//
// The independence is currently true BY ACCIDENT OF WHICH RECORDER WRITES WHICH
// FAMILY. Nothing in the type system stops the enforce gate reaching for a
// decision-shadow series, and the consequence of that edit is the failure
// #3633 exists to prevent, arriving from the other side: the identity axis's
// enforce precondition would start being satisfied - or blocked - by evidence
// about a different plane's dual-evaluation, which nobody reading
// "org_not_measured" would suspect.
//
// The question was asked directly during #3552 gap 3's review ("could a
// per-organization plane narrowing falling back to the deployment's list widen
// the denominator the enforce precondition reads?"). The answer today is no,
// and it is no because the two families are written by different recorders -
// which is exactly the kind of answer that stops being true without anyone
// deciding it should.
//
// It fails on the IMPORT as well as on the series name, because the import is
// the cheaper thing to notice and it is the first thing such an edit would add.

// decisionShadowSymbols are the names that mean "this code is reading the
// decision axis". Deliberately spelled here rather than imported: importing the
// planeshadow package to name its symbols would create the very dependency this
// test forbids.
var decisionShadowSymbols = []string{
	"planeshadow",
	"axonflow_decision_shadow",
	"shadowObservations",
	"shadowComparisons",
	"shadowOrgModeFailures",
	"shadowOrgPlanesFailures",
	"MetricShadowObservations",
}

// identityMetricSymbols is the CONTROL. A scan that found nothing because it
// was looking in the wrong place, or because the file moved, reports the same
// clean result as a scan that found nothing because nothing is there - so the
// scan must also find what it is SUPPOSED to find, in the same pass.
var identityMetricSymbols = []string{"compatOrgComparisons", "compatOrgDivergences"}

func TestTheEnforcePreconditionReadsOnlyTheIdentityAxis(t *testing.T) {
	const gateFile = "compat_enforce_gate.go"
	src, err := os.ReadFile(filepath.Clean(gateFile))
	if err != nil {
		t.Fatalf("reading %s: %v. The enforce gate moved; re-anchor this guard rather than deleting it - "+
			"a census that cannot find its subject passes.", gateFile, err)
	}
	text := string(src)

	// THE CONTROL FIRST, so a zero below is a fact about the gate rather than
	// about this test.
	control := 0
	for _, want := range identityMetricSymbols {
		control += strings.Count(text, want)
	}
	if control == 0 {
		t.Fatalf("%s references none of %v. Either the gate no longer reads the identity axis's own "+
			"counters - which is a much larger problem than the one this test guards - or this scan is "+
			"reading the wrong file, and its zero below would prove nothing.", gateFile, identityMetricSymbols)
	}

	for _, sym := range decisionShadowSymbols {
		if n := strings.Count(text, sym); n > 0 {
			t.Errorf("%s references %q %d time(s).\n\n"+
				"The identity axis's enforce precondition must read the IDENTITY plane's own comparison and "+
				"divergence volume and nothing else. A decision-shadow series here would let evidence about a "+
				"different plane's dual-evaluation satisfy - or block - an identity enforcement transition, and "+
				"an operator reading org_not_measured or org_still_diverging would have no way to suspect it. "+
				"The two axes are two columns of one row and nothing more.\n"+
				"(Control: the file references the identity counters %d time(s), so this scan is looking at the "+
				"right file.)", gateFile, sym, n, control)
		}
	}
}

// planeshadowImportNeedle assembles the import line to look for, in pieces.
//
// IT IS ASSEMBLED SO THIS FILE DOES NOT MATCH ITSELF. Written as a literal, the
// needle appears in the very file doing the scanning, and the guard reported
// ITSELF as an offender on its first run - a presence check satisfied by its own
// text, in the failing direction. Excluding this file by name would have worked
// and would have been worse: it would leave the one file in the package that
// nothing checks, which is exactly where an import would be quietest.
func planeshadowImportNeedle() string {
	return `"axonflow/platform/shared/` + "planeshadow" + `"`
}

// TestThePlaneshadowImportNeedleMatchesARealImportLine is that assembly's
// control. A needle built from pieces can be built wrong - a missing quote, a
// stray slash - and a needle that matches nothing makes the census below pass
// on every tree, for ever, silently.
func TestThePlaneshadowImportNeedleMatchesARealImportLine(t *testing.T) {
	sample := "import (\n\t\"context\"\n\n\t\"axonflow/platform/shared/planeshadow\"\n)"
	if !strings.Contains(sample, planeshadowImportNeedle()) {
		t.Fatalf("the assembled needle %q does not match a real import line; the census that uses it "+
			"would pass on any tree", planeshadowImportNeedle())
	}
	// And it must NOT match a package whose name merely starts the same way, or
	// the census would fire on an import nobody made.
	other := "\t\"axonflow/platform/shared/planeshadowutil\"\n"
	if strings.Contains(other, planeshadowImportNeedle()) {
		t.Errorf("the needle matches %q; the closing quote is not binding", other)
	}
}

// TestIdentityDoesNotImportTheDecisionShadow is the same invariant one level
// up, and it is the cheaper half to notice.
//
// The dependency runs ONE WAY by design: planeshadow imports identity, for the
// mode vocabulary and the per-organization settings contracts. The reverse
// import would make the cycle impossible to add later without a refactor, so
// today it is simply absent - and "absent" is worth pinning, because the first
// step of the edit this file forbids is exactly that import.
func TestIdentityDoesNotImportTheDecisionShadow(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	scanned, offenders := 0, []string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}
		// TEST FILES ARE SCANNED TOO, and deliberately: a test that imported
		// planeshadow would make the production dependency one deletion away,
		// and the cycle would appear the moment someone moved the helper it was
		// using. THIS file names the symbols as strings for that reason.
		body, rerr := os.ReadFile(filepath.Clean(name))
		if rerr != nil {
			continue
		}
		scanned++
		if strings.Contains(string(body), planeshadowImportNeedle()) {
			offenders = append(offenders, name)
		}
	}
	if scanned == 0 {
		t.Fatal("the scan read no Go files in this package; the walk, not the code, is broken")
	}
	if len(offenders) > 0 {
		t.Errorf("%v import the decision shadow.\n\n"+
			"The dependency runs one way: planeshadow imports identity, never the reverse. The reverse import "+
			"is the first step of letting the identity axis read decision-axis evidence, and it is also how the "+
			"two packages acquire a cycle. If identity needs something from planeshadow, the thing it needs "+
			"belongs on this side of the boundary (as the raw, uninterpreted decision_shadow_planes string "+
			"already does, precisely so identity never parses a plane name).", offenders)
	}
}
