// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package shadow

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// EVERY FILE IN THIS PACKAGE IS EITHER PART OF SemanticsDigest OR NAMED HERE
// WITH A REASON.
//
// SemanticsDigest is half of a comparison's EvaluatorVersion, and
// EvaluatorVersion is a RESET STAMP for ADR-065 gate 18: it exists so a change
// to what counts as an expected_change moves an observable field, and an
// operator reading "180 days, zero unexplained" can tell one window from two
// glued together.
//
// A stamp computed from an INCOMPLETE input set fails in the only direction
// that matters. It stays still across a change that altered the classification,
// and a window that did not reset when its semantics changed is
// indistinguishable from a window that did not need to.
//
// It had that gap. classify.go was the whole set, and Classify calls
// Verdict.Canonical() - in verdict.go - on BOTH sides of every comparison.
// Canonical's own comment says the set/multiset asymmetry is load-bearing:
// de-duplicating Effects "let a compiler that dropped two of three targets
// correspond cleanly with a legacy side that demanded three". So a change that
// turned a dropped obligation into a `match` would not have moved the stamp
// that exists to say the semantics moved. case.go (the request the PDP is
// asked) and world.go (the world it is asked against, and ActionID) are on the
// same runtime path and were equally uncovered.
//
// A prose list cannot catch the NEXT such file, because nothing re-reads prose
// when a file is added. This test is that re-reading.
var semanticsDigestExclusions = map[string]string{
	// The OFFLINE corpus machinery. #3577's harness generates cases from a
	// compiled policy set and runs them in CI; none of it is on the path a
	// PRODUCTION comparison takes, which is what EvaluatorVersion stamps. A
	// change to how the corpus is built does not change how a live observation
	// is classified, and resetting a production window for one would train an
	// operator to ignore the stamp.
	"run.go":    "offline corpus execution; not on the path a production comparison takes",
	"runall.go": "offline per-plane corpus driver; not on the path a production comparison takes",
	"gate.go":   "the CI gate over an offline run; decides pass/fail of a build, not the class of a comparison",
	"legacy.go": "ModelEvaluator, which infers a legacy verdict for the OFFLINE corpus; the runtime legacy side comes from the plane's own result (planeshadow/translate.go), never from here",

	// Self-reference would be circular: embedding semantics.go into the digest
	// it computes changes the digest, which changes semantics.go, forever.
	"semantics.go": "computes the digest; embedding it would be circular",
}

func TestEveryShadowFileIsEmbeddedOrExcludedWithAReason(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the package directory: %v", err)
	}

	src, err := os.ReadFile("semantics.go")
	if err != nil {
		t.Fatalf("reading semantics.go: %v", err)
	}
	embedded := map[string]bool{}
	for _, m := range regexp.MustCompile(`//go:embed ([A-Za-z0-9_]+\.go)`).FindAllStringSubmatch(string(src), -1) {
		embedded[m[1]] = true
	}

	// ANTI-VACUITY on both inputs: a regex that stopped matching, or a
	// directory read that returned nothing, would make every check below hold
	// over an empty set.
	if len(embedded) == 0 {
		t.Fatal("no //go:embed directive found in semantics.go; this test would then require " +
			"every file to be excluded and would pass by measuring nothing")
	}

	var files []string
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		files = append(files, n)
	}
	sort.Strings(files)
	if len(files) < 5 {
		t.Fatalf("only %d non-test .go file(s) found (%v); the directory read is wrong and this "+
			"census is measuring almost nothing", len(files), files)
	}

	var unclassified []string
	for _, f := range files {
		if embedded[f] {
			continue
		}
		if reason, ok := semanticsDigestExclusions[f]; ok {
			if strings.TrimSpace(reason) == "" {
				t.Errorf("%s is excluded with an EMPTY reason; an exclusion nobody has to "+
					"justify is the same as no list", f)
			}
			continue
		}
		unclassified = append(unclassified, f)
	}
	if len(unclassified) > 0 {
		t.Fatalf("these files are in the shadow package and are NEITHER embedded into "+
			"SemanticsDigest NOR excluded with a reason: %v\n\n"+
			"SemanticsDigest is half of EvaluatorVersion, a reset stamp for ADR-065 gate 18.\n"+
			"A stamp over an incomplete input set stays STILL across a change that altered the\n"+
			"classification, and a window that did not reset when its semantics changed reads as\n"+
			"one continuous window when it is two.\n\n"+
			"Decide, and record the decision: add a //go:embed in semantics.go, or add the file\n"+
			"to semanticsDigestExclusions with a sentence saying why a production comparison\n"+
			"never passes through it.", unclassified)
	}

	present := map[string]bool{}
	for _, f := range files {
		present[f] = true
	}
	var stale []string
	for f := range semanticsDigestExclusions {
		if !present[f] {
			stale = append(stale, f)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("semanticsDigestExclusions names file(s) that no longer exist: %v", stale)
	}
}

// TestTheSemanticsDigestMovesWhenAnEmbeddedFileChanges proves the mechanism is
// live rather than declarative.
//
// "The file is embedded" has to mean "editing it moves the stamp", not "its
// name appears in a directive" - a part left out of the digest's argument list
// is invisible to a census that only reads directives.
func TestTheSemanticsDigestMovesWhenAnEmbeddedFileChanges(t *testing.T) {
	base := semanticsDigestOf(srcClassify, srcVerdict, srcCase, srcWorld)
	if base != SemanticsDigest() {
		t.Fatalf("recomputing over the same inputs gave a different value:\n"+
			"  SemanticsDigest() = %s\n  recomputed         = %s\n"+
			"This test says nothing about the real stamp if it is not computing it.",
			SemanticsDigest(), base)
	}

	// EACH PART IS MUTATED IN TURN, BY INDEX. A single mutation would prove
	// only that SOME part is wired; a part quietly left out of
	// semanticsDigestOf's argument list is invisible to a census that reads
	// only the //go:embed directives, and that is the failure this loop exists
	// to catch.
	names := []string{"classify.go", "verdict.go", "case.go", "world.go"}
	for i, name := range names {
		parts := [][]byte{srcClassify, srcVerdict, srcCase, srcWorld}
		if len(parts[i]) == 0 {
			t.Fatalf("%s embedded as zero bytes; the go:embed did not take", name)
		}
		mutated := append([]byte(nil), parts[i]...)
		mutated[0] ^= 0xFF
		parts[i] = mutated
		if got := semanticsDigestOf(parts...); got == base {
			t.Fatalf("changing a byte of %s did NOT move the semantics digest, so the reset "+
				"stamp cannot see a change to the semantics it covers", name)
		}
	}

	// The length prefix must separate the parts: moving one byte ACROSS a
	// boundary has to move the digest, or a refactor that relocates a rule from
	// classify.go into verdict.go leaves the stamp unmoved.
	shiftedA := srcClassify[:len(srcClassify)-1]
	shiftedB := append(append([]byte(nil), srcClassify[len(srcClassify)-1]), srcVerdict...)
	if got := semanticsDigestOf(shiftedA, shiftedB, srcCase, srcWorld); got == base {
		t.Fatal("moving one byte across a part boundary did not move the digest; the length " +
			"prefix is not separating the parts")
	}
}
