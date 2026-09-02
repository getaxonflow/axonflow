// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package planeshadow

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// EVERY FILE IN THIS PACKAGE IS EITHER PART OF THE ADAPTER DIGEST OR NAMED HERE
// WITH A REASON.
//
// AdapterVersion is a RESET STAMP: it exists so that a change to how a plane's
// evaluation becomes a PDP question moves an observable field, and an operator
// reading "180 days, zero unexplained" can tell one window from four glued
// together. A stamp computed from an INCOMPLETE set of inputs fails in the one
// direction that matters - it stays still across a change that altered what the
// window contains, which is indistinguishable from continuity.
//
// It had that gap. stamp.go owns the single rendering both sides of a snapshot
// key must agree on, and it was neither embedded nor excluded: rows.go, which
// CALLS normalizeStamp, was embedded, so the digest covered the caller and not
// the decision. A change to stampLayouts would have made every comparison
// not-comparable - a permanently empty denominator - without moving the stamp
// that exists to say the semantics moved.
//
// A prose list of exclusions cannot catch the NEXT such file, because nothing
// re-reads prose when a file is added. This test is that re-reading: a new .go
// file in this package must be embedded, or appear below with a stated reason.
// Neither choice is silent, which is the only property being bought here.
var adapterDigestExclusions = map[string]string{
	// Reported and scheduled, not decided. A change to a log line's field order
	// or the worker pool size does not change what a comparison SAYS, and
	// resetting a 180-day window for one would train an operator to ignore the
	// stamp.
	"recorder.go": "decides how a comparison is reported, not what it says",
	"metrics.go":  "decides how a comparison is counted, not what it says",
	"observer.go": "decides when and whether a comparison is scheduled, not what it says",

	// Wiring and configuration reading. The values it resolves (the realm, the
	// content target, the plane list) reach the comparison through
	// compileOpts and Config, which mode.go and worlds.go already cover.
	"bootstrap.go": "reads deployment configuration into Config; the values it resolves are covered by mode.go and worlds.go",

	// Not code.
	"doc.go": "package documentation; contains no decision",

	// Self-reference would be circular: embedding versions.go into the digest
	// it computes changes the digest, which changes versions.go, forever.
	"versions.go": "computes the digest; embedding it would be circular",
}

func TestEveryPackageFileIsEmbeddedOrExcludedWithAReason(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the package directory: %v", err)
	}

	src, err := os.ReadFile("versions.go")
	if err != nil {
		t.Fatalf("reading versions.go: %v", err)
	}
	embedRe := regexp.MustCompile(`//go:embed ([A-Za-z0-9_]+\.go)`)
	embedded := map[string]bool{}
	for _, m := range embedRe.FindAllStringSubmatch(string(src), -1) {
		embedded[m[1]] = true
	}

	// ANTI-VACUITY, on both inputs. A regex that matched nothing, or a
	// directory read that returned nothing, would make every assertion below
	// hold over an empty set - the exact shape this package argues about
	// everywhere else.
	if len(embedded) == 0 {
		t.Fatal("no //go:embed directive was found in versions.go; this test would then " +
			"require every file to be excluded and would pass by measuring nothing")
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
		t.Fatalf("only %d non-test .go file(s) found (%v); the directory read is wrong and "+
			"this census is measuring almost nothing", len(files), files)
	}

	var unclassified []string
	for _, f := range files {
		if embedded[f] {
			continue
		}
		if reason, ok := adapterDigestExclusions[f]; ok {
			if strings.TrimSpace(reason) == "" {
				t.Errorf("%s is excluded from the adapter digest with an EMPTY reason; an "+
					"exclusion nobody has to justify is the same as no list", f)
			}
			continue
		}
		unclassified = append(unclassified, f)
	}

	if len(unclassified) > 0 {
		t.Fatalf("these files are in planeshadow and are NEITHER embedded into AdapterVersion "+
			"NOR excluded with a reason: %v\n\n"+
			"AdapterVersion is a reset stamp for ADR-065 gate 18. A stamp computed from an\n"+
			"incomplete input set stays STILL across a change that altered what the observation\n"+
			"window contains, and a window that did not reset when its semantics changed reads\n"+
			"as one continuous window when it is two.\n\n"+
			"Decide, and record the decision: add a //go:embed for the file in versions.go, or\n"+
			"add it to adapterDigestExclusions with a sentence saying why it decides nothing\n"+
			"about what a comparison SAYS.", unclassified)
	}

	// And the list may not name files that no longer exist, or the reasoning it
	// records is about a package that has moved on.
	present := map[string]bool{}
	for _, f := range files {
		present[f] = true
	}
	var stale []string
	for f := range adapterDigestExclusions {
		if !present[f] {
			stale = append(stale, f)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("adapterDigestExclusions names file(s) that no longer exist: %v", stale)
	}
}

// TestTheAdapterDigestMovesWhenAnEmbeddedFileChanges proves the mechanism the
// census above is protecting actually works.
//
// A census over an inert digest would be bookkeeping. This reads the real
// digest, then recomputes it over the same inputs with one byte changed, and
// requires the two to differ - so "the file is embedded" means "editing it
// moves the stamp" rather than "its name appears in a directive".
func TestTheAdapterDigestMovesWhenAnEmbeddedFileChanges(t *testing.T) {
	base := digestOf([]byte("adapter\x00"), srcTranslate, srcWorlds, srcRows, srcObservation, srcMode, srcStamp)
	if base != AdapterVersion() {
		t.Fatalf("recomputing the adapter digest over the same inputs gave a different value:\n"+
			"  AdapterVersion() = %s\n  recomputed        = %s\n"+
			"This test cannot say anything about the real stamp if it is not computing it.",
			AdapterVersion(), base)
	}

	// One byte changed in ONE of the parts.
	mutated := append([]byte(nil), srcStamp...)
	if len(mutated) == 0 {
		t.Fatal("stamp.go embedded as zero bytes; the go:embed did not take")
	}
	mutated[0] ^= 0xFF
	if got := digestOf([]byte("adapter\x00"), srcTranslate, srcWorlds, srcRows, srcObservation, srcMode, mutated); got == base {
		t.Fatal("changing a byte of an embedded file did NOT move the adapter digest, so the " +
			"reset stamp cannot see a change to the semantics it covers")
	}

	// And the separator does its job: moving a byte ACROSS a part boundary must
	// still move the digest. Without the length prefix, (a+b) and (a'+b')
	// collide whenever content shifts between two files - which is exactly what
	// a refactor that moves a rule from translate.go into worlds.go looks like.
	if len(srcTranslate) == 0 || len(srcWorlds) == 0 {
		t.Fatal("an embedded part is empty; the shift test below would prove nothing")
	}
	shiftedA := srcTranslate[:len(srcTranslate)-1]
	shiftedB := append(append([]byte(nil), srcTranslate[len(srcTranslate)-1]), srcWorlds...)
	if got := digestOf([]byte("adapter\x00"), shiftedA, shiftedB, srcRows, srcObservation, srcMode, srcStamp); got == base {
		t.Fatal("moving one byte across a part boundary did not move the digest; the length " +
			"prefix in digestOf is not separating the parts, and a refactor that relocates a " +
			"rule between two embedded files would leave the reset stamp unmoved")
	}
}
