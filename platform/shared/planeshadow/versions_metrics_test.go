// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package planeshadow

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/legacycompile/shadow"
)

// TestTheFailOpenSeriesIsExportedBeforeAnythingFailsOpen is the regression for
// the defect runtime-e2e 3564 found: `axonflow_decision_shadow_fail_open_total
// is not exported`.
//
// A CounterVec is registered but rendered by walking its CHILDREN. With none,
// the scrape carries no sample, no # HELP and no # TYPE - so on the one
// deployment shape the gate is about, the healthy one where nothing has ever
// failed open, gate 18's operand series DID NOT EXIST. An alert on an absent
// series does not fire, and the gate's central promise reads as satisfied
// because nothing was measuring it. That is the same vacuity as a zero
// denominator, one level down.
//
// The assertion is deliberately made WITHOUT recording a comparison first: the
// point is that the series exists before any traffic, which is exactly what a
// test that recorded one would fail to prove.
func TestTheFailOpenSeriesIsExportedBeforeAnythingFailsOpen(t *testing.T) {
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gathering the default registry: %v", err)
	}
	var family *dto.MetricFamily
	for _, f := range families {
		if f.GetName() == "axonflow_decision_shadow_fail_open_total" {
			family = f
			break
		}
	}
	if family == nil {
		t.Fatal("axonflow_decision_shadow_fail_open_total is not exported at all; a vector with no children renders nothing, and gate 18's operand would be an absent series an alert cannot fire on")
	}

	planes := ImplementedPlanes()
	if len(planes) == 0 {
		t.Fatal("ImplementedPlanes() is empty, so this test would pass over nothing")
	}
	seen := map[string]bool{}
	for _, m := range family.GetMetric() {
		labels := map[string]string{}
		for _, l := range m.GetLabel() {
			labels[l.GetName()] = l.GetValue()
		}
		if labels["direction"] == gateOperandDirection && labels["classification"] == gateOperandClass {
			seen[labels["plane"]] = true
		}
	}
	var missing []string
	for _, p := range planes {
		if !seen[string(p)] {
			missing = append(missing, string(p))
		}
	}
	if len(missing) > 0 {
		t.Fatalf("the gate-18 coordinate is not pre-created for plane(s) %v; those planes' fail-open series would be absent until the first one occurs, which is the moment it is too late to have been alerting",
			missing)
	}
}

// TestTheGateOperandSeriesMatchesTheClassifier pins the two label VALUES the
// pre-created series uses against the classifier's own constants.
//
// They are spelled as literals in metrics.go so the pre-creation does not drag
// a dependency into the metric declarations, and that is exactly the shape
// that silently drifts: a rename in the classifier would move every real
// sample onto a new coordinate while the pre-created, permanently-zero one
// stayed where the alert was looking. The alert would then read zero forever,
// on a series nothing writes to, which is worse than an absent one.
func TestTheGateOperandSeriesMatchesTheClassifier(t *testing.T) {
	if gateOperandDirection != string(shadow.FailOpenNewPermitted) {
		t.Fatalf("the pre-created direction %q is not shadow.FailOpenNewPermitted (%q); the alert would watch a coordinate nothing writes to",
			gateOperandDirection, shadow.FailOpenNewPermitted)
	}
	if gateOperandClass != string(shadow.ClassUnexplained) {
		t.Fatalf("the pre-created classification %q is not shadow.ClassUnexplained (%q)",
			gateOperandClass, shadow.ClassUnexplained)
	}
}

// TestTheResetStampsAreDistinctAndDerived covers the three properties a reset
// stamp has to have to be one at all.
func TestTheResetStampsAreDistinctAndDerived(t *testing.T) {
	if EvaluatorVersion() == "" || AdapterVersion() == "" {
		t.Fatalf("a reset stamp is empty (evaluator=%q adapter=%q); an empty stamp makes every window look like the same window",
			EvaluatorVersion(), AdapterVersion())
	}
	if EvaluatorVersion() == AdapterVersion() {
		t.Fatal("the evaluator and adapter stamps are equal, so one of them is not covering what it claims to; a change to either would move both and neither would say which")
	}
	if shadow.SemanticsDigest() == "" {
		t.Fatal("the classifier reports no semantics digest, so the evaluator stamp is composed from nothing")
	}
	// The stamps must be STABLE within a process: they are read once per
	// comparison and a value that varied per call would make every record its
	// own window.
	if EvaluatorVersion() != EvaluatorVersion() || AdapterVersion() != AdapterVersion() {
		t.Fatal("a stamp is not stable across reads")
	}
}

// TestDigestOfSeparatesItsParts is the property the length prefix exists for.
//
// Concatenating parts and hashing the result cannot tell (a+b) from (a'+b')
// when a byte moves across the boundary - so a refactor that moved a rule from
// translate.go into worlds.go, which is precisely the change someone would
// call cosmetic, would leave the adapter stamp unmoved.
func TestDigestOfSeparatesItsParts(t *testing.T) {
	ab := digestOf([]byte("alpha"), []byte("beta"))
	shifted := digestOf([]byte("alph"), []byte("abeta"))
	if ab == shifted {
		t.Fatal("digestOf collides when content moves across a part boundary; a rule relocated between two adapter files would not move the stamp")
	}
	if digestOf([]byte("alpha"), []byte("beta")) != ab {
		t.Fatal("digestOf is not deterministic")
	}
}

// TestTheEvaluatorStampNamesTheEngineItRuns proves the OPA half of the
// evaluator stamp is READ rather than guessed, and that it actually reaches
// the composed digest.
//
// It is the only one of the four reset boundaries with no source file of ours
// to digest, so a silently-unavailable value would compose a stamp that never
// moves on an evaluator upgrade - and would do so invisibly, because the
// digest would still look like a digest.
//
// The first revision of this read debug.ReadBuildInfo(). That is why this test
// exists in this shape: `go test` binaries carry an EMPTY Deps list, so the
// value under test was `unknown` in every unit test and the stamp's one
// unobservable component was also its untested one.
func TestTheEvaluatorStampNamesTheEngineItRuns(t *testing.T) {
	got := shadow.EngineVersion()
	if strings.TrimSpace(got) == "" {
		t.Fatal("the engine reports no version, so the evaluator stamp cannot move when OPA is upgraded")
	}
	// COMPOSED IN, not merely available. A constant that is read and then
	// dropped on the floor is the same as one that was never read.
	if EvaluatorVersion() == digestOf([]byte("evaluator"), []byte(shadow.SemanticsDigest())) {
		t.Fatal("the evaluator stamp is the classifier digest alone; the engine version is not composed into it, so an OPA upgrade would not reset the window")
	}
	if EvaluatorVersion() != digestOf([]byte("evaluator"), []byte(shadow.SemanticsDigest()), []byte(got)) {
		t.Fatal("the evaluator stamp is not the documented composition of the classifier digest and the engine version")
	}
}

// TestTheAdapterStampCoversTheTranslationLayer states, in a test rather than
// only in a comment, WHICH files the adapter stamp is a statement about.
//
// The list is a judgement call - recorder.go and observer.go are deliberately
// excluded because they decide how a comparison is reported and scheduled, not
// what it says - and a judgement call that lives only in a comment is one
// nobody re-reads when adding a file to the package.
func TestTheAdapterStampCoversTheTranslationLayer(t *testing.T) {
	// stamp.go joined this set after review: it owns stampLayouts and
	// normalizeStamp, the ONE rendering both sides of a snapshot key must agree
	// on, and a change to the accepted layouts makes every comparison
	// not-comparable - an empty denominator that reads as a healthy gate. rows.go
	// was embedded and CALLS normalizeStamp, so the stamp covered the caller and
	// not the decision. TestEveryPackageFileIsEmbeddedOrExcludedWithAReason now
	// makes the next such omission a build failure rather than a reading.
	for name, src := range map[string][]byte{
		"translate.go":   srcTranslate,
		"worlds.go":      srcWorlds,
		"rows.go":        srcRows,
		"observation.go": srcObservation,
		"mode.go":        srcMode,
		"stamp.go":       srcStamp,
	} {
		if len(src) == 0 {
			t.Fatalf("%s embedded as empty; the adapter stamp is not covering it", name)
		}
	}
	// And the stamp must actually depend on each of them: a part accidentally
	// left out of digestOf's argument list is invisible to the check above.
	base := digestOf([]byte("adapter\x00"), srcTranslate, srcWorlds, srcRows, srcObservation, srcMode, srcStamp)
	if base != AdapterVersion() {
		t.Fatal("AdapterVersion() is not the digest of the six embedded adapter files; the stamp and its documented coverage disagree")
	}
}

// TestSpecForEveryImplementedPlane keeps the pre-created series honest about
// what a plane is: the init loop above stamps a label per implemented plane,
// and a plane the compiler has no spec for would put a label on a dashboard
// for a surface that cannot be observed.
func TestSpecForEveryImplementedPlane(t *testing.T) {
	for _, p := range ImplementedPlanes() {
		if _, err := legacycompile.SpecFor(p); err != nil {
			t.Fatalf("plane %q is pre-created as a metric label but has no compiler spec: %v", p, err)
		}
	}
}
