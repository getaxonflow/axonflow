// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// The reset stamps (#3564 round 2).
//
// # WHY BundleDigest IS NOT ENOUGH
//
// ADR-065 gate 18 is a statement about a WINDOW, and epic #3552's redefinition
// RESETS that window on a material semantic change to the observed path -
// including changes to components both sides share. A reset boundary that has
// to be reconstructed from git history is not a property of the data: the
// records themselves must say which semantics produced them, or an operator
// reading "180 days, zero unexplained" has no way to know whether it is one
// window or four glued together.
//
// Comparison.BundleDigest covers exactly one of the moving parts: the
// compiler's Rego rendering of a given set of policy rows. It is derived from
// those rows, so for an UNCHANGED policy set it is byte-identical across:
//
//   - a change to shadow.Classify, which decides what counts as an
//     expected_change and therefore what lands in the gate's numerator;
//   - a change to translate.go or worlds.go, which decide what request the
//     PDP is even asked about;
//   - a change to a plane's observation site, which decides what facts reach
//     the shadow at all;
//   - a change to the OPA version the bundle is EVALUATED by, which can move
//     a verdict with no change to the policy or its rendering.
//
// Each of those is a reset boundary, and before this file none of them moved
// an observable field. Three stamps close that, and each is DERIVED at build
// or init rather than typed by hand: see the argument in
// shadow.SemanticsDigest for why a version constant is the mechanism that
// fails silently in the dangerous direction.
package planeshadow

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"

	"axonflow/platform/decision/legacycompile/shadow"
)

// The adapter's own semantics: how a plane's report becomes a PDP question.
//
// translate.go and worlds.go build the ADR-065 request and the world it is
// asked against; rows.go decides which policy rows the shadow may compile
// from; observation.go is the contract a call site fills in, and the set of
// facts it can carry bounds what either side can ever see; mode.go decides
// which planes are observed at all, and a narrowing there changes the
// population a window covers.
//
// recorder.go, metrics.go and observer.go are deliberately ABSENT. They decide
// how a comparison is reported and scheduled, not what it says: a change to a
// log line's field order or to the worker pool size is not a semantic change
// to the observed path, and resetting a 180-day window for one would train an
// operator to ignore the stamp.
var (
	//go:embed translate.go
	srcTranslate []byte
	//go:embed worlds.go
	srcWorlds []byte
	//go:embed rows.go
	srcRows []byte
	//go:embed observation.go
	srcObservation []byte
	//go:embed mode.go
	srcMode []byte
	// stamp.go IS SEMANTIC, and its omission was the gap this list had.
	//
	// It owns stampLayouts and normalizeStamp - the ONE rendering both sides of
	// a snapshot key must agree on. The plane's side is built through
	// StampKey (tier_shadow_observe.go, shared/policy/loader.go) and the
	// shadow's own read is normalized in rows.go, so a change to the accepted
	// layouts changes whether two readings of ONE instant collapse to one key.
	//
	// stamp.go's own header states the consequence: a key that differs by
	// spelling makes every comparison not-comparable forever - "a permanently
	// empty denominator that reads as a healthy zero-unexplained gate". That is
	// a change to the window's POPULATION, which is exactly what rows.go is
	// embedded for. Embedding rows.go and not the rule it calls covered the
	// caller and not the decision.
	//go:embed stamp.go
	srcStamp []byte
	// org_planes.go IS SEMANTIC for the same reason mode.go is, one scope
	// down: mode.go decides which planes the DEPLOYMENT observes, and this
	// decides which of those an ORGANIZATION observes. Both change the
	// window's POPULATION - which planes have evidence at all - and gate 18 is
	// stated per plane, so a change to the composition rule changes what a
	// per-plane reading is a reading OF.
	//
	// Concretely: if the intersection rule became a replacement rule, an
	// organization's record could re-open a plane the deployment withdrew, and
	// comparisons for that plane would start appearing in a window an operator
	// believes excludes it. That is two windows read as one, which is the
	// failure this stamp exists to make visible.
	//go:embed org_planes.go
	srcOrgPlanes []byte
)

// EvaluatorVersion is the digest of the ADR-065 side's evaluation semantics:
// the classifier's source and the OPA build that runs the bundle.
//
// It is what changes when the answer changes for reasons that have nothing to
// do with the policy set, which is precisely the class BundleDigest cannot
// see.
func EvaluatorVersion() string { return evaluatorVersion }

// AdapterVersion is the digest of the translation layer between a plane's
// evaluation and the PDP question asked about it.
func AdapterVersion() string { return adapterVersion }

var (
	evaluatorVersion = digestOf(
		[]byte("evaluator"),
		[]byte(shadow.SemanticsDigest()),
		[]byte(shadow.EngineVersion()),
	)

	adapterVersion = digestOf(append([][]byte{[]byte("adapter\x00")}, adapterDigestParts()...)...)
)

// adapterDigestParts is the ORDERED list of sources the adapter stamp covers,
// written ONCE.
//
// It exists because this list was written in three places - the digest itself
// and two tests that recompute it - and the failure mode of that shape is not
// a compile error: adding a file to one copy leaves the other two computing a
// DIFFERENT digest, and the test that then fails says "the stamp and its
// documented coverage disagree" while the disagreement is between two copies
// of the same sentence.
//
// ORDER IS PART OF THE VALUE: digestOf length-prefixes each part, so a
// reordering changes the digest. That is correct - it is a reset stamp, and an
// unexplained reset is cheap while a missed one is the failure this exists to
// prevent - but it means this function DEFINES the order rather than being a
// convenience over it.
func adapterDigestParts() [][]byte {
	out := make([][]byte, 0, len(adapterDigestSources))
	for _, s := range adapterDigestSources {
		out = append(out, s.src)
	}
	return out
}

// adapterDigestSources names each covered source beside its bytes, so a check
// on the parts can say WHICH file it is talking about without a second list.
var adapterDigestSources = []struct {
	name string
	src  []byte
}{
	{"translate.go", srcTranslate},
	{"worlds.go", srcWorlds},
	{"rows.go", srcRows},
	{"observation.go", srcObservation},
	{"mode.go", srcMode},
	{"stamp.go", srcStamp},
	{"org_planes.go", srcOrgPlanes},
}

// digestOf hashes its parts with an explicit separator between them.
//
// The separator is not decoration. Concatenating two source files and hashing
// the result makes (a+b) and (a'+b') collide whenever a byte moves across the
// boundary, so a change that only SHIFTED content between two of these files
// would leave the stamp unmoved - and a refactor that moves a rule from
// translate.go into worlds.go is exactly the shape of a change someone would
// call cosmetic and this stamp exists to catch.
func digestOf(parts ...[]byte) string {
	h := sha256.New()
	for _, p := range parts {
		var lenPrefix [8]byte
		n := uint64(len(p))
		for i := 0; i < 8; i++ {
			lenPrefix[i] = byte(n >> (8 * (7 - i)))
		}
		h.Write(lenPrefix[:])
		h.Write(p)
	}
	return hex.EncodeToString(h.Sum(nil))
}
