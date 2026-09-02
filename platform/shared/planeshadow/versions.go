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

	adapterVersion = digestOf(
		[]byte("adapter\x00"),
		srcTranslate, srcWorlds, srcRows, srcObservation, srcMode, srcStamp,
	)
)

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
