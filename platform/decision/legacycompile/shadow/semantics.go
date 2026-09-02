// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package shadow

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"

	opaversion "github.com/open-policy-agent/opa/v1/version"
)

// The classifier's own source, embedded so its digest can be STAMPED ON EVERY
// COMPARISON (#3564 round 2, epic #3552's reset rule).
//
// # WHY A SOURCE DIGEST AND NOT A VERSION CONSTANT
//
// ADR-065 gate 18 RESETS on a material semantic change to the observed path,
// and the reset boundary has to be detectable FROM THE RECORDED DATA. A window
// that silently spans a change to what counts as an expected_change is not one
// window, it is two windows added together, and nothing in the records would
// say so.
//
// A hand-maintained `const evaluatorVersion = "3"` is the obvious mechanism and
// the wrong one: it is a stamp nobody updates. The person changing
// Classify's tri-state handling is not thinking about a version string three
// files away, and the failure is silent in the direction that matters - the
// window keeps accumulating across the boundary and reads as longer and
// healthier than it is.
//
// Embedding the source makes the stamp a CONSEQUENCE of the edit rather than a
// chore attached to it. Every change to this file moves the digest, including
// the ones nobody would have thought to bump for.
//
// # WHAT IT DELIBERATELY OVER-REPORTS
//
// A comment-only edit moves the digest too, and that is the intended trade.
// The alternative is deciding, in code, which edits to classify.go are
// semantic - which is the same judgement call the version constant already
// failed at, plus a parser. A spurious reset costs a window; a missed one
// costs the gate's meaning.
//
// THE FOUR FILES THE RUNTIME COMPARISON ACTUALLY PASSES THROUGH.
//
// classify.go alone was the original set, and it covered the caller and not
// everything it decides with. Classify calls Verdict.Canonical() on BOTH sides
// of every comparison (classify.go's own `Legacy: in.Legacy.Canonical(), New:
// in.New.Canonical()`), and Canonical lives in verdict.go, where its comment
// explains that the set/multiset asymmetry is load-bearing: de-duplicating
// Effects "let a compiler that dropped two of three targets correspond cleanly
// with a legacy side that demanded three". A change there turns a dropped
// obligation into a `match`, and the stamp would not have moved.
//
// case.go decides the QUESTION - Case.Request builds the contract.Request the
// PDP is asked - and world.go decides the world it is asked against, including
// ActionID, the single registered action every request must name. Both are on
// the runtime path (planeshadow calls shadow.Case, shadow.NewWorld and
// shadow.ActionID directly), and a change to either moves an answer with no
// change to a policy.
//
// The offline corpus machinery is deliberately absent - see
// semanticsDigestExclusions in the coverage test, which requires every file in
// this package to be embedded or to carry a reason, so the next one is a
// decision rather than an omission.
var (
	//go:embed classify.go
	srcClassify []byte
	//go:embed verdict.go
	srcVerdict []byte
	//go:embed case.go
	srcCase []byte
	//go:embed world.go
	srcWorld []byte
)

// SemanticsDigest is the digest of the classification semantics this binary
// carries. It is one half of a comparison's evaluator stamp; the other half is
// EngineVersion.
func SemanticsDigest() string { return semanticsDigest }

// EngineVersion is the OPA build that actually evaluates the compiled bundle.
//
// It is the ONE reset boundary with no source file of ours to digest, and it
// is real: an evaluator upgrade can move a verdict with no change to a policy,
// to its Rego rendering, or to a line of this repository.
//
// It is read from the LIBRARY'S OWN CONSTANT rather than from
// debug.ReadBuildInfo. Build info is the obvious source and it is unusable
// here: `go test` binaries carry an EMPTY dependency list, so every unit test
// of the stamp would have seen `unknown` and the one assertion that could
// prove the version reaches the record could not be written. A version a test
// cannot observe is a version nobody has checked. The library constant is
// compiled in, identical in a test binary and a production one, and moves with
// the module pin.
func EngineVersion() string { return opaversion.Version }

var semanticsDigest = semanticsDigestOf(srcClassify, srcVerdict, srcCase, srcWorld)

// semanticsDigestOf hashes its parts with an explicit LENGTH PREFIX between
// them.
//
// Concatenating the sources and hashing the result makes (a+b) and (a'+b')
// collide whenever a byte moves across the boundary - so a refactor that
// relocated a rule from classify.go into verdict.go would leave the digest
// unmoved, and that is precisely the change someone would call cosmetic and
// this stamp exists to catch.
func semanticsDigestOf(parts ...[]byte) string {
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
