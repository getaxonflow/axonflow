// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package replay_test

import (
	"errors"
	"strings"
	"testing"

	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/replay"
)

// A REPLAY ENVIRONMENT IS PINNED BY WHAT ITS BUNDLES ACTUALLY HASH TO (#3700).
//
// Environment.BundleDigests is the site where trusting the advertised digest
// mattered most, and it is the one of the four that a caller can reach with a
// bundle it did not build: nothing upstream verifies the bundles, because
// Validate checks the declared keys and a caller need never call Engine().
// cmd/decision-replay prints these pins before it replays anything, and
// EXPORTS the method, so "the digest of this environment's bundle" was an
// advertised label any consumer could read.
//
// WHAT THIS DOES AND DOES NOT CLOSE, stated precisely because an earlier
// version of this comment overstated it and R3 caught that. It is NOT true
// that a mislabelled bundle made CheckPins compare equal to a record it did
// not produce: Record.EnvironmentDigest hashes the WHOLE Environment,
// bundles included, so any drift in content or label already changed it and
// CheckPins already refused - record.go says as much where it calls the
// bundle pins "redundant with EnvironmentDigest only when nothing is wrong".
// What was genuinely unguarded is the exported BundleDigests itself and every
// consumer of its output that does not also check the environment digest.
// The value of recomputing here is that the pin a caller reads is a fact
// about content rather than a label, and that CheckPins now reports the
// disagreement as a pin problem instead of inheriting it as a coincidence.
func TestAnEnvironmentWhoseBundleIsMislabelledRefusesToProducePins(t *testing.T) {
	env, recs := loadFixture(t)
	if len(recs) == 0 {
		t.Fatal("the fixture carries no records")
	}

	// The genuine environment pins, and CheckPins accepts its own record.
	pins, err := env.BundleDigests()
	if err != nil {
		t.Fatalf("a genuine environment refused to produce pins: %v", err)
	}
	if len(pins) == 0 {
		t.Fatal("the environment produced no pins; this test would prove nothing")
	}
	if err := replay.CheckPins(env, recs[0]); err != nil {
		t.Fatalf("the fixture's own record does not check against its environment: %v", err)
	}

	// Now relabel one bundle. Its content, signature, provenance and manifest
	// are untouched; only the advertised digest is a lie.
	tampered := cloneEnvironment(t, env)
	if len(tampered.Roots) == 0 || tampered.Roots[0].Bundle == nil {
		t.Fatal("the cloned environment carries no bundle to relabel")
	}
	was := tampered.Roots[0].Bundle.Digest
	tampered.Roots[0].Bundle.Digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	if was == tampered.Roots[0].Bundle.Digest {
		t.Fatal("the relabel did not change the advertised digest")
	}

	// THE SLICE AND THE ERROR MUST BE DISJOINT, and this is the assertion the
	// census cannot make. R3 round 5 put ONE line back into BundleDigests -
	// appending `Pin{Root: r.Root, Digest: u.Advertised}` beside the refusal -
	// and everything stayed green: the whole module, and the census at exactly
	// 27 sites and 40 occurrences, because the row was already declared and the
	// count did not move. A census pins the SET OF READERS; it cannot see a
	// declared reader being used for something new. The revert control works
	// and the ADDITION is what it is blind to.
	//
	// So the contract is asserted where it lives: a root the error names must
	// not appear in the pins, because the entire point of the partial slice is
	// that it holds only what could be VERIFIED. A caller that trusted a pin
	// for an unpinnable root would be reading the advertised label again, which
	// is the defect this whole change exists to remove.
	if pins, err := tampered.BundleDigests(); err != nil {
		var unpin *replay.UnpinnableBundlesError
		if !errors.As(err, &unpin) {
			t.Fatalf("BundleDigests refused with %T, not an *UnpinnableBundlesError; a caller cannot tell which roots are missing from the slice", err)
		}
		if len(unpin.Roots) == 0 {
			t.Fatal("the refusal names no roots, so the assertion below could not fail")
		}
		named := map[pdp.Root]bool{}
		for _, u := range unpin.Roots {
			named[u.Root] = true
		}
		if len(pins) == 0 {
			t.Fatal("the partial slice is empty, so it cannot demonstrate that the pinnable roots survive alongside the error")
		}
		for _, p := range pins {
			if named[p.Root] {
				t.Errorf("BundleDigests returned a pin for root %q AND named it unpinnable; the partial slice must hold only roots whose digest was verified, or a caller reading it is trusting the advertised label again", p.Root)
			}
		}
	}

	if _, err := tampered.BundleDigests(); err == nil {
		t.Fatal("an environment holding a bundle whose content does not hash to its advertised digest produced pins anyway; " +
			"every consumer of this exported method would then be reading a label as though it were a fact about content")
	} else {
		if !strings.Contains(err.Error(), "does not match content digest") {
			t.Errorf("the refusal does not name the mismatch: %v", err)
		}
		if !strings.Contains(err.Error(), string(tampered.Roots[0].Root)) {
			t.Errorf("the refusal does not name the root it came from: %v", err)
		}
	}

	// And the refusal propagates AS A PIN ERROR, carrying both facts.
	//
	// The type matters beyond tidiness: cmd/decision-replay chooses exitPin
	// ("these are not your artifacts") over exitUsage ("you called me wrong")
	// with errors.As on *PinError, so returning the raw error here would have
	// downgraded the exit code of the exact scenario this test exists for.
	err = replay.CheckPins(tampered, recs[0])
	if err == nil {
		t.Fatal("CheckPins accepted an environment whose bundle digest does not describe its content")
	}
	if !strings.Contains(err.Error(), "does not match content digest") {
		t.Errorf("CheckPins reported something other than the digest mismatch: %v", err)
	}
	var pinErr *replay.PinError
	if !errors.As(err, &pinErr) {
		t.Fatalf("CheckPins returned %T, not a *replay.PinError; the CLI selects its exit code with errors.As, so this refusal would report as a usage error", err)
	}
	// Both facts survive: the environment digest moved too, and a reader must
	// see both rather than whichever the function noticed first.
	var kinds []string
	for _, m := range pinErr.Mismatches {
		kinds = append(kinds, m.Kind)
	}
	if len(pinErr.Mismatches) < 2 {
		t.Errorf("the refusal carries only %v; the environment digest also moved and CheckPins reports BOTH directions", kinds)
	}
	// BOTH DIRECTIONS SURVIVE THE NEW PATH. R3 round 3 measured a
	// missing_root row DISAPPEARING once a bundle became unverifiable,
	// because the function returned on the first refusal - so the operator
	// was told one of the two facts, in a function whose doc is about
	// reporting both. The refusal is recorded and the comparison continues.
	var haveEnvironment, haveUnverifiable bool
	for _, m := range pinErr.Mismatches {
		switch m.Kind {
		case "environment":
			haveEnvironment = true
		case "unverifiable_bundle":
			haveUnverifiable = true
		}
	}
	if !haveUnverifiable {
		t.Errorf("the refusal does not name the unverifiable bundle: %v", kinds)
	}
	if !haveEnvironment {
		t.Errorf("the refusal lost the environment mismatch that was already found: %v", kinds)
	}

	// AND NOTHING IN THE REFUSAL IS FALSE. R3 round 4 found that the fix for
	// the disappearing row introduced a spurious one: the unpinnable root
	// falls out of the pin slice, so the pinned-root loop reported the one
	// root this environment demonstrably HOLDS as a root it does not hold -
	// and the record's pin for it is the content digest, so the record and the
	// content agreed perfectly and only the label was wrong. The refusal sent
	// an operator looking for an artifact that was in front of them.
	//
	// This asserts the property rather than the sentence: no mismatch may
	// claim a root is absent when the environment holds a bundle for it.
	holds := map[pdp.Root]bool{}
	for _, r := range tampered.Roots {
		if r.Bundle != nil {
			holds[r.Root] = true
		}
	}
	if len(holds) == 0 {
		t.Fatal("the fixture environment holds no bundles at all, so the assertion below could not fail")
	}
	for _, m := range pinErr.Mismatches {
		if m.Kind == "missing_root" && holds[m.Root] {
			t.Errorf("the refusal says this environment holds no bundle for root %q, and it does hold one; an unpinnable bundle is not a missing one, and telling an operator otherwise sends them looking for an artifact they already have", m.Root)
		}
	}
	// THE NOTE IS ASSERTED, IN BOTH DIRECTIONS. Review found it was documented
	// and not tested: flipping the comparison that chooses between the two
	// sentences left the whole module green with every operator-facing
	// diagnosis backwards. That is this PR's own thesis one level down - a
	// claim in an artefact with no test exercising it - so the sentence gets
	// the same treatment the digests did.
	//
	// This environment is the LABEL-ONLY case: the content is exactly what the
	// record pins, so the reassuring note is the true one.
	for _, m := range pinErr.Mismatches {
		if m.Kind != "unverifiable_bundle" {
			continue
		}
		var pinned string
		for _, p := range recs[0].BundlePins {
			if p.Root == m.Root {
				pinned = p.Digest
			}
		}
		if pinned != m.Got {
			t.Fatalf("the fixture is no longer the label-only case (record pins %s, content is %s), so the note asserted below is about a different situation", pinned, m.Got)
		}
		if !strings.Contains(m.Note, "the content IS the digest your record pins") {
			t.Errorf("the content matches what the record pins and the note does not say so; an operator is told to go looking for an artifact they already have: %q", m.Note)
		}
		if strings.Contains(m.Note, "DIFFERENT artifact") {
			t.Errorf("the note calls this a different artifact when the content is exactly what the record pins: %q", m.Note)
		}
	}

	// THE OTHER DIRECTION, on a record whose pin does NOT match the content.
	// Without this the comparison could be inverted, or absent, and the case
	// above would still pass.
	drifted := *recs[0]
	drifted.BundlePins = append([]replay.Pin(nil), recs[0].BundlePins...)
	for i := range drifted.BundlePins {
		if drifted.BundlePins[i].Root == tampered.Roots[0].Root {
			drifted.BundlePins[i].Digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
		}
	}
	driftErr := replay.CheckPins(tampered, &drifted)
	if driftErr == nil {
		t.Fatal("an environment whose bundle is unverifiable was accepted against a record pinning a different digest")
	}
	var driftPin *replay.PinError
	if !errors.As(driftErr, &driftPin) {
		t.Fatalf("CheckPins returned %T, not a *replay.PinError", driftErr)
	}
	var sawDrift bool
	for _, m := range driftPin.Mismatches {
		if m.Kind != "unverifiable_bundle" {
			continue
		}
		sawDrift = true
		if !strings.Contains(m.Note, "DIFFERENT artifact") {
			t.Errorf("the content does NOT match what the record pins and the note does not say so; the reassuring sentence sends an operator the wrong way: %q", m.Note)
		}
		if strings.Contains(m.Note, "the content IS the digest your record pins") {
			t.Errorf("the note reassures on a record whose pin does not match the content: %q", m.Note)
		}
	}
	if !sawDrift {
		t.Error("the drifted-record case produced no unverifiable_bundle row, so its note was never asserted")
	}

	// The unverifiable row carries both digests, so the operator can see that
	// the content is what the record pinned and only the label moved.
	for _, m := range pinErr.Mismatches {
		if m.Kind != "unverifiable_bundle" {
			continue
		}
		if m.Root == "" {
			t.Error("the unverifiable_bundle row names no root; a refusal an operator cannot act on is prose")
		}
		if m.Want == "" || m.Got == "" || m.Want == m.Got {
			t.Errorf("the unverifiable_bundle row must carry the advertised digest and the content digest, and they must differ; got want=%q got=%q", m.Want, m.Got)
		}
		for _, p := range recs[0].BundlePins {
			if p.Root == m.Root && p.Digest != m.Got {
				t.Errorf("the record pins %s for root %q and the content digest is %s; this fixture is meant to be the case where only the LABEL is wrong, so if these differ the test is no longer about that case", p.Digest, m.Root, m.Got)
			}
		}
	}
}
