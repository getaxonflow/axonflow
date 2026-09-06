// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package replay_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"axonflow/platform/decision/conformance"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/replay"
)

// ADR-065 acceptance gate 16: "replay reproduces sampled decisions from pinned
// inputs and bundles."
//
// The gate's sentence has an affirmative half and a negative half, and only
// the affirmative half is usually written down. "Identical input reproduces
// identical output" is satisfied by a tool that returns a constant, and
// "identical input and bundle" is satisfied by a tool that ignores the bundle.
// So the three cases below are:
//
//	IDENTICAL   every sample reproduces its recorded decision, offline, from
//	            the committed artifact - and the recorded decision is itself
//	            pinned to a live evaluation, so the corpus cannot drift into
//	            agreeing with a broken tool.
//	CHANGED     a matched pair differing in ONE attribute produces different
//	            decisions, so reproduction is a function of the input.
//	MISMATCHED  a record whose pin does not name the environment's bundle is
//	            REFUSED, and no decision is returned to be mistaken for one.

func loadFixture(t *testing.T) (*replay.Environment, []*replay.Record) {
	t.Helper()
	env, err := replay.LoadEnvironment("testdata/environment.json")
	if err != nil {
		t.Fatalf("loading the committed environment: %v", err)
	}
	entries, err := os.ReadDir("testdata/samples")
	if err != nil {
		t.Fatalf("reading the committed samples: %v", err)
	}
	var recs []*replay.Record
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		rec, err := replay.LoadRecord(filepath.Join("testdata/samples", e.Name()))
		if err != nil {
			t.Fatalf("loading %s: %v", e.Name(), err)
		}
		recs = append(recs, rec)
	}
	if len(recs) == 0 {
		t.Fatal("no committed samples were loaded; every case in this file would pass over an empty set")
	}
	return env, recs
}

func recordByID(t *testing.T, recs []*replay.Record, id string) *replay.Record {
	t.Helper()
	for _, r := range recs {
		if r.CaseID == id {
			return r
		}
	}
	t.Fatalf("the fixture holds no sample %q", id)
	return nil
}

// TestReplayReproducesEveryLiveDecision is the affirmative half, and it is
// checked against TWO references rather than one.
//
// The committed expectation is one reference and it is the weak one: a
// generator with a bug writes an expectation that matches its own bug, and a
// replay that agreed with it would prove only that two copies of the same
// mistake agree. So every sample is also decided on a LIVE conformance world -
// built in this process, from the corpus, through NewWorld - and all three
// must agree: the file, the live engine, and the offline replay.
func TestReplayReproducesEveryLiveDecision(t *testing.T) {
	env, recs := loadFixture(t)

	world, err := conformance.NewWorld(context.Background())
	if err != nil {
		t.Fatalf("building the live conformance world: %v", err)
	}

	for _, rec := range recs {
		t.Run(rec.CaseID, func(t *testing.T) {
			if rec.Expected == nil {
				t.Fatalf("sample %q records no expected decision, so replaying it asserts nothing", rec.CaseID)
			}

			res, err := replay.Replay(context.Background(), env, rec)
			if err != nil {
				t.Fatalf("replaying %s: %v", rec.CaseID, err)
			}
			if !res.Verified {
				t.Fatalf("the offline replay did not reproduce the recorded decision:\n  %s", strings.Join(res.Differences, "\n  "))
			}

			// The fidelity leg. The live engine is a different Engine value,
			// built from differently SIGNED bundles (the fixture key is not
			// the world's ephemeral one), so agreement here is agreement about
			// the decision rather than about the object that produced it.
			live, err := world.Engine.Decide(context.Background(), rec.Request)
			if err != nil {
				t.Fatalf("deciding %s on the live world: %v", rec.CaseID, err)
			}
			if diffs := replay.Diff(live, res.Decision); len(diffs) != 0 {
				t.Fatalf("the offline replay and the live engine disagree about %s:\n  %s",
					rec.CaseID, strings.Join(diffs, "\n  "))
			}

			// And a second replay of the same record, because determinism is
			// the claim and one evaluation cannot show it. The decision id is
			// derived from the request binding, so a non-deterministic
			// evaluator would move it.
			again, err := replay.Replay(context.Background(), env, rec)
			if err != nil {
				t.Fatalf("replaying %s a second time: %v", rec.CaseID, err)
			}
			if diffs := replay.Diff(res.Decision, again.Decision); len(diffs) != 0 {
				t.Fatalf("two replays of one record disagree about %s:\n  %s", rec.CaseID, strings.Join(diffs, "\n  "))
			}
		})
	}
}

// TestTheSampledPopulationSpansTheDecisionSurface is the anti-vacuity floor
// under every other case in this file.
//
// A fixture whose samples all produced DENY would be reproduced perfectly by a
// tool that always returned DENY, and every assertion in
// TestReplayReproducesEveryLiveDecision would still pass. The floor is on the
// OUTCOMES the samples actually produce, derived from the committed records
// rather than from a list restated here, and it requires a non-restrictive
// decision to be among them - a spread of restrictive states is not a spread.
func TestTheSampledPopulationSpansTheDecisionSurface(t *testing.T) {
	_, recs := loadFixture(t)

	states := map[contract.OperationalState]int{}
	reasons := map[contract.ReasonCode]int{}
	for _, rec := range recs {
		if rec.Expected == nil {
			t.Fatalf("sample %q records no decision and cannot contribute to the spread", rec.CaseID)
		}
		states[rec.Expected.State]++
		reasons[rec.Expected.Reason]++
	}
	t.Logf("sampled population: %d record(s), states %v, reasons %v", len(recs), states, reasons)

	if len(states) < 3 {
		t.Errorf("the samples span %d operational state(s) %v; a replay tool returning a constant would reproduce them all", len(states), states)
	}
	if len(reasons) < 3 {
		t.Errorf("the samples span %d reason code(s) %v; gate 16 is about reproducing safe REASON CODES as well as states", len(reasons), reasons)
	}
	if states[contract.StateAllow] == 0 {
		t.Errorf("no sample is ALLOW; a population of refusals cannot show that reproduction depends on the policy set")
	}
}

// TestAChangedInputChangesTheDecision is the negative half.
//
// The matched pair differs in exactly one attribute. The assertion is in two
// parts because either half alone is satisfiable by something wrong: that the
// requests differ ONLY in args.amount_cents (so the difference in outcome is
// attributable), and that the decisions differ (so the tool is reading the
// input at all).
func TestAChangedInputChangesTheDecision(t *testing.T) {
	env, recs := loadFixture(t)
	low := recordByID(t, recs, "spend-below-threshold")
	high := recordByID(t, recs, "spend-above-threshold")

	differing := attributeDifferences(t, low.Request, high.Request)
	if len(differing) != 1 || differing[0] != conformance.PathArgsAmount {
		t.Fatalf("the matched pair differs in %v, want exactly [%s]; a pair differing in more than one field cannot attribute the outcome to the change",
			differing, conformance.PathArgsAmount)
	}

	lowRes, err := replay.Replay(context.Background(), env, low)
	if err != nil {
		t.Fatalf("replaying the low arm: %v", err)
	}
	highRes, err := replay.Replay(context.Background(), env, high)
	if err != nil {
		t.Fatalf("replaying the high arm: %v", err)
	}
	if !lowRes.Verified || !highRes.Verified {
		t.Fatalf("an arm of the matched pair did not reproduce its recorded decision: low=%v high=%v",
			lowRes.Differences, highRes.Differences)
	}

	if diffs := replay.Diff(lowRes.Decision, highRes.Decision); len(diffs) == 0 {
		t.Fatalf("the two arms produced identical decisions (%s/%s); the replay is not a function of its input",
			lowRes.Decision.State, lowRes.Decision.Reason)
	}
	if lowRes.Decision.State == highRes.Decision.State {
		t.Errorf("both arms are %s; the amount crossed the C1 approval threshold and the operational state did not move",
			lowRes.Decision.State)
	}
	if lowRes.Decision.DecisionID == highRes.Decision.DecisionID {
		t.Error("the two arms share a decision id; the identifier is not bound to the input it was derived from")
	}
	t.Logf("low arm %s/%s, high arm %s/%s",
		lowRes.Decision.State, lowRes.Decision.Reason, highRes.Decision.State, highRes.Decision.Reason)

	// THE DECISION MUST COME FROM EVALUATING THE REQUEST, AND NOTHING ABOVE
	// SHOWS THAT.
	//
	// R3 round 1 found it: a Replay that returned `rec.Expected` instead of
	// what the engine produced survives every assertion above, because each
	// record carries its OWN expectation - so the echoing implementation hands
	// back two different decisions, marks both verified, and satisfies the
	// pair. Only the command's exit-3 test caught it, in a different package.
	//
	// The two legs below close it from inside this one, and each closes a
	// different half.

	// Leg 1: HIGH's request carrying LOW's expectation. An implementation that
	// reads the request reports a difference; one that echoes the record
	// reports Verified.
	swapped := cloneRecord(t, high)
	swapped.CaseID = "spend-above-threshold-carrying-the-low-arms-expectation"
	swapped.Expected = cloneRecord(t, low).Expected
	swappedRes, err := replay.Replay(context.Background(), env, swapped)
	if err != nil {
		t.Fatalf("replaying the swapped-expectation record: %v", err)
	}
	if swappedRes.Verified {
		t.Fatalf("a record pairing the HIGH arm's request with the LOW arm's expectation verified; "+
			"the reported decision is the record's own expectation echoed back, not the result of evaluating the request (%s/%s)",
			swappedRes.Decision.State, swappedRes.Decision.Reason)
	}
	named := false
	for _, d := range swappedRes.Differences {
		if strings.HasPrefix(d, "state:") {
			named = true
		}
	}
	if !named {
		t.Errorf("the mismatch does not name the operational state that moved: %v", swappedRes.Differences)
	}
	if diffs := replay.Diff(highRes.Decision, swappedRes.Decision); len(diffs) != 0 {
		t.Errorf("the swapped record produced a different decision from the same request:\n  %s", strings.Join(diffs, "\n  "))
	}

	// Leg 2: HIGH's request carrying NO expectation at all. There is nothing
	// to echo, and the decision must still be the one the request produces.
	// This is the half leg 1 cannot reach: an implementation that echoed the
	// expectation only when one was present would pass leg 1's inequality.
	bare := cloneRecord(t, high)
	bare.CaseID = "spend-above-threshold-with-no-expectation"
	bare.Expected = nil
	bareRes, err := replay.Replay(context.Background(), env, bare)
	if err != nil {
		t.Fatalf("replaying the expectation-free record: %v", err)
	}
	if bareRes.Verified {
		t.Error("a record carrying no expectation was reported as verified")
	}
	if diffs := replay.Diff(highRes.Decision, bareRes.Decision); len(diffs) != 0 {
		t.Errorf("a record carrying no expectation produced a different decision from the same request:\n  %s",
			strings.Join(diffs, "\n  "))
	}
}

// attributeDifferences names every attribute path on which two requests
// disagree, across the shared surface and every actor-chain hop.
func attributeDifferences(t *testing.T, a, b *contract.Request) []string {
	t.Helper()
	var out []string
	seen := map[string]bool{}
	consider := func(path string, x, y contract.Attribute, ok1, ok2 bool) {
		if seen[path] {
			return
		}
		if ok1 != ok2 {
			seen[path] = true
			out = append(out, path)
			return
		}
		dx, err1 := contract.ExactDigest(x)
		dy, err2 := contract.ExactDigest(y)
		if err1 != nil || err2 != nil {
			t.Fatalf("digesting attribute %s: %v / %v", path, err1, err2)
		}
		if dx != dy {
			seen[path] = true
			out = append(out, path)
		}
	}
	for path, x := range a.Attributes {
		y, ok := b.Attributes[path]
		consider(path, x, y, true, ok)
	}
	for path, y := range b.Attributes {
		x, ok := a.Attributes[path]
		consider(path, x, y, ok, true)
	}
	if len(a.Context.ActorChain) != len(b.Context.ActorChain) {
		out = append(out, "context.actor_chain")
		return out
	}
	for i := range a.Context.ActorChain {
		for path, x := range a.Context.ActorChain[i].Attributes {
			y, ok := b.Context.ActorChain[i].Attributes[path]
			consider(path, x, y, true, ok)
		}
	}
	return out
}

// TestAMismatchedBundlePinRefusesRatherThanFallingBack is the third case.
//
// Three mismatch shapes, because they fail differently and an operator needs
// to be told which one happened:
//
//	a bundle digest that names a different policy set;
//	a root the environment does not hold at all;
//	an environment root the record never pinned - the direction that would
//	otherwise pass silently, because everything the record names IS present.
//
// In every shape the assertion is that NO decision comes back. A replay tool
// that returned a decision alongside a warning would put an authoritative
// looking answer to a different question in front of someone in an incident.
func TestAMismatchedBundlePinRefusesRatherThanFallingBack(t *testing.T) {
	env, recs := loadFixture(t)
	base := recordByID(t, recs, "spend-above-threshold")

	// The control: unmodified, the same record replays.
	if _, err := replay.Replay(context.Background(), env, base); err != nil {
		t.Fatalf("the unmodified record does not replay, so every refusal below could be for the wrong reason: %v", err)
	}

	rows := []struct {
		name    string
		mutate  func(*replay.Record)
		wantMsg string
	}{
		{
			name: "a bundle digest naming a different policy set",
			mutate: func(r *replay.Record) {
				r.BundlePins[0].Digest = "sha256:" + strings.Repeat("0", 64)
			},
			wantMsg: "the record pins bundle",
		},
		{
			name: "a pinned root the environment does not hold",
			mutate: func(r *replay.Record) {
				r.BundlePins = append(r.BundlePins, replay.Pin{Root: "third-party", Digest: "sha256:" + strings.Repeat("1", 64)})
			},
			wantMsg: "holds no bundle for that root",
		},
		{
			name: "an environment root the record does not pin",
			mutate: func(r *replay.Record) {
				r.BundlePins = r.BundlePins[:1]
			},
			wantMsg: "which the record does not pin",
		},
		{
			name: "an environment digest from a different environment",
			mutate: func(r *replay.Record) {
				r.EnvironmentDigest = "sha256:" + strings.Repeat("2", 64)
			},
			wantMsg: "and this environment digests to",
		},
	}

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			rec := cloneRecord(t, base)
			row.mutate(rec)

			res, err := replay.Replay(context.Background(), env, rec)
			if err == nil {
				t.Fatalf("the mismatch was accepted and a %s decision was returned", res.Decision.State)
			}
			if res != nil {
				t.Fatalf("a decision was returned alongside the refusal: %+v", res)
			}
			var pinErr *replay.PinError
			if !asPinError(err, &pinErr) {
				t.Fatalf("the refusal is not a pin refusal: %v", err)
			}
			if !strings.Contains(err.Error(), row.wantMsg) {
				t.Errorf("the refusal does not name the mismatch (%q):\n%v", row.wantMsg, err)
			}
		})
	}
}

// TestAnEnvironmentChangeAloneChangesTheDecision is why the environment is
// pinned separately from the bundles.
//
// The bundles are untouched and byte-identical; only the enforcement profile
// changes, to one that advertises no capabilities. ADR-065 invariant 8 makes
// that a DENY for a decision carrying a mandatory obligation. A tool that
// pinned only bundle digests would have replayed this happily and reported a
// decision the sample never made.
func TestAnEnvironmentChangeAloneChangesTheDecision(t *testing.T) {
	env, recs := loadFixture(t)
	rec := recordByID(t, recs, "spend-above-threshold")

	if _, err := replay.Replay(context.Background(), env, rec); err != nil {
		t.Fatalf("the unmodified record does not replay: %v", err)
	}

	// Same bundles, deaf enforcement point.
	weakened := cloneEnvironment(t, env)
	weakened.PEP = &contract.PEPProfile{ID: "deaf-pep"}

	before, _ := env.BundleDigests(), 0
	after := weakened.BundleDigests()
	if len(before) != len(after) {
		t.Fatalf("the clone changed the bundle set")
	}
	for i := range before {
		if before[i] != after[i] {
			t.Fatalf("the clone changed bundle %s; the case must vary the environment ALONE", before[i].Root)
		}
	}

	if _, err := replay.Replay(context.Background(), weakened, rec); err == nil {
		t.Fatal("a record was replayed against an environment whose enforcement profile it was not taken against")
	}

	// The refusal is not the whole point: the reason the pin matters is that
	// the decision genuinely differs. Replayed against a record re-pinned to
	// the weakened environment, the outcome moves - which is what an
	// unpinned-environment tool would have reported as the original decision.
	repinned := cloneRecord(t, rec)
	d, err := weakened.Digest()
	if err != nil {
		t.Fatalf("digesting the weakened environment: %v", err)
	}
	repinned.EnvironmentDigest = d
	repinned.Expected = nil
	got, err := replay.Replay(context.Background(), weakened, repinned)
	if err != nil {
		t.Fatalf("replaying against the weakened environment: %v", err)
	}
	if got.Verified {
		t.Fatal("a record carrying no expectation was reported as verified")
	}
	if got.Decision.State == rec.Expected.State && got.Decision.Reason == rec.Expected.Reason {
		t.Fatalf("removing every enforcement capability left the decision at %s/%s; "+
			"the environment pin would then be guarding something that does not affect the outcome",
			got.Decision.State, got.Decision.Reason)
	}
	t.Logf("pinned environment: %s/%s; deaf enforcement point: %s/%s",
		rec.Expected.State, rec.Expected.Reason, got.Decision.State, got.Decision.Reason)
}

// TestTheDocumentsSurviveTheirRoundTrip is the artifact's own soundness.
//
// The engine binds each source document to the bundle it accompanies by
// digest, and refuses when they disagree. That check runs over the document as
// DECODED FROM JSON, so the whole tool rests on the encoding being lossless for
// the authoring types - a number literal that came back as a float, or an
// optional field that vanished, would either break activation loudly or, worse,
// re-digest to the same value while compiling to something else.
func TestTheDocumentsSurviveTheirRoundTrip(t *testing.T) {
	env, _ := loadFixture(t)
	if len(env.Roots) == 0 {
		t.Fatal("the environment carries no roots")
	}
	live := map[pdp.Root]*pdp.Document{
		pdp.RootSystem:       conformance.SystemDocument(),
		pdp.RootOrganization: conformance.OrganizationDocument(),
	}
	for _, r := range env.Roots {
		want, ok := live[r.Root]
		if !ok {
			t.Fatalf("the environment carries root %q, which the conformance corpus does not define", r.Root)
		}
		wantDigest, err := contract.ExactDigest(want)
		if err != nil {
			t.Fatalf("digesting the live %s document: %v", r.Root, err)
		}
		gotDigest, err := contract.ExactDigest(r.Document)
		if err != nil {
			t.Fatalf("digesting the decoded %s document: %v", r.Root, err)
		}
		if gotDigest != wantDigest {
			t.Errorf("the %s document does not survive the JSON round trip: decoded %s, live %s", r.Root, gotDigest, wantDigest)
		}
		if r.Bundle.Provenance.SourceDigest != wantDigest {
			t.Errorf("the %s bundle was compiled from %s and the document digests to %s",
				r.Root, r.Bundle.Provenance.SourceDigest, wantDigest)
		}
	}
}

func cloneRecord(t *testing.T, in *replay.Record) *replay.Record {
	t.Helper()
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("cloning a record: %v", err)
	}
	var out replay.Record
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("cloning a record: %v", err)
	}
	return &out
}

func cloneEnvironment(t *testing.T, in *replay.Environment) *replay.Environment {
	t.Helper()
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("cloning an environment: %v", err)
	}
	var out replay.Environment
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("cloning an environment: %v", err)
	}
	return &out
}

func asPinError(err error, target **replay.PinError) bool {
	for err != nil {
		if pe, ok := err.(*replay.PinError); ok {
			*target = pe
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
