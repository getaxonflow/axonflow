// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package planeshadow

import (
	"bytes"
	"context"
	"errors"
	"log"
	"strings"
	"testing"

	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/shared/identity"
)

// fixtureOrgPlanes answers a recorded plane narrowing per organization, as the
// RAW string the column stores. An org absent from the map has no record, which
// is the ordinary state.
type fixtureOrgPlanes struct {
	raw map[string]string
	err error
	// calls counts reads, so a test can assert a lookup did NOT happen. It is
	// not guarded: every test here drives Observe from one goroutine.
	calls int
}

func (f *fixtureOrgPlanes) OrgDecisionShadowPlanes(_ context.Context, orgID string) (string, bool, error) {
	f.calls++
	if f.err != nil {
		return "", false, f.err
	}
	raw, ok := f.raw[orgID]
	if !ok {
		return "", false, nil
	}
	return raw, true, nil
}

// twoPlanes returns two distinct implemented planes, failing the test if the
// deployment model cannot supply them.
//
// Derived rather than hard-coded: a test naming `mcp` and `wcp` would go
// quietly vacuous the day one is renamed, and every assertion below is about
// telling one plane from another rather than about which two they are.
func twoPlanes(t *testing.T) (kept, dropped legacycompile.Plane) {
	t.Helper()
	planes := ImplementedPlanes()
	if len(planes) < 2 {
		t.Fatalf("this test needs two implemented planes to tell a narrowing from a disabling; got %d", len(planes))
	}
	return planes[0], planes[1]
}

// observationOn is a valid observation for one plane and one organization.
func observationOn(p legacycompile.Plane, orgID string) Observation {
	obs := fixtureObservation(true, false)
	obs.Plane = p
	obs.OrgID = orgID
	obs.OrgScope = orgID
	return obs
}

// TestPerOrganizationPlanesNarrowOneOrganizationAndNotTheOthers is the whole
// feature in one test, and it is TWO-SIDED on both axes.
//
// A narrowing that dropped the plane for everyone would satisfy a check on the
// narrowed organization alone; a narrowing that did nothing would satisfy a
// check on the other organization alone. So one process observes two
// organizations on two planes, and exactly three of the four combinations must
// produce a comparison.
func TestPerOrganizationPlanesNarrowOneOrganizationAndNotTheOthers(t *testing.T) {
	kept, dropped := twoPlanes(t)
	rec := newCapturingRecorder(3)
	o, _ := newFixtureObserver(t, fixtureConfig(identity.CompatModeShadow), rec,
		WithOrgPlanes(&fixtureOrgPlanes{raw: map[string]string{
			fixtureOrg: string(kept),
		}}))

	o.Observe(context.Background(), observationOn(kept, fixtureOrg))         // recorded
	o.Observe(context.Background(), observationOn(dropped, fixtureOrg))      // NARROWED AWAY
	o.Observe(context.Background(), observationOn(kept, fixtureOtherOrg))    // recorded: no record
	o.Observe(context.Background(), observationOn(dropped, fixtureOtherOrg)) // recorded: no record

	got := rec.wait(t)
	if len(got) != 3 {
		t.Fatalf("recorded %d comparison(s), want exactly 3 of 4: the narrowed organization's "+
			"dropped plane is the only combination that must not be measured. Got: %+v", len(got), planesOf(got))
	}
	for _, c := range got {
		if c.OrgID == fixtureOrg && c.Plane == dropped {
			t.Errorf("the narrowed organization was measured on %q, which its record omits", dropped)
		}
	}
	// The positive half, stated separately so "3 comparisons" cannot be
	// satisfied by three of the wrong ones.
	if !hasPlaneOrg(got, dropped, fixtureOtherOrg) {
		t.Errorf("the organization with NO record was not measured on %q; one organization's narrowing "+
			"has narrowed the deployment. Got: %+v", dropped, planesOf(got))
	}
	if !hasPlaneOrg(got, kept, fixtureOrg) {
		t.Errorf("the narrowed organization was not measured on %q, which its record NAMES; the lever "+
			"must narrow the set, not disable the organization. Got: %+v", kept, planesOf(got))
	}
}

// TestPerOrganizationPlanesCanOnlyNarrowNeverWiden pins the one place this
// axis's composition rule differs from the mode's, and the difference is the
// whole safety argument.
//
// The MODE wins in both directions: a record raises one organization to shadow
// on an off deployment, which is how a staged rollout starts. A PLANE LIST must
// not, because a deployment withdraws a plane for reasons that belong to the
// deployment - its worker pool cannot afford that plane's compilations, that
// plane's comparisons are known-bad on this build - and a per-tenant row that
// re-enabled it would let one tenant's settings spend the deployment's money
// and reopen a plane the operator switched off.
func TestPerOrganizationPlanesCanOnlyNarrowNeverWiden(t *testing.T) {
	kept, withdrawn := twoPlanes(t)
	cfg := fixtureConfig(identity.CompatModeShadow)
	// The DEPLOYMENT withdrew one plane.
	cfg.Planes = map[legacycompile.Plane]bool{kept: true}

	src := &fixtureOrgPlanes{raw: map[string]string{
		// The organization's record names BOTH, including the withdrawn one.
		fixtureOrg: string(kept) + "," + string(withdrawn),
	}}
	rec := newCapturingRecorder(1)
	o, _ := newFixtureObserver(t, cfg, rec, WithOrgPlanes(src))

	o.Observe(context.Background(), observationOn(withdrawn, fixtureOrg))
	o.Observe(context.Background(), observationOn(kept, fixtureOrg))

	got := rec.wait(t)
	if len(got) != 1 || got[0].Plane != kept {
		t.Fatalf("recorded %+v, want exactly one comparison on %q. An organization's record naming a "+
			"plane the DEPLOYMENT withdrew must not re-enable it: the resolved set is the "+
			"intersection, not a replacement.", planesOf(got), kept)
	}
	// AND THE READ WAS NEVER MADE for the withdrawn plane. The verdict alone
	// would be identical if the record were read and then intersected, but
	// every observation on a withdrawn plane would pay a settings lookup for a
	// question already answered.
	if src.calls != 1 {
		t.Errorf("the per-organization record was read %d time(s) across two observations; the "+
			"deployment's refusal is final, so the observation on the withdrawn plane must not "+
			"reach the store at all", src.calls)
	}
}

// TestAnAbsentPlaneRecordLeavesTheDeploymentListInCharge is the ordinary state,
// and it is asserted in BOTH directions because a source that answered
// found=false for everything would otherwise be indistinguishable from one
// answering "no planes".
func TestAnAbsentPlaneRecordLeavesTheDeploymentListInCharge(t *testing.T) {
	inList, outOfList := twoPlanes(t)
	cfg := fixtureConfig(identity.CompatModeShadow)
	cfg.Planes = map[legacycompile.Plane]bool{inList: true}

	rec := newCapturingRecorder(1)
	o, _ := newFixtureObserver(t, cfg, rec, WithOrgPlanes(&fixtureOrgPlanes{raw: map[string]string{}}))

	o.Observe(context.Background(), observationOn(inList, fixtureOrg))
	o.Observe(context.Background(), observationOn(outOfList, fixtureOrg))

	got := rec.wait(t)
	if len(got) != 1 || got[0].Plane != inList {
		t.Fatalf("recorded %+v, want exactly one comparison on %q: with no record the deployment's "+
			"list decides, in both directions", planesOf(got), inList)
	}
}

// TestAnUnreadablePlaneRecordFallsBackToTheDeploymentList pins the direction of
// the fall-back, which is the opposite of the intuitive one.
//
// Falling back to "no planes" would look safer and is wrong. The value is
// refused at the write path and by the column's CHECK, so the ways to reach
// here are a restore from backup, a hand-written row, or a plane removed from
// the vocabulary by a later build - and in every one of those, an organization's
// window closing silently is worse than it staying open, because a closed
// window is invisible in the evidence and an operator reads an empty series as
// agreement.
func TestAnUnreadablePlaneRecordFallsBackToTheDeploymentList(t *testing.T) {
	kept, other := twoPlanes(t)

	for name, src := range map[string]*fixtureOrgPlanes{
		"the read failed":            {err: errors.New("settings store unavailable")},
		"the stored value is a typo": {raw: map[string]string{fixtureOrg: "gatewayrequest"}},
		"the stored value names nothing": {raw: map[string]string{
			// ParsePlanes refuses a list that names nothing, which is the
			// shape an unexpanded variable produces.
			fixtureOrg: ",",
		}},
	} {
		t.Run(name, func(t *testing.T) {
			rec := newCapturingRecorder(2)
			o, _ := newFixtureObserver(t, fixtureConfig(identity.CompatModeShadow), rec, WithOrgPlanes(src))
			before := o.OrgPlanesFailures()

			o.Observe(context.Background(), observationOn(kept, fixtureOrg))
			o.Observe(context.Background(), observationOn(other, fixtureOrg))

			got := rec.wait(t)
			if len(got) != 2 {
				t.Fatalf("recorded %d comparison(s), want 2: an unusable record must leave the "+
					"deployment's list in charge, not close the organization's window", len(got))
			}
			if o.OrgPlanesFailures() <= before {
				t.Errorf("the fall-back was not COUNTED (%d -> %d). A silent fall-back is a "+
					"deployment measuring more planes for an organization than its record asks "+
					"for, with nothing anywhere saying so", before, o.OrgPlanesFailures())
			}
		})
	}
}

// TestNoPlaneSourceMeansTheDeploymentListDecides is the community build and
// every deployment with no settings store.
func TestNoPlaneSourceMeansTheDeploymentListDecides(t *testing.T) {
	kept, dropped := twoPlanes(t)
	cfg := fixtureConfig(identity.CompatModeShadow)
	cfg.Planes = map[legacycompile.Plane]bool{kept: true}

	rec := newCapturingRecorder(1)
	o, _ := newFixtureObserver(t, cfg, rec)
	if o.HasPerOrgPlanes() {
		t.Fatal("HasPerOrgPlanes() is true with no source wired")
	}

	o.Observe(context.Background(), observationOn(dropped, fixtureOrg))
	o.Observe(context.Background(), observationOn(kept, fixtureOrg))

	got := rec.wait(t)
	if len(got) != 1 || got[0].Plane != kept {
		t.Fatalf("recorded %+v, want one comparison on %q", planesOf(got), kept)
	}
}

// TestAnObservationWithNoOrgIDDoesNotReachThePlaneStore.
//
// A plane with no organization - and no OrgScope, so the earlier refusal does
// not fire - resolves against the deployment's list. Asking the store "what did
// organization ” record" is a question with no answer that would cost a lookup
// per observation on every plane that has no tenant.
//
// The observable is the STORE CALL, not a recorded comparison: the fixture row
// source has policy rows for the fixture organization only, so an observation
// with no organization produces no comparison for reasons that have nothing to
// do with this lever. A control drives the same probe WITH an organization and
// requires the call to happen, so a zero above cannot be a fixture that never
// reached the resolver at all.
func TestAnObservationWithNoOrgIDDoesNotReachThePlaneStore(t *testing.T) {
	kept, _ := twoPlanes(t)
	src := &fixtureOrgPlanes{raw: map[string]string{}}
	o, _ := newFixtureObserver(t, fixtureConfig(identity.CompatModeShadow), newCapturingRecorder(0), WithOrgPlanes(src))

	obs := observationOn(kept, "")
	obs.OrgScope = ""
	o.Observe(context.Background(), obs)
	if src.calls != 0 {
		t.Errorf("the plane store was read %d time(s) for an observation with no org id", src.calls)
	}

	o.Observe(context.Background(), observationOn(kept, fixtureOrg))
	if src.calls != 1 {
		t.Errorf("the CONTROL observation, with an organization, read the store %d time(s), want 1; "+
			"the zero above is then evidence about this fixture rather than about the empty org id", src.calls)
	}
}

// TestPlaneSetCacheParsesOnceAndCachesBothOutcomes.
//
// The resolution is on the request path, so a re-parse per observation would be
// a string split and a map allocation per governed request. Both outcomes are
// cached, and the failure case is the one worth pinning: caching only successes
// would re-parse and RE-LOG every malformed value at request rate, landing the
// extra work on the organization that is already misconfigured.
func TestPlaneSetCacheParsesOnceAndCachesBothOutcomes(t *testing.T) {
	kept, _ := twoPlanes(t)
	c := newPlaneSetCache()

	first, why := c.get(string(kept))
	if why != "" {
		t.Fatalf("a valid list was refused: %s", why)
	}
	second, _ := c.get(string(kept))
	if len(first) == 0 || len(second) == 0 {
		t.Fatal("the parsed set is empty; this test would prove nothing about caching")
	}
	// THE CACHE SIZE IS THE OBSERVABLE, not map identity: two gets of one value
	// must leave exactly one entry, which is false for a cache that stores per
	// call and false for one that stores nothing.
	if len(c.parsed) != 1 {
		t.Errorf("the cache holds %d parsed entries after two gets of one value, want 1", len(c.parsed))
	}

	if _, why := c.get("not_a_plane"); why == "" {
		t.Fatal("a value naming no declared plane was accepted")
	}
	if _, why := c.get("not_a_plane"); why == "" {
		t.Fatal("the second get of a bad value was accepted; the failure was not cached, and the two " +
			"answers to one question disagree")
	}
	if len(c.failed) != 1 {
		t.Errorf("the cache holds %d failed entries after two gets of one bad value, want 1", len(c.failed))
	}
	if len(c.parsed) != 1 {
		t.Errorf("a failed parse was stored as a success (%d parsed entries, want 1)", len(c.parsed))
	}
}

// TestTheOrgPlanesFailureCounterIsSeparateFromTheModeCounter.
//
// The two failures move a window in OPPOSITE directions: a failed MODE read
// drops an organization out of the window entirely, while a failed PLANE read
// leaves it measuring more planes than its record asks for. One counter for
// both would make them indistinguishable on the dashboard where the difference
// decides what an operator does next.
func TestTheOrgPlanesFailureCounterIsSeparateFromTheModeCounter(t *testing.T) {
	kept, _ := twoPlanes(t)
	rec := newCapturingRecorder(1)
	o, _ := newFixtureObserver(t, fixtureConfig(identity.CompatModeShadow), rec,
		WithOrgModes(fixtureOrgModes{modes: map[string]identity.CompatMode{fixtureOrg: identity.CompatModeShadow}}),
		WithOrgPlanes(&fixtureOrgPlanes{err: errors.New("settings store unavailable")}))

	o.Observe(context.Background(), observationOn(kept, fixtureOrg))
	rec.wait(t)

	if o.OrgPlanesFailures() == 0 {
		t.Error("a failed plane read did not move OrgPlanesFailures")
	}
	if o.OrgModeFailures() != 0 {
		t.Errorf("a failed PLANE read moved OrgModeFailures to %d; the two failures are opposite "+
			"and an operator reading one series could not tell which happened", o.OrgModeFailures())
	}
}

// planesOf and hasPlaneOrg keep the failure messages readable: a %+v of a
// Comparison slice is unreadable at four entries.
func planesOf(cs []Comparison) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.OrgID+"/"+string(c.Plane))
	}
	return out
}

func hasPlaneOrg(cs []Comparison, plane legacycompile.Plane, org string) bool {
	for _, c := range cs {
		if c.Plane == plane && c.OrgID == org {
			return true
		}
	}
	return false
}

// TestObservesForOrgIsTheOnlyPlaneScopeDecision is the census: Config.Observes
// answers the DEPLOYMENT's half, and a call site that asked it directly would
// honour the deployment's list and ignore the organization's - a narrowing
// applied on some planes and not others, which is indistinguishable from a
// clean window.
func TestObservesForOrgIsTheOnlyPlaneScopeDecision(t *testing.T) {
	sources := packageSources(t)
	if len(sources) == 0 {
		t.Fatal("the census read no sources; the walk, not the code, is broken")
	}
	found := 0
	for name, body := range sources {
		for _, line := range strings.Split(string(body), "\n") {
			if !strings.Contains(line, "cfg.Observes(") && !strings.Contains(line, "o.cfg.Observes(") {
				continue
			}
			found++
			if name != "org_planes.go" {
				t.Errorf("%s reads the deployment plane list directly:\n\t%s\n\n"+
					"observesForOrg is the one place the deployment's list and the organization's "+
					"record are composed. A second reader honours one and ignores the other, and "+
					"a narrowing that applies on some planes and not others cannot be told from a "+
					"clean window.", name, strings.TrimSpace(line))
			}
		}
	}
	if found == 0 {
		t.Fatal("no reader of the deployment plane list was found at all; the census is matching " +
			"nothing and would pass after observesForOrg was deleted")
	}
}

// TestTheParseFailureNamesTheRecordNotTheDeploymentVariable pins a DIAGNOSTIC,
// because this one was wrong in the first draft and the wrongness is the
// expensive kind: it sends an operator to inspect a healthy deployment
// variable.
//
// ParsePlanes names AXONFLOW_DECISION_SHADOW_PLANES in every message it writes,
// which is right for its other caller. Reached from a per-organization record,
// that sentence describes a variable that is fine while the row is what needs
// fixing - and the fix is an admin write, not a redeploy.
func TestTheParseFailureNamesTheRecordNotTheDeploymentVariable(t *testing.T) {
	line := describeParseFailure("acme", "gatewayrequest", "planeshadow: "+EnvPlanes+" names plane \"gatewayrequest\"")
	for _, want := range []string{
		"recorded for this organization",
		"acme",
		"gatewayrequest",
		"identity settings surface",
	} {
		if !strings.Contains(line, want) {
			t.Errorf("the per-organization parse failure does not mention %q, so a reader cannot tell "+
				"which of the two sources of a plane list is at fault:\n%s", want, line)
		}
	}
	// AND it must still carry the parser's own text: dropping it would leave
	// the operator knowing the row is wrong and not knowing which name is.
	if !strings.Contains(line, EnvPlanes) {
		t.Errorf("the parser's own message was dropped, so the offending plane name never reaches "+
			"the log:\n%s", line)
	}
}

// TestAFallBackReAdmitsTheVERYPlaneTheRecordExcluded is the consequence of the
// fallback direction, pinned as its own claim.
//
// An organization narrows specifically to exclude a plane that diverges. The
// stored value later becomes unparseable - a restore, a hand-written row, a
// plane withdrawn from the vocabulary. The deployment fallback then RE-ADMITS
// the excluded plane and its divergences reappear.
//
// That is the intended, loud outcome and not a regression, so it is asserted
// rather than left to be discovered: the alternative fallback would have hidden
// exactly the plane an operator was watching, in the one state where they had
// already said they knew it was noisy.
//
// It cannot silently unlock anything. This axis has no enforcement before v11,
// and the identity axis's enforce precondition reads a different metric family
// (identity.compatOrgComparisons and compatOrgDivergences, written by the
// identity adapter's recorder), so no reading on this path reaches it.
func TestAFallBackReAdmitsTheVERYPlaneTheRecordExcluded(t *testing.T) {
	kept, excluded := twoPlanes(t)

	// FIRST: a well-formed record that excludes the noisy plane. Its exclusion
	// is asserted, so the re-admission below is a CHANGE rather than a state
	// that was always true.
	good := &fixtureOrgPlanes{raw: map[string]string{fixtureOrg: string(kept)}}
	rec := newCapturingRecorder(1)
	o, _ := newFixtureObserver(t, fixtureConfig(identity.CompatModeShadow), rec, WithOrgPlanes(good))
	o.Observe(context.Background(), observationOn(excluded, fixtureOrg))
	o.Observe(context.Background(), observationOn(kept, fixtureOrg))
	got := rec.wait(t)
	if len(got) != 1 || got[0].Plane != kept {
		t.Fatalf("with a well-formed narrowing the excluded plane was measured (%+v); this test's premise "+
			"is that it was excluded first", planesOf(got))
	}

	// THEN: the same organization, same deployment, with the stored value now
	// unusable.
	broken := &fixtureOrgPlanes{raw: map[string]string{fixtureOrg: "a_plane_this_build_does_not_know"}}
	rec2 := newCapturingRecorder(1)
	o2, _ := newFixtureObserver(t, fixtureConfig(identity.CompatModeShadow), rec2, WithOrgPlanes(broken))
	o2.Observe(context.Background(), observationOn(excluded, fixtureOrg))
	got2 := rec2.wait(t)
	if len(got2) != 1 || got2[0].Plane != excluded {
		t.Fatalf("the excluded plane was NOT re-admitted after the record became unusable (%+v). The "+
			"deployment fallback is what re-admits it, and the loud direction is the whole reason that "+
			"fallback was chosen over falling back to no planes.", planesOf(got2))
	}
	if o2.OrgPlanesFailures() == 0 {
		t.Error("the plane came back with no failure counted, so an operator seeing its divergences reappear " +
			"has nothing telling them the record stopped being honoured - which is the half that makes " +
			"over-measuring the safe direction")
	}
}

// TestAnOrganizationThatIsNotRecordingNeverReadsThePlaneNarrowing is the READER
// half of the mode/planes coupling, and it exists because the property is
// currently true only by STATEMENT ORDER.
//
// Observe resolves the effective mode and returns when it does not record,
// before it reaches observesForOrg. Nothing but the order of two statements
// enforces that, and both are edits somebody will make. The consequence of the
// wrong order is not a wrong verdict - it is a settings lookup, and possibly a
// counted fall-back, charged to every request of every organization that is not
// in the window at all: on the documented rollout shape (process off, one
// organization shadowing) that is 99% of traffic.
//
// The customer-portal's TestIdentityOrgSettingsPutRefusesPlanesBesideAnOffMode
// is the writer half. The two are pinned as AGREEING: the API refuses to store
// a narrowing beside an off mode, and the reader never consults one for an
// organization that is not recording. A future edit that moves either alone
// breaks a test.
func TestAnOrganizationThatIsNotRecordingNeverReadsThePlaneNarrowing(t *testing.T) {
	kept, _ := twoPlanes(t)
	src := &fixtureOrgPlanes{raw: map[string]string{fixtureOrg: string(kept)}}

	// The deployment is OFF and the organization has no mode record, so nothing
	// about this organization records.
	o, _ := newFixtureObserver(t, fixtureConfig(identity.CompatModeOff), newCapturingRecorder(0),
		WithOrgModes(fixtureOrgModes{modes: map[string]identity.CompatMode{}}),
		WithOrgPlanes(src))

	o.Observe(context.Background(), observationOn(kept, fixtureOrg))
	if src.calls != 0 {
		t.Errorf("a non-recording organization consulted the plane narrowing %d time(s). The mode decides "+
			"whether anything is observed at all, so the narrowing is not a question worth asking - and asking "+
			"it charges a settings lookup to every request of every organization outside the window.", src.calls)
	}

	// THE CONTROL, in the same test: the same probe on a RECORDING organization
	// must consult the source. Without it, a zero above is satisfied by an
	// observer that never reaches the resolver for any reason at all.
	rec := newCapturingRecorder(1)
	on, _ := newFixtureObserver(t, fixtureConfig(identity.CompatModeShadow), rec, WithOrgPlanes(src))
	on.Observe(context.Background(), observationOn(kept, fixtureOrg))
	rec.wait(t)
	if src.calls == 0 {
		t.Error("the RECORDING organization did not consult the narrowing either, so the zero above is " +
			"evidence about this fixture rather than about the mode gate")
	}
}

// TestTheFallBackCountsEveryTimeAndLogsOnce is R3 item M4, and it pins the two
// halves as DIFFERENT on purpose.
//
// Measured before the fix: ten observations for one misconfigured organization
// produced ten counter increments and ten ~400-byte log lines. The counter is a
// RATE and must move every time - an operator sizing the blast radius of a bad
// row needs to know whether it is one request an hour or every request. The log
// is a DIAGNOSIS: the second identical line adds nothing and the ten-thousandth
// costs a log budget.
//
// Both directions are asserted, because suppressing the counter as well would
// be the easy over-correction and would make the rate unreadable.
func TestTheFallBackCountsEveryTimeAndLogsOnce(t *testing.T) {
	kept, _ := twoPlanes(t)
	src := &fixtureOrgPlanes{raw: map[string]string{fixtureOrg: "a_plane_this_build_does_not_know"}}

	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	const observations = 10
	rec := newCapturingRecorder(observations)
	o, _ := newFixtureObserver(t, fixtureConfig(identity.CompatModeShadow), rec, WithOrgPlanes(src))
	for i := 0; i < observations; i++ {
		o.Observe(context.Background(), observationOn(kept, fixtureOrg))
	}
	rec.wait(t)

	if got := o.OrgPlanesFailures(); got != observations {
		t.Errorf("the failure counter moved %d time(s) across %d observations, want %d. It is a rate: "+
			"suppressing it would leave an operator unable to tell one bad request an hour from every request",
			got, observations, observations)
	}
	if n := strings.Count(buf.String(), "per-org plane narrowing unavailable"); n != 1 {
		t.Errorf("the fall-back logged %d line(s) across %d observations, want exactly 1. The parse cache "+
			"suppresses the PARSE, not the log line - the suppression has to be at the log call, keyed on the "+
			"(organization, value) pair.\n%s", n, observations, buf.String())
	}

	// A DIFFERENT ORGANIZATION WITH THE SAME BAD VALUE LOGS AGAIN, because the
	// key is the pair. A cache keyed on the value alone would tell an operator
	// about the first tenant and silently about none of the others.
	src.raw[fixtureOtherOrg] = "a_plane_this_build_does_not_know"
	rec2 := newCapturingRecorder(1)
	o2, _ := newFixtureObserver(t, fixtureConfig(identity.CompatModeShadow), rec2, WithOrgPlanes(src))
	o2.Observe(context.Background(), observationOn(kept, fixtureOtherOrg))
	rec2.wait(t)
	if !strings.Contains(buf.String(), fixtureOtherOrg) {
		t.Errorf("a SECOND organization with the same unusable value was never logged; the suppression key "+
			"must be the (organization, value) pair, not the value.\n%s", buf.String())
	}
}
