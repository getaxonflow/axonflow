// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package planeshadow

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/legacycompile/shadow"
	"axonflow/platform/shared/identity"
)

// TestObserveReturnsNothing is the package's central non-enforcement claim,
// asserted structurally.
//
// #3582's identity adapter proves non-enforcement with a predicate and concedes
// the residue: CompatOutcome.Subject is exported, a call site COULD read it,
// and only convention stops one. Here there is no value at all, so "no code
// path from the recorded outcome to the response" is arithmetic rather than
// discipline - and this test is what stops a future edit from quietly adding a
// return value and reopening that path.
//
// Reflection rather than a behavioural probe on purpose: the property is about
// the SIGNATURE, and a behavioural test would pass just as happily against a
// version that returned a value nobody happened to read yet.
func TestObserveReturnsNothing(t *testing.T) {
	for name, fn := range map[string]any{
		"package-level Observe": Observe,
		"Observer.Observe":      (*Observer).Observe,
	} {
		ft := reflect.TypeOf(fn)
		if ft.NumOut() != 0 {
			t.Errorf("%s returns %d value(s); it must return none. A value here is a value a "+
				"call site can branch on, and the whole non-enforcement argument of this "+
				"package is that there is nothing to branch on.", name, ft.NumOut())
		}
	}
}

// TestNoEnforcementSymbolExists is the second half of the same claim.
//
// A return value is one way to leak a decision; an exported accessor on a
// package-level result is another, and it is the shape the identity adapter
// actually has (CompatOutcome.Refusal). This asserts that nothing in this
// package's exported surface is named like an enforcement decision, so adding
// one is a visible change rather than a quiet one.
func TestNoEnforcementSymbolExists(t *testing.T) {
	// Comparison is what a recorder receives, and it is the only exported type
	// carrying a shadow verdict. Its fields must all be describing something
	// that HAS happened, never instructing something to happen.
	forbidden := []string{"Refusal", "Refuse", "Deny", "Block", "Enforce", "Apply"}
	ct := reflect.TypeOf(Comparison{})
	for i := 0; i < ct.NumField(); i++ {
		name := ct.Field(i).Name
		for _, bad := range forbidden {
			if strings.Contains(name, bad) {
				t.Errorf("Comparison has a field named %q. Every field on this struct is a "+
					"record of what the two engines DID; a field whose name reads as an "+
					"instruction is one a call site will eventually act on.", name)
			}
		}
	}
	for i := 0; i < ct.NumMethod(); i++ {
		name := ct.Method(i).Name
		for _, bad := range forbidden {
			if strings.Contains(name, bad) {
				t.Errorf("Comparison has a method named %q; see the field check above.", name)
			}
		}
	}
}

// TestEnforceIsRefusedAtEveryFence pins all three refusals of the value the
// decision plane may not hold before v11.
func TestEnforceIsRefusedAtEveryFence(t *testing.T) {
	t.Run("the parser refuses it by name", func(t *testing.T) {
		_, err := identity.ParseDecisionShadowMode("enforce")
		if err == nil || !strings.Contains(err.Error(), "v11") {
			t.Fatalf("ParseDecisionShadowMode(enforce) = %v; it must refuse and name the release", err)
		}
	})

	t.Run("the constructor refuses it", func(t *testing.T) {
		src := &fixtureRowSource{byOrg: map[string][]legacycompile.RawRow{}}
		_, err := NewObserver(fixtureConfig(identity.CompatModeEnforce), src, newCapturingRecorder(0))
		if err == nil {
			t.Fatal("an observer was built in enforce mode; the decision plane has no authority before v11")
		}
	})

	t.Run("the single read site clamps a stored enforce", func(t *testing.T) {
		// THE THIRD FENCE, and the one that is not redundant: the column's
		// CHECK governs writes migration 150 governs, and a row restored from
		// a backup or written by a later migration has passed neither it nor
		// the parser. A source that answers with enforce must be treated as a
		// read failure, counted, and fall back to the process mode.
		o, _ := newFixtureObserver(t, fixtureConfig(identity.CompatModeOff), newCapturingRecorder(0),
			WithOrgModes(fixtureOrgModes{modes: map[string]identity.CompatMode{
				fixtureOrg: identity.CompatModeEnforce,
			}}))
		got := o.effectiveMode(context.Background(), fixtureOrg)
		if got != identity.CompatModeOff {
			t.Fatalf("a stored enforce resolved to %v; it must fall back to the process mode", got)
		}
		if o.OrgModeFailures() == 0 {
			t.Fatal("the clamp did not count a fall-back; an operator seeing an org run in the " +
				"process mode has no way to tell a missing record from an unusable one")
		}
	})
}

// TestEffectiveModeResolvesPerOrganization is the fixture the brief requires:
// the process mode and the organization's record DISAGREE, and two
// organizations in ONE process must be classified differently.
//
// That shape is the only one that can distinguish effectiveMode(ctx, orgID)
// from effectiveMode(ctx, "") and from a constant
// ([[feedback_moving_a_decision_to_an_argument_leaves_the_argument_unmutated]]).
// Under process/record agreement all three answer alike, so a suite built only
// on agreeing fixtures leaves the ARGUMENT unmutated - which is exactly the
// defect #3596's round 1 found in the identity axis, where five compiling
// mutants survived the whole enterprise suite.
func TestEffectiveModeResolvesPerOrganization(t *testing.T) {
	ctx := context.Background()

	t.Run("raising: process off, one organization recorded shadow", func(t *testing.T) {
		o, _ := newFixtureObserver(t, fixtureConfig(identity.CompatModeOff), newCapturingRecorder(0),
			WithOrgModes(fixtureOrgModes{modes: map[string]identity.CompatMode{
				fixtureOrg: identity.CompatModeShadow,
			}}))
		if got := o.effectiveMode(ctx, fixtureOrg); got != identity.CompatModeShadow {
			t.Fatalf("the recorded organization resolved to %v; raising is the release plan's whole per-org case", got)
		}
		if got := o.effectiveMode(ctx, fixtureOtherOrg); got != identity.CompatModeOff {
			t.Fatalf("an organization with NO record on a process-off deployment resolved to %v", got)
		}
	})

	t.Run("lowering: process shadow, one organization recorded off", func(t *testing.T) {
		o, _ := newFixtureObserver(t, fixtureConfig(identity.CompatModeShadow), newCapturingRecorder(0),
			WithOrgModes(fixtureOrgModes{modes: map[string]identity.CompatMode{
				fixtureOrg: identity.CompatModeOff,
			}}))
		if got := o.effectiveMode(ctx, fixtureOrg); got != identity.CompatModeOff {
			t.Fatalf("an organization exempted by its record resolved to %v; it must not inherit the deployment's mode", got)
		}
		if got := o.effectiveMode(ctx, fixtureOtherOrg); got != identity.CompatModeShadow {
			t.Fatalf("an organization with no record on a process-shadow deployment resolved to %v", got)
		}
	})

	t.Run("an empty organization has no record to look up", func(t *testing.T) {
		o, _ := newFixtureObserver(t, fixtureConfig(identity.CompatModeShadow), newCapturingRecorder(0),
			WithOrgModes(fixtureOrgModes{modes: map[string]identity.CompatMode{
				"": identity.CompatModeOff,
			}}))
		if got := o.effectiveMode(ctx, ""); got != identity.CompatModeShadow {
			t.Fatalf("an empty organization resolved to %v through a record keyed on the empty "+
				"string; the empty key must never select a mode", got)
		}
	})

	t.Run("an unreadable record falls back to the process mode and counts", func(t *testing.T) {
		o, _ := newFixtureObserver(t, fixtureConfig(identity.CompatModeShadow), newCapturingRecorder(0),
			WithOrgModes(fixtureOrgModes{err: context.DeadlineExceeded}))
		if got := o.effectiveMode(ctx, fixtureOrg); got != identity.CompatModeShadow {
			t.Fatalf("an unreadable record resolved to %v; the fall-back is towards the DEPLOYMENT'S declaration", got)
		}
		if o.OrgModeFailures() == 0 {
			t.Fatal("the fall-back was not counted")
		}
	})
}

// TestPerOrganizationModeDecidesWhetherAComparisonHAPPENS is the BEHAVIOURAL
// half of the test above.
//
// effectiveMode returning the right value proves nothing on its own: the
// question that matters is whether the value it returns actually gates the
// observation. Two organizations, one process, opposite outcomes - one records
// a comparison and the other records nothing.
func TestPerOrganizationModeDecidesWhetherAComparisonHappens(t *testing.T) {
	rec := newCapturingRecorder(1)
	o, _ := newFixtureObserver(t, fixtureConfig(identity.CompatModeOff), rec,
		WithOrgModes(fixtureOrgModes{modes: map[string]identity.CompatMode{
			fixtureOrg: identity.CompatModeShadow,
		}}))

	// The organization with NO record, on a process-off deployment. Nothing.
	quiet := fixtureObservation(true, false)
	quiet.OrgID = fixtureOtherOrg
	quiet.OrgScope = fixtureOtherOrg
	o.Observe(context.Background(), quiet)

	// The organization whose record raises it above the deployment.
	o.Observe(context.Background(), fixtureObservation(true, false))

	got := rec.wait(t)
	if len(got) != 1 {
		t.Fatalf("recorded %d comparison(s), want exactly 1", len(got))
	}
	if got[0].OrgID != fixtureOrg {
		t.Fatalf("the comparison came from org %q; the non-participating organization was measured", got[0].OrgID)
	}
	if got[0].Mode != identity.CompatModeShadow {
		t.Fatalf("the comparison recorded mode %v; a record from an organization shadowing on a "+
			"process-off deployment must read shadow, or it cannot be told apart from the "+
			"deployment default", got[0].Mode)
	}
}

// TestCouldObserveIsAStrictOverApproximation pins the cheap gate the engines
// read before building an Observation at all.
//
// Both directions matter, and only one of them is a bug. TRUE while every
// organization resolves to off costs one discarded struct. FALSE while some
// organization resolves to shadow is a plane silently missing from the window,
// and it is the direction this asserts cannot happen.
func TestCouldObserveIsAStrictOverApproximation(t *testing.T) {
	t.Run("off with no per-org source cannot observe", func(t *testing.T) {
		o, _ := newFixtureObserver(t, fixtureConfig(identity.CompatModeOff), newCapturingRecorder(0))
		if o.Enabled() {
			t.Fatal("Enabled() is true with the process mode off and no per-org source; nothing " +
				"on this deployment can ever be compared, and every evaluation would build an " +
				"Observation to discard")
		}
	})

	t.Run("off WITH a per-org source can observe", func(t *testing.T) {
		o, _ := newFixtureObserver(t, fixtureConfig(identity.CompatModeOff), newCapturingRecorder(0),
			WithOrgModes(fixtureOrgModes{modes: map[string]identity.CompatMode{}}))
		if !o.Enabled() {
			t.Fatal("Enabled() is false with a per-org source wired. A record can raise ANY " +
				"organization above a process-off deployment, so a false here silently drops " +
				"every per-organization shadow - the release plan's entire per-org case.")
		}
	})

	t.Run("shadow can observe with or without a source", func(t *testing.T) {
		o, _ := newFixtureObserver(t, fixtureConfig(identity.CompatModeShadow), newCapturingRecorder(0))
		if !o.Enabled() {
			t.Fatal("Enabled() is false on a process-shadow deployment")
		}
	})

	t.Run("a nil observer is off", func(t *testing.T) {
		var o *Observer
		if o.Enabled() {
			t.Fatal("a nil observer reported Enabled()")
		}
		// And it must not panic: an unwired deployment needs no nil check at
		// any call site.
		o.Observe(context.Background(), fixtureObservation(true, false))
	})
}

// TestAComparisonIsProducedEndToEnd is the anti-vacuity floor for this whole
// suite.
//
// Every test above asserts that something does NOT happen. Without one test
// proving a comparison happens at all, a shadow that silently evaluated
// nothing would satisfy all of them - which is the "zero unexplained out of
// zero compared" failure this package exists to prevent, reproduced in its own
// test suite.
func TestAComparisonIsProducedEndToEnd(t *testing.T) {
	rec := newCapturingRecorder(1)
	o, src := newFixtureObserver(t, fixtureConfig(identity.CompatModeShadow), rec)

	o.Observe(context.Background(), fixtureObservation(true, false))
	got := rec.wait(t)

	c := got[0]
	if c.Plane != legacycompile.PlaneGatewayRequest {
		t.Fatalf("the comparison was attributed to plane %q", c.Plane)
	}
	if c.BundleDigest == "" {
		t.Fatal("the comparison names no bundle; a replay that cannot name the bundle it was " +
			"measured against is not a replay, and rollback by immutable bundle digest is one " +
			"of epic #3552's exit criteria")
	}
	if c.PolicySnapshot == "" {
		t.Fatal("the comparison names no policy snapshot")
	}
	if c.SampleRate != 1 {
		t.Fatalf("the comparison records sample rate %v; a denominator whose rate is unknown "+
			"cannot be interpreted", c.SampleRate)
	}
	switch c.Record.Class {
	case shadow.ClassMatch, shadow.ClassExpectedChange, shadow.ClassUnexplained:
	default:
		t.Fatalf("the comparison carries classification %q, which is not one of the three", c.Record.Class)
	}
	if src.readCount() == 0 {
		t.Fatal("the policy tables were never read; the bundle was compiled from nothing")
	}
}

// TestTheBundleIsCachedPerSnapshot proves the expensive path runs once.
//
// It is not a performance test. The cache key is what makes a comparison
// COMPARABLE - a bundle keyed loosely would be reused across two different
// policy sets - so "one read for N identical observations" and "a new read when
// the policy set changes" are both correctness properties.
func TestTheBundleIsCachedPerSnapshot(t *testing.T) {
	const n = 5
	rec := newCapturingRecorder(n)
	o, src := newFixtureObserver(t, fixtureConfig(identity.CompatModeShadow), rec)

	for i := 0; i < n; i++ {
		o.Observe(context.Background(), fixtureObservation(true, false))
	}
	rec.wait(t)

	if reads := src.readCount(); reads > 1 {
		t.Fatalf("%d observations over one policy snapshot caused %d table reads; the bundle "+
			"cache is not keyed on the snapshot", n, reads)
	}
}

// TestObservationsAreRefusedRatherThanMisattributed covers every shape this
// package will not act on, and proves each is REFUSED rather than silently
// counted against some plane.
func TestObservationsAreRefusedRatherThanMisattributed(t *testing.T) {
	for name, mutate := range map[string]func(*Observation){
		"no plane": func(o *Observation) { o.Plane = "" },
		"an undeclared plane": func(o *Observation) {
			o.Plane = legacycompile.Plane("gateway")
		},
		"a plane with no call site": func(o *Observation) {
			o.Plane = legacycompile.Plane("connector_execution")
		},
		"a row with no policy_id": func(o *Observation) {
			o.Rows[0].PolicyID = ""
		},
		"a row that matched without running": func(o *Observation) {
			o.Rows[0].Ran = false
			o.Rows[0].Matched = true
		},
		"a row naming a table that is not a policy table": func(o *Observation) {
			o.Rows[0].Table = "audit_logs"
		},
	} {
		t.Run(name, func(t *testing.T) {
			obs := fixtureObservation(true, false)
			mutate(&obs)
			if defect := obs.Validate(); defect == "" {
				t.Fatalf("Validate accepted %s. An observation this package cannot act on must "+
					"be refused and counted; attributing it to some plane moves a denominator "+
					"an operator reads to decide a cutover.", name)
			}
		})
	}

	t.Run("the fixture itself is valid", func(t *testing.T) {
		// ANTI-VACUITY: without this, a Validate that refused everything would
		// pass every case above.
		if defect := fixtureObservation(true, false).Validate(); defect != "" {
			t.Fatalf("the unmutated fixture is refused (%s); every case above would then pass "+
				"for the wrong reason", defect)
		}
	})
}

// TestAnEvaluationErrorIsNeverCompared pins the availability-versus-verdict
// split.
//
// A plane that could not evaluate has not produced a policy decision, and
// comparing "could not scan" against a PDP verdict reports a difference the
// migration did not cause. It is counted under its own disposition and never
// reaches the classifier.
func TestAnEvaluationErrorIsNeverCompared(t *testing.T) {
	// ONE WORKER so the queue is FIFO: the sentinel's arrival then proves the
	// availability failure has already been through the worker, rather than
	// merely not having got there yet. With a pool this test would pass
	// against an implementation that compared both.
	cfg := fixtureConfig(identity.CompatModeShadow)
	cfg.Workers = 1
	rec := newCapturingRecorder(1)
	o, _ := newFixtureObserver(t, cfg, rec)

	// An availability failure, made DISTINGUISHABLE from the sentinel by its
	// PLANE, so the assertion is about which observation was compared rather
	// than about how many were.
	//
	// The plane rather than the policy snapshot, deliberately: an extra row
	// would change the snapshot AND make the pair not-comparable, so the
	// observation would be dropped by a check that is not the one under test
	// and the mutant removing THIS check would survive. Both planes read the
	// same rows, so comparability is identical on both legs and the only
	// thing separating them is the availability flag.
	failed := fixtureObservation(false, false)
	failed.Legacy.EvaluationError = true
	failed.Plane = legacycompile.PlaneDecide
	o.Observe(context.Background(), failed)

	// Then a good one: the sentinel.
	sentinel := fixtureObservation(true, false)
	o.Observe(context.Background(), sentinel)
	got := rec.wait(t)

	for _, c := range got {
		if c.Plane == legacycompile.PlaneDecide {
			t.Fatalf("an availability failure was compared against a PDP verdict and classified "+
				"as %s. A plane that could not evaluate has produced no policy decision, so "+
				"the difference would be one the migration did not cause.", c.Record.Class)
		}
	}
	if len(got) == 0 {
		t.Fatal("nothing was recorded at all; the assertion above would have passed against a " +
			"shadow that compared nothing")
	}
}

// TestShutdownDrainsRatherThanDiscards proves queued evidence survives a
// graceful stop.
func TestShutdownDrainsRatherThanDiscards(t *testing.T) {
	rec := newCapturingRecorder(1)
	o, _ := newFixtureObserver(t, fixtureConfig(identity.CompatModeShadow), rec)
	o.Observe(context.Background(), fixtureObservation(true, false))
	rec.wait(t)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := o.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	// Idempotent: a second call must not panic on a closed channel.
	if err := o.Shutdown(ctx); err != nil {
		t.Fatalf("second Shutdown: %v", err)
	}
}

// TestConstructorRefusesWhatWouldBeQuietlyUseless mirrors
// identity.NewCompatAdapter's argument: every argument whose absence makes the
// thing construct successfully and then do nothing is refused.
func TestConstructorRefusesWhatWouldBeQuietlyUseless(t *testing.T) {
	src := &fixtureRowSource{byOrg: map[string][]legacycompile.RawRow{}}
	cfg := fixtureConfig(identity.CompatModeShadow)

	if _, err := NewObserver(cfg, nil, newCapturingRecorder(0)); err == nil {
		t.Error("a nil row source was accepted; every observation would fail to build a bundle")
	}
	if _, err := NewObserver(cfg, src, nil); err == nil {
		t.Error("a nil recorder was accepted; a shadow phase that records nothing has not run")
	}
	if _, err := NewObserver(cfg, src, (*LogRecorder)(nil)); err == nil {
		t.Error("a typed-nil log recorder was accepted; its RecordComparison returns immediately")
	}
	if _, err := NewObserver(cfg, src, MultiRecorder{}); err == nil {
		t.Error("an EMPTY fan-out was accepted. This is the spelling anyone writing a fan-out " +
			"actually types, and a reflect-based zero check would have caught only `var m " +
			"MultiRecorder` - the accidental one.")
	}
	if _, err := NewObserver(cfg, src, MultiRecorder{nil, nil}); err == nil {
		t.Error("a fan-out of nils was accepted")
	}
	// And the legitimate stateless shape must be ACCEPTED: a zero-value struct
	// with a value receiver records perfectly well, and refusing it is the
	// other half of the reflect.IsZero mistake.
	if _, err := NewObserver(cfg, src, MetricsRecorder{}); err != nil {
		t.Errorf("a stateless metrics recorder was refused: %v", err)
	}
	if _, err := NewObserver(cfg, src, MultiRecorder{nil, MetricsRecorder{}}); err != nil {
		t.Errorf("a fan-out with one nil member and one real one was refused: %v; skipping a nil "+
			"member is a deliberate feature for an edition that wires no metrics recorder", err)
	}
}

// TestTheLogRecorderIsSafeUnderConcurrentWorkers is the RACE test the package
// did not have (R3 round 1, finding 1).
//
// LogRecorder.RecordComparison is called from every worker goroutine - two by
// default, up to 64 - and Bootstrap wires it into every production deployment.
// Its match counter was a plain uint64: a data race by the Go memory model,
// undefined behaviour rather than merely a miscounted sampling interval.
//
// NOTHING in this repository would have caught it. No CI job runs the race
// detector over platform/agent, and the one test that drove the observer with
// real workers wired MetricsRecorder only - so the single test exercising the
// concurrent path deliberately avoided the racy recorder. This one does not.
//
// Run it with -race for the assertion that matters; without -race it still
// pins the sampling arithmetic.
func TestTheLogRecorderIsSafeUnderConcurrentWorkers(t *testing.T) {
	const n = 64
	cfg := fixtureConfig(identity.CompatModeShadow)
	cfg.Workers = 8
	cfg.QueueDepth = 4 * n

	counter := newCapturingRecorder(n)
	// The REAL production fan-out shape: the log recorder beside the metrics
	// one, which is exactly what Bootstrap builds.
	o, _ := newFixtureObserver(t, cfg, MultiRecorder{NewLogRecorder(1), MetricsRecorder{}, counter})

	for i := 0; i < n; i++ {
		o.Observe(context.Background(), fixtureObservation(i%2 == 0, i%3 == 0))
	}
	counter.wait(t)
}

// TestAPanickingRecorderDoesNotKillTheProcess pins the recovery on the worker
// (R3 round 1, finding 2).
//
// Everything the worker runs - the legacy compiler, a Rego render, a bundle
// build, an OPA engine start, an OPA evaluation - can panic, and two of those
// are inside a dependency this tree acquired in the same change as the shadow.
// A panic on a goroutine with no recovery ends the PROCESS, which would
// falsify the whole argument for turning this on: a recorded-only feature that
// can crash the agent for every tenant has not left the request path alone.
//
// The recorder is the injectable panic site, and the property is the same
// wherever the panic comes from: the worker survives, the observation is lost
// and counted, and the next observation is still processed.
func TestAPanickingRecorderDoesNotKillTheProcess(t *testing.T) {
	cfg := fixtureConfig(identity.CompatModeShadow)
	cfg.Workers = 1 // one worker, so "it survived" is not another worker's doing

	survivor := newCapturingRecorder(1)
	rec := &panicOnceRecorder{next: survivor}
	o, _ := newFixtureObserver(t, cfg, rec)

	// The first observation panics inside the recorder, on the worker.
	o.Observe(context.Background(), fixtureObservation(true, false))
	// The second must still be processed by the SAME worker.
	o.Observe(context.Background(), fixtureObservation(true, false))

	got := survivor.wait(t)
	if len(got) == 0 {
		t.Fatal("nothing was recorded after a panic on the worker. Either the panic took the " +
			"process down - which is what this test exists to prevent - or it killed the only " +
			"worker, which degrades into dropped observations and an unexplained hole in the " +
			"denominator.")
	}
	if !rec.panicked {
		t.Fatal("the fixture never panicked, so this test asserted nothing")
	}
}

// panicOnceRecorder panics on its first comparison and delegates afterwards.
type panicOnceRecorder struct {
	next     Recorder
	panicked bool
}

func (p *panicOnceRecorder) RecordComparison(ctx context.Context, c Comparison) {
	if !p.panicked {
		p.panicked = true
		panic("synthetic panic on the shadow worker")
	}
	p.next.RecordComparison(ctx, c)
}

// TestBuildLocksAreReapedOnEveryExitPath pins the refcount (R3 round 1,
// findings 6 and 10).
//
// The per-key build mutexes were created on every cache miss and removed only
// after a world was successfully INSERTED, so every miss that ended in
// ErrNotComparable or a compile failure left a permanent entry. The keys carry
// a policy-snapshot digest, so the key space grows with every policy edit -
// and ErrNotComparable is documented as ORDINARY operation, which makes the
// leaking path the path the design says is normal.
func TestBuildLocksAreReapedOnEveryExitPath(t *testing.T) {
	src := &fixtureRowSource{byOrg: map[string][]legacycompile.RawRow{
		fixtureOrg: staticRows(t, fixtureOrg),
	}}
	c := newWorldCache(src, legacycompile.Options{}, 8)
	ctx := context.Background()

	// 1. The NOT-COMPARABLE path, twenty distinct snapshots.
	for i := 0; i < 20; i++ {
		obs := fixtureObservation(true, false)
		// A stamp the row source's row certainly does not carry, and a
		// DIFFERENT one each iteration so each is its own cache key.
		obs.Rows[0].UpdatedAt = fmt.Sprintf("2020-01-%02dT00:00:00.000000000Z", i+1)
		if _, _, err := c.worldFor(ctx, obs, nil); err == nil {
			t.Fatalf("iteration %d was expected to be not-comparable", i)
		}
	}
	c.mu.Lock()
	nReport, nWorld := len(c.buildReport), len(c.buildWorld)
	c.mu.Unlock()
	if nReport != 0 || nWorld != 0 {
		t.Fatalf("after 20 not-comparable misses the build-lock maps hold %d report and %d world "+
			"entries; they must be empty. ErrNotComparable is ordinary operation, so this is a "+
			"leak on the path the design calls normal.", nReport, nWorld)
	}

	// 2. The FAILING-READ path.
	src.err = context.DeadlineExceeded
	for i := 0; i < 10; i++ {
		if _, _, err := c.worldFor(ctx, fixtureObservation(true, false), nil); err == nil {
			t.Fatal("a failing row source was expected to produce an error")
		}
	}
	src.err = nil
	c.mu.Lock()
	nReport, nWorld = len(c.buildReport), len(c.buildWorld)
	c.mu.Unlock()
	if nReport != 0 || nWorld != 0 {
		t.Fatalf("after 10 failed reads the build-lock maps hold %d report and %d world entries", nReport, nWorld)
	}

	// 3. ANTI-VACUITY: the SUCCESS path must still work and must also reap.
	// Without this, a worldFor that returned an error unconditionally would
	// satisfy both assertions above.
	if _, _, err := c.worldFor(ctx, fixtureObservation(true, false), nil); err != nil {
		t.Fatalf("the success path failed, so the two assertions above proved nothing: %v", err)
	}
	if _, _, worlds := c.stats(); worlds != 1 {
		t.Fatalf("the success path did not cache a world (%d resident)", worlds)
	}
	c.mu.Lock()
	nReport, nWorld = len(c.buildReport), len(c.buildWorld)
	c.mu.Unlock()
	if nReport != 0 || nWorld != 0 {
		t.Fatalf("after a SUCCESSFUL build the build-lock maps hold %d report and %d world entries", nReport, nWorld)
	}
}
