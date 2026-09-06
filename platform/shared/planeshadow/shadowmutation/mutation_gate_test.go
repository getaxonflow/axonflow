// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package shadowmutation proves that the guard tests protecting the ADR-065
// per-plane decision shadow CAN FAIL (#3564).
//
// # WHY THIS EXISTS
//
// Almost every assertion in this change says that something does NOT happen:
// the shadow does not change a decision, an unrun detector does not become a
// known false, a policy edit does not become an unexplained difference, an
// organization with no record does not get measured. A test asserting that
// nothing happened and an implementation in which nothing CAN happen are
// indistinguishable from outside - and the second is exactly what a green run
// over an inert shadow looks like.
//
// So each property gets a compiling mutant that removes it and a named
// behavioural test that must then fail.
//
// # THE ONE THE BRIEF ASKS FOR BY NAME
//
// "a mutant that leaks the shadow outcome into the decision MUST be killed by
// a behavioral test". That mutant is `the shadow's verdict reaches the
// response` below, and it is a TWO-FILE overlay because a single-file edit
// cannot express it: the shadow returns nothing, so leaking requires both a
// value to leak (a package-level var written by the worker) and a reader (the
// engine consulting it). Needing two coordinated edits in two packages is
// itself the measurement - it is how far a future author would have to go to
// reintroduce the defect, and it is why the void return is the guarantee
// rather than a convention.
//
// # HOW IT WORKS
//
// Each mutant is compiled through `go test -overlay`. NOTHING ON DISK IS
// MODIFIED, which is the fix for a failure this repo has already paid for: a
// mutation script killed between "write the mutation" and "restore the backup"
// leaves the mutation in the tree, and the next run's backup captures the
// mutation as the good state.
//
// TWO OUTCOMES ARE FAILURES, and distinguishing them is the point:
//
//   - the target test PASSES under the mutant, so the assertion is decorative;
//   - the mutant does not COMPILE, so nothing was tested.
//
// The second is the trap. `go test` exits non-zero for a build error and for a
// test failure alike, so a harness checking only the exit code would report a
// mutant that never compiled as proof of a working guard.
package shadowmutation

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// edit is one textual replacement in one file.
type edit struct {
	// file is relative to the platform module root.
	file string
	// from must appear EXACTLY ONCE in the file. Zero matches means the code
	// moved and the mutant now tests nothing; more than one means the edit is
	// broader than described. Both fail.
	from string
	to   string
}

// mutant is a set of edits and the test they must break.
type mutant struct {
	// name describes the SEMANTIC change, not the textual one.
	name  string
	edits []edit
	// pkg is the package to run, relative to the module root.
	pkg string
	// test is the -run pattern for the test that must FAIL.
	test string
	// why records what the mutant restores or breaks.
	why string
}

const (
	shadowPkg = "./shared/planeshadow/"
	policyPkg = "./shared/policy/"
)

var mutants = []mutant{
	// --- THE LEAK. The property this whole package is built around. ---
	{
		name: "the shadow's outcome reaches the response",
		edits: []edit{
			{
				// A value to leak, written by the worker after it classifies.
				file: "shared/planeshadow/observer.go",
				// KEYED ON THE COMPARISON HAVING HAPPENED, NOT ON WHAT IT SAID,
				// and the reason is a mutant that went quiet.
				//
				// This was `Store(rec.Class != shadow.ClassMatch)` - "block when
				// the shadow disagrees" - and it SURVIVED as soon as R3 round 2's
				// ContentTarget fix made this fixture's comparisons classify as
				// `match`. The mutant was keyed on a value the code under test
				// can legitimately move, so improving the product silently
				// disarmed the proof, and the harness then reported the guard as
				// decorative when the guard was fine.
				//
				// The property is "no edit can make the shadow's opinion reach a
				// response". A response that depends on the shadow having
				// produced a verdict violates it exactly as much as one that
				// depends on which verdict, and "a comparison happened" is the
				// one fact that cannot go quiet because a classification
				// improved.
				from: `	shadowObservations.WithLabelValues(plane, dispositionCompared).Inc()`,
				to: `	shadowObservations.WithLabelValues(plane, dispositionCompared).Inc()
	LeakedVerdictDenies.Store(true)`,
			},
			{
				file: "shared/planeshadow/observer.go",
				from: `// Shutdown stops the workers and waits for in-flight evaluations.`,
				to: `// LeakedVerdictDenies is the mutant's leak channel.
var LeakedVerdictDenies atomic.Bool

// Shutdown stops the workers and waits for in-flight evaluations.`,
			},
			{
				// The import the reader needs. A mutant that does not COMPILE
				// proves nothing, and this is exactly the shape that catches
				// it out: the leak's reader lives in a package that has no
				// reason to import planeshadow directly today.
				file: "shared/policy/engine.go",
				from: `	"strconv"
	"sync"
	"time"
)`,
				to: `	"strconv"
	"sync"
	"time"

	"axonflow/platform/shared/planeshadow"
)`,
			},
			{
				// A reader: the engine consults it.
				file: "shared/policy/engine.go",
				from: `	trace.emit(ctx, PhaseRequest, opts, result.MatchedPolicies, !result.Blocked, result.EvaluationError)

	return result
}`,
				to: `	trace.emit(ctx, PhaseRequest, opts, result.MatchedPolicies, !result.Blocked, result.EvaluationError)
	if planeshadow.LeakedVerdictDenies.Load() {
		result.Blocked = true
		result.BlockReason = "denied by the ADR-065 decision plane"
	}

	return result
}`,
			},
			{
				// Synchronous, so the leak is observable within one request -
				// which is what a real regression of this shape would do.
				file: "shared/planeshadow/observer.go",
				from: `	select {
	case o.queue <- obs:
	default:`,
				to: `	o.evaluate(obs)
	select {
	case <-o.stop:
	default:`,
			},
		},
		pkg:  policyPkg,
		test: "^TestShadowNeverChangesTheRequestOutcome$",
		why: "the guarantee is that no edit can make the shadow's opinion reach a response. " +
			"This mutant is what reintroducing that would look like, and it takes two " +
			"packages and four edits - which is the measurement.",
	},

	// --- THE R3 ROUND-1 FIXES. Each was a real defect; each gets a mutant. ---
	{
		name: "a panic on the worker is not recovered, so it takes the process down",
		edits: []edit{{
			file: "shared/planeshadow/observer.go",
			// The recover() CALL is what has to go, not the branch after it.
			// `if r := recover(); false && r != nil` still CALLS recover(),
			// which stops the panic regardless of what the branch then does -
			// so that mutant compiled, the test passed, and it proved nothing.
			// Measured: it survived. Binding r to a nil literal keeps the
			// variable used (so it compiles) and never recovers.
			from: `		if r := recover(); r != nil {`,
			to:   `		if r := any(nil); r != nil {`,
		}},
		pkg:  shadowPkg,
		test: "^TestAPanickingRecorderDoesNotKillTheProcess$",
		why: "everything the worker runs can panic - including OPA, a dependency this tree " +
			"acquired in the same change - and a panic on a goroutine with no recovery ends the " +
			"PROCESS. A recorded-only feature that can crash the agent for every tenant has not " +
			"left the request path alone, whatever its return type says.",
	},
	{
		name: "the build locks are not reaped, so the map grows on every not-comparable miss",
		edits: []edit{{
			file: "shared/planeshadow/worlds.go",
			from: `		if l.refs == 0 {
			delete(locks, key)
		}`,
			to: `		if l.refs < 0 {
			delete(locks, key)
		}`,
		}},
		pkg:  shadowPkg,
		test: "^TestBuildLocksAreReapedOnEveryExitPath$",
		why: "the keys carry a policy-snapshot digest, so the key space grows with every policy " +
			"edit - and ErrNotComparable is documented as ORDINARY operation, which makes the " +
			"leaking path the path the design calls normal",
	},
	{
		name: "a condition field read at two values is compared anyway",
		edits: []edit{{
			file: "orchestrator/shadowobserve.go",
			from: `	if len(t.movedFields) > 0 {`,
			to:   `	if false {`,
		}},
		pkg:  "./orchestrator/",
		test: "^TestEmitRefusesToCompareAMovedField$",
		why: "modify_risk mutates risk_score mid-loop, so one evaluation reads one field at two " +
			"values; one request carries one value per attribute, so some row would be judged " +
			"against a number the legacy engine never showed it and the determining sets would " +
			"differ on every request of that shape, in gate 18's numerator",
	},

	{
		name: "a moved condition field is not detected in the first place",
		edits: []edit{{
			file: "orchestrator/shadowobserve.go",
			from: `	if prev, seen := t.fields[name]; seen && !sameFieldValue(prev, value) {`,
			to:   `	if prev, seen := t.fields[name]; false && seen && !sameFieldValue(prev, value) {`,
		}},
		pkg:  "./orchestrator/",
		test: "^TestAMovedConditionFieldIsNotComparable$",
		why: "the DETECTOR and the BRANCH are two properties. A test of only the branch leaves " +
			"the detector free to stop noticing, and vice versa - which is how a guard survives " +
			"in halves.",
	},

	// --- THE TRI-STATE. ADR-065's central correction, on the runtime path. ---
	{
		name: "a detector that never ran is reported as one that ran and did not match",
		edits: []edit{{
			file: "shared/policy/shadowobserve.go",
			from: `			Ran:       t.ran[p.PolicyID],`,
			to:   `			Ran:       true,`,
		}},
		pkg:  policyPkg,
		test: "^TestTheEngineReportsWhichDetectorsActuallyRan$",
		why: "collapsing 'did not run' into 'ran and did not match' tells the PDP a skipped " +
			"detector positively did not fire - a fail-open on every request a category " +
			"filter or capability scoping narrowed, and one that produces a permit either way",
	},
	{
		name: "the case writes a false verdict for a detector that never ran",
		edits: []edit{{
			file: "shared/planeshadow/translate.go",
			from: `		if !r.Ran {`,
			to:   `		if false {`,
		}},
		pkg:  shadowPkg,
		test: "^TestTheCaseCarriesTheTriState$",
		why: "the other end of the same property: the translator, not the collector, is what " +
			"turns an unrun detector into an absent attribute",
	},

	{
		name: "the plane's tool identity addresses the ADR-065 request",
		edits: []edit{{
			file: "shared/planeshadow/translate.go",
			from: `		Action:  shadow.ActionID,`,
			to:   `		Action:  strings.TrimSpace(obs.Action),`,
		}},
		pkg:  shadowPkg,
		test: "^TestTheRequestNamesTheRegisteredAction$",
		why: "a compiled world registers exactly ONE action, so a request naming anything else is " +
			"denied for unknown_action with an empty determining set and nothing explains it. " +
			"Every production call site passes a tool identity, so this turns the WHOLE window " +
			"into UNEXPLAINED noise and makes gate 18 unreadable - measured: identical " +
			"observations classified UNEXPLAINED with a tool identity and match/EC2 without one.",
	},

	// --- COMPARABILITY. Neither a match nor unexplained. ---
	{
		name: "a policy edit between the plane's load and the read is compared anyway",
		edits: []edit{{
			file: "shared/planeshadow/worlds.go",
			from: `	if detail := coversPlaneRows(raw, obs.Rows); detail != "" {`,
			to:   `	if detail := ""; detail != "" {`,
		}},
		pkg:  shadowPkg,
		test: "^TestNotComparableIsNeitherAMatchNorUnexplained$",
		why: "comparing across two policy sets manufactures differences on every request in a " +
			"cache window, which fills gate 18's numerator with noise",
	},
	{
		name: "a row deleted since the plane evaluated it is treated as present",
		edits: []edit{{
			file: "shared/planeshadow/worlds.go",
			from: `		stamp, ok := have[key]
		if !ok {`,
			to: `		stamp, ok := have[key], true
		if !ok {`,
		}},
		pkg:  shadowPkg,
		test: "^TestCoversPlaneRowsIsOneDirectional$",
		why:  "a deleted row makes the bundle describe a policy the plane did not evaluate",
	},

	// --- THE PER-ORGANIZATION AXIS. The ARGUMENT, not the branch. ---
	{
		name: "the organization's record is ignored and the process mode always wins",
		edits: []edit{{
			file: "shared/planeshadow/observer.go",
			from: `	mode, err := identity.EffectiveMode(process, record, found)`,
			to:   `	mode, err := identity.EffectiveMode(process, record, found && false)`,
		}},
		pkg:  shadowPkg,
		test: "^TestEffectiveModeResolvesPerOrganization$",
		why: "the release plan's whole per-org case is an organization shadowing on a " +
			"deployment that is otherwise off; ignoring the record deletes it silently",
	},
	{
		name: "the mode is resolved for no organization rather than for THIS one",
		edits: []edit{{
			file: "shared/planeshadow/observer.go",
			from: `	mode := o.effectiveMode(ctx, obs.OrgID)`,
			to:   `	mode := o.effectiveMode(ctx, "")`,
		}},
		pkg:  shadowPkg,
		test: "^TestPerOrganizationModeDecidesWhetherAComparisonHappens$",
		why: "THE ARGUMENT, NOT THE BRANCH. Every fixture in which the process mode and the " +
			"record agree makes this mutant, a constant, and the real call answer alike; " +
			"only a two-organization fixture with a DISAGREEING record can tell them apart",
	},
	{
		name: "a stored enforce is honoured instead of clamped",
		edits: []edit{{
			file: "shared/planeshadow/observer.go",
			from: `	if !identity.DecisionShadowModeIsStorable(mode) {`,
			to:   `	if false {`,
		}},
		pkg:  shadowPkg,
		test: "^TestEnforceIsRefusedAtEveryFence$",
		why: "the third fence exists because the first two govern writes; a row from a restore " +
			"or a later migration has passed neither",
	},

	// --- THE CHEAP GATE. Its false direction is a silently missing plane. ---
	{
		name: "the cheap gate ignores the per-organization source",
		edits: []edit{{
			file: "shared/planeshadow/observer.go",
			from: `	o.couldObserve.Store(records(cfg.Mode) || o.orgModes != nil)`,
			to:   `	o.couldObserve.Store(records(cfg.Mode))`,
		}},
		pkg:  shadowPkg,
		test: "^TestCouldObserveIsAStrictOverApproximation$",
		why: "a record can raise ANY organization above a process-off deployment, so dropping " +
			"the source from the gate silently drops every per-organization shadow",
	},

	// --- THE DENOMINATOR. Refused, never misattributed. ---
	{
		name: "an observation with no plane is accepted and attributed to the empty plane",
		edits: []edit{{
			file: "shared/planeshadow/observation.go",
			// BOTH arms, because removing only the first leaves SpecFor("")
			// refusing the empty plane for a different reason - so a
			// single-arm mutant is killed by a check that is not the one
			// under test, and reports a green that says nothing about the
			// arm it removed. A doubly-guarded property needs the other
			// guard put in its permissive state, not left to absorb the
			// mutant ([[feedback_a_doubly_guarded_property_makes_a_single_guard_mutant_survive]]).
			from: `	if strings.TrimSpace(string(o.Plane)) == "" {
		return "the call site named no plane; an observation attributed to no plane cannot be counted, and attributing it to some plane would move a denominator an operator is reading"
	}
	if _, err := legacycompile.SpecFor(o.Plane); err != nil {`,
			to: `	if false {
		return "the call site named no plane; an observation attributed to no plane cannot be counted, and attributing it to some plane would move a denominator an operator is reading"
	}
	if _, err := legacycompile.SpecFor(o.Plane); false && err != nil {`,
		}},
		pkg:  shadowPkg,
		test: "^TestObservationsAreRefusedRatherThanMisattributed$",
		why: "an unattributed observation counted against some plane moves a denominator an " +
			"operator reads to decide whether that plane may cut over",
	},
	{
		name: "an availability failure is compared against a policy verdict",
		edits: []edit{{
			file: "shared/planeshadow/observer.go",
			from: `	if obs.Legacy.EvaluationError {`,
			to:   `	if false {`,
		}},
		pkg:  shadowPkg,
		test: "^TestAnEvaluationErrorIsNeverCompared$",
		why: "a plane that could not evaluate has produced no policy decision; comparing it " +
			"reports a difference the migration did not cause",
	},

	// --- THE LEGACY SIDE IS THE REAL OUTCOME. ModelLimitations item 1. ---
	{
		name: "the legacy state is inferred from the row's action instead of the plane's outcome",
		edits: []edit{{
			file: "shared/planeshadow/translate.go",
			from: `	if obs.Legacy.Executable {
		v.State = contract.StateAllow
	} else {
		v.State = contract.StateDeny
	}`,
			to: `	v.State = contract.StateAllow
	for _, r := range obs.Rows {
		if r.Matched && (r.Action == "block" || r.Action == "require_approval") {
			v.Executable = false
			v.State = contract.StateDeny
		}
	}`,
		}},
		pkg:  shadowPkg,
		test: "^TestLegacyVerdictIsTheRealOutcome$",
		why: "this IS shadow.ModelLimitations item 1 reintroduced: DEPLOYMENT_MODE=community " +
			"turns require_approval into ALLOW, so an actions-derived state reports a deny " +
			"the running system never issued - wrong in the fail-open direction for a whole " +
			"deployment mode",
	},

	// --- THE SEGMENT TRI-STATE. #3482's class. ---
	{
		name: "an unresolved group closure is presented as a resolved empty one",
		edits: []edit{{
			file: "shared/planeshadow/translate.go",
			from: `	if obs.SegmentsUnresolved {`,
			to:   `	if false {`,
		}},
		pkg:  shadowPkg,
		test: "^TestUnresolvedSegmentsAreNotAnEmptyClosure$",
		why: "a known empty closure EXCLUDES every segment-scoped policy, so presenting an " +
			"unresolved one that way silently drops every segment-scoped constraint from the " +
			"ADR-065 side while the legacy engine still applies it",
	},

	// --- THE SNAPSHOT. The bundle cache key. ---
	{
		name: "the snapshot ignores the row version, so an edited policy reuses its old bundle",
		edits: []edit{{
			file: "shared/planeshadow/observation.go",
			from: `		k := fmt.Sprintf("%d:%s|%d:%s|%d:%s",
			len(r.Table), r.Table, len(r.PolicyID), r.PolicyID, len(r.UpdatedAt), r.UpdatedAt)`,
			to: `		k := fmt.Sprintf("%d:%s|%d:%s",
			len(r.Table), r.Table, len(r.PolicyID), r.PolicyID)`,
		}},
		pkg:  shadowPkg,
		test: "^TestSnapshotIdentifiesThePolicySet$",
		why: "the cache would serve a bundle compiled from the previous version of the policy, " +
			"and every difference it produced would be attributed to the migration",
	},

	{
		name: "the snapshot counts sibling facts, so the policy-set digest varies with request content",
		edits: []edit{{
			file: "shared/planeshadow/observation.go",
			from: `		if _, dup := seen[k]; dup {
			continue
		}`,
			to: `		if _, dup := seen[k]; false && dup {
			continue
		}`,
		}},
		pkg:  shadowPkg,
		test: "^TestTheSnapshotDigestDoesNotVaryWithTheNUMBEROfSiblingFacts$",
		why: "one dynamic row producing N instructions becomes N sibling RowFacts sharing a row " +
			"key, so without de-duplication the digest documented as identifying the POLICY SET " +
			"varies with request CONTENT - each shape a separate worldKey and reportKey, a fresh " +
			"compile, bundle build-sign-verify and OPA engine, against a 256-entry cache",
	},

	// --- THE COMPILATION OPTIONS. The same value must reach BOTH sides. ---
	{
		name: "the stored options are not normalized, so the two sides name different content roots",
		edits: []edit{{
			file: "shared/planeshadow/worlds.go",
			from: `	opts := c.opts.Normalized()`,
			to:   `	opts := c.opts`,
		}},
		pkg:  shadowPkg,
		test: "^TestTheContentTargetIsNormalizedOnBothSidesOfTheDiff$",
		why: "Compile normalizes internally but the caller's copy is what builds the LEGACY side, " +
			"so an un-normalized copy gives the legacy redaction an empty target while the " +
			"ADR-065 effect targets response.content - every static redaction on every plane " +
			"classifies UNEXPLAINED, on every deployment that has not set the variable",
	},

	// --- SHADOWED ROWS. Two facts that must not be collapsed. ---
	{
		name: "a shadowed row is claimed by the legacy determining set",
		edits: []edit{{
			file: "shared/planeshadow/translate.go",
			from: `		if r.Shadowed {`,
			to:   `		if false && r.Shadowed {`,
		}},
		pkg:  shadowPkg,
		test: "^TestAShadowedRowKeepsItsDetectorVerdictAndLeavesTheDeterminingSet$",
		why: "a row the plane's combiner discarded determined nothing, so claiming it in the " +
			"legacy determining set manufactures a disagreement with the ADR-065 side on every " +
			"request where the first-match reduction hid a row",
	},

	// --- PER-ORGANIZATION ATTRIBUTION. ---
	{
		name: "an observation with an org scope and no org id is accepted, so the process mode silently decides",
		edits: []edit{{
			file: "shared/planeshadow/observer.go",
			from: `	if o.HasPerOrgSource() && obs.OrgScope != "" && obs.OrgID == "" {`,
			to:   `	if false && o.HasPerOrgSource() && obs.OrgScope != "" && obs.OrgID == "" {`,
		}},
		pkg:  shadowPkg,
		test: "^TestAnObservationWithAnOrgScopeAndNoOrgIDIsRefusedAndCounted$",
		why: "effectiveMode falls back to the PROCESS mode for an empty org id, so a site that " +
			"has an organization and did not pass it is never reached by a per-org enablement " +
			"and never released by a per-org exemption - silently, because that early return " +
			"is deliberately uncounted",
	},

	// --- THE PLANE LIST. Derived, never hand-maintained. ---
	{
		name: "a plane with no policy-evaluation call site is offered in the plane list",
		edits: []edit{{
			file: "shared/planeshadow/mode.go",
			from: `		if _, unimplemented := legacycompile.UnimplementedPlanes[name]; unimplemented {`,
			to:   `		if false {`,
		}},
		pkg:  shadowPkg,
		test: "^TestObservationsAreRefusedRatherThanMisattributed$|^TestParsePlanesRefusesTheUnimplemented$",
		why: "connector_execution has no evaluation call site anywhere in the tree; naming it " +
			"would manufacture a denominator out of a surface that does not evaluate policy",
	},

	// --- THE VACUITY GUARD. A window nothing can read is not a window. ---
	{
		name: "the window's denominator is absent until the first comparison",
		edits: []edit{{
			file: "shared/planeshadow/metrics.go",
			from: "\t\tobservations.WithLabelValues(string(p), dispositionCompared)\n",
			to:   "",
		}},
		pkg:  shadowPkg,
		test: "^TestBothGateOperandsAreExportedBeforeAnyTraffic$|^TestPreCreationIsTargetedAtTheGateOperandsOnly$",
		why: "this is the state the tree shipped in: the NUMERATOR was pre-created and the " +
			"DENOMINATOR was not, so on a plane that was watched and never compared anything, " +
			"gate 18's ratio had no divisor. An expression over an absent series is not a low " +
			"reading, it is no reading, and a v11 cutover read off it would be authorised by silence",
	},
	{
		name: "a wired process publishes no mode, so the vacuity rule has no left-hand side",
		edits: []edit{{
			file: "shared/planeshadow/bootstrap.go",
			from: "\tpublishMode(component, o.cfg.Observes, o.Mode())\n",
			to:   "",
		}},
		pkg: shadowPkg,
		// The WIRED arm specifically. Testing publishMode directly proves the
		// function correct and says nothing about whether InstallProcess calls
		// it, and the nil arm cannot reach this line.
		test: "^TestInstallProcessPublishesTheModeGaugeForAWiredObserver$",
		why: "a zero denominator is only a defect on a plane that was SUPPOSED to be measured, " +
			"and nothing in the counters says which those are; with no published mode the rule " +
			"evaluates over an empty vector and the vacuous window reports nothing",
	},
	{
		name: "an unwired process publishes no mode at all",
		edits: []edit{{
			file: "shared/planeshadow/bootstrap.go",
			from: "\t\tpublishMode(component, func(legacycompile.Plane) bool { return true }, identity.CompatModeOff)\n",
			to:   "",
		}},
		pkg:  shadowPkg,
		test: "^TestInstallProcessPublishesTheModeGauge$",
		why: "an all-zero gauge is a positive statement; its absence makes 'this process was " +
			"never wired' indistinguishable from 'this process is not scraped' and from 'the " +
			"rule file never loaded'",
	},
	{
		name: "the mode gauge reports every plane as watched, ignoring the plane list",
		edits: []edit{{
			file: "shared/planeshadow/metrics.go",
			from: "\t\tif !observes(p) {",
			to:   "\t\tif false {",
		}},
		pkg:  shadowPkg,
		test: "^TestTheModeGaugeIsPublishedForEveryPlaneAndMode$",
		why: "AXONFLOW_DECISION_SHADOW_PLANES narrows which planes observe; reporting the " +
			"excluded ones as watched would make each of them raise a vacuity alert that is a " +
			"statement about the plane list rather than about the window",
	},
	// --- #3552 gap 3: the per-organization, per-plane narrowing ---
	{
		name: "an organization's record can WIDEN past the deployment's plane list",
		edits: []edit{{
			file: "shared/planeshadow/org_planes.go",
			from: `	if !o.cfg.Observes(p) {`,
			to:   `	if false && !o.cfg.Observes(p) {`,
		}},
		pkg:  shadowPkg,
		test: "^TestPerOrganizationPlanesCanOnlyNarrowNeverWiden$",
		why:  "a deployment withdraws a plane for reasons that belong to the deployment - a worker pool that cannot afford its compilations, comparisons known-bad on this build - and a per-tenant row that re-enabled it would let one tenant's settings spend the deployment's money and reopen a plane the operator switched off",
	},
	{
		name: "an unusable per-org plane record closes the organization's window instead of falling back",
		edits: []edit{{
			file: "shared/planeshadow/org_planes.go",
			// RE-ANCHORED when the log-once suppression (R3 M4) gave
			// noteOrgPlanesFailure a dedupe key. The anchor guard reported it,
			// which is the whole reason that guard exists.
			from: `		o.noteOrgPlanesFailure(orgID, raw, describeParseFailure(orgID, raw, why))
		return o.cfg.Observes(p)`,
			to: `		o.noteOrgPlanesFailure(orgID, raw, describeParseFailure(orgID, raw, why))
		return false`,
		}},
		pkg: shadowPkg,
		// BOTH tests, GROUPED. `^A|B$` parses as (^A)|(B$) and would also match
		// any test ENDING with the second name; the group is what makes the
		// anchors bind to the alternation rather than to one arm each.
		test: "^(TestAnUnreadablePlaneRecordFallsBackToTheDeploymentList|TestAFallBackReAdmitsTheVERYPlaneTheRecordExcluded)$",
		why:  "closing the window looks like the safe direction and is not: the value is refused at the write path and by the column's CHECK, so reaching that branch means a restore or a hand-written row, and a silently closed window is invisible in the evidence while an operator reads the empty series as agreement",
	},
	{
		name: "an ABSENT per-org plane record is read as 'no planes' rather than 'the deployment decides'",
		edits: []edit{{
			file: "shared/planeshadow/org_planes.go",
			from: `	if !found {
		// The ordinary answer: no narrowing recorded, so the deployment's list
		// decides. Not a failure and not counted as one.
		return o.cfg.Observes(p)
	}`,
			to: `	if !found {
		return false
	}`,
		}},
		pkg:  shadowPkg,
		test: "^TestAnAbsentPlaneRecordLeavesTheDeploymentListInCharge$",
		why:  "no record is the state of every organization on every deployment, so reading it as 'no planes' empties the whole window at once - the same shape as reading a nil path set as no paths on the identity axis, and it produces no error anywhere",
	},
	{
		name: "the per-org plane fall-back is silent",
		edits: []edit{{
			file: "shared/planeshadow/org_planes.go",
			// Still ONE match after M4: the two increments stayed together at the
			// top of the function and the suppression was added below them,
			// which is also the order the counter's contract needs - it counts
			// before anything can return early.
			from: `	o.orgPlanesFailures.Add(1)
	shadowOrgPlanesFailures.Inc()`,
			to: `	_ = 0`,
		}},
		pkg:  shadowPkg,
		test: "^TestAnUnreadablePlaneRecordFallsBackToTheDeploymentList$",
		why:  "a fall-back nobody counts is a deployment measuring more planes for an organization than its record asks for, with nothing anywhere saying so - and it inflates a denominator rather than emptying one, which is the opposite direction from the mode's failure and the reason the two have separate counters",
	},
}

// TestEveryShadowGuardCanFail runs each mutant and requires its named test to
// fail, having first proven the mutant COMPILES.
func TestEveryShadowGuardCanFail(t *testing.T) {
	if testing.Short() {
		t.Skip("mutation gate compiles and runs the suite once per mutant; skipped under -short")
	}
	root := moduleRoot(t)

	for _, m := range mutants {
		m := m
		t.Run(m.name, func(t *testing.T) {
			t.Parallel()
			overlay := writeMutant(t, root, m)

			// STEP 1: the mutant must BUILD. `go test` exits non-zero for a
			// build error and a test failure alike, so a harness reading only
			// the exit code would report a mutant that never compiled as proof
			// of a working guard.
			out, err := runGo(t, root, []string{"build", "-overlay=" + overlay, m.pkg, policyPkg, shadowPkg})
			if err != nil {
				t.Fatalf("the mutant does not COMPILE, so it tested nothing:\n%s", out)
			}

			// STEP 2: the named test must now FAIL.
			out, err = runGo(t, root, []string{"test", "-count=1", "-overlay=" + overlay, "-run", m.test, m.pkg})
			if err == nil {
				t.Fatalf("SURVIVOR: %s\n  the mutant compiled and %s still PASSED.\n"+
					"  why this matters: %s\n"+
					"  A guard that survives the defect it names is decorative.\n%s",
					m.name, m.test, m.why, out)
			}
			if strings.Contains(out, "build failed") || strings.Contains(out, "cannot use") {
				t.Fatalf("the run failed to BUILD rather than to assert; the mutant tested nothing:\n%s", out)
			}
		})
	}
}

// TestTheMutationGateCanReportASurvivor is the harness's own failing input.
//
// N killed mutants prove nothing unless the runner can report a SURVIVOR: a
// harness whose survivor branch is unreachable reports success for every input,
// including an empty mutant list
// ([[feedback_a_mutation_gate_needs_a_survivor_test]]).
func TestTheMutationGateCanReportASurvivor(t *testing.T) {
	if testing.Short() {
		t.Skip("skipped under -short")
	}
	root := moduleRoot(t)

	// A mutant that compiles, changes something real, and is NOT covered by
	// the test it is pointed at. It must be reported as a survivor.
	harmless := mutant{
		name: "a comment changes and an unrelated test is named",
		edits: []edit{{
			file: "shared/planeshadow/doc.go",
			from: `// Package planeshadow dual-evaluates`,
			to:   `// Package planeshadow (survivor probe) dual-evaluates`,
		}},
		pkg:  shadowPkg,
		test: "^TestObserveReturnsNothing$",
	}
	overlay := writeMutant(t, root, harmless)
	if out, err := runGo(t, root, []string{"build", "-overlay=" + overlay, shadowPkg}); err != nil {
		t.Fatalf("the probe does not compile, so it proves nothing about the runner:\n%s", out)
	}
	_, err := runGo(t, root, []string{"test", "-count=1", "-overlay=" + overlay, "-run", harmless.test, harmless.pkg})
	if err != nil {
		t.Fatal("the probe mutant FAILED its named test. It is meant to survive, so either " +
			"the probe is no longer harmless or the runner is failing for an unrelated reason " +
			"- and in both cases the survivor branch above is unproven.")
	}
	// The runner would have reported this as a survivor, which is what
	// TestEveryShadowGuardCanFail's err == nil branch does.
}

// TestEveryShadowMutantEditIsUniqueAndPresent is the anchor check, run
// SEPARATELY from the gate so an anchor that has drifted is reported as an
// anchor problem rather than as a survivor.
//
// Zero matches means the code moved and the mutant now tests nothing; more than
// one means the edit is broader than the name claims. Both are silent failures
// of the gate rather than of the tree.
func TestEveryShadowMutantEditIsUniqueAndPresent(t *testing.T) {
	root := moduleRoot(t)
	if len(mutants) == 0 {
		t.Fatal("the mutant list is empty; the gate would pass while testing nothing")
	}
	seen := map[string]bool{}
	for _, m := range mutants {
		if seen[m.name] {
			t.Errorf("two mutants share the name %q; a failure would not say which", m.name)
		}
		seen[m.name] = true
		if len(m.edits) == 0 {
			t.Errorf("mutant %q has no edits", m.name)
		}
		if m.test == "" || !strings.HasPrefix(m.test, "^") {
			t.Errorf("mutant %q names test pattern %q; it must be anchored, or -run would "+
				"match a broader set and a failure elsewhere would read as a kill", m.name, m.test)
		}
		if m.why == "" {
			t.Errorf("mutant %q records no reason; a mutant nobody can explain is one nobody "+
				"can decide to remove", m.name)
		}
		for _, e := range m.edits {
			src, err := os.ReadFile(filepath.Join(root, e.file))
			if err != nil {
				t.Errorf("mutant %q: reading %s: %v", m.name, e.file, err)
				continue
			}
			if n := strings.Count(string(src), e.from); n != 1 {
				t.Errorf("mutant %q: its anchor matches %d times in %s, want exactly 1:\n%s",
					m.name, n, e.file, e.from)
			}
		}
	}
}

// moduleRoot returns the platform module root. This harness lives at
// platform/shared/planeshadow/shadowmutation, so the root is three levels up.
func moduleRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	root := filepath.Clean(filepath.Join(wd, "..", "..", ".."))
	// SYMLINKS ARE RESOLVED, and this is not tidiness.
	//
	// A -overlay entry is matched by the go command against the path it
	// computes for a file, and that path is the physical one. Staging this
	// tree anywhere under a symlinked prefix - /tmp on macOS is a symlink to
	// /private/tmp, which is exactly where the community-mirror simulation
	// stages it - makes every overlay key miss SILENTLY: the build succeeds
	// because the original file is used, the target test passes because
	// nothing was mutated, and the harness reports FOURTEEN SURVIVORS. That
	// is the worst available failure for a mutation gate, because it accuses
	// the guards rather than itself. Measured: every mutant survived on the
	// staged mirror and none did here.
	if resolved, rerr := filepath.EvalSymlinks(root); rerr == nil {
		root = resolved
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("no go.mod at the computed module root %q; this harness's relative path "+
			"assumption is wrong: %v", root, err)
	}
	return root
}

// writeMutant renders every mutated file into a temp dir and returns the path
// of an overlay JSON mapping each original to its mutant. NOTHING ON DISK IS
// MODIFIED.
func writeMutant(t *testing.T, root string, m mutant) string {
	t.Helper()
	dir := t.TempDir()
	replace := map[string]string{}

	// Edits to the SAME file are applied in sequence to one buffer, so a
	// two-edit mutant on one file produces one mutated copy rather than two
	// that overwrite each other - which would silently drop an edit and turn a
	// four-part mutant into a partial one.
	byFile := map[string]string{}
	order := []string{}
	for _, e := range m.edits {
		if _, ok := byFile[e.file]; !ok {
			src, err := os.ReadFile(filepath.Join(root, e.file))
			if err != nil {
				t.Fatalf("read %s: %v", e.file, err)
			}
			byFile[e.file] = string(src)
			order = append(order, e.file)
		}
		cur := byFile[e.file]
		if strings.Count(cur, e.from) != 1 {
			t.Fatalf("the anchor for %q does not match exactly once in %s; see "+
				"TestEveryShadowMutantEditIsUniqueAndPresent", m.name, e.file)
		}
		byFile[e.file] = strings.Replace(cur, e.from, e.to, 1)
	}

	for i, file := range order {
		out := filepath.Join(dir, filepathSafe(file, i))
		if err := os.WriteFile(out, []byte(byFile[file]), 0o600); err != nil {
			t.Fatalf("write mutant: %v", err)
		}
		replace[filepath.Join(root, file)] = out
	}

	overlay, err := json.Marshal(map[string]any{"Replace": replace})
	if err != nil {
		t.Fatalf("marshal overlay: %v", err)
	}
	overlayPath := filepath.Join(dir, "overlay.json")
	if err := os.WriteFile(overlayPath, overlay, 0o600); err != nil {
		t.Fatalf("write overlay: %v", err)
	}
	return overlayPath
}

// filepathSafe renders a repo-relative path as a unique flat filename, keeping
// the .go suffix the toolchain needs.
func filepathSafe(rel string, i int) string {
	return strings.NewReplacer("/", "_", ".", "_").Replace(rel) + "_" + string(rune('a'+i)) + ".go"
}

func runGo(t *testing.T, root string, args []string) (string, error) {
	t.Helper()
	cmd := exec.Command("go", args...)
	cmd.Dir = root
	// GOFLAGS is cleared so an ambient -mod or -tags from the parent run
	// cannot change what the child compiles.
	cmd.Env = append(os.Environ(), "GOFLAGS=")
	out, err := cmd.CombinedOutput()
	return string(out), err
}
