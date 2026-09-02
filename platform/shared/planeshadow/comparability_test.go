// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package planeshadow

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/legacycompile/shadow"
	"axonflow/platform/shared/identity"
)

// TestNotComparableIsNeitherAMatchNorUnexplained is the property that keeps a
// policy edit out of ADR-065 gate 18's numerator AND out of its agreement
// count.
//
// Both wrong readings are available and both are silent. Counting a
// not-comparable pair as a MATCH inflates agreement with comparisons that never
// happened, so a window looks healthier the more often policy is edited.
// Counting it as UNEXPLAINED reds the gate every time an operator saves a
// policy, which trains everyone to ignore the one signal v11 depends on.
func TestNotComparableIsNeitherAMatchNorUnexplained(t *testing.T) {
	// ONE WORKER, and it is load-bearing rather than tidiness.
	//
	// The two observations below are enqueued in order and the assertion is
	// that the FIRST produced nothing. With a pool the second can be recorded
	// while the first is still in flight, so a recorder that stops at the
	// expected count would snapshot before the defect had a chance to appear -
	// and the test would pass against an implementation that compared both.
	// A single worker makes the queue FIFO, so the sentinel arriving proves
	// the stale one is finished.
	cfg := fixtureConfig(identity.CompatModeShadow)
	cfg.Workers = 1
	rec := newCapturingRecorder(1)
	o, _ := newFixtureObserver(t, cfg, rec)

	// A plane that evaluated a version of the row the tables no longer hold.
	stale := fixtureObservation(true, false)
	stale.Rows[0].UpdatedAt = "2020-01-01T00:00:00.000000000Z"
	staleSnapshot := stale.Snapshot()
	o.Observe(context.Background(), stale)

	// Then a comparable one: the sentinel whose arrival proves the stale one
	// has already been through the worker.
	sentinel := fixtureObservation(true, false)
	o.Observe(context.Background(), sentinel)
	got := rec.wait(t)

	for _, c := range got {
		if c.PolicySnapshot == staleSnapshot {
			t.Fatalf("a pair across two policy versions was CLASSIFIED as %s. It is neither a "+
				"match (which would inflate agreement with a comparison that never happened) "+
				"nor unexplained (which would red gate 18 every time an operator saves a "+
				"policy); it is its own counter.", c.Record.Class)
		}
	}
	if len(got) == 0 || got[len(got)-1].PolicySnapshot != sentinel.Snapshot() {
		t.Fatalf("the sentinel comparison was not recorded (%d record(s)); the assertion above "+
			"would then have passed against a shadow that compared nothing at all", len(got))
	}
}

// TestCoversPlaneRowsIsOneDirectional pins exactly which disagreements between
// the plane's set and the read make a pair uncomparable.
func TestCoversPlaneRowsIsOneDirectional(t *testing.T) {
	raw := staticRows(t, fixtureOrg)
	planeRow := RowFact{Table: "static_policies", PolicyID: fixturePolicy, UpdatedAt: fixtureStamp}

	t.Run("the plane's rows all present and unchanged is comparable", func(t *testing.T) {
		if d := coversPlaneRows(raw, []RowFact{planeRow}); d != "" {
			t.Fatalf("a matching set was reported uncomparable: %s", d)
		}
	})

	t.Run("EXTRA rows in the read are fine", func(t *testing.T) {
		// This direction is expected on every request: the plane loads one
		// phase and may narrow by category or by capability scoping, while the
		// read takes the whole table. Those rows reach the ADR-065 side as
		// detectors that did not run, which is exactly what they were.
		wider := append(append([]legacycompile.RawRow(nil), raw...),
			staticFixtureRow(t, "sys_pii_email", fixtureOrg, nil))
		if d := coversPlaneRows(wider, []RowFact{planeRow}); d != "" {
			t.Fatalf("extra rows in the read made the pair uncomparable: %s", d)
		}
	})

	t.Run("a DELETED row is not comparable", func(t *testing.T) {
		d := coversPlaneRows(nil, []RowFact{planeRow})
		if d == "" {
			t.Fatal("a row the plane evaluated and the tables no longer hold was reported comparable")
		}
		if !strings.Contains(d, "deleted") {
			t.Fatalf("the detail does not name the cause: %s", d)
		}
	})

	t.Run("an EDITED row is not comparable", func(t *testing.T) {
		edited := []legacycompile.RawRow{
			staticFixtureRow(t, fixturePolicy, fixtureOrg, map[string]any{"updated_at": "2026-06-01T00:00:00Z"}),
		}
		d := coversPlaneRows(edited, []RowFact{planeRow})
		if d == "" {
			t.Fatal("a row edited between the plane's load and the read was reported comparable")
		}
		if !strings.Contains(d, "edited") {
			t.Fatalf("the detail does not name the cause: %s", d)
		}
	})

	t.Run("an unrenderable version on either side refuses rather than assumes", func(t *testing.T) {
		// The dangerous shape: assuming two unknown versions match would hold
		// most of the time and be invisible when it did not.
		noPlaneStamp := RowFact{Table: "static_policies", PolicyID: fixturePolicy}
		if d := coversPlaneRows(raw, []RowFact{noPlaneStamp}); d == "" {
			t.Fatal("a plane row with no updated_at was reported comparable")
		}
		noRowStamp := []legacycompile.RawRow{
			staticFixtureRow(t, fixturePolicy, fixtureOrg, map[string]any{"updated_at": nil}),
		}
		if d := coversPlaneRows(noRowStamp, []RowFact{planeRow}); d == "" {
			t.Fatal("a read row with a NULL updated_at was reported comparable")
		}
	})

	t.Run("an empty plane set is comparable", func(t *testing.T) {
		// A plane that loaded no policy is a real state (a tenant with none),
		// and it has to be measurable: it is the case where ADR-065's default
		// deny differs most loudly from the legacy engines' permit.
		if d := coversPlaneRows(raw, nil); d != "" {
			t.Fatalf("a plane that loaded no policy was reported uncomparable: %s", d)
		}
	})
}

// TestSnapshotIdentifiesThePolicySet pins the bundle cache key.
func TestSnapshotIdentifiesThePolicySet(t *testing.T) {
	base := fixtureObservation(true, false)

	t.Run("row ORDER does not change the snapshot", func(t *testing.T) {
		two := base
		two.Rows = []RowFact{
			{Table: "static_policies", PolicyID: "a", UpdatedAt: fixtureStamp},
			{Table: "static_policies", PolicyID: "b", UpdatedAt: fixtureStamp},
		}
		reversed := base
		reversed.Rows = []RowFact{two.Rows[1], two.Rows[0]}
		if two.Snapshot() != reversed.Snapshot() {
			t.Fatal("the same policy set in two orders produced two snapshots; every reordering " +
				"would rebuild the bundle and every comparison would be against a fresh engine")
		}
	})

	t.Run("an EDIT changes the snapshot", func(t *testing.T) {
		edited := base
		edited.Rows = []RowFact{{Table: "static_policies", PolicyID: fixturePolicy, UpdatedAt: "2026-06-01T00:00:00.000000000Z"}}
		if base.Snapshot() == edited.Snapshot() {
			t.Fatal("an edited row produced the same snapshot; the cache would serve a bundle " +
				"compiled from the previous version of the policy")
		}
	})

	t.Run("the two TABLES are distinguished", func(t *testing.T) {
		// policy_id is unique within each table and the two tables are
		// independent, so a static row and a dynamic row can share one.
		static := base
		static.Rows = []RowFact{{Table: "static_policies", PolicyID: "shared", UpdatedAt: fixtureStamp}}
		dynamic := base
		dynamic.Rows = []RowFact{{Table: "dynamic_policies", PolicyID: "shared", UpdatedAt: fixtureStamp}}
		if static.Snapshot() == dynamic.Snapshot() {
			t.Fatal("two rows sharing a policy_id across the two tables produced one snapshot")
		}
	})

	t.Run("the encoding is unambiguous", func(t *testing.T) {
		// policy_id is VARCHAR(100) with no character constraint, so any
		// delimiter is a character an id may contain. Two different sets must
		// not encode identically through one.
		a := base
		a.Rows = []RowFact{{Table: "static_policies", PolicyID: "x|y", UpdatedAt: fixtureStamp}}
		b := base
		b.Rows = []RowFact{{Table: "static_policies", PolicyID: "x", UpdatedAt: "y|" + fixtureStamp}}
		if a.Snapshot() == b.Snapshot() {
			t.Fatal("two different policy sets encoded to one snapshot through a delimiter " +
				"appearing inside a policy_id")
		}
	})
}

// TestErrNotComparableIsDistinguishable proves the worker can tell an ordinary
// policy edit from a real failure, which is what keeps the two on separate
// counters.
func TestErrNotComparableIsDistinguishable(t *testing.T) {
	err := error(&ErrNotComparable{Detail: "edited"})
	var nc *ErrNotComparable
	if !errors.As(err, &nc) {
		t.Fatal("ErrNotComparable does not match errors.As; the worker would count a routine " +
			"policy edit as an evaluation failure")
	}
	if !errors.As(fmtWrap(err), &nc) {
		t.Fatal("ErrNotComparable does not survive wrapping")
	}
}

func fmtWrap(err error) error { return errors.Join(errors.New("context"), err) }

// TestTheCaseCarriesTheTriState is the heart of the ADR-065 correction, on the
// runtime path.
//
// Three states, three different meanings, and the one that matters is the
// difference between "ran and did not match" and "did not run". Collapsing them
// is a fail-open on every request a category filter or capability scoping
// narrowed - and it is invisible, because both produce a permit.
func TestTheCaseCarriesTheTriState(t *testing.T) {
	opts := legacycompile.Options{}

	t.Run("ran and matched is KNOWN true", func(t *testing.T) {
		c := caseFor(withRow(RowFact{Table: "static_policies", PolicyID: "p", Ran: true, Matched: true}), "id", opts)
		if got, ok := c.DetectorVerdicts["p"]; !ok || !got {
			t.Fatalf("DetectorVerdicts[p] = %v, %v; want true, true", got, ok)
		}
	})

	t.Run("ran and did NOT match is KNOWN false", func(t *testing.T) {
		c := caseFor(withRow(RowFact{Table: "static_policies", PolicyID: "p", Ran: true}), "id", opts)
		got, ok := c.DetectorVerdicts["p"]
		if !ok {
			t.Fatal("a detector that ran and did not match is ABSENT from the verdicts, which " +
				"makes it unknown on the ADR-065 side. The legacy engine looked and found " +
				"nothing; that is a known false.")
		}
		if got {
			t.Fatal("a detector that did not match reported true")
		}
	})

	t.Run("did not run is ABSENT, which is UNKNOWN", func(t *testing.T) {
		c := caseFor(withRow(RowFact{Table: "static_policies", PolicyID: "p"}), "id", opts)
		if _, ok := c.DetectorVerdicts["p"]; ok {
			t.Fatal("a detector that never ran was given a verdict. Writing false here tells " +
				"the PDP a skipped detector positively did not match, which is the one thing " +
				"ADR-065's tri-state exists to stop.")
		}
	})

	t.Run("a dynamic row's verdict lands on its content detector path", func(t *testing.T) {
		c := caseFor(withRow(RowFact{Table: "dynamic_policies", PolicyID: "d", Ran: true, Matched: true}), "id", opts)
		path := legacycompile.DynamicContentDetectorPath("d")
		if got, ok := c.ContentVerdicts[path]; !ok || !got {
			t.Fatalf("ContentVerdicts[%s] = %v, %v; want true, true", path, got, ok)
		}
		if _, wrong := c.DetectorVerdicts["d"]; wrong {
			t.Fatal("a dynamic row was recorded as a static detector")
		}
	})
}

// TestUnresolvedSegmentsAreNotAnEmptyClosure pins #3482's class.
//
// An empty group closure is a RESOLVED fact that excludes every segment-scoped
// policy. A FAILURE to resolve is not, and presenting it as one silently drops
// every segment-scoped constraint from the ADR-065 side while the legacy engine
// still applies it - a fail-open, in the direction gate 18 exists to find.
func TestUnresolvedSegmentsAreNotAnEmptyClosure(t *testing.T) {
	opts := legacycompile.Options{}

	resolved := caseFor(fixtureObservation(true, false), "id", opts)
	if attr, ok := resolved.PrincipalAttributes["principal.groups"]; ok && attr != nil {
		t.Fatalf("a resolved (empty) closure supplied an override attribute %+v; it must reach "+
			"the request as a KNOWN empty array, which is what excludes segment-scoped policies", *attr)
	}

	obs := fixtureObservation(true, false)
	obs.SegmentsUnresolved = true
	obs.Groups = []string{"grp_finance"}
	unresolved := caseFor(obs, "id", opts)
	attr, ok := unresolved.PrincipalAttributes["principal.groups"]
	if !ok || attr == nil {
		t.Fatal("an unresolved closure did not override principal.groups; it would reach the " +
			"PDP as a resolved empty set and silently exclude every segment-scoped constraint")
	}
	if attr.State != contract.StateUnknown {
		t.Fatalf("an unresolved closure reached the request in state %v; it must be UNKNOWN, "+
			"because unknown cannot permit and a resolved empty set can", attr.State)
	}
	if len(unresolved.Groups) != 0 {
		t.Fatal("the case still carries a group list beside the unknown attribute; the two " +
			"would disagree about what the resolver said")
	}
}

// TestLegacyVerdictIsTheRealOutcome is what keeps shadow.ModelLimitations item
// 1 - community mode turning require_approval into ALLOW while the offline
// model reports a deny - out of the runtime path by construction.
func TestLegacyVerdictIsTheRealOutcome(t *testing.T) {
	// A row whose ACTION is require_approval, on a plane that ALLOWED the
	// request. That is precisely the community-mode shape, and an
	// actions-derived state would report a deny the running system never
	// issued.
	obs := Observation{
		Plane:  legacycompile.PlaneGatewayRequest,
		Legacy: LegacyOutcome{Executable: true},
		Rows: []RowFact{{
			Table: "static_policies", PolicyID: "hitl", UpdatedAt: fixtureStamp,
			Ran: true, Matched: true, Action: "require_approval",
		}},
	}
	v := legacyVerdictFor(obs, "response.content")
	if !v.Executable || v.State != contract.StateAllow {
		t.Fatalf("legacy verdict = executable %v state %v; the plane ALLOWED the request and "+
			"the verdict must say so, whatever the row's action column reads",
			v.Executable, v.State)
	}
	// The action still reaches the classifier as an EFFECT, so the difference
	// against ADR-065's challenge is visible - it is just not invented into an
	// outcome the running system did not produce.
	if len(v.Effects) != 1 || !strings.Contains(v.Effects[0], "require_approval") {
		t.Fatalf("effects = %v; the row's action must still be attributed", v.Effects)
	}

	blocked := obs
	blocked.Legacy.Executable = false
	bv := legacyVerdictFor(blocked, "response.content")
	if bv.Executable || bv.State != contract.StateDeny {
		t.Fatalf("a blocked request produced executable %v state %v", bv.Executable, bv.State)
	}
}

// TestARedactionWithNoStoredTargetTakesTheConfiguredRoot pins that BOTH sides
// are given the same content root.
func TestARedactionWithNoStoredTargetTakesTheConfiguredRoot(t *testing.T) {
	obs := Observation{
		Plane:  legacycompile.PlaneMCP,
		Legacy: LegacyOutcome{Executable: true},
		Rows: []RowFact{{
			Table: "static_policies", PolicyID: "pii", UpdatedAt: fixtureStamp,
			Ran: true, Matched: true, Action: "redact",
		}},
	}
	v := legacyVerdictFor(obs, "response.content")
	if len(v.Effects) != 1 || !strings.Contains(v.Effects[0], "target=response.content") {
		t.Fatalf("effects = %v; a static redaction stores no field path, so the target must "+
			"come from the compilation options both sides share", v.Effects)
	}

	// A stored target is NOT overridden.
	withTarget := obs
	withTarget.Rows[0].Target = "rows[0].ssn"
	tv := legacyVerdictFor(withTarget, "response.content")
	if !strings.Contains(tv.Effects[0], "target=rows[0].ssn") {
		t.Fatalf("effects = %v; a stored target was replaced by the configured root", tv.Effects)
	}
}

// TestAMatchedRowWithNoActionContributesNoEffect pins a real legacy shape.
//
// An action type the engine's switch has no arm for applies nothing - migration
// 036's "warn" was inert for exactly that reason. The row still DETERMINED the
// outcome, so it stays in the determining set; inventing an effect for it would
// make the correspondence table answer for a control the running system never
// applied.
func TestAMatchedRowWithNoActionContributesNoEffect(t *testing.T) {
	obs := Observation{
		Plane:  legacycompile.PlaneWCP,
		Legacy: LegacyOutcome{Executable: true},
		Rows: []RowFact{{
			Table: "dynamic_policies", PolicyID: "inert", UpdatedAt: fixtureStamp,
			Ran: true, Matched: true,
		}},
	}
	v := legacyVerdictFor(obs, "response.content")
	if len(v.Effects) != 0 {
		t.Fatalf("effects = %v; a row that resolved to nothing must contribute none", v.Effects)
	}
	if len(shadow.SourceDetermining(v)) != 1 {
		t.Fatalf("determining = %v; a row that fired is still determining", shadow.SourceDetermining(v))
	}
}

// TestPostureDropsAnUninterpretableAction pins the conservative direction.
func TestPostureDropsAnUninterpretableAction(t *testing.T) {
	got := posture(map[string]string{"pii-us": "redact", "security-sqli": "teleport"})
	if got["pii-us"] != legacycompile.ActionRedact {
		t.Fatalf("a known action was dropped: %+v", got)
	}
	if _, present := got["security-sqli"]; present {
		t.Fatal("an action the compiler cannot interpret was carried into the posture. The " +
			"lever DISPLACES a stored action, so carrying an uninterpretable value would " +
			"replace a known action with one nothing can read.")
	}
	if posture(nil) != nil {
		t.Fatal("an empty posture map produced a non-nil posture; an absent lever and a lever " +
			"set to nothing are different facts")
	}
}

// TestStampKeyCollapsesBothSpellingsOfOneInstant is the property that stops
// every comparison being permanently not-comparable.
//
// Postgres renders a timestamptz through row_to_json one way and database/sql
// hands a Go caller a time.Time it formats another. Two spellings of one
// instant must produce ONE key, or the denominator is permanently empty behind
// a gate that reads as healthy zero-unexplained.
func TestStampKeyCollapsesBothSpellingsOfOneInstant(t *testing.T) {
	instant := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fromGo := StampKey(instant)
	for _, wire := range []string{
		"2026-01-01T00:00:00Z",
		"2026-01-01T00:00:00.000Z",
		"2026-01-01T00:00:00+00:00",
		"2026-01-01T01:00:00+01:00",
	} {
		if got := normalizeStamp(wire); got != fromGo {
			t.Errorf("normalizeStamp(%q) = %q but StampKey of the same instant is %q; the two "+
				"sides of a snapshot key would never match and every comparison would be "+
				"permanently not-comparable", wire, got, fromGo)
		}
	}
	if StampKey(time.Time{}) != "" {
		t.Error("the zero time rendered a non-empty key; an unknown version must refuse rather " +
			"than compare equal to another unknown version")
	}
	// An unparseable stamp is returned rather than dropped: it still
	// distinguishes two versions of a row, and dropping it would make an
	// edited row compare equal to its previous version.
	if normalizeStamp("not-a-time") != "not-a-time" {
		t.Error("an unparseable stamp was dropped rather than carried")
	}
}

// withRow builds a minimal observation carrying one row fact.
func withRow(r RowFact) Observation {
	return Observation{Plane: legacycompile.PlaneGatewayRequest, Rows: []RowFact{r}}
}

// TestTheRequestNamesTheRegisteredAction pins the defect the R3 round-1 probe
// uncovered, which would have made the entire production window unreadable.
//
// A compiled world registers exactly ONE action (shadow.ActionID), because the
// legacy static substrate is content inspection that applies to every request
// on its plane and the dynamic substrate selects on request attributes rather
// than on a registered action. An ADR-065 request naming anything else hits an
// UNREGISTERED action and is denied for unknown_action, with an empty
// determining set - so nothing explains it and it classifies UNEXPLAINED.
//
// Every production call site passes a tool identity
// (EvalOptions.ToolIdentity, OrchestratorRequest.RequestType). MEASURED before
// the fix: an observation carrying "postgres.query" classified UNEXPLAINED
// whatever its detectors had done, while the identical observation with no
// action classified `match` and `expected_change/EC2` correctly.
func TestTheRequestNamesTheRegisteredAction(t *testing.T) {
	t.Run("the case addresses the registered action, whatever the plane reported", func(t *testing.T) {
		for _, tool := range []string{"", "postgres.query", "claude_code.mcp__atlassian__editJiraIssue"} {
			obs := fixtureObservation(true, false)
			obs.Action = tool
			c := caseFor(obs, "id", legacycompile.Options{})
			if c.Action != shadow.ActionID {
				t.Fatalf("a plane reporting tool %q produced a request naming action %q. The "+
					"compiled world registers only %q, so this is denied for unknown_action "+
					"with an empty determining set and classifies UNEXPLAINED - on every "+
					"request, which is the whole window.", tool, c.Action, shadow.ActionID)
			}
		}
	})

	t.Run("a tool identity classifies the same as no tool identity", func(t *testing.T) {
		// The behavioural half, and the one that would have caught this
		// without anyone thinking to look at the action id: the SAME
		// evaluation must classify the same whether or not the plane happened
		// to report a tool.
		classify := func(tool string) shadow.Classification {
			rec := newCapturingRecorder(1)
			o, _ := newFixtureObserver(t, fixtureConfig(identity.CompatModeShadow), rec)
			obs := fixtureObservation(true, false)
			obs.Action = tool
			o.Observe(context.Background(), obs)
			return rec.wait(t)[0].Record.Class
		}
		withTool, withoutTool := classify("postgres.query"), classify("")
		if withTool != withoutTool {
			t.Fatalf("the same evaluation classified %q with a tool identity and %q without one. "+
				"The tool a plane reports must not change what the two engines are asked.",
				withTool, withoutTool)
		}
	})

	t.Run("the tool identity is still recorded for attribution", func(t *testing.T) {
		// It must not be silently discarded either: an operator triaging a
		// difference needs to know which tool it came from.
		rec := newCapturingRecorder(1)
		o, _ := newFixtureObserver(t, fixtureConfig(identity.CompatModeShadow), rec)
		obs := fixtureObservation(true, false)
		obs.Action = "postgres.query"
		o.Observe(context.Background(), obs)
		if got := rec.wait(t)[0].Tool; got != "postgres.query" {
			t.Fatalf("the comparison records tool %q; a difference could not be traced to the "+
				"tool it came from", got)
		}
	})
}
