package registry

import (
	"strings"
	"testing"
	"time"

	"axonflow/platform/decision/contract"
)

// TestBothPostureAxesAreMandatory is AXC-315.
func TestBothPostureAxesAreMandatory(t *testing.T) {
	MarkConformanceCase("AXC-315")

	// The counterfactual first: the same record with both axes declared is
	// accepted. Without it, a rule that refused every action would pass every
	// case below.
	c := newFixtureCatalog(t)
	accepted(t, c.RegisterAction(sampleAction("docs.read")))

	for name, posture := range map[string]Posture{
		"neither axis":  {},
		"no unmatched":  {OnError: contract.AuthzIndeterminate},
		"no on_error":   {Unmatched: contract.AuthzNotApplicable},
		"empty strings": {Unmatched: "", OnError: ""},
	} {
		t.Run(name, func(t *testing.T) {
			cat := newFixtureCatalog(t)
			a := sampleAction("docs.partial")
			a.Posture = posture
			err := cat.RegisterAction(a)
			refusal(t, err, CodePostureNotDeclared)
			// The message names the axis, because "the posture is incomplete"
			// sends the operator back to read both fields.
			if posture.Unmatched == "" && !strings.Contains(err.Error(), "unmatched") {
				t.Errorf("the refusal does not name the unmatched axis: %v", err)
			}
			if posture.OnError == "" && !strings.Contains(err.Error(), "on_error") {
				t.Errorf("the refusal does not name the on_error axis: %v", err)
			}
			// And the refused record is not in the catalog, so the projection
			// cannot carry it. That the projection ALSO refuses a catalog
			// carrying such a record, however it got there, is AXC-319.
			if _, ok := cat.Action(a.ID); ok {
				t.Fatalf("the refused action %q is in the catalog", a.ID)
			}
		})
	}
}

// TestUnmatchedPostureCannotForgeAnExplicitConstraint is AXC-320.
func TestUnmatchedPostureCannotForgeAnExplicitConstraint(t *testing.T) {
	MarkConformanceCase("AXC-320")

	c := newFixtureCatalog(t)
	a := sampleAction("docs.denyseed")
	a.Posture = Posture{Unmatched: contract.AuthzDeny, OnError: contract.AuthzIndeterminate}
	err := c.RegisterAction(a)
	refusal(t, err, CodePostureNotPermitted)
	if !strings.Contains(err.Error(), string(contract.AuthzNotApplicable)) {
		t.Fatalf("the refusal does not name the fail-closed value it wants instead: %v", err)
	}

	// The fail-closed seed IS accepted, and it is a different value from deny.
	// Both reach StateDeny, which is the point: the choice costs nothing
	// operationally and preserves which of the two happened.
	clean := newFixtureCatalog(t)
	accepted(t, clean.RegisterAction(sampleAction("docs.closed")))
	state, stateErr := contract.StateFor(contract.AuthzNotApplicable, false)
	if stateErr != nil {
		t.Fatalf("mapping not_applicable: %v", stateErr)
	}
	if state != contract.StateDeny {
		t.Fatalf("the fail-closed unmatched seed maps to %q, expected %q", state, contract.StateDeny)
	}

	// An outcome that is not one of the four at all is refused as an undeclared
	// outcome rather than as a policy choice, so a typo does not read as a
	// deliberate setting the registry disagreed with.
	bogus := newFixtureCatalog(t)
	b := sampleAction("docs.bogus")
	b.Posture = Posture{Unmatched: contract.Authorization("mostly"), OnError: contract.AuthzIndeterminate}
	bogusErr := bogus.RegisterAction(b)
	refusal(t, bogusErr, CodePostureNotPermitted)
	if !strings.Contains(bogusErr.Error(), "is not a declared outcome") {
		t.Fatalf("an undeclared outcome was reported as a disallowed axis value: %v", bogusErr)
	}
}

// TestPermissivePostureNeedsALiveException is AXC-316.
func TestPermissivePostureNeedsALiveException(t *testing.T) {
	MarkConformanceCase("AXC-316")

	permissive := func(name string) ActionRecord {
		a := sampleAction(name)
		a.Posture = Posture{Unmatched: contract.AuthzPermit, OnError: contract.AuthzIndeterminate}
		return a
	}

	t.Run("no exception at all", func(t *testing.T) {
		c := newFixtureCatalog(t)
		refusal(t, c.RegisterAction(permissive("legacy.list")), CodePostureCompatibilityRequired)
	})

	for field, mutate := range map[string]func(*CompatibilityException){
		"owner":         func(e *CompatibilityException) { e.Owner = "" },
		"metric":        func(e *CompatibilityException) { e.Metric = "" },
		"removal issue": func(e *CompatibilityException) { e.RemovalIssue = "" },
	} {
		t.Run("an exception with no "+field, func(t *testing.T) {
			c := newFixtureCatalog(t)
			e := completeException(actionID("legacy.list"))
			mutate(&e)
			// The incomplete exception is refused at ITS registration, which is
			// the earliest point it can be, so the action is then refused for
			// having no exception at all.
			refusal(t, c.RegisterCompatibilityException(e), CodeCompatibilityIncomplete)
			refusal(t, c.RegisterAction(permissive("legacy.list")), CodePostureCompatibilityRequired)
		})
	}

	t.Run("an expired exception", func(t *testing.T) {
		c := newFixtureCatalog(t)
		e := completeException(actionID("legacy.list"))
		e.ExpiresAt = fixtureNow.Add(-time.Hour)
		refusal(t, c.RegisterCompatibilityException(e), CodeCompatibilityExpired)
	})

	t.Run("a complete live exception is accepted", func(t *testing.T) {
		c := newFixtureCatalog(t)
		accepted(t, c.RegisterCompatibilityException(completeException(actionID("legacy.list"))))
		accepted(t, c.RegisterAction(permissive("legacy.list")))
		// Registering the exception is itself an alarm: it is the only
		// sanctioned deviation from default deny.
		if !c.Events().Alarms().Has(EventCompatibilityRegistered, actionID("legacy.list").String()) {
			t.Fatalf("registering a compatibility exception raised no alarm: %v", c.Events())
		}
		// And it reaches the engine's compatibility profile, so the exception
		// the registry governs and the one an evaluation honours are one set.
		profile := c.CompatibilityProfile()
		if profile == nil || len(profile.Entries) != 1 {
			t.Fatalf("the compatibility profile does not carry the exception: %#v", profile)
		}
	})

	t.Run("an exception on a fail-closed action does not arm anything", func(t *testing.T) {
		c := newFixtureCatalog(t)
		accepted(t, c.RegisterCompatibilityException(completeException(actionID("docs.search"))))
		// docs.search declares the fail-closed posture, so the exception is
		// inert. Projecting it anyway would arm a fail-open the action does not
		// ask for.
		if profile := c.CompatibilityProfile(); profile != nil {
			t.Fatalf("an exception on a fail-closed action reached the compatibility profile: %#v", profile)
		}
	})
}

// TestCompatibilityPostureIsUnavailableForHighRiskActions is AXC-317.
func TestCompatibilityPostureIsUnavailableForHighRiskActions(t *testing.T) {
	MarkConformanceCase("AXC-317")

	for name, mutate := range map[string]func(*Effects){
		"privileged":   func(e *Effects) { e.Privileged = DeclarationYes },
		"irreversible": func(e *Effects) { e.Irreversible = DeclarationYes },
		"data egress":  func(e *Effects) { e.DataEgress = DeclarationYes },
	} {
		t.Run(name, func(t *testing.T) {
			c := newFixtureCatalog(t)
			accepted(t, c.RegisterCompatibilityException(completeException(actionID("legacy.risky"))))
			a := sampleAction("legacy.risky")
			a.Posture = Posture{Unmatched: contract.AuthzPermit, OnError: contract.AuthzIndeterminate}
			effects := failClosedEffects()
			mutate(&effects)
			a.Effects = effects
			refusal(t, c.RegisterAction(a), CodePostureCompatibilityIneligible)
		})
	}

	t.Run("spend alone does not make it ineligible", func(t *testing.T) {
		// ADR-065 names privileged, irreversible and data-egress. Spend is a
		// risk class the policy set reads and not one of the three, and
		// widening the refusal beyond what the ADR says would be this package
		// legislating.
		c := newFixtureCatalog(t)
		accepted(t, c.RegisterCompatibilityException(completeException(actionID("legacy.spendy"))))
		a := sampleAction("legacy.spendy")
		a.Posture = Posture{Unmatched: contract.AuthzPermit, OnError: contract.AuthzIndeterminate}
		effects := failClosedEffects()
		effects.Spend = DeclarationYes
		a.Effects = effects
		accepted(t, c.RegisterAction(a))
	})
}

// TestPermissiveErrorPostureHasNoExceptionPath is AXC-318.
func TestPermissiveErrorPostureHasNoExceptionPath(t *testing.T) {
	MarkConformanceCase("AXC-318")

	for name, withException := range map[string]bool{
		"with no exception":         false,
		"with a complete exception": true,
	} {
		t.Run(name, func(t *testing.T) {
			c := newFixtureCatalog(t)
			if withException {
				accepted(t, c.RegisterCompatibilityException(completeException(actionID("legacy.failopen"))))
			}
			a := sampleAction("legacy.failopen")
			a.Posture = Posture{Unmatched: contract.AuthzNotApplicable, OnError: contract.AuthzPermit}
			err := c.RegisterAction(a)
			refusal(t, err, CodePostureNotPermitted)
			if !strings.Contains(err.Error(), "under any exception") {
				t.Fatalf("the refusal does not say the exception path is closed: %v", err)
			}
		})
	}
}

// TestPostureValidationIsIndependentOfAxisOrder proves the two axes are
// checked independently, which is the property that makes them two fields.
//
// A single validator that stopped at the first bad axis would report one defect
// where there are two, and an operator would fix one, re-register, and be
// refused again.
func TestPostureValidationIsIndependentOfAxisOrder(t *testing.T) {
	f := Posture{}.Validate("subject")
	var unmatched, onError int
	for _, one := range f {
		if strings.Contains(one.Message, "unmatched") {
			unmatched++
		}
		if strings.Contains(one.Message, "on_error") {
			onError++
		}
	}
	if unmatched == 0 || onError == 0 {
		t.Fatalf("an empty posture produced findings for %d unmatched and %d on_error axes: %v", unmatched, onError, f)
	}
}
