package registry

import (
	"strings"
	"testing"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// TestActionWithAnUndeclaredRequiredArgumentIsRefused is AXC-303.
func TestActionWithAnUndeclaredRequiredArgumentIsRefused(t *testing.T) {
	MarkConformanceCase("AXC-303")

	c := newFixtureCatalog(t)
	a := sampleAction("crm.get_contact")
	a.Arguments = map[string]pdp.ValueType{"contact_id": pdp.TypeString}
	a.RequiredArguments = []string{"contact_id", "tenant_id"}
	err := c.RegisterAction(a)
	refusal(t, err, CodeArgumentNotDeclared)
	if !strings.Contains(err.Error(), "tenant_id") {
		t.Fatalf("the refusal does not name the undeclared argument: %v", err)
	}

	// This matters because of what admission does with it: a required argument
	// the schema never declared is reported to every caller as a schema
	// violation, so the caller is blamed for a registry defect.
	a.RequiredArguments = []string{"contact_id"}
	accepted(t, c.RegisterAction(a))

	// An argument declaring a value type the admission validator cannot check
	// is refused for the same reason: pdp.valueMatchesType treats an
	// unrecognized type as a mismatch, so every call would be a schema
	// violation and the schema would never be named.
	bogus := sampleAction("crm.bogus")
	bogus.Arguments = map[string]pdp.ValueType{"contact_id": pdp.ValueType("uuid")}
	bogus.RequiredArguments = nil
	refusal(t, c.RegisterAction(bogus), CodeArgumentNotDeclared)
}

// TestEveryRiskClassIsDeclared is AXC-326.
func TestEveryRiskClassIsDeclared(t *testing.T) {
	MarkConformanceCase("AXC-326")

	for name, mutate := range map[string]func(*Effects){
		"irreversible": func(e *Effects) { e.Irreversible = DeclarationUnspecified },
		"spend":        func(e *Effects) { e.Spend = DeclarationUnspecified },
		"data egress":  func(e *Effects) { e.DataEgress = DeclarationUnspecified },
		"privileged":   func(e *Effects) { e.Privileged = DeclarationUnspecified },
	} {
		t.Run("an unspecified "+name, func(t *testing.T) {
			c := newFixtureCatalog(t)
			a := sampleAction("crm.partial")
			effects := failClosedEffects()
			mutate(&effects)
			a.Effects = effects
			err := c.RegisterAction(a)
			refusal(t, err, CodeEffectNotDeclared)
			if !strings.Contains(err.Error(), "permissive answer") {
				t.Fatalf("the refusal does not say why an unfilled class is dangerous: %v", err)
			}
		})
	}

	// An out-of-range value is refused too, not just the zero value. A check
	// written as d != DeclarationUnspecified would accept every one of these.
	for _, d := range []Declaration{Declaration(99), Declaration(-1), Declaration(3)} {
		c := newFixtureCatalog(t)
		a := sampleAction("crm.outofrange")
		effects := failClosedEffects()
		effects.Privileged = d
		a.Effects = effects
		refusal(t, c.RegisterAction(a), CodeEffectNotDeclared)
		if d.Yes() {
			t.Errorf("Declaration(%d) reported itself an explicit yes", int(d))
		}
		if d.IsValid() {
			t.Errorf("Declaration(%d) reported itself a declared member", int(d))
		}
	}

	c := newFixtureCatalog(t)
	accepted(t, c.RegisterAction(sampleAction("crm.complete")))
}

// TestDelegationDepthMustBePositive proves the registry refuses what admission
// would otherwise have to.
func TestDelegationDepthMustBePositive(t *testing.T) {
	c := newFixtureCatalog(t)
	for _, depth := range []int{0, -1} {
		a := sampleAction("crm.unbounded")
		a.MaxDelegationDepth = depth
		refusal(t, c.RegisterAction(a), CodeDelegationDepthNotDeclared)
	}
	accepted(t, c.RegisterAction(sampleAction("crm.bounded")))
}

// TestActionIdentifierKindIsChecked proves a record cannot carry an identifier
// of the wrong kind, which would make the catalog key something no request
// looks up.
func TestActionIdentifierKindIsChecked(t *testing.T) {
	c := newFixtureCatalog(t)
	a := sampleAction("crm.wrongkind")
	a.ID = contract.MustParseID(contract.KindTool, "Tool::crm.wrongkind")
	refusal(t, c.RegisterAction(a), CodeIdentifierInvalid)

	tool := sampleTool("crm.wrongkind", "docs.search")
	tool.ID = contract.MustParseID(contract.KindAction, "Action::crm.wrongkind")
	refusal(t, c.RegisterTool(tool), CodeIdentifierInvalid)
}

// TestRequiredCapabilitiesAreValidated proves an action's own capability floor
// cannot name an obligation type the contract does not declare, or a version
// that matches only an unset one.
func TestRequiredCapabilitiesAreValidated(t *testing.T) {
	c := newFixtureCatalog(t)
	a := sampleAction("crm.floor")
	a.RequiredCapabilities = []contract.Capability{{Type: contract.ObligationType("invented"), Version: 1}}
	refusal(t, c.RegisterAction(a), CodeObligationTypeUndeclared)

	a.RequiredCapabilities = []contract.Capability{{Type: contract.ObFieldRedact, Version: 0}}
	refusal(t, c.RegisterAction(a), CodeCapabilityVersionInvalid)

	a.RequiredCapabilities = []contract.Capability{{Type: contract.ObFieldRedact, Version: 1}}
	accepted(t, c.RegisterAction(a))
}
