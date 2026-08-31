package registry

import (
	"strings"
	"testing"

	"axonflow/platform/decision/contract"
)

// TestEnforcementPointRealmMustBeDeclared is AXC-309.
func TestEnforcementPointRealmMustBeDeclared(t *testing.T) {
	MarkConformanceCase("AXC-309")

	c := newFixtureCatalog(t)
	accepted(t, c.RegisterPEP(samplePEP("gateway", EditionEnterprise,
		contract.Capability{Type: contract.ObImmutableAudit, Version: 1})))

	undeclared := samplePEP("stray", EditionEnterprise)
	undeclared.Realm = "realm_nobody_declared"
	refusal(t, c.RegisterPEP(undeclared), CodeUnknownRealm)

	none := samplePEP("anonymous", EditionEnterprise)
	none.Realm = ""
	err := c.RegisterPEP(none)
	refusal(t, err, CodeUnknownRealm)
	if !strings.Contains(err.Error(), "scoped to by any policy") {
		t.Fatalf("the refusal does not say why a realmless plane is useless: %v", err)
	}

	// An unset edition is refused for the same class of reason: it is a fact
	// about the enforcement point that decides which obligations it may be
	// sent, and nobody declared it.
	noEdition := samplePEP("editionless", EditionUnspecified)
	refusal(t, c.RegisterPEP(noEdition), CodeEditionNotDeclared)
	for _, e := range []Edition{Edition(99), Edition(-1)} {
		refusal(t, c.RegisterPEP(samplePEP("bogus", e)), CodeEditionNotDeclared)
	}
}

// TestCapabilityCheckRefusesAnUnsupportedType is AXC-310.
func TestCapabilityCheckRefusesAnUnsupportedType(t *testing.T) {
	MarkConformanceCase("AXC-310")

	c := newFixtureCatalog(t)
	accepted(t, c.RegisterPEP(samplePEP("gateway", EditionEnterprise,
		contract.Capability{Type: contract.ObImmutableAudit, Version: 1},
		contract.Capability{Type: contract.ObFieldRedact, Version: 1})))

	// The counterfactual: an advertised type at the advertised version.
	ok := c.SupportsObligation("gateway", obligation(contract.ObFieldRedact, 1, true))
	if !ok.Supported() || ok.Status != CapabilitySupported {
		t.Fatalf("an advertised capability was refused: %#v", ok)
	}

	got := c.SupportsObligation("gateway", obligation(contract.ObStepUpAuth, 1, true))
	if got.Supported() {
		t.Fatalf("an unadvertised obligation type was supported: %#v", got)
	}
	if got.Status != CapabilityTypeUnsupported {
		t.Fatalf("an unadvertised type answered %s", got.Status)
	}

	// An obligation whose own version is unset matches nothing, rather than
	// matching a capability whose version is also unset.
	unversioned := c.SupportsObligation("gateway", obligation(contract.ObFieldRedact, 0, true))
	if unversioned.Supported() || unversioned.Status != CapabilityObligationUnversioned {
		t.Fatalf("an unversioned obligation answered %#v", unversioned)
	}
}

// TestCapabilityCheckMatchesTheVersionExactly is AXC-311.
func TestCapabilityCheckMatchesTheVersionExactly(t *testing.T) {
	MarkConformanceCase("AXC-311")

	c := newFixtureCatalog(t)
	accepted(t, c.RegisterPEP(samplePEP("gateway", EditionEnterprise,
		contract.Capability{Type: contract.ObFieldRedact, Version: 2})))

	older := c.SupportsObligation("gateway", obligation(contract.ObFieldRedact, 1, true))
	if older.Supported() {
		t.Fatalf("a v2 enforcement point satisfied a v1 obligation: %#v", older)
	}
	if older.Status != CapabilityVersionUnsupported {
		t.Fatalf("a version mismatch answered %s", older.Status)
	}
	if !strings.Contains(older.Detail, "[2]") {
		t.Fatalf("the detail does not name the versions actually advertised: %s", older.Detail)
	}

	// And the other direction, which is the one a rolling deploy hits: a v1
	// enforcement point does not satisfy a v2 obligation.
	c2 := newFixtureCatalog(t)
	accepted(t, c2.RegisterPEP(samplePEP("gateway", EditionEnterprise,
		contract.Capability{Type: contract.ObFieldRedact, Version: 1})))
	newer := c2.SupportsObligation("gateway", obligation(contract.ObFieldRedact, 2, true))
	if newer.Supported() || newer.Status != CapabilityVersionUnsupported {
		t.Fatalf("a v1 enforcement point satisfied a v2 obligation: %#v", newer)
	}

	// A capability advertised at a non-positive version is refused at
	// registration, so the two unset values can never agree.
	refusal(t, c.RegisterPEP(samplePEP("zero", EditionEnterprise,
		contract.Capability{Type: contract.ObFieldRedact, Version: 0})), CodeCapabilityVersionInvalid)
}

// TestAbsentRecordIsDistinguishableFromDeclaredEmpty is AXC-312.
//
// This is the correction to the #2958 fulfillment handshake, whose capability
// list is an omitempty field: an enforcement point advertising an empty set is
// byte-identical on the wire to one that advertised nothing, and both read as
// "legacy caller". That is defensible where the enforcement point fails closed
// on an obligation it cannot fulfil, and it is not defensible for audit or
// notification, where failing to discharge is silent.
func TestAbsentRecordIsDistinguishableFromDeclaredEmpty(t *testing.T) {
	MarkConformanceCase("AXC-312")

	c := newFixtureCatalog(t)
	accepted(t, c.RegisterPEP(samplePEP("simulation", EditionEnterprise)))

	o := obligation(contract.ObImmutableAudit, 1, true)

	absent := c.SupportsObligation("never-registered", o)
	declaredNone := c.SupportsObligation("simulation", o)

	if absent.Status == declaredNone.Status {
		t.Fatalf("an absent record and a declared-empty set share status %s", absent.Status)
	}
	if absent.Status != CapabilityNoRecord {
		t.Fatalf("an absent record answered %s", absent.Status)
	}
	if declaredNone.Status != CapabilityDeclaredNone {
		t.Fatalf("a declared-empty set answered %s", declaredNone.Status)
	}
	// Both refuse. The distinction is in the explanation, not in the outcome:
	// one enforcement point never told us anything, the other told us it can
	// do nothing, and ADR-065 invariant 8 denies on either.
	if absent.Supported() || declaredNone.Supported() {
		t.Fatalf("one of the two not-knowing states admitted the obligation")
	}
	// And the lookup itself keeps the distinction, so a caller that wants it
	// does not have to infer it from a zero value.
	if _, found := c.PEP("never-registered"); found {
		t.Fatalf("an unregistered enforcement point was found")
	}
	rec, found := c.PEP("simulation")
	if !found {
		t.Fatalf("a registered enforcement point was not found")
	}
	if len(rec.Capabilities) != 0 {
		t.Fatalf("the declared-empty record carries %d capabilities", len(rec.Capabilities))
	}
}

// TestPublicationRefusesAnUndischargeableObligation is AXC-313.
func TestPublicationRefusesAnUndischargeableObligation(t *testing.T) {
	MarkConformanceCase("AXC-313")

	c := newFixtureCatalog(t)
	accepted(t, c.RegisterPEP(samplePEP("gateway", EditionEnterprise,
		contract.Capability{Type: contract.ObImmutableAudit, Version: 1})))
	accepted(t, c.RegisterPEP(samplePEP("mcp", EditionEnterprise,
		contract.Capability{Type: contract.ObImmutableAudit, Version: 1},
		contract.Capability{Type: contract.ObFieldRedact, Version: 1})))

	planes := []string{"gateway", "mcp"}

	// The counterfactual: an obligation both can discharge publishes.
	if f := c.CheckPublication(planes, []contract.Obligation{obligation(contract.ObImmutableAudit, 1, true)}); f.Blocking() {
		t.Fatalf("a dischargeable obligation was refused: %v", f)
	}

	// One capable plane is not enough. The alternative quantifier makes a
	// policy whose meaning depends on which entry point the caller reached.
	f := c.CheckPublication(planes, []contract.Obligation{obligation(contract.ObFieldRedact, 1, true)})
	if !f.Blocking() {
		t.Fatalf("an obligation only one plane can discharge was published")
	}
	if !f.Has(CodeCapabilityMissing) {
		t.Fatalf("the refusal names %v", f)
	}
	named := false
	for _, one := range f {
		if one.Subject == "gateway" {
			named = true
		}
		if one.Subject == "mcp" {
			t.Fatalf("the capable plane was named as the problem: %v", one)
		}
	}
	if !named {
		t.Fatalf("the refusal does not name the incapable plane: %v", f)
	}

	// An ADVISORY obligation no plane can discharge does not block
	// publication. An advisory control that can block is an enforcement
	// control that was never declared as one.
	advisory := c.CheckPublication(planes, []contract.Obligation{obligation(contract.ObStepUpAuth, 1, false)})
	if advisory.Blocking() {
		t.Fatalf("an advisory obligation blocked publication: %v", advisory)
	}

	// Publication naming no enforcement point at all is refused rather than
	// vacuously satisfied.
	none := c.CheckPublication(nil, []contract.Obligation{obligation(contract.ObImmutableAudit, 1, true)})
	if !none.Blocking() {
		t.Fatalf("publication with no named enforcement point was accepted")
	}

	// The action's own floor is a separate question from the published
	// policies, and is asked separately.
	a := sampleAction("crm.export_floor")
	a.RequiredCapabilities = []contract.Capability{{Type: contract.ObFieldRedact, Version: 1}}
	accepted(t, c.RegisterAction(a))
	if f := c.RequiredCapabilityCheck("mcp", a.ID); f.Blocking() {
		t.Fatalf("a plane meeting the action's floor was refused: %v", f)
	}
	if f := c.RequiredCapabilityCheck("gateway", a.ID); !f.Blocking() {
		t.Fatalf("a plane below the action's floor was accepted")
	}
	if f := c.RequiredCapabilityCheck("gateway", actionID("never.registered")); !f.Has(CodeUnknownAction) {
		t.Fatalf("an unregistered action answered %v", f)
	}
}

// TestCommunityEnforcementPointCannotAdvertiseEnterpriseFamilies is AXC-314.
func TestCommunityEnforcementPointCannotAdvertiseEnterpriseFamilies(t *testing.T) {
	MarkConformanceCase("AXC-314")

	families := EnterpriseOnlyFamilies()
	if len(families) == 0 {
		t.Fatalf("no family is Enterprise-only, so this case asserts nothing")
	}

	c := newFixtureCatalog(t)
	// approval_challenge is in the approval family, which the community build
	// cannot discharge: hitl.Service.CreateApprovalRequest is a stub returning
	// ErrHITLApprovalDisabledByTier there.
	err := c.RegisterPEP(samplePEP("community-gateway", EditionCommunity,
		contract.Capability{Type: contract.ObApprovalChallenge, Version: 1}))
	refusal(t, err, CodeCapabilityMissing)
	if !strings.Contains(err.Error(), "over-advertising") {
		t.Fatalf("the refusal does not say which direction is dangerous: %v", err)
	}

	// The same record on an Enterprise build is accepted, so the rule tracks
	// the edition rather than refusing the capability outright.
	accepted(t, c.RegisterPEP(samplePEP("enterprise-gateway", EditionEnterprise,
		contract.Capability{Type: contract.ObApprovalChallenge, Version: 1})))

	// A universal family is fine on community.
	accepted(t, c.RegisterPEP(samplePEP("community-mcp", EditionCommunity,
		contract.Capability{Type: contract.ObFieldRedact, Version: 1})))

	// Every named family is a family the contract declares, so the map cannot
	// name something that stopped existing.
	declared := map[contract.ObligationFamily]bool{}
	for _, f := range contract.AllObligationFamilies() {
		declared[f] = true
	}
	for _, f := range families {
		if !declared[f] {
			t.Fatalf("Enterprise-only family %q is not a declared obligation family", f)
		}
	}
}

// TestCapabilityStatusAdmitsOnlyOneMember proves Supported is membership
// against the one admitting value.
func TestCapabilityStatusAdmitsOnlyOneMember(t *testing.T) {
	for _, s := range []CapabilityStatus{
		CapabilityStatusUnspecified, CapabilityNoRecord, CapabilityDeclaredNone,
		CapabilityTypeUnsupported, CapabilityVersionUnsupported, CapabilityObligationUnversioned,
		CapabilityStatus(99), CapabilityStatus(-1),
	} {
		if (CapabilityCheck{Status: s}).Supported() {
			t.Errorf("CapabilityStatus(%d) admitted an obligation", int(s))
		}
	}
	if !(CapabilityCheck{Status: CapabilitySupported}).Supported() {
		t.Fatalf("the supported status did not admit an obligation")
	}
	// Every declared member has a distinct rendering, so two states cannot be
	// confused in a log line.
	seen := map[string]CapabilityStatus{}
	for _, s := range AllCapabilityStatuses() {
		if !s.IsValid() {
			t.Errorf("%s is in AllCapabilityStatuses but is not a declared member", s)
		}
		if prev, dup := seen[s.String()]; dup {
			t.Errorf("statuses %d and %d both render as %q", int(prev), int(s), s.String())
		}
		seen[s.String()] = s
	}
}

// TestProfileProjectionMatchesTheContractCheck proves the record and the
// contract's own PEPProfile agree, so the set a decision is composed against
// and the set the registry governs are one table rendered twice.
func TestProfileProjectionMatchesTheContractCheck(t *testing.T) {
	c := newFixtureCatalog(t)
	accepted(t, c.RegisterPEP(samplePEP("gateway", EditionEnterprise,
		contract.Capability{Type: contract.ObFieldRedact, Version: 1},
		contract.Capability{Type: contract.ObImmutableAudit, Version: 2})))
	rec, _ := c.PEP("gateway")
	profile := rec.Profile()

	for _, o := range []contract.Obligation{
		obligation(contract.ObFieldRedact, 1, true),
		obligation(contract.ObFieldRedact, 2, true),
		obligation(contract.ObImmutableAudit, 1, true),
		obligation(contract.ObImmutableAudit, 2, true),
		obligation(contract.ObStepUpAuth, 1, true),
	} {
		want := profile.Supports(o)
		got := c.SupportsObligation("gateway", o).Supported()
		if want != got {
			t.Errorf("registry says %t and the contract profile says %t for %s@%d",
				got, want, o.Type, o.SchemaVersion)
		}
	}
}
