package registry

import (
	"encoding/json"
	"strings"
	"testing"

	"axonflow/platform/decision/contract"
)

func externalCatalog(t *testing.T) *Catalog {
	t.Helper()
	c := NewCatalog(fixtureNow)
	if err := RegisterExternalPEPRealm(c); err != nil {
		t.Fatalf("declaring the external realm: %v", err)
	}
	return c
}

func handshakeWith(caps ...contract.Capability) contract.PEPHandshake {
	if caps == nil {
		caps = []contract.Capability{}
	}
	return contract.PEPHandshake{
		ProfileVersion: contract.PEPHandshakeProfileV1,
		PEPID:          "sdk-go",
		Audience:       "axonflow-decision-proof",
		Capabilities:   caps,
	}
}

// TestExternalPEPIdentifierIsBuiltFromTheChannelNotTheDocument.
//
// The identity property holds STRUCTURALLY rather than by a comparison that
// could be deleted: the caller supplies a name INSIDE its credential's
// namespace and there is no input that reaches the prefix. A test that only
// asserted "a mismatched id is refused" would be testing a comparison; this
// asserts that no document can produce another credential's identifier at all.
//
// AXC-328.
func TestExternalPEPIdentifierIsBuiltFromTheChannelNotTheDocument(t *testing.T) {
	MarkConformanceCase("AXC-328")

	got := ExternalPEPID("acme-credential", "sdk-go")
	if got != "client:acme-credential:sdk-go" {
		t.Fatalf("identifier = %q", got)
	}
	if !strings.HasPrefix(got, ExternalPEPPrefix) {
		t.Errorf("identifier %q does not carry the external prefix", got)
	}
	if strings.HasPrefix(got, LegacyPlanePEPPrefix) {
		t.Errorf("identifier %q collides with the in-process plane namespace", got)
	}

	// The load-bearing assertion: two credentials naming the SAME enforcement
	// point produce different identifiers, so one can never answer for the
	// other. There is no argument to this function by which a caller reaches
	// another credential's namespace.
	mine := ExternalPEPID("acme-credential", "sdk-go")
	theirs := ExternalPEPID("other-credential", "sdk-go")
	if mine == theirs {
		t.Fatal("two credentials produced one identifier; a declaration from one enforcement point would answer for another's request")
	}

	// And two enforcement points behind ONE credential stay distinguishable,
	// which is what the gateway adapters need: their body-capable and
	// headers-only call paths authenticate identically and declare differently.
	if ExternalPEPID("acme", "gateway-body-capable") == ExternalPEPID("acme", "gateway-headers-only") {
		t.Fatal("two call paths behind one credential collapsed to one enforcement point")
	}

	// The identifier parses back unambiguously even when the CREDENTIAL carries
	// a colon, because contract.PEPHandshake refuses a colon in the name.
	withColon := ExternalPEPID("realm:acme", "sdk-go")
	name := withColon[strings.LastIndex(withColon, ":")+1:]
	if name != "sdk-go" {
		t.Errorf("last-colon parse of %q gave %q", withColon, name)
	}
}

// TestAdmitExternalPEPRequiresADeclaredRealm. AXC-329.
//
// The same fence RegisterPEP puts in front of the in-process planes: a
// deployment that has not declared the external realm cannot admit an external
// enforcement point at all. Without it, "which realm does this plane
// authenticate as" would have an answer no policy could be scoped to.
func TestAdmitExternalPEPRequiresADeclaredRealm(t *testing.T) {
	MarkConformanceCase("AXC-329")

	undeclared := NewCatalog(fixtureNow) // deliberately NOT declaring the realm
	rec := ExternalPEPRecordFrom("acme", EditionEnterprise, handshakeWith(contract.Capability{Type: contract.ObFieldRedact, Version: 1}))
	if _, findings := undeclared.AdmitExternalPEP(rec); findings.Err() == nil {
		t.Fatal("an external enforcement point was admitted against a catalog that declares no external realm")
	}

	if _, findings := externalCatalog(t).AdmitExternalPEP(rec); findings.Err() != nil {
		t.Fatalf("control failed: the same record was refused by a catalog that DOES declare the realm: %v", findings.Err())
	}
}

// TestAdmissionIsNotRegistrationAndRepeatsAreFine. AXC-330.
//
// Catalog registration is create-only, which is correct for the in-process
// planes and wrong for an external enforcement point: applied here it would
// refuse the SECOND request from the same caller. Admission stores nothing, so
// a repeat is a second declaration rather than a collision.
func TestAdmissionIsNotRegistrationAndRepeatsAreFine(t *testing.T) {
	MarkConformanceCase("AXC-330")

	c := externalCatalog(t)
	rec := ExternalPEPRecordFrom("acme", EditionEnterprise, handshakeWith(contract.Capability{Type: contract.ObFieldRedact, Version: 1}))
	for i := 0; i < 3; i++ {
		if _, findings := c.AdmitExternalPEP(rec); findings.Err() != nil {
			t.Fatalf("admission %d was refused: %v", i+1, findings.Err())
		}
	}
	// Nothing was stored, so nothing is queryable and nothing can go stale.
	if _, ok := c.PEP(rec.ID); ok {
		t.Error("admission stored a record; a stored declaration would answer for a request from a DIFFERENT instance of the same enforcement point")
	}
	if len(c.PEPIDs()) != 0 {
		t.Errorf("the catalog gained %d registered enforcement points from admission", len(c.PEPIDs()))
	}
}

// TestUnadmittedExternalPEPRefusesAndIsRecognisableAsADefect. AXC-331.
//
// The zero value must not answer CapabilityDeclaredNone. That is a plausible,
// WRONG answer - it reads as "this enforcement point told us it discharges
// nothing" when the truth is that nobody ever admitted one, and a construction
// defect must not be indistinguishable from a declaration.
func TestUnadmittedExternalPEPRefusesAndIsRecognisableAsADefect(t *testing.T) {
	MarkConformanceCase("AXC-331")

	var zero ExternalPEP
	if zero.Admitted() {
		t.Fatal("the zero value reports itself as admitted")
	}
	if zero.Profile() != nil {
		t.Error("an unadmitted value must project a NIL profile; ADR-065 invariant 12 refuses a request rather than interpreting it partially")
	}
	check := zero.SupportsObligation(contract.Obligation{Type: contract.ObFieldRedact, SchemaVersion: 1, Mandatory: true})
	if check.Supported() {
		t.Fatal("an unadmitted value admitted an obligation")
	}
	if check.Status == CapabilityDeclaredNone {
		t.Fatal("an unadmitted value answered DeclaredNone; that status means the enforcement point TOLD us it discharges nothing, which nobody did")
	}
	if check.Status.IsValid() {
		t.Errorf("status = %s; a construction defect must answer with a status that is not a declared member, so it cannot be mistaken for a real answer", check.Status)
	}
}

// TestExternalCapabilityStatusPerWireState. AXC-332.
//
// One case per status the handshake can produce, through the SAME
// checkCapability the registered path uses. The distinction that matters, and
// that a single "it denied" assertion would lose: DeclaredNone and
// TypeUnsupported are different operator problems - one enforcement point is
// not configured, the other is out of date.
func TestExternalCapabilityStatusPerWireState(t *testing.T) {
	MarkConformanceCase("AXC-332")

	c := externalCatalog(t)
	admit := func(t *testing.T, caps ...contract.Capability) ExternalPEP {
		t.Helper()
		e, findings := c.AdmitExternalPEP(ExternalPEPRecordFrom("acme", EditionEnterprise, handshakeWith(caps...)))
		if findings.Err() != nil {
			t.Fatalf("admission refused: %v", findings.Err())
		}
		return e
	}
	ask := contract.Obligation{Type: contract.ObFieldRedact, SchemaVersion: 1, Mandatory: true}

	for _, tc := range []struct {
		name string
		caps []contract.Capability
		want CapabilityStatus
	}{
		{"declared empty", nil, CapabilityDeclaredNone},
		{"other types only", []contract.Capability{{Type: contract.ObImmutableAudit, Version: 1}}, CapabilityTypeUnsupported},
		{"other versions only", []contract.Capability{{Type: contract.ObFieldRedact, Version: 2}}, CapabilityVersionUnsupported},
		{"exact match", []contract.Capability{{Type: contract.ObFieldRedact, Version: 1}}, CapabilitySupported},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := admit(t, tc.caps...).SupportsObligation(ask)
			if got.Status != tc.want {
				t.Fatalf("status = %s, want %s (detail: %s)", got.Status, tc.want, got.Detail)
			}
			if got.Supported() != (tc.want == CapabilitySupported) {
				t.Errorf("Supported() = %v for status %s", got.Supported(), got.Status)
			}
		})
	}

	// The distinctness assertion. A build that collapsed the two statuses would
	// pass every subtest above that only checked "it was not supported".
	none := admit(t).SupportsObligation(ask)
	typeGap := admit(t, contract.Capability{Type: contract.ObImmutableAudit, Version: 1}).SupportsObligation(ask)
	if none.Status == typeGap.Status {
		t.Fatal("an empty declaration and an unsupported type produced the same status; the two are different operator problems and must stay distinguishable")
	}
	if none.Detail == typeGap.Detail {
		t.Fatal("the two refusals produced identical prose, so an operator reading a log line cannot tell them apart")
	}
}

// TestOverAdvertisementIsSplitNotIgnored. AXC-333.
//
// One predicate, two remedies. A REGISTERED record is refused - it comes from a
// checked-in fixture and a defect is fixable before shipping. An EXTERNAL
// declaration is SPLIT so the caller layer can drop the unclaimable entries and
// proceed, because refusing would 400 every call from a correctly-built client
// whose single compile-time capability set names a family this deployment does
// not issue.
func TestOverAdvertisementIsSplitNotIgnored(t *testing.T) {
	MarkConformanceCase("AXC-333")

	approval := contract.Capability{Type: contract.ObApprovalChallenge, Version: 1}
	redact := contract.Capability{Type: contract.ObFieldRedact, Version: 1}

	kept, dropped := SplitOverAdvertised(EditionCommunity, []contract.Capability{approval, redact})
	if len(dropped) != 1 || dropped[0] != approval {
		t.Fatalf("community: dropped = %v, want exactly the approval capability", dropped)
	}
	if len(kept) != 1 || kept[0] != redact {
		t.Fatalf("community: kept = %v, want exactly the redaction capability", kept)
	}

	// The CONTROL that makes the split about the EDITION rather than about the
	// capability: the same set, an Enterprise enforcement point, nothing
	// dropped.
	kept, dropped = SplitOverAdvertised(EditionEnterprise, []contract.Capability{approval, redact})
	if len(dropped) != 0 {
		t.Fatalf("enterprise: dropped %v; the family is Enterprise-only, not forbidden", dropped)
	}
	if len(kept) != 2 {
		t.Fatalf("enterprise: kept = %v, want both", kept)
	}

	// An UNDECLARED type is kept, not reported as an over-advertisement: it is
	// a type this build cannot identify at all, which validateCapabilities owns.
	kept, dropped = SplitOverAdvertised(EditionCommunity, []contract.Capability{{Type: "teleport_pii", Version: 1}})
	if len(dropped) != 0 || len(kept) != 1 {
		t.Fatalf("an undeclared type must not be reported as an over-advertisement: kept=%v dropped=%v", kept, dropped)
	}

	// And the REGISTERED path still refuses, through the same predicate.
	rec := PEPRecord{ID: "plane:x", Realm: LegacyPlaneRealm, Edition: EditionCommunity, Capabilities: []contract.Capability{approval}}
	if rec.Validate().Err() == nil {
		t.Fatal("a registered community record advertising an Enterprise-only family must still be refused")
	}
}

// TestExternalRecordDerivesIdentityAndEditionRatherThanTakingThem. AXC-334.
//
// A PEP may declare what it can DO. The record's identity comes from the
// authenticated credential and its edition from the enforcement context, and
// neither has a wire member - a community build claiming Enterprise would
// defeat exactly the rule that exists to catch it.
func TestExternalRecordDerivesIdentityAndEditionRatherThanTakingThem(t *testing.T) {
	MarkConformanceCase("AXC-334")

	h := handshakeWith(contract.Capability{Type: contract.ObFieldRedact, Version: 1})
	rec := ExternalPEPRecordFrom("acme", EditionCommunity, h)

	if rec.ID != ExternalPEPID("acme", h.PEPID) {
		t.Errorf("ID = %q, want it built from the credential", rec.ID)
	}
	if rec.Edition != EditionCommunity {
		t.Errorf("edition = %s, want the one the caller layer derived", rec.Edition)
	}
	if rec.Realm != ExternalPEPRealm {
		t.Errorf("realm = %q, want %q", rec.Realm, ExternalPEPRealm)
	}

	// The same handshake, a different derived edition, a different record. If
	// the edition were read from the document these two would be equal.
	if ExternalPEPRecordFrom("acme", EditionEnterprise, h).Edition == rec.Edition {
		t.Fatal("the edition did not follow the caller-supplied derivation")
	}

	// The handshake type carries no edition member at all, so there is nothing
	// for a caller to set. Asserted on the ENCODING rather than on the struct,
	// because a member added with a json tag is what would actually reach the
	// wire.
	raw, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"edition", "realm", "tier", "license"} {
		if strings.Contains(string(raw), `"`+forbidden+`"`) {
			t.Errorf("the handshake encoding carries a %q member; a PEP may declare what it can do and never what the platform already knows about it: %s", forbidden, raw)
		}
	}
}

// TestDeclaredEmptyProfileRendersAsAnEmptyListNotNull. AXC-335.
//
// The regression this lane found and fixed. sortedCapabilities was
// `append([]Capability(nil), caps...)`, which returns NIL for an empty input -
// so RegisterPEP stored a declared-empty record with a nil slice and Profile()
// rendered `"capabilities": null`, an ABSENT member on the wire. That is
// exactly the collapse PEPRecord.clone's own comment forbids and exactly the
// #2958 defect this package exists to correct: the one enforcement point that
// says "I discharge nothing" was serialised as one that had said nothing.
func TestDeclaredEmptyProfileRendersAsAnEmptyListNotNull(t *testing.T) {
	MarkConformanceCase("AXC-335")

	rec := PEPRecord{
		ID: "plane:policy_simulation", Realm: LegacyPlaneRealm,
		Edition: EditionCommunity, Capabilities: []contract.Capability{},
	}
	raw, err := json.Marshal(rec.Profile())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"capabilities":null`) {
		t.Fatalf("a declared-empty capability set rendered as an absent member: %s", raw)
	}
	if !strings.Contains(string(raw), `"capabilities":[]`) {
		t.Fatalf("profile = %s, want an explicit empty list", raw)
	}

	// And through the registered path, which is where the defect actually lived.
	c := NewCatalog(fixtureNow)
	if err := c.RegisterRealm(LegacyPlaneRealm); err != nil {
		t.Fatal(err)
	}
	if err := c.RegisterPEP(rec); err != nil {
		t.Fatal(err)
	}
	stored, ok := c.PEP(rec.ID)
	if !ok {
		t.Fatal("record not stored")
	}
	if stored.Capabilities == nil {
		t.Error("RegisterPEP stored a nil capability slice for a declared-empty record, defeating clone's own guarantee")
	}
	storedRaw, err := json.Marshal(stored.Profile())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(storedRaw), `"capabilities":[]`) {
		t.Errorf("stored profile = %s, want an explicit empty list", storedRaw)
	}
}

// TestLegacyPlanesStillRegisterAfterTheSortConvergence is the regression
// control for replacing three comparators with one. It exercises the real
// checked-in fixture rather than a synthetic record.
func TestLegacyPlanesStillRegisterAfterTheSortConvergence(t *testing.T) {
	for _, edition := range AllEditions() {
		records, err := LegacyPlanePEPs(edition)
		if err != nil {
			t.Fatalf("%s: %v", edition, err)
		}
		if len(records) == 0 {
			t.Fatalf("%s: no legacy plane records, so this test asserts nothing", edition)
		}
		for _, r := range records {
			if r.Capabilities == nil {
				t.Errorf("%s: plane %q has a nil capability slice; the fixture writes an empty set as \"-\" and it must stay a non-nil empty slice", edition, r.ID)
			}
		}
	}
}

// TestAdmissionRefusesTheDegenerateInputsRatherThanPanicking. AXC-336.
//
// The nil-catalog and empty-realm arms are the ones a caller reaches by
// CONSTRUCTION rather than by a wire value, so nothing on the request path
// exercises them - which is exactly why they need a test: an untested arm that
// panics turns a construction defect into an outage, and one that silently
// admits turns it into a permit.
func TestAdmissionRefusesTheDegenerateInputsRatherThanPanicking(t *testing.T) {
	MarkConformanceCase("AXC-336")

	rec := ExternalPEPRecordFrom("acme", EditionEnterprise,
		handshakeWith(contract.Capability{Type: contract.ObFieldRedact, Version: 1}))

	// A nil catalog REFUSES; it neither panics nor admits.
	var nilCatalog *Catalog
	admitted, findings := nilCatalog.AdmitExternalPEP(rec)
	if findings.Err() == nil {
		t.Error("a nil catalog admitted an enforcement point")
	}
	if admitted.Admitted() {
		t.Error("a nil catalog produced an admitted value")
	}
	if err := RegisterExternalPEPRealm(nil); err == nil {
		t.Error("declaring the external realm on a nil catalog did not error")
	}

	// A record declaring NO realm is refused, and with the realm finding rather
	// than as a side effect of some other rule: a plane that authenticates as
	// nothing cannot be scoped to by any policy.
	realmless := rec
	realmless.Realm = ""
	if _, findings := externalCatalog(t).AdmitExternalPEP(realmless); findings.Err() == nil {
		t.Error("a record declaring no realm was admitted")
	}

	// Declaring the realm is IDEMPOTENT: the catalog an agent admits against is
	// built once per process, and a second call is a caller asking for a state
	// that already holds rather than a collision worth refusing.
	c := externalCatalog(t)
	if err := RegisterExternalPEPRealm(c); err != nil {
		t.Errorf("a second realm declaration errored: %v", err)
	}
	if _, findings := c.AdmitExternalPEP(rec); findings.Err() != nil {
		t.Errorf("admission broke after a repeated realm declaration: %v", findings.Err())
	}
}

// TestAdmittedAccessorsHandOutCopiesAndAProfile. AXC-337.
//
// Record() must COPY. An accessor returning the admitted record's own slice
// would let a caller reorder or extend what the enforcement point declared
// after admission validated it - the registration rules would be advisory for
// anyone holding the value, which is the property TestTheCatalogHandsOutCopies
// pins for the registered path.
func TestAdmittedAccessorsHandOutCopiesAndAProfile(t *testing.T) {
	MarkConformanceCase("AXC-337")

	c := externalCatalog(t)
	admitted, findings := c.AdmitExternalPEP(ExternalPEPRecordFrom("acme", EditionEnterprise,
		handshakeWith(contract.Capability{Type: contract.ObFieldRedact, Version: 1})))
	if findings.Err() != nil {
		t.Fatal(findings.Err())
	}

	got := admitted.Record()
	if len(got.Capabilities) != 1 {
		t.Fatalf("record = %+v", got)
	}
	got.Capabilities[0] = contract.Capability{Type: contract.ObImmutableAudit, Version: 9}
	if admitted.Record().Capabilities[0].Type != contract.ObFieldRedact {
		t.Fatal("Record() handed out the admitted record's own slice; a holder could rewrite what the enforcement point declared after admission validated it")
	}

	p := admitted.Profile()
	if p == nil || p.ID != admitted.Record().ID {
		t.Fatalf("profile = %+v", p)
	}
	if !p.Supports(contract.Obligation{Type: contract.ObFieldRedact, SchemaVersion: 1}) {
		t.Error("the projected profile does not support the declared capability")
	}
}
