// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"strings"
	"testing"
	"time"
)

// TestRealmValidateRefusesEveryUndeclaredTriState covers AXC-201.
//
// This is the second half of the EX-47 fix and the half that is easy to leave
// out. Denying an undeclared ISSUER stops a credential from an unknown
// directory. It does nothing about an operator who declares a realm and leaves
// its directory source unset: that realm IS declared, so the lookup succeeds,
// and a zero-valued DirectorySource reads as "no group graph", which makes an
// empty closure look authoritative and skips every segment-scoped ceiling. The
// same front door exists for interactivity, revocation and delegation.
//
// The test is written as a sweep over every tri-state field rather than as four
// hand-written cases, so a tri-state added later without a Validate check fails
// here rather than shipping with a permissive zero value. It starts from a
// realm that VALIDATES, then zeroes exactly one field, so a failure can only be
// the field under test.
func TestRealmValidateRefusesEveryUndeclaredTriState(t *testing.T) {
	MarkConformanceCase("AXC-201")

	if err := workspaceRealm().Validate(); err != nil {
		t.Fatalf("the fixture realm must validate before any field is zeroed: %v", err)
	}

	zeroers := map[string]func(*TrustRealm){
		"Directory":        func(r *TrustRealm) { r.Directory = DirectorySourceUnspecified },
		"Interactive":      func(r *TrustRealm) { r.Interactive = InteractiveUnspecified },
		"Revocation":       func(r *TrustRealm) { r.Revocation = RevocationSourceUnspecified },
		"Delegation":       func(r *TrustRealm) { r.Delegation = DelegationUnspecified },
		"MinimumAssurance": func(r *TrustRealm) { r.MinimumAssurance = AssuranceUnspecified },
		// Added after R3 found both of these as permissive falsy defaults the
		// file doc claimed could not exist: a zero MaxCredentialAge meant
		// UNBOUNDED and a nil AuthorizedParties meant azp UNCHECKED, and
		// neither was refused at registration. Both are real controls, so
		// their absence has to be a declaration rather than an omission.
		"AuthorizedPartyPolicy": func(r *TrustRealm) { r.AuthorizedPartyPolicy = AuthorizedPartyUnspecified },
		"CredentialAgePolicy":   func(r *TrustRealm) { r.CredentialAgePolicy = CredentialAgeUnspecified },
	}
	for field, zero := range zeroers {
		t.Run(field, func(t *testing.T) {
			realm := workspaceRealm()
			zero(&realm)
			if err := realm.Validate(); err == nil {
				t.Fatalf("a realm with %s left at its zero value validated", field)
			}
			reg := NewRealmRegistry()
			if err := reg.Register(realm); err != nil {
				return // refused at registration, which is what we want
			}
			t.Fatalf("a realm with %s left at its zero value was registered", field)
		})
	}

	// The zero values must also be conservative if a struct built outside a
	// constructor is ever read. Registration prevents that state existing, but
	// a defensive read is what makes the prevention safe rather than merely
	// tidy.
	var zero TrustRealm
	if zero.HasGroupGraph() {
		t.Errorf("a zero TrustRealm reports that it has a group graph")
	}
	if zero.CanAnswerApprovals() {
		t.Errorf("a zero TrustRealm reports that its subjects can answer an escalation")
	}
	if zero.PermitsDelegateRealm(realmWorkspace) {
		t.Errorf("a zero TrustRealm permits delegation")
	}
	if zero.AcceptsSubjectType(SubjectUser) {
		t.Errorf("a zero TrustRealm accepts a subject type")
	}
	if zero.AcceptsCredentialType(CredentialBearerJWT) {
		t.Errorf("a zero TrustRealm accepts a credential type")
	}
}

// TestRealmValidateRejectsUnsafeConfiguration covers the remaining refusals
// that are not tri-state zero values.
func TestRealmValidateRejectsUnsafeConfiguration(t *testing.T) {
	cases := map[string]func(*TrustRealm){
		"no org":                   func(r *TrustRealm) { r.OrgID = "" },
		"no issuer":                func(r *TrustRealm) { r.CanonicalIssuer = "  " },
		"unknown kind":             func(r *TrustRealm) { r.Kind = "ldap" },
		"no subject types":         func(r *TrustRealm) { r.AcceptedSubjectTypes = nil },
		"unknown subject type":     func(r *TrustRealm) { r.AcceptedSubjectTypes = []SubjectType{"Robot"} },
		"no credential types":      func(r *TrustRealm) { r.AcceptedCredentialTypes = nil },
		"no audiences":             func(r *TrustRealm) { r.Audiences = nil },
		"empty audience":           func(r *TrustRealm) { r.Audiences = []string{""} },
		"empty azp":                func(r *TrustRealm) { r.AuthorizedParties = []string{""} },
		"no algorithms":            func(r *TrustRealm) { r.AllowedSigningAlgorithms = nil },
		"alg none":                 func(r *TrustRealm) { r.AllowedSigningAlgorithms = []string{"none"} },
		"alg NONE":                 func(r *TrustRealm) { r.AllowedSigningAlgorithms = []string{"NONE"} },
		"no claim mapping version": func(r *TrustRealm) { r.ClaimMapping.Version = 0 },
		"no subject claim":         func(r *TrustRealm) { r.ClaimMapping.SubjectClaim = "" },
		"unaccepted mapped type":   func(r *TrustRealm) { r.ClaimMapping.SubjectType = SubjectWorkload },
		"negative skew":            func(r *TrustRealm) { r.ClockSkew = -time.Second },
		"excessive skew":           func(r *TrustRealm) { r.ClockSkew = maxRealmClockSkew + time.Second },
		"negative max age":         func(r *TrustRealm) { r.MaxCredentialAge = -time.Second },
		"no version":               func(r *TrustRealm) { r.Version = 0 },
		"allow list with no realms": func(r *TrustRealm) {
			r.Delegation = DelegationAllowList
			r.DelegateRealms = nil
		},
		"delegate realms under the wrong policy": func(r *TrustRealm) {
			r.Delegation = DelegationDenied
			r.DelegateRealms = []RealmID{realmCloudIAM}
		},
		"invalid delegate realm": func(r *TrustRealm) {
			r.Delegation = DelegationAllowList
			r.DelegateRealms = []RealmID{"bad:realm"}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			realm := workspaceRealm()
			mutate(&realm)
			if err := realm.Validate(); err == nil {
				t.Fatalf("Validate accepted a realm with: %s", name)
			}
		})
	}

	// A trusted-header realm cannot attest more than it observes. AxonFlow
	// does not verify the upstream's authentication, so claiming substantial
	// or high assurance for it would let a policy requiring strong
	// authentication be satisfied by a header.
	header := workspaceRealm()
	header.Kind = RealmKindTrustedHeader
	header.MinimumAssurance = AssuranceHigh
	if err := header.Validate(); err == nil {
		t.Fatalf("a trusted-header realm was allowed to declare high assurance")
	}
	header.MinimumAssurance = AssuranceLow
	if err := header.Validate(); err != nil {
		t.Fatalf("a trusted-header realm declaring low assurance was refused: %v", err)
	}
}

// TestRealmValidateRefusesAliasAsSubjectClaim covers AXC-206.
//
// ADR-065 invariant 3 says an email is never an identifier. Every code path
// downstream honors that, and none of them can tell the difference if the
// operator points the SUBJECT claim at the same claim they mapped as the email
// alias: the canonical subject then IS the email, through configuration rather
// than through code. The check has to live in realm validation because that is
// the last point at which the two are distinguishable.
func TestRealmValidateRefusesAliasAsSubjectClaim(t *testing.T) {
	MarkConformanceCase("AXC-206")

	realm := workspaceRealm()
	realm.ClaimMapping.SubjectClaim = "email"
	realm.ClaimMapping.AliasClaims = map[AliasKind]string{AliasEmail: "email"}

	err := realm.Validate()
	if err == nil {
		t.Fatalf("a realm using its email alias claim as the canonical subject validated")
	}
	if !strings.Contains(err.Error(), "email") {
		t.Fatalf("the refusal does not name the offending claim: %v", err)
	}

	// The same realm with the subject claim pointed at a genuine subject claim
	// validates, so the refusal is about the collision and not about having an
	// email alias at all.
	realm.ClaimMapping.SubjectClaim = "sub"
	if err := realm.Validate(); err != nil {
		t.Fatalf("a realm carrying an email ALIAS alongside a real subject claim was refused: %v", err)
	}

	// An alias mapped to an empty claim is refused too: it would record an
	// alias with no source.
	realm.ClaimMapping.AliasClaims = map[AliasKind]string{AliasEmail: ""}
	if err := realm.Validate(); err == nil {
		t.Fatalf("a realm mapping an alias to an empty claim validated")
	}
}

// TestRealmLookupIsOrganizationScoped covers AXC-202.
//
// Two customers federating the same public IdP is ordinary, so an issuer
// string is unique only within an organization. A cross-org lookup would let
// one customer's declaration answer for the other's credential, which is a
// realm collision with a tenancy boundary crossed on the way.
func TestRealmLookupIsOrganizationScoped(t *testing.T) {
	MarkConformanceCase("AXC-202")

	reg := fixtureRegistry(t)

	if _, ok := reg.Lookup(fixtureOrg, realmWorkspace); !ok {
		t.Fatalf("the workspace realm is not visible in its own organization")
	}
	if _, ok := reg.Lookup(fixtureOtherOrg, realmWorkspace); ok {
		t.Fatalf("another organization can see a realm it did not declare")
	}
	if _, ok := reg.LookupByIssuer(fixtureOtherOrg, issuerWorkspace); ok {
		t.Fatalf("another organization can resolve an issuer it did not declare")
	}

	// The same issuer declared by two organizations resolves to each one's own
	// realm, with no interference.
	otherRealm := workspaceRealm()
	otherRealm.OrgID = fixtureOtherOrg
	otherRealm.RealmID = "their-workspace"
	if err := reg.Register(otherRealm); err != nil {
		t.Fatalf("a second organization could not declare the same issuer: %v", err)
	}
	mine, ok := reg.LookupByIssuer(fixtureOrg, issuerWorkspace)
	if !ok || mine.RealmID != realmWorkspace {
		t.Fatalf("my organization's issuer resolved to %v (ok=%t)", mine.RealmID, ok)
	}
	theirs, ok := reg.LookupByIssuer(fixtureOtherOrg, issuerWorkspace)
	if !ok || theirs.RealmID != "their-workspace" {
		t.Fatalf("the other organization's issuer resolved to %v (ok=%t)", theirs.RealmID, ok)
	}
}

// TestRegistryRefusesAmbiguousIssuersAndDropsWithdrawnOnes pins two registry
// behaviors that are only visible under reconfiguration.
//
// The second one is the interesting one. Re-registering a realm under a new
// issuer must remove the OLD issuer from the index. Leaving it would keep a
// withdrawn directory admissible for as long as the process lives, which is
// EX-47 in reverse: a credential from an issuer the operator deliberately
// stopped trusting would still resolve to a live realm.
func TestRegistryRefusesAmbiguousIssuersAndDropsWithdrawnOnes(t *testing.T) {
	reg := fixtureRegistry(t)

	clash := cloudIAMRealm()
	clash.RealmID = "second-realm"
	clash.CanonicalIssuer = issuerWorkspace
	if err := reg.Register(clash); err == nil {
		t.Fatalf("two realms in one organization were allowed to claim the same issuer")
	}

	moved := workspaceRealm()
	moved.CanonicalIssuer = "https://idp.acme-new.example"
	moved.Version = 2
	if err := reg.Register(moved); err != nil {
		t.Fatalf("re-registering a realm under a new issuer failed: %v", err)
	}
	if _, ok := reg.LookupByIssuer(fixtureOrg, issuerWorkspace); ok {
		t.Fatalf("the withdrawn issuer still resolves to a realm")
	}
	if got, ok := reg.LookupByIssuer(fixtureOrg, "https://idp.acme-new.example"); !ok || got.RealmID != realmWorkspace {
		t.Fatalf("the new issuer does not resolve to the realm")
	}

	reg.Remove(fixtureOrg, realmWorkspace)
	if _, ok := reg.Lookup(fixtureOrg, realmWorkspace); ok {
		t.Fatalf("a removed realm is still resolvable by id")
	}
	if _, ok := reg.LookupByIssuer(fixtureOrg, "https://idp.acme-new.example"); ok {
		t.Fatalf("a removed realm is still resolvable by issuer")
	}
}

// TestRegistryEpochMovesOnEveryMutation pins the value a decision proof binds.
//
// If the epoch did not move, a cached closure or a proof issued before a realm
// changed would still compare equal afterwards, and the change would take
// effect silently on some requests and not others.
func TestRegistryEpochMovesOnEveryMutation(t *testing.T) {
	reg := NewRealmRegistry()
	start := reg.Epoch()

	if err := reg.Register(workspaceRealm()); err != nil {
		t.Fatalf("register: %v", err)
	}
	afterRegister := reg.Epoch()
	if afterRegister <= start {
		t.Fatalf("the epoch did not move on registration: %d -> %d", start, afterRegister)
	}

	reg.Remove(fixtureOrg, realmWorkspace)
	afterRemove := reg.Epoch()
	if afterRemove <= afterRegister {
		t.Fatalf("the epoch did not move on removal: %d -> %d", afterRegister, afterRemove)
	}

	// Removing something that is not there must not move the epoch: a no-op
	// that bumps the epoch invalidates every live proof for nothing.
	reg.Remove(fixtureOrg, "never-declared")
	if reg.Epoch() != afterRemove {
		t.Fatalf("removing an absent realm moved the epoch")
	}
}

// TestRegistryHandsOutCopies pins that a caller cannot edit registered
// configuration through a slice or map header it was handed.
//
// A realm is read on every request. If Lookup returned the stored slices, any
// consumer appending to Audiences for a local purpose would be editing the
// deployment's trust configuration for every subsequent request in the process.
func TestRegistryHandsOutCopies(t *testing.T) {
	reg := fixtureRegistry(t)

	got, ok := reg.Lookup(fixtureOrg, realmWorkspace)
	if !ok {
		t.Fatalf("the fixture realm is missing")
	}
	got.Audiences[0] = "attacker-audience"
	got.AllowedSigningAlgorithms = append(got.AllowedSigningAlgorithms, "none")
	got.ClaimMapping.AliasClaims[AliasEmail] = "sub"

	again, _ := reg.Lookup(fixtureOrg, realmWorkspace)
	if again.Audiences[0] != audienceAxonFlow {
		t.Fatalf("editing a returned realm changed the registry's audiences: %v", again.Audiences)
	}
	if containsExact(again.AllowedSigningAlgorithms, "none") {
		t.Fatalf("editing a returned realm added an algorithm to the registry")
	}
	if again.ClaimMapping.AliasClaims[AliasEmail] != "email" {
		t.Fatalf("editing a returned realm changed the registry's claim mapping")
	}

	// The same must hold for the input: mutating the struct passed to Register
	// afterwards must not reach the stored copy.
	source := cloudIAMRealm()
	source.RealmID = "mutable"
	source.CanonicalIssuer = "https://mutable.example"
	if err := reg.Register(source); err != nil {
		t.Fatalf("register: %v", err)
	}
	source.Audiences[0] = "attacker-audience"
	stored, _ := reg.Lookup(fixtureOrg, "mutable")
	if stored.Audiences[0] != audienceAxonFlow {
		t.Fatalf("mutating the registered struct afterwards changed the stored realm")
	}
}

// TestEveryTriStateIsValidatedByMembershipNotInequality covers AXC-277.
//
// Round two of the review found this and it defeats the tri-states entirely.
// Each was checked as `if field == Unspecified { refuse }`, which admits every
// OTHER out-of-range value. `DirectorySource(99)` then reaches `HasGroupGraph`,
// which answers false, which is the permissive default the tri-state was
// introduced to abolish. One enum value over the top of the range reinstated
// the fail-open.
//
// The threat is the same one the tri-states exist for and which their own
// comments name: a mis-serialised value, a second adapter, or a newer producer
// writing an enum this build does not know. Membership refuses all three;
// inequality refuses exactly one of them.
//
// The sweep runs over every tri-state rather than the ones review happened to
// name, so a field added later with an inequality check fails here. "Every"
// here means every field of TrustRealm: round three found that scoping was
// itself a blind spot, when SCIMIngestOptions.Nesting kept an inequality check
// one file over. The SCIM-side tri-states are Enterprise-only types that this
// untagged file cannot name, so they are swept by the Enterprise-tagged
// companion, TestEverySCIMTriStateIsValidatedByMembershipNotInequality in
// directory_scim_test.go, and the two sweeps together are the package census.
func TestEveryTriStateIsValidatedByMembershipNotInequality(t *testing.T) {
	MarkConformanceCase("AXC-277")

	const outOfRange = 99

	setters := map[string]func(*TrustRealm){
		"Directory":             func(r *TrustRealm) { r.Directory = DirectorySource(outOfRange) },
		"Interactive":           func(r *TrustRealm) { r.Interactive = InteractiveClass(outOfRange) },
		"Revocation":            func(r *TrustRealm) { r.Revocation = RevocationSource(outOfRange) },
		"Delegation":            func(r *TrustRealm) { r.Delegation = DelegationPolicy(outOfRange) },
		"MinimumAssurance":      func(r *TrustRealm) { r.MinimumAssurance = AssuranceClass(outOfRange) },
		"AuthorizedPartyPolicy": func(r *TrustRealm) { r.AuthorizedPartyPolicy = AuthorizedPartyPolicy(outOfRange) },
		"CredentialAgePolicy":   func(r *TrustRealm) { r.CredentialAgePolicy = CredentialAgePolicy(outOfRange) },
	}
	for field, set := range setters {
		t.Run(field, func(t *testing.T) {
			realm := workspaceRealm()
			set(&realm)
			if err := realm.Validate(); err == nil {
				t.Fatalf("a realm with %s out of range validated; an inequality check against the zero value admits every other value", field)
			}
			reg := NewRealmRegistry()
			if err := reg.Register(realm); err == nil {
				t.Fatalf("a realm with %s out of range was registered", field)
			}
		})
	}

	// The IsValid methods themselves, so the sweep above cannot pass because
	// Validate happens to reject for an unrelated reason.
	if DirectorySource(outOfRange).IsValid() || DirectorySourceUnspecified.IsValid() {
		t.Errorf("DirectorySource.IsValid accepts an undeclared value")
	}
	if !DirectorySourceNone.IsValid() || !DirectorySourceSCIM.IsValid() || !DirectorySourceExternalGraph.IsValid() {
		t.Errorf("DirectorySource.IsValid rejects a declared value")
	}
	if AssuranceClass(outOfRange).IsValid() {
		t.Errorf("AssuranceClass.IsValid accepts an out-of-range class, which would satisfy every realm minimum by integer comparison")
	}
	for _, valid := range []interface{ IsValid() bool }{
		InteractiveHuman, RevocationSourceNone, DelegationDenied,
		AuthorizedPartyNotChecked, CredentialAgeUnbounded, AssuranceLow,
	} {
		if !valid.IsValid() {
			t.Errorf("%T rejects a declared value", valid)
		}
	}
}

// TestRealmVersionMustAdvanceOnReRegistration covers AXC-278.
//
// Round two found `SourceVersion` was not a version. `Register` never required
// `Version` to move, so re-registering a realm with a materially different
// declaration at the same version produced closures carrying the identical
// `realm/<id>/v<n>` string. A decision proof and a replay could not tell the
// two apart, which is the whole and only job of that field.
func TestRealmVersionMustAdvanceOnReRegistration(t *testing.T) {
	MarkConformanceCase("AXC-278")

	reg := NewRealmRegistry()
	first := cloudIAMRealm()
	if err := reg.Register(first); err != nil {
		t.Fatalf("register: %v", err)
	}

	// A materially different declaration at the SAME version is refused.
	same := cloudIAMRealm()
	same.Interactive = InteractiveHuman
	same.Delegation = DelegationDenied
	same.MinimumAssurance = AssuranceHigh
	if err := reg.Register(same); err == nil {
		t.Fatalf("a changed realm re-registered at the same version; the recorded source version would not move and the change would be undetectable in replay")
	}

	// Going backwards is refused too.
	older := cloudIAMRealm()
	older.Version = 0
	if err := reg.Register(older); err == nil {
		t.Fatalf("a realm was re-registered at a lower version")
	}

	// Advancing works, and the recorded source version moves with it.
	advanced := same
	advanced.Version = 2
	if err := reg.Register(advanced); err != nil {
		t.Fatalf("an advanced version was refused: %v", err)
	}
	stored, _ := reg.Lookup(fixtureOrg, realmCloudIAM)
	before := NewNoGraphClosure(fixtureAgentA, first, fixtureNow).SourceVersion
	after := NewNoGraphClosure(fixtureAgentA, stored, fixtureNow).SourceVersion
	if before == after {
		t.Fatalf("the recorded source version did not move across a realm change: %q", before)
	}
}
