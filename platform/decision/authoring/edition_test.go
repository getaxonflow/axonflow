// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoring

import (
	"context"
	"crypto/ed25519"
	"sort"
	"strings"
	"testing"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// publishAtEdition publishes the baseline document, optionally edited, under a
// named edition and requires the publication to be REFUSED.
//
// It requires the refusal rather than tolerating it because every caller here
// is asserting a boundary: a helper that returned the findings of a successful
// publication would let a case pass on a document the edition actually
// accepted, with the expected code absent and the failure reported as a
// missing code rather than as a boundary that did not hold.
func publishAtEdition(t *testing.T, ed Edition, edit func(*Metadata, *pdp.Document)) Findings {
	t.Helper()
	cat := baseCatalog(t)
	d := documentWith(t, cat, edit)
	_, priv := testKeys(t)
	opts := publishOptions(t, priv)
	opts.Profile = mustProfile(t, ed)
	_, findings, err := Publish(context.Background(), d, cat, opts)
	if err == nil {
		t.Fatalf("the %s edition accepted a publication it does not carry the constructs for", ed)
	}
	return findings
}

func quotaObligation(source string) contract.Obligation {
	return contract.Obligation{
		Type:          contract.ObQuotaReservation,
		Params:        map[string]string{"budget": "refunds"},
		Mandatory:     true,
		SourcePolicy:  source,
		SchemaVersion: 1,
	}
}

func stepUpObligation(source string) contract.Obligation {
	return contract.Obligation{
		Type:          contract.ObStepUpAuth,
		Params:        map[string]string{"assurance": string(contract.AssuranceLevel2)},
		Mandatory:     true,
		SourcePolicy:  source,
		SchemaVersion: 1,
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Totality. The two classification tables are held over the CLOSED vocabularies
// the contract declares, so a family or a namespace added there and not
// classified here fails a named test rather than defaulting to permitted.
// ─────────────────────────────────────────────────────────────────────────────

func TestEveryObligationFamilyIsClassified(t *testing.T) {
	var missing []string
	for _, f := range contract.AllObligationFamilies() {
		if _, ok := obligationFamilyFloor[f]; !ok {
			missing = append(missing, string(f))
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("obligation families with no edition row: %v — an unclassified family is a construct nobody ruled, "+
			"and the table must say so explicitly (reservedFloor) rather than by omission", missing)
	}
	for f := range obligationFamilyFloor {
		if _, err := contract.FamilyOf(contract.ObApprovalChallenge); err != nil {
			t.Fatalf("contract vocabulary unreadable: %v", err)
		}
		var known bool
		for _, declared := range contract.AllObligationFamilies() {
			if declared == f {
				known = true
				break
			}
		}
		if !known {
			t.Fatalf("the edition table classifies %q, which the contract does not declare as a family", f)
		}
	}
}

func TestEveryAttributeNamespaceIsClassified(t *testing.T) {
	var missing []string
	for _, ns := range contract.AllNamespaces() {
		if _, ok := namespaceFloor[ns]; !ok {
			missing = append(missing, string(ns))
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("attribute namespaces with no edition row: %v", missing)
	}
	for ns := range namespaceFloor {
		var known bool
		for _, declared := range contract.AllNamespaces() {
			if declared == ns {
				known = true
				break
			}
		}
		if !known {
			t.Fatalf("the edition table classifies %q, which the contract does not declare as a namespace", ns)
		}
	}
}

// TestTheTablesAreNotVacuouslyPermissive is the anti-vacuity control the
// totality tests cannot supply on their own.
//
// A table that is TOTAL and that says "community" in every cell would pass both
// tests above while carrying no boundary at all — the shape a classification
// acquires when somebody makes a totality test green by filling the gaps with
// the loosest value. So this asserts that each edition's permitted set is a
// PROPER subset of the next one's, which is the property the ladder claims and
// which no single-cell edit can satisfy accidentally.
func TestTheTablesAreNotVacuouslyPermissive(t *testing.T) {
	var prev EditionConstructReport
	for i, ed := range AllEditions() {
		p, err := ProfileFor(ed)
		if err != nil {
			t.Fatalf("ProfileFor(%s): %v", ed, err)
		}
		rep := p.Constructs()
		if i > 0 {
			if len(rep.ObligationFamilies) <= len(prev.ObligationFamilies) && len(rep.Namespaces) <= len(prev.Namespaces) && rep.GroupScope == prev.GroupScope {
				t.Fatalf("the %s edition carries no construct the %s edition does not; the ladder has a rung that is not a rung",
					ed, prev.Edition)
			}
			for _, f := range prev.ObligationFamilies {
				if !containsString(rep.ObligationFamilies, f) {
					t.Fatalf("the %s edition carries obligation family %q and the wider %s edition does not; the ladder is not monotonic",
						prev.Edition, f, ed)
				}
			}
			for _, ns := range prev.Namespaces {
				if !containsString(rep.Namespaces, ns) {
					t.Fatalf("the %s edition carries namespace %q and the wider %s edition does not; the ladder is not monotonic",
						prev.Edition, ns, ed)
				}
			}
		}
		prev = rep
	}
	// The strict end: Enterprise must carry everything the contract declares
	// except what is explicitly reserved, and Community must not.
	ent, _ := ProfileFor(EditionEnterprise)
	com, _ := ProfileFor(EditionCommunity)
	if len(com.Constructs().ObligationFamilies) >= len(contract.AllObligationFamilies()) {
		t.Fatal("the community edition carries every obligation family, so the family table bounds nothing")
	}
	if len(com.Constructs().Namespaces) >= len(contract.AllNamespaces()) {
		t.Fatal("the community edition reads every attribute namespace, so the namespace table bounds nothing")
	}
	if !ent.AllowsGroupScope() || com.AllowsGroupScope() {
		t.Fatal("group scope must be Enterprise-only (PRD 5.2, nested group graph None/None/Full)")
	}
}

// TestAReservedConstructIsRefusedBelowEnterpriseAndNamedAsUnruled pins the
// reservation mechanism itself, separately from any construct that happens to
// use it today.
//
// It matters because the mechanism is the part that will outlive the current
// contents of the table: the day step-up authentication gets a ruling, the row
// moves and this test must still describe how an unruled construct behaves.
func TestAReservedConstructIsRefusedBelowEnterpriseAndNamedAsUnruled(t *testing.T) {
	for _, ed := range AllEditions() {
		p, err := ProfileFor(ed)
		if err != nil {
			t.Fatalf("ProfileFor(%s): %v", ed, err)
		}
		allowed, unruled := p.constructFloorAllows(reservedFloor)
		if !unruled {
			t.Fatalf("%s: a reserved floor must report unruled so the finding can name the absence of a ruling", ed)
		}
		if want := ed == EditionEnterprise; allowed != want {
			t.Fatalf("%s: reserved construct allowed=%v, want %v", ed, allowed, want)
		}
	}
}

// TestAnUnclassifiedConstructIsRefusedOnEveryEditionIncludingEnterprise is the
// direction the totality tests do not cover.
//
// Totality says the table has every row today. This says what happens if it
// does not: a family or namespace that is genuinely absent from the table must
// be refused even on Enterprise, because permitting the widest edition to spend
// a construct nobody classified is how an omission becomes a grant.
func TestAnUnclassifiedConstructIsRefusedOnEveryEditionIncludingEnterprise(t *testing.T) {
	for _, ed := range AllEditions() {
		p, err := ProfileFor(ed)
		if err != nil {
			t.Fatalf("ProfileFor(%s): %v", ed, err)
		}
		allowed, unruled := p.AllowsObligationFamily(contract.ObligationFamily("family_that_does_not_exist"))
		if allowed || !unruled {
			t.Fatalf("%s: an unclassified obligation family was allowed=%v unruled=%v; want refused and unruled", ed, allowed, unruled)
		}
		allowed, unruled = p.AllowsNamespace(contract.Namespace("namespace_that_does_not_exist"))
		if allowed || !unruled {
			t.Fatalf("%s: an unclassified namespace was allowed=%v unruled=%v; want refused and unruled", ed, allowed, unruled)
		}
	}
}

func TestAnUndeclaredEditionIsRefused(t *testing.T) {
	for _, bad := range []Edition{"", "enterprise_plus", "COMMUNITY", "free", reservedFloor} {
		if _, err := ProfileFor(bad); err == nil {
			t.Fatalf("ProfileFor(%q) was accepted; an unrecognised edition must be refused rather than folded onto a default", bad)
		}
	}
}

func TestEditionForFoldsEveryTierAndDefaultsToCommunity(t *testing.T) {
	cases := map[string]Edition{
		"community":       EditionCommunity,
		"Community":       EditionCommunity,
		"  evaluation  ":  EditionEvaluation,
		"professional":    EditionEnterprise,
		"enterprise":      EditionEnterprise,
		"enterprise_plus": EditionEnterprise,
		// The fold is total: anything this build does not recognise resolves to
		// the SMALLEST boundary, which is the same direction the verified
		// licence read folds an absent, forged or expired key.
		"":                EditionCommunity,
		"free":            EditionCommunity,
		"not-a-tier-2026": EditionCommunity,
	}
	for tier, want := range cases {
		if got := EditionFor(tier); got != want {
			t.Fatalf("EditionFor(%q) = %q, want %q", tier, got, want)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Separation of duties. The row that made the ladder unspendable.
// ─────────────────────────────────────────────────────────────────────────────

// communityDocument is the baseline with the two constructs Community does not
// carry removed: the group scope on perm.refund and the signal read on
// insp.pii. It is what a Community author can actually write, and the
// end-to-end tests below use it to prove they can write it. It is an
// ORGANIZATION-root document, because that is the only root a Community author
// writes to and the only one an API accepts (#4047).
func communityDocument(t *testing.T) *Document {
	t.Helper()
	cat := baseCatalog(t)
	d := organizationDocumentWith(t, cat, func(_ *Metadata, doc *pdp.Document) {
		policyByIDIn(doc, "perm.refund").Scope = pdp.Scope{Principals: []contract.ID{pid(t, principalAlice)}}
		// insp.pii is the only signal reader; drop the policy rather than
		// rewriting its condition, because a Community deployment that cannot
		// read detector output has no version of that policy to write.
		var kept []pdp.Policy
		for _, p := range doc.Policies {
			if p.ID != "insp.pii" {
				kept = append(kept, p)
			}
		}
		doc.Policies = kept
	})
	findings := Validate(d, cat)
	if findings.Rejected() {
		t.Fatalf("the community baseline must be a valid document, got %v", findings.Rejections())
	}
	return d
}

// communityFixtures are baseFixtures with the dropped policy's expectation
// removed. The gauntlet requires a fixture to name exactly the policies the
// document declares, which is the property that stops a fixture set drifting
// away from the document it certifies — so a document with one fewer policy
// needs a fixture set with one fewer expectation, not a relaxed gauntlet.
func communityFixtures() []Fixture {
	out := baseFixtures()
	for i := range out {
		delete(out[i].Expect, "insp.pii")
	}
	return out
}

// communityPublishOptions is organizationPublishOptions with the community
// fixture set and no approvers: the shape a sole administrator actually
// publishes with.
func communityPublishOptions(t *testing.T, priv ed25519.PrivateKey, ed Edition) PublishOptions {
	t.Helper()
	opts := organizationPublishOptions(t, priv)
	opts.Profile = mustProfile(t, ed)
	opts.Fixtures = communityFixtures()
	opts.Approvers = nil
	return opts
}

// TestASoleAdministratorCanPublishAndActivateOnCommunity is the end-to-end
// assertion #3907 exists for, at the library layer.
//
// Before the edition profile this was IMPOSSIBLE, and impossible in a way no
// limit or route could fix: checkSeparationOfDuties refused a publication whose
// approvers did not include somebody other than the author, and
// checkActivationAuthority refused an activation by anyone who was not a
// recorded approver. One administrator, one deployment, no second person to
// name: zero policies, whatever the ladder said.
func TestASoleAdministratorCanPublishAndActivateOnCommunity(t *testing.T) {
	for _, ed := range []Edition{EditionCommunity, EditionEvaluation} {
		t.Run(string(ed), func(t *testing.T) {
			cat := baseCatalog(t)
			trust, priv := organizationTrust(t)
			api, err := NewAPI(cat, StaticTrust(trust), mustProfile(t, ed))
			if err != nil {
				t.Fatalf("NewAPI: %v", err)
			}
			d := communityDocument(t)
			alice := pid(t, principalAlice)

			// NO APPROVERS AT ALL. Not "the author as their own approver",
			// which would be inventing a second identity for a person who is
			// one person — the thing #3893 says not to do.
			opts := communityPublishOptions(t, priv, ed)
			art, findings, err := api.Publish(context.Background(), d, opts)
			if err != nil {
				t.Fatalf("a sole administrator could not publish on %s: %v\nfindings: %v", ed, err, findings)
			}
			if findings.Rejected() {
				t.Fatalf("publication returned rejections: %v", findings.Rejections())
			}

			// And the same person activates it. This is the second half, and it
			// is a separate refusal in the source: a publication that succeeded
			// and an activation that could not would still leave the policy
			// unenforced.
			act, err := api.Promote(context.Background(), pdp.RootOrganization, art.Digest(), alice, timeFixture(), "sole administrator")
			if err != nil {
				t.Fatalf("a sole administrator could not activate their own version on %s: %v", ed, err)
			}
			if act.Actor != alice {
				t.Fatalf("activation recorded actor %q, want %q; the record must still name who did it", act.Actor, alice)
			}
			got, err := api.Store().History(context.Background(), pdp.RootOrganization)
			if err != nil {
				t.Fatalf("reading the activation history: %v", err)
			}
			if len(got) != 1 {
				t.Fatalf("activation history has %d entries, want 1; a relaxed duty separation must not relax the audit trail", len(got))
			}
		})
	}
}

// TestEnterpriseStillRequiresTwoPeople is the NEGATIVE TWIN.
//
// The whole change is a relaxation, so the assertion that matters most is the
// one that says it did not reach Enterprise. Both halves are checked, because
// they are two different functions and a fix that relaxed one would look
// complete: publication without a distinct approver, and activation by the
// author.
func TestEnterpriseStillRequiresTwoPeople(t *testing.T) {
	cat := baseCatalog(t)
	trust, priv := organizationTrust(t)
	api, err := NewAPI(cat, StaticTrust(trust), mustProfile(t, EditionEnterprise))
	if err != nil {
		t.Fatalf("NewAPI: %v", err)
	}
	alice := pid(t, principalAlice)

	// Publication half.
	opts := organizationPublishOptions(t, priv)
	opts.Approvers = nil
	_, findings, err := api.Publish(context.Background(), organizationDocument(t), opts)
	if err == nil {
		t.Fatal("Enterprise accepted a publication with no approver; separation of duties is PRD 5.3 Full on Enterprise")
	}
	if !findings.Has(CodeApproverIsAuthor) {
		t.Fatalf("Enterprise refused the publication but not for the separation-of-duties reason; codes: %v", findings.Codes())
	}

	// Activation half: publish properly, then have the AUTHOR try to activate.
	opts = organizationPublishOptions(t, priv)
	art, _, err := api.Publish(context.Background(), organizationDocument(t), opts)
	if err != nil {
		t.Fatalf("the properly approved publication was refused: %v", err)
	}
	if _, err := api.Promote(context.Background(), pdp.RootOrganization, art.Digest(), alice, timeFixture(), "self"); err == nil {
		t.Fatal("Enterprise let the author activate their own version")
	} else if !strings.Contains(err.Error(), "separation of author and approver duties") {
		t.Fatalf("Enterprise refused the activation for the wrong reason: %v", err)
	}
}

// TestAnUnattributedActivationIsRefusedOnEveryEdition pins the half of the
// activation check that is NOT edition-conditional.
//
// The relaxation is "no second person required", not "no person required". An
// activation with no actor, or with an actor that is not a principal, is an
// unattributed change to enforced policy and is refused on Community exactly as
// on Enterprise. Without this test the two conditions sit in one function and
// the next edit that touches it has nothing holding them apart.
func TestAnUnattributedActivationIsRefusedOnEveryEdition(t *testing.T) {
	for _, ed := range AllEditions() {
		t.Run(string(ed), func(t *testing.T) {
			cat := baseCatalog(t)
			trust, priv := organizationTrust(t)
			api, err := NewAPI(cat, StaticTrust(trust), mustProfile(t, ed))
			if err != nil {
				t.Fatalf("NewAPI: %v", err)
			}
			d := communityDocument(t)
			opts := communityPublishOptions(t, priv, ed)
			if ed == EditionEnterprise {
				opts.Approvers = []contract.ID{pid(t, principalBob)}
			}
			art, _, err := api.Publish(context.Background(), d, opts)
			if err != nil {
				t.Fatalf("publish on %s: %v", ed, err)
			}
			if _, err := api.Promote(context.Background(), pdp.RootOrganization, art.Digest(), contract.ID{}, timeFixture(), "nobody"); err == nil {
				t.Fatalf("%s accepted an activation naming no actor", ed)
			}
			notAPrincipal := gid(t, groupFinance)
			if _, err := api.Promote(context.Background(), pdp.RootOrganization, art.Digest(), notAPrincipal, timeFixture(), "a group"); err == nil {
				t.Fatalf("%s accepted an activation whose actor is a %q rather than a principal", ed, notAPrincipal.Kind)
			}
		})
	}
}

// TestTheApiOverridesACallerSuppliedEdition proves the transport cannot widen
// its own boundary by naming one.
func TestTheApiOverridesACallerSuppliedEdition(t *testing.T) {
	cat := baseCatalog(t)
	trust, priv := organizationTrust(t)
	api, err := NewAPI(cat, StaticTrust(trust), mustProfile(t, EditionCommunity))
	if err != nil {
		t.Fatalf("NewAPI: %v", err)
	}
	opts := organizationPublishOptions(t, priv)
	// A caller claiming Enterprise on a Community surface. The baseline
	// document uses group scope, which Enterprise carries and Community does
	// not, so if the claim were honoured this would succeed.
	opts.Profile = mustProfile(t, EditionEnterprise)
	_, findings, err := api.Publish(context.Background(), organizationDocument(t), opts)
	if err == nil {
		t.Fatal("a Community authoring surface published an Enterprise-only construct because the request said Enterprise")
	}
	if !findings.Has(CodeGroupScopeNotInEdition) {
		t.Fatalf("refused for the wrong reason; codes: %v", findings.Codes())
	}
}

// TestPublishRefusesAnUnsetEdition pins the required-field decision. An
// omitted boundary must be a refusal and not a default, because the default a
// caller would silently get is the one thing this file exists to prevent.
//
// The zero Profile is the shape a caller can actually produce - Profile is a
// struct, so `PublishOptions{}` carries one whatever the constructors say -
// and it is the one that must be refused BY NAME. It would otherwise be an
// unnamed boundary that refuses every construct and, because tierEstablished
// is false in a zero value, requires a second approver: safe in both
// directions and declared by nobody, which is not a boundary this package
// enforces.
func TestPublishRefusesAnUnsetEdition(t *testing.T) {
	cat := baseCatalog(t)
	_, priv := testKeys(t)
	opts := communityPublishOptions(t, priv, EditionCommunity)
	opts.Profile = Profile{}
	_, _, err := Publish(context.Background(), communityDocument(t), cat, opts)
	if err == nil {
		t.Fatal("a publication naming no edition was accepted")
	}
	if !strings.Contains(err.Error(), "edition") {
		t.Fatalf("the refusal does not name the edition as the cause: %v", err)
	}
}

// TestConstructsReportsTheBoundaryBeforeItIsMet checks the shape a transport
// serves, since an author with no UI has nothing else to read it from.
func TestConstructsReportsTheBoundaryBeforeItIsMet(t *testing.T) {
	com, _ := ProfileFor(EditionCommunity)
	rep := com.Constructs()
	if rep.Edition != EditionCommunity {
		t.Fatalf("report names edition %q", rep.Edition)
	}
	if rep.GroupScope {
		t.Fatal("the community report claims group scope")
	}
	if rep.SeparationOfDuties {
		t.Fatal("the community report claims separation of duties")
	}
	if !containsString(rep.Namespaces, string(contract.NsPrincipal)) {
		t.Fatalf("the community report omits the principal namespace: %v", rep.Namespaces)
	}
	if containsString(rep.Namespaces, string(contract.NsState)) {
		t.Fatalf("the community report includes the platform-state namespace: %v", rep.Namespaces)
	}
	// A reserved construct is reported as reserved and NOT as permitted, so a
	// caller can tell "you may not" from "nobody has said".
	if !containsString(rep.Reserved, "obligation_family:"+string(contract.FamilyStepUp)) {
		t.Fatalf("the community report does not name the reserved step-up family: %v", rep.Reserved)
	}
	if containsString(rep.ObligationFamilies, string(contract.FamilyStepUp)) {
		t.Fatalf("a reserved family is reported as permitted: %v", rep.ObligationFamilies)
	}
	ent, _ := ProfileFor(EditionEnterprise)
	entRep := ent.Constructs()
	if !containsString(entRep.ObligationFamilies, string(contract.FamilyStepUp)) {
		t.Fatalf("Enterprise does not carry the reserved family: %v", entRep.ObligationFamilies)
	}
	if !containsString(entRep.Reserved, "obligation_family:"+string(contract.FamilyStepUp)) {
		t.Fatal("Enterprise carries the reserved family but does not report it as reserved; the question is still open on every edition")
	}
}
