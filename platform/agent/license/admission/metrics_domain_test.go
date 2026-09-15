// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package admission

import (
	"context"
	"testing"

	"axonflow/platform/agent/license"
	"axonflow/platform/shared/metricdomain"
)

// refusalLabelDomains declares, per label, what bounds the value on
// axonflow_tier_limit_refusals_total. Declared next to the metric (this
// package is outside platform/agent's guarded-file census, which registers
// the collector through RefusalsCollectorForTest) and checked LIVE below after
// the counter has been driven with every dimension, both limited editions and
// both reasons.
func refusalLabelDomains() map[string]metricdomain.Domain {
	dims := make([]string, 0, len(Dimensions()))
	for _, d := range Dimensions() {
		dims = append(dims, string(d))
	}
	return map[string]metricdomain.Domain{
		"dimension": metricdomain.Closed(
			"Dimension is a closed type; Admit refuses an invalid one with ErrInvalidRequest before any label is written",
			dims...),
		"edition": metricdomain.Closed(
			"editionLabel folds the tier onto five names with \"other\" as the fall-through; a refusal can only carry the two limited ones but the set is declared whole",
			Editions()...),
		"reason": metricdomain.Closed(
			"refuse() is called with one of two package constants and nothing else",
			Reasons()...),
	}
}

func admissionLabelDomains() map[string]metricdomain.Domain {
	d := refusalLabelDomains()
	d["source"] = metricdomain.Closed(
		"Source is a closed type assigned only from the five package constants",
		string(SourceUnlimitedTier), string(SourceSeenSet), string(SourceLedgerExisting), string(SourceLedgerAdmitted), string(SourceRefused))
	delete(d, "reason")
	return d
}

// TestRefusalLabelsStayInsideTheirDeclaredDomain drives a refusal of every
// shape and asks metricdomain.Check whether any series escaped.
func TestRefusalLabelsStayInsideTheirDeclaredDomain(t *testing.T) {
	for _, ed := range limitedEditions {
		ledger := newFakeLedger()
		leases := newFakeLeases()
		a := New(ledger, WithTierReader(readerFor(ed.tier, LicenceValid)), WithNodeLeases(leases),
			WithLimits(func(license.Tier) license.TierLimits {
				return license.TierLimits{MaxHumanPrincipals: 0, MaxServicePrincipals: 0, MaxNodes: 0, OrgPolicies: 0}
			}))
		for _, d := range Dimensions() {
			if dec, _ := a.Admit(context.Background(), Request{Dimension: d, OrgID: "dom", PrincipalID: "new"}); dec.Allowed {
				t.Fatalf("%s %s: expected an over_limit refusal", ed.edition, d)
			}
		}
		// The outage drive needs a POSITIVE limit: with a limit of 0 a failed
		// existence probe reports the ceiling, not a retryable outage (M7), so
		// driving it at 0 would never produce a dependency_unreachable series.
		b := New(ledger, WithTierReader(readerFor(ed.tier, LicenceValid)), WithNodeLeases(leases),
			WithLimits(func(license.Tier) license.TierLimits {
				return license.TierLimits{MaxHumanPrincipals: 3, MaxServicePrincipals: 3, MaxNodes: 3, OrgPolicies: 3}
			}))
		ledger.setDown(true)
		leases.setDown(true)
		for _, d := range Dimensions() {
			if dec, _ := b.Admit(context.Background(), Request{Dimension: d, OrgID: "dom", PrincipalID: "other"}); dec.Allowed || dec.Reason != ReasonDependencyUnreachable {
				t.Fatalf("%s %s: expected a dependency_unreachable refusal, got %+v", ed.edition, d, dec)
			}
		}
	}
	if problems := metricdomain.Check("axonflow_tier_limit_refusals_total", refusalsTotal, refusalLabelDomains()); len(problems) > 0 {
		t.Fatalf("refusal labels escaped their domain:\n%v", problems)
	}
	// Drive every source on the admissions counter, then check it too.
	a := New(newFakeLedger(), WithTierReader(readerFor(license.TierEnterprise, LicenceValid)))
	_, _ = a.Admit(context.Background(), Request{Dimension: HumanPrincipal, OrgID: "dom", PrincipalID: "p"})
	b := New(newFakeLedger(), WithTierReader(readerFor(license.TierCommunity, LicenceAbsent)))
	_, _ = b.Admit(context.Background(), Request{Dimension: HumanPrincipal, OrgID: "dom", PrincipalID: "p"}) // ledger_admitted
	_, _ = b.Admit(context.Background(), Request{Dimension: HumanPrincipal, OrgID: "dom", PrincipalID: "p"}) // seen_set
	c := New(b.ledger, WithTierReader(readerFor(license.TierCommunity, LicenceAbsent)))
	_, _ = c.Admit(context.Background(), Request{Dimension: HumanPrincipal, OrgID: "dom", PrincipalID: "p"}) // ledger_existing
	if problems := metricdomain.Check("axonflow_tier_admissions_total", admissionsTotal, admissionLabelDomains()); len(problems) > 0 {
		t.Fatalf("admission labels escaped their domain:\n%v", problems)
	}
	// The background-drop counter was NOT covered until R3 round 2, and the
	// gap was not theoretical: the panic handler read the dimension from the
	// wrong field on the audit branch and emitted dimension="" for as long as
	// nothing was looking. Both of its label sets are already closed in the
	// package (Dimensions, BackgroundDropReasons), so there was never a reason
	// to leave it out.
	if problems := metricdomain.Check("axonflow_tier_admission_background_drops_total", backgroundDropsTotal, backgroundDropLabelDomains()); len(problems) > 0 {
		t.Fatalf("background-drop labels escaped their domain:\n%v", problems)
	}
}

// backgroundDropLabelDomains declares the two closed sets for the drop counter.
func backgroundDropLabelDomains() map[string]metricdomain.Domain {
	dims := make([]string, 0, len(Dimensions()))
	for _, d := range Dimensions() {
		dims = append(dims, string(d))
	}
	return map[string]metricdomain.Domain{
		"dimension": metricdomain.Closed(
			"every drop site takes its dimension from the queued write, which carries one of the four Dimension constants; an empty label means a site read a field the other kind of write populates",
			dims...),
		"reason": metricdomain.Closed(
			"the literals the drop sites pass, and nothing else; the set is BackgroundDropReasons rather than a count, so adding a reason cannot make this description stale",
			BackgroundDropReasons()...),
	}
}
