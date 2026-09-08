// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package pdp

import (
	"context"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"axonflow/platform/decision/contract"
)

// THE PER-REQUEST PEP PROFILE REACHES ALL THREE COMPOSITION SITES (#3706).
//
// e.pep used to be read in three places - CombineInput.PEP for every hop,
// MeetOptions.PEP for the multi-hop meet, and ComposeInput.PEP inside
// applyCompatibility, which bypasses CombineInput entirely. A change written
// from the first site alone would leave the other two answering against the
// engine-wide profile, silently, because each remaining site keeps passing its
// own tests. So there is a test per site, and each is written to fail if ONLY
// its own site is reverted.
//
// # HOW A SITE IS ISOLATED, AND WHY MOST OF THESE READ AS A PERMIT
//
// The obvious probe - a per-request profile that LACKS a capability, expecting
// a refusal - isolates site 1 only. It cannot isolate sites 2 and 3, because
// site 1 runs first: the per-hop Combine would already have denied, and the
// test would pass with sites 2 and 3 still reading e.pep. An assertion that
// cannot fail for the site it names is not evidence about that site.
//
// The isolating probe is the mirror: the PER-REQUEST profile SUPPORTS the
// capability and the ENGINE-WIDE one does not. Then site 1 permits, and the
// site under test is the only thing that can still refuse. If it reads e.pep
// the request is denied; if it reads the per-request profile the request is
// permitted. Each test below therefore expects a PERMIT and fails on a DENY,
// and the deny is exactly what the mutant produces.
//
// Both directions are asserted where both can be: sites 1 and 3 also carry the
// "lacks the capability, and the refusal comes from the PDP" probe the issue
// describes.

const auditObligationSource = "R1"

// obligationDoc is a document whose requirement policy attaches ONE mandatory
// immutable-audit obligation to the action under test. That obligation is what
// makes the capability check decide the outcome.
func obligationDoc() *Document {
	d := testDoc()
	d.Policies = append(d.Policies, Policy{
		ID:        auditObligationSource,
		Authority: contract.AuthorityRequirement,
		Root:      RootSystem,
		Mandatory: true,
		Scope:     Scope{Organization: true},
		Actions:   ActionSelector{RequiredTags: []string{"spend"}},
		Where:     True(),
		Obligations: []contract.Obligation{{
			Type:          contract.ObImmutableAudit,
			Params:        map[string]string{"level": "high", "channel": "audit", "delivery": string(contract.DeliveryDurable)},
			SourcePolicy:  auditObligationSource,
			SchemaVersion: 1,
		}},
	})
	return d
}

func auditCapableProfile(id string) *contract.PEPProfile {
	return &contract.PEPProfile{
		ID:           id,
		Capabilities: []contract.Capability{{Type: contract.ObImmutableAudit, Version: 1}},
	}
}

// engineWithProfiles builds an engine over d whose ENGINE-WIDE profile is pep.
func engineWithProfiles(t *testing.T, d *Document, pep *contract.PEPProfile, compat *CompatibilityProfile) *Engine {
	t.Helper()
	b, err := BuildBundle(d)
	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := b.Sign("k1", priv); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	ts := NewTrustStore()
	ts.Authorize(d.Root, "k1", pub)
	e, err := NewEngine(context.Background(), EngineConfig{
		Bundles:       []*Bundle{b},
		Documents:     []*Document{d},
		TrustStore:    ts,
		PayloadLeaves: []string{"response.ssn", "response.name"},
		PEP:           pep,
		Compat:        compat,
		Registry: &Registry{
			Actions: map[string]ActionEntry{
				"Action::stripe.create_refund": {
					ID:                 contract.MustParseID(contract.KindAction, "Action::stripe.create_refund"),
					Tags:               []string{"spend"},
					MaxDelegationDepth: 3,
					Arguments:          map[string]ValueType{"amount_cents": TypeNumber},
				},
			},
			Realms: map[string]bool{"realm_ws": true, "jira": true},
		},
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e
}

// SITE 1 of 3: CombineInput.PEP, read by every per-hop Combine.
func TestSite1TheCombineInputProfileIsTheRequestsProfile(t *testing.T) {
	ctx := context.Background()

	t.Run("per-request profile LACKS the capability: the PDP refuses", func(t *testing.T) {
		// The ENGINE could discharge the obligation; the caller cannot. The
		// refusal must come from the PDP, on the request's profile.
		e := engineWithProfiles(t, obligationDoc(), auditCapableProfile("engine-pep"), nil)
		dec, err := e.DecideWith(ctx, testRequest(baseAttrs()), DecideOptions{
			PEP: &contract.PEPProfile{ID: "deaf-pep"},
		})
		if err != nil {
			t.Fatalf("DecideWith: %v", err)
		}
		if dec.Authorization != contract.AuthzDeny || dec.Reason != contract.ReasonUnsupportedObligation {
			t.Fatalf("a caller that cannot discharge a mandatory obligation was not refused by the PDP: authorization=%q reason=%q",
				dec.Authorization, dec.Reason)
		}
		// The refusal must name the enforcement point that advertised, so an
		// operator reading it learns WHICH caller could not discharge it -
		// which is the difference between a per-request check and an
		// engine-wide one that cannot say who was asked.
		if !strings.Contains(remediationOf(dec), "deaf-pep") {
			t.Errorf("the refusal does not name the enforcement point that advertised: remediation=%q", remediationOf(dec))
		}
	})

	t.Run("per-request profile SUPPORTS it and the engine's does not: permitted", func(t *testing.T) {
		// This is the isolating direction. With site 1 reverted to e.pep the
		// per-hop Combine denies and this fails.
		//
		// THE ENGINE PROFILE MUST BE DEAF, and it was not: this line built the
		// engine with auditCapableProfile("deaf-engine"), which despite the
		// name DOES carry the capability. Both profiles were capable, the
		// permit came out either way, and the assertion could not fail for the
		// site it names - reverting site 1 left this sub-test GREEN while its
		// own comment said it would red. Sites 2 and 3 use the empty literal,
		// which is what was meant here.
		//
		// The name was the evidence. A helper called auditCapableProfile,
		// handed an id called "deaf-engine", reads as a deaf profile at a
		// glance and is the opposite of one.
		e := engineWithProfiles(t, obligationDoc(), &contract.PEPProfile{ID: "deaf-engine"}, nil)
		dec, err := e.DecideWith(ctx, testRequest(baseAttrs()), DecideOptions{
			PEP: auditCapableProfile("capable-caller"),
		})
		if err != nil {
			t.Fatalf("DecideWith: %v", err)
		}
		if dec.Authorization != contract.AuthzPermit {
			t.Fatalf("SITE 1 did not read the per-request profile: a caller that CAN discharge the obligation was refused (authorization=%q reason=%q)",
				dec.Authorization, dec.Reason)
		}
	})

	t.Run("no per-request profile: the engine-wide one still applies", func(t *testing.T) {
		e := engineWithProfiles(t, obligationDoc(), auditCapableProfile("engine-pep"), nil)
		dec, err := e.Decide(ctx, testRequest(baseAttrs()))
		if err != nil {
			t.Fatalf("Decide: %v", err)
		}
		if dec.Authorization != contract.AuthzPermit {
			t.Fatalf("the engine-wide profile stopped applying when no per-request profile was supplied: %q/%q", dec.Authorization, dec.Reason)
		}
	})
}

// SITE 2 of 3: MeetOptions.PEP, the multi-hop meet.
//
// The meet RECOMPOSES the union of the permitted hops' obligations, so it runs
// the capability check a second time. Reaching it needs a chain of more than
// one actor: MeetDecisions returns the single entry untouched otherwise.
func TestSite2TheMeetProfileIsTheRequestsProfile(t *testing.T) {
	ctx := context.Background()
	e := engineWithProfiles(t, obligationDoc(), &contract.PEPProfile{ID: "deaf-engine"}, nil)

	req := testRequest(baseAttrs())
	// A second hop, sharing the first's identity attributes so both hops
	// resolve the same way and both permit. Without this the meet is not
	// reached at all and the test would prove nothing about site 2.
	if len(req.Context.ActorChain) != 1 {
		t.Fatalf("the fixture request carries %d actors; this test needs to extend a single-actor chain", len(req.Context.ActorChain))
	}
	first := req.Context.ActorChain[0]
	// The second hop carries the FIRST hop's identity attributes verbatim, so
	// both hops resolve identically and both permit. That is deliberate: this
	// test isolates the MEET, and a second hop that decided differently for a
	// policy reason would change the outcome for a reason that has nothing to
	// do with which profile the meet read.
	agent := contract.MustParseID(contract.KindPrincipal, "Agent::realm_ws:refund-bot")
	attrs := contract.AttributeSet{}
	for k, v := range first.Attributes {
		attrs[k] = v
	}
	req.Context.ActorChain = append(req.Context.ActorChain, contract.Actor{ID: agent, Attributes: attrs})

	// TWO PRECONDITIONS, BOTH ASSERTED, because each alone is only necessary.
	//
	// R3 round 1 neutered the second-actor append and this test still passed:
	// MeetDecisions returns a single entry untouched and a one-hop request
	// still permits. R3 round 2 then found the second route with the first
	// precondition in place - revert site 2 AND drift the requirement policy
	// so no mandatory obligation attaches, and the capability check never
	// runs at all, because the PEP loop skips non-mandatory obligations. An
	// empty union reads the profile zero times, so the outcome is a permit
	// either way.
	//
	// So the meet must have more than one entry to combine, AND the combined
	// set must contain the mandatory obligation whose support is the thing
	// under test. The second is asserted after the decision, below.
	if len(req.Context.ActorChain) != 2 {
		t.Fatalf("the request carries %d actors; MeetDecisions returns a single entry UNTOUCHED, so with fewer than two hops this test cannot say anything about site 2",
			len(req.Context.ActorChain))
	}

	dec, err := e.DecideWith(ctx, req, DecideOptions{PEP: auditCapableProfile("capable-caller")})
	if err != nil {
		t.Fatalf("DecideWith: %v", err)
	}
	if dec.Authorization == contract.AuthzDeny && dec.Reason == contract.ReasonUnsupportedObligation {
		t.Fatalf("SITE 2 did not read the per-request profile: every hop permitted against the caller's profile and the MEET then refused against the engine-wide one (authorization=%q reason=%q)",
			dec.Authorization, dec.Reason)
	}
	if dec.Authorization != contract.AuthzPermit {
		t.Fatalf("the two-hop request was not permitted for an unrelated reason (%q/%q); this test can no longer isolate site 2 and must be repaired, not deleted",
			dec.Authorization, dec.Reason)
	}
	// THE SECOND PRECONDITION. The capability check only runs over MANDATORY
	// obligations, so a decision that carries none never consults a profile
	// and this test would be green with site 2 reverted.
	var mandatory int
	for _, o := range dec.Obligations {
		if o.Mandatory {
			mandatory++
		}
	}
	if mandatory == 0 {
		t.Fatalf("the permitted decision carries no MANDATORY obligation (%d obligation(s) in total), so the capability check never ran and neither the meet's profile nor any other could have been consulted; the fixture policy has drifted and this test is asserting nothing about site 2",
			len(dec.Obligations))
	}
	// THE THIRD PRECONDITION, and the one round 3 found unasserted: the
	// ENGINE-WIDE profile must be one that would decide DIFFERENTLY. Both
	// checks above are satisfied by an engine profile that is also capable, and
	// then site 2 could read either profile and produce the same permit - so
	// editing line 180 to hand this engine a capable profile would leave the
	// test green with site 2 reverted.
	//
	// Asserted as a MEASUREMENT of the engine's ACTUAL profile - e.pep, read
	// from the engine rather than restated here. Restating it is how this
	// assertion would pass while saying nothing: a literal deaf profile denies
	// whatever the engine holds, so the control has to be the engine's own
	// value or it is not a control at all.
	control, err := e.DecideWith(ctx, req, DecideOptions{PEP: e.pep})
	if err != nil {
		t.Fatalf("control DecideWith under the engine-wide profile: %v", err)
	}
	if control.Authorization != contract.AuthzDeny || control.Reason != contract.ReasonUnsupportedObligation {
		t.Fatalf("the engine-wide profile PERMITS this request too (authorization=%q reason=%q), so the two profiles do not disagree and site 2 could read either one and still produce the permit asserted above; give the engine a profile that cannot discharge the mandatory obligation",
			control.Authorization, control.Reason)
	}
}

// SITE 3 of 3: ComposeInput.PEP inside applyCompatibility - a DIRECT call that
// never passes through CombineInput.
//
// It is reached only when the decision is NotApplicable and an unexpired
// compatibility exception covers the action. The exception carries a mandatory
// immutable-audit obligation, so the capability check decides whether the
// exception may be applied at all.
func TestSite3TheCompatibilityProfileIsTheRequestsProfile(t *testing.T) {
	ctx := context.Background()
	action := contract.MustParseID(contract.KindAction, "Action::stripe.create_refund")
	compat := &CompatibilityProfile{Entries: []CompatibilityEntry{{
		Action:       action,
		Owner:        "platform",
		ExpiresAt:    time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		RemovalIssue: "#3706",
	}}}

	// A request that matches no permission: NotApplicable, which is the only
	// state applyCompatibility acts on. The base document's permission requires
	// the support-tier2 group, so a principal without it falls through.
	notApplicable := func() *contract.Request {
		req := testRequest(baseAttrs())
		attrs := req.Context.ActorChain[0].Attributes
		attrs["principal.groups"] = contract.Known([]any{}, contract.ProvDirectory, 83, req.EvaluatedAt)
		return req
	}

	t.Run("per-request profile SUPPORTS the audit obligation, engine's does not: exception applies", func(t *testing.T) {
		e := engineWithProfiles(t, testDoc(), &contract.PEPProfile{ID: "deaf-engine"}, compat)
		dec, err := e.DecideWith(ctx, notApplicable(), DecideOptions{PEP: auditCapableProfile("capable-caller")})
		if err != nil {
			t.Fatalf("DecideWith: %v", err)
		}
		if dec.Authorization != contract.AuthzPermit {
			t.Fatalf("SITE 3 did not read the per-request profile: the caller CAN write the compatibility audit record and the exception was refused anyway (authorization=%q reason=%q, warnings=%v)",
				dec.Authorization, dec.Reason, warningsOf(dec))
		}
	})

	t.Run("per-request profile LACKS it, engine's has it: exception refused", func(t *testing.T) {
		// The mirror direction, and it isolates site 3 too: nothing else in
		// this evaluation consults a profile, because a NotApplicable decision
		// carries no mandatory obligations of its own.
		e := engineWithProfiles(t, testDoc(), auditCapableProfile("engine-pep"), compat)
		dec, err := e.DecideWith(ctx, notApplicable(), DecideOptions{PEP: &contract.PEPProfile{ID: "deaf-caller"}})
		if err != nil {
			t.Fatalf("DecideWith: %v", err)
		}
		if dec.Authorization == contract.AuthzPermit {
			t.Fatal("SITE 3 granted a compatibility exception to an enforcement point that cannot write its mandatory audit record; the exception is only tolerable BECAUSE that record is written")
		}
		var found bool
		for _, w := range warningsOf(dec) {
			if strings.Contains(w, "mandatory audit obligation cannot be discharged") {
				found = true
			}
		}
		if !found {
			t.Errorf("the refusal to apply the exception was not recorded as a warning: %v", warningsOf(dec))
		}
	})
}

func warningsOf(d *contract.Decision) []string {
	if d == nil || d.Trace == nil {
		return nil
	}
	return d.Trace.Warnings
}

func remediationOf(d *contract.Decision) string {
	if d == nil || d.Trace == nil {
		return ""
	}
	return d.Trace.Remediation
}
