// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package pdp

import (
	"testing"
	"time"

	"axonflow/platform/decision/contract"
)

// TestAnAdvisoryApprovalDoesNotChallengeTheRequest pins, at the seam where it
// reaches a caller, the invariant #3891 fixed one level down.
//
// `Combine` turns a composed approval requirement into `ReasonApprovalRequired`
// by a bare nil check (combine.go: `if outcome.Approval != nil`), so the ONLY
// thing standing between a detector's advisory approval obligation and a
// CHALLENGE is whether the algebra composed a requirement at all. Before the
// fix it did: an advisory-only approval produced `{1 of [<pool>]}` with nothing
// dropped, and this path turned it into an approval-required decision - a
// caller held for an approval no policy required, whose timeout is deny.
//
// The algebra's own golden table asserts `Approval == nil` for that input. This
// test exists because that is one seam away from the consequence: a future
// change that reintroduced an empty-but-non-nil requirement would satisfy a
// nil-check-free reading of the golden row and still challenge every request
// here. It asserts the OUTCOME a caller sees, not the intermediate value.
func TestAnAdvisoryApprovalDoesNotChallengeTheRequest(t *testing.T) {
	principal := contract.MustParseID(contract.KindPrincipal, "User::realm_ws:alice")
	action := contract.MustParseID(contract.KindAction, "Action::ticket.read")
	now := time.Now()

	req := &contract.Request{
		RequestID:    "r-advisory-approval",
		Organization: contract.MustParseID(contract.KindOrganization, "Organization::org_acme"),
		Principal:    principal,
		Action:       action,
		Resource:     contract.MustParseID(contract.KindResource, "Ticket::conn:T-1"),
		Context:      contract.Context{ActorChain: []contract.Actor{{ID: principal, Attributes: contract.AttributeSet{}}}},
		Snapshot:     contract.Snapshot{SchemaVersion: contract.SchemaVersion, PolicyBundle: "sha256:aa"},
		Attributes:   contract.AttributeSet{},
		EvaluatedAt:  now,
	}

	approval := func(mandatory bool, source, pool string) contract.Obligation {
		return contract.Obligation{
			Type: contract.ObApprovalChallenge, SourcePolicy: source, SchemaVersion: 1, Mandatory: mandatory,
			Params: map[string]string{"quorum": "1", "eligible": pool},
		}
	}
	pep := &contract.PEPProfile{ID: "pep", Capabilities: []contract.Capability{
		{Type: contract.ObApprovalChallenge, Version: 1},
	}}

	// One permission matches, and one REQUIREMENT policy carries the approval
	// obligation whose binding is the variable under test.
	build := func(o contract.Obligation, mandatory bool) CombineInput {
		return CombineInput{
			Request: req,
			Outcomes: []PolicyOutcome{
				{PolicyID: "perm", Authority: contract.AuthorityPermission, Root: RootOrganization, Verdict: VerdictMatch},
				{PolicyID: "req", Authority: contract.AuthorityRequirement, Root: RootOrganization, Verdict: VerdictMatch},
			},
			Meta: map[string]PolicyMeta{
				"perm": {ID: "perm", Authority: contract.AuthorityPermission, Root: RootOrganization},
				"req": {ID: "req", Authority: contract.AuthorityRequirement, Root: RootOrganization,
					Obligations: []contract.Obligation{o}, Mandatory: mandatory},
			},
			PEP:            pep,
			ApprovalExpiry: now.Add(time.Hour),
			DecisionID:     "d-1",
		}
	}

	t.Run("advisory only: permitted, with no approval and no challenge", func(t *testing.T) {
		dec, err := Combine(build(approval(false, "detector", "Group::realm_ws:nobody"), false))
		if err != nil {
			t.Fatalf("combine: %v", err)
		}
		if dec.Reason == contract.ReasonApprovalRequired {
			t.Fatalf("an ADVISORY approval obligation put the request into a challenge. Timeout is always deny, so a detector alone can now refuse a request. decision=%+v", dec)
		}
		if dec.Reason != contract.ReasonPermitted {
			t.Fatalf("reason = %q, want %q", dec.Reason, contract.ReasonPermitted)
		}
		if dec.Approval != nil {
			t.Fatalf("an approval requirement was composed from advisory obligations alone: %+v", dec.Approval)
		}
	})

	// THE POSITIVE CONTROL. Without it, "no challenge" would also be satisfied
	// by a build in which approval obligations reach nothing at all, and this
	// test would pass over a plane that had stopped challenging entirely.
	t.Run("mandatory: still challenges, so the rule is about the binding", func(t *testing.T) {
		dec, err := Combine(build(approval(true, "policy", "Group::realm_ws:leads"), true))
		if err != nil {
			t.Fatalf("combine: %v", err)
		}
		if dec.Reason != contract.ReasonApprovalRequired {
			t.Fatalf("reason = %q, want %q: a MANDATORY approval must still hold the request", dec.Reason, contract.ReasonApprovalRequired)
		}
		if dec.Approval == nil || len(dec.Approval.AllOf) != 1 {
			t.Fatalf("approval = %+v, want one clause", dec.Approval)
		}
	})
}
