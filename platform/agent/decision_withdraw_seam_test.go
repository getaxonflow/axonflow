// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"testing"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// enfLedgerDocuments is an active-document source whose tip walks an activation
// ledger: a digest and a sequence number, where an empty digest at a sequence
// past zero is a withdrawal - the durable store's ActiveTip reports one exactly
// that way (PRD v11 §1.15).
type enfLedgerDocuments struct {
	tip    string
	seq    int64
	source *enfDocuments
}

func (d *enfLedgerDocuments) ActiveTip(context.Context, string) (string, int64, error) {
	return d.tip, d.seq, nil
}

func (d *enfLedgerDocuments) Load(ctx context.Context, orgID, digest string) (*authoring.Artifact, *pdp.TrustStore, error) {
	return d.source.Load(ctx, orgID, digest)
}

// WITHDRAWING IS A FRESH INSTALL (PRD v11 §1.15). A decision after a withdrawal
// carries, byte for byte, the policy bundle a never-activated organization's
// decision carries, and its policy epoch has advanced past the activation it
// withdrew, so nothing issued under the withdrawn document survives it. The
// template digest the ledger entry names is audit provenance and never reaches
// the decision.
func TestAWithdrawnOrganizationIsDecidedAsANeverActivatedOneWithTheEpochAdvanced(t *testing.T) {
	enfSetup(t)
	ctx := context.Background()
	noLLM := enfPublishConstraints(t, enfSnapshot(t), enfConstraint{"ceiling.no_llm_for_alice", enfUser, []string{authoringcatalog.ActionLLMCompletion}})
	published, _, err := noLLM.ActiveTip(ctx, enfOrgPublished)
	if err != nil || published == "" {
		t.Fatalf("the fixture document has no tip: %q %v", published, err)
	}
	docs := &enfLedgerDocuments{source: noLLM}
	enforcer, in := enfSeamUnit(t, docs)
	e := enforcer(t)
	local, ok := decideActionForStage(in.stage)
	if !ok {
		t.Fatalf("stage %q maps to no registered action", in.stage)
	}
	decide := func(t *testing.T, tip string, seq int64) *contract.Decision {
		t.Helper()
		docs.tip, docs.seq = tip, seq
		v := e.evaluate(ctx, anchoredCall{
			scope: decideSeamScope, orgID: in.orgID, requestID: in.decisionID,
			subject: requestSubject(in.orgID, in.auth, in.user, in.userIdentity),
			action:  local, query: in.query, observation: in.observation, pep: in.pep,
		})
		if v.unavailable != "" || v.refusal != nil || v.decision == nil {
			t.Fatalf("tip %q seq %d: no decision (unavailable %q, refusal %v)", tip, seq, v.unavailable, v.refusal)
		}
		return v.decision
	}

	never := decide(t, "", 0)
	active := decide(t, published, 1)
	withdrawn := decide(t, "", 2)

	// THE CONTROL: the published document decides differently and under its own
	// bundle, so the equality below is not two reads of one constant.
	if never.State != contract.StateAllow || active.State == contract.StateAllow || withdrawn.State != contract.StateAllow {
		t.Fatalf("states never/active/withdrawn = %s/%s/%s; want allow, a refusal by the document, allow", never.State, active.State, withdrawn.State)
	}
	if active.Snapshot.PolicyBundle == never.Snapshot.PolicyBundle {
		t.Fatal("the published document decided under the implicit bundle's digest; the control proves nothing")
	}
	if withdrawn.Snapshot.PolicyBundle != never.Snapshot.PolicyBundle {
		t.Fatalf("after the withdrawal the decision carries bundle %s; a never-activated organization's carries %s - withdrawing must be a fresh install, byte for byte",
			withdrawn.Snapshot.PolicyBundle, never.Snapshot.PolicyBundle)
	}
	if withdrawn.Snapshot.PolicyEpoch != 2 || withdrawn.Snapshot.PolicyEpoch <= active.Snapshot.PolicyEpoch {
		t.Fatalf("policy epoch never/active/withdrawn = %d/%d/%d; the withdrawal must advance it past the activation it withdrew",
			never.Snapshot.PolicyEpoch, active.Snapshot.PolicyEpoch, withdrawn.Snapshot.PolicyEpoch)
	}
}
