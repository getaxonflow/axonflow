//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/contract"
)

// THE COMMUNITY TWIN OF #4370. HITL is Enterprise, so the Community build has
// no queue to hold in: a challenge on mcp:request keeps the refusal PRD v11
// §1.13 gives a plane with no hold - approval_required, naming the plane - and
// an approval id on the retry changes nothing, by header or by argument.
// Nothing is queued and nothing is read (approval_hold_community.go).
func TestCommunityACallHeldForApprovalIsStillRefusedApprovalRequired(t *testing.T) {
	w := mrsSetup(t)
	w.mrsWire(t, enfPublishPolicyDocumentAs(t, authoring.EditionEnterprise, enfSnapshot(t), ahApprovalDocument(), ahApprovalFixture()))
	alice := mrqSession(t, w.org, enfUser)
	id := uuid.NewString()
	for name, c := range map[string]struct {
		args   map[string]interface{}
		header string
	}{
		"a first call":                  {nil, ""},
		"a retry naming it by header":   {nil, id},
		"a retry naming it by argument": {map[string]interface{}{approvalIDArgument: id}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			resp := ahCheckPolicy(t, w, alice, "SELECT * FROM invoices", c.args, c.header)
			br, _ := resp["block_reason"].(string)
			if resp["allowed"] != false || resp["pending_approval"] != nil ||
				!strings.HasPrefix(br, string(contract.ReasonApprovalRequired)+": ") || !strings.Contains(br, "mcp:request") {
				t.Fatalf("allowed=%v pending=%v block_reason=%q; want today's approval_required refusal naming the plane, and no pending approval", resp["allowed"], resp["pending_approval"], br)
			}
		})
	}
}

// The decide twin: the Community build answers today's deny, never
// needs_approval, and an approval id changes nothing.
func TestCommunityADecideHeldForApprovalIsStillDeniedApprovalRequired(t *testing.T) {
	ahDecideWorld(t)
	token := enfMintUserToken(t, enfOrgPublished, enfUser)
	for _, id := range []string{"", uuid.NewString()} {
		r := ahDecide(t, enfOrgPublished, token, "SELECT 1", id, "")
		reasons := r.strings(t, "reasons")
		if r.str(t, "verdict") != VerdictDeny || len(reasons) == 0 || !strings.HasPrefix(reasons[0], string(contract.ReasonApprovalRequired)+": ") {
			t.Fatalf("verdict %q reasons %v; want today's deny approval_required. body=%s", r.str(t, "verdict"), reasons, r.raw)
		}
		if _, has := r.body["pending_approval"]; has {
			t.Fatalf("a community build answered a pending approval: %s", r.raw)
		}
	}
}
