// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
	sharedidentity "axonflow/platform/shared/identity"
)

// The approval world #4370's cells share across both builds: the Enterprise
// cells (approval_hold_mcp_enterprise_test.go) hold in it, and the Community
// twin (approval_hold_mcp_community_test.go) proves it still refuses.

// ahToolCallAction is the action mcp:request decides.
var ahToolCallAction = "Action::" + authoringcatalog.ActionToolCall

// ahRequirementPolicy is the world's one requirement.
const ahRequirementPolicy = "require.approval_alice_tools"

// ahApprovalDocument holds every tool.call alice makes for one approver from
// the minted realm's approvers group.
func ahApprovalDocument() pdp.Document {
	tool := contract.MustParseID(contract.KindAction, ahToolCallAction)
	req := pdp.Policy{
		ID: ahRequirementPolicy, Authority: contract.AuthorityRequirement, Root: pdp.RootOrganization, Mandatory: true,
		Scope:   pdp.Scope{Organization: true},
		Actions: pdp.ActionSelector{Actions: []contract.ID{tool}},
		Where:   pdp.Compare(pdp.PrincipalIDPath, pdp.OpEq, enfMintedPrincipal(enfUser)),
	}
	pool := legacycompile.ApprovalPool{Quorum: 1, Eligible: []string{"Group::" + string(sharedidentity.BuiltinRealmMinted) + ":approvers"}}
	return pdp.Document{
		Root: pdp.RootOrganization, Version: 1,
		Attributes: []pdp.AttributeSchema{
			{Path: pdp.PrincipalIDPath, Type: pdp.TypeString},
			{Path: pdp.ActionIDPath, Type: pdp.TypeString},
			{Path: pdp.ActionTagsPath, Type: pdp.TypeArray},
		},
		Policies: []pdp.Policy{*legacycompile.ApprovalPolicy(req, pool)},
	}
}

func ahApprovalFixture() []authoring.Fixture {
	now := time.Now().UTC()
	return []authoring.Fixture{{
		Name: "alice's tool call meets the approval requirement",
		Attributes: contract.AttributeSet{
			pdp.PrincipalIDPath: contract.Known(enfMintedPrincipal(enfUser), contract.ProvAuthentication, 1, now),
			pdp.ActionIDPath:    contract.Known(ahToolCallAction, contract.ProvPlatform, 1, now),
			pdp.ActionTagsPath:  contract.Known([]any{"stage:" + authzenActionStage[authoringcatalog.ActionToolCall]}, contract.ProvPlatform, 1, now),
		},
		Expect: map[string]pdp.Verdict{ahRequirementPolicy: pdp.VerdictMatch},
	}}
}

// ahCheckPolicy calls check_policy as session, with args beside the statement
// and header as the X-Axonflow-Approval-Id header ("" sends none).
func ahCheckPolicy(t *testing.T, w *mrsWorld, session *mcpSession, statement string, args map[string]interface{}, header string) map[string]interface{} {
	t.Helper()
	ctx := context.WithValue(context.Background(), ContextKeyOrgID, w.org)
	ctx = context.WithValue(ctx, approvalIDHeaderKey{}, header)
	all := map[string]interface{}{"connector_type": "postgres", "tool": "run_query", "statement": statement}
	for k, v := range args {
		all[k] = v
	}
	resp, err := mcpToolCheckPolicy(ctx, session, all, pepHandshakeResolution{})
	if err != nil {
		t.Fatalf("check_policy failed rather than answering: %v", err)
	}
	return resp.(map[string]interface{})
}

// ahDecide drives handleDecide as an Enterprise caller in org, presenting token
// as its user token, for a tool.call on query, naming approvalID by header
// ("" names none) and bodyID in the request's approval_id field.
func ahDecide(t *testing.T, org, token, query, approvalID, bodyID string) enfResponse {
	t.Helper()
	return ahDecideWithContext(t, org, token, query, approvalID, bodyID, nil)
}

// ahDecideWithContext is ahDecide sending reqContext as the request's context.
func ahDecideWithContext(t *testing.T, org, token, query, approvalID, bodyID string, reqContext map[string]interface{}) enfResponse {
	t.Helper()
	body := DecideRequest{Stage: DecisionStageTool, Target: DecisionTarget{Type: DecisionStageTool, Tool: "run_query"}, Query: query, UserToken: token, ApprovalID: bodyID, Context: reqContext}
	req := decideEnterpriseReq(t, body, org, org)
	if approvalID != "" {
		req.Header.Set(approvalIDHeader, approvalID)
	}
	rr := httptest.NewRecorder()
	handleDecide(rr, req)
	out := enfResponse{code: rr.Code, raw: rr.Body.Bytes(), body: map[string]json.RawMessage{}}
	if err := json.Unmarshal(rr.Body.Bytes(), &out.body); err != nil {
		t.Fatalf("the response is not a JSON object: %v\n%s", err, rr.Body.String())
	}
	return out
}

// ahDecideWorld is decide's enforcing world with the approval document
// published for enfOrgPublished.
func ahDecideWorld(t *testing.T) {
	t.Helper()
	enfSetup(t)
	enfInstallSeam(t, enfPublishPolicyDocumentAs(t, authoring.EditionEnterprise, enfSnapshot(t), ahApprovalDocument(), ahApprovalFixture()))
}
