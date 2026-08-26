// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// #3447 (ADR-060 Slice 3) — the ORCHESTRATOR half of the MCP dynamic plane's
// segment enforcement.
//
// Threading the agent-resolved segment set into the local static pass closes
// only HALF the bypass on the three MCP routes that run runDynamicPolicy:
// evaluateInputPolicies (agent/mcp_handler.go) relays to THIS handler first
// and evaluates static locally second, so a verified segment member would
// still get segment-scoped DYNAMIC policies silently skipped while the static
// half enforced them — a split verdict on one request.
//
// The wire now carries MCPPolicyEvaluationRequest.SegmentIDs, and
// getPoliciesForMCP passes it to ListActivePoliciesForTenant (which has
// accepted a segmentIDs argument since #3052 — this was a threading job, not
// new machinery). These tests pin the threading END TO END through the real
// route, plus the exact value handed to the engine.
//
// The orchestrator deliberately does NOT resolve segments for itself: the
// agent and orchestrator hold separate segment caches with separate TTL
// clocks, so a second resolution could observe a different set on the SAME
// request. See MCPPolicyEngine's doc comment.

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
)

// seg3447CapturingEngine records the segmentIDs getPoliciesForMCP hands it and
// applies the same restriction-only predicate the real engines do: a
// segment-scoped policy is returned iff the caller's set contains its segment.
type seg3447CapturingEngine struct {
	policies []DynamicPolicy
	// calls records every segmentIDs argument seen, in order — so a test can
	// distinguish "nil was passed" from "the method was never called".
	calls [][]string
}

func (e *seg3447CapturingEngine) ListActivePoliciesForTenant(tenantID string, segmentIDs []string) []DynamicPolicy {
	e.calls = append(e.calls, segmentIDs)
	var out []DynamicPolicy
	for _, p := range e.policies {
		if !p.Enabled || (p.TenantID != "" && p.TenantID != tenantID) {
			continue
		}
		if p.SegmentID != "" {
			member := false
			for _, s := range segmentIDs {
				if s == p.SegmentID {
					member = true
					break
				}
			}
			if !member {
				continue
			}
		}
		out = append(out, p)
	}
	return out
}

// seg3447Policy is a content-type policy (the type getPoliciesForMCP admits,
// #3061) that blocks any statement matching pattern, optionally scoped to a
// governance segment.
func seg3447Policy(id, tenantID, segmentID, pattern string) DynamicPolicy {
	return DynamicPolicy{
		ID:        id,
		Name:      "seg3447 " + id,
		Type:      "content",
		Enabled:   true,
		TenantID:  tenantID,
		SegmentID: segmentID,
		Conditions: []PolicyCondition{
			{Field: "query", Operator: "regex", Value: pattern},
		},
		Actions: []PolicyAction{
			{Type: "block", Config: map[string]interface{}{"reason": "blocked by " + id}},
		},
	}
}

// evaluateMCPSeg3447 drives the REAL route through the REAL router (the
// threading under test lives on the request path, so calling
// getPoliciesForMCP directly would not exercise the decode) and returns both
// the response and the engine that served it.
func evaluateMCPSeg3447(t *testing.T, engine *seg3447CapturingEngine, req MCPPolicyEvaluationRequest) MCPPolicyEvaluationResponse {
	t.Helper()
	req = defaultOrgFromTenant(req)
	router := mux.NewRouter()
	NewMCPDynamicPolicyHandler(engine).RegisterRoutes(router)

	jsonBody, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	httpReq := httptest.NewRequest("POST", "/api/v1/mcp/evaluate-policies", bytes.NewBuffer(jsonBody))
	httpReq.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, httpReq)

	if rr.Code != 200 {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var resp MCPPolicyEvaluationResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return resp
}

const (
	seg3447Tenant  = "tenant-3447"
	seg3447Segment = "finance-3447"
	seg3447Pattern = "confidential_ledger_3447"
)

// TestMCP3447_SegmentIDsReachListActivePoliciesForTenant is the threading pin:
// the exact set the agent put on the wire must be the exact set the engine is
// asked with. Pre-#3447 getPoliciesForMCP passed a hardcoded nil, so this
// fails on the unfixed handler even though the request carried the set.
func TestMCP3447_SegmentIDsReachListActivePoliciesForTenant(t *testing.T) {
	engine := &seg3447CapturingEngine{}

	evaluateMCPSeg3447(t, engine, MCPPolicyEvaluationRequest{
		TenantID:      seg3447Tenant,
		ConnectorName: "postgres",
		Operation:     "execute",
		Statement:     "select 1",
		SegmentIDs:    []string{seg3447Segment, "eng-3447"},
	})

	if len(engine.calls) != 1 {
		t.Fatalf("ListActivePoliciesForTenant call count = %d, want exactly 1", len(engine.calls))
	}
	got := engine.calls[0]
	if len(got) != 2 || got[0] != seg3447Segment || got[1] != "eng-3447" {
		t.Fatalf("segmentIDs handed to the engine = %v, want [%s eng-3447] — the relayed set must reach the engine verbatim",
			got, seg3447Segment)
	}
}

// TestMCP3447_AbsentSegmentIDsIsOrgOnly: an absent set is org-only, matching
// the static plane's rule. nil, never a non-nil empty slice, so the engine's
// own predicate cannot accidentally distinguish the two.
func TestMCP3447_AbsentSegmentIDsIsOrgOnly(t *testing.T) {
	engine := &seg3447CapturingEngine{}

	evaluateMCPSeg3447(t, engine, MCPPolicyEvaluationRequest{
		TenantID:      seg3447Tenant,
		ConnectorName: "postgres",
		Operation:     "execute",
		Statement:     "select 1",
	})

	if len(engine.calls) != 1 {
		t.Fatalf("ListActivePoliciesForTenant call count = %d, want exactly 1", len(engine.calls))
	}
	if got := engine.calls[0]; len(got) != 0 {
		t.Fatalf("segmentIDs = %v, want empty for a request that carried none", got)
	}
}

// TestMCP3447_SegmentMemberBlockedOnDynamicPlane is the enforcement half: the
// same statement, the same policy, the same tenant — the ONLY difference
// between this test and the non-member one below is the relayed segment set.
func TestMCP3447_SegmentMemberBlockedOnDynamicPlane(t *testing.T) {
	engine := &seg3447CapturingEngine{policies: []DynamicPolicy{
		seg3447Policy("p-seg", seg3447Tenant, seg3447Segment, seg3447Pattern),
	}}

	resp := evaluateMCPSeg3447(t, engine, MCPPolicyEvaluationRequest{
		TenantID:      seg3447Tenant,
		ConnectorName: "postgres",
		Operation:     "execute",
		Statement:     "please read the " + seg3447Pattern + " for Q3",
		SegmentIDs:    []string{seg3447Segment},
	})

	if resp.Allowed {
		t.Fatalf("a member of %s must be blocked by the segment-scoped DYNAMIC policy, got %+v", seg3447Segment, resp)
	}
	if len(resp.MatchedPolicies) != 1 || resp.MatchedPolicies[0].PolicyID != "p-seg" {
		t.Fatalf("matched_policies = %+v, want exactly the segment-scoped policy p-seg — "+
			"a fail-closed deny would satisfy a bare allowed==false check", resp.MatchedPolicies)
	}
}

// TestMCP3447_NonMemberNotBlockedOnDynamicPlane: a caller in a DIFFERENT
// segment (not merely zero segments) must not be blocked, and the policy must
// be absent from evaluation entirely rather than merely failing to fire.
func TestMCP3447_NonMemberNotBlockedOnDynamicPlane(t *testing.T) {
	engine := &seg3447CapturingEngine{policies: []DynamicPolicy{
		seg3447Policy("p-seg", seg3447Tenant, seg3447Segment, seg3447Pattern),
	}}

	resp := evaluateMCPSeg3447(t, engine, MCPPolicyEvaluationRequest{
		TenantID:      seg3447Tenant,
		ConnectorName: "postgres",
		Operation:     "execute",
		Statement:     "please read the " + seg3447Pattern + " for Q3",
		SegmentIDs:    []string{"engineering-3447"},
	})

	if !resp.Allowed {
		t.Fatalf("a NON-member must not be blocked by a segment-scoped policy outside their segment, got %+v", resp)
	}
	if resp.PoliciesEvaluated != 0 {
		t.Fatalf("policies_evaluated = %d, want 0 — the segment-scoped row must be EXCLUDED from evaluation for a non-member, not merely fail to match",
			resp.PoliciesEvaluated)
	}
}

// TestMCP3447_OrgTierPolicyStillEnforcesForEveryone is the over-enforcement
// control: threading segments must be restriction-only. A policy with NO
// segment scope keeps enforcing for a member, a non-member and a caller with
// no set at all — otherwise "segments now apply" could silently mean "only
// segment members are governed".
func TestMCP3447_OrgTierPolicyStillEnforcesForEveryone(t *testing.T) {
	for _, tc := range []struct {
		name     string
		segments []string
	}{
		{"member", []string{seg3447Segment}},
		{"non-member", []string{"engineering-3447"}},
		{"no segments relayed", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine := &seg3447CapturingEngine{policies: []DynamicPolicy{
				seg3447Policy("p-org", seg3447Tenant, "", "org_wide_secret_3447"),
			}}

			resp := evaluateMCPSeg3447(t, engine, MCPPolicyEvaluationRequest{
				TenantID:      seg3447Tenant,
				ConnectorName: "postgres",
				Operation:     "execute",
				Statement:     "this query contains org_wide_secret_3447 data",
				SegmentIDs:    tc.segments,
			})

			if resp.Allowed {
				t.Fatalf("a non-segment-scoped policy must enforce regardless of segment membership, got %+v", resp)
			}
			if len(resp.MatchedPolicies) != 1 || resp.MatchedPolicies[0].PolicyID != "p-org" {
				t.Fatalf("matched_policies = %+v, want p-org", resp.MatchedPolicies)
			}
		})
	}
}

// TestMCP3447_MemberAllowedControl is the vacuity control for the block tests
// above: the SAME member, the SAME policy set, a statement matching nothing.
// Without it, "segment targeting works" and "the member is denied
// unconditionally" are indistinguishable.
func TestMCP3447_MemberAllowedControl(t *testing.T) {
	engine := &seg3447CapturingEngine{policies: []DynamicPolicy{
		seg3447Policy("p-seg", seg3447Tenant, seg3447Segment, seg3447Pattern),
	}}

	resp := evaluateMCPSeg3447(t, engine, MCPPolicyEvaluationRequest{
		TenantID:      seg3447Tenant,
		ConnectorName: "postgres",
		Operation:     "execute",
		Statement:     "what is the weather forecast",
		SegmentIDs:    []string{seg3447Segment},
	})

	if !resp.Allowed {
		t.Fatalf("a member sending a statement matching no policy must be allowed, got %+v", resp)
	}
	if resp.PoliciesEvaluated != 1 {
		t.Fatalf("policies_evaluated = %d, want 1 — the member's segment-scoped policy must still be IN scope (it simply did not match); "+
			"0 would mean the allow came from the row being excluded, not from a real evaluation", resp.PoliciesEvaluated)
	}
}
