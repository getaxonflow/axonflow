// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// POST /api/v1/decide READS NO SEGMENTS (PRD v11 §1.1, §1.2).
//
// #3456 (ADR-060 Slice 3) made /decide resolve the caller's governance-segment
// set before evaluation, so a segment-scoped static_policies row could enforce
// there, and refused the request when that resolution failed. v11 retired both
// halves: /decide is decided by the anchored engine, which reads no segments,
// and an organization's segment-scoped rows no longer decide anywhere the
// anchored engine does. What this file pins is the consequence: the handler
// never consults the segment resolver, for any caller, and a resolver that
// would fail changes nothing.
//
// FIXTURES. The markers and segment ids are #3447's
// (mcp_rest_segment_enforcement_test.go), where the MCP request pass still
// resolves segments (W3-H). /decide runs behind apiAuthMiddleware, so
// decideEnterpriseReq injects the authenticated identity via CONTEXT
// (decision_handler_test.go).

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	sharedidentity "axonflow/platform/shared/identity"
	sharedpolicy "axonflow/platform/shared/policy"
)

const (
	// The authenticated deployment identity for these tests. The tenant is
	// stamped into the request context AND into the minted token's tenant_id
	// claim: handleDecide denies on a mismatch (tenant_mismatch), so a drift
	// here would look like something else entirely.
	seg3456Tenant = "seg3456-tenant"
	seg3456Org    = "org-3456"

	seg3456MemberEmail = "alice-member-3456@corp.example"
)

// setupDecide3456 wires an enterprise /decide deployment: a JWT secret so the
// body's user_token validates, no auth DB, an enterprise circuit breaker over
// sqlmock (a real DENY verdict makes the breaker record a violation, and a nil
// *sql.DB there would segfault), no dynamic evaluator, and a clean detection
// cache. usageDB is nil'd.
func setupDecide3456(t *testing.T) {
	t.Helper()
	t.Setenv("DEPLOYMENT_MODE", "enterprise")

	origAuthDB := authDB
	authDB = nil
	t.Cleanup(func() { authDB = origAuthDB })

	origSecret := jwtSecret
	jwtSecret = []byte(testJWTSecret)
	t.Cleanup(func() { jwtSecret = origSecret })

	withChecker(t, nil)

	origUsageDB := usageDB
	usageDB = nil
	t.Cleanup(func() { usageDB = origUsageDB })

	sharedpolicy.ResetGlobalExfiltrationChecker()
	t.Cleanup(sharedpolicy.ResetGlobalExfiltrationChecker)

	installCircuitBreakerWithMockDB(t)

	// DEPLOYMENT_MODE just changed under a process-global cache.
	ResetDetectionConfigCache()
	t.Cleanup(ResetDetectionConfigCache)

	ResetFleetSegmentResolverForTest()
	t.Cleanup(ResetFleetSegmentResolverForTest)
}

// seg3456MintUserToken mints a valid per-user HS256 token for email, carrying
// the tenant/org this deployment authenticates as.
func seg3456MintUserToken(t *testing.T, email string) string {
	t.Helper()
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss":       sharedidentity.UserTokenIssuer,
		"sub":       email,
		"tenant_id": seg3456Tenant,
		"org_id":    seg3456Org,
		"email":     email,
		"jti":       "jti-seg3456-" + email,
		"role":      "developer",
		"exp":       time.Now().Add(time.Hour).Unix(),
	}).SignedString(jwtSecret)
	if err != nil {
		t.Fatalf("mint user token: %v", err)
	}
	return tok
}

// seg3456Decide drives the real handler with the given body content and
// optional per-user token, through the same context-injected enterprise
// identity the middleware would stamp.
func seg3456Decide(t *testing.T, token, query string) *httptest.ResponseRecorder {
	t.Helper()
	req := decideEnterpriseReq(t, DecideRequest{
		Stage:     DecisionStageLLM,
		Target:    DecisionTarget{Type: "llm", Model: "gpt-4o", Provider: "openai"},
		Query:     query,
		UserToken: token,
	}, seg3456Tenant, seg3456Org)
	rr := httptest.NewRecorder()
	handleDecide(rr, req)
	return rr
}

// TestDecideReadsNoSegments: /decide never consults the segment resolver, and
// the request is decided by the anchored engine, whoever the caller is and
// whatever the resolver would answer. The gate that stood in front of the
// evaluation refused a verified human when resolution failed, on behalf of an
// organization's segment-scoped rows, which no longer decide.
func TestDecideReadsNoSegments(t *testing.T) {
	member := func(t *testing.T) string { return seg3456MintUserToken(t, seg3456MemberEmail) }
	membership := sharedidentity.ResolvedIdentity{Segments: []sharedidentity.Segment{{ID: sharedidentity.SegmentID(seg3447MemberSegment)}}}
	for _, tc := range []struct {
		name     string
		token    func(t *testing.T) string
		resolver *fakeSegmentResolver
	}{
		{"a verified human, and a resolver that fails", member, &fakeSegmentResolver{err: errors.New("segment query failed (3456)")}},
		{"a verified human, and a resolver that would answer a membership", member, &fakeSegmentResolver{resolved: membership}},
		{"a caller with no user token", func(*testing.T) string { return "" }, &fakeSegmentResolver{resolved: membership}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setupDecide3456(t)
			withFleetSegmentResolver(t, tc.resolver)

			rr := seg3456Decide(t, tc.token(t), seg3447Benign)
			if rr.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
			}
			var resp DecideResponse
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode: %v: %s", err, rr.Body.String())
			}
			if resp.Engine != decisionEngineAnchored {
				t.Fatalf("engine = %q, want %q: the anchored engine authors /decide's verdict", resp.Engine, decisionEngineAnchored)
			}
			if c := tc.resolver.callCount(); c != 0 {
				t.Fatalf("/decide consulted the segment resolver %d time(s); it reads no segments", c)
			}
		})
	}
}
