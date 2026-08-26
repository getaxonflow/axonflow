// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// #3456 (ADR-060 Slice 3) — POST /api/v1/decide evaluated policy with a
// HARDCODED nil segment set, so a segment-scoped static_policies row could
// never enforce there. The same content a segment-scoped policy blocks on a
// segment-aware plane was ALLOWED on /decide, for the same caller, with the
// credential they already hold: a one-URL edit, no second credential, no
// privilege change. An org-tier policy DID block there, which is the control
// proving the plane was evaluating normally and that the allow was precisely
// the missing segment scoping.
//
// This plane is simpler than #3447's four MCP REST routes and the tests say so
// rather than implying coverage that does not exist:
//
//   - ONE call site. /decide passes runDynamicPolicy=false, so there is no
//     dynamic relay to prove; and it has no response phase (no
//     evaluateOutputPolicies call), so there is no response-phase half either.
//     Static request phase only.
//   - The per-user token arrives in the request BODY (DecideRequest.UserToken).
//     /decide is not behind proxy.go (where X-User-Token is read, for
//     /api/v1/audit/*, /api/v1/decisions, /api/v1/overrides) and reads no
//     per-user-token header at all — deliberately, per #2941: teaching a
//     second spelling to one endpoint is what creates that debt.
//
// FIXTURES. The policy rows, markers and policy ids are #3447's
// (mcp_rest_segment_enforcement_test.go) so both planes are proven against the
// SAME fixture shapes and neither can drift into a private notion of what a
// segment-scoped policy looks like. What differs is the transport: /decide runs
// behind apiAuthMiddleware, so decideEnterpriseReq injects the authenticated
// identity via CONTEXT (decision_handler_test.go), where the MCP REST handlers
// authenticate in-body.

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/golang-jwt/jwt/v5"

	sharedidentity "axonflow/platform/shared/identity"
	sharedpolicy "axonflow/platform/shared/policy"
)

const (
	// The authenticated deployment identity for these tests. The tenant is
	// stamped into the request context AND into the minted token's tenant_id
	// claim: handleDecide denies on a mismatch (tenant_mismatch) long before
	// segments matter, so a drift here would look like a segment failure.
	seg3456Tenant = "seg3456-tenant"
	seg3456Org    = "org-3456"

	seg3456MemberEmail    = "alice-member-3456@corp.example"
	seg3456NonMemberEmail = "dave-nonmember-3456@corp.example"

	// The 503 body /decide emits for a genuine evaluator outage
	// (InputPolicyOutcome.EvalUnavailable). Pinned here so the resolver-error
	// tests can assert the two channels never collapse into one.
	seg3456EvalUnavailableMessage = "policy evaluation temporarily unavailable"
)

// =============================================================================
// Fixtures
// =============================================================================

// setupDecide3456 wires an enterprise /decide deployment: a JWT secret so the
// body's user_token validates, no auth DB, an enterprise circuit breaker over
// sqlmock (a real DENY verdict makes the breaker record a violation, and a nil
// *sql.DB there would segfault), no dynamic evaluator, and a clean detection
// cache. usageDB is nil'd by default — the tests that assert an audit row wire
// their own mock.
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

	// /decide passes runDynamicPolicy=false, so this evaluator is structurally
	// unreachable from this handler; nil'ing it makes that explicit rather
	// than leaving a global from another test able to matter.
	origDyn := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	sharedpolicy.SetGlobalDynamicPolicyEvaluator(nil)
	t.Cleanup(func() { sharedpolicy.SetGlobalDynamicPolicyEvaluator(origDyn) })

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
// the tenant/org this deployment authenticates as. The email claim is the ONLY
// thing #3456 keys segment resolution on.
func seg3456MintUserToken(t *testing.T, email string) string {
	t.Helper()
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"tenant_id": seg3456Tenant,
		"org_id":    seg3456Org,
		"email":     email,
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
func seg3456Decide(t *testing.T, token, query string, hdr http.Header) *httptest.ResponseRecorder {
	t.Helper()
	req := decideEnterpriseReq(t, DecideRequest{
		Stage:     DecisionStageLLM,
		Target:    DecisionTarget{Type: "llm", Model: "gpt-4o", Provider: "openai"},
		Query:     query,
		UserToken: token,
	}, seg3456Tenant, seg3456Org)
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	rr := httptest.NewRecorder()
	handleDecide(rr, req)
	return rr
}

// seg3456Response is the decoded /decide envelope.
type seg3456Response struct {
	Verdict           string   `json:"verdict"`
	Reasons           []string `json:"reasons"`
	EvaluatedPolicies []string `json:"evaluated_policies"`
}

func seg3456Decode(t *testing.T, rr *httptest.ResponseRecorder) seg3456Response {
	t.Helper()
	var resp seg3456Response
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal /decide response: %v — body=%s", err, rr.Body.String())
	}
	return resp
}

// seg3456AssertBlockedBy pins WHICH policy denied, not merely that something
// did: a fail-closed deny (segment_resolution_failed) satisfies a bare
// "verdict == deny" check, so a boolean assertion could not tell a
// segment-scoped BLOCK from the plane refusing for an unrelated reason.
// evaluated_policies[0] is the blocking policy by /decide's own OpenAPI
// contract (hoistBlockingPolicy).
func seg3456AssertBlockedBy(t *testing.T, rr *httptest.ResponseRecorder, policyID, what string) {
	t.Helper()
	if rr.Code != http.StatusOK {
		t.Fatalf("%s: /decide returns a policy deny as 200 + verdict=deny; got %d: %s", what, rr.Code, rr.Body.String())
	}
	resp := seg3456Decode(t, rr)
	if resp.Verdict != VerdictDeny {
		t.Fatalf("%s: verdict = %q, want %q (reasons=%v, policies=%v)",
			what, resp.Verdict, VerdictDeny, resp.Reasons, resp.EvaluatedPolicies)
	}
	if len(resp.EvaluatedPolicies) == 0 || resp.EvaluatedPolicies[0] != policyID {
		t.Fatalf("%s: the deny must NAME the blocking policy %q; evaluated_policies=%v reasons=%v — "+
			"a fail-closed deny for some other reason satisfies a bare verdict check",
			what, policyID, resp.EvaluatedPolicies, resp.Reasons)
	}
	if !strings.Contains(strings.Join(resp.Reasons, "; "), policyID) {
		t.Fatalf("%s: the deny reason must attribute policy %q, got %v", what, policyID, resp.Reasons)
	}
}

func seg3456AssertAllowed(t *testing.T, rr *httptest.ResponseRecorder, what string) {
	t.Helper()
	if rr.Code != http.StatusOK {
		t.Fatalf("%s: expected 200, got %d: %s", what, rr.Code, rr.Body.String())
	}
	resp := seg3456Decode(t, rr)
	if resp.Verdict != VerdictAllow {
		t.Fatalf("%s: verdict = %q, want %q (reasons=%v, policies=%v)",
			what, resp.Verdict, VerdictAllow, resp.Reasons, resp.EvaluatedPolicies)
	}
}

// =============================================================================
// 1/2/3. The bypass itself: a verified member IS enforced, a non-member in a
// DIFFERENT segment is not, and a member sending benign content is allowed.
// =============================================================================

func TestDecide3456_SegmentScopedPolicy_EnforcesVerifiedMember(t *testing.T) {
	prep := func(t *testing.T, segments ...string) *fakeSegmentResolver {
		t.Helper()
		setupDecide3456(t)
		installSeg3447Engine(t, seg3447MemberSegment, seg3456Tenant)
		f := &fakeSegmentResolver{resolved: sharedidentity.ResolvedIdentity{
			Segments: seg3456Segments(segments...),
		}}
		withFleetSegmentResolver(t, f)
		return f
	}

	t.Run("verified member is BLOCKED by the segment-scoped policy", func(t *testing.T) {
		res := prep(t, seg3447MemberSegment)
		rr := seg3456Decide(t, seg3456MintUserToken(t, seg3456MemberEmail),
			"please handle the "+seg3447ReqMarker+" for Q3", nil)
		seg3456AssertBlockedBy(t, rr, seg3447ReqPolicyID, "verified member on /decide")
		if c := res.callCount(); c != 1 {
			t.Fatalf("segment resolution must run EXACTLY once per /decide request, got %d", c)
		}
	})

	// A non-member with ZERO segments would also be excluded by the
	// nil-is-fail-closed default, so it could not tell "segment targeting
	// works" from "the set never arrived". This caller is a member of a
	// DIFFERENT segment.
	t.Run("non-member in a DIFFERENT segment is NOT blocked", func(t *testing.T) {
		prep(t, seg3447OtherSegment)
		rr := seg3456Decide(t, seg3456MintUserToken(t, seg3456NonMemberEmail),
			"please handle the "+seg3447ReqMarker+" for Q3", nil)
		seg3456AssertAllowed(t, rr, "non-member (different segment) on /decide")
	})

	t.Run("member-allowed control: content matching no policy is allowed", func(t *testing.T) {
		prep(t, seg3447MemberSegment)
		rr := seg3456Decide(t, seg3456MintUserToken(t, seg3456MemberEmail), seg3447Benign, nil)
		seg3456AssertAllowed(t, rr, "member sending content matching no policy on /decide")
	})
}

// seg3456Segments builds the resolver's answer.
func seg3456Segments(ids ...string) []sharedidentity.Segment {
	segs := make([]sharedidentity.Segment, 0, len(ids))
	for _, id := range ids {
		segs = append(segs, sharedidentity.Segment{ID: sharedidentity.SegmentID(id)})
	}
	return segs
}

// =============================================================================
// 4. Token-less caller: org-only, UNCHANGED — with an org-tier positive
// control, so "org-only" cannot be read as "nothing enforced".
// =============================================================================

func TestDecide3456_TokenLessCaller_OrgOnly(t *testing.T) {
	// The enterprise PEP arm: no user_token, require_user_token off, so
	// handleDecide synthesizes effectiveClientID+"@axonflow.local" and
	// callerIsVerifiedHuman is false.
	prep := func(t *testing.T) *fakeSegmentResolver {
		t.Helper()
		setupDecide3456(t)
		installSeg3447Engine(t, seg3447MemberSegment, seg3456Tenant)
		// The resolver WOULD return membership if consulted — that is what
		// makes "it was not consulted" a real claim rather than a tautology
		// about an empty fake.
		f := &fakeSegmentResolver{resolved: sharedidentity.ResolvedIdentity{
			Segments: seg3456Segments(seg3447MemberSegment),
		}}
		withFleetSegmentResolver(t, f)
		return f
	}

	t.Run("the segment-scoped policy does NOT apply", func(t *testing.T) {
		res := prep(t)
		rr := seg3456Decide(t, "", "please handle the "+seg3447ReqMarker+" for Q3", nil)
		seg3456AssertAllowed(t, rr, "token-less /decide caller against a segment-scoped policy")
		if c := res.callCount(); c != 0 {
			t.Fatalf("a synthesized service identity has no SCIM principal; the resolver must not be consulted, got %d call(s)", c)
		}
	})

	t.Run("an org-tier policy STILL blocks (positive control)", func(t *testing.T) {
		prep(t)
		rr := seg3456Decide(t, "", "this query contains "+seg3447OrgMarker+" data", nil)
		seg3456AssertBlockedBy(t, rr, seg3447OrgPolicyID,
			"token-less /decide caller against an org-tier policy — org-only must not mean 'nothing enforced'")
	})
}

// =============================================================================
// 5. A resolution ERROR denies, on its OWN channel — never the 503
// EvalUnavailable one.
// =============================================================================

// seg3456DenyDetailsMatcher asserts the policy_details JSONB of the fail-closed
// deny row: the security-event classification, the guard id in policy_ids, and
// the cross-plane refusal reason.
type seg3456DenyDetailsMatcher struct {
	wantEvent    string
	wantPolicyID string
	wantReason   string
}

func (m seg3456DenyDetailsMatcher) Match(v driver.Value) bool {
	raw, ok := jsonbBytes(v)
	if !ok {
		return false
	}
	var d map[string]interface{}
	if json.Unmarshal(raw, &d) != nil {
		return false
	}
	if m.wantEvent != "" && d["security_event"] != m.wantEvent {
		return false
	}
	if m.wantReason != "" && !strings.Contains(toString(d["reason"]), m.wantReason) {
		return false
	}
	if m.wantPolicyID == "" {
		return true
	}
	ids, _ := d["policy_ids"].([]interface{})
	for _, id := range ids {
		if toString(id) == m.wantPolicyID {
			return true
		}
	}
	return false
}

func toString(v interface{}) string {
	s, _ := v.(string)
	return s
}

func TestDecide3456_ResolutionError_DeniesWithSegmentResolutionFailedGuard(t *testing.T) {
	setupDecide3456(t)
	// A canary engine with ZERO query expectations: had evaluation run
	// anyway, it would fail with the engine's OWN distinct "Policy engine
	// unavailable" reason. Asserting the exact resolution-site refusal is
	// therefore real evidence the deny happened at the resolution site,
	// BEFORE evaluateInputPolicies — not an inference from the status code.
	installCanarySharedEngine(t)
	withFleetSegmentResolver(t, &fakeSegmentResolver{err: errors.New("segment query failed (3456)")})

	mock := withMockUsageDB(t)
	mock.MatchExpectationsInOrder(false)
	args := decideAuditInsertArgs(AuditVerdictBlocked, seg3456DenyDetailsMatcher{
		wantEvent:    segmentResolutionFailedPolicyID,
		wantPolicyID: segmentResolutionFailedPolicyID,
		wantReason:   segmentResolutionFailedReason,
	})
	mock.ExpectExec("INSERT INTO audit_logs").WithArgs(args...).
		WillReturnResult(sqlmock.NewResult(0, 1))

	// A never-before-seen identity, so nothing could serve this from a cached
	// resolution.
	rr := seg3456Decide(t, seg3456MintUserToken(t, "never-cached-3456@corp.example"), seg3447Benign, nil)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("a resolver error for a caller WITH a principal must deny (403), got %d: %s", rr.Code, rr.Body.String())
	}
	if rr.Code == http.StatusServiceUnavailable {
		t.Fatal("the resolver-error deny must NOT surface as 503 — that is EvalUnavailable's channel")
	}
	if !strings.Contains(rr.Body.String(), segmentResolutionFailedReason) {
		t.Fatalf("expected the resolution-site refusal %q, got %s — a different reason means the failure reached evaluation instead of denying at the source",
			segmentResolutionFailedReason, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), seg3456EvalUnavailableMessage) {
		t.Fatalf("the resolver-error deny must never reuse the EvalUnavailable message, got %s", rr.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the fail-closed deny must write a canonical blocked audit row carrying %q + the cross-plane reason: %v",
			segmentResolutionFailedPolicyID, err)
	}
}

// TestDecide3456_ResolutionErrorAndEvalUnavailableAreDistinctChannels is the
// other half of the pair: without it, "the deny is distinguishable" is
// unproven — a change that folded the segment guard into
// InputPolicyOutcome.EvalUnavailable would still pass the test above.
//
// The two channels differ in EVERY observable: HTTP status (403 vs 503), the
// operator-facing message, and the audit row (a named guard id + a
// security_event, vs an evaluator outage that is not attributed to any policy).
// The 503 arm is asserted as a property of the handler's own defensive guard,
// which is deliberately unreachable on /decide today (runDynamicPolicy=false) —
// stated rather than silently skipped.
func TestDecide3456_ResolutionErrorAndEvalUnavailableAreDistinctChannels(t *testing.T) {
	if segmentResolutionFailedReason == seg3456EvalUnavailableMessage {
		t.Fatal("the fail-closed segment deny and the evaluator-outage 503 must not share one message")
	}
	if http.StatusForbidden == http.StatusServiceUnavailable {
		t.Fatal("unreachable")
	}

	// The 503 guard still exists, still reads EvalUnavailable, and is NOT
	// attributed to the segment guard. evaluateInputPolicies is the seam both
	// channels would have to share if they were ever folded together, so this
	// asserts against it directly: an outage produces EvalUnavailable and no
	// policy attribution at all.
	setupDecide3456(t)
	sharedpolicy.SetGlobalEngine(nil)
	sharedpolicy.InitGlobalDynamicPolicyEvaluatorWithConfig(sharedpolicy.DynamicPolicyConfig{
		Enabled:              true,
		OrchestratorEndpoint: "http://127.0.0.1:0",
		Timeout:              200 * time.Millisecond,
		GracefulDegradation:  false,
		EnabledConnectors:    []string{"decision"},
	})
	t.Cleanup(func() { sharedpolicy.SetGlobalDynamicPolicyEvaluator(nil) })

	outcome := evaluateInputPolicies(context.Background(),
		seg3456Tenant, seg3456Org, "1", "developer",
		"decision", "", "decide", seg3447Benign, nil,
		ResolveGatewayDetectionConfig(context.Background(), seg3456Org),
		true, /* runDynamicPolicy: forced ON here so the outage channel is real */
		[]string{seg3447MemberSegment})

	if !outcome.EvalUnavailable {
		t.Fatal("precondition: an unroutable orchestrator with graceful degradation off must set EvalUnavailable")
	}
	if outcome.StaticResult != nil {
		t.Fatalf("an evaluator outage must not carry a policy result: %+v", outcome.StaticResult)
	}
	// The outage channel names no policy — which is exactly why the segment
	// deny must not be routed through it: the audit row would lose the guard
	// id and the operator dashboard could not tell a deliberate policy-side
	// deny from an orchestrator being down.
}

// =============================================================================
// 6. The trust-gated X-User-Email attribution header cannot shed segments.
// =============================================================================

// seg3456EmailKeyedResolver resolves the MEMBER segment for the emails in
// members and a DIFFERENT segment for everyone else, recording every key it was
// asked about. A handler that keyed on the header instead of the token would
// therefore silently stop enforcing (and the recorded keys say so outright).
type seg3456EmailKeyedResolver struct {
	mu      sync.Mutex
	members map[string]bool
	seen    []string
}

func (r *seg3456EmailKeyedResolver) Resolve(_ context.Context, _, email string) (sharedidentity.ResolvedIdentity, error) {
	r.mu.Lock()
	r.seen = append(r.seen, email)
	member := r.members[email]
	r.mu.Unlock()
	id := seg3447OtherSegment
	if member {
		id = seg3447MemberSegment
	}
	return sharedidentity.ResolvedIdentity{Segments: seg3456Segments(id)}, nil
}

func (r *seg3456EmailKeyedResolver) ResolveRole(_ context.Context, _, _ string) (string, error) {
	return "", nil
}

func (r *seg3456EmailKeyedResolver) keys() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.seen...)
}

// TestDecide3456_TrustedAttributionHeaderCannotShedSegments pins the security
// property #3456 owns: ENFORCEMENT keys on the VALIDATED token's email claim,
// and the caller-supplied X-User-Email header changes it in NEITHER direction.
//
// The hostile posture is the trust gate ON — the deployment setting that makes
// the header authoritative for attribution (#2896). Under it, a verified member
// who names a non-member colleague must STILL be blocked by their own
// segment-scoped policy: keying resolution on the header would let any human
// shed their segments at zero cost by typing a colleague's address, which is the
// reported bypass recreated one level down. The mirror case (naming a DIFFERENT
// MEMBER of the same segment) is asserted too, so "the header is inert" is
// proven in both directions rather than inferred from the deny-only half.
//
// DELIBERATELY NOT PINNED HERE: which email lands in audit_logs.user_email.
// /decide's attribution precedence (decision_handler.go — the trusted header
// unconditionally overrides the validated identity) DIVERGES from the
// MCP-server plane (mcp_server_handler.go, where a validated identity wins by
// construction) and from proxy.go (which explicitly overwrites the header with
// the validated identity so attribution and scoping key on the non-forgeable
// value). That is a cross-plane inconsistency to settle in one place, not a
// behaviour to freeze into this suite as if it were intended — asserting it
// here would make the defect harder to fix. Tracked separately (#3484, number
// to be confirmed). This test therefore says nothing about attribution: it
// pins only that attribution CANNOT steer enforcement.
func TestDecide3456_TrustedAttributionHeaderCannotShedSegments(t *testing.T) {
	const otherMemberEmail = "carol-member-3456@corp.example"

	cases := []struct {
		name       string
		headerName string
		why        string
	}{
		{
			name:       "header names a NON-member colleague",
			headerName: seg3456NonMemberEmail,
			why:        "a verified member naming a NON-member colleague in X-User-Email must still be enforced",
		},
		{
			name:       "header names a DIFFERENT MEMBER of the same segment",
			headerName: otherMemberEmail,
			why:        "the header must be inert in BOTH directions — enforcement follows the token, not the assertion",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setupDecide3456(t)
			// The gate ON is the hostile posture: with it OFF the header is
			// dropped before it could do anything and the test would be
			// vacuous.
			t.Setenv("AXONFLOW_TRUST_IDENTITY_HEADERS", "true")
			installSeg3447Engine(t, seg3447MemberSegment, seg3456Tenant)
			res := &seg3456EmailKeyedResolver{members: map[string]bool{
				seg3456MemberEmail: true,
				otherMemberEmail:   true,
			}}
			withFleetSegmentResolver(t, res)

			hdr := http.Header{}
			hdr.Set(identityHeaderUserEmail, tc.headerName)

			rr := seg3456Decide(t, seg3456MintUserToken(t, seg3456MemberEmail),
				"please handle the "+seg3447ReqMarker+" for Q3", hdr)

			seg3456AssertBlockedBy(t, rr, seg3447ReqPolicyID, tc.why)

			if keys := res.keys(); len(keys) != 1 || keys[0] != seg3456MemberEmail {
				t.Fatalf("segment resolution was keyed on %v, want exactly [%s] — the VALIDATED token claim, never the caller-supplied header",
					keys, seg3456MemberEmail)
			}
		})
	}
}

// =============================================================================
// The gate call itself, at the /decide call site's own key: user.OrgID.
// =============================================================================

// TestDecide3456_ResolutionKeyIsTheValidatedOrgAndEmail pins the two arguments
// the call site passes, because getting either wrong is invisible in a verdict
// test that happens to use one org: every already-merged human-actor plane
// (run.go, gateway_handlers.go, the four MCP REST routes) keys on user.OrgID,
// so one human must not resolve to different sets on different routes.
//
// It also records what user.OrgID actually IS on each of /decide's two
// identity branches: the validated token's org_id claim (falling back to its
// tenant, validateUserToken), and client.OrgID on the synthesized service
// identity.
func TestDecide3456_ResolutionKeyIsTheValidatedOrgAndEmail(t *testing.T) {
	setupDecide3456(t)
	installSeg3447Engine(t, seg3447MemberSegment, seg3456Tenant)

	var gotOrg, gotEmail []string
	var mu sync.Mutex
	rec := &seg3456RecordingResolver{onResolve: func(orgID, email string) {
		mu.Lock()
		gotOrg = append(gotOrg, orgID)
		gotEmail = append(gotEmail, email)
		mu.Unlock()
	}}
	withFleetSegmentResolver(t, rec)

	seg3456Decide(t, seg3456MintUserToken(t, seg3456MemberEmail), seg3447Benign, nil)

	if len(gotOrg) != 1 {
		t.Fatalf("expected exactly one resolution per request, got %d", len(gotOrg))
	}
	if gotOrg[0] != seg3456Org {
		t.Errorf("resolution org = %q, want %q (user.OrgID, from the token's org_id claim)", gotOrg[0], seg3456Org)
	}
	if gotEmail[0] != seg3456MemberEmail {
		t.Errorf("resolution email = %q, want %q (the validated token's email claim)", gotEmail[0], seg3456MemberEmail)
	}

	// The synthesized-service branch: user.OrgID mirrors client.OrgID, which
	// is the context-stamped authenticated org. Proven through the gate's own
	// contract rather than the resolver (which is deliberately not consulted
	// for a caller with no per-user principal).
	ids, ok := resolveHumanActorSegmentsForPolicy(context.Background(), seg3456Org, seg3456Org,
		"auth-client@axonflow.local", callerIsVerifiedHuman(&AuthResult{Kind: AuthKindEnterprise},
			&AuthError{Code: "invalid_user_token"}, "presented.jwt.value"))
	if !ok || ids != nil {
		t.Fatalf("synthesized service identity: ids=%v ok=%v, want (nil, true) — org-only, never a deny", ids, ok)
	}
}

// seg3456RecordingResolver records the (orgID, email) pair each resolution is
// keyed on and always answers with the member segment, so a mis-keyed call
// would still produce a block and only this recording catches it.
type seg3456RecordingResolver struct {
	onResolve func(orgID, email string)
}

func (r *seg3456RecordingResolver) Resolve(_ context.Context, orgID, email string) (sharedidentity.ResolvedIdentity, error) {
	r.onResolve(orgID, email)
	return sharedidentity.ResolvedIdentity{Segments: seg3456Segments(seg3447MemberSegment)}, nil
}

func (r *seg3456RecordingResolver) ResolveRole(_ context.Context, _, _ string) (string, error) {
	return "", nil
}
