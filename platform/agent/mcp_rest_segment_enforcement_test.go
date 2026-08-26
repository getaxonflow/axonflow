// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// #3447 (ADR-060 Slice 3) — the four legacy MCP REST handlers
// (mcpQueryHandler /mcp/resources/query, mcpExecuteHandler
// /mcp/tools/execute, mcpCheckInputHandler /api/v1/mcp/check-input,
// mcpCheckOutputHandler /api/v1/mcp/check-output) authenticate a real human
// via ResolveUser -> validateUserToken and then passed Segments: nil
// unconditionally into policy evaluation. A verified SCIM member of a
// governance segment therefore had segment-scoped policies SILENTLY SKIPPED
// on these four URLs while the same human, on the same credential, was
// blocked on the MCP-server JSON-RPC plane (#3430). A one-URL edit evaded the
// control.
//
// Both planes are covered here and proven SEPARATELY, because wiring only one
// of them compiles and looks right:
//
//   - STATIC: the local shared-engine pass (evaluateInputPolicies'
//     EvalOptions.Segments / evaluateOutputPolicies' EvalOptions.Segments).
//   - DYNAMIC: the orchestrator relay (DynamicPolicyRequest.SegmentIDs ->
//     MCPPolicyEvaluationRequest.SegmentIDs -> getPoliciesForMCP ->
//     ListActivePoliciesForTenant). The orchestrator half is pinned in
//     orchestrator/mcp_dynamic_policy_segment_3447_test.go; the agent half
//     (does the resolved set actually reach the wire, and does it change the
//     verdict) is pinned here against a mock orchestrator.
//
// check-output has NO dynamic plane (runDynamicPolicy applies to
// evaluateInputPolicies only), so its coverage is static response-phase only
// — stated rather than silently omitted.
//
// FIXTURE NOTE. The knownClients static AXON- whitelist keys only satisfy
// license.ValidateLicense in the COMMUNITY build, so a fixture relying on them
// passes VACUOUSLY under `-tags enterprise`. These tests reuse the
// minted-licence machinery from mcp_rest_user_token_rejected_test.go
// (utrSetupTestKeypair / utrGenTestLicenseKey / the knownClients swap) with an
// org_id added to the payload, so Basic auth succeeds identically in BOTH
// build lanes and auth.OrgID is a real org rather than "".

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
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

	"axonflow/platform/connectors/base"
	"axonflow/platform/connectors/registry"
	"axonflow/platform/shared/idempotency"
	sharedidentity "axonflow/platform/shared/identity"
	sharedpolicy "axonflow/platform/shared/policy"
	"axonflow/platform/shared/policy/policytest"
)

const (
	// The caller's segment, and a DIFFERENT one for the non-member half: a
	// non-member with zero segments would also be excluded by the nil-is-
	// fail-closed default, so it could not tell "segment targeting works"
	// from "the set never arrived".
	seg3447MemberSegment = "finance-3447"
	seg3447OtherSegment  = "engineering-3447"

	seg3447OrgID = "org-3447"

	// Markers, each matching EXACTLY one fixture policy.
	seg3447ReqMarker  = "confidential_ledger_3447"          // segment-scoped, request phase
	seg3447OrgMarker  = "org_wide_secret_3447"              // org-tier (segment_id NULL), request phase
	seg3447RespMarker = "confidential_ledger_response_3447" // segment-scoped, response phase
	seg3447Benign     = "what is the weather forecast"

	// Policy ids, asserted by name so a fail-closed deny cannot pass for a
	// segment-scoped block (a boolean check would accept either).
	seg3447ReqPolicyID  = "seg3447_request_block"
	seg3447OrgPolicyID  = "org3447_control_block"
	seg3447RespPolicyID = "seg3447_response_block"

	seg3447Connector = "test-db" // registered connector for query/execute
)

// =============================================================================
// Fixtures
// =============================================================================

// seg3447GenLicenseKey mints an Ed25519-signed AXON- license carrying org_id,
// signed with utrTestEntSeedB64 (valid only once utrSetupTestKeypair has
// overridden the embedded public keys). ServiceName is deliberately absent —
// see utrGenTestLicenseKey's comment: a service license would open
// validateServiceLicense's permission bypass and skip the tenant/connector
// authorization these tests need to pass through.
func seg3447GenLicenseKey(t *testing.T, tier, orgID string) string {
	t.Helper()
	seed, err := base64.StdEncoding.DecodeString(utrTestEntSeedB64)
	if err != nil {
		t.Fatalf("decode test seed: %v", err)
	}
	privKey := ed25519.NewKeyFromSeed(seed)

	type payload struct {
		Tier      string `json:"tier"`
		TenantID  string `json:"tenant_id"`
		OrgID     string `json:"org_id"`
		IssuedAt  string `json:"issued_at"`
		ExpiresAt string `json:"expires_at"`
	}
	p := payload{
		Tier:      tier,
		TenantID:  "seg3447-test-deployment",
		OrgID:     orgID,
		IssuedAt:  time.Now().Format("20060102"),
		ExpiresAt: time.Now().AddDate(1, 0, 0).Format("20060102"),
	}
	pJSON, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal license payload: %v", err)
	}
	pB64 := base64.RawURLEncoding.EncodeToString(pJSON)
	sig := ed25519.Sign(privKey, []byte(pB64))
	return "AXON-" + pB64 + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// setupSeg3447Test wires an enterprise deployment whose Basic auth succeeds in
// BOTH build lanes on a minted, org-bearing licence; a JWT secret so
// validateUserToken can validate the per-user tokens these tests mint; an
// empty connector registry (tests that need one register it); and nils the
// optional services so the only DB traffic is the policy-engine load a test
// installs for itself.
func setupSeg3447Test(t *testing.T) {
	t.Helper()
	t.Setenv("DEPLOYMENT_MODE", "enterprise")

	origAuthDB := authDB
	authDB = nil
	t.Cleanup(func() { authDB = origAuthDB })

	utrSetupTestKeypair(t)
	minted := seg3447GenLicenseKey(t, "Enterprise", seg3447OrgID)
	origEntry, existed := knownClients[utrTestClientID]
	var origCopy *ClientAuth
	if existed {
		c := *origEntry
		origCopy = &c
	}
	knownClients[utrTestClientID] = &ClientAuth{
		ClientID:    utrTestClientID,
		LicenseKey:  minted,
		Name:        "Seg3447 Test Client (minted license)",
		TenantID:    utrTestTenant,
		Permissions: []string{"query", "llm", "connectors", "planning"},
		RateLimit:   1000,
		Enabled:     true,
	}
	t.Cleanup(func() {
		if existed {
			knownClients[utrTestClientID] = origCopy
		} else {
			delete(knownClients, utrTestClientID)
		}
	})

	origSecret := jwtSecret
	jwtSecret = []byte(testJWTSecret)
	t.Cleanup(func() { jwtSecret = origSecret })

	origRegistry := mcpRegistry
	mcpRegistry = registry.NewRegistry()
	t.Cleanup(func() { mcpRegistry = origRegistry })

	withChecker(t, nil)

	// usageDB nil: every audit writer these tests reach nil-guards on it.
	// The resolver-error tests wire their own sqlmock instead.
	origUsageDB := usageDB
	usageDB = nil
	t.Cleanup(func() { usageDB = origUsageDB })

	// Dynamic evaluator OFF by default so the static half is what is under
	// test; the dynamic tests install their own.
	origDyn := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	sharedpolicy.SetGlobalDynamicPolicyEvaluator(nil)
	t.Cleanup(func() { sharedpolicy.SetGlobalDynamicPolicyEvaluator(origDyn) })

	sharedpolicy.ResetGlobalExfiltrationChecker()
	t.Cleanup(sharedpolicy.ResetGlobalExfiltrationChecker)

	// The detection-config cache is process-global and DEPLOYMENT_MODE just
	// changed under it.
	ResetDetectionConfigCache()
	t.Cleanup(ResetDetectionConfigCache)
}

// installSeg3447Engine seeds THREE policies plus the mandatory system row on
// every load:
//
//	seg3447ReqPolicyID   segment-scoped (segmentID), request phase, block
//	seg3447OrgPolicyID   org-tier (segment_id NULL), request phase, block
//	seg3447RespPolicyID  segment-scoped (segmentID), response phase, block
//
// The response-phase row is sensitive-data on purpose: evaluateOutputPolicies'
// static pass enumerates only the PII / sensitive-data / security-dangerous
// categories, so the compliance-rbi category the request-phase rows use is
// never evaluated on the response phase and could prove nothing there. Callers
// needing the response row to BLOCK must also set SENSITIVE_DATA_ACTION=block
// (withSensitiveDataBlockPosture), because BuildActionOverrides rewrites that
// category's action to the deployment posture, whose default is warn.
func installSeg3447Engine(t *testing.T, segmentID, tenantID string) {
	t.Helper()
	mockDB, mockSQL, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = mockDB.Close() })
	mockSQL.MatchExpectationsInOrder(false)

	// Spare loads: query/execute evaluate BOTH phases in one request, and
	// each phase makes several category-enumeration loads. Unconsumed spares
	// are harmless (no ExpectationsWereMet assertion on this mock).
	for i := 0; i < 60; i++ {
		rows := policytest.SegmentScopedPolicyRow(sqlmock.NewRows(policytest.LoaderCols()),
			"seg3447-req", seg3447ReqPolicyID, tenantID, segmentID,
			"compliance-rbi", seg3447ReqMarker, "critical", "request", "block", 100)
		rows = orgTierControlPolicyRow(rows,
			"seg3447-org", seg3447OrgPolicyID, tenantID,
			"compliance-rbi", seg3447OrgMarker, "critical", "request", "block", 90)
		// Response-phase segment-scoped row, built literally so it can carry
		// an explicit action_response (SegmentScopedPolicyRow leaves it NULL).
		rows = rows.AddRow(
			"seg3447-resp", seg3447RespPolicyID, "Test policy "+seg3447RespPolicyID,
			"sensitive-data", "tenant", seg3447RespMarker, "critical",
			nil, "both", "block", "block",
			true, 100, tenantID, segmentID, []byte(`{}`),
			time.Now().UTC(),
		)
		rows = policytest.SystemPolicyRow(rows,
			"seg3447-sys", "sys_test_never_matches",
			"security-sqli", "ZZ_NEVER_MATCHES_ZZ", "low", "request", "block", 1)
		mockSQL.ExpectQuery("SELECT").WillReturnRows(rows)
	}
	policytest.ScopedTxPlumbing(mockSQL, 60)

	installGlobalEngine(t, mockDB)
}

// seg3447MintUserToken mints a valid per-user HS256 token for email. The
// email claim is the ONLY thing #3447 keys segment resolution on.
func seg3447MintUserToken(t *testing.T, email string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"tenant_id": utrTestTenant,
		"org_id":    seg3447OrgID,
		"email":     email,
		"role":      "developer",
		"exp":       time.Now().Add(time.Hour).Unix(),
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(jwtSecret)
	if err != nil {
		t.Fatalf("mint user token: %v", err)
	}
	return tok
}

// seg3447Resolver wires a fake segment resolver returning the given segment
// ids for every lookup, and returns it so a test can assert the call count
// (exactly one resolution per request — never two).
func seg3447Resolver(t *testing.T, segmentIDs ...string) *fakeSegmentResolver {
	t.Helper()
	segs := make([]sharedidentity.Segment, 0, len(segmentIDs))
	for _, id := range segmentIDs {
		segs = append(segs, sharedidentity.Segment{ID: sharedidentity.SegmentID(id)})
	}
	f := &fakeSegmentResolver{resolved: sharedidentity.ResolvedIdentity{Segments: segs}}
	withFleetSegmentResolver(t, f)
	return f
}

func seg3447RegisterConnector(t *testing.T, conn *mockConnector) {
	t.Helper()
	if err := mcpRegistry.Register(seg3447Connector, conn,
		&base.ConnectorConfig{Name: seg3447Connector, TenantID: "*"}); err != nil {
		t.Fatalf("register connector: %v", err)
	}
}

// =============================================================================
// Route drivers — one per handler, all four driven as real HTTP requests so a
// regression in the HANDLER-side wiring (not just in the helper) is caught.
// =============================================================================

func seg3447Post(t *testing.T, path string, body interface{}, h http.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	return seg3447PostWithHeaders(t, path, body, h, nil)
}

func seg3447PostWithHeaders(t *testing.T, path string, body interface{}, h http.HandlerFunc, extra http.Header) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	r := httptest.NewRequest("POST", path, bytes.NewBuffer(b))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", utrBasicAuthHeader())
	for k, vs := range extra {
		for _, v := range vs {
			r.Header.Add(k, v)
		}
	}
	w := httptest.NewRecorder()
	h(w, r)
	return w
}

func seg3447DoQuery(t *testing.T, token, statement string) *httptest.ResponseRecorder {
	t.Helper()
	return seg3447Post(t, "/mcp/resources/query", MCPQueryRequest{
		Connector: seg3447Connector, Statement: statement, UserToken: token,
	}, mcpQueryHandler)
}

func seg3447DoExecute(t *testing.T, token, statement string) *httptest.ResponseRecorder {
	t.Helper()
	return seg3447Post(t, "/mcp/tools/execute", MCPExecuteRequest{
		Connector: seg3447Connector, Action: "SELECT", Statement: statement, UserToken: token,
	}, mcpExecuteHandler)
}

func seg3447DoCheckInput(t *testing.T, token, statement string) *httptest.ResponseRecorder {
	t.Helper()
	return seg3447Post(t, "/api/v1/mcp/check-input", MCPCheckInputRequest{
		ConnectorType: "postgres", Statement: statement, UserToken: token,
	}, mcpCheckInputHandler)
}

func seg3447DoCheckOutput(t *testing.T, token, message string) *httptest.ResponseRecorder {
	t.Helper()
	return seg3447Post(t, "/api/v1/mcp/check-output", MCPCheckOutputRequest{
		ConnectorType: "postgres", Message: message, UserToken: token,
	}, mcpCheckOutputHandler)
}

// seg3447AssertBlockedBy pins WHICH policy fired, not merely that something
// did. The engine's BlockReason is "Blocked by policy: Test policy <id>" (the
// fixture rows carry no description), so the policy id is on the wire for
// every one of these four routes.
func seg3447AssertBlockedBy(t *testing.T, w *httptest.ResponseRecorder, policyID, what string) {
	t.Helper()
	if w.Code != http.StatusForbidden {
		t.Fatalf("%s: expected 403 (blocked by %s), got %d: %s", what, policyID, w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), policyID) {
		t.Fatalf("%s: expected the block attributed to policy %q, got %s — a fail-closed deny for some other reason satisfies a bare 403 check",
			what, policyID, w.Body.String())
	}
}

func seg3447AssertAllowed(t *testing.T, w *httptest.ResponseRecorder, what string) {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("%s: expected 200 (allowed), got %d: %s", what, w.Code, w.Body.String())
	}
}

// =============================================================================
// 1/2/3/4. STATIC plane — member enforced, non-member (in a DIFFERENT segment)
// not, member-allowed control, policy identity pinned. All four routes.
// =============================================================================

func TestMCP3447_StaticPlane_AllFourRoutes(t *testing.T) {
	// Route drivers keyed by the statement/message they should carry. query
	// and execute prove the REQUEST phase here; the RESPONSE phase of those
	// two routes is proven separately below (nil-ing one plane's set must not
	// leave the other's tests green).
	routes := []struct {
		name string
		// blockMarker is the marker the segment-scoped policy matches for
		// this route's phase, and blockPolicy the policy that must fire.
		blockMarker string
		blockPolicy string
		drive       func(t *testing.T, token, content string) *httptest.ResponseRecorder
		// needsConnector: the two managed-connector routes must reach a real
		// connector before policy evaluation runs.
		needsConnector bool
		// respPhase: this route's proof is the RESPONSE phase, which needs
		// the sensitive-data block posture.
		respPhase bool
	}{
		{"resources/query", seg3447ReqMarker, seg3447ReqPolicyID, seg3447DoQuery, true, false},
		{"tools/execute", seg3447ReqMarker, seg3447ReqPolicyID, seg3447DoExecute, true, false},
		{"check-input", seg3447ReqMarker, seg3447ReqPolicyID, seg3447DoCheckInput, false, false},
		{"check-output", seg3447RespMarker, seg3447RespPolicyID, seg3447DoCheckOutput, false, true},
	}

	for _, rt := range routes {
		t.Run(rt.name, func(t *testing.T) {
			prep := func(t *testing.T, segments ...string) *fakeSegmentResolver {
				t.Helper()
				setupSeg3447Test(t)
				if rt.respPhase {
					withSensitiveDataBlockPosture(t)
				}
				installSeg3447Engine(t, seg3447MemberSegment, utrTestTenant)
				if rt.needsConnector {
					seg3447RegisterConnector(t, &mockConnector{})
				}
				return seg3447Resolver(t, segments...)
			}

			t.Run("member is enforced", func(t *testing.T) {
				res := prep(t, seg3447MemberSegment)
				w := rt.drive(t, seg3447MintUserToken(t, "alice-member@corp.example"),
					"please handle the "+rt.blockMarker+" for Q3")
				seg3447AssertBlockedBy(t, w, rt.blockPolicy, "verified member on "+rt.name)
				if c := res.callCount(); c != 1 {
					t.Fatalf("segment resolution must run EXACTLY once per request, got %d", c)
				}
			})

			t.Run("non-member in a different segment is not enforced", func(t *testing.T) {
				prep(t, seg3447OtherSegment)
				w := rt.drive(t, seg3447MintUserToken(t, "dave-nonmember@corp.example"),
					"please handle the "+rt.blockMarker+" for Q3")
				seg3447AssertAllowed(t, w, "non-member on "+rt.name)
			})

			t.Run("member-allowed control", func(t *testing.T) {
				prep(t, seg3447MemberSegment)
				w := rt.drive(t, seg3447MintUserToken(t, "alice-member@corp.example"), seg3447Benign)
				seg3447AssertAllowed(t, w, "member sending a statement matching no policy on "+rt.name)
			})
		})
	}
}

// TestMCP3447_StaticResponsePhase_QueryAndExecute proves the RESPONSE-phase
// call site of the two managed-connector routes independently of their
// request-phase one: nil-ing evaluateOutputPolicies' segment set there must
// turn a test red, and the request-phase tests above would not notice.
func TestMCP3447_StaticResponsePhase_QueryAndExecute(t *testing.T) {
	// The connector's OUTPUT carries the response-phase marker; the caller's
	// statement is benign, so only the response phase can block.
	rows := []map[string]interface{}{{"note": "row carrying " + seg3447RespMarker + " data"}}

	routes := []struct {
		name  string
		conn  *mockConnector
		drive func(t *testing.T, token, content string) *httptest.ResponseRecorder
	}{
		{"resources/query", &mockConnector{queryResult: &base.QueryResult{Rows: rows, RowCount: 1, Duration: time.Millisecond}}, seg3447DoQuery},
		{"tools/execute", &mockConnector{executeResult: &base.CommandResult{RowsAffected: 1, Message: "done: " + seg3447RespMarker}}, seg3447DoExecute},
	}

	for _, rt := range routes {
		t.Run(rt.name, func(t *testing.T) {
			prep := func(t *testing.T, segments ...string) {
				t.Helper()
				setupSeg3447Test(t)
				withSensitiveDataBlockPosture(t)
				installSeg3447Engine(t, seg3447MemberSegment, utrTestTenant)
				seg3447RegisterConnector(t, rt.conn)
				seg3447Resolver(t, segments...)
			}

			t.Run("member is enforced on the response phase", func(t *testing.T) {
				prep(t, seg3447MemberSegment)
				w := rt.drive(t, seg3447MintUserToken(t, "alice-member@corp.example"), seg3447Benign)
				seg3447AssertBlockedBy(t, w, seg3447RespPolicyID, "response phase, verified member on "+rt.name)
			})

			t.Run("non-member is not enforced on the response phase", func(t *testing.T) {
				prep(t, seg3447OtherSegment)
				w := rt.drive(t, seg3447MintUserToken(t, "dave-nonmember@corp.example"), seg3447Benign)
				seg3447AssertAllowed(t, w, "response phase, non-member on "+rt.name)
			})
		})
	}
}

// =============================================================================
// 1 (dynamic half) + 8. DYNAMIC plane — the relayed set must reach the
// orchestrator request AND change the verdict there.
// =============================================================================

// seg3447DynamicOrchestrator stands in for the orchestrator's
// /api/v1/mcp/evaluate-policies. It records every segment_ids it received and
// blocks iff the request carried blockOnSegment — so the ONLY difference
// between a blocked and an allowed call is the relayed set.
type seg3447DynamicOrchestrator struct {
	mu              sync.Mutex
	received        [][]string
	sawField        bool
	blockOnSegment  string
	blockReasonText string
}

func (o *seg3447DynamicOrchestrator) record(ids []string, present bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.received = append(o.received, ids)
	if present {
		o.sawField = true
	}
}

func (o *seg3447DynamicOrchestrator) snapshot() ([][]string, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([][]string(nil), o.received...), o.sawField
}

func seg3447StartDynamicOrchestrator(t *testing.T, blockOnSegment string, connectors ...string) *seg3447DynamicOrchestrator {
	t.Helper()
	orch := &seg3447DynamicOrchestrator{
		blockOnSegment:  blockOnSegment,
		blockReasonText: "blocked by " + seg3447ReqPolicyID + " (dynamic plane)",
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Decode into a RAW map first so the assertion is about the JSON on
		// the wire, not about a struct that would silently default.
		var raw map[string]json.RawMessage
		body := struct {
			SegmentIDs []string `json:"segment_ids"`
		}{}
		buf := new(bytes.Buffer)
		if _, err := buf.ReadFrom(r.Body); err != nil {
			t.Errorf("orchestrator stub: read body: %v", err)
		}
		if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
			t.Errorf("orchestrator stub: decode raw body: %v", err)
		}
		if err := json.Unmarshal(buf.Bytes(), &body); err != nil {
			t.Errorf("orchestrator stub: decode body: %v", err)
		}
		_, present := raw["segment_ids"]
		orch.record(body.SegmentIDs, present)

		resp := sharedpolicy.DynamicPolicyResponse{Allowed: true, PoliciesEvaluated: 1}
		for _, s := range body.SegmentIDs {
			if s == orch.blockOnSegment {
				resp = sharedpolicy.DynamicPolicyResponse{
					Allowed:           false,
					BlockReason:       orch.blockReasonText,
					PoliciesEvaluated: 1,
					MatchedPolicies: []sharedpolicy.DynamicPolicyMatch{
						{PolicyID: seg3447ReqPolicyID, PolicyType: "content", Action: "block"},
					},
				}
				break
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(server.Close)

	// Static engine OFF so the verdict under test can only come from the
	// dynamic plane.
	origEngine := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(nil)
	t.Cleanup(func() { sharedpolicy.SetGlobalEngine(origEngine) })

	origEval := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	sharedpolicy.InitGlobalDynamicPolicyEvaluatorWithConfig(sharedpolicy.DynamicPolicyConfig{
		Enabled:              true,
		OrchestratorEndpoint: server.URL,
		Timeout:              5 * time.Second,
		GracefulDegradation:  false,
		EnabledConnectors:    connectors,
	})
	t.Cleanup(func() { sharedpolicy.SetGlobalDynamicPolicyEvaluator(origEval) })

	return orch
}

func TestMCP3447_DynamicPlane_RelayReachesOrchestratorAndEnforces(t *testing.T) {
	// check-output is absent on purpose: it runs no dynamic evaluation at all
	// (runDynamicPolicy is an evaluateInputPolicies concern).
	routes := []struct {
		name       string
		connectors []string
		withConn   bool
		drive      func(t *testing.T, token, content string) *httptest.ResponseRecorder
	}{
		{"resources/query", []string{seg3447Connector}, true, seg3447DoQuery},
		{"tools/execute", []string{seg3447Connector}, true, seg3447DoExecute},
		{"check-input", []string{"postgres"}, false, seg3447DoCheckInput},
	}

	for _, rt := range routes {
		t.Run(rt.name, func(t *testing.T) {
			prep := func(t *testing.T, segments ...string) *seg3447DynamicOrchestrator {
				t.Helper()
				setupSeg3447Test(t)
				if rt.withConn {
					seg3447RegisterConnector(t, &mockConnector{})
				}
				seg3447Resolver(t, segments...)
				return seg3447StartDynamicOrchestrator(t, seg3447MemberSegment, rt.connectors...)
			}

			t.Run("member: set relayed and dynamic policy blocks", func(t *testing.T) {
				orch := prep(t, seg3447MemberSegment)
				w := rt.drive(t, seg3447MintUserToken(t, "alice-member@corp.example"), seg3447Benign)

				got, sawField := orch.snapshot()
				if len(got) != 1 {
					t.Fatalf("expected exactly one orchestrator evaluation, got %d", len(got))
				}
				if !sawField {
					t.Fatal("the request body carried NO segment_ids field — the agent is not relaying the resolved set")
				}
				if len(got[0]) != 1 || got[0][0] != seg3447MemberSegment {
					t.Fatalf("relayed segment_ids = %v, want [%s]", got[0], seg3447MemberSegment)
				}
				if w.Code != http.StatusForbidden {
					t.Fatalf("expected 403 from the dynamic plane, got %d: %s", w.Code, w.Body.String())
				}
				if !strings.Contains(w.Body.String(), seg3447ReqPolicyID) {
					t.Fatalf("dynamic block must name the policy that fired, got %s", w.Body.String())
				}
			})

			t.Run("non-member: different set relayed, not blocked", func(t *testing.T) {
				orch := prep(t, seg3447OtherSegment)
				w := rt.drive(t, seg3447MintUserToken(t, "dave-nonmember@corp.example"), seg3447Benign)

				got, _ := orch.snapshot()
				if len(got) != 1 || len(got[0]) != 1 || got[0][0] != seg3447OtherSegment {
					t.Fatalf("relayed segment_ids = %v, want [%s]", got, seg3447OtherSegment)
				}
				seg3447AssertAllowed(t, w, "non-member on the dynamic plane of "+rt.name)
			})
		})
	}
}

// =============================================================================
// 5. Resolver error -> deny, with the named guard id, and DISTINGUISHABLE from
// EvalUnavailable / 503.
// =============================================================================

func TestMCP3447_ResolverError_DeniesWithSegmentResolutionFailedGuard(t *testing.T) {
	routes := []struct {
		name     string
		withConn bool
		drive    func(t *testing.T, token, content string) *httptest.ResponseRecorder
	}{
		{"resources/query", true, seg3447DoQuery},
		{"tools/execute", true, seg3447DoExecute},
		{"check-input", false, seg3447DoCheckInput},
		{"check-output", false, seg3447DoCheckOutput},
	}

	for _, rt := range routes {
		t.Run(rt.name, func(t *testing.T) {
			setupSeg3447Test(t)
			// A canary engine with ZERO query expectations: if evaluation ran
			// anyway it would fail with the engine's OWN distinct
			// "Policy engine unavailable" reason, so the exact-reason check
			// below is real evidence the deny happened at the resolution
			// site, before any evaluation.
			installCanarySharedEngine(t)
			if rt.withConn {
				seg3447RegisterConnector(t, &mockConnector{})
			}
			withFleetSegmentResolver(t, &fakeSegmentResolver{err: errors.New("segment query failed (3447)")})

			mockDB, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock.New: %v", err)
			}
			t.Cleanup(func() { _ = mockDB.Close() })
			mock.MatchExpectationsInOrder(false)
			usageDB = mockDB
			mock.ExpectExec("INSERT INTO audit_logs").
				WithArgs(
					sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
					sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
					sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
					mcpVerdictBlocked,
					utrPolicyIDsMatcher{want: mcpSegmentResolutionFailedPolicyID},
					sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
					sqlmock.AnyArg(), sqlmock.AnyArg(),
				).
				WillReturnResult(sqlmock.NewResult(0, 1))

			// A never-before-seen identity, so nothing could serve this from
			// a cached resolution.
			w := rt.drive(t, seg3447MintUserToken(t, "never-cached-3447-"+rt.name+"@corp.example"), seg3447Benign)

			if w.Code != http.StatusForbidden {
				t.Fatalf("a resolver error for a caller WITH a principal must deny (403), got %d: %s", w.Code, w.Body.String())
			}
			if w.Code == http.StatusServiceUnavailable {
				t.Fatal("the resolver-error deny must NOT surface as 503 — that is EvalUnavailable's channel")
			}
			if !strings.Contains(w.Body.String(), segmentResolutionFailedReason) {
				t.Fatalf("expected the resolution-site refusal text %q, got %s — a different reason means the failure reached evaluation instead of denying at the source",
					segmentResolutionFailedReason, w.Body.String())
			}
			if strings.Contains(w.Body.String(), "Dynamic policy evaluation unavailable") {
				t.Fatal("the resolver-error deny must never reuse the EvalUnavailable message")
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("the fail-closed deny must write a canonical blocked audit row carrying %q: %v",
					mcpSegmentResolutionFailedPolicyID, err)
			}
		})
	}
}

// TestMCP3447_EvalUnavailableStaysA503 is the other half of the pair above: on
// the SAME route, a genuine dynamic-evaluator outage must still be a 503 with
// the availability message and must NOT be attributed to the segment guard.
// Without this, "the deny is distinguishable" is unproven — a change that
// collapsed both into one channel would still pass the test above.
func TestMCP3447_EvalUnavailableStaysA503(t *testing.T) {
	setupSeg3447Test(t)
	seg3447Resolver(t, seg3447MemberSegment)
	// Unroutable orchestrator + GracefulDegradation off => EvalUnavailable.
	origEngine := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(nil)
	t.Cleanup(func() { sharedpolicy.SetGlobalEngine(origEngine) })
	origEval := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	sharedpolicy.InitGlobalDynamicPolicyEvaluatorWithConfig(sharedpolicy.DynamicPolicyConfig{
		Enabled:              true,
		OrchestratorEndpoint: "http://127.0.0.1:0",
		Timeout:              200 * time.Millisecond,
		GracefulDegradation:  false,
		EnabledConnectors:    []string{"postgres"},
	})
	t.Cleanup(func() { sharedpolicy.SetGlobalDynamicPolicyEvaluator(origEval) })

	w := seg3447DoCheckInput(t, seg3447MintUserToken(t, "alice-member@corp.example"), seg3447Benign)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("a dynamic-evaluator outage must stay a 503, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "Dynamic policy evaluation unavailable") {
		t.Fatalf("expected the availability message, got %s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), mcpSegmentResolutionFailedPolicyID) ||
		strings.Contains(w.Body.String(), segmentResolutionFailedReason) {
		t.Fatalf("an outage must never be attributed to the segment guard, got %s", w.Body.String())
	}
}

// =============================================================================
// 6. Token-less caller: org-only, unchanged — WITH an org-tier positive
// control, so "org-only" is not confused with "nothing enforced".
// =============================================================================

func TestMCP3447_TokenLessCaller_OrgOnly(t *testing.T) {
	prep := func(t *testing.T) *fakeSegmentResolver {
		t.Helper()
		setupSeg3447Test(t)
		installSeg3447Engine(t, seg3447MemberSegment, utrTestTenant)
		// The resolver WOULD return membership if it were consulted — that is
		// what makes "it was not consulted" a real claim rather than a
		// tautology about an empty fake.
		return seg3447Resolver(t, seg3447MemberSegment)
	}

	t.Run("segment-scoped policy does NOT apply", func(t *testing.T) {
		res := prep(t)
		w := seg3447DoCheckInput(t, "", "please handle the "+seg3447ReqMarker+" for Q3")
		seg3447AssertAllowed(t, w, "token-less caller against a segment-scoped policy")
		if c := res.callCount(); c != 0 {
			t.Fatalf("a synthetic service identity has no SCIM principal; the resolver must not be consulted, got %d calls", c)
		}
	})

	t.Run("org-tier policy STILL enforces (positive control)", func(t *testing.T) {
		prep(t)
		w := seg3447DoCheckInput(t, "", "this query contains "+seg3447OrgMarker+" data")
		seg3447AssertBlockedBy(t, w, seg3447OrgPolicyID,
			"token-less caller against an org-tier policy — org-only must not mean 'nothing enforced'")
	})
}

// =============================================================================
// 7. A validated token naming a SHARED SYNTHETIC identity: nil segments,
// org-only, and NOT a deny.
// =============================================================================

func TestMCP3447_SharedSyntheticTokenSubject_OrgOnlyNotADeny(t *testing.T) {
	for _, subject := range []string{
		"svc@axonflow.local",
		"orchestrator@axonflow.internal",
		sharedidentity.ClientPseudoIdentityPrefix + "some-client",
	} {
		t.Run(subject, func(t *testing.T) {
			setupSeg3447Test(t)
			installSeg3447Engine(t, seg3447MemberSegment, utrTestTenant)
			// Precondition: without it this test could pass for the wrong
			// reason (a subject that simply is not a member).
			if !sharedidentity.IsSharedSyntheticIdentity(subject, false) {
				t.Fatalf("precondition: %q must census as a shared synthetic or this test is vacuous", subject)
			}
			res := seg3447Resolver(t, seg3447MemberSegment)

			t.Run("segment-scoped policy does not apply, and it is not a deny", func(t *testing.T) {
				w := seg3447DoCheckInput(t, seg3447MintUserToken(t, subject),
					"please handle the "+seg3447ReqMarker+" for Q3")
				seg3447AssertAllowed(t, w, "shared-synthetic subject")
				if strings.Contains(w.Body.String(), mcpSegmentResolutionFailedPolicyID) {
					t.Fatalf("a shared-synthetic subject is org-only, NOT a fail-closed deny: %s", w.Body.String())
				}
				if c := res.callCount(); c != 0 {
					t.Fatalf("the resolver must not be keyed on a shared synthetic; got %d calls", c)
				}
			})

			t.Run("org-tier policy still enforces", func(t *testing.T) {
				w := seg3447DoCheckInput(t, seg3447MintUserToken(t, subject),
					"this query contains "+seg3447OrgMarker+" data")
				seg3447AssertBlockedBy(t, w, seg3447OrgPolicyID, "shared-synthetic subject, org-tier control")
			})
		})
	}
}

// =============================================================================
// The trust-gated X-User-Email header must NEVER be the segment-resolution
// key. Keying on it would recreate the reported bypass one level down: the
// same verified human sheds their segments by naming a non-member colleague,
// at zero cost, with the trust gate ON (the deployment posture that makes the
// header attribution-authoritative in the first place).
//
// Both handlers that compute attributedUserEmail are covered. The resolver is
// asserted to have been keyed on the TOKEN's email, not the header's.
// =============================================================================

// seg3447EmailKeyedResolver returns member segments only for wantEmail; every
// other identity resolves to a different segment. So a handler that keyed on
// the header would silently stop enforcing.
type seg3447EmailKeyedResolver struct {
	mu        sync.Mutex
	wantEmail string
	seen      []string
}

func (r *seg3447EmailKeyedResolver) Resolve(_ context.Context, _, email string) (sharedidentity.ResolvedIdentity, error) {
	r.mu.Lock()
	r.seen = append(r.seen, email)
	r.mu.Unlock()
	id := seg3447OtherSegment
	if email == r.wantEmail {
		id = seg3447MemberSegment
	}
	return sharedidentity.ResolvedIdentity{Segments: []sharedidentity.Segment{{ID: sharedidentity.SegmentID(id)}}}, nil
}

func (r *seg3447EmailKeyedResolver) ResolveRole(_ context.Context, _, _ string) (string, error) {
	return "", nil
}

func (r *seg3447EmailKeyedResolver) keys() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.seen...)
}

func TestMCP3447_TrustedHeaderCannotShedSegments(t *testing.T) {
	const memberEmail = "alice-member@corp.example"
	const colleagueEmail = "dave-nonmember@corp.example"

	routes := []struct {
		name    string
		marker  string
		policy  string
		respful bool
		drive   func(t *testing.T, token, content string, hdr http.Header) *httptest.ResponseRecorder
	}{
		{"check-input", seg3447ReqMarker, seg3447ReqPolicyID, false,
			func(t *testing.T, token, content string, hdr http.Header) *httptest.ResponseRecorder {
				t.Helper()
				return seg3447PostWithHeaders(t, "/api/v1/mcp/check-input", MCPCheckInputRequest{
					ConnectorType: "postgres", Statement: content, UserToken: token,
				}, mcpCheckInputHandler, hdr)
			}},
		{"check-output", seg3447RespMarker, seg3447RespPolicyID, true,
			func(t *testing.T, token, content string, hdr http.Header) *httptest.ResponseRecorder {
				t.Helper()
				return seg3447PostWithHeaders(t, "/api/v1/mcp/check-output", MCPCheckOutputRequest{
					ConnectorType: "postgres", Message: content, UserToken: token,
				}, mcpCheckOutputHandler, hdr)
			}},
	}

	for _, rt := range routes {
		t.Run(rt.name, func(t *testing.T) {
			setupSeg3447Test(t)
			// The gate ON is the hostile posture: with it OFF the header is
			// dropped before it could do anything, so the test would be
			// vacuous.
			t.Setenv("AXONFLOW_TRUST_IDENTITY_HEADERS", "true")
			if rt.respful {
				withSensitiveDataBlockPosture(t)
			}
			installSeg3447Engine(t, seg3447MemberSegment, utrTestTenant)
			res := &seg3447EmailKeyedResolver{wantEmail: memberEmail}
			withFleetSegmentResolver(t, res)

			hdr := http.Header{}
			hdr.Set(identityHeaderUserEmail, colleagueEmail)

			w := rt.drive(t, seg3447MintUserToken(t, memberEmail),
				"please handle the "+rt.marker+" for Q3", hdr)

			seg3447AssertBlockedBy(t, w, rt.policy,
				"a verified member naming a NON-member colleague in X-User-Email must still be enforced")

			keys := res.keys()
			if len(keys) != 1 || keys[0] != memberEmail {
				t.Fatalf("segment resolution was keyed on %v, want exactly [%s] — the validated token claim, never the caller-supplied header",
					keys, memberEmail)
			}
		})
	}
}

// =============================================================================
// The gate's own contract, unit level — the three-way split and the "exactly
// once" property, asserted directly so a handler refactor cannot quietly move
// the discriminator.
// =============================================================================

func TestMCP3447_Gate_VerifiedHumanDiscriminator(t *testing.T) {
	authErr := &AuthError{Code: "invalid_user_token"}
	const tok = "presented.jwt.value"
	cases := []struct {
		name  string
		kind  AuthKind
		err   *AuthError
		token string
		want  bool
	}{
		{"enterprise + validated token", AuthKindEnterprise, nil, tok, true},
		{"enterprise + ResolveUser error (synthetic service identity)", AuthKindEnterprise, authErr, tok, false},
		// A token-ABSENT enterprise caller reaches the synthetic service
		// identity, not a verified one — pinned explicitly because the
		// no-error/enterprise pair alone does not exclude it.
		{"enterprise + NO token presented", AuthKindEnterprise, nil, "", false},
		{"community", AuthKindCommunity, nil, tok, false},
		{"community-saas", AuthKindCommunitySaaS, nil, tok, false},
		{"internal service", AuthKindInternalService, nil, tok, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := callerIsVerifiedHuman(&AuthResult{Kind: tc.kind}, tc.err, tc.token)
			if got != tc.want {
				t.Fatalf("callerIsVerifiedHuman = %v, want %v", got, tc.want)
			}
		})
	}

	// The deployment-mode short-circuit: validateUserToken returns a synthetic
	// identity with NO error in community / community-SaaS deployments even
	// under AuthKindEnterprise, so the enterprise+no-error pair alone would
	// misclassify those synthetics as verified humans.
	for _, mode := range []string{"community", "community-saas"} {
		t.Run("deployment mode "+mode+" is never a verified human", func(t *testing.T) {
			t.Setenv("DEPLOYMENT_MODE", mode)
			if callerIsVerifiedHuman(&AuthResult{Kind: AuthKindEnterprise}, nil, tok) {
				t.Fatalf("DEPLOYMENT_MODE=%s must never yield a verified human: validateUserToken "+
					"short-circuits there and the identity is synthetic", mode)
			}
		})
	}
}

func TestMCP3447_Gate_ResolutionOutcomes(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")

	t.Run("verified human resolves and proceeds", func(t *testing.T) {
		f := seg3447Resolver(t, seg3447MemberSegment)
		ids, ok := resolveHumanActorSegmentsForPolicy(context.Background(), seg3447OrgID, seg3447OrgID, "alice@corp.example", true)
		if !ok || len(ids) != 1 || ids[0] != seg3447MemberSegment {
			t.Fatalf("ids=%v ok=%v, want ([%s], true)", ids, ok, seg3447MemberSegment)
		}
		if c := f.callCount(); c != 1 {
			t.Fatalf("resolver call count = %d, want exactly 1", c)
		}
	})

	t.Run("resolver error fails closed", func(t *testing.T) {
		withFleetSegmentResolver(t, &fakeSegmentResolver{err: errors.New("boom")})
		ids, ok := resolveHumanActorSegmentsForPolicy(context.Background(), seg3447OrgID, seg3447OrgID, "alice@corp.example", true)
		if ok {
			t.Fatal("a resolver error for a caller WITH a principal must fail closed (ok == false)")
		}
		if ids != nil {
			t.Fatalf("a failed resolution must return no set, got %v", ids)
		}
	})

	t.Run("no verified human is org-only, never a failure", func(t *testing.T) {
		f := seg3447Resolver(t, seg3447MemberSegment)
		ids, ok := resolveHumanActorSegmentsForPolicy(context.Background(), seg3447OrgID, seg3447OrgID, "svc-client@axonflow.local", false)
		if !ok || ids != nil {
			t.Fatalf("ids=%v ok=%v, want (nil, true)", ids, ok)
		}
		if c := f.callCount(); c != 0 {
			t.Fatalf("resolver must not be consulted without a verified human, got %d calls", c)
		}
	})

	t.Run("shared synthetic subject is org-only, never a failure", func(t *testing.T) {
		f := seg3447Resolver(t, seg3447MemberSegment)
		ids, ok := resolveHumanActorSegmentsForPolicy(context.Background(), seg3447OrgID, seg3447OrgID, "svc@axonflow.local", true)
		if !ok || ids != nil {
			t.Fatalf("ids=%v ok=%v, want (nil, true) — a shared synthetic is 'member of nothing', not a deny", ids, ok)
		}
		if c := f.callCount(); c != 0 {
			t.Fatalf("resolver must not be keyed on a shared synthetic, got %d calls", c)
		}
	})

	t.Run("no resolver wired proceeds org-only", func(t *testing.T) {
		ResetFleetSegmentResolverForTest()
		ids, ok := resolveHumanActorSegmentsForPolicy(context.Background(), seg3447OrgID, seg3447OrgID, "alice@corp.example", true)
		if !ok || ids != nil {
			t.Fatalf("ids=%v ok=%v, want (nil, true) for a deployment with no identity-attribute resolver", ids, ok)
		}
	})
}

// =============================================================================
// A segment-resolution ERROR must not deny a token-less caller.
//
// Framing note, deliberate: the fail-closed deny on the verified-human path
// exists because a caller WITH a principal has an UNDETERMINED segment set —
// segment-scoped policies may target them and we cannot tell which — so
// serving them would silently skip a control aimed at them. It is NOT there to
// tolerate an unreachable or slow datastore: that is a system-wide outage to
// escalate, not a per-call-site concern, and framing it that way would argue
// for defensive handling this plane deliberately does not have.
//
// The token-less arm has no such ambiguity. Its set was never
// resolution-dependent — #3447 makes it org-only with no census and no refusal
// (the refusal for that population is #3476's, opt-in per org) — so a
// resolution error must leave it untouched.
//
// This pair does NOT, on its own, kill a mutation that removes the
// `verifiedHuman` guard: the token-less compat path synthesises
// `<client>@axonflow.local`, which the shared-synthetic census one line below
// catches anyway, so a blanket resolve still returns (nil, true) here. What
// kills that mutation is TestMCP3447_NonEnterpriseCallersNeverResolve, where
// the COMMUNITY arm is not covered by the census (in community mode the
// predicate reads local-dev as legitimate) and the guard is therefore the only
// thing keeping that caller off the resolver.
//
// What this pair does prove is its own property, which nothing else covers: a
// resolution ERROR must not turn the token-less arm into a 403. That arm is
// org-only by contract (#3447), and the refusal for that population is
// #3476's, opt-in per org.
func TestMCP3447_ResolutionError_TokenLessCallerStillOrgOnly(t *testing.T) {
	routes := []struct {
		name     string
		withConn bool
		drive    func(t *testing.T, token, content string) *httptest.ResponseRecorder
	}{
		{"resources/query", true, seg3447DoQuery},
		{"tools/execute", true, seg3447DoExecute},
		{"check-input", false, seg3447DoCheckInput},
		{"check-output", false, seg3447DoCheckOutput},
	}

	for _, rt := range routes {
		t.Run(rt.name+"/segment-scoped policy does not apply, and is not a deny", func(t *testing.T) {
			setupSeg3447Test(t)
			installSeg3447Engine(t, seg3447MemberSegment, utrTestTenant)
			if rt.withConn {
				seg3447RegisterConnector(t, &mockConnector{})
			}
			// Resolution ERRORS here. A verified human would be denied (see
			// TestMCP3447_ResolverError_...); a token-less caller must not be,
			// because their set was never resolution-dependent.
			res := &fakeSegmentResolver{err: errors.New("segment resolution failed (3447)")}
			withFleetSegmentResolver(t, res)

			w := rt.drive(t, "", "please handle the "+seg3447ReqMarker+" for Q3")

			if w.Code == http.StatusForbidden {
				t.Fatalf("a segment-resolution ERROR must not deny a token-less caller — that arm is "+
					"org-only by contract (#3447); got 403: %s", w.Body.String())
			}
			seg3447AssertAllowed(t, w, "token-less caller when segment resolution errors")
			if c := res.callCount(); c != 0 {
				t.Fatalf("the resolver must not be consulted at all for a caller with no per-user "+
					"principal; got %d call(s) — resolution is not conditional on verifiedHuman", c)
			}
		})
	}

	// The positive control: with resolution still erroring, an ORG-tier policy
	// must STILL enforce. Without this, "not denied" and "the plane stopped
	// evaluating entirely" are indistinguishable.
	t.Run("org-tier policy still enforces when resolution errors (positive control)", func(t *testing.T) {
		setupSeg3447Test(t)
		installSeg3447Engine(t, seg3447MemberSegment, utrTestTenant)
		withFleetSegmentResolver(t, &fakeSegmentResolver{err: errors.New("segment resolution failed (3447)")})

		w := seg3447DoCheckInput(t, "", "this query contains "+seg3447OrgMarker+" data")

		seg3447AssertBlockedBy(t, w, seg3447OrgPolicyID,
			"org-tier policy when segment resolution errors — org-only must not mean 'nothing enforced'")
	})
}

// =============================================================================
// Every non-enterprise caller is kept off segment resolution — and this pins
// WHICH mechanism does it for each.
//
// Two mechanisms sit one line apart in the gate: the `verifiedHuman` guard,
// and the shared-synthetic census below it. An earlier revision of this file
// claimed the census covered every non-enterprise identity, making the guard
// pure defence in depth. That is false for the community arm, and the earlier
// test only appeared to confirm it because it passed a literal
// `communityMode=false` rather than the value production computes:
// IsSharedSyntheticIdentity special-cases the local-dev identity as
// `return !communityMode`, and AuthKindCommunity is minted only inside
// `if isCommunityMode()` (authenticator.go) — so in the only deployment that
// can produce that caller, the census returns FALSE and the guard is the ONLY
// thing keeping it off the resolver.
//
// So the honest invariant is not "the census covers everything" but "between
// the two, nothing non-enterprise resolves". This asserts that per kind, with
// the deployment mode that actually produces each one, and records which
// mechanism is load-bearing where.
func TestMCP3447_NonEnterpriseCallersNeverResolve(t *testing.T) {
	for _, tc := range []struct {
		name           string
		mode           string
		kind           AuthKind
		censusCoversIt bool // false => the verifiedHuman guard is load-bearing
	}{
		// In community mode the census returns false for local-dev (it reads
		// that identity as legitimate there), so the guard carries this one.
		{"community", "community", AuthKindCommunity, false},
		{"community-saas", "community-saas", AuthKindCommunitySaaS, true},
		{"internal-service", "enterprise", AuthKindInternalService, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DEPLOYMENT_MODE", tc.mode)

			auth := &AuthResult{Kind: tc.kind, TenantID: utrTestTenant, OrgID: utrTestTenant}
			user, err := ResolveUser(auth, "")
			if err != nil {
				t.Fatalf("ResolveUser(%s) returned an error: %v", tc.name, err.Message)
			}

			// Mechanism 1: never classified as a verified human.
			if callerIsVerifiedHuman(auth, nil, "presented.jwt.value") {
				t.Fatalf("%s must never be classified as a verified human", tc.name)
			}

			// Mechanism 2: whether the census ALSO catches it, evaluated the
			// way production does.
			gotCensus := sharedidentity.IsSharedSyntheticIdentity(user.Email, isCommunityMode())
			if gotCensus != tc.censusCoversIt {
				t.Errorf("census coverage for %s changed: IsSharedSyntheticIdentity(%q, isCommunityMode()=%v) = %v, "+
					"expected %v. If the census now covers a caller it did not, the verifiedHuman guard has "+
					"become redundant for it; if it stopped covering one, that guard is now the ONLY thing "+
					"keeping it off the resolver. Either way the gate's own comments need updating — do NOT "+
					"widen IsSharedSyntheticIdentity, which would be the second copy of the census predicate "+
					"#2896/#2938 exists to prevent.",
					tc.name, user.Email, isCommunityMode(), gotCensus, tc.censusCoversIt)
			}

			// The property that actually matters, whichever mechanism carries
			// it: the resolver is never consulted for this caller.
			res := seg3447Resolver(t, seg3447MemberSegment)
			ids, ok := resolveHumanActorSegmentsForPolicy(context.Background(),
				utrTestTenant, utrTestTenant, user.Email,
				callerIsVerifiedHuman(auth, nil, "presented.jwt.value"))
			if !ok || ids != nil {
				t.Fatalf("%s: ids=%v ok=%v, want (nil, true) — org-only, never a deny", tc.name, ids, ok)
			}
			if c := res.callCount(); c != 0 {
				t.Fatalf("%s: the resolver was consulted %d time(s); a caller with no verified per-user "+
					"principal must never reach it", tc.name, c)
			}
		})
	}
}

// =============================================================================
// #3447 SECURITY: the check-input idempotency cache must be scoped to the
// principal the verdict was computed for.
//
// idempotency.Wrap replays a cache hit WITHOUT invoking the handler, so the
// segment gate does not run on a replay. Its key is (org, tenant,
// Idempotency-Key, endpoint) and carries no principal. That was harmless while
// this route passed Segments: nil unconditionally — every caller in the org got
// the same verdict, so a replay could only return a verdict the replaying
// caller would have received anyway.
//
// Segment-scoped enforcement makes the verdict a function of the principal. A
// shared cache row is then a bypass: a member of a targeted segment replaying a
// NON-member's cached allow is served an allow on a statement their segment's
// policy blocks, on a key the caller chooses. The 403 caches the same way, so
// one caller's transient resolution failure would be replayed to everyone
// sharing that key.
// =============================================================================

func TestMCP3447_IdempotencyScopeIsPerPrincipal(t *testing.T) {
	alice := mcpCheckInputIdempEndpoint("alice@corp.example")
	bob := mcpCheckInputIdempEndpoint("bob@corp.example")

	if alice == bob {
		t.Fatalf("two different principals share an idempotency scope (%q) — a member could replay "+
			"a non-member's cached allow on a statement their segment's policy blocks", alice)
	}
	// A genuine retry by the SAME caller must still dedup, or the fix has
	// simply disabled idempotency on this route.
	if alice != mcpCheckInputIdempEndpoint("alice@corp.example") {
		t.Fatal("the same principal must map to a stable scope, otherwise no retry ever dedups")
	}
	// Canonicalised, so a case/whitespace variant is the same principal rather
	// than a second cache partition (and cannot be used to force a miss).
	if alice != mcpCheckInputIdempEndpoint("  Alice@Corp.Example  ") {
		t.Fatal("scope must be computed on the canonical identity, so a case variant is not a second partition")
	}
	// Identity material must not land in idempotency_keys.endpoint.
	if strings.Contains(alice, "alice") || strings.Contains(alice, "@") {
		t.Fatalf("scope leaks identity material into the endpoint column: %q", alice)
	}
	if !strings.HasPrefix(alice, "mcp.check-input|") {
		t.Fatalf("scope must stay recognisable as this endpoint, got %q", alice)
	}
}

// The wiring half: drive the real handler with two different verified
// principals and assert the STORE was consulted with two different endpoint
// values. TestMCP3447_IdempotencyScopeIsPerPrincipal alone would pass even if
// the helper were never called.
func TestMCP3447_CheckInputIdempotencyLookupIsScopedToPrincipal(t *testing.T) {
	seen := make([]string, 0, 2)

	for _, email := range []string{"alice-idem-3447@corp.example", "bob-idem-3447@corp.example"} {
		setupSeg3447Test(t)
		installSeg3447Engine(t, seg3447MemberSegment, utrTestTenant)
		seg3447Resolver(t, seg3447MemberSegment)

		mockDB, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("sqlmock.New: %v", err)
		}
		t.Cleanup(func() { _ = mockDB.Close() })
		// rls.WithOrgAndTenantScope opens a txn and sets two GUCs before the
		// lookup. Declare that shape for the Lookup txn; the handler's own
		// later writes fall through harmlessly once the capture has happened.
		mock.MatchExpectationsInOrder(false)
		mock.ExpectBegin()
		for i := 0; i < 5; i++ {
			mock.ExpectExec("set_config").WillReturnResult(sqlmock.NewResult(0, 1))
		}
		mock.ExpectQuery("FROM idempotency_keys").
			WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), endpointCapture{&seen}).
			WillReturnError(sql.ErrNoRows)
		mock.ExpectRollback()

		origStore := mcpIdempStore
		mcpIdempStore = idempotency.NewStore(mockDB, nil)
		t.Cleanup(func() { mcpIdempStore = origStore })

		seg3447PostWithHeaders(t, "/api/v1/mcp/check-input", MCPCheckInputRequest{
			ConnectorType: "postgres",
			Statement:     seg3447Benign,
			UserToken:     seg3447MintUserToken(t, email),
		}, mcpCheckInputHandler, http.Header{"Idempotency-Key": []string{"shared-key-3447"}})
	}

	// sqlmock may consult an argument matcher more than once while resolving
	// expectations, so compare the DISTINCT endpoints rather than the raw
	// capture count.
	distinct := map[string]struct{}{}
	for _, e := range seen {
		distinct[e] = struct{}{}
	}
	if len(seen) == 0 {
		t.Fatal("the idempotency store was never consulted — the wiring assertion measured nothing")
	}
	if len(distinct) != 2 {
		t.Fatalf("two different principals must look up two different idempotency rows; got %d distinct "+
			"endpoint(s) %v — a shared row means a replay crosses principals and skips the segment gate",
			len(distinct), seen)
	}
}

// endpointCapture records the endpoint argument the store was queried with and
// always matches, so the assertion lives in the test body rather than in the
// matcher.
type endpointCapture struct{ into *[]string }

func (c endpointCapture) Match(v driver.Value) bool {
	if s, ok := v.(string); ok {
		*c.into = append(*c.into, s)
	}
	return true
}

// The subject org (the validated token's org_id claim) is not bound to the
// credential's authenticated org — the handlers bind the TENANT, not the org.
// A mismatch cannot escalate, because segment ids are org-scoped group UUIDs
// and the asserted org's groups can never match the governing org's policies.
// What it does is UNDER-enforce silently: the lookup joins to zero rows, which
// is a successful empty resolution, so a verified member of a targeted segment
// is evaluated org-only and is indistinguishable from a genuine non-member.
//
// Pinned as OBSERVABLE rather than refused: refusing would break deployments
// whose tokens default org_id to the tenant id, and the same subject key is
// used by the already-merged /api/v1/process and gateway pre-check planes, so
// refusing on one plane would diverge the three.
func TestMCP3447_SubjectOrgMismatchIsObservableAndNeverOverMatches(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")

	t.Run("mismatch resolves against the SUBJECT org, so it can only under-match", func(t *testing.T) {
		// The resolver answers only for the authenticated org. A subject org
		// that disagrees must therefore come back empty — never with the
		// governing org's segments.
		f := &orgKeyedSegmentResolver{answerFor: "governing-org", segment: seg3447MemberSegment}
		withFleetSegmentResolver(t, f)

		ids, ok := resolveHumanActorSegmentsForPolicy(context.Background(),
			"asserted-other-org", "governing-org", "alice@corp.example", true)

		if !ok {
			t.Fatal("a subject/authenticated org disagreement must not deny — it is not a resolution failure")
		}
		if len(ids) != 0 {
			t.Fatalf("resolved %v for a mismatched subject org — a mismatch must never yield the "+
				"governing org's segments", ids)
		}
		if f.askedFor != "asserted-other-org" {
			t.Fatalf("resolved against %q; the subject org is the key every merged human-actor plane "+
				"uses, and silently switching to the authenticated org here would diverge them",
				f.askedFor)
		}
	})

	t.Run("agreement resolves normally", func(t *testing.T) {
		f := &orgKeyedSegmentResolver{answerFor: "governing-org", segment: seg3447MemberSegment}
		withFleetSegmentResolver(t, f)

		ids, ok := resolveHumanActorSegmentsForPolicy(context.Background(),
			"governing-org", "governing-org", "alice@corp.example", true)

		if !ok || len(ids) != 1 || ids[0] != seg3447MemberSegment {
			t.Fatalf("ids=%v ok=%v, want ([%s], true) — the mismatch guard must not disturb the "+
				"agreeing case", ids, ok, seg3447MemberSegment)
		}
	})
}

// orgKeyedSegmentResolver answers only for one org, so a resolution keyed on
// the wrong org comes back empty rather than silently succeeding.
type orgKeyedSegmentResolver struct {
	answerFor string
	segment   string
	askedFor  string
}

func (r *orgKeyedSegmentResolver) Resolve(_ context.Context, orgID, _ string) (sharedidentity.ResolvedIdentity, error) {
	r.askedFor = orgID
	if orgID != r.answerFor {
		return sharedidentity.ResolvedIdentity{}, nil
	}
	return sharedidentity.ResolvedIdentity{
		Segments: []sharedidentity.Segment{{ID: sharedidentity.SegmentID(r.segment)}},
	}, nil
}

func (r *orgKeyedSegmentResolver) ResolveRole(_ context.Context, _, _ string) (string, error) {
	return "", nil
}
