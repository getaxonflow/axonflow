//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Tests for the Enterprise per-client version-distribution telemetry (#2860):
// the recorder's validation/cardinality contract, and the two capture planes
// (decide + MCP check-output) end-to-end through the real handlers — including
// the fail-open guarantee that a garbage header never affects a verdict.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/prometheus/client_golang/prometheus/testutil"

	sharedpolicy "axonflow/platform/shared/policy"
)

// resetClientVersionSeen swaps in a fresh series-cap map for one test and
// restores the previous map afterwards, so cap tests can't starve later tests
// (the map is package-global process state).
func resetClientVersionSeen(t *testing.T) {
	t.Helper()
	clientVersionSeenMu.Lock()
	prev := clientVersionSeen
	clientVersionSeen = make(map[string]struct{}, 64)
	clientVersionSeenMu.Unlock()
	t.Cleanup(func() {
		clientVersionSeenMu.Lock()
		clientVersionSeen = prev
		clientVersionSeenMu.Unlock()
	})
}

// TestRecordClientVersionTelemetry_DesktopProxyShape pins the exact wire shape
// the Claude Desktop proxy sends (mcp-proxy/<semver>) landing as a
// {plane, client, client_version} sample — the headline behavior of #2860.
func TestRecordClientVersionTelemetry_DesktopProxyShape(t *testing.T) {
	resetClientVersionSeen(t)
	before := testutil.ToFloat64(clientVersionRequests.WithLabelValues(PlaneDecision, "mcp-proxy", "0.3.0"))
	recordClientVersionTelemetry(PlaneDecision, "mcp-proxy/0.3.0")
	if got := testutil.ToFloat64(clientVersionRequests.WithLabelValues(PlaneDecision, "mcp-proxy", "0.3.0")); got != before+1 {
		t.Errorf("clientVersionRequests{decision,mcp-proxy,0.3.0} = %v, want %v", got, before+1)
	}
}

// TestRecordClientVersionTelemetry_ParseAndValidate pins the split/validation
// contract: the LAST "/" separates client from version (same contract as the
// ingest side's ParseClient), clients are lowercased, unversioned ids get the
// explicit "unversioned" bucket, and anything outside the admitted shapes is
// dropped — never emitted as a label value.
func TestRecordClientVersionTelemetry_ParseAndValidate(t *testing.T) {
	resetClientVersionSeen(t)
	cases := []struct {
		name   string
		header string
		// wantClient/wantVersion empty → expect a drop with wantDrop reason.
		wantClient, wantVersion string
		wantDrop                string
	}{
		{"desktop proxy", "mcp-proxy/0.3.0", "mcp-proxy", "0.3.0", ""},
		{"claude-code plugin", "claude-code-plugin/1.9.1", "claude-code-plugin", "1.9.1", ""},
		{"sdk mixed case lowered", "SDK-Go/8.5.0", "sdk-go", "8.5.0", ""},
		{"prerelease version", "openclaw/2.4.0-rc1", "openclaw", "2.4.0-rc1", ""},
		{"unversioned client id", "claude-code-plugin", "claude-code-plugin", "unversioned", ""},
		{"whitespace padded", "  mcp-proxy/0.3.0  ", "mcp-proxy", "0.3.0", ""},

		{"absent", "", "", "", "absent"},
		{"whitespace only", "   ", "", "", "absent"},
		{"html junk", "<script>alert(1)</script>/1.0", "", "", "invalid"},
		{"spaces in client", "not a client/1.0", "", "", "invalid"},
		{"control bytes", "mcp-proxy\x00/0.3.0", "", "", "invalid"},
		{"leading slash", "/0.3.0", "", "", "invalid"},
		{"trailing slash keeps whole as client, invalid slash char", "mcp-proxy/0.3.0/", "", "", "invalid"},
		{"overlong client", strings.Repeat("a", 80) + "/1.0", "", "", "invalid"},
		{"overlong version", "mcp-proxy/" + strings.Repeat("9", 40), "", "", "invalid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.wantDrop != "" {
				dropBefore := testutil.ToFloat64(clientVersionDropped.WithLabelValues(tc.wantDrop))
				seriesBefore := testutil.CollectAndCount(clientVersionRequests)
				recordClientVersionTelemetry(PlaneDecision, tc.header)
				if got := testutil.ToFloat64(clientVersionDropped.WithLabelValues(tc.wantDrop)); got != dropBefore+1 {
					t.Errorf("dropped{%s} = %v, want %v", tc.wantDrop, got, dropBefore+1)
				}
				if got := testutil.CollectAndCount(clientVersionRequests); got != seriesBefore {
					t.Errorf("a dropped header minted a series (%d -> %d): cardinality/PII leak", seriesBefore, got)
				}
				return
			}
			before := testutil.ToFloat64(clientVersionRequests.WithLabelValues(PlaneDecision, tc.wantClient, tc.wantVersion))
			recordClientVersionTelemetry(PlaneDecision, tc.header)
			if got := testutil.ToFloat64(clientVersionRequests.WithLabelValues(PlaneDecision, tc.wantClient, tc.wantVersion)); got != before+1 {
				t.Errorf("clientVersionRequests{%s,%s} = %v, want %v", tc.wantClient, tc.wantVersion, got, before+1)
			}
		})
	}
}

// TestRecordClientVersionTelemetry_SeriesCap pins the hard cardinality bound:
// past clientVersionMaxSeries distinct label sets, new pairs are dropped into
// the overflow bucket instead of minting series — while ALREADY-SEEN pairs
// keep counting (an established fleet's telemetry never stops).
func TestRecordClientVersionTelemetry_SeriesCap(t *testing.T) {
	resetClientVersionSeen(t)

	// Admit one real pair, then saturate the map artificially (not via the
	// public API — filling 512 real series would pollute the registry).
	recordClientVersionTelemetry(PlaneDecision, "mcp-proxy/0.3.0")
	clientVersionSeenMu.Lock()
	for i := 0; len(clientVersionSeen) < clientVersionMaxSeries; i++ {
		clientVersionSeen[fmt.Sprintf("synthetic\x00client\x00%d", i)] = struct{}{}
	}
	clientVersionSeenMu.Unlock()

	overflowBefore := testutil.ToFloat64(clientVersionDropped.WithLabelValues("overflow"))
	seriesBefore := testutil.CollectAndCount(clientVersionRequests)
	recordClientVersionTelemetry(PlaneDecision, "brand-new-client/9.9.9")
	if got := testutil.ToFloat64(clientVersionDropped.WithLabelValues("overflow")); got != overflowBefore+1 {
		t.Errorf("dropped{overflow} = %v, want %v", got, overflowBefore+1)
	}
	if got := testutil.CollectAndCount(clientVersionRequests); got != seriesBefore {
		t.Errorf("over-cap header minted a series (%d -> %d)", seriesBefore, got)
	}

	// Already-seen pair still counts past the cap.
	before := testutil.ToFloat64(clientVersionRequests.WithLabelValues(PlaneDecision, "mcp-proxy", "0.3.0"))
	recordClientVersionTelemetry(PlaneDecision, "mcp-proxy/0.3.0")
	if got := testutil.ToFloat64(clientVersionRequests.WithLabelValues(PlaneDecision, "mcp-proxy", "0.3.0")); got != before+1 {
		t.Errorf("already-seen pair stopped counting at the cap: %v, want %v", got, before+1)
	}
}

// TestHandleDecide_ClientVersionCapture drives a full /decide request with the
// Desktop proxy's header and asserts (a) the version lands on the decide-plane
// distribution counter and (b) the request itself is governed normally.
func TestHandleDecide_ClientVersionCapture(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	t.Setenv("ENVIRONMENT", "development")
	resetClientVersionSeen(t)
	installSharedEngineWithMockDB(t)
	installCircuitBreaker(t)

	before := testutil.ToFloat64(clientVersionRequests.WithLabelValues(PlaneDecision, "mcp-proxy", "0.3.0"))

	body, _ := json.Marshal(DecideRequest{
		Stage:          DecisionStageTool,
		CallerIdentity: DecisionCallerIdentity{GatewayID: "claude_desktop.fleet-mac", TenantID: "test-tenant"},
		Target:         DecisionTarget{Type: "tool", Tool: "lookup"},
		Query:          "tool_call: lookup",
	})
	req := httptest.NewRequest("POST", decisionHandlerPath, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Axonflow-Client", "mcp-proxy/0.3.0")
	rr := httptest.NewRecorder()
	handleDecide(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200; body=%s", rr.Code, rr.Body.String())
	}
	if got := testutil.ToFloat64(clientVersionRequests.WithLabelValues(PlaneDecision, "mcp-proxy", "0.3.0")); got != before+1 {
		t.Errorf("clientVersionRequests{decision,mcp-proxy,0.3.0} = %v, want %v", got, before+1)
	}
}

// TestHandleDecide_GarbageClientHeader_FailOpen pins the fail-open DoD (#2860):
// a garbage X-Axonflow-Client on a real /decide request (a) never changes the
// HTTP status or verdict, (b) never mints a label series, and (c) lands in the
// bounded invalid-drop counter. Telemetry can never fail a decision.
func TestHandleDecide_GarbageClientHeader_FailOpen(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	t.Setenv("ENVIRONMENT", "development")
	resetClientVersionSeen(t)
	installSharedEngineWithMockDB(t)
	installCircuitBreaker(t)

	invalidBefore := testutil.ToFloat64(clientVersionDropped.WithLabelValues("invalid"))
	seriesBefore := testutil.CollectAndCount(clientVersionRequests)

	body, _ := json.Marshal(DecideRequest{
		Stage:          DecisionStageTool,
		CallerIdentity: DecisionCallerIdentity{GatewayID: "claude_desktop.fleet-mac", TenantID: "test-tenant"},
		Target:         DecisionTarget{Type: "tool", Tool: "lookup"},
		Query:          "tool_call: lookup",
	})
	req := httptest.NewRequest("POST", decisionHandlerPath, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Axonflow-Client", "x!!/////not a client@@@ <script>alert(1)</script> "+strings.Repeat("a", 100))
	rr := httptest.NewRecorder()
	handleDecide(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("garbage telemetry header affected the decision: got %d want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp DecideResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Verdict == "" {
		t.Fatalf("garbage telemetry header produced an empty verdict; body=%s", rr.Body.String())
	}
	if got := testutil.ToFloat64(clientVersionDropped.WithLabelValues("invalid")); got != invalidBefore+1 {
		t.Errorf("dropped{invalid} = %v, want %v", got, invalidBefore+1)
	}
	if got := testutil.CollectAndCount(clientVersionRequests); got != seriesBefore {
		t.Errorf("garbage header minted a series (%d -> %d)", seriesBefore, got)
	}
}

// TestHandleDecide_OptionsPreflight_NoSeriesMint pins the fix for the
// anonymous-OPTIONS series-minting hole (R3 HIGH-1): the decide route is
// registered .Methods("POST","OPTIONS") and apiAuthMiddleware forwards a CORS
// preflight to this handler UNAUTHENTICATED. A bare OPTIONS carrying a
// valid-shaped X-Axonflow-Client must NOT mint a label series (else an
// anonymous caller could exhaust the cap and blind the distribution).
func TestHandleDecide_OptionsPreflight_NoSeriesMint(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	t.Setenv("ENVIRONMENT", "development")
	resetClientVersionSeen(t)
	installSharedEngineWithMockDB(t)
	installCircuitBreaker(t)

	// Touch the target child FIRST (WithLabelValues is get-or-create) so
	// seriesBefore already accounts for it — then the only way the count can
	// grow is handleDecide minting a DIFFERENT series.
	before := testutil.ToFloat64(clientVersionRequests.WithLabelValues(PlaneDecision, "optprobe", "9.9.9"))
	seriesBefore := testutil.CollectAndCount(clientVersionRequests)

	req := httptest.NewRequest("OPTIONS", decisionHandlerPath, nil)
	req.Header.Set("X-Axonflow-Client", "optprobe/9.9.9") // valid shape → would mint if unguarded
	rr := httptest.NewRecorder()
	handleDecide(rr, req)

	if got := testutil.ToFloat64(clientVersionRequests.WithLabelValues(PlaneDecision, "optprobe", "9.9.9")); got != before {
		t.Errorf("OPTIONS incremented the version series: %v (want unchanged %v)", got, before)
	}
	if got := testutil.CollectAndCount(clientVersionRequests); got != seriesBefore {
		t.Errorf("OPTIONS changed the series count (%d -> %d): anonymous cap-exhaustion vector", seriesBefore, got)
	}
}

// TestMCPCheckOutput_ClientVersionCapture drives the REAL check-output handler
// (the second plane the Desktop proxy calls on every governed tools/call) with
// the proxy's header and asserts the response-plane capture — and that the
// allow verdict is untouched. Mirrors the allow-path setup of
// TestMCPCheckOutputHandler_AllowEmitsAuditLogsDecisionRow.
func TestMCPCheckOutput_ClientVersionCapture(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	resetClientVersionSeen(t)

	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer mockDB.Close()
	origDB := usageDB
	usageDB = mockDB
	defer func() { usageDB = origDB }()

	originalEngine := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(nil)
	defer sharedpolicy.SetGlobalEngine(originalEngine)
	originalChecker := sharedpolicy.GetGlobalExfiltrationChecker()
	sharedpolicy.SetGlobalExfiltrationChecker(nil)
	defer sharedpolicy.SetGlobalExfiltrationChecker(originalChecker)

	mock.ExpectExec("INSERT INTO audit_logs").WillReturnResult(sqlmock.NewResult(0, 1))

	before := testutil.ToFloat64(clientVersionRequests.WithLabelValues(PlaneMCP, "mcp-proxy", "0.3.0"))

	body, _ := json.Marshal(MCPCheckOutputRequest{
		ConnectorType: "claude-desktop-proxy",
		Message:       "3 rows: aggregate sales figures",
		TenantID:      "default",
	})
	req := httptest.NewRequest("POST", "/api/v1/mcp/check-output", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Axonflow-Client", "mcp-proxy/0.3.0")
	w := httptest.NewRecorder()
	mcpCheckOutputHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (allow), got %d: %s", w.Code, w.Body.String())
	}
	if got := testutil.ToFloat64(clientVersionRequests.WithLabelValues(PlaneMCP, "mcp-proxy", "0.3.0")); got != before+1 {
		t.Errorf("clientVersionRequests{mcp,mcp-proxy,0.3.0} = %v, want %v", got, before+1)
	}
}
