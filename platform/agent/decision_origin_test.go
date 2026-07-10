// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package agent

// Unit tests for the WS-5 (#2761) caller-origin bucket on the Decision Mode
// metrics: classifyDecisionOrigin (the bucketing), recordDecideOutcomeMetrics
// (the obligations + blocks supplementary series), and the origin label on the
// axonflow_decision_requests_total / _duration_milliseconds metrics end-to-end
// through handleDecide.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
)

// histSampleCount reads the sample count from a histogram child (Observer). Used
// to assert the duration histogram observed under a specific origin label.
func histSampleCount(t *testing.T, o prometheus.Observer) uint64 {
	t.Helper()
	h, ok := o.(prometheus.Histogram)
	if !ok {
		t.Fatalf("observer is not a prometheus.Histogram: %T", o)
	}
	var m dto.Metric
	if err := h.Write(&m); err != nil {
		t.Fatalf("histogram Write: %v", err)
	}
	return m.GetHistogram().GetSampleCount()
}

// TestClassifyDecisionOrigin pins the bucketing contract: every input maps to
// exactly one closed-enum bucket, raw hostnames/emails/versions NEVER surface as
// a value, and the gateway_id claude_desktop marker is authoritative for Desktop.
func TestClassifyDecisionOrigin(t *testing.T) {
	cases := []struct {
		name         string
		clientHeader string
		gatewayID    string
		want         string
	}{
		// Claude Code — both the current header and the legacy versioned form.
		{"claude-code-plugin header", "claude-code-plugin", "", OriginClaudeCode},
		{"claude-code versioned header", "claude-code/1.6.0", "", OriginClaudeCode},
		{"claude-code mixed case", "Claude-Code-Plugin", "", OriginClaudeCode},

		// Claude Desktop — gateway_id is authoritative (proxy may omit header).
		{"claude_desktop gateway wins", "", "claude_desktop.fleet-mac", OriginClaudeDesktop},
		{"claude_desktop gateway hostname not leaked", "", "claude_desktop.some-very-long-hostname.internal", OriginClaudeDesktop},
		{"claude-desktop hyphen gateway", "", "claude-desktop.host", OriginClaudeDesktop},
		{"desktop header form", "claude-desktop-proxy", "", OriginClaudeDesktop},
		{"gateway desktop beats client header", "sdk-go/1.2.3", "claude_desktop.host", OriginClaudeDesktop},
		// #2860: the Desktop proxy's on-wire client id — bucketed to Desktop
		// even without the (normally authoritative) claude_desktop gateway_id.
		{"mcp-proxy versioned header", "mcp-proxy/0.3.0", "", OriginClaudeDesktop},
		{"mcp-proxy header with desktop gateway", "mcp-proxy/0.3.0", "claude_desktop.fleet-mac", OriginClaudeDesktop},

		// SDKs.
		{"sdk-go", "sdk-go/1.2.3", "", OriginSDK},
		{"sdk-python", "sdk-python/8.5.0", "", OriginSDK},

		// Other plugins.
		{"openclaw", "openclaw/2.6.7", "", OriginPlugin},
		{"cursor-plugin", "cursor-plugin/1.3.0", "", OriginPlugin},
		{"codex-plugin", "codex-plugin/1.5.2", "", OriginPlugin},

		// Generic infra PEP that asserts a gateway_id but no known client header.
		{"generic gateway", "", "acme-egress-proxy-01", OriginGateway},
		{"unknown client header falls to gateway when gateway present", "some-future-thing/9", "acme-proxy", OriginGateway},

		// Nothing identifiable.
		{"no signal at all", "", "", OriginUnknown},
		{"unknown header, no gateway", "curl/8.4.0", "", OriginUnknown},
		{"whitespace only", "   ", "  ", OriginUnknown},
	}

	closed := map[string]bool{
		OriginClaudeCode: true, OriginClaudeDesktop: true, OriginSDK: true,
		OriginPlugin: true, OriginGateway: true, OriginUnknown: true,
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyDecisionOrigin(tc.clientHeader, tc.gatewayID)
			if got != tc.want {
				t.Errorf("classifyDecisionOrigin(%q, %q) = %q, want %q", tc.clientHeader, tc.gatewayID, got, tc.want)
			}
			if !closed[got] {
				t.Errorf("classifyDecisionOrigin returned %q which is NOT a closed-enum bucket (cardinality leak)", got)
			}
		})
	}
}

// TestRecordDecideOutcomeMetrics verifies the two supplementary series:
//   - allow + redact obligation → decideObligations{redact_pii} increments
//   - deny → decideBlocks{blocking policy} increments (with the documented
//     fallbacks), and NOT on allow/needs_approval.
func TestRecordDecideOutcomeMetrics(t *testing.T) {
	const origin = "claude-code"

	t.Run("allow with redact obligation increments obligations, not blocks", func(t *testing.T) {
		obBefore := testutil.ToFloat64(decideObligations.WithLabelValues(ObligationRedactPII, "llm", origin))
		blBefore := testutil.CollectAndCount(decideBlocks)
		recordDecideOutcomeMetrics(VerdictAllow, "llm", origin,
			[]DecisionObligation{newRedactPIIObligation("PII detected")}, "", "", nil)
		if got := testutil.ToFloat64(decideObligations.WithLabelValues(ObligationRedactPII, "llm", origin)); got != obBefore+1 {
			t.Errorf("decideObligations{redact_pii} = %v, want %v", got, obBefore+1)
		}
		if got := testutil.CollectAndCount(decideBlocks); got != blBefore {
			t.Errorf("decideBlocks series count changed on an allow (%d -> %d)", blBefore, got)
		}
	})

	t.Run("allow with no obligation records nothing", func(t *testing.T) {
		obBefore := testutil.CollectAndCount(decideObligations)
		recordDecideOutcomeMetrics(VerdictAllow, "tool", origin, nil, "", "", nil)
		if got := testutil.CollectAndCount(decideObligations); got != obBefore {
			t.Errorf("decideObligations series count changed on an obligation-free allow (%d -> %d)", obBefore, got)
		}
	})

	t.Run("deny increments blocks keyed by blocking policy", func(t *testing.T) {
		before := testutil.ToFloat64(decideBlocks.WithLabelValues("sys_pii_ssn", origin))
		recordDecideOutcomeMetrics(VerdictDeny, "llm", origin, nil, "sys_pii_ssn", "system", []string{"sys_pii_ssn", "other"})
		if got := testutil.ToFloat64(decideBlocks.WithLabelValues("sys_pii_ssn", origin)); got != before+1 {
			t.Errorf("decideBlocks{sys_pii_ssn} = %v, want %v", got, before+1)
		}
	})

	t.Run("deny falls back to evaluated_policies[0] when blockingPolicyID empty", func(t *testing.T) {
		before := testutil.ToFloat64(decideBlocks.WithLabelValues("rbi_pii_protection", origin))
		recordDecideOutcomeMetrics(VerdictDeny, "tool", origin, nil, "", "", []string{"rbi_pii_protection"})
		if got := testutil.ToFloat64(decideBlocks.WithLabelValues("rbi_pii_protection", origin)); got != before+1 {
			t.Errorf("decideBlocks fallback = %v, want %v", got, before+1)
		}
	})

	t.Run("deny by per-tenant custom policy collapses to tenant_custom (no cardinality bomb)", func(t *testing.T) {
		before := testutil.ToFloat64(decideBlocks.WithLabelValues("tenant_custom", origin))
		// A tenant custom policy: unbounded "custom_<hex>" id, tier=tenant.
		recordDecideOutcomeMetrics(VerdictDeny, "llm", origin, nil, "custom_9f3a2b1c4d5e", "tenant", nil)
		recordDecideOutcomeMetrics(VerdictDeny, "llm", origin, nil, "custom_00112233aabb", "organization", nil)
		if got := testutil.ToFloat64(decideBlocks.WithLabelValues("tenant_custom", origin)); got != before+2 {
			t.Errorf("decideBlocks{tenant_custom} = %v, want %v", got, before+2)
		}
		// The raw custom ids must NEVER appear as label values.
		if got := testutil.ToFloat64(decideBlocks.WithLabelValues("custom_9f3a2b1c4d5e", origin)); got != 0 {
			t.Errorf("raw custom policy id leaked as a label value (cardinality bomb): %v", got)
		}
	})

	t.Run("deny with no policy info records unknown (never silently uncounted)", func(t *testing.T) {
		before := testutil.ToFloat64(decideBlocks.WithLabelValues("unknown", origin))
		recordDecideOutcomeMetrics(VerdictDeny, "agent", origin, nil, "", "", nil)
		if got := testutil.ToFloat64(decideBlocks.WithLabelValues("unknown", origin)); got != before+1 {
			t.Errorf("decideBlocks{unknown} = %v, want %v", got, before+1)
		}
	})

	t.Run("needs_approval records neither obligations nor blocks", func(t *testing.T) {
		obBefore := testutil.CollectAndCount(decideObligations)
		blBefore := testutil.CollectAndCount(decideBlocks)
		recordDecideOutcomeMetrics(VerdictNeedsApproval, "llm", origin, nil, "", "", nil)
		if got := testutil.CollectAndCount(decideObligations); got != obBefore {
			t.Errorf("decideObligations changed on needs_approval (%d -> %d)", obBefore, got)
		}
		if got := testutil.CollectAndCount(decideBlocks); got != blBefore {
			t.Errorf("decideBlocks changed on needs_approval (%d -> %d)", blBefore, got)
		}
	})
}

// TestBoundedBlockPolicy pins the cardinality guard on the decideBlocks `policy`
// label: system/enterprise ids pass through (the useful ranking), per-tenant/org
// custom ids collapse to one bucket, empty is "unknown".
func TestBoundedBlockPolicy(t *testing.T) {
	cases := []struct {
		policyID, tier, want string
	}{
		{"sys_sqli_union_select", "system", "sys_sqli_union_select"},
		{"rbi_pii_protection", "enterprise", "rbi_pii_protection"},
		{"sys_dangerous_injection", "", "sys_dangerous_injection"}, // engine-bypass fallback: system-safe
		{"custom_9f3a2b1c4d5e", "tenant", "tenant_custom"},
		{"custom_00112233aabb", "organization", "tenant_custom"},
		{"whatever", "invalid", "tenant_custom"},
		{"", "system", "unknown"},
		{"", "tenant", "unknown"},
	}
	for _, tc := range cases {
		got := boundedBlockPolicy(tc.policyID, tc.tier)
		if got != tc.want {
			t.Errorf("boundedBlockPolicy(%q,%q) = %q, want %q", tc.policyID, tc.tier, got, tc.want)
		}
		// a non-system/enterprise tier must NEVER echo the raw id
		if tc.tier != "system" && tc.tier != "enterprise" && tc.tier != "" && got == tc.policyID && tc.policyID != "" {
			t.Errorf("boundedBlockPolicy leaked raw id %q for tier %q", tc.policyID, tc.tier)
		}
	}
}

// TestHandleDecide_OriginLabel_ClaudeCode drives a full /decide request carrying
// the Claude Code client header and asserts the origin label lands on BOTH the
// request counter and the duration histogram — i.e. per-integration filtering
// works end-to-end, not just at the classify boundary.
func TestHandleDecide_OriginLabel_ClaudeCode(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	t.Setenv("ENVIRONMENT", "development")
	installSharedEngineWithMockDB(t)
	installCircuitBreaker(t)

	reqBefore := testutil.ToFloat64(decideRequests.WithLabelValues(VerdictAllow, DecisionStageLLM, OriginClaudeCode))
	durBefore := histSampleCount(t, decideDuration.WithLabelValues(OriginClaudeCode))

	body, _ := json.Marshal(DecideRequest{
		Stage:          DecisionStageLLM,
		CallerIdentity: DecisionCallerIdentity{GatewayID: "test-llm-gateway", TenantID: "test-tenant"},
		Target:         DecisionTarget{Type: "llm", Model: "gpt-4o", Provider: "openai"},
		Query:          "What is the weather today?",
	})
	req := httptest.NewRequest("POST", decisionHandlerPath, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Axonflow-Client", "claude-code-plugin")
	rr := httptest.NewRecorder()
	handleDecide(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200; body=%s", rr.Code, rr.Body.String())
	}

	reqAfter := testutil.ToFloat64(decideRequests.WithLabelValues(VerdictAllow, DecisionStageLLM, OriginClaudeCode))
	if reqAfter != reqBefore+1 {
		t.Errorf("axonflow_decision_requests_total{verdict=allow,stage=llm,origin=claude-code} = %v, want %v", reqAfter, reqBefore+1)
	}
	// The duration histogram must have observed exactly one more sample under
	// origin=claude-code — i.e. the label flows onto the histogram too, not just
	// the counter.
	if got := histSampleCount(t, decideDuration.WithLabelValues(OriginClaudeCode)); got != durBefore+1 {
		t.Errorf("decideDuration{origin=claude-code} sample count = %d, want %d", got, durBefore+1)
	}
}

// TestHandleDecide_OriginLabel_IndonesiaBlock proves the EARLY-RETURN policy
// deny path (Indonesia PII block under PII_ACTION=block) records BOTH the
// origin-labelled deny count AND the top-blocked-policies series — i.e. block
// attribution is complete across the early-return paths, not only the terminal
// shared-engine deny.
func TestHandleDecide_OriginLabel_IndonesiaBlock(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	t.Setenv("ENVIRONMENT", "development")
	t.Setenv("PII_ACTION", "block")
	ResetDetectionConfigCache()
	installSharedEngineWithMockDB(t)
	installCircuitBreaker(t)

	denyBefore := testutil.ToFloat64(decideRequests.WithLabelValues(VerdictDeny, DecisionStageTool, OriginClaudeCode))
	blockBefore := testutil.ToFloat64(decideBlocks.WithLabelValues("indonesia_pii_protection", OriginClaudeCode))

	body, _ := json.Marshal(DecideRequest{
		Stage:          DecisionStageTool,
		CallerIdentity: DecisionCallerIdentity{GatewayID: "test-tool-gateway", TenantID: "test-tenant"},
		Target:         DecisionTarget{Type: "tool", Tool: "db.query"},
		Query:          "Customer NIK is 3174042506780001",
	})
	req := httptest.NewRequest("POST", decisionHandlerPath, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Axonflow-Client", "claude-code-plugin")
	rr := httptest.NewRecorder()
	handleDecide(rr, req)

	var resp DecideResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v -- body=%s", err, rr.Body.String())
	}
	if resp.Verdict != VerdictDeny {
		t.Fatalf("verdict: got %q want deny (block); reasons=%v", resp.Verdict, resp.Reasons)
	}
	if got := testutil.ToFloat64(decideRequests.WithLabelValues(VerdictDeny, DecisionStageTool, OriginClaudeCode)); got != denyBefore+1 {
		t.Errorf("decideRequests{deny,tool,claude-code} = %v, want %v", got, denyBefore+1)
	}
	if got := testutil.ToFloat64(decideBlocks.WithLabelValues("indonesia_pii_protection", OriginClaudeCode)); got != blockBefore+1 {
		t.Errorf("decideBlocks{indonesia_pii_protection,claude-code} = %v, want %v", got, blockBefore+1)
	}
}
