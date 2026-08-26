// Copyright 2025 AxonFlow
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

import (
	"context"
	"testing"

	"axonflow/platform/agent/telemetry"
)

// TestDecisionStageForPreCheck covers the stage classification helper —
// pre-check stages map to "tool" when a data_sources list is present
// (signaling an MCP call is next), otherwise "llm" (the default
// caller-is-about-to-hit-an-LLM case).
func TestDecisionStageForPreCheck(t *testing.T) {
	cases := []struct {
		name string
		req  PreCheckRequest
		want string
	}{
		{"empty request defaults to llm", PreCheckRequest{ClientID: "c1", Query: "q"}, "llm"},
		{"data_sources signals tool", PreCheckRequest{ClientID: "c1", Query: "q", DataSources: []string{"postgres"}}, "tool"},
		{"multiple data sources still tool", PreCheckRequest{ClientID: "c1", Query: "q", DataSources: []string{"postgres", "snowflake"}}, "tool"},
		{"empty data_sources slice is llm", PreCheckRequest{ClientID: "c1", Query: "q", DataSources: []string{}}, "llm"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := decisionStageForPreCheck(tc.req); got != tc.want {
				t.Errorf("decisionStageForPreCheck() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestVerdictFromPreCheck covers the three-valued verdict mapping. HITL
// takes precedence over Approved (a HITL request is also unapproved
// pending review) so the verdict enum reflects the *reason* the
// request was held, not just the outcome boolean.
func TestVerdictFromPreCheck(t *testing.T) {
	cases := []struct {
		name         string
		resp         PreCheckResponse
		requiresHITL bool
		want         string
	}{
		{"approved no-HITL → allow", PreCheckResponse{Approved: true}, false, "allow"},
		{"denied no-HITL → deny", PreCheckResponse{Approved: false}, false, "deny"},
		{"HITL beats Approved=true → needs_approval", PreCheckResponse{Approved: true}, true, "needs_approval"},
		{"HITL beats Approved=false → needs_approval (HITL is the cause)", PreCheckResponse{Approved: false}, true, "needs_approval"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := verdictFromPreCheck(tc.resp, tc.requiresHITL); got != tc.want {
				t.Errorf("verdictFromPreCheck() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestReasonsFromPreCheck covers reason aggregation: BlockReason is
// authoritative, policyResult.Reason supplements only when distinct
// (no duplicate strings on the span attribute).
func TestReasonsFromPreCheck(t *testing.T) {
	cases := []struct {
		name         string
		resp         PreCheckResponse
		policyResult *StaticPolicyResult
		want         []string
	}{
		{"nothing populated → nil", PreCheckResponse{}, nil, nil},
		{"only BlockReason → one entry", PreCheckResponse{BlockReason: "PII detected"}, &StaticPolicyResult{}, []string{"PII detected"}},
		{"distinct policy reason appended", PreCheckResponse{BlockReason: "PII detected"}, &StaticPolicyResult{Reason: "regulated category"}, []string{"PII detected", "regulated category"}},
		{"identical policy reason deduped", PreCheckResponse{BlockReason: "PII detected"}, &StaticPolicyResult{Reason: "PII detected"}, []string{"PII detected"}},
		{"only policyResult.Reason populated", PreCheckResponse{}, &StaticPolicyResult{Reason: "circuit open"}, []string{"circuit open"}},
		{"nil policyResult tolerated", PreCheckResponse{BlockReason: "kill switch"}, nil, []string{"kill switch"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := reasonsFromPreCheck(tc.resp, tc.policyResult, policyStepUpResult{})
			if len(got) != len(tc.want) {
				t.Fatalf("reasonsFromPreCheck() len=%d, want len=%d (got=%v want=%v)", len(got), len(tc.want), got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("reasons[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestRecordPreCheckDecision_NoopTracerReturnsEmpty exercises the deny-
// path early-exit telemetry helper with the noop tracer wired in. The
// helper must return "" (the noop tracer's contract) without panicking
// when the package-global Provider holds a noop tracer.
func TestRecordPreCheckDecision_NoopTracerReturnsEmpty(t *testing.T) {
	saved := decisionTracerProvider
	decisionTracerProvider = &telemetry.Provider{Tracer: telemetry.NewNoopTracer()}
	defer func() { decisionTracerProvider = saved }()

	got := recordPreCheckDecision(context.Background(), "ctx-1", "org-1", "tenant-1", "llm", "kill switch", []string{"rbi_kill_switch"}, 3)
	if got != "" {
		t.Fatalf("noop tracer must produce empty trace_id; got %q", got)
	}
}

// TestRecordPreCheckDecision_NilProviderTolerated guarantees the helper
// is safe even before run.go has wired the global Provider. If a test
// calls the handler without initializing the tracer, the trace_id is
// just empty — never a nil-pointer panic.
func TestRecordPreCheckDecision_NilProviderTolerated(t *testing.T) {
	saved := decisionTracerProvider
	decisionTracerProvider = nil
	defer func() { decisionTracerProvider = saved }()

	got := recordPreCheckDecision(context.Background(), "ctx-2", "org-2", "tenant-2", "tool", "budget exceeded", []string{"budget_exceeded"}, 5)
	if got != "" {
		t.Fatalf("nil provider must produce empty trace_id; got %q", got)
	}
}
