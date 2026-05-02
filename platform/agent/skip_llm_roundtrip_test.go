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
	"encoding/json"
	"strings"
	"testing"
)

// TestClientRequest_SkipLLMRoundTrip verifies that skip_llm:true sent in the
// JSON body decodes to ClientRequest.SkipLLM=true. This is a regression
// test for an observed symptom where the perf-testing harness sent
// skip_llm:true and the orchestrator log showed skip_llm=false. The
// field has the JSON tag `skip_llm,omitempty` — `omitempty` only affects
// MARSHAL (output), not unmarshal. The bug is not in the round-trip but
// the test pins that contract so future struct-tag refactors can't silently
// regress it.
func TestClientRequest_SkipLLMRoundTrip(t *testing.T) {
	cases := []struct {
		name       string
		body       string
		wantSkip   bool
	}{
		{
			name:     "skip_llm true",
			body:     `{"query":"SELECT 1","skip_llm":true,"client_id":"x","request_type":"sql"}`,
			wantSkip: true,
		},
		{
			name:     "skip_llm false",
			body:     `{"query":"SELECT 1","skip_llm":false,"client_id":"x","request_type":"sql"}`,
			wantSkip: false,
		},
		{
			name:     "skip_llm omitted defaults to false",
			body:     `{"query":"SELECT 1","client_id":"x","request_type":"sql"}`,
			wantSkip: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var req ClientRequest
			if err := json.Unmarshal([]byte(tc.body), &req); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if req.SkipLLM != tc.wantSkip {
				t.Errorf("SkipLLM=%v, want %v (body=%s)", req.SkipLLM, tc.wantSkip, tc.body)
			}
		})
	}
}

// TestClientRequest_OmitemptyOnMarshal asserts that the JSON tag's
// `omitempty` modifier drops skip_llm from the output when false. This
// matters for the agent → orchestrator forward: the orchestrator's
// OrchestratorRequest also uses `omitempty`, so an omitted field is
// equivalent to false on the receiving end. We don't want a
// false→omitted→false round-trip to be confused with a genuine "field not
// present" signal somewhere downstream.
func TestClientRequest_OmitemptyOnMarshal(t *testing.T) {
	t.Run("true is emitted", func(t *testing.T) {
		req := ClientRequest{Query: "SELECT 1", SkipLLM: true}
		out, err := json.Marshal(req)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if !strings.Contains(string(out), `"skip_llm":true`) {
			t.Errorf("expected `skip_llm:true` in output, got %s", out)
		}
	})

	t.Run("false is omitted", func(t *testing.T) {
		req := ClientRequest{Query: "SELECT 1", SkipLLM: false}
		out, err := json.Marshal(req)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if strings.Contains(string(out), `"skip_llm"`) {
			t.Errorf("expected `skip_llm` omitted from output, got %s", out)
		}
	})
}

// TestPolicyEvaluationInfo_BothFieldsEmitMatchedPolicies asserts that both
// the new canonical `matched_policies` JSON field and the backward-compat
// `policies_evaluated` alias contain the same list. Existing dashboards/SDKs
// reading the legacy name keep working; new consumers should switch to
// matched_policies. Both populated identically by every constructor in
// platform/agent/run.go.
func TestPolicyEvaluationInfo_BothFieldsEmitMatchedPolicies(t *testing.T) {
	info := PolicyEvaluationInfo{
		MatchedPolicies:   []string{"sys_sqli_union_select", "sys_sqli_drop"},
		PoliciesEvaluated: []string{"sys_sqli_union_select", "sys_sqli_drop"},
		StaticChecks:      []string{"shared_policy_engine"},
		ProcessingTime:    "39ms",
		TenantID:          "loadtest",
	}
	out, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	matched, ok1 := parsed["matched_policies"].([]interface{})
	legacy, ok2 := parsed["policies_evaluated"].([]interface{})
	if !ok1 {
		t.Fatalf("matched_policies missing from JSON output: %s", out)
	}
	if !ok2 {
		t.Fatalf("policies_evaluated missing from JSON output (backward compat broken): %s", out)
	}
	if len(matched) != len(legacy) {
		t.Errorf("length mismatch: matched_policies=%d, policies_evaluated=%d", len(matched), len(legacy))
	}
	for i := range matched {
		if matched[i] != legacy[i] {
			t.Errorf("slot %d: matched_policies=%v, policies_evaluated=%v (should be identical)", i, matched[i], legacy[i])
		}
	}
}

