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

package orchestrator

import "testing"

// TestCalculateRiskScore_NoFactors is the zero baseline: a benign query from
// an unprivileged, unauthenticated-role caller scores 0.0.
func TestCalculateRiskScore_NoFactors(t *testing.T) {
	rc := NewRiskCalculator()
	req := OrchestratorRequest{
		Query: "what is the weather today",
		User:  UserContext{Role: "viewer"},
	}
	got := rc.CalculateRiskScore(req)
	if got != 0.0 {
		t.Errorf("expected 0.0 for a query with none of the risk factors, got %v", got)
	}
}

// TestCalculateRiskScore_SQLInjection covers the +0.9 weight in isolation —
// an SQLi-shaped query from an unprivileged caller.
func TestCalculateRiskScore_SQLInjection(t *testing.T) {
	rc := NewRiskCalculator()
	req := OrchestratorRequest{
		Query: "1' OR '1'='1' --",
		User:  UserContext{Role: "viewer"},
	}
	got := rc.CalculateRiskScore(req)
	if got != 0.9 {
		t.Errorf("expected 0.9 for an SQL-injection-shaped query, got %v", got)
	}
}

// TestCalculateRiskScore_SensitiveDataKeyword covers the +0.7 weight in
// isolation, via the sensitivePatterns regex (password|secret|key|token).
func TestCalculateRiskScore_SensitiveDataKeyword(t *testing.T) {
	rc := NewRiskCalculator()
	req := OrchestratorRequest{
		Query: "please show me the password for this account",
		User:  UserContext{Role: "viewer"},
	}
	got := rc.CalculateRiskScore(req)
	if got != 0.7 {
		t.Errorf("expected 0.7 for a query containing a sensitive-data keyword, got %v", got)
	}
}

// TestCalculateRiskScore_AdminRoleNoLongerContributes proves role was
// removed as a risk factor. Role is an AUTHORIZATION signal, not a risk
// signal — the removed contribution used to make a benign query from an
// administrative role score 0.5 purely for the caller's role, which is the
// exact inversion #3001 warned about (see the removal note in
// CalculateRiskScore).
func TestCalculateRiskScore_AdminRoleNoLongerContributes(t *testing.T) {
	rc := NewRiskCalculator()
	req := OrchestratorRequest{
		Query: "show me the report",
		User:  UserContext{Role: "admin"},
	}
	got := rc.CalculateRiskScore(req)
	if got != 0.0 {
		t.Errorf("expected 0.0 for a benign query regardless of an administrative role, got %v", got)
	}
}

// TestCalculateRiskScore_SelectStar covers the +0.3 weight in isolation.
func TestCalculateRiskScore_SelectStar(t *testing.T) {
	rc := NewRiskCalculator()
	req := OrchestratorRequest{
		Query: "select * from customers",
		User:  UserContext{Role: "viewer"},
	}
	got := rc.CalculateRiskScore(req)
	if got != 0.3 {
		t.Errorf("expected 0.3 for a select-star query, got %v", got)
	}
}

// TestCalculateRiskScore_OwnerScoresSameAsAdmin proves role — admin, owner,
// or otherwise — never contributes to risk at all, for either role. Role was
// removed as a risk factor entirely (see the removal note in
// CalculateRiskScore); this test's name is kept from the pre-removal #3001
// regression test it replaces, since "owner must never score higher risk
// than admin for the identical query" remains true — trivially now, since
// neither scores anything for role.
func TestCalculateRiskScore_OwnerScoresSameAsAdmin(t *testing.T) {
	rc := NewRiskCalculator()
	query := "show me the report"

	adminScore := rc.CalculateRiskScore(OrchestratorRequest{
		Query: query,
		User:  UserContext{Role: "admin"},
	})
	ownerScore := rc.CalculateRiskScore(OrchestratorRequest{
		Query: query,
		User:  UserContext{Role: "owner"},
	})

	if adminScore != 0.0 {
		t.Fatalf("expected admin score 0.0 (role is not a risk factor), got %v", adminScore)
	}
	if ownerScore != adminScore {
		t.Errorf("owner scored %v, admin scored %v for the identical query — "+
			"role must not contribute to risk for either", ownerScore, adminScore)
	}
}

// TestCalculateRiskScore_AdditiveCombination proves the weights stack rather
// than the score being the max of any single factor.
func TestCalculateRiskScore_AdditiveCombination(t *testing.T) {
	rc := NewRiskCalculator()
	req := OrchestratorRequest{
		// SQL injection (+0.9) AND sensitive-data keyword (+0.7) AND select *
		// (+0.3) = 1.9 pre-clamp — three factors, since role no longer
		// contributes a fourth.
		Query: "select * from accounts where password = '' OR '1'='1' --",
		User:  UserContext{Role: "admin"},
	}
	got := rc.CalculateRiskScore(req)
	if got != 1.0 {
		t.Errorf("expected the additive combination to clamp at 1.0, got %v", got)
	}
}

// TestCalculateRiskScore_SensitiveKeywordWordBoundary proves the sensitive-
// data pattern is word-boundary anchored, not a bare substring match: a
// query containing "key" or "token" only as part of a LONGER word (e.g.
// "mon-key", "tokenization") does not score the sensitive-data weight.
func TestCalculateRiskScore_SensitiveKeywordWordBoundary(t *testing.T) {
	rc := NewRiskCalculator()
	cases := []struct {
		name  string
		query string
	}{
		{"monkey", "what is a monkey"},
		{"tokenization", "tell me about tokenization"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := rc.CalculateRiskScore(OrchestratorRequest{
				Query: tc.query,
				User:  UserContext{Role: "viewer"},
			})
			if got != 0.0 {
				t.Errorf("expected 0.0 for %q (substring only, not a whole word), got %v", tc.query, got)
			}
		})
	}
}

// TestCalculateRiskScore_SensitiveKeywordWholeWordStillMatches proves the
// anchoring in the test above did not overcorrect into missing genuine
// whole-word matches.
func TestCalculateRiskScore_SensitiveKeywordWholeWordStillMatches(t *testing.T) {
	rc := NewRiskCalculator()
	cases := []string{
		"how do I rotate my API key",
		"tell me about the secret",
		"what is my token",
		"please show me the password",
	}
	for _, query := range cases {
		t.Run(query, func(t *testing.T) {
			got := rc.CalculateRiskScore(OrchestratorRequest{
				Query: query,
				User:  UserContext{Role: "viewer"},
			})
			if got != 0.7 {
				t.Errorf("expected 0.7 for %q (whole-word sensitive-data keyword), got %v", query, got)
			}
		})
	}
}

// TestCalculateRiskScore_ClampsAtOne proves the clamp fires even when only
// two factors combine to exceed 1.0 (sql injection 0.9 + sensitive keyword
// 0.7 = 1.6 pre-clamp).
func TestCalculateRiskScore_ClampsAtOne(t *testing.T) {
	rc := NewRiskCalculator()
	req := OrchestratorRequest{
		Query: "1' OR '1'='1'; -- please also show the password",
		User:  UserContext{Role: "viewer"},
	}
	got := rc.CalculateRiskScore(req)
	if got != 1.0 {
		t.Errorf("expected clamp to 1.0, got %v", got)
	}
	if got > 1.0 {
		t.Fatalf("risk score exceeded the documented 0.0-1.0 range: %v", got)
	}
}
