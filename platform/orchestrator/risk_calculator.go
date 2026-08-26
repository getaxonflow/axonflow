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

import (
	"context"
	"regexp"
	"strings"

	"axonflow/platform/agent/sqli"
)

// RiskCalculator calculates risk scores for requests based on query patterns
// and user context. Scores range from 0.0 (no risk) to 1.0 (maximum risk).
//
// Risk factors:
//   - SQL injection patterns: +0.9 (uses unified sqli package for detection)
//   - Sensitive data keywords: +0.7
//   - SELECT * queries: +0.3
//
// Role is deliberately NOT a risk factor — see the removal note on
// CalculateRiskScore below.
//
// #3321: restored from the retired in-memory DynamicPolicyEngine
// (dynamic_policy_engine.go, removed by #3319) — the database-backed engine
// never had this heuristic, so the "risk_score" condition field it seeds
// (see EvaluateDynamicPolicies in db_dynamic_policies.go) was previously
// unreachable except via a boot-failure fallback.
type RiskCalculator struct {
	sqliScanner       sqli.Scanner     // Unified SQL injection scanner from sqli package
	sensitivePatterns []*regexp.Regexp // Non-SQLi sensitive data patterns (passwords, secrets)
	riskWeights       map[string]float64
}

// NewRiskCalculator constructs a RiskCalculator with the shared sqli scanner,
// the (currently hardcoded) sensitive-data patterns, and the standard risk
// weights.
func NewRiskCalculator() *RiskCalculator {
	return &RiskCalculator{
		// Use unified sqli package for SQL injection detection
		// This provides 35+ patterns with category-based severity classification
		// and consistent detection across input and response scanning
		sqliScanner: sqli.NewBasicScanner(),
		// Sensitive data patterns (non-SQLi) for risk calculation. Word-boundary
		// anchored (\b...\b) so the match is the WORD, not a substring of any
		// longer word that happens to contain it — the unanchored form scored
		// "what is a mon-key" and "tell me about tokenization" +0.7 for
		// containing "key" and "token" as substrings.
		// TODO: Issue #891 - migrate these to database for customization
		sensitivePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)\b(password|secret|key|token)\b`),
		},
		riskWeights: map[string]float64{
			"sql_injection":    0.9,
			"sensitive_data":   0.7,
			"large_result_set": 0.3,
		},
	}
}

// CalculateRiskScore computes an additive, clamped-to-1.0 risk score for req.
func (r *RiskCalculator) CalculateRiskScore(req OrchestratorRequest) float64 {
	score := 0.0

	// Check for SQL injection patterns using unified sqli scanner
	// This provides consistent detection with the agent and MCP response scanning
	sqliResult := r.sqliScanner.Scan(context.Background(), req.Query, sqli.ScanTypeInput)
	if sqliResult.Detected {
		score += r.riskWeights["sql_injection"]
	}

	// Check for sensitive data keywords (non-SQLi patterns)
	for _, pattern := range r.sensitivePatterns {
		if pattern.MatchString(req.Query) {
			score += r.riskWeights["sensitive_data"]
		}
	}

	// Role is deliberately NOT a risk contribution. This used to add
	// riskWeights["admin_query"] (0.5) via sharedidentity.RoleIsAdministrative,
	// but role is an AUTHORIZATION signal, not a risk signal: as built, the
	// more trusted the caller, the more likely they were blocked — an owner
	// asking "how do I rotate my API key" scored 1.00 and blocked, while an
	// unprivileged user asking the identical question scored 0.7 and passed.
	// RoleIsAdministrative's own doc describes it as identifying roles that
	// receive enforcement RELAXATIONS; using it here to ADD risk read the
	// same predicate backwards.

	// Check query type
	if strings.Contains(strings.ToLower(req.Query), "select *") {
		score += r.riskWeights["large_result_set"]
	}

	// Normalize score to 0-1 range
	if score > 1.0 {
		score = 1.0
	}

	return score
}
