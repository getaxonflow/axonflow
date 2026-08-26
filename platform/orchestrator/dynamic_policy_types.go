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

import "time"

// DynamicPolicy represents a runtime policy that can be evaluated against
// incoming requests. Policies are stored in the dynamic_policies database
// table and can be created, updated, and deleted via the Policy Management API.
//
// All conditions within a single policy must match for that policy to
// trigger (AND logic).
//
// Evaluation order across DIFFERENT policies (as of #3319/#3322) is NOT
// priority order despite the Priority field existing on this type:
// DatabaseDynamicPolicyEngine.EvaluateDynamicPolicies (db_dynamic_policies.go)
// iterates its in-memory cache with a plain `range` over a
// map[string]interface{}, and Go deliberately randomizes map iteration order
// per run. Priority is honored within a single evaluation for the "keep the
// highest severity so far" and "keep the highest risk_score so far" reducers,
// but the ORDER policies are visited in is not priority, and an action whose
// effect is last-writer-wins across policies (e.g. two matching `route`
// policies disagreeing on PreferredProvider, or two matching `modify_risk`
// policies) can pick a different winner run to run. A deterministic total
// order (priority DESC, created_at DESC, cacheKey ASC) is planned via
// sortedDynamicPolicyEntries — see #3321/#3324, which also makes risk_score
// itself computed rather than caller-supplied, the change that first exposed
// this nondeterminism as security-relevant (a matched policy's modify_risk
// can now escalate a LATER condition's risk_score>N check within the same
// evaluation).
//
// #3319: relocated from dynamic_policy_engine.go, which was deleted along
// with the retired in-memory DynamicPolicyEngine. This type is data, not a
// component — it is produced by loadDefaultDynamicPolicies (policy_defaults.go)
// and by DatabaseDynamicPolicyEngine's ListActivePolicies /
// ListActivePoliciesForTenant (db_dynamic_policies.go), and consumed widely
// across the policy API, MCP handler, and simulation/conflict services.
type DynamicPolicy struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Type        string            `json:"type"` // "content", "user", "risk", "cost", "media"
	Category    string            `json:"category,omitempty"`
	Conditions  []PolicyCondition `json:"conditions"`
	Actions     []PolicyAction    `json:"actions"`
	Priority    int               `json:"priority"`
	Enabled     bool              `json:"enabled"`
	TenantID    string            `json:"tenant_id,omitempty"`
	// SegmentID (ADR-060 #2989 P3b) is the stable scim_groups.id this policy
	// is scoped to, or "" when the policy is not segment-scoped (the
	// overwhelming majority — every pre-P3b policy, and every org that never
	// authors a segment-scoped policy). Orthogonal to TenantID, mirroring
	// migration 159 / static_policies.SegmentID (P3): a policy can be
	// tenant-scoped, segment-scoped, both, or neither. Empty string (not a
	// pointer) matches this type's existing TenantID convention.
	SegmentID     string    `json:"segment_id,omitempty"`
	RiskLevel     string    `json:"risk_level,omitempty"` // low|medium|high|critical (ADR-044). Default "medium".
	AllowOverride bool      `json:"allow_override"`       // Session override allowed? Forced false for critical risk (ADR-044).
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// IsOverridable returns true if the policy's deny decision can be overridden
// by an active session override. Critical-risk policies cannot be overridden
// regardless of the AllowOverride flag (ADR-044 invariant).
func (p *DynamicPolicy) IsOverridable() bool {
	if p.RiskLevel == "critical" {
		return false
	}
	return p.AllowOverride
}

// PolicyCondition defines when a policy should trigger.
//
// Supported operators:
//   - contains: Field value contains the specified string (case-insensitive)
//   - equals: Field value exactly matches the specified value
//   - not_equals: Field value does not match the specified value
//   - greater_than: Numeric field is greater than the specified value
//   - less_than: Numeric field is less than the specified value
//   - regex: Field value matches the specified regular expression
//   - in: Field value is in the specified list
//
// Supported fields:
//   - query: The raw query text
//   - request_type: Type of request
//   - user.role, user.email, user.tenant_id: User context
//   - client.id, client.name: Client context
//   - risk_score: Calculated risk score (0.0-1.0)
//   - context.<key>: Custom context values
type PolicyCondition struct {
	Field    string      `json:"field"`    // "query", "user.role", "risk_score", etc.
	Operator string      `json:"operator"` // "contains", "equals", "greater_than", etc.
	Value    interface{} `json:"value"`
}

// PolicyAction defines what happens when a policy triggers.
//
// Supported action types:
//   - block: Deny the request (Config: {"reason": "string"})
//   - redact: Mark fields for redaction (Config: {"fields": ["field1", "field2"]})
//   - alert: Send alert to monitoring (Config varies by alerting system)
//   - log: Enhanced logging for the request
//   - modify_risk: Adjust the risk score additively (Config: {"add": 0.2}).
//     Not the same key/semantics as the retired in-memory engine's
//     multiplicative "modifier" -- this engine's switch has always read
//     "add" (see migration 031's sys_dyn_llm_cost system policy).
type PolicyAction struct {
	Type   string                 `json:"type"` // "block", "redact", "alert", "log"
	Config map[string]interface{} `json:"config"`
}

// severityOrdinal returns the ordinal for severity comparison. Higher = more
// severe. Used by DatabaseDynamicPolicyEngine.EvaluateDynamicPolicies
// (db_dynamic_policies.go) to keep the highest severity when multiple
// require_approval policies match.
func severityOrdinal(s string) int {
	switch s {
	case "critical":
		return 3
	case "high":
		return 2
	case "medium":
		return 1
	case "low":
		return 0
	default:
		return -1
	}
}
