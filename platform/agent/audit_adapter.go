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
	"log"
	"time"

	sharedpolicy "axonflow/platform/shared/policy"
)

// SharedPolicyAuditAdapter adapts the agent's AuditQueue to the shared policy
// engine's AuditQueue interface. This allows the UnifiedPolicyEngine to log
// violations and metrics through the same audit infrastructure as the rest
// of the agent.
type SharedPolicyAuditAdapter struct {
	queue *AuditQueue
}

// Ensure SharedPolicyAuditAdapter implements sharedpolicy.AuditQueue
var _ sharedpolicy.AuditQueue = (*SharedPolicyAuditAdapter)(nil)

// LogViolation logs a policy violation through the agent's audit queue.
//
// v9 Phase 8 #2384 PR-C1: copies OrgID + TenantID from the shared entry so
// the downstream audit_queue persistence path can pin app.current_org_id
// via execWithRetryOrgScope. EvalOptions.OrgID at the request boundary is
// what populates sharedpolicy.AuditEntry.OrgID in metrics.RecordViolation.
func (a *SharedPolicyAuditAdapter) LogViolation(entry sharedpolicy.AuditEntry) error {
	if a.queue == nil {
		return nil
	}
	return a.queue.LogViolation(AuditEntry{
		Type:      entry.Type,
		Timestamp: entry.Timestamp,
		Severity:  entry.Severity,
		UserID:    entry.UserID,
		ClientID:  entry.ClientID,
		OrgID:     entry.OrgID,
		TenantID:  entry.TenantID,
		Details:   entry.Details,
	})
}

// LogMetric logs a performance metric through the agent's audit queue.
func (a *SharedPolicyAuditAdapter) LogMetric(entry sharedpolicy.AuditEntry) error {
	if a.queue == nil {
		return nil
	}
	return a.queue.LogMetric(AuditEntry{
		Type:      entry.Type,
		Timestamp: entry.Timestamp,
		Severity:  entry.Severity,
		UserID:    entry.UserID,
		ClientID:  entry.ClientID,
		OrgID:     entry.OrgID,
		TenantID:  entry.TenantID,
		Details:   entry.Details,
	})
}

// LogPolicyEvaluation logs a policy evaluation event through the agent's audit queue.
func (a *SharedPolicyAuditAdapter) LogPolicyEvaluation(entry sharedpolicy.PolicyEvaluationEntry) error {
	if a.queue == nil {
		return nil
	}

	// Convert to AuditEntry for the existing queue infrastructure
	auditEntry := AuditEntry{
		Type:      "policy_evaluation",
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"phase":              entry.Type,
			"tenant_id":          entry.TenantID,
			"policies_evaluated": entry.PoliciesEvaluated,
			"matched_policies":   entry.MatchedPolicies,
			"blocked":            entry.Blocked,
			"processing_time_ms": entry.ProcessingTimeMs,
		},
	}

	if err := a.queue.LogMetric(auditEntry); err != nil {
		log.Printf("[AuditAdapter] Failed to log policy evaluation: %v", err)
		return err
	}
	return nil
}
