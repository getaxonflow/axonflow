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

//go:build enterprise

package rbi

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	"axonflow/platform/agent/rls"
)

// #3103. rbi_kill_switches is RLS-gated by migration 301
// (`FOR ALL USING (org_id = get_current_org_id())`) but this file never set
// app.current_org_id. On an axonflow_app_role pool both reads below returned
// zero rows — and for CheckKillSwitch zero rows is spelled "no kill switch is
// active", so an RLS-blind read here silently UN-TRIPS a tripped kill switch.
// Both statements now run inside rls.WithOrgScope.
//
// SCOPE NARROWING, deliberate and called out: both statements select
// `scope = 'global'` rows in addition to the caller's own. `scope` is the kill
// switch's blast radius, not an org sentinel — a 'global' row still carries the
// org_id of the tenant that created it. Unscoped, that meant ANY tenant's
// 'global' kill switch halted EVERY tenant. Under the wrap only the caller's
// own 'global' rows are visible, which is what the migration-301 policy has
// declared all along.

// KillSwitchChecker provides kill switch checking for the agent.
// This is a lightweight implementation that queries the kill switch table
// to check for active kill switches during request pre-check.
type KillSwitchChecker struct {
	db *sql.DB
}

// NewKillSwitchChecker creates a new kill switch checker.
func NewKillSwitchChecker(db *sql.DB) *KillSwitchChecker {
	return &KillSwitchChecker{db: db}
}

// KillSwitchCheckResult represents the result of a kill switch check.
type KillSwitchCheckResult struct {
	// IsBlocked indicates if the request should be blocked
	IsBlocked bool `json:"is_blocked"`

	// Reason provides the blocking reason if blocked
	Reason string `json:"reason,omitempty"`

	// KillSwitchID is the ID of the active kill switch if any
	KillSwitchID string `json:"kill_switch_id,omitempty"`

	// Scope indicates the kill switch scope
	Scope string `json:"scope,omitempty"`

	// FallbackBehavior indicates what to do when blocked
	FallbackBehavior string `json:"fallback_behavior,omitempty"`
}

// CheckKillSwitch checks if any active kill switch applies to the request.
// It checks for:
// 1. Global kill switches (scope='global')
// 2. Organization-level kill switches (scope='organization')
// 3. System-level kill switches for the specified system
func (k *KillSwitchChecker) CheckKillSwitch(ctx context.Context, orgID, systemID string) *KillSwitchCheckResult {
	if k.db == nil {
		return &KillSwitchCheckResult{IsBlocked: false}
	}

	// Query for any active kill switch that applies to this org/system
	// Priority: global > organization > system
	query := `
		SELECT id, scope, system_id, activation_reason, fallback_behavior
		FROM rbi_kill_switches
		WHERE is_active = true
		AND (
			scope = 'global'
			OR (scope = 'organization' AND org_id = $1)
			OR (scope = 'system' AND org_id = $1 AND (system_id = $2 OR system_id = ''))
		)
		ORDER BY
			CASE scope
				WHEN 'global' THEN 1
				WHEN 'organization' THEN 2
				WHEN 'system' THEN 3
				ELSE 4
			END
		LIMIT 1
	`

	// An org-less caller cannot be scoped, and rls.WithOrgScope rejects an empty
	// orgID by design. Handled explicitly rather than left to surface as an
	// opaque wrap error, and logged: this function's contract is fail-open on
	// error, so a silent empty org would be an enforcement hole nobody sees.
	if orgID == "" {
		log.Printf("[RBI KillSwitch] no authenticated org on the request — cannot scope the kill-switch read; not blocking (#3103)")
		return &KillSwitchCheckResult{IsBlocked: false}
	}

	var id, scope, sysID, reason, fallback string
	err := rls.WithOrgScope(ctx, k.db, orgID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, query, orgID, systemID).Scan(&id, &scope, &sysID, &reason, &fallback)
	})
	if err != nil {
		if err == sql.ErrNoRows {
			// No active kill switch - request is allowed
			return &KillSwitchCheckResult{IsBlocked: false}
		}
		// Log error but don't block on DB errors (fail open)
		log.Printf("[RBI KillSwitch] Error checking kill switch: %v", err)
		return &KillSwitchCheckResult{IsBlocked: false}
	}

	// Active kill switch found
	log.Printf("[RBI KillSwitch] BLOCKING request - active kill switch id=%s scope=%s reason=%s", id, scope, reason)

	return &KillSwitchCheckResult{
		IsBlocked:        true,
		Reason:           fmt.Sprintf("RBI Kill Switch Active (%s): %s", scope, reason),
		KillSwitchID:     id,
		Scope:            scope,
		FallbackBehavior: fallback,
	}
}

// KillSwitchEnabled returns whether kill switch enforcement is enabled.
// In enterprise mode, this returns true.
func KillSwitchEnabled() bool {
	return true
}

// ListActiveKillSwitches returns all active kill switches for an org.
func (k *KillSwitchChecker) ListActiveKillSwitches(ctx context.Context, orgID string) ([]*ActiveKillSwitch, error) {
	if k.db == nil {
		return nil, nil
	}

	query := `
		SELECT id, scope, system_id, target_identifier, activated_by, activation_reason, fallback_behavior
		FROM rbi_kill_switches
		WHERE is_active = true
		AND (scope = 'global' OR org_id = $1)
		ORDER BY activated_at DESC
	`

	var result []*ActiveKillSwitch
	if err := rls.WithOrgScope(ctx, k.db, orgID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, query, orgID)
		if err != nil {
			return fmt.Errorf("failed to list active kill switches: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			ks := &ActiveKillSwitch{}
			var sysID, targetID, activatedBy, reason, fallback sql.NullString
			if scanErr := rows.Scan(&ks.ID, &ks.Scope, &sysID, &targetID, &activatedBy, &reason, &fallback); scanErr != nil {
				return fmt.Errorf("failed to scan kill switch: %w", scanErr)
			}
			ks.SystemID = sysID.String
			ks.TargetIdentifier = targetID.String
			ks.ActivatedBy = activatedBy.String
			ks.ActivationReason = reason.String
			ks.FallbackBehavior = fallback.String
			result = append(result, ks)
		}

		return rows.Err()
	}); err != nil {
		return nil, err
	}

	return result, nil
}

// ActiveKillSwitch represents a simplified view of an active kill switch.
type ActiveKillSwitch struct {
	ID               string `json:"id"`
	Scope            string `json:"scope"`
	SystemID         string `json:"system_id,omitempty"`
	TargetIdentifier string `json:"target_identifier,omitempty"`
	ActivatedBy      string `json:"activated_by"`
	ActivationReason string `json:"activation_reason"`
	FallbackBehavior string `json:"fallback_behavior"`
}
