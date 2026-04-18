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
)

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

	var id, scope, sysID, reason, fallback string
	err := k.db.QueryRowContext(ctx, query, orgID, systemID).Scan(&id, &scope, &sysID, &reason, &fallback)
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

	rows, err := k.db.QueryContext(ctx, query, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to list active kill switches: %w", err)
	}
	defer rows.Close()

	var result []*ActiveKillSwitch
	for rows.Next() {
		ks := &ActiveKillSwitch{}
		var sysID, targetID, activatedBy, reason, fallback sql.NullString
		if err := rows.Scan(&ks.ID, &ks.Scope, &sysID, &targetID, &activatedBy, &reason, &fallback); err != nil {
			return nil, fmt.Errorf("failed to scan kill switch: %w", err)
		}
		ks.SystemID = sysID.String
		ks.TargetIdentifier = targetID.String
		ks.ActivatedBy = activatedBy.String
		ks.ActivationReason = reason.String
		ks.FallbackBehavior = fallback.String
		result = append(result, ks)
	}

	return result, rows.Err()
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
