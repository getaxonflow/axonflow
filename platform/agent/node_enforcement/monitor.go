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

package node_enforcement

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"axonflow/platform/agent/rls"
)

// NodeMonitor monitors node counts against license limits
type NodeMonitor struct {
	db       *sql.DB
	alerter  AlertService
	interval time.Duration
	stopCh   chan struct{}
}

// ViolationInfo contains details about a node limit violation
type ViolationInfo struct {
	OrgID             string
	LicenseKeyHash    string
	Tier              string
	MaxNodesAllowed   int
	ActualNodeCount   int
	ExcessNodes       int
	ActiveInstances   []string
	ViolationStart    time.Time
	ViolationDuration time.Duration
}

// AlertService interface for sending alerts (Slack, email, CloudWatch)
type AlertService interface {
	SendNodeViolationAlert(ctx context.Context, violation *ViolationInfo) error
	SendNodeCountWarning(ctx context.Context, orgID string, usage float64) error
}

// NewNodeMonitor creates a new node monitor
func NewNodeMonitor(db *sql.DB, alerter AlertService) *NodeMonitor {
	return &NodeMonitor{
		db:       db,
		alerter:  alerter,
		interval: 5 * time.Minute, // Check every 5 minutes
		stopCh:   make(chan struct{}),
	}
}

// Start begins monitoring node counts
func (m *NodeMonitor) Start(ctx context.Context) {
	go m.monitorLoop(ctx)
}

// Stop stops the monitor
func (m *NodeMonitor) Stop() {
	close(m.stopCh)
}

// monitorLoop runs periodic node count checks
func (m *NodeMonitor) monitorLoop(ctx context.Context) {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	// Run immediately on start
	if err := m.checkAllNodeCounts(ctx); err != nil {
		fmt.Printf("Node count check error: %v\n", err)
	}

	for {
		select {
		case <-ticker.C:
			if err := m.checkAllNodeCounts(ctx); err != nil {
				fmt.Printf("Node count check error: %v\n", err)
			}
		case <-m.stopCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

// checkAllNodeCounts checks node counts for all organizations
func (m *NodeMonitor) checkAllNodeCounts(ctx context.Context) error {
	// Get active nodes grouped by org
	nodesByOrg, err := GetActiveNodesByOrg(ctx, m.db)
	if err != nil {
		return fmt.Errorf("failed to get active nodes by org: %w", err)
	}

	// For each org, check against license limits
	for orgID, actualCount := range nodesByOrg {
		if err := m.checkOrgNodeCount(ctx, orgID, actualCount); err != nil {
			fmt.Printf("Error checking org %s: %v\n", orgID, err)
		}
	}

	// Clean up resolved violations
	if err := m.cleanupResolvedViolations(ctx); err != nil {
		fmt.Printf("Error cleaning up violations: %v\n", err)
	}

	return nil
}

// checkOrgNodeCount checks a single organization's node count against their license
func (m *NodeMonitor) checkOrgNodeCount(ctx context.Context, orgID string, actualCount int) error {
	// Get organization details from database
	var maxNodes int
	var tier string
	var licenseKey string

	query := `
		SELECT o.max_nodes, o.tier, o.license_key
		FROM organizations o
		WHERE o.org_id = $1
	`
	err := m.db.QueryRowContext(ctx, query, orgID).Scan(&maxNodes, &tier, &licenseKey)
	if err == sql.ErrNoRows {
		// Organization not found in database, skip
		fmt.Printf("⚠️  Organization %s not found in database, skipping node count check\n", orgID)
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to get organization details for %s: %w", orgID, err)
	}

	// Hash the license key for storage (don't store raw keys)
	licenseKeyHash := hashLicenseKey(licenseKey)

	// Check for violation
	if actualCount > maxNodes {
		violation := &ViolationInfo{
			OrgID:           orgID,
			LicenseKeyHash:  licenseKeyHash,
			Tier:            tier,
			MaxNodesAllowed: maxNodes,
			ActualNodeCount: actualCount,
			ExcessNodes:     actualCount - maxNodes,
		}

		if err := m.recordViolation(ctx, violation); err != nil {
			return fmt.Errorf("failed to record violation: %w", err)
		}

		// Send alert
		if err := m.alerter.SendNodeViolationAlert(ctx, violation); err != nil {
			fmt.Printf("Failed to send violation alert: %v\n", err)
		}
	}

	// Check for warning (80% usage)
	usagePercent := float64(actualCount) / float64(maxNodes)
	if usagePercent >= 0.8 && usagePercent < 1.0 {
		if err := m.alerter.SendNodeCountWarning(ctx, orgID, usagePercent); err != nil {
			fmt.Printf("Failed to send warning alert: %v\n", err)
		}
	}

	return nil
}

// recordViolation records a node limit violation in the database.
//
// v9 Phase 8 #2384 PR-C1: node_violations is ENABLE-RLS (mig 018) and
// FORCE-RLS (mig 107) — under axonflow_app_role the INSERT/UPDATE WITH
// CHECK predicate `org_id = current_setting('app.current_org_id')` fires.
// We wrap the existence-probe SELECT + the INSERT/UPDATE in a single
// WithOrgScope transaction so app.current_org_id is pinned to
// violation.OrgID for the lifetime of the read-then-write. Doing the
// SELECT inside the wrap is required: the read is also gated by
// USING (org_id = ...) and would silently return zero rows without it,
// flipping the switch case into "create new" even when an active
// violation already exists.
func (m *NodeMonitor) recordViolation(ctx context.Context, violation *ViolationInfo) error {
	if violation == nil || violation.OrgID == "" {
		return fmt.Errorf("recordViolation: violation.OrgID must be non-empty (RLS enforced by mig 018+107)")
	}

	return rls.WithOrgScope(ctx, m.db, violation.OrgID, func(tx *sql.Tx) error {
		// Check if there's already an active violation for this org
		var existingID int
		query := `
			SELECT id FROM node_violations
			WHERE org_id = $1 AND resolved = FALSE
			LIMIT 1
		`
		err := tx.QueryRowContext(ctx, query, violation.OrgID).Scan(&existingID)

		switch err {
		case sql.ErrNoRows:
			// Create new violation
			metadata, _ := json.Marshal(violation)
			insertQuery := `
				INSERT INTO node_violations (
					org_id, license_key_hash, tier, max_nodes_allowed,
					actual_node_count, excess_nodes, metadata
				) VALUES ($1, $2, $3, $4, $5, $6, $7)
			`
			_, err = tx.ExecContext(ctx, insertQuery,
				violation.OrgID,
				violation.LicenseKeyHash,
				violation.Tier,
				violation.MaxNodesAllowed,
				violation.ActualNodeCount,
				violation.ExcessNodes,
				metadata,
			)
			if err != nil {
				return fmt.Errorf("failed to insert violation: %w", err)
			}
			fmt.Printf("⚠️  Node violation recorded: org=%s, actual=%d, max=%d, excess=%d\n",
				violation.OrgID, violation.ActualNodeCount, violation.MaxNodesAllowed, violation.ExcessNodes)
		case nil:
			// Update existing violation
			updateQuery := `
				UPDATE node_violations
				SET actual_node_count = $1,
				    excess_nodes = $2,
				    alert_sent = TRUE
				WHERE id = $3
			`
			_, err = tx.ExecContext(ctx, updateQuery,
				violation.ActualNodeCount,
				violation.ExcessNodes,
				existingID,
			)
			if err != nil {
				return fmt.Errorf("failed to update violation: %w", err)
			}
		default:
			return fmt.Errorf("failed to check existing violations: %w", err)
		}

		return nil
	})
}

// cleanupResolvedViolations marks violations as resolved if node count is back within limits
func (m *NodeMonitor) cleanupResolvedViolations(ctx context.Context) error {
	// Find all unresolved violations
	query := `
		SELECT nv.id, nv.org_id, nv.max_nodes_allowed
		FROM node_violations nv
		WHERE nv.resolved = FALSE
	`

	rows, err := m.db.QueryContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to query unresolved violations: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Printf("Error closing rows: %v", err)
		}
	}()

	for rows.Next() {
		var id int
		var orgID string
		var maxNodes int

		if err := rows.Scan(&id, &orgID, &maxNodes); err != nil {
			return err
		}

		// Check current node count for this org
		nodesByOrg, err := GetActiveNodesByOrg(ctx, m.db)
		if err != nil {
			continue
		}

		currentCount := nodesByOrg[orgID]

		// If within limits, mark as resolved
		if currentCount <= maxNodes {
			// v9 Phase 8 #2384 PR-C1: wrap the per-row UPDATE in WithOrgScope.
			// node_violations is FORCE-RLS'd (mig 107) — under app_role the
			// UPDATE WHERE id=$1 alone is gated by the USING predicate, which
			// silently zeroes rows-affected without app.current_org_id set.
			// We have orgID per row from the outer SELECT loop, so the wrap
			// is mechanical even though cleanupResolvedViolations is
			// conceptually a cross-org sweep.
			updateQuery := `
				UPDATE node_violations
				SET resolved = TRUE, violation_end = NOW()
				WHERE id = $1
			`
			updateErr := rls.WithOrgScope(ctx, m.db, orgID, func(tx *sql.Tx) error {
				_, exErr := tx.ExecContext(ctx, updateQuery, id)
				return exErr
			})
			if updateErr != nil {
				fmt.Printf("Failed to resolve violation %d: %v\n", id, updateErr)
			} else {
				fmt.Printf("✅ Violation resolved: org=%s, current=%d, max=%d\n",
					orgID, currentCount, maxNodes)
			}
		}
	}

	return nil
}

// GetViolationHistory returns all violations for an organization
func GetViolationHistory(ctx context.Context, db *sql.DB, orgID string) ([]*ViolationInfo, error) {
	query := `
		SELECT org_id, tier, max_nodes_allowed, actual_node_count, excess_nodes,
		       violation_start, violation_end, resolved
		FROM node_violations
		WHERE org_id = $1
		ORDER BY violation_start DESC
		LIMIT 100
	`

	rows, err := db.QueryContext(ctx, query, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to query violation history: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Printf("Error closing rows: %v", err)
		}
	}()

	var violations []*ViolationInfo
	for rows.Next() {
		var v ViolationInfo
		var violationStart sql.NullTime
		var violationEnd sql.NullTime
		var resolved bool

		err := rows.Scan(
			&v.OrgID, &v.Tier, &v.MaxNodesAllowed,
			&v.ActualNodeCount, &v.ExcessNodes,
			&violationStart, &violationEnd, &resolved,
		)
		if err != nil {
			return nil, err
		}

		// Populate ViolationStart and calculate duration
		if violationStart.Valid {
			v.ViolationStart = violationStart.Time
			if violationEnd.Valid {
				v.ViolationDuration = violationEnd.Time.Sub(violationStart.Time)
			} else if !resolved {
				// Still ongoing - calculate duration from start to now
				v.ViolationDuration = time.Since(violationStart.Time)
			}
		}

		violations = append(violations, &v)
	}

	return violations, nil
}
