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
	"database/sql"
	"fmt"
	"log"
	"time"

	"axonflow/platform/shared/execution"
)

// AuditCleanupService handles periodic cleanup of expired audit log entries
// and execution history purging based on tier-aware limits from LicenseChecker.
type AuditCleanupService struct {
	db             *sql.DB
	licenseChecker LicenseChecker
	executionRepo  execution.ExecutionRepository
}

// NewAuditCleanupService creates a new audit cleanup service.
func NewAuditCleanupService(db *sql.DB, licenseChecker LicenseChecker) *AuditCleanupService {
	return &AuditCleanupService{
		db:             db,
		licenseChecker: licenseChecker,
	}
}

// SetExecutionRepo sets the execution repository for execution history purging.
func (s *AuditCleanupService) SetExecutionRepo(repo execution.ExecutionRepository) {
	s.executionRepo = repo
}

// StartCleanupWorker starts a background goroutine that periodically removes
// audit log entries older than the tier-configured retention period.
func (s *AuditCleanupService) StartCleanupWorker(ctx context.Context, interval time.Duration) {
	if interval == 0 {
		interval = 1 * time.Hour
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Println("[AuditCleanup] Cleanup worker stopped")
				return
			case <-ticker.C:
				count, err := s.CleanupExpiredAuditLogs(ctx)
				if err != nil {
					log.Printf("[AuditCleanup] Audit log cleanup error: %v", err)
				} else if count > 0 {
					log.Printf("[AuditCleanup] Cleaned up %d expired audit log entries", count)
				}

				purged, err := s.PurgeExcessExecutionHistory(ctx)
				if err != nil {
					log.Printf("[AuditCleanup] Execution history purge error: %v", err)
				} else if purged > 0 {
					log.Printf("[AuditCleanup] Purged %d excess execution history records", purged)
				}
			}
		}
	}()

	log.Printf("[AuditCleanup] Started cleanup worker (interval: %v, retention: %d days)",
		interval, s.licenseChecker.AuditRetentionDays())
}

// CleanupExpiredAuditLogs removes audit log entries older than the retention period.
// Returns the number of deleted rows.
func (s *AuditCleanupService) CleanupExpiredAuditLogs(ctx context.Context) (int64, error) {
	if s.db == nil {
		return 0, nil
	}

	retentionDays := s.licenseChecker.AuditRetentionDays()
	if retentionDays <= 0 {
		return 0, nil
	}

	cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays)

	result, err := s.db.ExecContext(ctx,
		`DELETE FROM audit_logs WHERE timestamp < $1`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup audit logs: %w", err)
	}

	count, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}

	return count, nil
}

// RetentionCutoff returns the earliest timestamp that should be visible
// based on the current tier's retention policy.
func (s *AuditCleanupService) RetentionCutoff() time.Time {
	retentionDays := s.licenseChecker.AuditRetentionDays()
	if retentionDays <= 0 {
		return time.Time{} // no cutoff
	}
	return time.Now().UTC().AddDate(0, 0, -retentionDays)
}

// PurgeExcessExecutionHistory removes execution history records that exceed
// the tier-based MaxExecutionHistory limit per tenant.
func (s *AuditCleanupService) PurgeExcessExecutionHistory(ctx context.Context) (int64, error) {
	if s.executionRepo == nil || s.db == nil {
		return 0, nil
	}

	maxHistory := s.licenseChecker.MaxExecutionHistory()
	if maxHistory <= 0 {
		return 0, nil // unlimited
	}

	// Get distinct tenant IDs from execution history
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT tenant_id FROM execution_history WHERE tenant_id != ''`)
	if err != nil {
		return 0, fmt.Errorf("failed to query tenant IDs: %w", err)
	}
	defer rows.Close()

	var totalPurged int64
	for rows.Next() {
		var tenantID string
		if err := rows.Scan(&tenantID); err != nil {
			continue
		}
		purged, err := s.executionRepo.PurgeOldest(ctx, tenantID, maxHistory)
		if err != nil {
			log.Printf("[AuditCleanup] Failed to purge execution history for tenant %s: %v", tenantID, err)
			continue
		}
		totalPurged += purged
	}

	return totalPurged, nil
}
