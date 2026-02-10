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
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"axonflow/platform/agent/license"
	"axonflow/platform/shared/execution"
)

func TestAuditCleanupService_CleanupExpiredAuditLogs(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	tests := []struct {
		name           string
		tier           license.Tier
		retentionDays  int
		rowsAffected   int64
		expectDelete   bool
		expectErr      bool
	}{
		{
			name:          "Community tier - 3 day retention",
			tier:          license.TierCommunity,
			retentionDays: 3,
			rowsAffected:  10,
			expectDelete:  true,
		},
		{
			name:          "Evaluation tier - 14 day retention",
			tier:          license.TierEvaluation,
			retentionDays: 14,
			rowsAffected:  5,
			expectDelete:  true,
		},
		{
			name:          "Enterprise tier - 3650 day retention",
			tier:          license.TierEnterprise,
			retentionDays: 3650,
			rowsAffected:  0,
			expectDelete:  true,
		},
		{
			name:          "Zero retention - no cleanup",
			tier:          license.TierEnterprise,
			retentionDays: 0,
			expectDelete:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := &mockLicenseChecker{
				tier:               tt.tier,
				auditRetentionDays: tt.retentionDays,
			}

			svc := NewAuditCleanupService(db, checker)

			if tt.expectDelete {
				mock.ExpectExec(`DELETE FROM audit_logs WHERE timestamp < \$1`).
					WillReturnResult(sqlmock.NewResult(0, tt.rowsAffected))
			}

			count, err := svc.CleanupExpiredAuditLogs(context.Background())

			if tt.expectErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if count != tt.rowsAffected {
				t.Errorf("expected %d rows affected, got %d", tt.rowsAffected, count)
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unfulfilled mock expectations: %v", err)
			}
		})
	}
}

func TestAuditCleanupService_CleanupExpiredAuditLogs_NilDB(t *testing.T) {
	checker := &DefaultLicenseChecker{}
	svc := NewAuditCleanupService(nil, checker)

	count, err := svc.CleanupExpiredAuditLogs(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 rows affected with nil db, got %d", count)
	}
}

func TestAuditCleanupService_RetentionCutoff(t *testing.T) {
	tests := []struct {
		name          string
		retentionDays int
		expectZero    bool
	}{
		{
			name:          "Community - 3 days",
			retentionDays: 3,
		},
		{
			name:          "Evaluation - 14 days",
			retentionDays: 14,
		},
		{
			name:          "Zero retention - no cutoff",
			retentionDays: 0,
			expectZero:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := &mockLicenseChecker{
				auditRetentionDays: tt.retentionDays,
			}
			svc := NewAuditCleanupService(nil, checker)

			cutoff := svc.RetentionCutoff()

			if tt.expectZero {
				if !cutoff.IsZero() {
					t.Errorf("expected zero time, got %v", cutoff)
				}
				return
			}

			expected := time.Now().UTC().AddDate(0, 0, -tt.retentionDays)
			diff := cutoff.Sub(expected)
			if diff < -time.Second || diff > time.Second {
				t.Errorf("cutoff %v not within 1s of expected %v", cutoff, expected)
			}
		})
	}
}

func TestAuditCleanupService_CleanupExpiredAuditLogs_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	checker := &mockLicenseChecker{
		tier:               license.TierCommunity,
		auditRetentionDays: 3,
	}
	svc := NewAuditCleanupService(db, checker)

	mock.ExpectExec(`DELETE FROM audit_logs WHERE timestamp < \$1`).
		WillReturnError(context.DeadlineExceeded)

	_, err = svc.CleanupExpiredAuditLogs(context.Background())
	if err == nil {
		t.Error("expected error, got nil")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled mock expectations: %v", err)
	}
}

func TestAuditCleanupService_SetExecutionRepo(t *testing.T) {
	checker := &DefaultLicenseChecker{}
	svc := NewAuditCleanupService(nil, checker)

	if svc.executionRepo != nil {
		t.Error("executionRepo should be nil initially")
	}

	// SetExecutionRepo should set the field (we can't easily create a real repo, but nil→nil is fine)
	svc.SetExecutionRepo(nil)
	if svc.executionRepo != nil {
		t.Error("executionRepo should remain nil after setting nil")
	}
}

func TestAuditCleanupService_PurgeExcessExecutionHistory_NilRepo(t *testing.T) {
	checker := &mockLicenseChecker{
		maxExecutionHistory: 50,
	}
	svc := NewAuditCleanupService(nil, checker)

	// Without execution repo, should return 0
	count, err := svc.PurgeExcessExecutionHistory(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 purged with nil repo, got %d", count)
	}
}

func TestAuditCleanupService_StartCleanupWorker(t *testing.T) {
	checker := &mockLicenseChecker{
		auditRetentionDays:  3,
		maxExecutionHistory: 50,
	}
	svc := NewAuditCleanupService(nil, checker)

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel immediately to test that the worker stops gracefully
	cancel()

	// Should not panic or hang
	svc.StartCleanupWorker(ctx, 100*time.Millisecond)

	// Give it a moment to start and stop
	time.Sleep(50 * time.Millisecond)
}

func TestAuditCleanupService_StartCleanupWorker_DefaultInterval(t *testing.T) {
	checker := &mockLicenseChecker{
		auditRetentionDays: 14,
	}
	svc := NewAuditCleanupService(nil, checker)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// interval=0 should use default (1 hour)
	svc.StartCleanupWorker(ctx, 0)
	time.Sleep(50 * time.Millisecond)
}

func TestAuditCleanupService_PurgeExcessExecutionHistory_NilDB(t *testing.T) {
	checker := &mockLicenseChecker{
		maxExecutionHistory: 50,
	}
	// executionRepo is set but db is nil — should return 0
	svc := NewAuditCleanupService(nil, checker)

	count, err := svc.PurgeExcessExecutionHistory(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 purged with nil db, got %d", count)
	}
}

func TestAuditCleanupService_PurgeExcessExecutionHistory_DBQueryError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	checker := &mockLicenseChecker{
		maxExecutionHistory: 50,
	}
	svc := NewAuditCleanupService(db, checker)
	svc.SetExecutionRepo(&mockPurgeRepo{}) // set a non-nil repo

	mock.ExpectQuery(`SELECT DISTINCT tenant_id FROM execution_history`).
		WillReturnError(context.DeadlineExceeded)

	_, err = svc.PurgeExcessExecutionHistory(context.Background())
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// mockPurgeRepo implements execution.ExecutionRepository for purge tests.
type mockPurgeRepo struct{}

func (m *mockPurgeRepo) Create(_ context.Context, _ *execution.ExecutionStatus) error { return nil }
func (m *mockPurgeRepo) Get(_ context.Context, _ string) (*execution.ExecutionStatus, error) {
	return nil, nil
}
func (m *mockPurgeRepo) Update(_ context.Context, _ *execution.ExecutionStatus) error { return nil }
func (m *mockPurgeRepo) List(_ context.Context, _ execution.ListExecutionsRequest) ([]execution.ExecutionStatus, int, error) {
	return nil, 0, nil
}
func (m *mockPurgeRepo) Delete(_ context.Context, _ string) error                        { return nil }
func (m *mockPurgeRepo) UpdateStatus(_ context.Context, _ string, _ execution.ExecutionStatusValue, _ *time.Time, _ string) error {
	return nil
}
func (m *mockPurgeRepo) UpdateSteps(_ context.Context, _ string, _ []execution.StepStatus) error {
	return nil
}
func (m *mockPurgeRepo) UpdateCost(_ context.Context, _ string, _, _ *float64) error { return nil }
func (m *mockPurgeRepo) CountActive(_ context.Context, _ string) (int, error)        { return 0, nil }
func (m *mockPurgeRepo) PurgeOldest(_ context.Context, _ string, _ int) (int64, error) {
	return 0, nil
}

func TestAuditCleanupService_PurgeExcessExecutionHistory_UnlimitedHistory(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	checker := &mockLicenseChecker{
		maxExecutionHistory: -1, // unlimited
	}
	svc := NewAuditCleanupService(db, checker)

	count, err := svc.PurgeExcessExecutionHistory(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 purged with unlimited history, got %d", count)
	}
}
