// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package execution

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

// Regression guard for the executions-list / get 500 fixed in WS-12 (#2778).
//
// `execution_history.source` is nullable (mig-042: "for MAP: null"). Before the
// fix, List/Get/GetByMetadata scanned `source` straight into a Go string, so a
// row with a NULL source errored "converting NULL to string is unsupported",
// 500-ing the entire /executions page for any tenant that had a MAP plan. The
// scan now uses sql.NullString. sqlmock injects a literal NULL (nil) below to
// reproduce the exact failing row shape; the existing tests only ever used an
// empty string, which is why they never caught it.

var nullScanColumns = []string{
	"id", "execution_type", "name", "source",
	"tenant_id", "org_id", "user_id", "client_id",
	"status", "current_step_index", "total_steps",
	"started_at", "completed_at", "estimated_cost_usd", "actual_cost_usd",
	"steps", "error_message", "metadata", "created_at", "updated_at",
}

func TestPostgresRepository_List_NullSource(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("mock: %v", err)
	}
	defer db.Close()

	repo := NewPostgresRepository(db)
	ctx := context.Background()
	now := time.Now()
	stepsJSON, _ := json.Marshal([]StepStatus{})
	metadataJSON, _ := json.Marshal(map[string]interface{}{})

	mock.ExpectQuery("SELECT COUNT\\(\\*\\)").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("SELECT .* FROM execution_history").
		WillReturnRows(sqlmock.NewRows(nullScanColumns).
			// source = nil (NULL), plus NULL org/user/client — the MAP-plan shape.
			AddRow("plan_null_src", "map_plan", "MAP Plan", nil, "tenant-1", nil, nil, nil,
				"running", 1, 3, now, nil, nil, nil, stepsJSON, nil, metadataJSON, now, now))

	results, total, err := repo.List(ctx, ListExecutionsRequest{OrgID: "org-1", OrgWide: true, Limit: 10})
	if err != nil {
		t.Fatalf("List() with a NULL source must not error (regression #2778): %v", err)
	}
	if total != 1 || len(results) != 1 {
		t.Fatalf("want 1 result/total, got len=%d total=%d", len(results), total)
	}
	if results[0].Source != "" {
		t.Errorf("NULL source should scan to empty string, got %q", results[0].Source)
	}
}

func TestPostgresRepository_Get_NullSource(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("mock: %v", err)
	}
	defer db.Close()

	repo := NewPostgresRepository(db)
	ctx := context.Background()
	now := time.Now()
	stepsJSON, _ := json.Marshal([]StepStatus{})
	metadataJSON, _ := json.Marshal(map[string]interface{}{})

	mock.ExpectQuery("SELECT .* FROM execution_history").
		WithArgs("plan_null_src").
		WillReturnRows(sqlmock.NewRows(nullScanColumns).
			AddRow("plan_null_src", "map_plan", "MAP Plan", nil, "tenant-1", nil, nil, nil,
				"running", 1, 3, now, nil, nil, nil, stepsJSON, nil, metadataJSON, now, now))

	exec, err := repo.Get(ctx, "plan_null_src")
	if err != nil {
		t.Fatalf("Get() with a NULL source must not error (regression #2778): %v", err)
	}
	if exec.Source != "" {
		t.Errorf("NULL source should scan to empty string, got %q", exec.Source)
	}
}

func TestPostgresRepository_GetByMetadata_NullSource(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("mock: %v", err)
	}
	defer db.Close()

	repo := NewPostgresRepository(db)
	ctx := context.Background()
	now := time.Now()
	stepsJSON, _ := json.Marshal([]StepStatus{})
	metadataJSON, _ := json.Marshal(map[string]interface{}{})

	// getByMetadataHardcoded (GetByPlanID / GetByMetadata) shares the same scan.
	mock.ExpectQuery("SELECT .* FROM execution_history").
		WithArgs("plan_null_src").
		WillReturnRows(sqlmock.NewRows(nullScanColumns).
			AddRow("plan_null_src", "map_plan", "MAP Plan", nil, "tenant-1", nil, nil, nil,
				"running", 1, 3, now, nil, nil, nil, stepsJSON, nil, metadataJSON, now, now))

	exec, err := repo.GetByPlanID(ctx, "plan_null_src")
	if err != nil {
		t.Fatalf("GetByPlanID() with a NULL source must not error (regression #2778): %v", err)
	}
	if exec.Source != "" {
		t.Errorf("NULL source should scan to empty string, got %q", exec.Source)
	}
}
