// Copyright 2026 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package rbi

import (
	"context"
	"strings"
	"testing"
)

// #3246(a): a board report with a NULL counter 500s the RBI board-report
// endpoints.
//
// migrations/industry/banking/301 declares the counters nullable with no
// default:
//
//	total_ai_systems INTEGER,
//	average_resolution_time_hours DECIMAL(10, 2),
//	compliance_score DECIMAL(5, 2),
//	...
//
// and both scan paths read them into plain int / float64 / int64. database/sql
// then returns `converting NULL to int is unsupported`, and since the list
// handler returns on the first scan error, ONE such row takes out the whole
// list for the organization.
//
// Both scan paths are exercised, because they are near-duplicates that have
// drifted before: Get() goes through scanBoardReport (*sql.Row) and List()
// through scanBoardReportRows (*sql.Rows). A fix applied to one only is exactly
// the shape this repository has produced before.

const nullCounterOrg = "org-null-counters"

func TestBoardReport_NullCounters_BothScanPaths(t *testing.T) {
	db := applyRBISchema(t)
	ctx := context.Background()

	if _, err := db.Exec(`
		INSERT INTO organizations (org_id, name, tier, license_key, created_at, updated_at)
		VALUES ($1, 'Null Counter Bank', 'enterprise', 'test-license-key', NOW(), NOW())
		ON CONFLICT (org_id) DO NOTHING`, nullCounterOrg); err != nil {
		t.Fatalf("seed org: %v", err)
	}

	// EXPLICIT NULLs, not omission (#3241 round 2, R3 finding 22).
	//
	// The first version of this test named only the NOT NULL columns and let
	// the rest default. That does not produce a NULL for any column carrying a
	// DEFAULT - `kill_switch_activations INTEGER DEFAULT 0`, `generated_at
	// TIMESTAMPTZ DEFAULT NOW()`, `approval_status VARCHAR(20) DEFAULT
	// 'draft'`, `created_at`, `updated_at` - so five of the sixteen assertions
	// below were checking a defaulted value against zero and could never have
	// failed. Writing the NULL explicitly is what a partial `INSERT ... SELECT`
	// or a backfill does, and it is the only way this test sees the columns it
	// claims to cover.
	// The PK is a uuid column, so the ids are real UUIDs.
	const id = "11111111-1111-4111-8111-111111111111"
	if _, err := db.Exec(`
		INSERT INTO rbi_board_reports
			(id, org_id, report_type,
			 total_ai_systems, new_systems_deployed, systems_deprecated,
			 total_validations, overdue_validations,
			 total_incidents, incidents_resolved, incidents_open,
			 average_resolution_time_hours, compliance_score, kill_switch_activations,
			 file_size_bytes, generated_at, approval_status, created_at, updated_at)
		VALUES ($1, $2, 'quarterly',
			 NULL, NULL, NULL,
			 NULL, NULL,
			 NULL, NULL, NULL,
			 NULL, NULL, NULL,
			 NULL, NULL, NULL, NULL, NULL)`, id, nullCounterOrg); err != nil {
		t.Fatalf("seed board report with NULL counters: %v", err)
	}

	// The fixture must really be NULL. A column that silently took a DEFAULT
	// would make its assertion below vacuous, which is exactly what the first
	// version of this test did for five of them.
	var nullCount int
	if err := db.QueryRow(`
		SELECT (total_ai_systems IS NULL)::int + (new_systems_deployed IS NULL)::int
		     + (systems_deprecated IS NULL)::int + (total_validations IS NULL)::int
		     + (overdue_validations IS NULL)::int + (total_incidents IS NULL)::int
		     + (incidents_resolved IS NULL)::int + (incidents_open IS NULL)::int
		     + (average_resolution_time_hours IS NULL)::int + (compliance_score IS NULL)::int
		     + (kill_switch_activations IS NULL)::int + (file_size_bytes IS NULL)::int
		     + (generated_at IS NULL)::int + (approval_status IS NULL)::int
		     + (created_at IS NULL)::int + (updated_at IS NULL)::int
		FROM rbi_board_reports WHERE id = $1`, id).Scan(&nullCount); err != nil {
		t.Fatalf("verify the NULL fixture: %v", err)
	}
	if nullCount != 16 {
		t.Fatalf("only %d of 16 columns are actually NULL - the rest took a DEFAULT and their "+
			"assertions below would be vacuous", nullCount)
	}

	repo := NewPostgresBoardReportRepository(db)

	t.Run("Get (scanBoardReport, *sql.Row)", func(t *testing.T) {
		rep, err := repo.Get(ctx, nullCounterOrg, id)
		if err != nil {
			if strings.Contains(err.Error(), "converting NULL") {
				t.Fatalf("#3246 reproduced on the Get path: %v", err)
			}
			t.Fatalf("Get: %v", err)
		}
		assertZeroCounters(t, rep)
	})

	t.Run("List (scanBoardReportRows, *sql.Rows)", func(t *testing.T) {
		reports, total, err := repo.List(ctx, nullCounterOrg, &ListBoardReportsParams{Limit: 10})
		if err != nil {
			if strings.Contains(err.Error(), "converting NULL") {
				t.Fatalf("#3246 reproduced on the List path - ONE row with a NULL counter takes out "+
					"the whole list for this organization: %v", err)
			}
			t.Fatalf("List: %v", err)
		}
		if total == 0 || len(reports) == 0 {
			t.Fatal("the seeded report is not in the list - this test would pass vacuously")
		}
		var found bool
		for _, rep := range reports {
			if rep.ID == id {
				found = true
				assertZeroCounters(t, rep)
			}
		}
		if !found {
			t.Fatalf("the seeded report %q is missing from a list of %d", id, len(reports))
		}
	})

	// CONTROL: a report with REAL counters must still read them back. Without
	// this, an implementation that returned zeros unconditionally would satisfy
	// everything above.
	t.Run("control: populated counters survive", func(t *testing.T) {
		const id2 = "22222222-2222-4222-8222-222222222222"
		if _, err := db.Exec(`
			INSERT INTO rbi_board_reports
				(id, org_id, report_type, generated_at, approval_status,
				 total_ai_systems, total_incidents, compliance_score,
				 average_resolution_time_hours, file_size_bytes, created_at, updated_at)
			VALUES ($1, $2, 'quarterly', NOW(), 'draft', 7, 3, 88.5, 12.25, 4096, NOW(), NOW())`,
			id2, nullCounterOrg); err != nil {
			t.Fatalf("seed populated report: %v", err)
		}

		rep, err := repo.Get(ctx, nullCounterOrg, id2)
		if err != nil {
			t.Fatalf("Get populated: %v", err)
		}
		if rep.TotalAISystems != 7 || rep.TotalIncidents != 3 {
			t.Errorf("int counters: got systems=%d incidents=%d, want 7/3", rep.TotalAISystems, rep.TotalIncidents)
		}
		if rep.ComplianceScore != 88.5 || rep.AverageResolutionTimeHours != 12.25 {
			t.Errorf("float counters: got score=%v avg=%v, want 88.5/12.25",
				rep.ComplianceScore, rep.AverageResolutionTimeHours)
		}
		if rep.FileSizeBytes != 4096 {
			t.Errorf("FileSizeBytes: got %d, want 4096", rep.FileSizeBytes)
		}
	})
}

// assertZeroCounters checks the NULL-to-zero mapping on every counter, so a
// partial fix that covered the two columns someone happened to test is caught.
func assertZeroCounters(t *testing.T, rep *BoardReport) {
	t.Helper()
	if rep == nil {
		t.Fatal("nil report")
	}
	for _, c := range []struct {
		name string
		got  float64
	}{
		{"TotalAISystems", float64(rep.TotalAISystems)},
		{"NewSystemsDeployed", float64(rep.NewSystemsDeployed)},
		{"SystemsDeprecated", float64(rep.SystemsDeprecated)},
		{"TotalValidations", float64(rep.TotalValidations)},
		{"OverdueValidations", float64(rep.OverdueValidations)},
		{"TotalIncidents", float64(rep.TotalIncidents)},
		{"IncidentsResolved", float64(rep.IncidentsResolved)},
		{"IncidentsOpen", float64(rep.IncidentsOpen)},
		{"AverageResolutionTimeHours", rep.AverageResolutionTimeHours},
		{"ComplianceScore", rep.ComplianceScore},
		{"KillSwitchActivations", float64(rep.KillSwitchActivations)},
		{"FileSizeBytes", float64(rep.FileSizeBytes)},
	} {
		if c.got != 0 {
			t.Errorf("%s = %v, want 0 for a NULL column", c.name, c.got)
		}
	}
	// The four non-numeric nullable columns, which the first pass at #3246(a)
	// left scanning into plain time.Time / string.
	if !rep.GeneratedAt.IsZero() {
		t.Errorf("GeneratedAt = %v, want the zero time for a NULL column", rep.GeneratedAt)
	}
	// NOT "": an empty ReportApprovalStatus fails the type's own Valid() and
	// walks straight through DeleteReport's `== ReportApprovalApproved` guard,
	// converting what used to be a loud scan error into a silent delete of a
	// report whose approval state is unknown. NULL maps to the column's
	// DEFAULT.
	if rep.ApprovalStatus != ReportApprovalDraft {
		t.Errorf("ApprovalStatus = %q, want %q (the column DEFAULT) for a NULL column",
			rep.ApprovalStatus, ReportApprovalDraft)
	}
	if !rep.CreatedAt.IsZero() {
		t.Errorf("CreatedAt = %v, want the zero time for a NULL column", rep.CreatedAt)
	}
	if !rep.UpdatedAt.IsZero() {
		t.Errorf("UpdatedAt = %v, want the zero time for a NULL column", rep.UpdatedAt)
	}
}
