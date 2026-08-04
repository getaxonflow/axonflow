// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package euaiact

import (
	"context"
	"database/sql/driver"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

// NULL-scan regression for #3243.
//
// Reproduced against a live enterprise stack while building the compliance page
// (epic #2892): GET /api/v1/euaiact/conformity answered
//
//	500 {"error":"sql: Scan error on column index 19, name \"submitted_by\":
//	     converting NULL to string is unsupported"}
//
// migration 116 declares submitted_by / approved_by / rejected_by /
// rejection_reason nullable; the struct declares them as plain strings; all
// three read paths scanned straight into them, so ONE such row failed the
// WHOLE list, not just itself.
//
// Stated precisely, because the first draft of this comment overclaimed:
// PostgresConformityRepository.Create passes the Go strings, so a row created
// through the API carries '' and is safe. NULL arrives from any other writer -
// a seed, a backfill, a migration, a direct INSERT - which is how it was hit.
// The sibling cases below are worse: euaiact_exports.file_path/.error are
// written through nullString() by Create, so the API itself produces NULLs.
//
// The existing sqlmock fixtures could not catch it: sampleConformityRow and
// sampleAlertRow pass "" for those columns, not nil, so they exercise the
// post-parse shape rather than the path. The rows below pass nil, which is what
// the driver hands database/sql for a real NULL.
//
// Same class in two sibling repositories, both on routes the portal calls:
// euaiact_exports.file_path / .error (a queued export has neither) and
// euaiact_accuracy_alerts.metric_type / .bias_category / .acked_by /
// .resolved_by (an unacknowledged alert has none). MAS FEAT already scanned
// these through sql.NullString; euaiact was missed.

// nullConformityRow is sampleConformityRow with the four nullable workflow
// columns actually NULL.
func nullConformityRow(id, orgID string) []driver.Value {
	now := time.Now().UTC()
	return []driver.Value{
		id, orgID, "sys-001", "Credit Scoring System",
		string(RiskCategoryHighRisk), string(AssessmentStatusDraft), 1,
		now, nil,
		[]byte(`["assessor1@example.com"]`),
		[]byte(`[]`), []byte(`[]`), []byte(`[]`), []byte(`{}`), []byte(`[]`),
		"creator@example.com", now, now,
		nil, nil, // submitted_at, submitted_by
		nil, nil, // approved_at, approved_by
		nil, nil, nil, // rejected_at, rejected_by, rejection_reason
	}
}

func TestConformityRepository_GetByID_ToleratesNullWorkflowColumns(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	// #3241 wrapped conformity and export reads in rls.WithOrgScope, which
	// BEGINs a transaction and issues set_config('app.current_org_id', ...) as
	// its first statement. sqlmock is strict about order, so the transaction is
	// expected here. Nothing about what this test proves changes: the NULL
	// columns still have to scan. (The accuracy tests below are untouched -
	// accuracy_repository.go is not wrapped.)
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`set_config`)).WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(`FROM euaiact_conformity_assessments`)).
		WithArgs("assess-draft", "org-001").
		WillReturnRows(sqlmock.NewRows(conformityColumns).AddRow(nullConformityRow("assess-draft", "org-001")...))

	mock.ExpectCommit()
	got, err := NewPostgresConformityRepository(db).GetByID(context.Background(), "org-001", "assess-draft")
	require.NoError(t, err, "a DRAFT assessment must read back, not 500 the endpoint")
	require.NotNil(t, got)
	require.Equal(t, "", got.SubmittedBy)
	require.Equal(t, "", got.ApprovedBy)
	require.Equal(t, "", got.RejectedBy)
	require.Equal(t, "", got.RejectionReason)
}

func TestConformityRepository_List_ToleratesNullWorkflowColumns(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	// #3241 wrapped conformity and export reads in rls.WithOrgScope, which
	// BEGINs a transaction and issues set_config('app.current_org_id', ...) as
	// its first statement. sqlmock is strict about order, so the transaction is
	// expected here. Nothing about what this test proves changes: the NULL
	// columns still have to scan. (The accuracy tests below are untouched -
	// accuracy_repository.go is not wrapped.)
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`set_config`)).WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT COUNT(*)`)).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))
	mock.ExpectQuery(regexp.QuoteMeta(`FROM euaiact_conformity_assessments`)).
		WillReturnRows(sqlmock.NewRows(conformityColumns).
			AddRow(nullConformityRow("assess-draft-1", "org-001")...).
			AddRow(nullConformityRow("assess-draft-2", "org-001")...))

	mock.ExpectCommit()
	got, total, err := NewPostgresConformityRepository(db).List(context.Background(), "org-001", "", 50, 0)
	require.NoError(t, err, "a list containing a DRAFT assessment must not fail the whole read")
	require.Equal(t, int64(2), total)
	require.Len(t, got, 2)
}

func TestConformityRepository_GetBySystemID_ToleratesNullWorkflowColumns(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	// #3241 wrapped conformity and export reads in rls.WithOrgScope, which
	// BEGINs a transaction and issues set_config('app.current_org_id', ...) as
	// its first statement. sqlmock is strict about order, so the transaction is
	// expected here. Nothing about what this test proves changes: the NULL
	// columns still have to scan. (The accuracy tests below are untouched -
	// accuracy_repository.go is not wrapped.)
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`set_config`)).WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(`FROM euaiact_conformity_assessments`)).
		WithArgs("org-001", "sys-001").
		WillReturnRows(sqlmock.NewRows(conformityColumns).
			AddRow(nullConformityRow("assess-draft", "org-001")...))

	mock.ExpectCommit()
	got, err := NewPostgresConformityRepository(db).GetBySystemID(context.Background(), "org-001", "sys-001")
	require.NoError(t, err)
	require.Len(t, got, 1)
}

// nullExportRow is a QUEUED export: no file yet and no error yet.
func nullExportRow(id, orgID string) []driver.Value {
	now := time.Now().UTC()
	return []driver.Value{
		id, orgID, string(ExportTypeFullAudit), string(ExportFormatJSON),
		string(ExportStatusPending), 0,
		nil, nil, nil, // file_path, file_size, record_count all NULL
		nil, nil,
		pq.StringArray{},
		[]byte(`{}`),
		nil, "admin@example.com", now, // error NULL
		nil, nil,
		nil, nil, nil,
	}
}

func TestExportRepository_GetByID_ToleratesNullFilePathAndError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	// #3241 wrapped conformity and export reads in rls.WithOrgScope, which
	// BEGINs a transaction and issues set_config('app.current_org_id', ...) as
	// its first statement. sqlmock is strict about order, so the transaction is
	// expected here. Nothing about what this test proves changes: the NULL
	// columns still have to scan. (The accuracy tests below are untouched -
	// accuracy_repository.go is not wrapped.)
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`set_config`)).WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(`FROM euaiact_exports`)).
		WithArgs("exp-queued", "org-001").
		WillReturnRows(sqlmock.NewRows(exportColumns).AddRow(nullExportRow("exp-queued", "org-001")...))

	mock.ExpectCommit()
	got, err := NewPostgresExportRepository(db).GetByID(context.Background(), "org-001", "exp-queued")
	require.NoError(t, err, "a QUEUED export has no file and no error; it must still read back")
	require.NotNil(t, got)
	require.Equal(t, "", got.FilePath)
	require.Equal(t, "", got.Error)
	require.Equal(t, int64(0), got.FileSize)
	require.Equal(t, 0, got.RecordCount)
}

func TestExportRepository_List_ToleratesNullFilePathAndError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	// #3241 wrapped conformity and export reads in rls.WithOrgScope, which
	// BEGINs a transaction and issues set_config('app.current_org_id', ...) as
	// its first statement. sqlmock is strict about order, so the transaction is
	// expected here. Nothing about what this test proves changes: the NULL
	// columns still have to scan. (The accuracy tests below are untouched -
	// accuracy_repository.go is not wrapped.)
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`set_config`)).WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT COUNT(*)`)).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery(regexp.QuoteMeta(`FROM euaiact_exports`)).
		WillReturnRows(sqlmock.NewRows(exportColumns).AddRow(nullExportRow("exp-queued", "org-001")...))

	mock.ExpectCommit()
	got, total, err := NewPostgresExportRepository(db).List(context.Background(), "org-001", 50, 0)
	require.NoError(t, err)
	require.Equal(t, int64(1), total)
	require.Len(t, got, 1)
}

// nullAlertRow is a freshly raised accuracy alert: no bias category (that is a
// bias alert's field), never acknowledged, never resolved.
func nullAlertRow(id, orgID, modelID string) []driver.Value {
	now := time.Now().UTC()
	return []driver.Value{
		id, orgID, modelID, "accuracy_degradation", string(AlertSeverityCritical),
		"Accuracy below threshold", "Model accuracy dropped to 0.72",
		nil, nil, 0.72, 0.80, now,
		nil, nil, nil, nil,
	}
}

func TestAccuracyRepository_GetActiveAlerts_ToleratesNullColumns(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectQuery(regexp.QuoteMeta(`FROM euaiact_accuracy_alerts`)).
		WillReturnRows(sqlmock.NewRows(alertColumns).AddRow(nullAlertRow("alert-1", "org-001", "model-1")...))

	got, err := NewPostgresAccuracyRepository(db).GetActiveAlerts(context.Background(), "org-001")
	require.NoError(t, err, "an unacknowledged alert must not fail the alert list")
	require.Len(t, got, 1)
	require.Equal(t, "", got[0].AckedBy)
	require.Equal(t, "", got[0].ResolvedBy)
	require.Equal(t, MetricType(""), got[0].MetricType)
	require.Equal(t, BiasCategory(""), got[0].BiasCategory)
}

func TestAccuracyRepository_GetAlertByID_ToleratesNullColumns(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectQuery(regexp.QuoteMeta(`FROM euaiact_accuracy_alerts`)).
		WithArgs("alert-1").
		WillReturnRows(sqlmock.NewRows(alertColumns).AddRow(nullAlertRow("alert-1", "org-001", "model-1")...))

	got, err := NewPostgresAccuracyRepository(db).GetAlertByID(context.Background(), "alert-1")
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, "", got.AckedBy)
}

// nullMetricRow is a measurement recorded without a window or a sample size:
// migration 116 permits all three, verified against a live database.
func nullMetricRow(id, orgID, modelID string) []driver.Value {
	now := time.Now().UTC()
	return []driver.Value{
		id, orgID, modelID, string(MetricTypeAccuracy), 0.95, nil,
		now, nil, nil, []byte(`{}`),
	}
}

func TestAccuracyRepository_GetMetrics_ToleratesNullWindowAndSampleSize(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT COUNT(*)`)).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery(regexp.QuoteMeta(`FROM euaiact_accuracy_metrics`)).
		WillReturnRows(sqlmock.NewRows(metricColumns).AddRow(nullMetricRow("m-1", "org-001", "model-1")...))

	got, total, err := NewPostgresAccuracyRepository(db).
		GetMetrics(context.Background(), "org-001", "model-1", MetricTypeAccuracy, time.Time{}, time.Now(), 50, 0)
	require.NoError(t, err, "a metric with no measurement window must not fail the whole list")
	require.Equal(t, int64(1), total)
	require.Len(t, got, 1)
	require.Equal(t, 0, got[0].SampleSize)
	require.True(t, got[0].WindowStart.IsZero())
}

func TestAccuracyRepository_GetLatestMetric_ToleratesNullWindowAndSampleSize(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectQuery(regexp.QuoteMeta(`FROM euaiact_accuracy_metrics`)).
		WillReturnRows(sqlmock.NewRows(metricColumns).AddRow(nullMetricRow("m-1", "org-001", "model-1")...))

	got, err := NewPostgresAccuracyRepository(db).
		GetLatestMetric(context.Background(), "org-001", "model-1", MetricTypeAccuracy)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, 0, got.SampleSize)
}

// nullBiasRow is a bias measurement with no window and no sample size.
func nullBiasRow(id, orgID, modelID string) []driver.Value {
	now := time.Now().UTC()
	return []driver.Value{
		id, orgID, modelID, string(BiasCategoryGender), 0.12, 0.10, true,
		nil, "group-a", "group-b", 0.8, 0.7,
		now, nil, nil, []byte(`{}`),
	}
}

func TestAccuracyRepository_GetBiasRecords_ToleratesNullWindowAndSampleSize(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectQuery(regexp.QuoteMeta(`FROM euaiact_bias_records`)).
		WillReturnRows(sqlmock.NewRows(biasColumns).AddRow(nullBiasRow("b-1", "org-001", "model-1")...))

	got, err := NewPostgresAccuracyRepository(db).
		GetBiasRecords(context.Background(), "org-001", "model-1", BiasCategoryGender, time.Time{}, time.Now())
	require.NoError(t, err, "a bias record with no measurement window must not fail the whole list")
	require.Len(t, got, 1)
	require.Equal(t, 0, got[0].SampleSize)
	require.True(t, got[0].WindowEnd.IsZero())
}
