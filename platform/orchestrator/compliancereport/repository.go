// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build enterprise

package compliancereport

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"axonflow/platform/agent/rls"
	"axonflow/platform/shared/tenantscope"
)

// ErrJobNotFound is returned when no job matches the id WITHIN the caller's
// org. It is deliberately indistinguishable from "this id does not exist at
// all": handlers map it to 404 so the endpoint cannot be used as a cross-org
// existence oracle (tenantscope.ErrNotOwned carries the same instruction).
var ErrJobNotFound = errors.New("compliancereport: report job not found")

// Repository persists report jobs.
type Repository interface {
	Create(ctx context.Context, job *ReportJob) error
	// GetByID returns the job with the given id OWNED BY scope.OrgID.
	// The org predicate is IN THE SQL, not applied after the fetch: a
	// post-fetch comparison is the fail-open shape #3065 catalogued.
	GetByID(ctx context.Context, scope tenantscope.Scope, id string) (*ReportJob, error)
	// Update persists the mutable lifecycle fields of an existing job. The
	// org predicate is in the WHERE clause here too, so a job can never be
	// mutated out from under another org even by a bug in the caller.
	Update(ctx context.Context, job *ReportJob) error
	// CountSince counts jobs created by an org since t.
	//
	// This is the DURABLE half of the daily budget (Service.usedToday). The
	// in-process counter alone resets on every restart, so without this a
	// rolling deploy handed a tenant a fresh budget and N replicas multiplied
	// it by N.
	CountSince(ctx context.Context, orgID string, since time.Time) (int, error)
}

// PostgresRepository is the Postgres implementation.
//
// EVERY statement runs inside rls.WithOrgScope: compliance_report_jobs is
// RLS-enabled by migration enterprise/136 and the orchestrator's pool connects
// as axonflow_app_role, so an unwrapped statement reads zero rows and writes
// are refused. That is the #3039 blind-read class; wrapping is not optional.
type PostgresRepository struct {
	db *sql.DB
}

// NewPostgresRepository creates a Postgres-backed repository.
func NewPostgresRepository(db *sql.DB) *PostgresRepository {
	return &PostgresRepository{db: db}
}

const jobColumns = `id, org_id, tenant_id, regulator, framework, format,
	period_start, period_end, status, report_state, progress, record_count,
	size_bytes, storage_key, checksum, error, requested_by,
	created_at, started_at, completed_at`

// Create inserts a new job. It refuses to persist a row with a missing tenancy
// key rather than letting the migration's CHECK constraint produce an opaque
// driver error — the application-layer half of the same invariant.
func (r *PostgresRepository) Create(ctx context.Context, job *ReportJob) error {
	if r == nil || r.db == nil {
		return fmt.Errorf("compliancereport: repository has no database handle")
	}
	if err := tenantscope.ValidateRowKeys(job.OrgID, job.TenantID); err != nil {
		return fmt.Errorf("compliancereport: refusing to persist an unowned job: %w", err)
	}
	const q = `
		INSERT INTO compliance_report_jobs (` + jobColumns + `)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`

	return rls.WithOrgScope(ctx, r.db, job.OrgID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, q,
			job.ID, job.OrgID, job.TenantID, string(job.Regulator), string(job.Framework), string(job.Format),
			job.PeriodStart, job.PeriodEnd, string(job.Status), string(job.ReportState), job.Progress, job.RecordCount,
			job.SizeBytes, job.StorageKey, job.Checksum, job.Error, job.RequestedBy,
			job.CreatedAt, job.StartedAt, job.CompletedAt,
		)
		return err
	})
}

// GetByID reads one job inside the caller's org scope.
func (r *PostgresRepository) GetByID(ctx context.Context, scope tenantscope.Scope, id string) (*ReportJob, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("compliancereport: repository has no database handle")
	}
	if !scope.Bound() {
		// Never degrade to an unscoped read. rls.WithOrgScope would reject an
		// empty org anyway; refusing here names the cause.
		return nil, tenantscope.ErrNoCallerScope
	}
	const q = `SELECT ` + jobColumns + ` FROM compliance_report_jobs WHERE id = $1 AND org_id = $2`

	var job *ReportJob
	err := rls.WithOrgScope(ctx, r.db, scope.OrgID, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, q, id, scope.OrgID)
		j, scanErr := scanJob(row)
		if scanErr != nil {
			return scanErr
		}
		job = j
		return nil
	})
	if errors.Is(err, ErrJobNotFound) {
		return nil, ErrJobNotFound
	}
	if err != nil {
		return nil, err
	}
	return job, nil
}

// Update writes the mutable lifecycle fields.
func (r *PostgresRepository) Update(ctx context.Context, job *ReportJob) error {
	if r == nil || r.db == nil {
		return fmt.Errorf("compliancereport: repository has no database handle")
	}
	if err := tenantscope.ValidateRowKeys(job.OrgID, job.TenantID); err != nil {
		return fmt.Errorf("compliancereport: refusing to update an unowned job: %w", err)
	}
	// BOTH tenancy keys are in the predicate.
	//
	// The org predicate is the security boundary and is what RLS also enforces.
	// tenant_id is added for a different reason: this is a blind write - the
	// caller hands in a whole ReportJob and every mutable field is overwritten
	// - and the row's tenancy is NOT among the columns being set. So without
	// it, a job whose TenantID had been altered in memory would still update
	// the stored row, writing one tenancy's lifecycle state onto another's
	// record while every field that could reveal it stayed put.
	//
	// It costs nothing (id is the primary key; this is a predicate on a row
	// already located) and it makes the zero-row check below meaningful in the
	// tenant dimension too, rather than only the org one. The asymmetry was
	// deliberate on GetByID - the SERVICE checks tenancy there through
	// tenantscope.Authorize, which returns 404-not-403 to avoid an existence
	// oracle - but a write has no such second gate.
	const q = `
		UPDATE compliance_report_jobs
		SET status = $1, report_state = $2, progress = $3, record_count = $4,
		    size_bytes = $5, storage_key = $6, checksum = $7, error = $8,
		    started_at = $9, completed_at = $10
		WHERE id = $11 AND org_id = $12 AND tenant_id = $13`

	return rls.WithOrgScope(ctx, r.db, job.OrgID, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, q,
			string(job.Status), string(job.ReportState), job.Progress, job.RecordCount,
			job.SizeBytes, job.StorageKey, job.Checksum, job.Error,
			job.StartedAt, job.CompletedAt,
			job.ID, job.OrgID, job.TenantID,
		)
		if err != nil {
			return err
		}
		// A zero-row UPDATE means the job is gone, or belongs to another org
		// or another tenancy.
		// Silently succeeding there would let the async processor believe it
		// had recorded a terminal state it never recorded.
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrJobNotFound
		}
		return nil
	})
}

// CountSince counts an org's jobs created at or after t.
func (r *PostgresRepository) CountSince(ctx context.Context, orgID string, since time.Time) (int, error) {
	if r == nil || r.db == nil {
		return 0, fmt.Errorf("compliancereport: repository has no database handle")
	}
	if orgID == "" {
		return 0, tenantscope.ErrNoCallerScope
	}
	const q = `SELECT COUNT(*) FROM compliance_report_jobs WHERE org_id = $1 AND created_at >= $2`
	var n int
	err := rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, q, orgID, since).Scan(&n)
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}

// rowScanner is satisfied by both *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...interface{}) error
}

func scanJob(row rowScanner) (*ReportJob, error) {
	var (
		job                           ReportJob
		regulator, framework, format  string
		status, reportState           string
		storageKey, checksum, errText sql.NullString
		requestedBy                   sql.NullString
		startedAt, completedAt        sql.NullTime
	)
	err := row.Scan(
		&job.ID, &job.OrgID, &job.TenantID, &regulator, &framework, &format,
		&job.PeriodStart, &job.PeriodEnd, &status, &reportState, &job.Progress, &job.RecordCount,
		&job.SizeBytes, &storageKey, &checksum, &errText, &requestedBy,
		&job.CreatedAt, &startedAt, &completedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrJobNotFound
	}
	if err != nil {
		return nil, err
	}
	job.Regulator = Regulator(regulator)
	job.Framework = Framework(framework)
	job.Format = Format(format)
	job.Status = Status(status)
	job.ReportState = ReportState(reportState)
	job.StorageKey = storageKey.String
	job.Checksum = checksum.String
	job.Error = errText.String
	job.RequestedBy = requestedBy.String
	if startedAt.Valid {
		t := startedAt.Time
		job.StartedAt = &t
	}
	if completedAt.Valid {
		t := completedAt.Time
		job.CompletedAt = &t
	}
	return &job, nil
}
