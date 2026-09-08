// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package admission

import (
	"context"
	"database/sql"
	"fmt"
	"hash/fnv"

	"axonflow/platform/agent/rls"
)

// PostgresLedger is the Ledger over migrations/core/171's principal_admissions.
//
// Every statement runs inside rls.WithOrgScope for the key's organization:
// the table is FORCE-RLS and the application role sees only rows whose org_id
// equals app.current_org_id. The ledger never sets the scope wider than the
// organization it is admitting for.
type PostgresLedger struct {
	db *sql.DB
}

// NewPostgresLedger wraps an application-role pool.
func NewPostgresLedger(db *sql.DB) *PostgresLedger { return &PostgresLedger{db: db} }

// Exists reports whether the key has a row.
func (l *PostgresLedger) Exists(ctx context.Context, k Key) (bool, error) {
	if l == nil || l.db == nil {
		return false, fmt.Errorf("admission ledger: no database")
	}
	var found bool
	err := rls.WithOrgScope(ctx, l.db, k.OrgID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT EXISTS (SELECT 1 FROM principal_admissions WHERE org_id = $1 AND dimension = $2 AND principal_id = $3)`,
			k.OrgID, string(k.Dimension), k.PrincipalID).Scan(&found)
	})
	if err != nil {
		return false, fmt.Errorf("admission ledger: exists: %w", err)
	}
	return found, nil
}

// AdmitUnderLimit is the atomic step. The transaction takes a per-(org,
// dimension) advisory lock first, so two first-time principals racing at N-1
// serialize: the second sees N and is refused. The count and the insert are
// two statements under that lock rather than one clever statement, because
// the count is also what the refusal reports.
//
// limit < 0 is not a valid call here (Admit returns before the ledger for an
// unlimited tier); it is refused rather than treated as "no limit" so the
// sentinel can never leak into a write path.
func (l *PostgresLedger) AdmitUnderLimit(ctx context.Context, k Key, limit int, licenceFingerprint string) (Outcome, error) {
	if l == nil || l.db == nil {
		return Outcome{}, fmt.Errorf("admission ledger: no database")
	}
	if limit < 0 {
		return Outcome{}, fmt.Errorf("admission ledger: AdmitUnderLimit called with the unlimited sentinel %d; Admit must short-circuit before the ledger", limit)
	}
	var out Outcome
	err := rls.WithOrgScope(ctx, l.db, k.OrgID, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, lockKey(k)); err != nil {
			return fmt.Errorf("advisory lock: %w", err)
		}
		var exists bool
		if err := tx.QueryRowContext(ctx,
			`SELECT EXISTS (SELECT 1 FROM principal_admissions WHERE org_id = $1 AND dimension = $2 AND principal_id = $3)`,
			k.OrgID, string(k.Dimension), k.PrincipalID).Scan(&exists); err != nil {
			return fmt.Errorf("exists: %w", err)
		}
		if err := tx.QueryRowContext(ctx,
			`SELECT count(*) FROM principal_admissions WHERE org_id = $1 AND dimension = $2`,
			k.OrgID, string(k.Dimension)).Scan(&out.Count); err != nil {
			return fmt.Errorf("count: %w", err)
		}
		if exists {
			out.Existing = true
			return nil
		}
		if out.Count >= limit {
			return nil // refused: Admitted and Existing both false
		}
		res, err := tx.ExecContext(ctx,
			`INSERT INTO principal_admissions (org_id, dimension, principal_id, licence_fingerprint)
			 VALUES ($1, $2, $3, $4) ON CONFLICT (org_id, dimension, principal_id) DO NOTHING`,
			k.OrgID, string(k.Dimension), k.PrincipalID, licenceFingerprint)
		if err != nil {
			return fmt.Errorf("insert: %w", err)
		}
		n, _ := res.RowsAffected()
		out.Admitted = n == 1
		out.Existing = n == 0
		return nil
	})
	if err != nil {
		return Outcome{}, fmt.Errorf("admission ledger: admit: %w", err)
	}
	return out, nil
}

// Record inserts the key with no limit check: the telemetry write an
// unlimited tier makes off the request path. ON CONFLICT DO NOTHING, so a
// principal already admitted is not an error and not a second row.
func (l *PostgresLedger) Record(ctx context.Context, k Key, licenceFingerprint string) error {
	if l == nil || l.db == nil {
		return fmt.Errorf("admission ledger: no database")
	}
	err := rls.WithOrgScope(ctx, l.db, k.OrgID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO principal_admissions (org_id, dimension, principal_id, licence_fingerprint)
			 VALUES ($1, $2, $3, $4) ON CONFLICT (org_id, dimension, principal_id) DO NOTHING`,
			k.OrgID, string(k.Dimension), k.PrincipalID, licenceFingerprint)
		return err
	})
	if err != nil {
		return fmt.Errorf("admission ledger: record: %w", err)
	}
	return nil
}

// Recent returns up to n keys for org, newest first.
func (l *PostgresLedger) Recent(ctx context.Context, orgID string, n int) ([]Key, error) {
	if l == nil || l.db == nil {
		return nil, fmt.Errorf("admission ledger: no database")
	}
	if n < 1 {
		return nil, nil
	}
	var keys []Key
	err := rls.WithOrgScope(ctx, l.db, orgID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx,
			`SELECT org_id, dimension, principal_id FROM principal_admissions
			  WHERE org_id = $1 ORDER BY admitted_at DESC LIMIT $2`, orgID, n)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var k Key
			var dim string
			if err := rows.Scan(&k.OrgID, &dim, &k.PrincipalID); err != nil {
				return err
			}
			k.Dimension = Dimension(dim)
			keys = append(keys, k)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("admission ledger: recent: %w", err)
	}
	return keys, nil
}

// lockKey folds (org, dimension) onto the 64-bit advisory lock space. A
// collision between two organizations only serializes them, never admits or
// refuses anything wrongly.
func lockKey(k Key) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte("principal_admissions\x00"))
	_, _ = h.Write([]byte(k.OrgID))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(k.Dimension))
	return int64(h.Sum64())
}
