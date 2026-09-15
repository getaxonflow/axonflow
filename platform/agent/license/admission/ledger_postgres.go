// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package admission

import (
	"context"
	"database/sql"
	"fmt"
	"hash/fnv"
	"strings"

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

// AdmitAllUnderLimit is the atomic BATCH step: every new key or none of them.
//
// It is the same transaction shape as AdmitUnderLimit - one advisory lock on
// (org, dimension), then count, then write - and it exists because doing that
// once per key cannot be all-or-nothing however carefully it is driven. Between
// two single admissions the count moves, so a document refused at the ceiling
// has already spent the slots for the policies before the boundary (#3973).
//
// THE LOCK IS TAKEN ON THE PAIR, so a mixed batch would need more than one and
// would not be atomic in the way the caller is being promised. Mixed input is
// therefore refused rather than split.
func (l *PostgresLedger) AdmitAllUnderLimit(ctx context.Context, keys []Key, limit int, licenceFingerprint string) (BatchOutcome, error) {
	if l == nil || l.db == nil {
		return BatchOutcome{}, fmt.Errorf("admission ledger: no database")
	}
	if limit < 0 {
		return BatchOutcome{}, fmt.Errorf("admission ledger: AdmitAllUnderLimit called with the unlimited sentinel %d; Admit must short-circuit before the ledger", limit)
	}
	if len(keys) == 0 {
		return BatchOutcome{}, nil
	}
	org, dim := keys[0].OrgID, keys[0].Dimension
	for _, k := range keys {
		if k.OrgID != org || k.Dimension != dim {
			return BatchOutcome{}, fmt.Errorf(
				"admission ledger: a batch must share one (org, dimension); got %q/%s beside %q/%s",
				k.OrgID, k.Dimension, org, dim)
		}
		if strings.TrimSpace(k.PrincipalID) == "" {
			return BatchOutcome{}, fmt.Errorf("admission ledger: a batch key has an empty principal id")
		}
	}
	var out BatchOutcome
	err := rls.WithOrgScope(ctx, l.db, org, func(tx *sql.Tx) error {
		out = BatchOutcome{}
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, lockKey(Key{OrgID: org, Dimension: dim})); err != nil {
			return fmt.Errorf("advisory lock: %w", err)
		}
		if err := tx.QueryRowContext(ctx,
			`SELECT count(*) FROM principal_admissions WHERE org_id = $1 AND dimension = $2`,
			org, string(dim)).Scan(&out.Count); err != nil {
			return fmt.Errorf("count: %w", err)
		}
		// WHICH KEYS ARE NEW IS READ INSIDE THE LOCK, because a key that exists
		// costs nothing and one that does not costs a slot - and that is exactly
		// what a concurrent admission changes. Duplicates within the batch are
		// folded here too: a document naming the same policy id twice is one
		// admission, not two, and would otherwise consume two slots for one row.
		room := limit - out.Count
		seenInBatch := make(map[string]bool, len(keys))
		newKeys := make([]Key, 0, len(keys))
		for _, k := range keys {
			if seenInBatch[k.PrincipalID] {
				continue
			}
			seenInBatch[k.PrincipalID] = true
			var exists bool
			if err := tx.QueryRowContext(ctx,
				`SELECT EXISTS (SELECT 1 FROM principal_admissions WHERE org_id = $1 AND dimension = $2 AND principal_id = $3)`,
				k.OrgID, string(k.Dimension), k.PrincipalID).Scan(&exists); err != nil {
				return fmt.Errorf("exists: %w", err)
			}
			if exists {
				out.Existing++
				continue
			}
			newKeys = append(newKeys, k)
			if len(newKeys) > room {
				// REFUSED, AND NOTHING IS WRITTEN. The transaction has made no
				// change yet, so returning here leaves the ledger exactly as the
				// caller found it.
				out.Overflow = k
				out.Admitted = 0
				return nil
			}
		}
		for _, k := range newKeys {
			res, err := tx.ExecContext(ctx,
				`INSERT INTO principal_admissions (org_id, dimension, principal_id, licence_fingerprint)
				 VALUES ($1, $2, $3, $4) ON CONFLICT (org_id, dimension, principal_id) DO NOTHING`,
				k.OrgID, string(k.Dimension), k.PrincipalID, licenceFingerprint)
			if err != nil {
				return fmt.Errorf("insert: %w", err)
			}
			if n, _ := res.RowsAffected(); n == 1 {
				out.Admitted++
			} else {
				out.Existing++
			}
		}
		return nil
	})
	if err != nil {
		return BatchOutcome{}, fmt.Errorf("admission ledger: admit all: %w", err)
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
