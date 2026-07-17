//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// dbRevocationStore reads the user_token_revocations deny-list (enterprise
// mig 135). Rows are written by the customer-portal admin plane
// (mint/rotate/revoke API); this side only reads.
type dbRevocationStore struct {
	db *sql.DB
}

// NewDBRevocationStore builds a RevocationChecker over the shared platform
// database. The table is FORCE-RLS org-isolated, so every query runs inside a
// transaction that sets app.current_org_id for the org being checked.
func NewDBRevocationStore(db *sql.DB) (RevocationChecker, error) {
	if db == nil {
		return nil, fmt.Errorf("identity: nil db for revocation store")
	}
	return &dbRevocationStore{db: db}, nil
}

// IsRevoked reports whether the token identified by (orgID, jti, email,
// issuedAt) is on the deny-list. Two shapes match (see mig 135):
//
//   - a jti row: that exact token was revoked;
//   - a mass-revocation row (user_email + issued_before): every token for
//     that user issued strictly before issued_before is revoked. A token
//     with NO iat claim has issuedAt == zero time and therefore matches any
//     mass revocation for its user — deliberately fail-closed (the mint API
//     always stamps iat; an iat-less token is not one of ours).
//
// Any storage error propagates so the validator fails closed.
func (s *dbRevocationStore) IsRevoked(ctx context.Context, orgID, jti, email string, issuedAt time.Time) (bool, error) {
	res, err := s.CheckRevocation(ctx, orgID, jti, email, issuedAt)
	if err != nil {
		return false, err
	}
	return res.Revoked, nil
}

// CheckRevocation returns the revoked verdict AND the user's current
// mass-revoke watermark in a single round trip (implements
// WatermarkedRevocationChecker for the #2931 hot-path cache). The verdict has
// the exact semantics documented on IsRevoked; the watermark is
// MAX(issued_before) across the user's mass-revocation rows (zero time when the
// user has none), so the cache can invalidate that user's cached not-revoked
// entries the instant it observes a newer mass revocation. Any storage error
// propagates so the caller fails closed.
func (s *dbRevocationStore) CheckRevocation(ctx context.Context, orgID, jti, email string, issuedAt time.Time) (RevocationCheck, error) {
	if orgID == "" {
		return RevocationCheck{}, fmt.Errorf("identity: revocation check requires an org")
	}
	canonEmail := CanonicalEmail(email)
	var (
		revoked   bool
		watermark sql.NullTime
	)
	err := withOrgScope(ctx, s.db, orgID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `
			SELECT
			  EXISTS(
				SELECT 1 FROM user_token_revocations
				WHERE org_id = $1
				  AND (
				        ($2 <> '' AND jti = $2)
				     OR ($3 <> '' AND user_email = $3 AND issued_before > $4)
				  )
			  ) AS revoked,
			  (
				SELECT MAX(issued_before) FROM user_token_revocations
				WHERE org_id = $1 AND $3 <> '' AND user_email = $3
			  ) AS mass_revoke_watermark
		`, orgID, jti, canonEmail, issuedAt).Scan(&revoked, &watermark)
	})
	if err != nil {
		return RevocationCheck{}, fmt.Errorf("identity: revocation lookup failed: %w", err)
	}
	out := RevocationCheck{Revoked: revoked}
	if watermark.Valid {
		out.MassRevokeWatermark = watermark.Time
	}
	return out, nil
}

// withOrgScope runs fn inside a transaction whose first statement pins the
// RLS tenant GUC (app.current_org_id, transaction-scoped). Same contract as
// the customer-portal's withOrgScope (rls_session.go) — duplicated here
// because platform/shared cannot import the ee portal module.
func withOrgScope(ctx context.Context, db *sql.DB, orgID string, fn func(*sql.Tx) error) error {
	if orgID == "" {
		return fmt.Errorf("identity: withOrgScope requires a non-empty org id")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("identity: begin org-scoped tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.current_org_id', $1, true)`, orgID); err != nil {
		return fmt.Errorf("identity: set org scope: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}
