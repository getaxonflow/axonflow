// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"
)

// The storage half of the once-only override import (PRD v11 §1.5,
// migrations/core/183): reading every organization's rows and recording each
// organization's draft. buildImportRecord, in policy_override_import.go, is the
// pure translation it calls. The two are separate files because this one
// imports no decision package: authoring's activator census reads Promote,
// Rollback and Withdraw by name in files that import authoring, and a
// transaction's Rollback here is not an activation.

// importPolicyOverrideDrafts runs the import at boot, on the owner connection,
// after every migration has applied.
//
// It is never fatal. An organization whose import fails has no record, so the
// next boot tries it again, and nothing any engine enforces depends on it.
func importPolicyOverrideDrafts(db *sql.DB) {
	if db == nil {
		return
	}
	var present bool
	if err := db.QueryRow(
		`SELECT to_regprocedure('public.typed_policy_import_candidates()') IS NOT NULL`,
	).Scan(&present); err != nil {
		log.Printf("❌ Per-policy override import skipped: checking for migrations/core/183 failed: %v", err)
		return
	}
	if !present {
		log.Printf("ℹ️  Per-policy override import skipped: schema predates migrations/core/183")
		return
	}
	written, recorded, err := runPolicyOverrideImport(context.Background(), db, time.Now().UTC())
	if err != nil {
		log.Printf("❌ Per-policy override import (PRD v11 §1.5): %d organization(s) recorded now, %d already; "+
			"the rest are tried again at the next boot: %v", written, recorded, err)
		return
	}
	log.Printf("✅ Per-policy override import (PRD v11 §1.5): %d organization(s) recorded now, %d already", written, recorded)
}

// runPolicyOverrideImport records, for every organization with a
// policy_overrides row and no record yet, what its rows import to. Each
// organization is written in its own transaction with the organization set,
// because typed_policy_import_drafts forces row-level security on its owner
// too, and a failure for one does not stop the others.
func runPolicyOverrideImport(ctx context.Context, db *sql.DB, now time.Time) (written, recorded int, err error) {
	byOrg, orgs, err := readImportCandidates(ctx, db)
	if err != nil {
		return 0, 0, err
	}
	var failed []error
	for _, org := range orgs {
		wrote, err := recordOrganizationImport(ctx, db, org, byOrg[org], now)
		switch {
		case err != nil:
			failed = append(failed, fmt.Errorf("organization %s: %w", org, err))
		case wrote:
			written++
		default:
			recorded++
		}
	}
	return written, recorded, errors.Join(failed...)
}

func readImportCandidates(ctx context.Context, db *sql.DB) (map[string][]importCandidate, []string, error) {
	rows, err := db.QueryContext(ctx, `SELECT override_id, org_id, tenant_id, policy_table, policy_id,
		enabled_override, action_override, revoked, expired, break_glass FROM typed_policy_import_candidates()`)
	if err != nil {
		return nil, nil, fmt.Errorf("reading the override rows: %w", err)
	}
	defer func() { _ = rows.Close() }()
	byOrg := map[string][]importCandidate{}
	var orgs []string
	for rows.Next() {
		var org string
		var c importCandidate
		if err := rows.Scan(&c.OverrideID, &org, &c.TenantID, &c.PolicyTable, &c.PolicyID,
			&c.Enabled, &c.Action, &c.Revoked, &c.Expired, &c.BreakGlass); err != nil {
			return nil, nil, fmt.Errorf("reading an override row: %w", err)
		}
		if _, seen := byOrg[org]; !seen {
			orgs = append(orgs, org)
		}
		byOrg[org] = append(byOrg[org], c)
	}
	return byOrg, orgs, rows.Err()
}

// recordOrganizationImport writes one organization's record unless it has one,
// and reports whether it wrote it.
func recordOrganizationImport(ctx context.Context, db *sql.DB, org string, rows []importCandidate, now time.Time) (bool, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.current_org_id', $1, true)`, org); err != nil {
		return false, err
	}
	var exists bool
	if err := tx.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM typed_policy_import_drafts WHERE org_id = $1)`, org).Scan(&exists); err != nil {
		return false, err
	}
	if exists {
		return false, tx.Commit()
	}
	rec, err := buildImportRecord(rows)
	if err != nil {
		return false, err
	}
	skipped, err := json.Marshal(rec.Skipped)
	if err != nil {
		return false, err
	}
	var draft, digest any
	if rec.Draft != nil {
		draft, digest = string(rec.Draft), rec.DraftDigest
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO typed_policy_import_drafts
		(org_id, imported_at, actor, source_row_count, imported_count, skipped, draft, draft_digest)
		VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8)
		ON CONFLICT (org_id) DO NOTHING`,
		org, now, policyOverrideImportActor, rec.SourceRows, rec.Imported, string(skipped), draft, digest)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, tx.Commit()
}
