// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package rls hosts the transaction-scoped org_id wrap helper used by every
// agent + orchestrator + customer-portal handler that writes into an RLS-gated
// table. Lives in its own leaf package so packages anywhere in the import
// graph — including platform/orchestrator/llm (consumed by platform/agent
// via the cost package) — can import the wrap without dragging the rest of
// platform/agent in. Mirrors the docstring on platform/agent.WithOrgScope.
package rls

import (
	"context"
	"database/sql"
	"fmt"
)

// WithOrgScope runs fn inside a transaction whose first statement is
// SELECT set_config('app.current_org_id', orgID, true). The session variable
// is bounded to the transaction — automatically cleared by COMMIT/ROLLBACK,
// with no leak risk on connection return-to-pool.
//
// Use this for any code path that must respect RLS under axonflow_app_role.
// Cross-org workers running under axonflow_platform_admin do NOT need this
// (BYPASSRLS makes the session var irrelevant for visibility).
//
// orgID must be non-empty. An empty orgID would set app.current_org_id to
// the SQL empty string, which evaluates as the empty string in policies and
// would mask data even when the caller meant "all orgs" — that mode is
// intentionally not supported; cross-org work must use the admin role.
func WithOrgScope(ctx context.Context, db *sql.DB, orgID string, fn func(*sql.Tx) error) (err error) {
	if db == nil {
		return fmt.Errorf("rls.WithOrgScope: db is nil")
	}
	if orgID == "" {
		return fmt.Errorf("rls.WithOrgScope: orgID must be non-empty (cross-org work belongs on the admin role)")
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("rls.WithOrgScope: begin txn: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	if _, err = tx.ExecContext(ctx, "SELECT set_config('app.current_org_id', $1, true)", orgID); err != nil {
		return fmt.Errorf("rls.WithOrgScope: set_config(app.current_org_id, %q, true): %w", orgID, err)
	}

	if err = fn(tx); err != nil {
		return err
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("rls.WithOrgScope: commit: %w", err)
	}
	return nil
}

// WithOrgAndTenantScope is the dual-key counterpart of WithOrgScope. It
// SETs app.current_org_id, app.current_tenant_id, and the legacy alias
// app.tenant_id as transaction-locals in a single BEGIN before running
// fn. Use this for tables whose RLS policy is keyed on the legacy
// app.current_tenant_id GUC — the canonical offender is mig 042's
// execution_history.tenant_isolation policy, which predates the post-
// Phase-6 GUC normalization to app.current_org_id. PR-C2's mig 110
// migrated policy_overrides + static_policy_versions + policy_versions
// to app.current_org_id, but mig 042 stays on app.current_tenant_id; a
// separate follow-up migration to flip it is the long-term fix.
//
// Empty strings on either key are rejected for the same SoX-safety
// reason WithOrgScope rejects empty orgID: a cross-tenant write belongs
// on the admin role, not on this helper.
//
// v9 Phase 8 #2384 PR-C1.
func WithOrgAndTenantScope(ctx context.Context, db *sql.DB, orgID, tenantID string, fn func(*sql.Tx) error) (err error) {
	if db == nil {
		return fmt.Errorf("rls.WithOrgAndTenantScope: db is nil")
	}
	if orgID == "" {
		return fmt.Errorf("rls.WithOrgAndTenantScope: orgID must be non-empty")
	}
	if tenantID == "" {
		return fmt.Errorf("rls.WithOrgAndTenantScope: tenantID must be non-empty")
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("rls.WithOrgAndTenantScope: begin txn: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	if _, err = tx.ExecContext(ctx, "SELECT set_config('app.current_org_id', $1, true)", orgID); err != nil {
		return fmt.Errorf("rls.WithOrgAndTenantScope: set_config(app.current_org_id, %q, true): %w", orgID, err)
	}
	if _, err = tx.ExecContext(ctx, "SELECT set_config('app.current_tenant_id', $1, true)", tenantID); err != nil {
		return fmt.Errorf("rls.WithOrgAndTenantScope: set_config(app.current_tenant_id, %q, true): %w", tenantID, err)
	}
	// Legacy single-word alias used by mig 030's policy_overrides /
	// static_policy_versions surfaces. PR-C2's mig 110 dropped those
	// legacy policies, but a self-hosted operator who hasn't applied mig
	// 110 yet still needs this set for the wrapped write to clear the
	// USING predicate. Setting it under the post-110 policy is a no-op.
	if _, err = tx.ExecContext(ctx, "SELECT set_config('app.tenant_id', $1, true)", tenantID); err != nil {
		return fmt.Errorf("rls.WithOrgAndTenantScope: set_config(app.tenant_id, %q, true): %w", tenantID, err)
	}

	if err = fn(tx); err != nil {
		return err
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("rls.WithOrgAndTenantScope: commit: %w", err)
	}
	return nil
}

// CurrentOrgIDInTx reads back the session variable from inside the tx.
// Used by tests to assert that the GUC actually landed.
func CurrentOrgIDInTx(ctx context.Context, tx *sql.Tx) (string, error) {
	var v sql.NullString
	if err := tx.QueryRowContext(ctx, "SELECT current_setting('app.current_org_id', true)").Scan(&v); err != nil {
		return "", fmt.Errorf("rls.CurrentOrgIDInTx: %w", err)
	}
	if !v.Valid {
		return "", nil
	}
	return v.String, nil
}
