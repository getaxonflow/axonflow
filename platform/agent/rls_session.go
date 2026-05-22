// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// v9 Phase 8 PR-C2 (#2384) extracted the canonical WithOrgScope
// implementation to the leaf package platform/agent/rls so it can be
// imported by any caller in the dep graph — including platform/orchestrator/llm,
// reached from platform/agent via the cost package — without creating a
// cycle. The aliases here keep the dozens of existing in-package call
// sites compiling unchanged.
//
// PR-C1 extends the rls package with WithOrgAndTenantScope (dual-key
// helper for mig 042's app.current_tenant_id-keyed RLS); re-export it
// here too so the same alias surface is preserved.

import (
	"context"
	"database/sql"

	"axonflow/platform/agent/rls"
)

// WithOrgScope re-exports [rls.WithOrgScope]. The canonical implementation
// lives in package rls (a leaf, importable from anywhere in the dep graph).
// Existing callers (platform/orchestrator, ee/platform/customer-portal,
// platform/agent internal sites) keep `agent.WithOrgScope(…)` working as-is.
func WithOrgScope(ctx context.Context, db *sql.DB, orgID string, fn func(*sql.Tx) error) error {
	return rls.WithOrgScope(ctx, db, orgID, fn)
}

// WithOrgAndTenantScope re-exports [rls.WithOrgAndTenantScope] — the
// dual-key variant for tables whose RLS policy is keyed on the legacy
// app.current_tenant_id GUC (mig 042's execution_history).
func WithOrgAndTenantScope(ctx context.Context, db *sql.DB, orgID, tenantID string, fn func(*sql.Tx) error) error {
	return rls.WithOrgAndTenantScope(ctx, db, orgID, tenantID, fn)
}

// CurrentOrgIDInTx re-exports [rls.CurrentOrgIDInTx].
func CurrentOrgIDInTx(ctx context.Context, tx *sql.Tx) (string, error) {
	return rls.CurrentOrgIDInTx(ctx, tx)
}
