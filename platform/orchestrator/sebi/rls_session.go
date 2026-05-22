// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build enterprise

package sebi

// v9 Phase 8 RLS — transaction-scoped org_id session variable (sebi copy).
//
// Mirrors platform/agent/rls_session.go + platform/orchestrator/rls_session.go.
// sebi is a sub-package of orchestrator and cannot import orchestrator without
// inducing an import cycle (orchestrator imports sebi for handler registration).
// The helper is intentionally duplicated. ~50 lines of code; a shared
// platform/shared/rls package would be the cleaner long-term home and can
// consolidate after Phase 8 lands.

import (
	"context"
	"database/sql"
	"fmt"
)

// withOrgScope runs fn inside a transaction whose first statement is
// SELECT set_config('app.current_org_id', $orgID, true). Transaction-bounded:
// COMMIT/ROLLBACK auto-clears the session variable, preventing connection-pool
// leak of org_id across requests.
//
// Used for the audit_retention_config reads under FORCE ROW LEVEL SECURITY
// (migration 100). The sebi service's checkRetentionCompliance + getRetentionConfig
// are per-tenant reads — orgID is the tenantID arg passed in by the caller.
func withOrgScope(ctx context.Context, db *sql.DB, orgID string, fn func(*sql.Tx) error) (err error) {
	if db == nil {
		return fmt.Errorf("withOrgScope: db is nil")
	}
	if orgID == "" {
		return fmt.Errorf("withOrgScope: orgID must be non-empty (cross-org work belongs on the admin role)")
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("withOrgScope: begin txn: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	if _, err = tx.ExecContext(ctx, "SELECT set_config('app.current_org_id', $1, true)", orgID); err != nil {
		return fmt.Errorf("withOrgScope: set_config(app.current_org_id, %q, true): %w", orgID, err)
	}

	if err = fn(tx); err != nil {
		return err
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("withOrgScope: commit: %w", err)
	}
	return nil
}
