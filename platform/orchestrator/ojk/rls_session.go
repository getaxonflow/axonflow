//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package ojk

import (
	"context"
	"database/sql"
	"fmt"
)

// withOrgScope runs fn inside a transaction whose first statement is
// SELECT set_config('app.current_org_id', $orgID, true). Transaction-bounded:
// COMMIT/ROLLBACK auto-clears the session variable, preventing connection-pool
// leak of org_id across requests.
func withOrgScope(ctx context.Context, db *sql.DB, orgID string, fn func(*sql.Tx) error) (err error) {
	if db == nil {
		return fmt.Errorf("withOrgScope: db is nil")
	}
	if orgID == "" {
		return fmt.Errorf("withOrgScope: orgID must be non-empty")
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
