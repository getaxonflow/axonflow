//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"database/sql"
)

// The Community build has no approval queue (HITL is Enterprise), so a
// challenge on mcp:request or decide keeps the refusal PRD v11 §1.13 gives a
// plane with no hold: a deny whose reason is approval_required. Nothing is
// queued, nothing is read, and an approval id on a retry is ignored - the
// retry is decided and refused exactly as the first call was (#4370).

func wireApprovalHold(*sql.DB) {}

func applyApprovalHold(_ context.Context, enforced requestPassEnforcement, _ approvalHoldCall) approvalHoldResult {
	return approvalHoldResult{enforced: enforced}
}
