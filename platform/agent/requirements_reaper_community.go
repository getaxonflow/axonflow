// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build !enterprise

package agent

import (
	"context"
	"database/sql"
)

// StartRequirementsReaper is a no-op on a community build.
//
// The two tables it cleans - `reservations` and `decision_proof_executions` -
// are created by migrations/enterprise/148 and /149, which a community
// deployment does not apply. There is nothing to reap, and a loop that ran
// anyway would error every interval against tables that do not exist.
//
// It is a STUB with the same signature rather than a call site guarded by a
// build tag in run.go, so the boot sequence reads identically in both editions
// and neither one can drift a step out of the other. The `any` on the rate
// source is what keeps this file free of the enterprise-only reservation
// package; the enterprise build takes the real type.
func StartRequirementsReaper(_ context.Context, _, _ *sql.DB, _ any) func() {
	return func() {}
}
