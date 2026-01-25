//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: Apache-2.0
//
// Community stub for WCP HITL wiring.
// HITL (Human-in-the-Loop) for WCP is an Enterprise feature.
//
// Issue #1082: Wire WCP require_approval action to HITL queue

package orchestrator

import (
	"database/sql"
	"log"
)

// InitializeWCPHITL is the Community stub for WCP HITL wiring.
// In Community mode, HITL is disabled for WCP require_approval actions.
// WCP will still evaluate policies and return require_approval decisions,
// but no HITL queue entries will be created.
func InitializeWCPHITL(_ *sql.DB, _ *WCPPolicyAdapter) error {
	log.Println("ℹ️  WCP HITL disabled (Community mode) - require_approval actions will block but not queue")
	return nil
}
