//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: Apache-2.0
//
// Tests for Community WCP HITL stub.
// Issue #1082: Wire WCP require_approval action to HITL queue

package orchestrator

import (
	"testing"
)

func TestInitializeWCPHITL_Community(t *testing.T) {
	// In community mode, InitializeWCPHITL should be a no-op
	err := InitializeWCPHITL(nil, nil)
	if err != nil {
		t.Errorf("InitializeWCPHITL() in community mode returned error: %v", err)
	}
}

func TestInitializeWCPHITL_CommunityWithAdapter(t *testing.T) {
	// Even with a real adapter, community mode should be a no-op
	adapter := &WCPPolicyAdapter{}
	err := InitializeWCPHITL(nil, adapter)
	if err != nil {
		t.Errorf("InitializeWCPHITL() with adapter in community mode returned error: %v", err)
	}

	// The adapter should NOT have HITL wired (it's community mode)
	// We can't easily test this without exposing hitlApproval field
}
