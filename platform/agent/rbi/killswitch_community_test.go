//go:build !enterprise

// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package rbi

import (
	"context"
	"testing"
)

func TestKillSwitchEnabled_Community(t *testing.T) {
	if KillSwitchEnabled() {
		t.Error("Expected KillSwitchEnabled() to return false in Community mode")
	}
}

func TestNewKillSwitchChecker_Community(t *testing.T) {
	checker := NewKillSwitchChecker(nil)
	if checker == nil {
		t.Error("Expected NewKillSwitchChecker to return non-nil checker")
	}
}

func TestCheckKillSwitch_Community(t *testing.T) {
	checker := NewKillSwitchChecker(nil)
	ctx := context.Background()

	result := checker.CheckKillSwitch(ctx, "org-123", "system-456")

	if result == nil {
		t.Fatal("Expected non-nil result")
	}
	if result.IsBlocked {
		t.Error("Expected Community stub to return IsBlocked=false")
	}
	if result.Reason != "" {
		t.Errorf("Expected empty reason, got %q", result.Reason)
	}
}

func TestListActiveKillSwitches_Community(t *testing.T) {
	checker := NewKillSwitchChecker(nil)
	ctx := context.Background()

	switches, err := checker.ListActiveKillSwitches(ctx, "org-123")

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if switches != nil && len(switches) > 0 {
		t.Errorf("Expected empty slice, got %d items", len(switches))
	}
}
