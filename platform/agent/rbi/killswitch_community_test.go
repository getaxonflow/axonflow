//go:build !enterprise

// Copyright 2025 AxonFlow
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package rbi

import (
	"context"
	"testing"
)

func TestKillSwitchEnabled_OSS(t *testing.T) {
	if KillSwitchEnabled() {
		t.Error("Expected KillSwitchEnabled() to return false in OSS mode")
	}
}

func TestNewKillSwitchChecker_OSS(t *testing.T) {
	checker := NewKillSwitchChecker(nil)
	if checker == nil {
		t.Error("Expected NewKillSwitchChecker to return non-nil checker")
	}
}

func TestCheckKillSwitch_OSS(t *testing.T) {
	checker := NewKillSwitchChecker(nil)
	ctx := context.Background()

	result := checker.CheckKillSwitch(ctx, "org-123", "system-456")

	if result == nil {
		t.Fatal("Expected non-nil result")
	}
	if result.IsBlocked {
		t.Error("Expected OSS stub to return IsBlocked=false")
	}
	if result.Reason != "" {
		t.Errorf("Expected empty reason, got %q", result.Reason)
	}
}

func TestListActiveKillSwitches_OSS(t *testing.T) {
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
