// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package anchoredenforcer

import (
	"strings"
	"testing"
	"time"
)

// #4249 row 5774029945: the deployment's approval window is read from one
// variable, defaults to the engine's 15 minutes, and a value outside the
// approval bounds is refused, never clamped.
func TestTheDeploymentApprovalWindowIsReadBoundedAndRefusedNotClamped(t *testing.T) {
	for _, tc := range []struct {
		name    string
		raw     string
		set     bool
		want    time.Duration
		refused string
	}{
		{"unset is the engine default", "", false, 15 * time.Minute, ""},
		{"empty is the engine default", "", true, 15 * time.Minute, ""},
		{"a day", "86400", true, 24 * time.Hour, ""},
		{"the floor", "60", true, time.Minute, ""},
		{"the ceiling", "604800", true, 7 * 24 * time.Hour, ""},
		{"surrounding space is trimmed", " 3600 ", true, time.Hour, ""},
		{"below the floor is refused", "59", true, 0, "outside the approval window's bounds 60..604800"},
		{"above the ceiling is refused", "604801", true, 0, "outside the approval window's bounds 60..604800"},
		{"zero is refused", "0", true, 0, "outside the approval window's bounds"},
		{"a duration string is refused", "15m", true, 0, "not a whole number of seconds"},
		{"a leading zero is refused", "0900", true, 0, "not a whole number of seconds"},
		{"a sign is refused", "+900", true, 0, "not a whole number of seconds"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ApprovalTTLFrom(func(k string) (string, bool) {
				if k != ApprovalTTLEnv {
					t.Fatalf("read %q, want only %s", k, ApprovalTTLEnv)
				}
				return tc.raw, tc.set
			})
			if tc.refused == "" {
				if err != nil || got != tc.want {
					t.Errorf("= %v, %v; want %v", got, err, tc.want)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.refused) || !strings.Contains(err.Error(), ApprovalTTLEnv) {
				t.Errorf("= %v, %v; want refused naming %s and %q", got, err, ApprovalTTLEnv, tc.refused)
			}
		})
	}
}
