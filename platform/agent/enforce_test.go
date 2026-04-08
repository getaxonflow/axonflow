// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"testing"
)

func TestParseEnforce(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantNil bool
		wantSet map[EnforceCategory]bool
		wantErr bool
	}{
		{"empty returns nil", "", true, nil, false},
		{"  whitespace returns nil", "   ", true, nil, false},
		{"all", "all", false, map[EnforceCategory]bool{
			EnforcePII: true, EnforceSQLI: true, EnforceSensitiveData: true,
			EnforceHighRisk: true, EnforceDangerousQuery: true, EnforceDangerousCommands: true,
		}, false},
		{"ALL uppercase", "ALL", false, map[EnforceCategory]bool{
			EnforcePII: true, EnforceSQLI: true, EnforceSensitiveData: true,
			EnforceHighRisk: true, EnforceDangerousQuery: true, EnforceDangerousCommands: true,
		}, false},
		{"none returns empty set", "none", false, map[EnforceCategory]bool{}, false},
		{"single", "pii", false, map[EnforceCategory]bool{EnforcePII: true}, false},
		{"multi", "pii,sqli,dangerous_commands", false, map[EnforceCategory]bool{
			EnforcePII: true, EnforceSQLI: true, EnforceDangerousCommands: true,
		}, false},
		{"whitespace tolerant", "pii , sqli ,dangerous_commands  ", false, map[EnforceCategory]bool{
			EnforcePII: true, EnforceSQLI: true, EnforceDangerousCommands: true,
		}, false},
		{"trailing comma", "pii,sqli,", false, map[EnforceCategory]bool{
			EnforcePII: true, EnforceSQLI: true,
		}, false},
		{"unknown token errors", "pii,nonsense", false, nil, true},
		{"single typo errors", "piii", false, nil, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseEnforce(tc.input)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParseEnforce(%q) error = %v, wantErr %v", tc.input, err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if tc.wantNil {
				if got != nil {
					t.Errorf("expected nil set, got %+v", got)
				}
				return
			}
			if len(got) != len(tc.wantSet) {
				t.Errorf("got %d categories, want %d (%+v vs %+v)", len(got), len(tc.wantSet), got, tc.wantSet)
			}
			for k, v := range tc.wantSet {
				if got[k] != v {
					t.Errorf("category %q: got %v, want %v", k, got[k], v)
				}
			}
		})
	}
}

func TestApplyEnforce(t *testing.T) {
	base := ProfileDefaults(ProfileDev) // all log/warn

	t.Run("nil set is no-op", func(t *testing.T) {
		got := ApplyEnforce(base, nil)
		if got != base {
			t.Errorf("nil set should be no-op")
		}
	})

	t.Run("set blocks listed warns rest", func(t *testing.T) {
		set := EnforceSet{EnforcePII: true, EnforceSQLI: true}
		got := ApplyEnforce(base, set)
		if got.PIIAction != DetectionActionBlock {
			t.Errorf("PII = %q, want block", got.PIIAction)
		}
		if got.SQLIAction != DetectionActionBlock {
			t.Errorf("SQLI = %q, want block", got.SQLIAction)
		}
		if got.DangerousCommandAction != DetectionActionWarn {
			t.Errorf("DangerousCommand = %q, want warn (not in set)", got.DangerousCommandAction)
		}
		if got.SensitiveDataAction != DetectionActionWarn {
			t.Errorf("SensitiveData = %q, want warn (not in set)", got.SensitiveDataAction)
		}
	})

	t.Run("none overrides profile to all warn", func(t *testing.T) {
		set, _ := ParseEnforce("none")
		got := ApplyEnforce(ProfileDefaults(ProfileStrict), set)
		// Strict would be all-block; "none" should make everything warn.
		if got.PIIAction != DetectionActionWarn {
			t.Errorf("PII = %q, want warn", got.PIIAction)
		}
		if got.DangerousCommandAction != DetectionActionWarn {
			t.Errorf("DangerousCommand = %q, want warn", got.DangerousCommandAction)
		}
	})

	t.Run("all matches strict-ish profile", func(t *testing.T) {
		set, _ := ParseEnforce("all")
		got := ApplyEnforce(ProfileDefaults(ProfileDev), set)
		if got.PIIAction != DetectionActionBlock || got.SQLIAction != DetectionActionBlock ||
			got.DangerousCommandAction != DetectionActionBlock {
			t.Errorf("'all' should block all categories, got %+v", got)
		}
	})
}
