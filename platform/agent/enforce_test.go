// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"testing"
)

func TestParseEnforce(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantUnset    bool
		wantSentinel string
		wantSet      map[EnforceCategory]bool
		wantErr      bool
	}{
		{"empty returns unset", "", true, "", nil, false},
		{"  whitespace returns unset", "   ", true, "", nil, false},
		{"all is a sentinel", "all", false, "all", nil, false},
		{"ALL uppercase", "ALL", false, "all", nil, false},
		{"none is a sentinel", "none", false, "none", nil, false},
		{"NONE uppercase", "NONE", false, "none", nil, false},
		{"single category", "pii", false, "", map[EnforceCategory]bool{EnforcePII: true}, false},
		{"multi category", "pii,sqli,dangerous_commands", false, "", map[EnforceCategory]bool{
			EnforcePII: true, EnforceSQLI: true, EnforceDangerousCommands: true,
		}, false},
		{"whitespace tolerant", "pii , sqli ,dangerous_commands  ", false, "", map[EnforceCategory]bool{
			EnforcePII: true, EnforceSQLI: true, EnforceDangerousCommands: true,
		}, false},
		{"trailing comma", "pii,sqli,", false, "", map[EnforceCategory]bool{
			EnforcePII: true, EnforceSQLI: true,
		}, false},
		{"unknown token errors", "pii,nonsense", false, "", nil, true},
		{"single typo errors", "piii", false, "", nil, true},
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
			if tc.wantUnset {
				if !got.Unset() {
					t.Errorf("expected unset, got sentinel=%q categories=%+v", got.Sentinel, got.Categories)
				}
				return
			}
			if got.Sentinel != tc.wantSentinel {
				t.Errorf("sentinel = %q, want %q", got.Sentinel, tc.wantSentinel)
			}
			if tc.wantSet != nil {
				if len(got.Categories) != len(tc.wantSet) {
					t.Errorf("got %d categories, want %d (%+v vs %+v)", len(got.Categories), len(tc.wantSet), got.Categories, tc.wantSet)
				}
				for k, v := range tc.wantSet {
					if got.Categories[k] != v {
						t.Errorf("category %q: got %v, want %v", k, got.Categories[k], v)
					}
				}
			}
		})
	}
}

func TestApplyEnforce(t *testing.T) {
	t.Run("unset is no-op", func(t *testing.T) {
		base := ProfileDefaults(ProfileDev)
		got := ApplyEnforce(base, EnforceResult{})
		if got != base {
			t.Errorf("unset should be no-op")
		}
	})

	t.Run("sentinel all equals strict profile exactly", func(t *testing.T) {
		// Fix for v6.2.0 review finding: `all` must produce the same matrix
		// as ProfileDefaults(ProfileStrict), NOT "block everything including
		// high_risk". strict leaves high_risk at warn.
		base := ProfileDefaults(ProfileDev)
		got := ApplyEnforce(base, EnforceResult{Sentinel: "all"})
		want := ProfileDefaults(ProfileStrict)
		if got != want {
			t.Errorf("all sentinel should equal strict profile exactly.\n  got:  %+v\n  want: %+v", got, want)
		}
		if got.HighRiskAction != DetectionActionWarn {
			t.Errorf("all sentinel high_risk: got %q, want warn (strict profile has high_risk=warn, NOT block)", got.HighRiskAction)
		}
	})

	t.Run("sentinel none equals dev profile exactly", func(t *testing.T) {
		// `none` must produce the dev-profile matrix (PII/SQLi/sensitive/high_risk=log,
		// dangerous=warn), NOT "warn everything".
		base := ProfileDefaults(ProfileStrict)
		got := ApplyEnforce(base, EnforceResult{Sentinel: "none"})
		want := ProfileDefaults(ProfileDev)
		if got != want {
			t.Errorf("none sentinel should equal dev profile exactly.\n  got:  %+v\n  want: %+v", got, want)
		}
		if got.PIIAction != DetectionActionLog {
			t.Errorf("none sentinel PII: got %q, want log (dev profile has PII=log, NOT warn)", got.PIIAction)
		}
	})

	t.Run("explicit list blocks listed, preserves profile for non-listed", func(t *testing.T) {
		// Second half of the fix: non-listed categories must NOT be silently
		// downgraded to warn. They keep whatever the profile base says.
		base := ProfileDefaults(ProfileDev)
		got := ApplyEnforce(base, EnforceResult{Categories: EnforceCategorySet{
			EnforcePII:  true,
			EnforceSQLI: true,
		}})
		if got.PIIAction != DetectionActionBlock {
			t.Errorf("PII = %q, want block", got.PIIAction)
		}
		if got.SQLIAction != DetectionActionBlock {
			t.Errorf("SQLI = %q, want block", got.SQLIAction)
		}
		// Non-listed: must stay at dev profile values.
		if got.SensitiveDataAction != DetectionActionLog {
			t.Errorf("SensitiveData = %q, want log (dev profile preserved)", got.SensitiveDataAction)
		}
		if got.HighRiskAction != DetectionActionLog {
			t.Errorf("HighRisk = %q, want log (dev profile preserved)", got.HighRiskAction)
		}
		if got.DangerousCommandAction != DetectionActionWarn {
			t.Errorf("DangerousCommand = %q, want warn (dev profile preserved)", got.DangerousCommandAction)
		}
	})

	t.Run("explicit list on strict profile preserves strict values for non-listed", func(t *testing.T) {
		base := ProfileDefaults(ProfileStrict)
		got := ApplyEnforce(base, EnforceResult{Categories: EnforceCategorySet{
			EnforceDangerousCommands: true,
		}})
		if got.DangerousCommandAction != DetectionActionBlock {
			t.Errorf("DangerousCommand = %q, want block", got.DangerousCommandAction)
		}
		// Non-listed PII must stay at strict's block.
		if got.PIIAction != DetectionActionBlock {
			t.Errorf("PII = %q, want block (strict profile preserved, NOT downgraded to warn)", got.PIIAction)
		}
	})
}

func TestLoadEnforceFromEnv_ReturnsErrorNotFatal(t *testing.T) {
	// Regression: v6.2.0 LoadEnforceFromEnv called log.Fatalf on invalid
	// input, crashing the whole test binary. Now returns an error.
	t.Setenv(EnvEnforce, "piii")
	_, err := LoadEnforceFromEnv()
	if err == nil {
		t.Fatal("expected error on invalid enforce value, got nil")
	}
}

func TestLoadEnforceFromEnv_UnsetReturnsNoError(t *testing.T) {
	t.Setenv(EnvEnforce, "")
	result, err := LoadEnforceFromEnv()
	if err != nil {
		t.Fatalf("unset should not error, got %v", err)
	}
	if !result.Unset() {
		t.Errorf("unset should return Unset() == true")
	}
}
