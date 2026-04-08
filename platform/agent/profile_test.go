// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"testing"
)

func TestResolveProfile(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want Profile
	}{
		{"unset returns default", "", ProfileDefault},
		{"dev", "dev", ProfileDev},
		{"DEV uppercase", "DEV", ProfileDev},
		{"  dev  whitespace", "  dev  ", ProfileDev},
		{"default", "default", ProfileDefault},
		{"strict", "strict", ProfileStrict},
		{"compliance", "compliance", ProfileCompliance},
		{"invalid falls back", "developer", ProfileDefault},
		{"empty falls back", "", ProfileDefault},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(EnvProfile, tc.env)
			if got := ResolveProfile(); got != tc.want {
				t.Errorf("ResolveProfile() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestProfileDefaultsMatrix is the authoritative 4×6 matrix asserting
// per-category defaults for each profile. Must match the table in
// docs/guides/governance-profiles.md and ADR-036.
func TestProfileDefaultsMatrix(t *testing.T) {
	type expect struct {
		pii, sqli, sensitive, highRisk, dangerousQuery, dangerousCmd DetectionAction
	}
	matrix := map[Profile]expect{
		ProfileDev: {
			pii:            DetectionActionLog,
			sqli:           DetectionActionLog,
			sensitive:      DetectionActionLog,
			highRisk:       DetectionActionLog,
			dangerousQuery: DetectionActionWarn,
			dangerousCmd:   DetectionActionWarn,
		},
		ProfileDefault: {
			pii:            DetectionActionWarn,
			sqli:           DetectionActionWarn,
			sensitive:      DetectionActionWarn,
			highRisk:       DetectionActionWarn,
			dangerousQuery: DetectionActionBlock,
			dangerousCmd:   DetectionActionBlock,
		},
		ProfileStrict: {
			pii:            DetectionActionBlock,
			sqli:           DetectionActionBlock,
			sensitive:      DetectionActionBlock,
			highRisk:       DetectionActionWarn,
			dangerousQuery: DetectionActionBlock,
			dangerousCmd:   DetectionActionBlock,
		},
		ProfileCompliance: {
			pii:            DetectionActionBlock,
			sqli:           DetectionActionBlock,
			sensitive:      DetectionActionBlock,
			highRisk:       DetectionActionBlock,
			dangerousQuery: DetectionActionBlock,
			dangerousCmd:   DetectionActionBlock,
		},
	}
	for p, want := range matrix {
		t.Run(string(p), func(t *testing.T) {
			got := ProfileDefaults(p)
			if got.PIIAction != want.pii {
				t.Errorf("PII = %q, want %q", got.PIIAction, want.pii)
			}
			if got.SQLIAction != want.sqli {
				t.Errorf("SQLI = %q, want %q", got.SQLIAction, want.sqli)
			}
			if got.SensitiveDataAction != want.sensitive {
				t.Errorf("SensitiveData = %q, want %q", got.SensitiveDataAction, want.sensitive)
			}
			if got.HighRiskAction != want.highRisk {
				t.Errorf("HighRisk = %q, want %q", got.HighRiskAction, want.highRisk)
			}
			if got.DangerousQueryAction != want.dangerousQuery {
				t.Errorf("DangerousQuery = %q, want %q", got.DangerousQueryAction, want.dangerousQuery)
			}
			if got.DangerousCommandAction != want.dangerousCmd {
				t.Errorf("DangerousCommand = %q, want %q", got.DangerousCommandAction, want.dangerousCmd)
			}
		})
	}
}

func TestProfileDefaultsUnknownProfileFallsBackToDefault(t *testing.T) {
	got := ProfileDefaults(Profile("nonsense"))
	want := ProfileDefaults(ProfileDefault)
	if got != want {
		t.Errorf("unknown profile = %+v, want default = %+v", got, want)
	}
}

func TestExplicitEnvVarOverridesProfile(t *testing.T) {
	// AXONFLOW_PROFILE=dev would normally make PII=log, but explicit
	// PII_ACTION=block must win.
	t.Setenv(EnvProfile, "dev")
	t.Setenv(EnvPIIAction, "block")
	defer ResetDetectionConfigCache()

	// Apply the same precedence logic the production code uses:
	cfg := ProfileDefaults(ResolveProfile())
	cfg = DetectionConfigFromEnvWithBase(cfg)

	if cfg.PIIAction != DetectionActionBlock {
		t.Errorf("expected explicit PII_ACTION=block to override profile dev, got %q", cfg.PIIAction)
	}
	// Categories WITHOUT an explicit override should still come from the profile.
	if cfg.SQLIAction != DetectionActionLog {
		t.Errorf("expected SQLi to inherit dev profile (log), got %q", cfg.SQLIAction)
	}
}

func TestLogProfileBannerNoPanic(t *testing.T) {
	// Just ensure the banner formatting doesn't panic; output goes to log.
	LogProfileBanner("test-component", ProfileDev, ProfileDefaults(ProfileDev))
	LogProfileBanner("test-component", ProfileCompliance, ProfileDefaults(ProfileCompliance))
}
