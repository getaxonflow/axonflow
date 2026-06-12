// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// #2705: BuildActionOverrides must wire the sensitive-data category so the
// governance profile + SENSITIVE_DATA_ACTION env lever actually drive the system
// sensitive-data policies. Before this fix the category was omitted, so those
// rows (NULL phase columns, migration 035) fell to GetActionForPhase's hardcoded
// 'log' fallback regardless of profile — making the documented warn/block posture
// a no-op.
//
// Red-on-revert: removing the `overrides[CategorySensitiveData] = ...` line makes
// every sub-test fail (the key goes missing).

import (
	"testing"

	sharedpolicy "axonflow/platform/shared/policy"
)

func TestBuildActionOverrides_SensitiveDataLever_ByProfile(t *testing.T) {
	// The documented governance matrix (docs/guides/governance-profiles.md /
	// platform/agent/profile.go): sensitive_data is log (dev), warn (default),
	// block (strict + compliance).
	cases := []struct {
		profile Profile
		want    sharedpolicy.Action
	}{
		{ProfileDev, sharedpolicy.ActionLog},
		{ProfileDefault, sharedpolicy.ActionWarn},
		{ProfileStrict, sharedpolicy.ActionBlock},
		{ProfileCompliance, sharedpolicy.ActionBlock},
	}
	for _, tc := range cases {
		t.Run(string(tc.profile), func(t *testing.T) {
			pd := ProfileDefaults(tc.profile)
			cfg := ModeDetectionConfig{SensitiveDataAction: pd.SensitiveDataAction}
			ov := cfg.BuildActionOverrides()

			got, ok := ov[sharedpolicy.CategorySensitiveData]
			if !ok {
				t.Fatalf("profile %s: CategorySensitiveData missing from BuildActionOverrides — the #2705 dead-lever regression (the SENSITIVE_DATA_ACTION lever does nothing)", tc.profile)
			}
			if got != tc.want {
				t.Errorf("profile %s: sensitive-data override = %q, want %q", tc.profile, got, tc.want)
			}
		})
	}
}

func TestBuildActionOverrides_SensitiveDataLever_EnvDrives(t *testing.T) {
	// SENSITIVE_DATA_ACTION (and per-mode equivalents) flow into
	// ModeDetectionConfig.SensitiveDataAction; assert each explicit value reaches
	// the override map verbatim.
	for _, tc := range []struct {
		action DetectionAction
		want   sharedpolicy.Action
	}{
		{DetectionActionBlock, sharedpolicy.ActionBlock},
		{DetectionActionWarn, sharedpolicy.ActionWarn},
		{DetectionActionLog, sharedpolicy.ActionLog},
	} {
		cfg := ModeDetectionConfig{SensitiveDataAction: tc.action}
		got, ok := cfg.BuildActionOverrides()[sharedpolicy.CategorySensitiveData]
		if !ok {
			t.Fatalf("SENSITIVE_DATA_ACTION=%s did not reach the override map (key missing)", tc.action)
		}
		if got != tc.want {
			t.Errorf("SENSITIVE_DATA_ACTION=%s -> override %q, want %q", tc.action, got, tc.want)
		}
	}
}

// TestModeDetectionConfig_InheritsSensitiveDataAction guards the wiring from the
// global config into both per-mode constructors (so the field is actually
// populated, not just present on the struct).
func TestModeDetectionConfig_InheritsSensitiveDataAction(t *testing.T) {
	t.Setenv("AXONFLOW_PROFILE", "strict")
	for _, build := range []struct {
		name string
		fn   func() ModeDetectionConfig
	}{
		{"gateway", GatewayDetectionConfigFromEnv},
		{"mcp", MCPDetectionConfigFromEnv},
	} {
		t.Run(build.name, func(t *testing.T) {
			cfg := build.fn()
			if cfg.SensitiveDataAction != DetectionActionBlock {
				t.Errorf("%s: SensitiveDataAction = %q under strict profile, want block (the constructor must inherit globalCfg.SensitiveDataAction)", build.name, cfg.SensitiveDataAction)
			}
			if cfg.BuildActionOverrides()[sharedpolicy.CategorySensitiveData] != sharedpolicy.ActionBlock {
				t.Errorf("%s: strict profile did not drive sensitive-data to block end-to-end", build.name)
			}
		})
	}
}
