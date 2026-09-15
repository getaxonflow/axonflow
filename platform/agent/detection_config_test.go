// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	sharedpolicy "axonflow/platform/shared/policy"
)

// TestDetectionAction_ShouldBlock tests the ShouldBlock method.
func TestDetectionAction_ShouldBlock(t *testing.T) {
	tests := []struct {
		action   DetectionAction
		expected bool
	}{
		{DetectionActionBlock, true},
		{DetectionActionWarn, false},
		{DetectionActionRedact, false},
		{DetectionActionLog, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.action), func(t *testing.T) {
			if got := tt.action.ShouldBlock(); got != tt.expected {
				t.Errorf("ShouldBlock() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

// TestDetectionAction_ShouldRedact tests the ShouldRedact method.
func TestDetectionAction_ShouldRedact(t *testing.T) {
	tests := []struct {
		action   DetectionAction
		expected bool
	}{
		{DetectionActionBlock, false},
		{DetectionActionWarn, false},
		{DetectionActionRedact, true},
		{DetectionActionLog, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.action), func(t *testing.T) {
			if got := tt.action.ShouldRedact(); got != tt.expected {
				t.Errorf("ShouldRedact() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

// TestDetectionAction_ShouldWarn tests the ShouldWarn method.
func TestDetectionAction_ShouldWarn(t *testing.T) {
	tests := []struct {
		action   DetectionAction
		expected bool
	}{
		{DetectionActionBlock, false},
		{DetectionActionWarn, true},
		{DetectionActionRedact, false},
		{DetectionActionLog, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.action), func(t *testing.T) {
			if got := tt.action.ShouldWarn(); got != tt.expected {
				t.Errorf("ShouldWarn() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

// TestDetectionAction_ShouldLog tests the ShouldLog method.
func TestDetectionAction_ShouldLog(t *testing.T) {
	// All actions should log
	tests := []DetectionAction{
		DetectionActionBlock,
		DetectionActionWarn,
		DetectionActionRedact,
		DetectionActionLog,
	}

	for _, action := range tests {
		t.Run(string(action), func(t *testing.T) {
			if got := action.ShouldLog(); !got {
				t.Errorf("ShouldLog() = %v, expected true", got)
			}
		})
	}
}

// TestDetectionAction_ToOverrideAction tests conversion to OverrideAction.
func TestDetectionAction_ToOverrideAction(t *testing.T) {
	tests := []struct {
		action   DetectionAction
		expected OverrideAction
	}{
		{DetectionActionBlock, ActionBlock},
		{DetectionActionWarn, ActionWarn},
		{DetectionActionRedact, ActionRedact},
		{DetectionActionLog, ActionLog},
		{DetectionAction("unknown"), ActionBlock}, // Unknown defaults to block
	}

	for _, tt := range tests {
		t.Run(string(tt.action), func(t *testing.T) {
			if got := tt.action.ToOverrideAction(); got != tt.expected {
				t.Errorf("ToOverrideAction() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

// TestDetectionAction_Constants tests the constant values.
func TestDetectionAction_Constants(t *testing.T) {
	// Verify constant values match expected strings
	tests := []struct {
		action   DetectionAction
		expected string
	}{
		{DetectionActionBlock, "block"},
		{DetectionActionWarn, "warn"},
		{DetectionActionRedact, "redact"},
		{DetectionActionLog, "log"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if string(tt.action) != tt.expected {
				t.Errorf("constant value = %q, expected %q", string(tt.action), tt.expected)
			}
		})
	}
}

// =============================================================================
// ModeDetectionConfig Tests
// =============================================================================

// clearModeEnvVars clears every mode env var AND every removed posture variable,
// so a test starts from a process that sets none of them.
func clearModeEnvVars() {
	envVars := []string{
		EnvMCPStaticPoliciesEnabled, EnvGatewayStaticPoliciesEnabled,
		EnvMCPStaticPoliciesSkipCategories, EnvGatewayStaticPoliciesSkipCategories,
		EnvMCPStaticPoliciesConnectors,
	}
	envVars = append(envVars, RemovedPostureEnvVars...)
	for _, env := range envVars {
		os.Unsetenv(env)
	}
}

func TestMCPDetectionConfigFromEnv_Defaults(t *testing.T) {
	clearModeEnvVars()
	defer clearModeEnvVars()

	cfg := MCPDetectionConfigFromEnv()

	if !cfg.Enabled {
		t.Error("Expected MCP static policies enabled by default")
	}
	// No action is set by the environment (#3961): the action fields hold only
	// an organization's recorded override, and a config read from the
	// environment has none.
	if cfg.PIIAction != "" || cfg.SQLIAction != "" || cfg.DangerousQueryAction != "" || cfg.DangerousCommandAction != "" {
		t.Errorf("a config read from the environment carries actions %+v; only a recorded override may set one", cfg)
	}
	if len(cfg.SkipCategories) != 0 {
		t.Errorf("SkipCategories: got %v, expected empty", cfg.SkipCategories)
	}
	if len(cfg.Connectors) != 0 {
		t.Errorf("Connectors: got %v, expected empty", cfg.Connectors)
	}
}

func TestGatewayDetectionConfigFromEnv_Defaults(t *testing.T) {
	clearModeEnvVars()
	defer clearModeEnvVars()

	cfg := GatewayDetectionConfigFromEnv()

	if !cfg.Enabled {
		t.Error("Expected Gateway static policies enabled by default")
	}
	if cfg.PIIAction != "" || cfg.SQLIAction != "" || cfg.DangerousQueryAction != "" || cfg.DangerousCommandAction != "" {
		t.Errorf("a config read from the environment carries actions %+v; only a recorded override may set one", cfg)
	}
}

// TestModeDetectionConfigFromEnv_RemovedVariablesSetNoAction is the #3961
// invariant stated as a test: with EVERY removed detection-posture variable set
// - to a blocking value and to a relaxing one - neither mode config carries an
// action and neither builds an action override, so every stored policy action
// stands.
func TestModeDetectionConfigFromEnv_RemovedVariablesSetNoAction(t *testing.T) {
	for _, value := range []string{"block", "warn", "log", "redact", "strict", "dev", "all", "true"} {
		t.Run(value, func(t *testing.T) {
			clearModeEnvVars()
			for _, name := range RemovedPostureEnvVars {
				t.Setenv(name, value)
			}
			ResetDetectionConfigCache()
			t.Cleanup(ResetDetectionConfigCache)
			InitDetectionConfigs()

			for label, cfg := range map[string]ModeDetectionConfig{
				"MCPDetectionConfigFromEnv":     MCPDetectionConfigFromEnv(),
				"GatewayDetectionConfigFromEnv": GatewayDetectionConfigFromEnv(),
				"GetMCPDetectionConfig":         GetMCPDetectionConfig(),
				"GetGatewayDetectionConfig":     GetGatewayDetectionConfig(),
			} {
				if cfg.PIIAction != "" || cfg.SQLIAction != "" || cfg.DangerousQueryAction != "" || cfg.DangerousCommandAction != "" {
					t.Errorf("%s with every removed variable = %q carries actions %+v", label, value, cfg)
				}
				if overrides := cfg.BuildActionOverrides(); len(overrides) != 0 {
					t.Errorf("%s with every removed variable = %q builds action overrides %v: a stored action would be displaced by the environment", label, value, overrides)
				}
				if !cfg.Enabled {
					t.Errorf("%s: a removed posture variable disabled static policy evaluation", label)
				}
			}
		})
	}
}

func TestMCPDetectionConfigFromEnv_Disabled(t *testing.T) {
	clearModeEnvVars()
	defer clearModeEnvVars()

	os.Setenv(EnvMCPStaticPoliciesEnabled, "false")

	cfg := MCPDetectionConfigFromEnv()

	if cfg.Enabled {
		t.Error("Expected MCP static policies disabled")
	}
}

func TestMCPDetectionConfigFromEnv_SkipCategories(t *testing.T) {
	clearModeEnvVars()
	defer clearModeEnvVars()

	os.Setenv(EnvMCPStaticPoliciesSkipCategories, "pii-global, pii-us")

	cfg := MCPDetectionConfigFromEnv()

	if len(cfg.SkipCategories) != 2 {
		t.Fatalf("Expected 2 skip categories, got %d: %v", len(cfg.SkipCategories), cfg.SkipCategories)
	}
	if cfg.SkipCategories[0] != "pii-global" {
		t.Errorf("Expected first skip category 'pii-global', got %s", cfg.SkipCategories[0])
	}
	if cfg.SkipCategories[1] != "pii-us" {
		t.Errorf("Expected second skip category 'pii-us', got %s", cfg.SkipCategories[1])
	}
}

func TestMCPDetectionConfigFromEnv_ConnectorsIgnoredWithoutEnterprise(t *testing.T) {
	clearModeEnvVars()
	defer clearModeEnvVars()

	// Without enterprise license, connectors should be ignored
	os.Setenv(EnvMCPStaticPoliciesConnectors, "postgres,mysql")
	// Ensure no enterprise license is set
	os.Unsetenv("AXONFLOW_LICENSE_KEY")

	cfg := MCPDetectionConfigFromEnv()

	if len(cfg.Connectors) != 0 {
		t.Errorf("Expected connectors to be empty without enterprise license, got %v", cfg.Connectors)
	}
}

func TestGatewayDetectionConfigFromEnv_Disabled(t *testing.T) {
	clearModeEnvVars()
	defer clearModeEnvVars()

	os.Setenv(EnvGatewayStaticPoliciesEnabled, "false")

	cfg := GatewayDetectionConfigFromEnv()

	if cfg.Enabled {
		t.Error("Expected Gateway static policies disabled")
	}
}

func TestGatewayDetectionConfigFromEnv_SkipCategories(t *testing.T) {
	clearModeEnvVars()
	defer clearModeEnvVars()

	os.Setenv(EnvGatewayStaticPoliciesSkipCategories, "security-sqli")

	cfg := GatewayDetectionConfigFromEnv()

	if len(cfg.SkipCategories) != 1 {
		t.Fatalf("Expected 1 skip category, got %d", len(cfg.SkipCategories))
	}
	if cfg.SkipCategories[0] != "security-sqli" {
		t.Errorf("Expected 'security-sqli', got %s", cfg.SkipCategories[0])
	}
}

// TestBuildActionOverrides_OnlyRecordedOverrides pins the shape of the map the
// shared engine receives: a category appears only when the organization's
// override for it is set, and then with exactly that action.
func TestBuildActionOverrides_OnlyRecordedOverrides(t *testing.T) {
	piiCats := []sharedpolicy.PolicyCategory{
		sharedpolicy.CategoryPIIGlobal, sharedpolicy.CategoryPIIUS, sharedpolicy.CategoryPIIIndia,
		sharedpolicy.CategoryPIIEU, sharedpolicy.CategoryPIISingapore, sharedpolicy.CategoryPIIIndonesia,
	}

	t.Run("no override builds an empty map", func(t *testing.T) {
		cfg := ModeDetectionConfig{Enabled: true}
		if got := cfg.BuildActionOverrides(); len(got) != 0 {
			t.Errorf("got %v, want no override", got)
		}
	})

	t.Run("a pii override reaches every pii category and nothing else", func(t *testing.T) {
		cfg := ModeDetectionConfig{Enabled: true, PIIAction: DetectionActionRedact}
		got := cfg.BuildActionOverrides()
		if len(got) != len(piiCats) {
			t.Errorf("got %d categories %v, want exactly the %d pii categories", len(got), got, len(piiCats))
		}
		for _, cat := range piiCats {
			if got[cat] != sharedpolicy.ActionRedact {
				t.Errorf("%s: got %q, want redact", cat, got[cat])
			}
		}
	})

	t.Run("sqli and dangerous_command reach their own category", func(t *testing.T) {
		cfg := ModeDetectionConfig{Enabled: true, SQLIAction: DetectionActionBlock, DangerousCommandAction: DetectionActionWarn}
		got := cfg.BuildActionOverrides()
		if len(got) != 2 || got[sharedpolicy.CategorySecuritySQLi] != sharedpolicy.ActionBlock ||
			got[sharedpolicy.CategorySecurityDangerous] != sharedpolicy.ActionWarn {
			t.Errorf("got %v, want security-sqli=block and security-dangerous=warn only", got)
		}
	})

	t.Run("dangerous_query maps to no category and sensitive-data is never overridden", func(t *testing.T) {
		cfg := ModeDetectionConfig{Enabled: true, DangerousQueryAction: DetectionActionBlock}
		got := cfg.BuildActionOverrides()
		if len(got) != 0 {
			t.Errorf("got %v, want none", got)
		}
		full := ModeDetectionConfig{PIIAction: DetectionActionBlock, SQLIAction: DetectionActionBlock, DangerousQueryAction: DetectionActionBlock, DangerousCommandAction: DetectionActionBlock}
		if _, ok := full.BuildActionOverrides()[sharedpolicy.CategorySensitiveData]; ok {
			t.Error("sensitive-data was overridden; the override table has no category for it")
		}
	})
}

func TestIsConnectorEnabled(t *testing.T) {
	tests := []struct {
		name       string
		connectors []string
		connector  string
		expected   bool
	}{
		{"empty list enables all", nil, "postgres", true},
		{"empty slice enables all", []string{}, "postgres", true},
		{"connector in list", []string{"postgres", "mysql"}, "postgres", true},
		{"connector not in list", []string{"postgres", "mysql"}, "redis", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := ModeDetectionConfig{Connectors: tt.connectors}
			if got := cfg.IsConnectorEnabled(tt.connector); got != tt.expected {
				t.Errorf("IsConnectorEnabled(%q) = %v, expected %v", tt.connector, got, tt.expected)
			}
		})
	}
}

func TestParseBoolEnv(t *testing.T) {
	tests := []struct {
		name       string
		value      string
		defaultVal bool
		expected   bool
	}{
		{"empty uses default true", "", true, true},
		{"empty uses default false", "", false, false},
		{"true", "true", false, true},
		{"TRUE", "TRUE", false, true},
		{"1", "1", false, true},
		{"yes", "yes", false, true},
		{"false", "false", true, false},
		{"FALSE", "FALSE", true, false},
		{"0", "0", true, false},
		{"no", "no", true, false},
		{"invalid uses default", "invalid", true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envName := "TEST_PARSE_BOOL"
			os.Unsetenv(envName)
			if tt.value != "" {
				os.Setenv(envName, tt.value)
				defer os.Unsetenv(envName)
			}
			if got := parseBoolEnv(envName, tt.defaultVal); got != tt.expected {
				t.Errorf("parseBoolEnv(%q, %v) = %v, expected %v", tt.value, tt.defaultVal, got, tt.expected)
			}
		})
	}
}

func TestParseCategoryList(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"empty string", "", 0},
		{"single category", "pii-global", 1},
		{"multiple categories", "pii-global,pii-us,pii-india", 3},
		{"with spaces", " pii-global , pii-us ", 2},
		{"trailing comma", "pii-global,", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseCategoryList(tt.input)
			if len(result) != tt.expected {
				t.Errorf("parseCategoryList(%q) returned %d categories, expected %d", tt.input, len(result), tt.expected)
			}
		})
	}
}

func TestParseCSV(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"empty string", "", 0},
		{"single value", "postgres", 1},
		{"multiple values", "postgres,mysql,redis", 3},
		{"with spaces", " postgres , mysql ", 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseCSV(tt.input)
			if len(result) != tt.expected {
				t.Errorf("parseCSV(%q) returned %d values, expected %d", tt.input, len(result), tt.expected)
			}
		})
	}
}

func TestToPolicyAction(t *testing.T) {
	tests := []struct {
		action   DetectionAction
		expected sharedpolicy.Action
	}{
		{DetectionActionBlock, sharedpolicy.ActionBlock},
		{DetectionActionRedact, sharedpolicy.ActionRedact},
		{DetectionActionWarn, sharedpolicy.ActionWarn},
		{DetectionActionLog, sharedpolicy.ActionLog},
		{DetectionAction("unknown"), sharedpolicy.ActionBlock},
	}

	for _, tt := range tests {
		t.Run(string(tt.action), func(t *testing.T) {
			if got := tt.action.ToPolicyAction(); got != tt.expected {
				t.Errorf("ToPolicyAction() = %s, expected %s", got, tt.expected)
			}
		})
	}
}

// TestMCPAndGatewayIndependentConfig pins that the two mode configs read their
// own switches.
func TestMCPAndGatewayIndependentConfig(t *testing.T) {
	clearModeEnvVars()
	defer clearModeEnvVars()

	os.Setenv(EnvMCPStaticPoliciesEnabled, "false")
	os.Setenv(EnvGatewayStaticPoliciesSkipCategories, "security-sqli")

	mcpCfg := MCPDetectionConfigFromEnv()
	gwCfg := GatewayDetectionConfigFromEnv()

	if mcpCfg.Enabled {
		t.Error("MCP: expected disabled")
	}
	if !gwCfg.Enabled {
		t.Error("Gateway: expected enabled (MCP's switch must not reach it)")
	}
	if len(mcpCfg.SkipCategories) != 0 {
		t.Errorf("MCP SkipCategories: got %v, want none (the gateway list must not reach it)", mcpCfg.SkipCategories)
	}
	if len(gwCfg.SkipCategories) != 1 || gwCfg.SkipCategories[0] != "security-sqli" {
		t.Errorf("Gateway SkipCategories: got %v, want [security-sqli]", gwCfg.SkipCategories)
	}
}

func TestDetectionConfigCache_ReturnsStartupValues(t *testing.T) {
	ResetDetectionConfigCache()
	t.Cleanup(ResetDetectionConfigCache)

	t.Setenv(EnvMCPStaticPoliciesEnabled, "false")
	t.Setenv(EnvGatewayStaticPoliciesSkipCategories, "pii-us")
	InitDetectionConfigs()

	if GetMCPDetectionConfig().Enabled {
		t.Error("cached MCP config: expected disabled")
	}
	if got := GetGatewayDetectionConfig().SkipCategories; len(got) != 1 || got[0] != "pii-us" {
		t.Errorf("cached Gateway SkipCategories: got %v, want [pii-us]", got)
	}

	// Change env vars - cached values must NOT change.
	t.Setenv(EnvMCPStaticPoliciesEnabled, "true")
	t.Setenv(EnvGatewayStaticPoliciesSkipCategories, "")
	if GetMCPDetectionConfig().Enabled {
		t.Error("cache should be stable after an env change: MCP became enabled")
	}
	if got := GetGatewayDetectionConfig().SkipCategories; len(got) != 1 {
		t.Errorf("cache should be stable after an env change: Gateway SkipCategories became %v", got)
	}

	// Reset + re-init picks up the new values.
	ResetDetectionConfigCache()
	InitDetectionConfigs()
	if !GetMCPDetectionConfig().Enabled {
		t.Error("after reset+reinit: expected MCP enabled")
	}
}

func TestDetectionConfigCache_FallbackWhenNotInitialized(t *testing.T) {
	ResetDetectionConfigCache()
	t.Cleanup(ResetDetectionConfigCache)

	t.Setenv(EnvMCPStaticPoliciesEnabled, "false")

	// Without InitDetectionConfigs(), resolution parses the environment.
	if GetMCPDetectionConfig().Enabled {
		t.Error("fallback should parse from env: expected MCP disabled")
	}
}

// TestReportIgnoredPostureEnv pins the boot census: one WARN line naming the
// variable, its value and what now decides, one counter increment per set
// variable, and nothing for an unset or empty one.
func TestReportIgnoredPostureEnv(t *testing.T) {
	clearModeEnvVars()
	t.Cleanup(clearModeEnvVars)
	t.Setenv("PII_ACTION", "warn")
	t.Setenv("AXONFLOW_PROFILE", "strict")
	t.Setenv("MCP_SQLI_ACTION", "") // set but empty: chose nothing, reported as nothing

	beforePII := testutil.ToFloat64(ignoredPostureEnvTotal.WithLabelValues("PII_ACTION"))
	beforeProfile := testutil.ToFloat64(ignoredPostureEnvTotal.WithLabelValues("AXONFLOW_PROFILE"))
	beforeEmpty := testutil.ToFloat64(ignoredPostureEnvTotal.WithLabelValues("MCP_SQLI_ACTION"))

	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	found := ReportIgnoredPostureEnv("agent")
	log.SetOutput(old)
	out := buf.String()

	if len(found) != 2 || found[0] != "PII_ACTION" || found[1] != "AXONFLOW_PROFILE" {
		t.Errorf("reported %v, want [PII_ACTION AXONFLOW_PROFILE] in RemovedPostureEnvVars order", found)
	}
	for _, want := range []string{
		"WARN [agent] detection posture env var ignored: PII_ACTION=warn no longer sets an action (v11); the stored policy action decides - see release notes",
		"WARN [agent] detection posture env var ignored: AXONFLOW_PROFILE=strict no longer sets an action (v11); the stored policy action decides - see release notes",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("boot log is missing %q; got:\n%s", want, out)
		}
	}
	if strings.Contains(out, "MCP_SQLI_ACTION") {
		t.Errorf("an empty variable was reported: %s", out)
	}
	if got := testutil.ToFloat64(ignoredPostureEnvTotal.WithLabelValues("PII_ACTION")) - beforePII; got != 1 {
		t.Errorf("axonflow_ignored_posture_env_total{name=PII_ACTION} moved by %v, want 1", got)
	}
	if got := testutil.ToFloat64(ignoredPostureEnvTotal.WithLabelValues("AXONFLOW_PROFILE")) - beforeProfile; got != 1 {
		t.Errorf("axonflow_ignored_posture_env_total{name=AXONFLOW_PROFILE} moved by %v, want 1", got)
	}
	if got := testutil.ToFloat64(ignoredPostureEnvTotal.WithLabelValues("MCP_SQLI_ACTION")) - beforeEmpty; got != 0 {
		t.Errorf("an empty variable moved the counter by %v", got)
	}

	// Nothing set: nothing reported.
	clearModeEnvVars()
	buf.Reset()
	log.SetOutput(&buf)
	none := ReportIgnoredPostureEnv("agent")
	log.SetOutput(old)
	if len(none) != 0 || strings.Contains(buf.String(), "detection posture env var ignored") {
		t.Errorf("with no removed variable set, reported %v and logged %q", none, buf.String())
	}
}

// TestRemovedPostureEnvVarsNameEveryLever holds the census list to the names
// the #3961 ruling removes. A name dropped from the list would stop being
// reported while still being ignored, so a deployment setting it would learn
// nothing at boot.
func TestRemovedPostureEnvVarsNameEveryLever(t *testing.T) {
	want := []string{
		"PII_ACTION", "SQLI_ACTION", "DANGEROUS_COMMAND_ACTION", "SENSITIVE_DATA_ACTION",
		"MCP_PII_ACTION", "MCP_SQLI_ACTION", "MCP_DANGEROUS_QUERY_ACTION", "MCP_DANGEROUS_COMMAND_ACTION",
		"GATEWAY_PII_ACTION", "GATEWAY_SQLI_ACTION", "GATEWAY_DANGEROUS_QUERY_ACTION", "GATEWAY_DANGEROUS_COMMAND_ACTION",
		"SQLI_BLOCK_MODE", "PII_BLOCK_CRITICAL", "DANGEROUS_QUERY_ACTION", "HIGH_RISK_ACTION",
		"AXONFLOW_PROFILE", "AXONFLOW_ENFORCE",
	}
	have := map[string]bool{}
	for _, n := range RemovedPostureEnvVars {
		if have[n] {
			t.Errorf("%s is listed twice", n)
		}
		have[n] = true
	}
	for _, n := range want {
		if !have[n] {
			t.Errorf("RemovedPostureEnvVars does not name %s", n)
		}
	}
	if len(have) != len(want) {
		t.Errorf("RemovedPostureEnvVars names %d variables, want %d", len(have), len(want))
	}
}
