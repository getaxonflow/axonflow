package sqli

import (
	"os"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	t.Run("input mode is basic", func(t *testing.T) {
		if cfg.InputMode != ModeBasic {
			t.Errorf("InputMode = %v, want %v", cfg.InputMode, ModeBasic)
		}
	})

	t.Run("response mode is basic", func(t *testing.T) {
		if cfg.ResponseMode != ModeBasic {
			t.Errorf("ResponseMode = %v, want %v", cfg.ResponseMode, ModeBasic)
		}
	})

	t.Run("block on detection is false (monitoring mode)", func(t *testing.T) {
		if cfg.BlockOnDetection {
			t.Error("BlockOnDetection should be false by default (monitoring mode)")
		}
	})

	t.Run("log detections is true", func(t *testing.T) {
		if !cfg.LogDetections {
			t.Error("LogDetections should be true by default")
		}
	})

	t.Run("audit trail is enabled", func(t *testing.T) {
		if !cfg.AuditTrailEnabled {
			t.Error("AuditTrailEnabled should be true by default")
		}
	})

	t.Run("max content length is 1MB", func(t *testing.T) {
		if cfg.MaxContentLength != 1048576 {
			t.Errorf("MaxContentLength = %d, want %d", cfg.MaxContentLength, 1048576)
		}
	})

	t.Run("connector overrides is initialized", func(t *testing.T) {
		if cfg.ConnectorOverrides == nil {
			t.Error("ConnectorOverrides should be initialized")
		}
	})
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name:    "default config is valid",
			config:  DefaultConfig(),
			wantErr: false,
		},
		{
			name: "all off modes is valid",
			config: Config{
				InputMode:        ModeOff,
				ResponseMode:     ModeOff,
				MaxContentLength: 1000,
			},
			wantErr: false,
		},
		{
			name: "advanced modes are valid",
			config: Config{
				InputMode:        ModeAdvanced,
				ResponseMode:     ModeAdvanced,
				MaxContentLength: 1000,
			},
			wantErr: false,
		},
		{
			name: "invalid input mode",
			config: Config{
				InputMode:        Mode("invalid"),
				ResponseMode:     ModeBasic,
				MaxContentLength: 1000,
			},
			wantErr: true,
		},
		{
			name: "invalid response mode",
			config: Config{
				InputMode:        ModeBasic,
				ResponseMode:     Mode("invalid"),
				MaxContentLength: 1000,
			},
			wantErr: true,
		},
		{
			name: "zero max content length",
			config: Config{
				InputMode:        ModeBasic,
				ResponseMode:     ModeBasic,
				MaxContentLength: 0,
			},
			wantErr: true,
		},
		{
			name: "negative max content length",
			config: Config{
				InputMode:        ModeBasic,
				ResponseMode:     ModeBasic,
				MaxContentLength: -1,
			},
			wantErr: true,
		},
		{
			name: "invalid connector override mode",
			config: Config{
				InputMode:        ModeBasic,
				ResponseMode:     ModeBasic,
				MaxContentLength: 1000,
				ConnectorOverrides: map[string]ConnectorConfig{
					"postgresql": {ResponseMode: Mode("invalid")},
				},
			},
			wantErr: true,
		},
		{
			name: "empty connector override mode is valid",
			config: Config{
				InputMode:        ModeBasic,
				ResponseMode:     ModeBasic,
				MaxContentLength: 1000,
				ConnectorOverrides: map[string]ConnectorConfig{
					"postgresql": {ResponseMode: "", Enabled: true},
				},
			},
			wantErr: false,
		},
		{
			name: "valid connector override",
			config: Config{
				InputMode:        ModeBasic,
				ResponseMode:     ModeBasic,
				MaxContentLength: 1000,
				ConnectorOverrides: map[string]ConnectorConfig{
					"postgresql": {ResponseMode: ModeAdvanced, Enabled: true},
					"redis":      {ResponseMode: ModeOff, Enabled: false},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfig_GetResponseModeForConnector(t *testing.T) {
	tests := []struct {
		name          string
		config        Config
		connectorName string
		want          Mode
	}{
		{
			name: "no override returns default",
			config: Config{
				ResponseMode: ModeBasic,
			},
			connectorName: "postgresql",
			want:          ModeBasic,
		},
		{
			name: "override returns override mode",
			config: Config{
				ResponseMode: ModeBasic,
				ConnectorOverrides: map[string]ConnectorConfig{
					"postgresql": {ResponseMode: ModeAdvanced},
				},
			},
			connectorName: "postgresql",
			want:          ModeAdvanced,
		},
		{
			name: "different connector returns default",
			config: Config{
				ResponseMode: ModeBasic,
				ConnectorOverrides: map[string]ConnectorConfig{
					"postgresql": {ResponseMode: ModeAdvanced},
				},
			},
			connectorName: "mysql",
			want:          ModeBasic,
		},
		{
			name: "empty override mode returns default",
			config: Config{
				ResponseMode: ModeBasic,
				ConnectorOverrides: map[string]ConnectorConfig{
					"postgresql": {ResponseMode: ""},
				},
			},
			connectorName: "postgresql",
			want:          ModeBasic,
		},
		{
			name: "off mode override",
			config: Config{
				ResponseMode: ModeBasic,
				ConnectorOverrides: map[string]ConnectorConfig{
					"redis": {ResponseMode: ModeOff},
				},
			},
			connectorName: "redis",
			want:          ModeOff,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.GetResponseModeForConnector(tt.connectorName)
			if got != tt.want {
				t.Errorf("GetResponseModeForConnector(%q) = %v, want %v", tt.connectorName, got, tt.want)
			}
		})
	}
}

func TestConfig_IsConnectorEnabled(t *testing.T) {
	tests := []struct {
		name          string
		config        Config
		connectorName string
		want          bool
	}{
		{
			name:          "no override returns true",
			config:        Config{},
			connectorName: "postgresql",
			want:          true,
		},
		{
			name: "enabled override returns true",
			config: Config{
				ConnectorOverrides: map[string]ConnectorConfig{
					"postgresql": {Enabled: true},
				},
			},
			connectorName: "postgresql",
			want:          true,
		},
		{
			name: "disabled override returns false",
			config: Config{
				ConnectorOverrides: map[string]ConnectorConfig{
					"redis": {Enabled: false},
				},
			},
			connectorName: "redis",
			want:          false,
		},
		{
			name: "different connector returns true",
			config: Config{
				ConnectorOverrides: map[string]ConnectorConfig{
					"redis": {Enabled: false},
				},
			},
			connectorName: "postgresql",
			want:          true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.IsConnectorEnabled(tt.connectorName)
			if got != tt.want {
				t.Errorf("IsConnectorEnabled(%q) = %v, want %v", tt.connectorName, got, tt.want)
			}
		})
	}
}

func TestConfig_WithInputMode(t *testing.T) {
	cfg := DefaultConfig()
	newCfg := cfg.WithInputMode(ModeOff)

	if newCfg.InputMode != ModeOff {
		t.Errorf("WithInputMode: InputMode = %v, want %v", newCfg.InputMode, ModeOff)
	}
	// Original should be unchanged
	if cfg.InputMode != ModeBasic {
		t.Errorf("Original config was modified: InputMode = %v, want %v", cfg.InputMode, ModeBasic)
	}
}

func TestConfig_WithResponseMode(t *testing.T) {
	cfg := DefaultConfig()
	newCfg := cfg.WithResponseMode(ModeAdvanced)

	if newCfg.ResponseMode != ModeAdvanced {
		t.Errorf("WithResponseMode: ResponseMode = %v, want %v", newCfg.ResponseMode, ModeAdvanced)
	}
	// Original should be unchanged
	if cfg.ResponseMode != ModeBasic {
		t.Errorf("Original config was modified: ResponseMode = %v, want %v", cfg.ResponseMode, ModeBasic)
	}
}

func TestConfig_WithBlockOnDetection(t *testing.T) {
	cfg := DefaultConfig() // Default is false (monitoring mode)
	newCfg := cfg.WithBlockOnDetection(true)

	if newCfg.BlockOnDetection != true {
		t.Error("WithBlockOnDetection(true): BlockOnDetection should be true")
	}
	// Original should be unchanged
	if cfg.BlockOnDetection {
		t.Error("Original config was modified: BlockOnDetection should still be false")
	}
}

func TestConfig_WithConnectorOverride(t *testing.T) {
	cfg := DefaultConfig()
	override := ConnectorConfig{
		ResponseMode: ModeOff,
		Enabled:      false,
	}
	newCfg := cfg.WithConnectorOverride("redis", override)

	got, ok := newCfg.ConnectorOverrides["redis"]
	if !ok {
		t.Fatal("WithConnectorOverride: redis override not found")
	}
	if got.ResponseMode != ModeOff {
		t.Errorf("WithConnectorOverride: ResponseMode = %v, want %v", got.ResponseMode, ModeOff)
	}
	if got.Enabled != false {
		t.Error("WithConnectorOverride: Enabled should be false")
	}

	// Original should not have the override
	if _, ok := cfg.ConnectorOverrides["redis"]; ok {
		t.Error("Original config was modified: redis override should not exist")
	}
}

func TestConfig_WithConnectorOverride_NilMap(t *testing.T) {
	cfg := Config{
		InputMode:          ModeBasic,
		ResponseMode:       ModeBasic,
		ConnectorOverrides: nil, // nil map
	}

	override := ConnectorConfig{ResponseMode: ModeOff}
	newCfg := cfg.WithConnectorOverride("redis", override)

	if newCfg.ConnectorOverrides == nil {
		t.Fatal("WithConnectorOverride should initialize nil map")
	}
	if _, ok := newCfg.ConnectorOverrides["redis"]; !ok {
		t.Error("WithConnectorOverride: redis override not found")
	}
}

func TestConfig_ChainedWith(t *testing.T) {
	cfg := DefaultConfig().
		WithInputMode(ModeAdvanced).
		WithResponseMode(ModeOff).
		WithBlockOnDetection(false).
		WithConnectorOverride("postgresql", ConnectorConfig{ResponseMode: ModeBasic})

	if cfg.InputMode != ModeAdvanced {
		t.Errorf("Chained InputMode = %v, want %v", cfg.InputMode, ModeAdvanced)
	}
	if cfg.ResponseMode != ModeOff {
		t.Errorf("Chained ResponseMode = %v, want %v", cfg.ResponseMode, ModeOff)
	}
	if cfg.BlockOnDetection {
		t.Error("Chained BlockOnDetection should be false")
	}
	if override, ok := cfg.ConnectorOverrides["postgresql"]; !ok || override.ResponseMode != ModeBasic {
		t.Error("Chained ConnectorOverride not set correctly")
	}
}

// TestConfigFromEnv_DefaultValues tests that ConfigFromEnv returns sensible defaults
// when no environment variables are set.
func TestConfigFromEnv_DefaultValues(t *testing.T) {
	// Clear any existing env vars
	os.Unsetenv(EnvSQLIScannerMode)
	os.Unsetenv(EnvSQLIBlockMode)

	cfg := ConfigFromEnv()

	t.Run("default scanner mode is basic", func(t *testing.T) {
		if cfg.InputMode != ModeBasic {
			t.Errorf("InputMode = %v, want %v", cfg.InputMode, ModeBasic)
		}
		if cfg.ResponseMode != ModeBasic {
			t.Errorf("ResponseMode = %v, want %v", cfg.ResponseMode, ModeBasic)
		}
	})

	t.Run("default block mode is block (true)", func(t *testing.T) {
		if !cfg.BlockOnDetection {
			t.Error("BlockOnDetection should be true by default")
		}
	})
}

// TestConfigFromEnv_ScannerMode tests SQLI_SCANNER_MODE parsing.
func TestConfigFromEnv_ScannerMode(t *testing.T) {
	tests := []struct {
		name         string
		envValue     string
		expectedMode Mode
	}{
		{"off mode", "off", ModeOff},
		{"basic mode", "basic", ModeBasic},
		{"advanced mode", "advanced", ModeAdvanced},
		{"off mode uppercase", "OFF", ModeOff},
		{"basic mode uppercase", "BASIC", ModeBasic},
		{"advanced mode uppercase", "ADVANCED", ModeAdvanced},
		{"basic mode mixed case", "Basic", ModeBasic},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv(EnvSQLIScannerMode, tt.envValue)
			os.Unsetenv(EnvSQLIBlockMode)
			defer os.Unsetenv(EnvSQLIScannerMode)

			cfg := ConfigFromEnv()

			if cfg.InputMode != tt.expectedMode {
				t.Errorf("InputMode = %v, want %v", cfg.InputMode, tt.expectedMode)
			}
			if cfg.ResponseMode != tt.expectedMode {
				t.Errorf("ResponseMode = %v, want %v", cfg.ResponseMode, tt.expectedMode)
			}
		})
	}
}

// TestConfigFromEnv_InvalidScannerMode tests fallback for invalid SQLI_SCANNER_MODE.
func TestConfigFromEnv_InvalidScannerMode(t *testing.T) {
	invalidModes := []string{"invalid", "super", "123", "enabled", "disabled"}

	for _, mode := range invalidModes {
		t.Run("invalid mode "+mode, func(t *testing.T) {
			os.Setenv(EnvSQLIScannerMode, mode)
			os.Unsetenv(EnvSQLIBlockMode)
			defer os.Unsetenv(EnvSQLIScannerMode)

			cfg := ConfigFromEnv()

			// Should fall back to basic mode
			if cfg.InputMode != ModeBasic {
				t.Errorf("InputMode = %v, want %v (fallback)", cfg.InputMode, ModeBasic)
			}
			if cfg.ResponseMode != ModeBasic {
				t.Errorf("ResponseMode = %v, want %v (fallback)", cfg.ResponseMode, ModeBasic)
			}
		})
	}
}

// TestConfigFromEnv_BlockMode tests SQLI_BLOCK_MODE parsing.
func TestConfigFromEnv_BlockMode(t *testing.T) {
	tests := []struct {
		name          string
		envValue      string
		expectedBlock bool
	}{
		{"block mode", "block", true},
		{"warn mode", "warn", false},
		{"block mode uppercase", "BLOCK", true},
		{"warn mode uppercase", "WARN", false},
		{"block mode mixed case", "Block", true},
		{"warn mode mixed case", "Warn", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Unsetenv(EnvSQLIScannerMode)
			os.Setenv(EnvSQLIBlockMode, tt.envValue)
			defer os.Unsetenv(EnvSQLIBlockMode)

			cfg := ConfigFromEnv()

			if cfg.BlockOnDetection != tt.expectedBlock {
				t.Errorf("BlockOnDetection = %v, want %v", cfg.BlockOnDetection, tt.expectedBlock)
			}
		})
	}
}

// TestConfigFromEnv_InvalidBlockMode tests fallback for invalid SQLI_BLOCK_MODE.
func TestConfigFromEnv_InvalidBlockMode(t *testing.T) {
	invalidModes := []string{"invalid", "log", "123", "on", "off", "true", "false"}

	for _, mode := range invalidModes {
		t.Run("invalid block mode "+mode, func(t *testing.T) {
			os.Unsetenv(EnvSQLIScannerMode)
			os.Setenv(EnvSQLIBlockMode, mode)
			defer os.Unsetenv(EnvSQLIBlockMode)

			cfg := ConfigFromEnv()

			// Should fall back to block mode (security-first)
			if !cfg.BlockOnDetection {
				t.Errorf("BlockOnDetection = false, want true (fallback to block for security)")
			}
		})
	}
}

// TestConfigFromEnv_CombinedSettings tests both environment variables together.
func TestConfigFromEnv_CombinedSettings(t *testing.T) {
	tests := []struct {
		name          string
		scannerMode   string
		blockMode     string
		expectedMode  Mode
		expectedBlock bool
	}{
		{"off mode with warn", "off", "warn", ModeOff, false},
		{"off mode with block", "off", "block", ModeOff, true},
		{"basic mode with warn", "basic", "warn", ModeBasic, false},
		{"basic mode with block", "basic", "block", ModeBasic, true},
		{"advanced mode with warn", "advanced", "warn", ModeAdvanced, false},
		{"advanced mode with block", "advanced", "block", ModeAdvanced, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv(EnvSQLIScannerMode, tt.scannerMode)
			os.Setenv(EnvSQLIBlockMode, tt.blockMode)
			defer func() {
				os.Unsetenv(EnvSQLIScannerMode)
				os.Unsetenv(EnvSQLIBlockMode)
			}()

			cfg := ConfigFromEnv()

			if cfg.InputMode != tt.expectedMode {
				t.Errorf("InputMode = %v, want %v", cfg.InputMode, tt.expectedMode)
			}
			if cfg.ResponseMode != tt.expectedMode {
				t.Errorf("ResponseMode = %v, want %v", cfg.ResponseMode, tt.expectedMode)
			}
			if cfg.BlockOnDetection != tt.expectedBlock {
				t.Errorf("BlockOnDetection = %v, want %v", cfg.BlockOnDetection, tt.expectedBlock)
			}
		})
	}
}

// TestEnvVarConstants tests that environment variable constants are correct.
func TestEnvVarConstants(t *testing.T) {
	if EnvSQLIScannerMode != "SQLI_SCANNER_MODE" {
		t.Errorf("EnvSQLIScannerMode = %q, want %q", EnvSQLIScannerMode, "SQLI_SCANNER_MODE")
	}
	if EnvSQLIBlockMode != "SQLI_BLOCK_MODE" {
		t.Errorf("EnvSQLIBlockMode = %q, want %q", EnvSQLIBlockMode, "SQLI_BLOCK_MODE")
	}
}
