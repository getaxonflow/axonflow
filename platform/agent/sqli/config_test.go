package sqli

import (
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
