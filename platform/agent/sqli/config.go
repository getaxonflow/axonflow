package sqli

import (
	"fmt"
	"log"
	"os"
	"strings"
)

// Config holds the SQL injection scanning configuration.
type Config struct {
	// InputMode is the scanning mode for user input/prompts.
	// Default: basic
	InputMode Mode `json:"input_mode" yaml:"input_mode"`

	// ResponseMode is the scanning mode for MCP connector responses.
	// Default: basic
	ResponseMode Mode `json:"response_mode" yaml:"response_mode"`

	// BlockOnDetection determines whether to block content when injection is detected.
	// If false, detection is logged but content is allowed through.
	// Default: true
	BlockOnDetection bool `json:"block_on_detection" yaml:"block_on_detection"`

	// LogDetections determines whether to log detection events.
	// Default: true
	LogDetections bool `json:"log_detections" yaml:"log_detections"`

	// AuditTrailEnabled determines whether to write detections to the audit trail.
	// Required for compliance (EU AI Act, RBI, SEBI).
	// Default: true
	AuditTrailEnabled bool `json:"audit_trail_enabled" yaml:"audit_trail_enabled"`

	// MaxContentLength is the maximum content length to scan (bytes).
	// Content exceeding this limit is truncated for scanning.
	// Default: 1MB (1048576)
	MaxContentLength int `json:"max_content_length" yaml:"max_content_length"`

	// ConnectorOverrides allows per-connector configuration overrides.
	// Key is the connector name (e.g., "postgresql", "salesforce").
	ConnectorOverrides map[string]ConnectorConfig `json:"connector_overrides,omitempty" yaml:"connector_overrides,omitempty"`
}

// ConnectorConfig holds per-connector scanning configuration.
type ConnectorConfig struct {
	// ResponseMode overrides the default response scanning mode for this connector.
	ResponseMode Mode `json:"response_mode" yaml:"response_mode"`

	// Enabled allows disabling scanning for specific connectors.
	// Default: true
	Enabled bool `json:"enabled" yaml:"enabled"`
}

// DefaultConfig returns the default configuration.
// Scanning is enabled by default in monitoring mode (detect and log, but don't block).
// Set BlockOnDetection to true after validating in your environment.
func DefaultConfig() Config {
	return Config{
		InputMode:         ModeBasic,
		ResponseMode:      ModeBasic,
		BlockOnDetection:  false, // Monitor mode: detect and log, don't block
		LogDetections:     true,
		AuditTrailEnabled: true,
		MaxContentLength:  1048576, // 1MB
		ConnectorOverrides: make(map[string]ConnectorConfig),
	}
}

// Environment variable names for SQL injection scanner configuration.
const (
	// EnvSQLIScannerMode sets the scanning mode for both input and response.
	// Valid values: "off", "basic", "advanced"
	// Default: "basic"
	EnvSQLIScannerMode = "SQLI_SCANNER_MODE"

	// EnvSQLIBlockMode sets whether to block or warn on detection.
	// Valid values: "block", "warn"
	// Default: "block"
	EnvSQLIBlockMode = "SQLI_BLOCK_MODE"
)

// ConfigFromEnv creates a configuration from environment variables.
// This allows runtime configuration without code changes.
//
// Environment variables:
//   - SQLI_SCANNER_MODE: off, basic, advanced (default: basic)
//   - SQLI_BLOCK_MODE: block, warn (default: block)
//
// Invalid values are logged and fall back to defaults.
func ConfigFromEnv() Config {
	cfg := DefaultConfig()

	// Parse SQLI_SCANNER_MODE
	if modeStr := os.Getenv(EnvSQLIScannerMode); modeStr != "" {
		mode, err := ParseMode(strings.ToLower(modeStr))
		if err != nil {
			log.Printf("[SQLi] WARNING: Invalid %s=%q, using default 'basic'. Valid values: off, basic, advanced",
				EnvSQLIScannerMode, modeStr)
		} else {
			cfg.InputMode = mode
			cfg.ResponseMode = mode
			log.Printf("[SQLi] Scanner mode set to %q from environment", mode)
		}
	}

	// Parse SQLI_BLOCK_MODE
	if blockStr := os.Getenv(EnvSQLIBlockMode); blockStr != "" {
		switch strings.ToLower(blockStr) {
		case "block":
			cfg.BlockOnDetection = true
			log.Printf("[SQLi] Block mode ENABLED - detections will be blocked")
		case "warn":
			cfg.BlockOnDetection = false
			log.Printf("[SQLi] Warn mode ENABLED - detections will be logged but not blocked")
		default:
			log.Printf("[SQLi] WARNING: Invalid %s=%q, using default 'block'. Valid values: block, warn",
				EnvSQLIBlockMode, blockStr)
			cfg.BlockOnDetection = true // Default to block for security
		}
	} else {
		// Default to block mode for security-first approach
		cfg.BlockOnDetection = true
	}

	return cfg
}

// Validate validates the configuration and returns any errors.
func (c *Config) Validate() error {
	var errs []string

	if !c.InputMode.IsValid() {
		errs = append(errs, fmt.Sprintf("invalid input_mode: %q", c.InputMode))
	}

	if !c.ResponseMode.IsValid() {
		errs = append(errs, fmt.Sprintf("invalid response_mode: %q", c.ResponseMode))
	}

	if c.MaxContentLength <= 0 {
		errs = append(errs, "max_content_length must be positive")
	}

	for name, override := range c.ConnectorOverrides {
		if !override.ResponseMode.IsValid() && override.ResponseMode != "" {
			errs = append(errs, fmt.Sprintf("invalid response_mode for connector %q: %q", name, override.ResponseMode))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("configuration errors: %s", strings.Join(errs, "; "))
	}

	return nil
}

// GetResponseModeForConnector returns the response scanning mode for a specific connector.
// Uses the connector override if configured, otherwise falls back to the default.
func (c *Config) GetResponseModeForConnector(connectorName string) Mode {
	if override, ok := c.ConnectorOverrides[connectorName]; ok {
		if override.ResponseMode != "" {
			return override.ResponseMode
		}
	}
	return c.ResponseMode
}

// IsConnectorEnabled returns whether scanning is enabled for a specific connector.
func (c *Config) IsConnectorEnabled(connectorName string) bool {
	if override, ok := c.ConnectorOverrides[connectorName]; ok {
		return override.Enabled
	}
	return true // Enabled by default
}

// WithInputMode returns a copy of the config with the input mode set.
func (c Config) WithInputMode(mode Mode) Config {
	c.InputMode = mode
	return c
}

// WithResponseMode returns a copy of the config with the response mode set.
func (c Config) WithResponseMode(mode Mode) Config {
	c.ResponseMode = mode
	return c
}

// WithBlockOnDetection returns a copy of the config with block on detection set.
func (c Config) WithBlockOnDetection(block bool) Config {
	c.BlockOnDetection = block
	return c
}

// WithConnectorOverride returns a copy of the config with a connector override added.
func (c Config) WithConnectorOverride(connectorName string, override ConnectorConfig) Config {
	// Deep copy the map to avoid modifying the original
	newOverrides := make(map[string]ConnectorConfig)
	for k, v := range c.ConnectorOverrides {
		newOverrides[k] = v
	}
	newOverrides[connectorName] = override
	c.ConnectorOverrides = newOverrides
	return c
}
