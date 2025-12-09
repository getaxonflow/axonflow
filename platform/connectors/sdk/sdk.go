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

package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"axonflow/platform/connectors/base"
)

// Version is the current SDK version
const Version = "1.0.0"

// ConnectorBuilder provides a fluent interface for building connectors
type ConnectorBuilder struct {
	name         string
	connType     string
	version      string
	capabilities []string
	authProvider AuthProvider
	rateLimiter  *RateLimiter
	retryConfig  *RetryConfig
	logger       *log.Logger
	validator    ConfigValidator
}

// NewConnectorBuilder creates a new connector builder
func NewConnectorBuilder(name, connType string) *ConnectorBuilder {
	return &ConnectorBuilder{
		name:         name,
		connType:     connType,
		version:      "1.0.0",
		capabilities: []string{},
		logger:       log.New(os.Stdout, fmt.Sprintf("[MCP_%s] ", connType), log.LstdFlags),
	}
}

// WithVersion sets the connector version
func (b *ConnectorBuilder) WithVersion(version string) *ConnectorBuilder {
	b.version = version
	return b
}

// WithCapabilities sets the connector capabilities
func (b *ConnectorBuilder) WithCapabilities(caps ...string) *ConnectorBuilder {
	b.capabilities = append(b.capabilities, caps...)
	return b
}

// WithAuth sets the authentication provider
func (b *ConnectorBuilder) WithAuth(auth AuthProvider) *ConnectorBuilder {
	b.authProvider = auth
	return b
}

// WithRateLimiter sets the rate limiter
func (b *ConnectorBuilder) WithRateLimiter(limiter *RateLimiter) *ConnectorBuilder {
	b.rateLimiter = limiter
	return b
}

// WithRetryConfig sets the retry configuration
func (b *ConnectorBuilder) WithRetryConfig(config *RetryConfig) *ConnectorBuilder {
	b.retryConfig = config
	return b
}

// WithLogger sets a custom logger
func (b *ConnectorBuilder) WithLogger(logger *log.Logger) *ConnectorBuilder {
	b.logger = logger
	return b
}

// WithValidator sets a configuration validator
func (b *ConnectorBuilder) WithValidator(validator ConfigValidator) *ConnectorBuilder {
	b.validator = validator
	return b
}

// Build creates a BaseConnector with the configured options
func (b *ConnectorBuilder) Build() *BaseConnector {
	return &BaseConnector{
		name:         b.name,
		connType:     b.connType,
		version:      b.version,
		capabilities: b.capabilities,
		authProvider: b.authProvider,
		rateLimiter:  b.rateLimiter,
		retryConfig:  b.retryConfig,
		logger:       b.logger,
		validator:    b.validator,
	}
}

// ConfigValidator validates connector configuration
type ConfigValidator interface {
	// Validate checks if the configuration is valid
	Validate(config *base.ConnectorConfig) error

	// RequiredFields returns the list of required configuration fields
	RequiredFields() []string

	// OptionalFields returns the list of optional fields with their defaults
	OptionalFields() map[string]interface{}
}

// DefaultConfigValidator provides basic configuration validation
type DefaultConfigValidator struct {
	required []string
	optional map[string]interface{}
}

// NewDefaultConfigValidator creates a new default config validator
func NewDefaultConfigValidator(required []string, optional map[string]interface{}) *DefaultConfigValidator {
	if optional == nil {
		optional = make(map[string]interface{})
	}
	return &DefaultConfigValidator{
		required: required,
		optional: optional,
	}
}

// Validate checks required fields are present
func (v *DefaultConfigValidator) Validate(config *base.ConnectorConfig) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}

	if config.Name == "" {
		return fmt.Errorf("connector name is required")
	}

	if config.Type == "" {
		return fmt.Errorf("connector type is required")
	}

	// Check required fields in Options
	for _, field := range v.required {
		if _, ok := config.Options[field]; !ok {
			// Check credentials too
			if _, ok := config.Credentials[field]; !ok {
				return fmt.Errorf("required field '%s' is missing", field)
			}
		}
	}

	return nil
}

// RequiredFields returns the required fields
func (v *DefaultConfigValidator) RequiredFields() []string {
	return v.required
}

// OptionalFields returns the optional fields with defaults
func (v *DefaultConfigValidator) OptionalFields() map[string]interface{} {
	return v.optional
}

// ApplyDefaults applies default values from OptionalFields to config
func (v *DefaultConfigValidator) ApplyDefaults(config *base.ConnectorConfig) {
	if config.Options == nil {
		config.Options = make(map[string]interface{})
	}

	for field, defaultValue := range v.optional {
		if _, exists := config.Options[field]; !exists {
			config.Options[field] = defaultValue
		}
	}
}

// ConfigSchema represents a JSON Schema for connector configuration
type ConfigSchema struct {
	Type       string                    `json:"type"`
	Properties map[string]PropertySchema `json:"properties"`
	Required   []string                  `json:"required"`
}

// PropertySchema represents a property in the config schema
type PropertySchema struct {
	Type        string      `json:"type"`
	Description string      `json:"description,omitempty"`
	Default     interface{} `json:"default,omitempty"`
	Enum        []string    `json:"enum,omitempty"`
	Minimum     *float64    `json:"minimum,omitempty"`
	Maximum     *float64    `json:"maximum,omitempty"`
	Pattern     string      `json:"pattern,omitempty"`
}

// SchemaValidator validates configuration against a JSON Schema
type SchemaValidator struct {
	schema *ConfigSchema
}

// NewSchemaValidator creates a schema-based validator
func NewSchemaValidator(schema *ConfigSchema) *SchemaValidator {
	return &SchemaValidator{schema: schema}
}

// Validate validates config against the schema
func (v *SchemaValidator) Validate(config *base.ConnectorConfig) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}

	// Check required fields
	for _, field := range v.schema.Required {
		if _, ok := config.Options[field]; !ok {
			if _, ok := config.Credentials[field]; !ok {
				return fmt.Errorf("required field '%s' is missing", field)
			}
		}
	}

	// Validate field types and constraints
	for fieldName, propSchema := range v.schema.Properties {
		value, ok := config.Options[fieldName]
		if !ok {
			value, ok = config.Credentials[fieldName]
		}
		if !ok {
			continue // Field not present, already checked required
		}

		if err := v.validateProperty(fieldName, value, propSchema); err != nil {
			return err
		}
	}

	return nil
}

func (v *SchemaValidator) validateProperty(name string, value interface{}, schema PropertySchema) error {
	switch schema.Type {
	case "string":
		if _, ok := value.(string); !ok {
			return fmt.Errorf("field '%s' must be a string", name)
		}
	case "integer":
		switch value.(type) {
		case int, int64, int32, float64:
			// OK
		default:
			return fmt.Errorf("field '%s' must be an integer", name)
		}
	case "number":
		switch value.(type) {
		case int, int64, int32, float64, float32:
			// OK
		default:
			return fmt.Errorf("field '%s' must be a number", name)
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("field '%s' must be a boolean", name)
		}
	case "array":
		switch value.(type) {
		case []interface{}, []string:
			// OK
		default:
			return fmt.Errorf("field '%s' must be an array", name)
		}
	}

	return nil
}

// RequiredFields returns the required fields from schema
func (v *SchemaValidator) RequiredFields() []string {
	return v.schema.Required
}

// OptionalFields returns optional fields with defaults
func (v *SchemaValidator) OptionalFields() map[string]interface{} {
	defaults := make(map[string]interface{})
	for name, prop := range v.schema.Properties {
		if prop.Default != nil {
			defaults[name] = prop.Default
		}
	}
	return defaults
}

// ToJSON converts schema to JSON string
func (s *ConfigSchema) ToJSON() (string, error) {
	bytes, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// LifecycleHooks provides hooks for connector lifecycle events
type LifecycleHooks struct {
	// OnConnect is called after successful connection
	OnConnect func(ctx context.Context, config *base.ConnectorConfig) error

	// OnDisconnect is called before disconnection
	OnDisconnect func(ctx context.Context) error

	// OnHealthCheck is called during health checks
	OnHealthCheck func(ctx context.Context, status *base.HealthStatus) error

	// OnQuery is called before each query
	OnQuery func(ctx context.Context, query *base.Query) error

	// OnQueryComplete is called after each query
	OnQueryComplete func(ctx context.Context, query *base.Query, result *base.QueryResult, err error)

	// OnExecute is called before each command execution
	OnExecute func(ctx context.Context, cmd *base.Command) error

	// OnExecuteComplete is called after each command execution
	OnExecuteComplete func(ctx context.Context, cmd *base.Command, result *base.CommandResult, err error)
}

// ContextKey is a type for context keys
type ContextKey string

const (
	// ContextKeyTenantID is the context key for tenant ID
	ContextKeyTenantID ContextKey = "tenant_id"

	// ContextKeyRequestID is the context key for request ID
	ContextKeyRequestID ContextKey = "request_id"

	// ContextKeyUserID is the context key for user ID
	ContextKeyUserID ContextKey = "user_id"

	// ContextKeyTraceID is the context key for trace ID
	ContextKeyTraceID ContextKey = "trace_id"
)

// GetTenantID extracts tenant ID from context
func GetTenantID(ctx context.Context) string {
	if v := ctx.Value(ContextKeyTenantID); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// GetRequestID extracts request ID from context
func GetRequestID(ctx context.Context) string {
	if v := ctx.Value(ContextKeyRequestID); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// WithTenantID adds tenant ID to context
func WithTenantID(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, ContextKeyTenantID, tenantID)
}

// WithRequestID adds request ID to context
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, ContextKeyRequestID, requestID)
}

// ConnectorMetadata holds metadata about a connector
type ConnectorMetadata struct {
	Name         string            `json:"name"`
	Type         string            `json:"type"`
	Version      string            `json:"version"`
	Capabilities []string          `json:"capabilities"`
	Description  string            `json:"description,omitempty"`
	Author       string            `json:"author,omitempty"`
	License      string            `json:"license,omitempty"`
	Homepage     string            `json:"homepage,omitempty"`
	Tags         []string          `json:"tags,omitempty"`
	CreatedAt    time.Time         `json:"created_at,omitempty"`
	UpdatedAt    time.Time         `json:"updated_at,omitempty"`
	Extra        map[string]string `json:"extra,omitempty"`
}

// NewConnectorMetadata creates metadata for a connector
func NewConnectorMetadata(name, connType, version string) *ConnectorMetadata {
	return &ConnectorMetadata{
		Name:      name,
		Type:      connType,
		Version:   version,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}
