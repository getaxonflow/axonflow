// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
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
	"log"
	"os"
	"strings"
	"testing"

	"axonflow/platform/connectors/base"
)

func TestConnectorBuilder(t *testing.T) {
	t.Run("basic builder", func(t *testing.T) {
		connector := NewConnectorBuilder("my-connector", "custom").Build()

		if connector.Name() != "my-connector" {
			t.Errorf("expected name my-connector, got %s", connector.Name())
		}

		if connector.Type() != "custom" {
			t.Errorf("expected type custom, got %s", connector.Type())
		}
	})

	t.Run("builder with options", func(t *testing.T) {
		logger := log.New(os.Stderr, "[TEST] ", log.LstdFlags)
		limiter := NewRateLimiter(100, 10)
		retryConfig := DefaultRetryConfig()
		auth := NewAPIKeyAuth("key", APIKeyInHeader, "X-API-Key")
		validator := NewDefaultConfigValidator([]string{"required_field"}, nil)

		connector := NewConnectorBuilder("full-connector", "full").
			WithVersion("2.0.0").
			WithCapabilities("query", "execute", "stream").
			WithLogger(logger).
			WithRateLimiter(limiter).
			WithRetryConfig(retryConfig).
			WithAuth(auth).
			WithValidator(validator).
			Build()

		if connector.Version() != "2.0.0" {
			t.Errorf("expected version 2.0.0, got %s", connector.Version())
		}

		caps := connector.Capabilities()
		if len(caps) != 3 {
			t.Errorf("expected 3 capabilities, got %d", len(caps))
		}

		if connector.GetLogger() != logger {
			t.Error("logger not set correctly")
		}

		if connector.GetRetryConfig() != retryConfig {
			t.Error("retry config not set correctly")
		}

		if connector.GetAuthProvider() != auth {
			t.Error("auth provider not set correctly")
		}
	})
}

func TestDefaultConfigValidator(t *testing.T) {
	t.Run("validate required fields", func(t *testing.T) {
		validator := NewDefaultConfigValidator(
			[]string{"host", "port"},
			map[string]interface{}{"timeout": 30},
		)

		// Missing required field
		config := &base.ConnectorConfig{
			Name:    "test",
			Type:    "test",
			Options: map[string]interface{}{"host": "localhost"},
		}

		err := validator.Validate(config)
		if err == nil {
			t.Error("expected error for missing required field")
		}

		// All required fields present
		config.Options["port"] = 5432
		err = validator.Validate(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("validate nil config", func(t *testing.T) {
		validator := NewDefaultConfigValidator(nil, nil)

		err := validator.Validate(nil)
		if err == nil {
			t.Error("expected error for nil config")
		}
	})

	t.Run("validate empty name", func(t *testing.T) {
		validator := NewDefaultConfigValidator(nil, nil)

		config := &base.ConnectorConfig{Type: "test"}
		err := validator.Validate(config)
		if err == nil {
			t.Error("expected error for empty name")
		}
	})

	t.Run("validate empty type", func(t *testing.T) {
		validator := NewDefaultConfigValidator(nil, nil)

		config := &base.ConnectorConfig{Name: "test"}
		err := validator.Validate(config)
		if err == nil {
			t.Error("expected error for empty type")
		}
	})

	t.Run("required fields in credentials", func(t *testing.T) {
		validator := NewDefaultConfigValidator([]string{"api_key"}, nil)

		config := &base.ConnectorConfig{
			Name:        "test",
			Type:        "test",
			Options:     map[string]interface{}{},
			Credentials: map[string]string{"api_key": "secret"},
		}

		err := validator.Validate(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("apply defaults", func(t *testing.T) {
		validator := NewDefaultConfigValidator(
			nil,
			map[string]interface{}{
				"timeout":  30,
				"max_conn": 10,
			},
		)

		config := &base.ConnectorConfig{
			Name:    "test",
			Type:    "test",
			Options: map[string]interface{}{"timeout": 60}, // Override default
		}

		validator.ApplyDefaults(config)

		if config.Options["timeout"] != 60 {
			t.Error("existing value should not be overwritten")
		}

		if config.Options["max_conn"] != 10 {
			t.Error("default should be applied for missing field")
		}
	})

	t.Run("apply defaults to nil options", func(t *testing.T) {
		validator := NewDefaultConfigValidator(nil, map[string]interface{}{"key": "value"})

		config := &base.ConnectorConfig{Name: "test", Type: "test"}
		validator.ApplyDefaults(config)

		if config.Options["key"] != "value" {
			t.Error("default should be applied when options is nil")
		}
	})

	t.Run("required and optional fields", func(t *testing.T) {
		validator := NewDefaultConfigValidator(
			[]string{"required1", "required2"},
			map[string]interface{}{"optional1": "default"},
		)

		if len(validator.RequiredFields()) != 2 {
			t.Error("expected 2 required fields")
		}

		if len(validator.OptionalFields()) != 1 {
			t.Error("expected 1 optional field")
		}
	})
}

func TestSchemaValidator(t *testing.T) {
	t.Run("validate against schema", func(t *testing.T) {
		schema := &ConfigSchema{
			Type: "object",
			Properties: map[string]PropertySchema{
				"host":    {Type: "string"},
				"port":    {Type: "integer"},
				"enabled": {Type: "boolean"},
			},
			Required: []string{"host"},
		}

		validator := NewSchemaValidator(schema)

		config := &base.ConnectorConfig{
			Name: "test",
			Type: "test",
			Options: map[string]interface{}{
				"host":    "localhost",
				"port":    5432,
				"enabled": true,
			},
		}

		err := validator.Validate(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("missing required field", func(t *testing.T) {
		schema := &ConfigSchema{
			Required: []string{"host"},
		}

		validator := NewSchemaValidator(schema)

		config := &base.ConnectorConfig{
			Name:    "test",
			Type:    "test",
			Options: map[string]interface{}{},
		}

		err := validator.Validate(config)
		if err == nil {
			t.Error("expected error for missing required field")
		}
	})

	t.Run("type validation string", func(t *testing.T) {
		schema := &ConfigSchema{
			Properties: map[string]PropertySchema{
				"name": {Type: "string"},
			},
		}

		validator := NewSchemaValidator(schema)

		config := &base.ConnectorConfig{
			Name:    "test",
			Type:    "test",
			Options: map[string]interface{}{"name": 123}, // Wrong type
		}

		err := validator.Validate(config)
		if err == nil {
			t.Error("expected error for wrong type")
		}
	})

	t.Run("type validation integer", func(t *testing.T) {
		schema := &ConfigSchema{
			Properties: map[string]PropertySchema{
				"count": {Type: "integer"},
			},
		}

		validator := NewSchemaValidator(schema)

		// Valid integer
		config := &base.ConnectorConfig{
			Name:    "test",
			Type:    "test",
			Options: map[string]interface{}{"count": 42},
		}

		if err := validator.Validate(config); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Float64 should work (JSON unmarshaling)
		config.Options["count"] = float64(42)
		if err := validator.Validate(config); err != nil {
			t.Fatalf("float64 should be valid as integer: %v", err)
		}

		// String should fail
		config.Options["count"] = "42"
		if err := validator.Validate(config); err == nil {
			t.Error("string should not be valid as integer")
		}
	})

	t.Run("type validation boolean", func(t *testing.T) {
		schema := &ConfigSchema{
			Properties: map[string]PropertySchema{
				"enabled": {Type: "boolean"},
			},
		}

		validator := NewSchemaValidator(schema)

		config := &base.ConnectorConfig{
			Name:    "test",
			Type:    "test",
			Options: map[string]interface{}{"enabled": "true"}, // String, not bool
		}

		err := validator.Validate(config)
		if err == nil {
			t.Error("expected error for wrong boolean type")
		}
	})

	t.Run("type validation array", func(t *testing.T) {
		schema := &ConfigSchema{
			Properties: map[string]PropertySchema{
				"items": {Type: "array"},
			},
		}

		validator := NewSchemaValidator(schema)

		// Valid array
		config := &base.ConnectorConfig{
			Name:    "test",
			Type:    "test",
			Options: map[string]interface{}{"items": []interface{}{"a", "b"}},
		}

		if err := validator.Validate(config); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// String slice should work
		config.Options["items"] = []string{"a", "b"}
		if err := validator.Validate(config); err != nil {
			t.Fatalf("string slice should be valid: %v", err)
		}

		// String should fail
		config.Options["items"] = "not an array"
		if err := validator.Validate(config); err == nil {
			t.Error("string should not be valid as array")
		}
	})

	t.Run("type validation number", func(t *testing.T) {
		schema := &ConfigSchema{
			Properties: map[string]PropertySchema{
				"rate": {Type: "number"},
			},
		}

		validator := NewSchemaValidator(schema)

		// Float
		config := &base.ConnectorConfig{
			Name:    "test",
			Type:    "test",
			Options: map[string]interface{}{"rate": 1.5},
		}

		if err := validator.Validate(config); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Int should work too
		config.Options["rate"] = 10
		if err := validator.Validate(config); err != nil {
			t.Fatalf("int should be valid as number: %v", err)
		}
	})

	t.Run("optional fields with defaults", func(t *testing.T) {
		schema := &ConfigSchema{
			Properties: map[string]PropertySchema{
				"timeout": {Type: "integer", Default: 30},
				"retries": {Type: "integer", Default: 3},
			},
		}

		validator := NewSchemaValidator(schema)

		defaults := validator.OptionalFields()
		if defaults["timeout"] != 30 {
			t.Error("expected timeout default of 30")
		}
		if defaults["retries"] != 3 {
			t.Error("expected retries default of 3")
		}
	})

	t.Run("nil config", func(t *testing.T) {
		validator := NewSchemaValidator(&ConfigSchema{})

		err := validator.Validate(nil)
		if err == nil {
			t.Error("expected error for nil config")
		}
	})

	t.Run("required from credentials", func(t *testing.T) {
		schema := &ConfigSchema{
			Required: []string{"api_key"},
		}

		validator := NewSchemaValidator(schema)

		config := &base.ConnectorConfig{
			Name:        "test",
			Type:        "test",
			Credentials: map[string]string{"api_key": "secret"},
		}

		err := validator.Validate(config)
		if err != nil {
			t.Fatalf("should find required field in credentials: %v", err)
		}
	})
}

func TestConfigSchemaToJSON(t *testing.T) {
	schema := &ConfigSchema{
		Type: "object",
		Properties: map[string]PropertySchema{
			"host": {Type: "string", Description: "Server hostname"},
			"port": {Type: "integer", Default: 5432},
		},
		Required: []string{"host"},
	}

	json, err := schema.ToJSON()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if json == "" {
		t.Error("expected non-empty JSON")
	}

	if !strings.Contains(json, "host") {
		t.Error("expected host in JSON")
	}
}

func TestLifecycleHooks(t *testing.T) {
	t.Run("all hooks defined", func(t *testing.T) {
		hooks := &LifecycleHooks{
			OnConnect:         func(ctx context.Context, config *base.ConnectorConfig) error { return nil },
			OnDisconnect:      func(ctx context.Context) error { return nil },
			OnHealthCheck:     func(ctx context.Context, status *base.HealthStatus) error { return nil },
			OnQuery:           func(ctx context.Context, query *base.Query) error { return nil },
			OnQueryComplete:   func(ctx context.Context, query *base.Query, result *base.QueryResult, err error) {},
			OnExecute:         func(ctx context.Context, cmd *base.Command) error { return nil },
			OnExecuteComplete: func(ctx context.Context, cmd *base.Command, result *base.CommandResult, err error) {},
		}

		if hooks.OnConnect == nil {
			t.Error("OnConnect should be set")
		}
	})
}

func TestContextHelpers(t *testing.T) {
	t.Run("tenant ID", func(t *testing.T) {
		ctx := context.Background()

		// No tenant ID
		if id := GetTenantID(ctx); id != "" {
			t.Errorf("expected empty tenant ID, got %s", id)
		}

		// With tenant ID
		ctx = WithTenantID(ctx, "tenant-123")
		if id := GetTenantID(ctx); id != "tenant-123" {
			t.Errorf("expected tenant-123, got %s", id)
		}
	})

	t.Run("request ID", func(t *testing.T) {
		ctx := context.Background()

		// No request ID
		if id := GetRequestID(ctx); id != "" {
			t.Errorf("expected empty request ID, got %s", id)
		}

		// With request ID
		ctx = WithRequestID(ctx, "req-456")
		if id := GetRequestID(ctx); id != "req-456" {
			t.Errorf("expected req-456, got %s", id)
		}
	})

	t.Run("wrong type in context", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), ContextKeyTenantID, 123)

		if id := GetTenantID(ctx); id != "" {
			t.Error("expected empty for wrong type")
		}
	})
}

func TestConnectorMetadata(t *testing.T) {
	t.Run("create metadata", func(t *testing.T) {
		meta := NewConnectorMetadata("my-connector", "postgres", "1.0.0")

		if meta.Name != "my-connector" {
			t.Errorf("expected name my-connector, got %s", meta.Name)
		}

		if meta.Type != "postgres" {
			t.Errorf("expected type postgres, got %s", meta.Type)
		}

		if meta.Version != "1.0.0" {
			t.Errorf("expected version 1.0.0, got %s", meta.Version)
		}

		if meta.CreatedAt.IsZero() {
			t.Error("expected CreatedAt to be set")
		}

		if meta.UpdatedAt.IsZero() {
			t.Error("expected UpdatedAt to be set")
		}
	})

	t.Run("metadata fields", func(t *testing.T) {
		meta := NewConnectorMetadata("test", "test", "1.0.0")
		meta.Description = "Test connector"
		meta.Author = "AxonFlow"
		meta.License = "Apache-2.0"
		meta.Homepage = "https://getaxonflow.com"
		meta.Tags = []string{"database", "test"}
		meta.Extra = map[string]string{"custom": "value"}

		if meta.Description != "Test connector" {
			t.Error("description not set")
		}

		if meta.Author != "AxonFlow" {
			t.Error("author not set")
		}

		if len(meta.Tags) != 2 {
			t.Error("tags not set correctly")
		}
	})
}

func TestContextKeys(t *testing.T) {
	// Verify context keys are distinct
	keys := []ContextKey{
		ContextKeyTenantID,
		ContextKeyRequestID,
		ContextKeyUserID,
		ContextKeyTraceID,
	}

	seen := make(map[ContextKey]bool)
	for _, key := range keys {
		if seen[key] {
			t.Errorf("duplicate context key: %s", key)
		}
		seen[key] = true
	}
}

func TestVersion(t *testing.T) {
	if Version != "1.0.0" {
		t.Errorf("expected SDK version 1.0.0, got %s", Version)
	}
}
