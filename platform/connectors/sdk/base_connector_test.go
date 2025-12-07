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
	"bytes"
	"context"
	"fmt"
	"log"
	"strings"
	"testing"
	"time"

	"axonflow/platform/connectors/base"
)

func TestBaseConnector(t *testing.T) {
	t.Run("create new base connector", func(t *testing.T) {
		conn := NewBaseConnector("test-type")

		if conn.Type() != "test-type" {
			t.Errorf("expected type test-type, got %s", conn.Type())
		}

		if conn.Version() != "1.0.0" {
			t.Errorf("expected version 1.0.0, got %s", conn.Version())
		}

		caps := conn.Capabilities()
		if len(caps) != 2 || caps[0] != "query" || caps[1] != "execute" {
			t.Errorf("unexpected capabilities: %v", caps)
		}
	})

	t.Run("connect and disconnect", func(t *testing.T) {
		conn := NewBaseConnector("test")
		ctx := context.Background()

		config := &base.ConnectorConfig{
			Name:    "my-connector",
			Type:    "test",
			Timeout: time.Second,
		}

		err := conn.Connect(ctx, config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !conn.IsConnected() {
			t.Error("expected connected after Connect")
		}

		if conn.Name() != "my-connector" {
			t.Errorf("expected name my-connector, got %s", conn.Name())
		}

		err = conn.Disconnect(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if conn.IsConnected() {
			t.Error("expected disconnected after Disconnect")
		}
	})

	t.Run("disconnect when not connected", func(t *testing.T) {
		conn := NewBaseConnector("test")
		ctx := context.Background()

		err := conn.Disconnect(ctx)
		if err != nil {
			t.Fatalf("disconnect when not connected should not error: %v", err)
		}
	})

	t.Run("default timeout", func(t *testing.T) {
		conn := NewBaseConnector("test")
		ctx := context.Background()

		config := &base.ConnectorConfig{
			Name: "test",
			Type: "test",
			// No timeout specified
		}

		err := conn.Connect(ctx, config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if conn.GetTimeout() != 30*time.Second {
			t.Errorf("expected default timeout 30s, got %v", conn.GetTimeout())
		}
	})

	t.Run("custom timeout", func(t *testing.T) {
		conn := NewBaseConnector("test")
		ctx := context.Background()

		config := &base.ConnectorConfig{
			Name:    "test",
			Type:    "test",
			Timeout: 5 * time.Second,
		}

		conn.Connect(ctx, config)

		if conn.GetTimeout() != 5*time.Second {
			t.Errorf("expected timeout 5s, got %v", conn.GetTimeout())
		}
	})

	t.Run("health check", func(t *testing.T) {
		conn := NewBaseConnector("test")
		ctx := context.Background()

		// Unhealthy when not connected
		status, err := conn.HealthCheck(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if status.Healthy {
			t.Error("expected unhealthy when not connected")
		}

		// Connect
		conn.Connect(ctx, &base.ConnectorConfig{Name: "test", Type: "test", Timeout: time.Second})

		// Healthy when connected
		status, err = conn.HealthCheck(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !status.Healthy {
			t.Error("expected healthy when connected")
		}

		if status.Details["connector_type"] != "test" {
			t.Error("expected connector_type in details")
		}
	})

	t.Run("query when not connected", func(t *testing.T) {
		conn := NewBaseConnector("test")
		ctx := context.Background()

		_, err := conn.Query(ctx, &base.Query{})
		if err == nil {
			t.Error("expected error when not connected")
		}
	})

	t.Run("execute when not connected", func(t *testing.T) {
		conn := NewBaseConnector("test")
		ctx := context.Background()

		_, err := conn.Execute(ctx, &base.Command{})
		if err == nil {
			t.Error("expected error when not connected")
		}
	})

	t.Run("query when connected", func(t *testing.T) {
		conn := NewBaseConnector("test")
		ctx := context.Background()

		conn.Connect(ctx, &base.ConnectorConfig{Name: "test", Type: "test", Timeout: time.Second})

		result, err := conn.Query(ctx, &base.Query{Statement: "SELECT 1"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.RowCount != 0 {
			t.Error("base connector should return empty result")
		}

		if result.Connector != "test" {
			t.Error("expected connector name in result")
		}
	})

	t.Run("execute when connected", func(t *testing.T) {
		conn := NewBaseConnector("test")
		ctx := context.Background()

		conn.Connect(ctx, &base.ConnectorConfig{Name: "test", Type: "test", Timeout: time.Second})

		result, err := conn.Execute(ctx, &base.Command{Action: "INSERT"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !result.Success {
			t.Error("base connector should return success")
		}
	})
}

func TestBaseConnectorWithValidator(t *testing.T) {
	t.Run("validation failure", func(t *testing.T) {
		conn := NewBaseConnector("test")
		conn.SetValidator(NewDefaultConfigValidator([]string{"required_field"}, nil))
		ctx := context.Background()

		config := &base.ConnectorConfig{
			Name:    "test",
			Type:    "test",
			Options: map[string]interface{}{},
		}

		err := conn.Connect(ctx, config)
		if err == nil {
			t.Error("expected validation error")
		}
	})

	t.Run("validation success with defaults", func(t *testing.T) {
		conn := NewBaseConnector("test")
		validator := NewDefaultConfigValidator(
			[]string{},
			map[string]interface{}{"default_field": "default_value"},
		)
		conn.SetValidator(validator)
		ctx := context.Background()

		config := &base.ConnectorConfig{
			Name:    "test",
			Type:    "test",
			Timeout: time.Second,
			Options: map[string]interface{}{},
		}

		err := conn.Connect(ctx, config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Check default was applied
		savedConfig := conn.GetConfig()
		if savedConfig.Options["default_field"] != "default_value" {
			t.Error("default value not applied")
		}
	})
}

func TestBaseConnectorWithRateLimiter(t *testing.T) {
	conn := NewBaseConnector("test")
	conn.SetRateLimiter(NewRateLimiter(100, 5))
	ctx := context.Background()

	conn.Connect(ctx, &base.ConnectorConfig{Name: "test", Type: "test", Timeout: time.Second})

	// Should succeed without rate limit issues
	for i := 0; i < 5; i++ {
		_, err := conn.Query(ctx, &base.Query{})
		if err != nil {
			t.Fatalf("unexpected error on query %d: %v", i, err)
		}
	}
}

func TestBaseConnectorWithHooks(t *testing.T) {
	t.Run("connect hook", func(t *testing.T) {
		conn := NewBaseConnector("test")
		hookCalled := false

		conn.SetHooks(&LifecycleHooks{
			OnConnect: func(ctx context.Context, config *base.ConnectorConfig) error {
				hookCalled = true
				return nil
			},
		})

		ctx := context.Background()
		conn.Connect(ctx, &base.ConnectorConfig{Name: "test", Type: "test", Timeout: time.Second})

		if !hookCalled {
			t.Error("connect hook not called")
		}
	})

	t.Run("connect hook error", func(t *testing.T) {
		conn := NewBaseConnector("test")

		conn.SetHooks(&LifecycleHooks{
			OnConnect: func(ctx context.Context, config *base.ConnectorConfig) error {
				return fmt.Errorf("hook error")
			},
		})

		ctx := context.Background()
		err := conn.Connect(ctx, &base.ConnectorConfig{Name: "test", Type: "test", Timeout: time.Second})

		if err == nil {
			t.Error("expected error from hook")
		}
	})

	t.Run("disconnect hook", func(t *testing.T) {
		conn := NewBaseConnector("test")
		hookCalled := false

		conn.SetHooks(&LifecycleHooks{
			OnDisconnect: func(ctx context.Context) error {
				hookCalled = true
				return nil
			},
		})

		ctx := context.Background()
		conn.Connect(ctx, &base.ConnectorConfig{Name: "test", Type: "test", Timeout: time.Second})
		conn.Disconnect(ctx)

		if !hookCalled {
			t.Error("disconnect hook not called")
		}
	})

	t.Run("disconnect hook error logged", func(t *testing.T) {
		conn := NewBaseConnector("test")

		conn.SetHooks(&LifecycleHooks{
			OnDisconnect: func(ctx context.Context) error {
				return fmt.Errorf("disconnect hook error")
			},
		})

		ctx := context.Background()
		conn.Connect(ctx, &base.ConnectorConfig{Name: "test", Type: "test", Timeout: time.Second})

		// Should not return error, just log it
		err := conn.Disconnect(ctx)
		if err != nil {
			t.Errorf("disconnect should not return hook error: %v", err)
		}
	})

	t.Run("query hook", func(t *testing.T) {
		conn := NewBaseConnector("test")
		hookCalled := false

		conn.SetHooks(&LifecycleHooks{
			OnQuery: func(ctx context.Context, query *base.Query) error {
				hookCalled = true
				return nil
			},
		})

		ctx := context.Background()
		conn.Connect(ctx, &base.ConnectorConfig{Name: "test", Type: "test", Timeout: time.Second})
		conn.Query(ctx, &base.Query{})

		if !hookCalled {
			t.Error("query hook not called")
		}
	})

	t.Run("query hook error", func(t *testing.T) {
		conn := NewBaseConnector("test")

		conn.SetHooks(&LifecycleHooks{
			OnQuery: func(ctx context.Context, query *base.Query) error {
				return fmt.Errorf("query hook error")
			},
		})

		ctx := context.Background()
		conn.Connect(ctx, &base.ConnectorConfig{Name: "test", Type: "test", Timeout: time.Second})
		_, err := conn.Query(ctx, &base.Query{})

		if err == nil {
			t.Error("expected error from query hook")
		}
	})

	t.Run("execute hook", func(t *testing.T) {
		conn := NewBaseConnector("test")
		hookCalled := false

		conn.SetHooks(&LifecycleHooks{
			OnExecute: func(ctx context.Context, cmd *base.Command) error {
				hookCalled = true
				return nil
			},
		})

		ctx := context.Background()
		conn.Connect(ctx, &base.ConnectorConfig{Name: "test", Type: "test", Timeout: time.Second})
		conn.Execute(ctx, &base.Command{})

		if !hookCalled {
			t.Error("execute hook not called")
		}
	})

	t.Run("execute hook error", func(t *testing.T) {
		conn := NewBaseConnector("test")

		conn.SetHooks(&LifecycleHooks{
			OnExecute: func(ctx context.Context, cmd *base.Command) error {
				return fmt.Errorf("execute hook error")
			},
		})

		ctx := context.Background()
		conn.Connect(ctx, &base.ConnectorConfig{Name: "test", Type: "test", Timeout: time.Second})
		_, err := conn.Execute(ctx, &base.Command{})

		if err == nil {
			t.Error("expected error from execute hook")
		}
	})

	t.Run("health check hook", func(t *testing.T) {
		conn := NewBaseConnector("test")

		conn.SetHooks(&LifecycleHooks{
			OnHealthCheck: func(ctx context.Context, status *base.HealthStatus) error {
				status.Details["custom"] = "value"
				return nil
			},
		})

		ctx := context.Background()
		conn.Connect(ctx, &base.ConnectorConfig{Name: "test", Type: "test", Timeout: time.Second})
		status, _ := conn.HealthCheck(ctx)

		if status.Details["custom"] != "value" {
			t.Error("health check hook not applied")
		}
	})

	t.Run("health check hook error", func(t *testing.T) {
		conn := NewBaseConnector("test")

		conn.SetHooks(&LifecycleHooks{
			OnHealthCheck: func(ctx context.Context, status *base.HealthStatus) error {
				return fmt.Errorf("health check failed")
			},
		})

		ctx := context.Background()
		conn.Connect(ctx, &base.ConnectorConfig{Name: "test", Type: "test", Timeout: time.Second})
		status, _ := conn.HealthCheck(ctx)

		if status.Healthy {
			t.Error("expected unhealthy when hook fails")
		}

		if status.Error == "" {
			t.Error("expected error message in status")
		}
	})
}

func TestBaseConnectorOptions(t *testing.T) {
	conn := NewBaseConnector("test")
	ctx := context.Background()

	config := &base.ConnectorConfig{
		Name:    "test",
		Type:    "test",
		Timeout: time.Second,
		Options: map[string]interface{}{
			"string_opt": "hello",
			"int_opt":    42,
			"float_opt":  float64(100),
			"bool_opt":   true,
		},
		Credentials: map[string]string{
			"api_key": "secret",
		},
	}

	conn.Connect(ctx, config)

	t.Run("get option", func(t *testing.T) {
		val := conn.GetOption("string_opt", "default")
		if val != "hello" {
			t.Errorf("expected hello, got %v", val)
		}

		val = conn.GetOption("missing", "default")
		if val != "default" {
			t.Errorf("expected default, got %v", val)
		}
	})

	t.Run("get string option", func(t *testing.T) {
		val := conn.GetStringOption("string_opt", "default")
		if val != "hello" {
			t.Errorf("expected hello, got %s", val)
		}

		val = conn.GetStringOption("int_opt", "default")
		if val != "default" {
			t.Errorf("expected default for non-string, got %s", val)
		}
	})

	t.Run("get int option", func(t *testing.T) {
		val := conn.GetIntOption("int_opt", 0)
		if val != 42 {
			t.Errorf("expected 42, got %d", val)
		}

		val = conn.GetIntOption("float_opt", 0)
		if val != 100 {
			t.Errorf("expected 100 from float, got %d", val)
		}

		val = conn.GetIntOption("string_opt", 99)
		if val != 99 {
			t.Errorf("expected default for non-int, got %d", val)
		}
	})

	t.Run("get bool option", func(t *testing.T) {
		val := conn.GetBoolOption("bool_opt", false)
		if !val {
			t.Error("expected true")
		}

		val = conn.GetBoolOption("string_opt", true)
		if !val {
			t.Error("expected default for non-bool")
		}
	})

	t.Run("get credential", func(t *testing.T) {
		val := conn.GetCredential("api_key")
		if val != "secret" {
			t.Errorf("expected secret, got %s", val)
		}

		val = conn.GetCredential("missing")
		if val != "" {
			t.Errorf("expected empty for missing credential, got %s", val)
		}
	})
}

func TestBaseConnectorNilConfig(t *testing.T) {
	conn := NewBaseConnector("test")

	// Options from nil config
	val := conn.GetOption("any", "default")
	if val != "default" {
		t.Error("expected default for nil config")
	}

	// Credential from nil config
	cred := conn.GetCredential("any")
	if cred != "" {
		t.Error("expected empty for nil config credentials")
	}

	// Timeout from nil config
	timeout := conn.GetTimeout()
	if timeout != 30*time.Second {
		t.Error("expected default timeout for nil config")
	}
}

func TestBaseConnectorWithTimeout(t *testing.T) {
	conn := NewBaseConnector("test")
	ctx := context.Background()

	conn.Connect(ctx, &base.ConnectorConfig{
		Name:    "test",
		Type:    "test",
		Timeout: 5 * time.Second,
	})

	newCtx, cancel := conn.WithTimeout(context.Background())
	defer cancel()

	deadline, ok := newCtx.Deadline()
	if !ok {
		t.Error("expected deadline to be set")
	}

	if time.Until(deadline) > 6*time.Second || time.Until(deadline) < 4*time.Second {
		t.Error("deadline not set correctly")
	}
}

func TestBaseConnectorSetters(t *testing.T) {
	conn := NewBaseConnector("test")

	t.Run("set logger", func(t *testing.T) {
		var buf bytes.Buffer
		logger := log.New(&buf, "[CUSTOM] ", 0)

		conn.SetLogger(logger)

		if conn.GetLogger() != logger {
			t.Error("logger not set")
		}

		conn.Log("test message")
		if !strings.Contains(buf.String(), "test message") {
			t.Error("log message not written")
		}
	})

	t.Run("set auth provider", func(t *testing.T) {
		auth := NewAPIKeyAuth("key", APIKeyInHeader, "X-API-Key")
		conn.SetAuthProvider(auth)

		if conn.GetAuthProvider() != auth {
			t.Error("auth provider not set")
		}
	})

	t.Run("set rate limiter", func(t *testing.T) {
		limiter := NewRateLimiter(100, 10)
		conn.SetRateLimiter(limiter)

		// No direct getter, but can verify through behavior
	})

	t.Run("set retry config", func(t *testing.T) {
		retryConfig := &RetryConfig{MaxRetries: 5}
		conn.SetRetryConfig(retryConfig)

		if conn.GetRetryConfig() != retryConfig {
			t.Error("retry config not set")
		}
	})

	t.Run("set validator", func(t *testing.T) {
		validator := NewDefaultConfigValidator([]string{"test"}, nil)
		conn.SetValidator(validator)

		// Validator is tested through connect behavior
	})

	t.Run("set hooks", func(t *testing.T) {
		hooks := &LifecycleHooks{}
		conn.SetHooks(hooks)

		// Hooks are tested through connect/query/execute behavior
	})

	t.Run("set capabilities", func(t *testing.T) {
		conn.SetCapabilities([]string{"custom1", "custom2"})

		caps := conn.Capabilities()
		if len(caps) != 2 || caps[0] != "custom1" {
			t.Error("capabilities not set correctly")
		}
	})

	t.Run("set version", func(t *testing.T) {
		conn.SetVersion("2.0.0")

		if conn.Version() != "2.0.0" {
			t.Error("version not set")
		}
	})
}

func TestBaseConnectorMetrics(t *testing.T) {
	conn := NewBaseConnector("test")

	metrics := conn.GetMetrics()
	if metrics == nil {
		t.Error("expected metrics to be initialized")
	}

	ctx := context.Background()
	conn.Connect(ctx, &base.ConnectorConfig{Name: "test", Type: "test", Timeout: time.Second})

	// Execute some operations
	conn.Query(ctx, &base.Query{})
	conn.Query(ctx, &base.Query{})
	conn.Execute(ctx, &base.Command{})

	stats := metrics.GetStats()
	if stats.QueriesTotal != 2 {
		t.Errorf("expected 2 queries, got %d", stats.QueriesTotal)
	}

	if stats.ExecutesTotal != 1 {
		t.Errorf("expected 1 execute, got %d", stats.ExecutesTotal)
	}
}

func TestBaseConnectorNameFallback(t *testing.T) {
	conn := NewBaseConnector("my-type")

	// Before connect, name should fall back to type
	if conn.Name() != "my-type" {
		t.Errorf("expected type as fallback name, got %s", conn.Name())
	}
}
