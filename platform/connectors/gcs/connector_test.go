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

package gcs

import (
	"context"
	"testing"
	"time"

	"axonflow/platform/connectors/base"
)

func TestNewGCSConnector(t *testing.T) {
	conn := NewGCSConnector()

	if conn == nil {
		t.Fatal("expected connector to be created")
	}

	if conn.Type() != "gcs" {
		t.Errorf("expected type gcs, got %s", conn.Type())
	}

	if conn.Version() != "1.0.0" {
		t.Errorf("expected version 1.0.0, got %s", conn.Version())
	}

	caps := conn.Capabilities()
	if len(caps) != 4 {
		t.Errorf("expected 4 capabilities, got %d", len(caps))
	}

	expectedCaps := map[string]bool{
		"query":     true,
		"execute":   true,
		"presign":   true,
		"streaming": true,
	}

	for _, cap := range caps {
		if !expectedCaps[cap] {
			t.Errorf("unexpected capability: %s", cap)
		}
	}
}

func TestGCSConnectorQueryWithoutConnect(t *testing.T) {
	conn := NewGCSConnector()
	ctx := context.Background()

	// GCS connector checks for nil client
	_, err := conn.Query(ctx, &base.Query{Statement: "list_objects"})
	if err == nil {
		t.Error("expected error when querying without connection")
	}
}

func TestGCSConnectorExecuteWithoutConnect(t *testing.T) {
	conn := NewGCSConnector()
	ctx := context.Background()

	_, err := conn.Execute(ctx, &base.Command{Action: "put_object"})
	if err == nil {
		t.Error("expected error when executing without connection")
	}
}

func TestGCSConnectorHealthCheckWithoutConnect(t *testing.T) {
	conn := NewGCSConnector()
	ctx := context.Background()

	status, err := conn.HealthCheck(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if status.Healthy {
		t.Error("expected unhealthy status without connection")
	}
}

func TestHelperFunctions(t *testing.T) {
	t.Run("getStringParam", func(t *testing.T) {
		params := map[string]interface{}{
			"key": "value",
		}

		if v := getStringParam(params, "key", "default"); v != "value" {
			t.Errorf("expected value, got %s", v)
		}

		if v := getStringParam(params, "missing", "default"); v != "default" {
			t.Errorf("expected default, got %s", v)
		}

		if v := getStringParam(nil, "key", "default"); v != "default" {
			t.Errorf("expected default for nil params, got %s", v)
		}
	})

	t.Run("getIntParam", func(t *testing.T) {
		params := map[string]interface{}{
			"int":     42,
			"int64":   int64(100),
			"float64": float64(200),
			"string":  "not an int",
		}

		if v := getIntParam(params, "int", 0); v != 42 {
			t.Errorf("expected 42, got %d", v)
		}

		if v := getIntParam(params, "int64", 0); v != 100 {
			t.Errorf("expected 100, got %d", v)
		}

		if v := getIntParam(params, "float64", 0); v != 200 {
			t.Errorf("expected 200, got %d", v)
		}

		if v := getIntParam(params, "string", 99); v != 99 {
			t.Errorf("expected 99 (default), got %d", v)
		}

		if v := getIntParam(nil, "key", 10); v != 10 {
			t.Errorf("expected 10 for nil params, got %d", v)
		}
	})
}

func TestGCSConnectorConfig(t *testing.T) {
	t.Run("config with credentials file", func(t *testing.T) {
		config := &base.ConnectorConfig{
			Name:    "test-gcs",
			Type:    "gcs",
			Timeout: 30 * time.Second,
			Options: map[string]interface{}{
				"project_id":     "my-project",
				"default_bucket": "my-bucket",
			},
			Credentials: map[string]string{
				"credentials_file": "/path/to/credentials.json",
			},
		}

		if config.Options["project_id"] != "my-project" {
			t.Error("expected project_id to be set")
		}
	})

	t.Run("config with credentials JSON", func(t *testing.T) {
		config := &base.ConnectorConfig{
			Name: "test-gcs-json",
			Type: "gcs",
			Options: map[string]interface{}{
				"project_id": "my-project",
			},
			Credentials: map[string]string{
				"credentials_json": `{"type":"service_account"...}`,
			},
		}

		if config.Credentials["credentials_json"] == "" {
			t.Error("expected credentials JSON to be set")
		}
	})

	t.Run("config with endpoint (emulator)", func(t *testing.T) {
		config := &base.ConnectorConfig{
			Name: "test-gcs-emulator",
			Type: "gcs",
			Options: map[string]interface{}{
				"endpoint":   "http://localhost:4443",
				"project_id": "test-project",
			},
		}

		if config.Options["endpoint"] != "http://localhost:4443" {
			t.Error("expected endpoint to be set")
		}
	})
}

func TestGCSConnectorGetBucket(t *testing.T) {
	conn := NewGCSConnector()
	conn.defaultBucket = "default-bucket"

	t.Run("bucket from params", func(t *testing.T) {
		params := map[string]interface{}{"bucket": "custom-bucket"}
		if b := conn.getBucket(params); b != "custom-bucket" {
			t.Errorf("expected custom-bucket, got %s", b)
		}
	})

	t.Run("default bucket", func(t *testing.T) {
		params := map[string]interface{}{}
		if b := conn.getBucket(params); b != "default-bucket" {
			t.Errorf("expected default-bucket, got %s", b)
		}
	})
}

func TestGCSConnectorUnsupportedOperations(t *testing.T) {
	conn := NewGCSConnector()
	conn.SetConnected(true) // Simulate connected state via SDK method

	ctx := context.Background()

	t.Run("unsupported query", func(t *testing.T) {
		_, err := conn.Query(ctx, &base.Query{Statement: "unknown_query"})
		if err == nil {
			t.Error("expected error for unsupported query")
		}
		connErr, ok := err.(*base.ConnectorError)
		if !ok {
			t.Error("expected ConnectorError")
		} else if connErr.Operation != "Query" {
			t.Errorf("expected operation Query, got %s", connErr.Operation)
		}
	})

	t.Run("unsupported action", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{Action: "unknown_action"})
		if err == nil {
			t.Error("expected error for unsupported action")
		}
		connErr, ok := err.(*base.ConnectorError)
		if !ok {
			t.Error("expected ConnectorError")
		} else if connErr.Operation != "Execute" {
			t.Errorf("expected operation Execute, got %s", connErr.Operation)
		}
	})
}

func TestGCSConnectorName(t *testing.T) {
	conn := NewGCSConnector()
	conn.SetName("test-connector") // Use SDK method

	if conn.Name() != "test-connector" {
		t.Errorf("expected name test-connector, got %s", conn.Name())
	}
}

func TestGCSConnectorTimeout(t *testing.T) {
	conn := NewGCSConnector()

	// Default timeout - use SDK getter
	if conn.GetTimeout() != 30*time.Second {
		t.Errorf("expected default timeout 30s, got %v", conn.GetTimeout())
	}
}

func TestGCSConnectorDisconnect(t *testing.T) {
	conn := NewGCSConnector()

	// Disconnect when not connected should not error
	err := conn.Disconnect(context.Background())
	if err != nil {
		t.Errorf("unexpected error on disconnect: %v", err)
	}

	if conn.IsConnected() {
		t.Error("expected connected to be false")
	}
}

func TestGCSConnectorQueryRequiresKey(t *testing.T) {
	conn := NewGCSConnector()
	conn.SetConnected(true)
	ctx := context.Background()

	t.Run("get_object requires key", func(t *testing.T) {
		_, err := conn.Query(ctx, &base.Query{
			Statement:  "get_object",
			Parameters: map[string]interface{}{},
		})
		if err == nil {
			t.Error("expected error when key is missing")
		}
	})

	t.Run("get_metadata requires key", func(t *testing.T) {
		_, err := conn.Query(ctx, &base.Query{
			Statement:  "get_metadata",
			Parameters: map[string]interface{}{},
		})
		if err == nil {
			t.Error("expected error when key is missing")
		}
	})

	t.Run("signed_url requires key", func(t *testing.T) {
		_, err := conn.Query(ctx, &base.Query{
			Statement:  "signed_url",
			Parameters: map[string]interface{}{},
		})
		if err == nil {
			t.Error("expected error when key is missing")
		}
	})
}

func TestGCSConnectorExecuteRequiresParams(t *testing.T) {
	conn := NewGCSConnector()
	conn.SetConnected(true)
	ctx := context.Background()

	t.Run("put_object requires key", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action:     "put_object",
			Parameters: map[string]interface{}{},
		})
		if err == nil {
			t.Error("expected error when key is missing")
		}
	})

	t.Run("delete_object requires key", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action:     "delete_object",
			Parameters: map[string]interface{}{},
		})
		if err == nil {
			t.Error("expected error when key is missing")
		}
	})

	t.Run("copy_object requires keys", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action:     "copy_object",
			Parameters: map[string]interface{}{},
		})
		if err == nil {
			t.Error("expected error when source_key/dest_key is missing")
		}
	})

	t.Run("create_bucket requires bucket", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action:     "create_bucket",
			Parameters: map[string]interface{}{},
		})
		if err == nil {
			t.Error("expected error when bucket is missing")
		}
	})

	t.Run("delete_bucket requires bucket", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action:     "delete_bucket",
			Parameters: map[string]interface{}{},
		})
		if err == nil {
			t.Error("expected error when bucket is missing")
		}
	})
}

func TestGCSConnectorQueryDefaultsToListObjects(t *testing.T) {
	conn := NewGCSConnector()
	conn.SetConnected(true)
	ctx := context.Background()

	// With empty statement, should default to list_objects but fail because no client
	_, err := conn.Query(ctx, &base.Query{Statement: ""})
	if err == nil {
		t.Error("expected error (no client), but got nil")
	}
	// The error should be about failed operation, not unknown action
	connErr, ok := err.(*base.ConnectorError)
	if ok && connErr.Operation != "Query" {
		t.Errorf("expected Query operation error, got %s", connErr.Operation)
	}
}

func TestGCSConnectorMetrics(t *testing.T) {
	conn := NewGCSConnector()
	metrics := conn.GetMetrics()

	if metrics == nil {
		t.Fatal("expected metrics to be initialized")
	}

	stats := metrics.GetStats()
	if stats.ConnectorType != "gcs" {
		t.Errorf("expected connector type gcs, got %s", stats.ConnectorType)
	}
}

