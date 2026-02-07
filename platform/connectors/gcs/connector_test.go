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

	"cloud.google.com/go/storage"
	"google.golang.org/api/option"

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

// --- Additional tests for improved coverage ---

// newTestConnectorWithClient creates a GCSConnector with a real (but unauthenticated)
// storage.Client. The client is non-nil so the nil-client guard is bypassed,
// allowing us to exercise parameter validation, routing, and error paths that
// occur before any actual GCS API call.
func newTestConnectorWithClient(t *testing.T) *GCSConnector {
	t.Helper()
	conn := NewGCSConnector()

	client, err := storage.NewClient(context.Background(), option.WithoutAuthentication())
	if err != nil {
		t.Fatalf("failed to create test GCS client: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	conn.client = client
	conn.SetConnected(true)
	return conn
}

// ---------- Query statement routing tests ----------

func TestQueryStatementRouting(t *testing.T) {
	conn := newTestConnectorWithClient(t)
	conn.defaultBucket = "test-bucket"
	ctx := context.Background()

	// Each supported statement should route to the correct handler.
	// Without a real GCS backend, operations will fail at the API layer
	// (after passing parameter validation), which is expected.
	supportedStatements := []string{
		"list_objects",
		"get_object",
		"get_object_metadata",
		"list_buckets",
		"get_bucket_metadata",
	}

	for _, stmt := range supportedStatements {
		t.Run(stmt, func(t *testing.T) {
			params := map[string]interface{}{
				"bucket":     "test-bucket",
				"key":        "test-key",
				"project_id": "test-project",
			}
			_, err := conn.Query(ctx, &base.Query{
				Statement:  stmt,
				Parameters: params,
			})
			// We expect errors (no real GCS) but NOT "unsupported query" errors.
			if err != nil {
				connErr, ok := err.(*base.ConnectorError)
				if ok && connErr.Message == "unsupported query: "+stmt {
					t.Errorf("statement %q should be routed to a handler, not treated as unsupported", stmt)
				}
			}
		})
	}
}

func TestQueryUnsupportedStatements(t *testing.T) {
	conn := newTestConnectorWithClient(t)
	ctx := context.Background()

	unsupportedStatements := []string{
		"unknown_query",
		"LIST_OBJECTS",     // case sensitive - uppercase not supported
		"List_Objects",     // mixed case not supported
		"get_objects",      // wrong plural
		"delete_object",    // this is an execute action, not a query
		"put_object",       // this is an execute action, not a query
		"create_bucket",    // this is an execute action, not a query
		"  list_objects  ", // leading/trailing spaces
	}

	for _, stmt := range unsupportedStatements {
		t.Run(stmt, func(t *testing.T) {
			_, err := conn.Query(ctx, &base.Query{
				Statement:  stmt,
				Parameters: map[string]interface{}{},
			})
			if err == nil {
				t.Errorf("expected error for unsupported query statement %q", stmt)
				return
			}
			connErr, ok := err.(*base.ConnectorError)
			if !ok {
				t.Errorf("expected *base.ConnectorError, got %T", err)
				return
			}
			if connErr.Operation != "Query" {
				t.Errorf("expected operation 'Query', got %q", connErr.Operation)
			}
			expectedMsg := "unsupported query: " + stmt
			if connErr.Message != expectedMsg {
				t.Errorf("expected message %q, got %q", expectedMsg, connErr.Message)
			}
		})
	}
}

// ---------- Execute action routing tests ----------

func TestExecuteActionRouting(t *testing.T) {
	conn := newTestConnectorWithClient(t)
	conn.defaultBucket = "test-bucket"
	ctx := context.Background()

	// Each supported action should route to the correct handler.
	supportedActions := []struct {
		action string
		params map[string]interface{}
	}{
		{
			action: "put_object",
			params: map[string]interface{}{
				"bucket":  "test-bucket",
				"key":     "test-key",
				"content": "hello",
			},
		},
		{
			action: "delete_object",
			params: map[string]interface{}{
				"bucket": "test-bucket",
				"key":    "test-key",
			},
		},
		{
			action: "copy_object",
			params: map[string]interface{}{
				"source_bucket":   "test-bucket",
				"source_key":      "src-key",
				"destination_key": "dst-key",
			},
		},
		{
			action: "create_bucket",
			params: map[string]interface{}{
				"bucket":     "new-bucket",
				"project_id": "test-project",
			},
		},
		{
			action: "delete_bucket",
			params: map[string]interface{}{
				"bucket": "test-bucket",
			},
		},
		{
			action: "generate_signed_url",
			params: map[string]interface{}{
				"bucket": "test-bucket",
				"key":    "test-key",
			},
		},
		{
			action: "presign",
			params: map[string]interface{}{
				"bucket": "test-bucket",
				"key":    "test-key",
			},
		},
	}

	for _, tc := range supportedActions {
		t.Run(tc.action, func(t *testing.T) {
			_, err := conn.Execute(ctx, &base.Command{
				Action:     tc.action,
				Parameters: tc.params,
			})
			// We expect errors (no real GCS) but NOT "unsupported action" errors.
			if err != nil {
				connErr, ok := err.(*base.ConnectorError)
				if ok && connErr.Message == "unsupported action: "+tc.action {
					t.Errorf("action %q should be routed to a handler, not treated as unsupported", tc.action)
				}
			}
		})
	}
}

func TestExecuteUnsupportedActions(t *testing.T) {
	conn := newTestConnectorWithClient(t)
	ctx := context.Background()

	unsupportedActions := []string{
		"unknown_action",
		"PUT_OBJECT",       // case sensitive
		"Put_Object",       // mixed case
		"list_objects",     // this is a query statement, not an execute action
		"get_object",       // this is a query statement, not an execute action
		"  put_object  ",   // leading/trailing spaces
		"generate_signed",  // partial match
		"presign_url",      // close but wrong
	}

	for _, action := range unsupportedActions {
		t.Run(action, func(t *testing.T) {
			_, err := conn.Execute(ctx, &base.Command{
				Action:     action,
				Parameters: map[string]interface{}{},
			})
			if err == nil {
				t.Errorf("expected error for unsupported action %q", action)
				return
			}
			connErr, ok := err.(*base.ConnectorError)
			if !ok {
				t.Errorf("expected *base.ConnectorError, got %T", err)
				return
			}
			if connErr.Operation != "Execute" {
				t.Errorf("expected operation 'Execute', got %q", connErr.Operation)
			}
			expectedMsg := "unsupported action: " + action
			if connErr.Message != expectedMsg {
				t.Errorf("expected message %q, got %q", expectedMsg, connErr.Message)
			}
		})
	}
}

// ---------- Query parameter validation ----------

func TestQueryListObjectsRequiresBucket(t *testing.T) {
	conn := newTestConnectorWithClient(t)
	// No default bucket set
	ctx := context.Background()

	_, err := conn.Query(ctx, &base.Query{
		Statement:  "list_objects",
		Parameters: map[string]interface{}{},
	})
	if err == nil {
		t.Fatal("expected error when bucket is missing")
	}
	connErr, ok := err.(*base.ConnectorError)
	if !ok {
		t.Fatalf("expected *base.ConnectorError, got %T", err)
	}
	if connErr.Message != "bucket is required" {
		t.Errorf("expected 'bucket is required', got %q", connErr.Message)
	}
	if connErr.Operation != "Query" {
		t.Errorf("expected operation 'Query', got %q", connErr.Operation)
	}
}

func TestQueryListObjectsUsesDefaultBucket(t *testing.T) {
	conn := newTestConnectorWithClient(t)
	conn.defaultBucket = "my-default-bucket"
	ctx := context.Background()

	// With default bucket set and no bucket in params, listObjects should
	// pass the bucket check (then fail at the API call, which is expected).
	_, err := conn.Query(ctx, &base.Query{
		Statement:  "list_objects",
		Parameters: map[string]interface{}{},
	})
	if err == nil {
		// Unlikely to succeed without real GCS, but not a test failure
		return
	}
	connErr, ok := err.(*base.ConnectorError)
	if !ok {
		t.Fatalf("expected *base.ConnectorError, got %T", err)
	}
	// Should NOT be "bucket is required" since we have a default bucket
	if connErr.Message == "bucket is required" {
		t.Error("expected default bucket to be used, but got 'bucket is required' error")
	}
}

func TestQueryGetObjectRequiresBucketAndKey(t *testing.T) {
	conn := newTestConnectorWithClient(t)
	ctx := context.Background()

	t.Run("missing bucket", func(t *testing.T) {
		_, err := conn.Query(ctx, &base.Query{
			Statement:  "get_object",
			Parameters: map[string]interface{}{},
		})
		if err == nil {
			t.Fatal("expected error")
		}
		connErr := err.(*base.ConnectorError)
		if connErr.Message != "bucket is required" {
			t.Errorf("expected 'bucket is required', got %q", connErr.Message)
		}
	})

	t.Run("has bucket but missing key", func(t *testing.T) {
		_, err := conn.Query(ctx, &base.Query{
			Statement:  "get_object",
			Parameters: map[string]interface{}{"bucket": "my-bucket"},
		})
		if err == nil {
			t.Fatal("expected error")
		}
		connErr := err.(*base.ConnectorError)
		if connErr.Message != "key is required" {
			t.Errorf("expected 'key is required', got %q", connErr.Message)
		}
	})
}

func TestQueryGetObjectMetadataRequiresBucketAndKey(t *testing.T) {
	conn := newTestConnectorWithClient(t)
	ctx := context.Background()

	t.Run("missing bucket", func(t *testing.T) {
		_, err := conn.Query(ctx, &base.Query{
			Statement:  "get_object_metadata",
			Parameters: map[string]interface{}{},
		})
		if err == nil {
			t.Fatal("expected error")
		}
		connErr := err.(*base.ConnectorError)
		if connErr.Message != "bucket is required" {
			t.Errorf("expected 'bucket is required', got %q", connErr.Message)
		}
	})

	t.Run("has bucket but missing key", func(t *testing.T) {
		_, err := conn.Query(ctx, &base.Query{
			Statement:  "get_object_metadata",
			Parameters: map[string]interface{}{"bucket": "my-bucket"},
		})
		if err == nil {
			t.Fatal("expected error")
		}
		connErr := err.(*base.ConnectorError)
		if connErr.Message != "key is required" {
			t.Errorf("expected 'key is required', got %q", connErr.Message)
		}
	})
}

func TestQueryListBucketsRequiresProjectID(t *testing.T) {
	conn := newTestConnectorWithClient(t)
	// No default projectID set
	ctx := context.Background()

	t.Run("missing project_id and no default", func(t *testing.T) {
		_, err := conn.Query(ctx, &base.Query{
			Statement:  "list_buckets",
			Parameters: map[string]interface{}{},
		})
		if err == nil {
			t.Fatal("expected error")
		}
		connErr := err.(*base.ConnectorError)
		if connErr.Message != "project_id is required" {
			t.Errorf("expected 'project_id is required', got %q", connErr.Message)
		}
	})

	t.Run("project_id from connector default", func(t *testing.T) {
		conn.projectID = "default-project"
		_, err := conn.Query(ctx, &base.Query{
			Statement:  "list_buckets",
			Parameters: map[string]interface{}{},
		})
		if err == nil {
			return // Unlikely without real GCS but not a failure
		}
		connErr, ok := err.(*base.ConnectorError)
		if !ok {
			t.Fatalf("expected *base.ConnectorError, got %T", err)
		}
		// Should NOT be "project_id is required"
		if connErr.Message == "project_id is required" {
			t.Error("expected default projectID to be used")
		}
	})

	t.Run("project_id from params overrides default", func(t *testing.T) {
		conn.projectID = "default-project"
		_, err := conn.Query(ctx, &base.Query{
			Statement: "list_buckets",
			Parameters: map[string]interface{}{
				"project_id": "override-project",
			},
		})
		if err == nil {
			return
		}
		connErr, ok := err.(*base.ConnectorError)
		if !ok {
			t.Fatalf("expected *base.ConnectorError, got %T", err)
		}
		if connErr.Message == "project_id is required" {
			t.Error("expected project_id from params to be used")
		}
	})
}

func TestQueryGetBucketMetadataRequiresBucket(t *testing.T) {
	conn := newTestConnectorWithClient(t)
	ctx := context.Background()

	_, err := conn.Query(ctx, &base.Query{
		Statement:  "get_bucket_metadata",
		Parameters: map[string]interface{}{},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	connErr := err.(*base.ConnectorError)
	if connErr.Message != "bucket is required" {
		t.Errorf("expected 'bucket is required', got %q", connErr.Message)
	}
}

// ---------- Execute parameter validation ----------

func TestExecutePutObjectValidation(t *testing.T) {
	conn := newTestConnectorWithClient(t)
	ctx := context.Background()

	t.Run("missing bucket", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action:     "put_object",
			Parameters: map[string]interface{}{"key": "test.txt"},
		})
		if err == nil {
			t.Fatal("expected error")
		}
		connErr := err.(*base.ConnectorError)
		if connErr.Message != "bucket is required" {
			t.Errorf("expected 'bucket is required', got %q", connErr.Message)
		}
		if connErr.Operation != "Execute" {
			t.Errorf("expected operation 'Execute', got %q", connErr.Operation)
		}
	})

	t.Run("has bucket but missing key", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action:     "put_object",
			Parameters: map[string]interface{}{"bucket": "my-bucket"},
		})
		if err == nil {
			t.Fatal("expected error")
		}
		connErr := err.(*base.ConnectorError)
		if connErr.Message != "key is required" {
			t.Errorf("expected 'key is required', got %q", connErr.Message)
		}
	})
}

func TestExecuteDeleteObjectValidation(t *testing.T) {
	conn := newTestConnectorWithClient(t)
	ctx := context.Background()

	t.Run("missing bucket", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action:     "delete_object",
			Parameters: map[string]interface{}{"key": "test.txt"},
		})
		if err == nil {
			t.Fatal("expected error")
		}
		connErr := err.(*base.ConnectorError)
		if connErr.Message != "bucket is required" {
			t.Errorf("expected 'bucket is required', got %q", connErr.Message)
		}
	})

	t.Run("has bucket but missing key", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action:     "delete_object",
			Parameters: map[string]interface{}{"bucket": "my-bucket"},
		})
		if err == nil {
			t.Fatal("expected error")
		}
		connErr := err.(*base.ConnectorError)
		if connErr.Message != "key is required" {
			t.Errorf("expected 'key is required', got %q", connErr.Message)
		}
	})
}

func TestExecuteCopyObjectValidation(t *testing.T) {
	conn := newTestConnectorWithClient(t)
	ctx := context.Background()

	t.Run("missing source_bucket with no default", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action:     "copy_object",
			Parameters: map[string]interface{}{},
		})
		if err == nil {
			t.Fatal("expected error")
		}
		connErr := err.(*base.ConnectorError)
		if connErr.Message != "source_bucket is required" {
			t.Errorf("expected 'source_bucket is required', got %q", connErr.Message)
		}
	})

	t.Run("source_bucket defaults to defaultBucket", func(t *testing.T) {
		conn.defaultBucket = "default-bucket"
		_, err := conn.Execute(ctx, &base.Command{
			Action:     "copy_object",
			Parameters: map[string]interface{}{},
		})
		if err == nil {
			t.Fatal("expected error")
		}
		connErr := err.(*base.ConnectorError)
		// Should pass source_bucket check and fail on source_key
		if connErr.Message != "source_key is required" {
			t.Errorf("expected 'source_key is required', got %q", connErr.Message)
		}
		conn.defaultBucket = "" // Reset
	})

	t.Run("has source_bucket and source_key but missing destination_key", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action: "copy_object",
			Parameters: map[string]interface{}{
				"source_bucket": "src-bucket",
				"source_key":    "src-key",
			},
		})
		if err == nil {
			t.Fatal("expected error")
		}
		connErr := err.(*base.ConnectorError)
		if connErr.Message != "destination_key is required" {
			t.Errorf("expected 'destination_key is required', got %q", connErr.Message)
		}
	})
}

func TestExecuteCreateBucketValidation(t *testing.T) {
	conn := newTestConnectorWithClient(t)
	ctx := context.Background()

	t.Run("missing bucket name", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action:     "create_bucket",
			Parameters: map[string]interface{}{},
		})
		if err == nil {
			t.Fatal("expected error")
		}
		connErr := err.(*base.ConnectorError)
		if connErr.Message != "bucket name is required" {
			t.Errorf("expected 'bucket name is required', got %q", connErr.Message)
		}
	})

	t.Run("has bucket but missing project_id with no default", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action: "create_bucket",
			Parameters: map[string]interface{}{
				"bucket": "new-bucket",
			},
		})
		if err == nil {
			t.Fatal("expected error")
		}
		connErr := err.(*base.ConnectorError)
		if connErr.Message != "project_id is required" {
			t.Errorf("expected 'project_id is required', got %q", connErr.Message)
		}
	})

	t.Run("project_id falls back to connector default", func(t *testing.T) {
		conn.projectID = "default-project"
		_, err := conn.Execute(ctx, &base.Command{
			Action: "create_bucket",
			Parameters: map[string]interface{}{
				"bucket": "new-bucket",
			},
		})
		if err == nil {
			return // Unlikely, but acceptable
		}
		connErr, ok := err.(*base.ConnectorError)
		if !ok {
			t.Fatalf("expected *base.ConnectorError, got %T", err)
		}
		if connErr.Message == "project_id is required" {
			t.Error("expected default projectID to be used, but got project_id is required")
		}
		conn.projectID = "" // Reset
	})
}

func TestExecuteDeleteBucketValidation(t *testing.T) {
	conn := newTestConnectorWithClient(t)
	ctx := context.Background()

	_, err := conn.Execute(ctx, &base.Command{
		Action:     "delete_bucket",
		Parameters: map[string]interface{}{},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	connErr := err.(*base.ConnectorError)
	if connErr.Message != "bucket name is required" {
		t.Errorf("expected 'bucket name is required', got %q", connErr.Message)
	}
}

func TestExecuteGenerateSignedURLValidation(t *testing.T) {
	conn := newTestConnectorWithClient(t)
	ctx := context.Background()

	t.Run("generate_signed_url missing bucket", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action:     "generate_signed_url",
			Parameters: map[string]interface{}{},
		})
		if err == nil {
			t.Fatal("expected error")
		}
		connErr := err.(*base.ConnectorError)
		if connErr.Message != "bucket is required" {
			t.Errorf("expected 'bucket is required', got %q", connErr.Message)
		}
	})

	t.Run("generate_signed_url has bucket but missing key", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action:     "generate_signed_url",
			Parameters: map[string]interface{}{"bucket": "my-bucket"},
		})
		if err == nil {
			t.Fatal("expected error")
		}
		connErr := err.(*base.ConnectorError)
		if connErr.Message != "key is required" {
			t.Errorf("expected 'key is required', got %q", connErr.Message)
		}
	})

	t.Run("presign alias missing bucket", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action:     "presign",
			Parameters: map[string]interface{}{},
		})
		if err == nil {
			t.Fatal("expected error")
		}
		connErr := err.(*base.ConnectorError)
		if connErr.Message != "bucket is required" {
			t.Errorf("expected 'bucket is required', got %q", connErr.Message)
		}
	})

	t.Run("presign alias has bucket but missing key", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action:     "presign",
			Parameters: map[string]interface{}{"bucket": "my-bucket"},
		})
		if err == nil {
			t.Fatal("expected error")
		}
		connErr := err.(*base.ConnectorError)
		if connErr.Message != "key is required" {
			t.Errorf("expected 'key is required', got %q", connErr.Message)
		}
	})
}

// ---------- Not connected error verification ----------

func TestQueryNotConnectedErrorContent(t *testing.T) {
	conn := NewGCSConnector()
	// client is nil, not connected
	ctx := context.Background()

	statements := []string{"list_objects", "get_object", "get_object_metadata", "list_buckets", "get_bucket_metadata"}

	for _, stmt := range statements {
		t.Run(stmt, func(t *testing.T) {
			_, err := conn.Query(ctx, &base.Query{Statement: stmt})
			if err == nil {
				t.Fatal("expected error")
			}
			connErr, ok := err.(*base.ConnectorError)
			if !ok {
				t.Fatalf("expected *base.ConnectorError, got %T", err)
			}
			if connErr.Operation != "Query" {
				t.Errorf("expected operation 'Query', got %q", connErr.Operation)
			}
			if connErr.Message != "not connected" {
				t.Errorf("expected message 'not connected', got %q", connErr.Message)
			}
			if connErr.Cause != nil {
				t.Errorf("expected nil cause, got %v", connErr.Cause)
			}
		})
	}
}

func TestExecuteNotConnectedErrorContent(t *testing.T) {
	conn := NewGCSConnector()
	// client is nil, not connected
	ctx := context.Background()

	actions := []string{"put_object", "delete_object", "copy_object", "create_bucket", "delete_bucket", "generate_signed_url", "presign"}

	for _, action := range actions {
		t.Run(action, func(t *testing.T) {
			_, err := conn.Execute(ctx, &base.Command{Action: action})
			if err == nil {
				t.Fatal("expected error")
			}
			connErr, ok := err.(*base.ConnectorError)
			if !ok {
				t.Fatalf("expected *base.ConnectorError, got %T", err)
			}
			if connErr.Operation != "Execute" {
				t.Errorf("expected operation 'Execute', got %q", connErr.Operation)
			}
			if connErr.Message != "not connected" {
				t.Errorf("expected message 'not connected', got %q", connErr.Message)
			}
		})
	}
}

// ---------- ConnectorError.Error() format verification ----------

func TestConnectorErrorFormat(t *testing.T) {
	conn := NewGCSConnector()
	conn.SetName("my-gcs")
	ctx := context.Background()

	_, err := conn.Query(ctx, &base.Query{Statement: "list_objects"})
	if err == nil {
		t.Fatal("expected error")
	}

	// Error string should contain connector name and operation
	errStr := err.Error()
	if errStr != "my-gcs.Query: not connected" {
		t.Errorf("expected 'my-gcs.Query: not connected', got %q", errStr)
	}
}

// ---------- Timeout override logic ----------

func TestQueryTimeoutOverride(t *testing.T) {
	conn := newTestConnectorWithClient(t)
	conn.defaultBucket = "test-bucket"
	ctx := context.Background()

	// Query with custom timeout - should not panic and should use the override.
	// The timeout is applied via context.WithTimeout, which always succeeds.
	// We verify the code path doesn't panic with a zero, negative, or positive timeout.
	timeouts := []time.Duration{
		0,                  // Should use connector default
		1 * time.Second,    // Short override
		60 * time.Second,   // Long override
	}

	for _, timeout := range timeouts {
		t.Run(timeout.String(), func(t *testing.T) {
			_, err := conn.Query(ctx, &base.Query{
				Statement:  "list_objects",
				Parameters: map[string]interface{}{"bucket": "test-bucket"},
				Timeout:    timeout,
			})
			// Error is expected (no real GCS), but no panic is the key assertion
			if err == nil {
				return
			}
			connErr, ok := err.(*base.ConnectorError)
			if !ok {
				t.Fatalf("expected *base.ConnectorError, got %T", err)
			}
			// Should never be "not connected" since we have a client
			if connErr.Message == "not connected" {
				t.Error("unexpected 'not connected' error with client set")
			}
		})
	}
}

func TestExecuteTimeoutOverride(t *testing.T) {
	conn := newTestConnectorWithClient(t)
	ctx := context.Background()

	// Timeout override with Execute path.
	// Using create_bucket without project_id to hit the validation error
	// (which exercises the timeout setup code path before the validation).
	timeouts := []time.Duration{
		0,
		5 * time.Second,
		120 * time.Second,
	}

	for _, timeout := range timeouts {
		t.Run(timeout.String(), func(t *testing.T) {
			_, err := conn.Execute(ctx, &base.Command{
				Action:     "create_bucket",
				Parameters: map[string]interface{}{},
				Timeout:    timeout,
			})
			if err == nil {
				t.Fatal("expected error")
			}
			connErr := err.(*base.ConnectorError)
			// Should hit validation, not "not connected"
			if connErr.Message == "not connected" {
				t.Error("unexpected 'not connected' error with client set")
			}
		})
	}
}

// ---------- Default bucket fallback edge cases ----------

func TestGetBucketEdgeCases(t *testing.T) {
	conn := NewGCSConnector()

	t.Run("nil params with no default", func(t *testing.T) {
		if b := conn.getBucket(nil); b != "" {
			t.Errorf("expected empty string, got %q", b)
		}
	})

	t.Run("nil params with default", func(t *testing.T) {
		conn.defaultBucket = "fallback"
		if b := conn.getBucket(nil); b != "fallback" {
			t.Errorf("expected 'fallback', got %q", b)
		}
	})

	t.Run("empty bucket in params falls back to default", func(t *testing.T) {
		conn.defaultBucket = "fallback"
		params := map[string]interface{}{"bucket": ""}
		if b := conn.getBucket(params); b != "fallback" {
			t.Errorf("expected 'fallback', got %q", b)
		}
	})

	t.Run("non-string bucket in params falls back to default", func(t *testing.T) {
		conn.defaultBucket = "fallback"
		params := map[string]interface{}{"bucket": 123}
		if b := conn.getBucket(params); b != "fallback" {
			t.Errorf("expected 'fallback', got %q", b)
		}
	})

	t.Run("bucket param takes priority over default", func(t *testing.T) {
		conn.defaultBucket = "fallback"
		params := map[string]interface{}{"bucket": "explicit"}
		if b := conn.getBucket(params); b != "explicit" {
			t.Errorf("expected 'explicit', got %q", b)
		}
	})

	t.Run("no bucket param and no default", func(t *testing.T) {
		conn.defaultBucket = ""
		params := map[string]interface{}{"other_key": "value"}
		if b := conn.getBucket(params); b != "" {
			t.Errorf("expected empty string, got %q", b)
		}
	})
}

// ---------- Helper function edge cases ----------

func TestGetStringParamEdgeCases(t *testing.T) {
	t.Run("non-string value returns default", func(t *testing.T) {
		params := map[string]interface{}{
			"int_val":   42,
			"bool_val":  true,
			"float_val": 3.14,
			"nil_val":   nil,
		}

		if v := getStringParam(params, "int_val", "default"); v != "default" {
			t.Errorf("expected 'default' for int value, got %q", v)
		}
		if v := getStringParam(params, "bool_val", "default"); v != "default" {
			t.Errorf("expected 'default' for bool value, got %q", v)
		}
		if v := getStringParam(params, "float_val", "default"); v != "default" {
			t.Errorf("expected 'default' for float value, got %q", v)
		}
		if v := getStringParam(params, "nil_val", "default"); v != "default" {
			t.Errorf("expected 'default' for nil value, got %q", v)
		}
	})

	t.Run("empty string value is returned", func(t *testing.T) {
		params := map[string]interface{}{"key": ""}
		if v := getStringParam(params, "key", "default"); v != "" {
			t.Errorf("expected empty string, got %q", v)
		}
	})

	t.Run("empty default is used when key missing", func(t *testing.T) {
		params := map[string]interface{}{}
		if v := getStringParam(params, "missing", ""); v != "" {
			t.Errorf("expected empty string default, got %q", v)
		}
	})
}

func TestGetIntParamEdgeCases(t *testing.T) {
	t.Run("bool value returns default", func(t *testing.T) {
		params := map[string]interface{}{"val": true}
		if v := getIntParam(params, "val", 77); v != 77 {
			t.Errorf("expected 77 for bool, got %d", v)
		}
	})

	t.Run("string number returns default", func(t *testing.T) {
		params := map[string]interface{}{"val": "42"}
		if v := getIntParam(params, "val", 77); v != 77 {
			t.Errorf("expected 77 for string number, got %d", v)
		}
	})

	t.Run("nil value returns default", func(t *testing.T) {
		params := map[string]interface{}{"val": nil}
		if v := getIntParam(params, "val", 55); v != 55 {
			t.Errorf("expected 55 for nil, got %d", v)
		}
	})

	t.Run("zero int is returned not default", func(t *testing.T) {
		params := map[string]interface{}{"val": 0}
		if v := getIntParam(params, "val", 99); v != 0 {
			t.Errorf("expected 0, got %d", v)
		}
	})

	t.Run("negative int", func(t *testing.T) {
		params := map[string]interface{}{"val": -5}
		if v := getIntParam(params, "val", 99); v != -5 {
			t.Errorf("expected -5, got %d", v)
		}
	})

	t.Run("negative int64", func(t *testing.T) {
		params := map[string]interface{}{"val": int64(-100)}
		if v := getIntParam(params, "val", 99); v != -100 {
			t.Errorf("expected -100, got %d", v)
		}
	})

	t.Run("float64 with fractional part truncates", func(t *testing.T) {
		params := map[string]interface{}{"val": float64(3.9)}
		if v := getIntParam(params, "val", 99); v != 3 {
			t.Errorf("expected 3 (truncated), got %d", v)
		}
	})

	t.Run("negative float64 truncates", func(t *testing.T) {
		params := map[string]interface{}{"val": float64(-2.7)}
		if v := getIntParam(params, "val", 99); v != -2 {
			t.Errorf("expected -2 (truncated), got %d", v)
		}
	})

	t.Run("large float64", func(t *testing.T) {
		params := map[string]interface{}{"val": float64(1000000)}
		if v := getIntParam(params, "val", 99); v != 1000000 {
			t.Errorf("expected 1000000, got %d", v)
		}
	})
}

// ---------- Metrics recording tests ----------

func TestQueryMetricsRecordedOnError(t *testing.T) {
	conn := newTestConnectorWithClient(t)
	ctx := context.Background()

	metrics := conn.GetMetrics()
	metrics.Reset()

	// Trigger an unsupported query error
	_, _ = conn.Query(ctx, &base.Query{Statement: "bad_statement"})

	stats := metrics.GetStats()
	if stats.QueriesTotal != 1 {
		t.Errorf("expected 1 query recorded, got %d", stats.QueriesTotal)
	}
	if stats.ErrorsTotal != 1 {
		t.Errorf("expected 1 error recorded, got %d", stats.ErrorsTotal)
	}
}

func TestExecuteMetricsRecordedOnError(t *testing.T) {
	conn := newTestConnectorWithClient(t)
	ctx := context.Background()

	metrics := conn.GetMetrics()
	metrics.Reset()

	// Trigger an unsupported action error
	_, _ = conn.Execute(ctx, &base.Command{Action: "bad_action"})

	stats := metrics.GetStats()
	if stats.ExecutesTotal != 1 {
		t.Errorf("expected 1 execute recorded, got %d", stats.ExecutesTotal)
	}
	if stats.ErrorsTotal != 1 {
		t.Errorf("expected 1 error recorded, got %d", stats.ErrorsTotal)
	}
}

func TestQueryMetricsRecordedOnValidationError(t *testing.T) {
	conn := newTestConnectorWithClient(t)
	ctx := context.Background()

	metrics := conn.GetMetrics()
	metrics.Reset()

	// Trigger a validation error (missing bucket)
	_, _ = conn.Query(ctx, &base.Query{
		Statement:  "list_objects",
		Parameters: map[string]interface{}{},
	})

	stats := metrics.GetStats()
	if stats.QueriesTotal != 1 {
		t.Errorf("expected 1 query recorded, got %d", stats.QueriesTotal)
	}
	if stats.ErrorsTotal != 1 {
		t.Errorf("expected 1 error recorded, got %d", stats.ErrorsTotal)
	}
}

func TestExecuteMetricsRecordedOnValidationError(t *testing.T) {
	conn := newTestConnectorWithClient(t)
	ctx := context.Background()

	metrics := conn.GetMetrics()
	metrics.Reset()

	// Trigger a validation error (missing bucket for put_object)
	_, _ = conn.Execute(ctx, &base.Command{
		Action:     "put_object",
		Parameters: map[string]interface{}{},
	})

	stats := metrics.GetStats()
	if stats.ExecutesTotal != 1 {
		t.Errorf("expected 1 execute recorded, got %d", stats.ExecutesTotal)
	}
	if stats.ErrorsTotal != 1 {
		t.Errorf("expected 1 error recorded, got %d", stats.ErrorsTotal)
	}
}

func TestMultipleOperationsAccumulateMetrics(t *testing.T) {
	conn := newTestConnectorWithClient(t)
	ctx := context.Background()

	metrics := conn.GetMetrics()
	metrics.Reset()

	// Run multiple queries and executes
	for i := 0; i < 3; i++ {
		_, _ = conn.Query(ctx, &base.Query{Statement: "bad"})
	}
	for i := 0; i < 2; i++ {
		_, _ = conn.Execute(ctx, &base.Command{Action: "bad"})
	}

	stats := metrics.GetStats()
	if stats.QueriesTotal != 3 {
		t.Errorf("expected 3 queries, got %d", stats.QueriesTotal)
	}
	if stats.ExecutesTotal != 2 {
		t.Errorf("expected 2 executes, got %d", stats.ExecutesTotal)
	}
	if stats.ErrorsTotal != 5 {
		t.Errorf("expected 5 errors, got %d", stats.ErrorsTotal)
	}
}

// ---------- HealthCheck detail verification ----------

func TestHealthCheckNotConnectedDetails(t *testing.T) {
	conn := NewGCSConnector()
	ctx := context.Background()

	status, err := conn.HealthCheck(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if status.Healthy {
		t.Error("expected unhealthy status")
	}

	if status.Error != "GCS client not initialized" {
		t.Errorf("expected 'GCS client not initialized', got %q", status.Error)
	}

	if status.Timestamp.IsZero() {
		t.Error("expected non-zero timestamp")
	}
}

// ---------- Disconnect edge cases ----------

func TestDisconnectWhenConnectedWithNoClient(t *testing.T) {
	conn := NewGCSConnector()
	conn.SetConnected(true)
	// client is nil but connected is true

	err := conn.Disconnect(context.Background())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if conn.IsConnected() {
		t.Error("expected connected to be false after disconnect")
	}
}

func TestDisconnectIdempotent(t *testing.T) {
	conn := NewGCSConnector()

	// Multiple disconnects should not error
	for i := 0; i < 3; i++ {
		err := conn.Disconnect(context.Background())
		if err != nil {
			t.Errorf("disconnect %d: unexpected error: %v", i, err)
		}
	}
}

// ---------- Query/Execute nil parameters ----------

func TestQueryWithNilParameters(t *testing.T) {
	conn := newTestConnectorWithClient(t)
	ctx := context.Background()

	// nil parameters should be handled gracefully by getStringParam
	t.Run("list_objects with nil params", func(t *testing.T) {
		_, err := conn.Query(ctx, &base.Query{
			Statement:  "list_objects",
			Parameters: nil,
		})
		if err == nil {
			t.Fatal("expected error")
		}
		connErr := err.(*base.ConnectorError)
		if connErr.Message != "bucket is required" {
			t.Errorf("expected 'bucket is required', got %q", connErr.Message)
		}
	})

	t.Run("get_object with nil params", func(t *testing.T) {
		_, err := conn.Query(ctx, &base.Query{
			Statement:  "get_object",
			Parameters: nil,
		})
		if err == nil {
			t.Fatal("expected error")
		}
		connErr := err.(*base.ConnectorError)
		if connErr.Message != "bucket is required" {
			t.Errorf("expected 'bucket is required', got %q", connErr.Message)
		}
	})

	t.Run("list_buckets with nil params", func(t *testing.T) {
		_, err := conn.Query(ctx, &base.Query{
			Statement:  "list_buckets",
			Parameters: nil,
		})
		if err == nil {
			t.Fatal("expected error")
		}
		connErr := err.(*base.ConnectorError)
		if connErr.Message != "project_id is required" {
			t.Errorf("expected 'project_id is required', got %q", connErr.Message)
		}
	})
}

func TestExecuteWithNilParameters(t *testing.T) {
	conn := newTestConnectorWithClient(t)
	ctx := context.Background()

	t.Run("put_object with nil params", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action:     "put_object",
			Parameters: nil,
		})
		if err == nil {
			t.Fatal("expected error")
		}
		connErr := err.(*base.ConnectorError)
		if connErr.Message != "bucket is required" {
			t.Errorf("expected 'bucket is required', got %q", connErr.Message)
		}
	})

	t.Run("copy_object with nil params", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action:     "copy_object",
			Parameters: nil,
		})
		if err == nil {
			t.Fatal("expected error")
		}
		connErr := err.(*base.ConnectorError)
		if connErr.Message != "source_bucket is required" {
			t.Errorf("expected 'source_bucket is required', got %q", connErr.Message)
		}
	})

	t.Run("create_bucket with nil params", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action:     "create_bucket",
			Parameters: nil,
		})
		if err == nil {
			t.Fatal("expected error")
		}
		connErr := err.(*base.ConnectorError)
		if connErr.Message != "bucket name is required" {
			t.Errorf("expected 'bucket name is required', got %q", connErr.Message)
		}
	})

	t.Run("delete_bucket with nil params", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action:     "delete_bucket",
			Parameters: nil,
		})
		if err == nil {
			t.Fatal("expected error")
		}
		connErr := err.(*base.ConnectorError)
		if connErr.Message != "bucket name is required" {
			t.Errorf("expected 'bucket name is required', got %q", connErr.Message)
		}
	})

	t.Run("generate_signed_url with nil params", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action:     "generate_signed_url",
			Parameters: nil,
		})
		if err == nil {
			t.Fatal("expected error")
		}
		connErr := err.(*base.ConnectorError)
		if connErr.Message != "bucket is required" {
			t.Errorf("expected 'bucket is required', got %q", connErr.Message)
		}
	})
}

// ---------- Interface compliance ----------

func TestGCSConnectorImplementsConnectorInterface(t *testing.T) {
	// The compile-time check exists (var _ base.Connector = (*GCSConnector)(nil))
	// but we verify it at runtime too.
	var c base.Connector = NewGCSConnector()
	if c == nil {
		t.Fatal("expected non-nil connector")
	}
	if c.Type() != "gcs" {
		t.Errorf("expected type 'gcs', got %q", c.Type())
	}
}

// ---------- ConnectorError name in errors ----------

func TestErrorsContainConnectorName(t *testing.T) {
	conn := newTestConnectorWithClient(t)
	conn.SetName("prod-gcs-connector")
	ctx := context.Background()

	t.Run("query unsupported includes connector name", func(t *testing.T) {
		_, err := conn.Query(ctx, &base.Query{Statement: "bad"})
		if err == nil {
			t.Fatal("expected error")
		}
		connErr := err.(*base.ConnectorError)
		if connErr.ConnectorName != "prod-gcs-connector" {
			t.Errorf("expected connector name 'prod-gcs-connector', got %q", connErr.ConnectorName)
		}
	})

	t.Run("execute unsupported includes connector name", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{Action: "bad"})
		if err == nil {
			t.Fatal("expected error")
		}
		connErr := err.(*base.ConnectorError)
		if connErr.ConnectorName != "prod-gcs-connector" {
			t.Errorf("expected connector name 'prod-gcs-connector', got %q", connErr.ConnectorName)
		}
	})

	t.Run("query validation error includes connector name", func(t *testing.T) {
		_, err := conn.Query(ctx, &base.Query{
			Statement:  "list_objects",
			Parameters: map[string]interface{}{},
		})
		if err == nil {
			t.Fatal("expected error")
		}
		connErr := err.(*base.ConnectorError)
		if connErr.ConnectorName != "prod-gcs-connector" {
			t.Errorf("expected connector name 'prod-gcs-connector', got %q", connErr.ConnectorName)
		}
	})
}

// ---------- Default bucket used across operations ----------

func TestDefaultBucketUsedForQueryOperations(t *testing.T) {
	conn := newTestConnectorWithClient(t)
	conn.defaultBucket = "shared-bucket"
	ctx := context.Background()

	// Each query operation that requires a bucket should use the default
	// when none is provided in params.
	queryStatements := []string{
		"list_objects",
		"get_bucket_metadata",
	}

	for _, stmt := range queryStatements {
		t.Run(stmt, func(t *testing.T) {
			_, err := conn.Query(ctx, &base.Query{
				Statement:  stmt,
				Parameters: map[string]interface{}{},
			})
			if err == nil {
				return // OK if it somehow passes
			}
			connErr, ok := err.(*base.ConnectorError)
			if !ok {
				return
			}
			// The bucket check should pass with the default
			if connErr.Message == "bucket is required" {
				t.Errorf("%s: expected default bucket to be used, but got 'bucket is required'", stmt)
			}
		})
	}
}

func TestDefaultBucketUsedForExecuteOperations(t *testing.T) {
	conn := newTestConnectorWithClient(t)
	conn.defaultBucket = "shared-bucket"
	ctx := context.Background()

	// put_object and delete_object use getBucket which falls back to default
	t.Run("put_object uses default bucket", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action:     "put_object",
			Parameters: map[string]interface{}{}, // no bucket, no key
		})
		if err == nil {
			t.Fatal("expected error")
		}
		connErr := err.(*base.ConnectorError)
		// Should fail on missing key, NOT missing bucket
		if connErr.Message != "key is required" {
			t.Errorf("expected 'key is required' (bucket should use default), got %q", connErr.Message)
		}
	})

	t.Run("delete_object uses default bucket", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action:     "delete_object",
			Parameters: map[string]interface{}{}, // no bucket, no key
		})
		if err == nil {
			t.Fatal("expected error")
		}
		connErr := err.(*base.ConnectorError)
		if connErr.Message != "key is required" {
			t.Errorf("expected 'key is required' (bucket should use default), got %q", connErr.Message)
		}
	})

	t.Run("generate_signed_url uses default bucket", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action:     "generate_signed_url",
			Parameters: map[string]interface{}{}, // no bucket, no key
		})
		if err == nil {
			t.Fatal("expected error")
		}
		connErr := err.(*base.ConnectorError)
		if connErr.Message != "key is required" {
			t.Errorf("expected 'key is required' (bucket should use default), got %q", connErr.Message)
		}
	})
}

// ---------- Empty statement / empty action ----------

func TestQueryEmptyStatementRouting(t *testing.T) {
	conn := newTestConnectorWithClient(t)
	ctx := context.Background()

	_, err := conn.Query(ctx, &base.Query{
		Statement:  "",
		Parameters: map[string]interface{}{},
	})
	if err == nil {
		t.Fatal("expected error for empty statement")
	}
	connErr, ok := err.(*base.ConnectorError)
	if !ok {
		t.Fatalf("expected *base.ConnectorError, got %T", err)
	}
	// Empty statement falls through to default case
	expectedMsg := "unsupported query: "
	if connErr.Message != expectedMsg {
		t.Errorf("expected %q, got %q", expectedMsg, connErr.Message)
	}
}

func TestExecuteEmptyActionRouting(t *testing.T) {
	conn := newTestConnectorWithClient(t)
	ctx := context.Background()

	_, err := conn.Execute(ctx, &base.Command{
		Action:     "",
		Parameters: map[string]interface{}{},
	})
	if err == nil {
		t.Fatal("expected error for empty action")
	}
	connErr, ok := err.(*base.ConnectorError)
	if !ok {
		t.Fatalf("expected *base.ConnectorError, got %T", err)
	}
	expectedMsg := "unsupported action: "
	if connErr.Message != expectedMsg {
		t.Errorf("expected %q, got %q", expectedMsg, connErr.Message)
	}
}

// ---------- Connector name defaults to type when not set ----------

func TestConnectorNameDefaultsToType(t *testing.T) {
	conn := NewGCSConnector()
	// Do not call SetName

	if conn.Name() != "gcs" {
		t.Errorf("expected name to default to 'gcs', got %q", conn.Name())
	}
}

// ---------- copy_object destination_bucket defaults ----------

func TestCopyObjectDestinationBucketDefaultsToSource(t *testing.T) {
	conn := newTestConnectorWithClient(t)
	ctx := context.Background()

	// When destination_bucket is not provided, it defaults to source_bucket.
	// We can verify this by providing source_bucket, source_key, and
	// destination_key. The copy should attempt to use source_bucket as
	// destination_bucket (and fail at the API level, which is fine).
	_, err := conn.Execute(ctx, &base.Command{
		Action: "copy_object",
		Parameters: map[string]interface{}{
			"source_bucket":   "my-src-bucket",
			"source_key":      "src.txt",
			"destination_key": "dst.txt",
			// destination_bucket not set - should default to source_bucket
		},
	})
	if err == nil {
		return // Unlikely but fine
	}
	connErr, ok := err.(*base.ConnectorError)
	if !ok {
		t.Fatalf("expected *base.ConnectorError, got %T", err)
	}
	// Should NOT fail on missing destination_bucket or source_bucket
	if connErr.Message == "source_bucket is required" || connErr.Message == "destination_key is required" {
		t.Errorf("unexpected validation error: %q", connErr.Message)
	}
}

