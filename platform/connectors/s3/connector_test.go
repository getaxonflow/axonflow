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

package s3

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"

	"axonflow/platform/connectors/base"
)

// newTestConnectorWithClient creates a connector with a non-nil S3 client
// (but no real AWS endpoint). This allows tests to pass the nil-client check
// and reach the action routing and parameter validation logic.
func newTestConnectorWithClient() *S3Connector {
	conn := NewS3Connector()
	conn.SetConnected(true)
	conn.client = s3.New(s3.Options{})
	conn.presignClient = s3.NewPresignClient(conn.client)
	return conn
}

func TestNewS3Connector(t *testing.T) {
	conn := NewS3Connector()

	if conn == nil {
		t.Fatal("expected connector to be created")
	}

	if conn.Type() != "s3" {
		t.Errorf("expected type s3, got %s", conn.Type())
	}

	if conn.Version() != "1.0.0" {
		t.Errorf("expected version 1.0.0, got %s", conn.Version())
	}

	caps := conn.Capabilities()
	if len(caps) != 5 {
		t.Errorf("expected 5 capabilities, got %d", len(caps))
	}

	expectedCaps := map[string]bool{
		"query":     true,
		"execute":   true,
		"presign":   true,
		"multipart": true,
		"streaming": true,
	}

	for _, cap := range caps {
		if !expectedCaps[cap] {
			t.Errorf("unexpected capability: %s", cap)
		}
	}
}

func TestS3ConnectorQueryWithoutConnect(t *testing.T) {
	conn := NewS3Connector()
	ctx := context.Background()

	_, err := conn.Query(ctx, &base.Query{Statement: "list_objects"})
	if err == nil {
		t.Error("expected error when querying without connection")
	}
}

func TestS3ConnectorExecuteWithoutConnect(t *testing.T) {
	conn := NewS3Connector()
	ctx := context.Background()

	_, err := conn.Execute(ctx, &base.Command{Action: "put_object"})
	if err == nil {
		t.Error("expected error when executing without connection")
	}
}

func TestS3ConnectorHealthCheckWithoutConnect(t *testing.T) {
	conn := NewS3Connector()
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

	t.Run("getStringSliceParam", func(t *testing.T) {
		params := map[string]interface{}{
			"strings":    []string{"a", "b", "c"},
			"interfaces": []interface{}{"x", "y", "z"},
			"invalid":    "not a slice",
		}

		if v := getStringSliceParam(params, "strings"); len(v) != 3 {
			t.Errorf("expected 3 strings, got %d", len(v))
		}

		if v := getStringSliceParam(params, "interfaces"); len(v) != 3 {
			t.Errorf("expected 3 strings from interfaces, got %d", len(v))
		}

		if v := getStringSliceParam(params, "invalid"); v != nil {
			t.Error("expected nil for invalid type")
		}

		if v := getStringSliceParam(nil, "key"); v != nil {
			t.Error("expected nil for nil params")
		}
	})
}

func TestS3ConnectorConfig(t *testing.T) {
	t.Run("config with credentials", func(t *testing.T) {
		config := &base.ConnectorConfig{
			Name:    "test-s3",
			Type:    "s3",
			Timeout: 30 * time.Second,
			Options: map[string]interface{}{
				"region":         "us-west-2",
				"default_bucket": "my-bucket",
			},
			Credentials: map[string]string{
				"access_key_id":     "AKIATEST",
				"secret_access_key": "SECRET",
			},
		}

		// This test verifies config structure, not actual connection
		if config.Options["region"] != "us-west-2" {
			t.Error("expected region to be set")
		}
	})

	t.Run("config with endpoint", func(t *testing.T) {
		config := &base.ConnectorConfig{
			Name: "test-s3-local",
			Type: "s3",
			Options: map[string]interface{}{
				"endpoint":         "http://localhost:9000",
				"force_path_style": true,
			},
		}

		if config.Options["endpoint"] != "http://localhost:9000" {
			t.Error("expected endpoint to be set")
		}
	})
}

func TestS3ConnectorGetBucket(t *testing.T) {
	conn := NewS3Connector()
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

func TestS3ConnectorUnsupportedOperations(t *testing.T) {
	conn := NewS3Connector()
	conn.SetConnected(true) // Simulate connected state

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

func TestS3ConnectorName(t *testing.T) {
	conn := NewS3Connector()
	conn.SetName("test-connector")

	if conn.Name() != "test-connector" {
		t.Errorf("expected name test-connector, got %s", conn.Name())
	}
}

func TestS3ConnectorTimeout(t *testing.T) {
	conn := NewS3Connector()

	// Default timeout
	if conn.GetTimeout() != 30*time.Second {
		t.Errorf("expected default timeout 30s, got %v", conn.GetTimeout())
	}
}

func TestS3ConnectorDisconnect(t *testing.T) {
	conn := NewS3Connector()

	// Disconnect when not connected should not error
	err := conn.Disconnect(context.Background())
	if err != nil {
		t.Errorf("unexpected error on disconnect: %v", err)
	}

	if conn.IsConnected() {
		t.Error("expected connected to be false")
	}
}

func TestS3ConnectorQueryRequiresKey(t *testing.T) {
	conn := NewS3Connector()
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

	t.Run("head_object requires key", func(t *testing.T) {
		_, err := conn.Query(ctx, &base.Query{
			Statement:  "head_object",
			Parameters: map[string]interface{}{},
		})
		if err == nil {
			t.Error("expected error when key is missing")
		}
	})

	t.Run("presign_get requires key", func(t *testing.T) {
		_, err := conn.Query(ctx, &base.Query{
			Statement:  "presign_get",
			Parameters: map[string]interface{}{},
		})
		if err == nil {
			t.Error("expected error when key is missing")
		}
	})

	t.Run("presign_put requires key", func(t *testing.T) {
		_, err := conn.Query(ctx, &base.Query{
			Statement:  "presign_put",
			Parameters: map[string]interface{}{},
		})
		if err == nil {
			t.Error("expected error when key is missing")
		}
	})
}

func TestS3ConnectorExecuteRequiresParams(t *testing.T) {
	conn := NewS3Connector()
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

	t.Run("delete_objects requires keys", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action:     "delete_objects",
			Parameters: map[string]interface{}{},
		})
		if err == nil {
			t.Error("expected error when keys is missing")
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

func TestS3ConnectorQueryDefaultsToListObjects(t *testing.T) {
	conn := NewS3Connector()
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

func TestS3ConnectorMetrics(t *testing.T) {
	conn := NewS3Connector()
	metrics := conn.GetMetrics()

	if metrics == nil {
		t.Fatal("expected metrics to be initialized")
	}

	stats := metrics.GetStats()
	if stats.ConnectorType != "s3" {
		t.Errorf("expected connector type s3, got %s", stats.ConnectorType)
	}
}

// --- Additional unit tests for improved coverage ---

func TestQueryStatementRoutingCaseVariations(t *testing.T) {
	// The Query method normalizes the statement via strings.ToLower before routing.
	// Using a connector with a fake client so we pass the nil-client check and
	// reach the actual routing switch. Operations will fail due to missing params
	// or no real endpoint, but they should NOT produce "unknown action" errors.

	conn := newTestConnectorWithClient()
	ctx := context.Background()

	validStatements := []string{
		// list_buckets variations
		"list_buckets", "LIST_BUCKETS", "List_Buckets", "LIST_buckets",
		// list_objects / list variations
		"list_objects", "LIST_OBJECTS", "List_Objects",
		"list", "LIST", "List",
		// get_object / get variations
		"get_object", "GET_OBJECT", "Get_Object",
		"get", "GET", "Get",
		// head_object / head variations
		"head_object", "HEAD_OBJECT", "Head_Object",
		"head", "HEAD", "Head",
		// presign_get variations
		"presign_get", "PRESIGN_GET", "Presign_Get",
		// presign_put variations
		"presign_put", "PRESIGN_PUT", "Presign_Put",
	}

	for _, stmt := range validStatements {
		t.Run("query_"+stmt, func(t *testing.T) {
			_, err := conn.Query(ctx, &base.Query{
				Statement:  stmt,
				Parameters: map[string]interface{}{},
			})
			// We expect an error (missing key param or S3 API failure), but
			// NOT "unknown action" -- the routing should recognize the statement.
			if err == nil {
				// Some operations (e.g. presign) may succeed without a real endpoint.
				// That's fine -- the point is it was routed correctly.
				return
			}
			connErr, ok := err.(*base.ConnectorError)
			if !ok {
				t.Fatalf("expected ConnectorError, got %T: %v", err, err)
			}
			if connErr.Operation != "Query" {
				t.Errorf("expected operation Query, got %s", connErr.Operation)
			}
			if strings.Contains(connErr.Message, "unknown action") {
				t.Errorf("valid statement %q was treated as unknown action", stmt)
			}
		})
	}
}

func TestExecuteActionRoutingCaseVariations(t *testing.T) {
	// The Execute method normalizes cmd.Action via strings.ToLower before routing.
	// Using a connector with a fake client to pass the nil-client check.

	conn := newTestConnectorWithClient()
	ctx := context.Background()

	validActions := []string{
		// put_object / put / upload variations
		"put_object", "PUT_OBJECT", "Put_Object",
		"put", "PUT", "Put",
		"upload", "UPLOAD", "Upload",
		// delete_object / delete variations
		"delete_object", "DELETE_OBJECT", "Delete_Object",
		"delete", "DELETE", "Delete",
		// delete_objects / delete_many variations
		"delete_objects", "DELETE_OBJECTS", "Delete_Objects",
		"delete_many", "DELETE_MANY", "Delete_Many",
		// copy_object / copy variations
		"copy_object", "COPY_OBJECT", "Copy_Object",
		"copy", "COPY", "Copy",
		// create_bucket
		"create_bucket", "CREATE_BUCKET", "Create_Bucket",
		// delete_bucket
		"delete_bucket", "DELETE_BUCKET", "Delete_Bucket",
	}

	for _, action := range validActions {
		t.Run("execute_"+action, func(t *testing.T) {
			_, err := conn.Execute(ctx, &base.Command{
				Action:     action,
				Parameters: map[string]interface{}{},
			})
			if err == nil {
				return // some may succeed without real endpoint -- routing was correct
			}
			connErr, ok := err.(*base.ConnectorError)
			if !ok {
				t.Fatalf("expected ConnectorError, got %T: %v", err, err)
			}
			if connErr.Operation != "Execute" {
				t.Errorf("expected operation Execute, got %s", connErr.Operation)
			}
			if strings.Contains(connErr.Message, "unknown action") {
				t.Errorf("valid action %q was treated as unknown action", action)
			}
		})
	}
}

func TestQueryUnknownAction(t *testing.T) {
	conn := newTestConnectorWithClient()
	ctx := context.Background()

	unknowns := []string{"foobar", "SELECT", "list_something", "update_object", "drop_bucket"}

	for _, stmt := range unknowns {
		t.Run("unknown_query_"+stmt, func(t *testing.T) {
			_, err := conn.Query(ctx, &base.Query{
				Statement:  stmt,
				Parameters: map[string]interface{}{},
			})
			if err == nil {
				t.Fatal("expected error for unknown query action")
			}
			connErr, ok := err.(*base.ConnectorError)
			if !ok {
				t.Fatalf("expected ConnectorError, got %T", err)
			}
			expectedMsg := "unknown action: " + stmt
			if connErr.Message != expectedMsg {
				t.Errorf("expected message %q, got %q", expectedMsg, connErr.Message)
			}
		})
	}
}

func TestExecuteUnknownAction(t *testing.T) {
	conn := newTestConnectorWithClient()
	ctx := context.Background()

	unknowns := []string{"foobar", "SELECT", "truncate", "list_objects", "head"}

	for _, action := range unknowns {
		t.Run("unknown_execute_"+action, func(t *testing.T) {
			_, err := conn.Execute(ctx, &base.Command{
				Action:     action,
				Parameters: map[string]interface{}{},
			})
			if err == nil {
				t.Fatal("expected error for unknown execute action")
			}
			connErr, ok := err.(*base.ConnectorError)
			if !ok {
				t.Fatalf("expected ConnectorError, got %T", err)
			}
			expectedMsg := "unknown action: " + action
			if connErr.Message != expectedMsg {
				t.Errorf("expected message %q, got %q", expectedMsg, connErr.Message)
			}
		})
	}
}

func TestQueryExecuteNilClientErrorMessages(t *testing.T) {
	// S3Connector's Query/Execute override checks c.client == nil first,
	// regardless of the connected state. The BaseConnector "not connected"
	// check never fires because the S3Connector's nil-client check takes precedence.

	ctx := context.Background()

	t.Run("query_not_connected_nil_client", func(t *testing.T) {
		conn := NewS3Connector()
		// Default: connected=false, client=nil
		_, err := conn.Query(ctx, &base.Query{Statement: "list_buckets"})
		if err == nil {
			t.Fatal("expected error")
		}
		connErr := err.(*base.ConnectorError)
		if connErr.Message != "S3 client not initialized" {
			t.Errorf("expected 'S3 client not initialized', got %q", connErr.Message)
		}
	})

	t.Run("query_connected_nil_client", func(t *testing.T) {
		conn := NewS3Connector()
		conn.SetConnected(true)
		_, err := conn.Query(ctx, &base.Query{Statement: "list_buckets"})
		if err == nil {
			t.Fatal("expected error")
		}
		connErr := err.(*base.ConnectorError)
		if connErr.Message != "S3 client not initialized" {
			t.Errorf("expected 'S3 client not initialized', got %q", connErr.Message)
		}
	})

	t.Run("execute_not_connected_nil_client", func(t *testing.T) {
		conn := NewS3Connector()
		_, err := conn.Execute(ctx, &base.Command{Action: "put_object"})
		if err == nil {
			t.Fatal("expected error")
		}
		connErr := err.(*base.ConnectorError)
		if connErr.Message != "S3 client not initialized" {
			t.Errorf("expected 'S3 client not initialized', got %q", connErr.Message)
		}
	})

	t.Run("execute_connected_nil_client", func(t *testing.T) {
		conn := NewS3Connector()
		conn.SetConnected(true)
		_, err := conn.Execute(ctx, &base.Command{Action: "put_object"})
		if err == nil {
			t.Fatal("expected error")
		}
		connErr := err.(*base.ConnectorError)
		if connErr.Message != "S3 client not initialized" {
			t.Errorf("expected 'S3 client not initialized', got %q", connErr.Message)
		}
	})
}

func TestQueryNilClientTakesPrecedenceOverParamValidation(t *testing.T) {
	// The nil-client check in Query fires BEFORE the switch statement routes
	// to individual handlers. So all query operations get "S3 client not
	// initialized" regardless of parameters when client is nil.
	conn := NewS3Connector()
	conn.SetConnected(true)
	ctx := context.Background()

	tests := []struct {
		name      string
		statement string
		params    map[string]interface{}
	}{
		{"get_object missing key", "get_object", map[string]interface{}{"bucket": "test-bucket"}},
		{"get_object empty key", "get_object", map[string]interface{}{"key": ""}},
		{"head_object missing key", "head_object", map[string]interface{}{"bucket": "test-bucket"}},
		{"head missing key (alias)", "head", map[string]interface{}{}},
		{"presign_get missing key", "presign_get", map[string]interface{}{"bucket": "test-bucket"}},
		{"presign_put missing key", "presign_put", map[string]interface{}{"bucket": "test-bucket"}},
		{"get alias missing key", "get", map[string]interface{}{}},
		{"list_buckets no params", "list_buckets", map[string]interface{}{}},
		{"list_objects with bucket", "list_objects", map[string]interface{}{"bucket": "b"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := conn.Query(ctx, &base.Query{
				Statement:  tc.statement,
				Parameters: tc.params,
			})
			if err == nil {
				t.Fatal("expected error")
			}
			connErr, ok := err.(*base.ConnectorError)
			if !ok {
				t.Fatalf("expected ConnectorError, got %T", err)
			}
			// All should get nil-client error, not param validation error
			if connErr.Message != "S3 client not initialized" {
				t.Errorf("expected 'S3 client not initialized', got %q", connErr.Message)
			}
			if connErr.Operation != "Query" {
				t.Errorf("expected operation Query, got %s", connErr.Operation)
			}
		})
	}
}

func TestQueryParameterValidation(t *testing.T) {
	// With a fake client, parameter validation fires after the nil-client check.
	conn := newTestConnectorWithClient()
	ctx := context.Background()

	tests := []struct {
		name        string
		statement   string
		params      map[string]interface{}
		expectedMsg string
	}{
		{"get_object missing key", "get_object", map[string]interface{}{"bucket": "b"}, "key is required"},
		{"get_object empty key", "get_object", map[string]interface{}{"key": ""}, "key is required"},
		{"get alias missing key", "get", map[string]interface{}{}, "key is required"},
		{"head_object missing key", "head_object", map[string]interface{}{}, "key is required"},
		{"head alias missing key", "head", map[string]interface{}{}, "key is required"},
		{"presign_get missing key", "presign_get", map[string]interface{}{}, "key is required"},
		{"presign_put missing key", "presign_put", map[string]interface{}{}, "key is required"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := conn.Query(ctx, &base.Query{
				Statement:  tc.statement,
				Parameters: tc.params,
			})
			if err == nil {
				t.Fatal("expected error")
			}
			connErr, ok := err.(*base.ConnectorError)
			if !ok {
				t.Fatalf("expected ConnectorError, got %T", err)
			}
			if connErr.Message != tc.expectedMsg {
				t.Errorf("expected %q, got %q", tc.expectedMsg, connErr.Message)
			}
			if connErr.Operation != "Query" {
				t.Errorf("expected operation Query, got %s", connErr.Operation)
			}
		})
	}
}

func TestExecuteNilClientTakesPrecedenceOverParamValidation(t *testing.T) {
	// The nil-client check in Execute fires BEFORE the switch statement routes
	// to individual handlers. So all execute operations get "S3 client not
	// initialized" regardless of parameters when client is nil.
	conn := NewS3Connector()
	conn.SetConnected(true)
	ctx := context.Background()

	tests := []struct {
		name   string
		action string
		params map[string]interface{}
	}{
		{"put_object missing key", "put_object", map[string]interface{}{"content": "hello"}},
		{"delete_object missing key", "delete_object", map[string]interface{}{"bucket": "b"}},
		{"delete_objects missing keys", "delete_objects", map[string]interface{}{"bucket": "b"}},
		{"copy_object missing both", "copy_object", map[string]interface{}{}},
		{"create_bucket missing bucket", "create_bucket", map[string]interface{}{}},
		{"delete_bucket missing bucket", "delete_bucket", map[string]interface{}{}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := conn.Execute(ctx, &base.Command{
				Action:     tc.action,
				Parameters: tc.params,
			})
			if err == nil {
				t.Fatal("expected error")
			}
			connErr, ok := err.(*base.ConnectorError)
			if !ok {
				t.Fatalf("expected ConnectorError, got %T", err)
			}
			if connErr.Message != "S3 client not initialized" {
				t.Errorf("expected 'S3 client not initialized', got %q", connErr.Message)
			}
			if connErr.Operation != "Execute" {
				t.Errorf("expected operation Execute, got %s", connErr.Operation)
			}
		})
	}
}

func TestExecuteParameterValidation(t *testing.T) {
	// With a fake client, parameter validation fires after the nil-client check.
	conn := newTestConnectorWithClient()
	ctx := context.Background()

	tests := []struct {
		name        string
		action      string
		params      map[string]interface{}
		expectedMsg string
	}{
		{"put_object missing key", "put_object", map[string]interface{}{"content": "hello"}, "key is required"},
		{"put alias missing key", "put", map[string]interface{}{}, "key is required"},
		{"upload alias missing key", "upload", map[string]interface{}{}, "key is required"},
		{"delete_object missing key", "delete_object", map[string]interface{}{"bucket": "b"}, "key is required"},
		{"delete alias missing key", "delete", map[string]interface{}{}, "key is required"},
		{"delete_objects missing keys", "delete_objects", map[string]interface{}{"bucket": "b"}, "keys is required"},
		{"delete_many alias missing keys", "delete_many", map[string]interface{}{}, "keys is required"},
		{"copy_object missing both", "copy_object", map[string]interface{}{}, "source_key and dest_key are required"},
		{"copy_object missing dest_key", "copy_object", map[string]interface{}{"source_key": "a"}, "source_key and dest_key are required"},
		{"copy_object missing source_key", "copy_object", map[string]interface{}{"dest_key": "b"}, "source_key and dest_key are required"},
		{"copy alias missing keys", "copy", map[string]interface{}{}, "source_key and dest_key are required"},
		{"create_bucket missing bucket", "create_bucket", map[string]interface{}{}, "bucket name is required"},
		{"create_bucket empty bucket", "create_bucket", map[string]interface{}{"bucket": ""}, "bucket name is required"},
		{"delete_bucket missing bucket", "delete_bucket", map[string]interface{}{}, "bucket name is required"},
		{"delete_bucket empty bucket", "delete_bucket", map[string]interface{}{"bucket": ""}, "bucket name is required"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := conn.Execute(ctx, &base.Command{
				Action:     tc.action,
				Parameters: tc.params,
			})
			if err == nil {
				t.Fatal("expected error")
			}
			connErr, ok := err.(*base.ConnectorError)
			if !ok {
				t.Fatalf("expected ConnectorError, got %T", err)
			}
			if connErr.Message != tc.expectedMsg {
				t.Errorf("expected %q, got %q", tc.expectedMsg, connErr.Message)
			}
			if connErr.Operation != "Execute" {
				t.Errorf("expected operation Execute, got %s", connErr.Operation)
			}
		})
	}
}

func TestDefaultBucketFallback(t *testing.T) {
	conn := NewS3Connector()

	t.Run("no default bucket, no param bucket", func(t *testing.T) {
		conn.defaultBucket = ""
		result := conn.getBucket(map[string]interface{}{})
		if result != "" {
			t.Errorf("expected empty string, got %q", result)
		}
	})

	t.Run("default bucket set, no param bucket", func(t *testing.T) {
		conn.defaultBucket = "fallback-bucket"
		result := conn.getBucket(map[string]interface{}{})
		if result != "fallback-bucket" {
			t.Errorf("expected fallback-bucket, got %q", result)
		}
	})

	t.Run("param bucket overrides default", func(t *testing.T) {
		conn.defaultBucket = "fallback-bucket"
		result := conn.getBucket(map[string]interface{}{"bucket": "override-bucket"})
		if result != "override-bucket" {
			t.Errorf("expected override-bucket, got %q", result)
		}
	})

	t.Run("nil params falls back to default", func(t *testing.T) {
		conn.defaultBucket = "nil-fallback"
		result := conn.getBucket(nil)
		if result != "nil-fallback" {
			t.Errorf("expected nil-fallback, got %q", result)
		}
	})

	t.Run("empty bucket param falls back to default", func(t *testing.T) {
		conn.defaultBucket = "default-b"
		result := conn.getBucket(map[string]interface{}{"bucket": ""})
		if result != "default-b" {
			t.Errorf("expected default-b, got %q", result)
		}
	})

	t.Run("non-string bucket param falls back to default", func(t *testing.T) {
		conn.defaultBucket = "typed-default"
		result := conn.getBucket(map[string]interface{}{"bucket": 12345})
		if result != "typed-default" {
			t.Errorf("expected typed-default, got %q", result)
		}
	})
}

func TestGetStringSliceParamEdgeCases(t *testing.T) {
	t.Run("nil params returns nil", func(t *testing.T) {
		result := getStringSliceParam(nil, "keys")
		if result != nil {
			t.Errorf("expected nil, got %v", result)
		}
	})

	t.Run("missing key returns nil", func(t *testing.T) {
		params := map[string]interface{}{"other": "value"}
		result := getStringSliceParam(params, "keys")
		if result != nil {
			t.Errorf("expected nil, got %v", result)
		}
	})

	t.Run("wrong type returns nil", func(t *testing.T) {
		params := map[string]interface{}{"keys": "not-a-slice"}
		result := getStringSliceParam(params, "keys")
		if result != nil {
			t.Errorf("expected nil, got %v", result)
		}
	})

	t.Run("int value returns nil", func(t *testing.T) {
		params := map[string]interface{}{"keys": 42}
		result := getStringSliceParam(params, "keys")
		if result != nil {
			t.Errorf("expected nil, got %v", result)
		}
	})

	t.Run("empty string slice returns empty", func(t *testing.T) {
		params := map[string]interface{}{"keys": []string{}}
		result := getStringSliceParam(params, "keys")
		if len(result) != 0 {
			t.Errorf("expected empty slice, got %v", result)
		}
	})

	t.Run("empty interface slice returns empty", func(t *testing.T) {
		params := map[string]interface{}{"keys": []interface{}{}}
		result := getStringSliceParam(params, "keys")
		if len(result) != 0 {
			t.Errorf("expected empty slice, got %v", result)
		}
	})

	t.Run("interface slice with non-string items skips them", func(t *testing.T) {
		params := map[string]interface{}{
			"keys": []interface{}{"a", 123, "b", true, "c"},
		}
		result := getStringSliceParam(params, "keys")
		if len(result) != 3 {
			t.Fatalf("expected 3 strings, got %d: %v", len(result), result)
		}
		expected := []string{"a", "b", "c"}
		for i, v := range expected {
			if result[i] != v {
				t.Errorf("index %d: expected %q, got %q", i, v, result[i])
			}
		}
	})

	t.Run("string slice preserves all items", func(t *testing.T) {
		params := map[string]interface{}{
			"keys": []string{"x", "y", "z"},
		}
		result := getStringSliceParam(params, "keys")
		if len(result) != 3 {
			t.Fatalf("expected 3 items, got %d", len(result))
		}
		if result[0] != "x" || result[1] != "y" || result[2] != "z" {
			t.Errorf("unexpected values: %v", result)
		}
	})
}

func TestGetStringParamEdgeCases(t *testing.T) {
	t.Run("wrong type returns default", func(t *testing.T) {
		params := map[string]interface{}{"key": 123}
		result := getStringParam(params, "key", "default")
		if result != "default" {
			t.Errorf("expected default, got %q", result)
		}
	})

	t.Run("bool type returns default", func(t *testing.T) {
		params := map[string]interface{}{"key": true}
		result := getStringParam(params, "key", "fallback")
		if result != "fallback" {
			t.Errorf("expected fallback, got %q", result)
		}
	})

	t.Run("empty string returns empty not default", func(t *testing.T) {
		params := map[string]interface{}{"key": ""}
		result := getStringParam(params, "key", "default")
		if result != "" {
			t.Errorf("expected empty string, got %q", result)
		}
	})
}

func TestGetIntParamEdgeCases(t *testing.T) {
	t.Run("missing key returns default", func(t *testing.T) {
		params := map[string]interface{}{"other": 1}
		result := getIntParam(params, "key", 42)
		if result != 42 {
			t.Errorf("expected 42, got %d", result)
		}
	})

	t.Run("bool type returns default", func(t *testing.T) {
		params := map[string]interface{}{"key": true}
		result := getIntParam(params, "key", 99)
		if result != 99 {
			t.Errorf("expected 99, got %d", result)
		}
	})

	t.Run("slice type returns default", func(t *testing.T) {
		params := map[string]interface{}{"key": []int{1, 2}}
		result := getIntParam(params, "key", 77)
		if result != 77 {
			t.Errorf("expected 77, got %d", result)
		}
	})
}

func TestQueryEmptyStatementDefaultsToListObjects(t *testing.T) {
	// When Query.Statement is empty, it defaults to "list_objects".
	// With a fake client, the routing should reach listObjects (not "unknown action").
	conn := newTestConnectorWithClient()
	ctx := context.Background()

	_, err := conn.Query(ctx, &base.Query{
		Statement:  "",
		Parameters: map[string]interface{}{},
	})
	// May error due to no real S3 endpoint, but should NOT be "unknown action"
	if err != nil {
		connErr, ok := err.(*base.ConnectorError)
		if !ok {
			t.Fatalf("expected ConnectorError, got %T", err)
		}
		if strings.Contains(connErr.Message, "unknown action") {
			t.Errorf("empty statement should default to list_objects, not unknown action")
		}
	}
}

func TestQueryNilParametersNilClient(t *testing.T) {
	// With client nil, the nil-client check fires first for all operations,
	// regardless of whether parameters are nil.
	conn := NewS3Connector()
	conn.SetConnected(true)
	ctx := context.Background()

	nilParamStatements := []string{"get_object", "head_object", "presign_get", "presign_put", "list_objects", "list_buckets"}

	for _, stmt := range nilParamStatements {
		t.Run(stmt+"_nil_params", func(t *testing.T) {
			_, err := conn.Query(ctx, &base.Query{
				Statement:  stmt,
				Parameters: nil,
			})
			if err == nil {
				t.Fatal("expected error")
			}
			connErr, ok := err.(*base.ConnectorError)
			if !ok {
				t.Fatalf("expected ConnectorError, got %T", err)
			}
			if connErr.Message != "S3 client not initialized" {
				t.Errorf("expected 'S3 client not initialized', got %q", connErr.Message)
			}
		})
	}
}

func TestExecuteNilParametersNilClient(t *testing.T) {
	// With client nil, the nil-client check fires first for all operations.
	conn := NewS3Connector()
	conn.SetConnected(true)
	ctx := context.Background()

	nilParamActions := []string{"put_object", "delete_object", "delete_objects", "copy_object", "create_bucket", "delete_bucket"}

	for _, action := range nilParamActions {
		t.Run(action+"_nil_params", func(t *testing.T) {
			_, err := conn.Execute(ctx, &base.Command{
				Action:     action,
				Parameters: nil,
			})
			if err == nil {
				t.Fatal("expected error")
			}
			connErr, ok := err.(*base.ConnectorError)
			if !ok {
				t.Fatalf("expected ConnectorError, got %T", err)
			}
			if connErr.Message != "S3 client not initialized" {
				t.Errorf("expected 'S3 client not initialized', got %q", connErr.Message)
			}
		})
	}
}

func TestConnectorErrorFormat(t *testing.T) {
	ctx := context.Background()

	t.Run("nil client error format", func(t *testing.T) {
		conn := NewS3Connector()
		conn.SetConnected(true)
		conn.SetName("my-s3")

		_, err := conn.Query(ctx, &base.Query{
			Statement:  "get_object",
			Parameters: map[string]interface{}{},
		})
		if err == nil {
			t.Fatal("expected error")
		}
		expected := "my-s3.Query: S3 client not initialized"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("nil client error even when not connected", func(t *testing.T) {
		// S3Connector.Query checks c.client == nil first (before the base
		// connector's connected check), so even an unconnected connector
		// reports "S3 client not initialized" rather than "not connected".
		conn := NewS3Connector()
		conn.SetName("test-s3")

		_, err := conn.Query(ctx, &base.Query{Statement: "list"})
		if err == nil {
			t.Fatal("expected error")
		}
		expected := "test-s3.Query: S3 client not initialized"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("parameter validation error format", func(t *testing.T) {
		conn := newTestConnectorWithClient()
		conn.SetName("my-s3")

		_, err := conn.Query(ctx, &base.Query{
			Statement:  "get_object",
			Parameters: map[string]interface{}{},
		})
		if err == nil {
			t.Fatal("expected error")
		}
		expected := "my-s3.Query: key is required"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("unknown action error format", func(t *testing.T) {
		conn := newTestConnectorWithClient()
		conn.SetName("my-s3")

		_, err := conn.Execute(ctx, &base.Command{
			Action:     "unknown_action",
			Parameters: map[string]interface{}{},
		})
		if err == nil {
			t.Fatal("expected error")
		}
		expected := "my-s3.Execute: unknown action: unknown_action"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})
}

func TestHealthCheckNotInitialized(t *testing.T) {
	conn := NewS3Connector()
	ctx := context.Background()

	status, err := conn.HealthCheck(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.Healthy {
		t.Error("expected unhealthy when client is nil")
	}
	if status.Error != "S3 client not initialized" {
		t.Errorf("expected 'S3 client not initialized', got %q", status.Error)
	}
}

func TestDisconnectClearsClient(t *testing.T) {
	conn := NewS3Connector()

	// Simulate that a client was previously set
	conn.SetConnected(true)

	err := conn.Disconnect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// After disconnect, client should be nil
	if conn.client != nil {
		t.Error("expected client to be nil after disconnect")
	}
	if conn.presignClient != nil {
		t.Error("expected presignClient to be nil after disconnect")
	}
}

func TestConnectorImplementsInterface(t *testing.T) {
	// Verify the compile-time interface check
	var _ base.Connector = (*S3Connector)(nil)
}

func TestCopyObjectPartialParams(t *testing.T) {
	conn := newTestConnectorWithClient()
	ctx := context.Background()

	t.Run("source_key only (no dest_key)", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action: "copy_object",
			Parameters: map[string]interface{}{
				"source_key": "file.txt",
			},
		})
		if err == nil {
			t.Fatal("expected error when dest_key is missing")
		}
		connErr := err.(*base.ConnectorError)
		if connErr.Message != "source_key and dest_key are required" {
			t.Errorf("expected 'source_key and dest_key are required', got %q", connErr.Message)
		}
	})

	t.Run("dest_key only (no source_key)", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action: "copy_object",
			Parameters: map[string]interface{}{
				"dest_key": "copy.txt",
			},
		})
		if err == nil {
			t.Fatal("expected error when source_key is missing")
		}
		connErr := err.(*base.ConnectorError)
		if connErr.Message != "source_key and dest_key are required" {
			t.Errorf("expected 'source_key and dest_key are required', got %q", connErr.Message)
		}
	})

	t.Run("both empty", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action: "copy_object",
			Parameters: map[string]interface{}{
				"source_key": "",
				"dest_key":   "",
			},
		})
		if err == nil {
			t.Fatal("expected error when both keys are empty")
		}
		connErr := err.(*base.ConnectorError)
		if connErr.Message != "source_key and dest_key are required" {
			t.Errorf("expected 'source_key and dest_key are required', got %q", connErr.Message)
		}
	})
}

func TestDeleteObjectsKeysValidation(t *testing.T) {
	conn := newTestConnectorWithClient()
	ctx := context.Background()

	t.Run("empty string slice", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action:     "delete_objects",
			Parameters: map[string]interface{}{"keys": []string{}},
		})
		if err == nil {
			t.Fatal("expected error for empty keys")
		}
		connErr := err.(*base.ConnectorError)
		if connErr.Message != "keys is required" {
			t.Errorf("expected 'keys is required', got %q", connErr.Message)
		}
	})

	t.Run("empty interface slice", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action:     "delete_objects",
			Parameters: map[string]interface{}{"keys": []interface{}{}},
		})
		if err == nil {
			t.Fatal("expected error for empty keys")
		}
		connErr := err.(*base.ConnectorError)
		if connErr.Message != "keys is required" {
			t.Errorf("expected 'keys is required', got %q", connErr.Message)
		}
	})

	t.Run("non-slice keys value", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action:     "delete_objects",
			Parameters: map[string]interface{}{"keys": "single-key"},
		})
		if err == nil {
			t.Fatal("expected error for non-slice keys")
		}
		connErr := err.(*base.ConnectorError)
		if connErr.Message != "keys is required" {
			t.Errorf("expected 'keys is required', got %q", connErr.Message)
		}
	})

	t.Run("missing keys param entirely", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action:     "delete_objects",
			Parameters: map[string]interface{}{"bucket": "b"},
		})
		if err == nil {
			t.Fatal("expected error for missing keys")
		}
		connErr := err.(*base.ConnectorError)
		if connErr.Message != "keys is required" {
			t.Errorf("expected 'keys is required', got %q", connErr.Message)
		}
	})
}

func TestGetBucketWithNilParams(t *testing.T) {
	conn := NewS3Connector()
	conn.defaultBucket = "default"

	result := conn.getBucket(nil)
	if result != "default" {
		t.Errorf("expected 'default', got %q", result)
	}
}

func TestMultipleConnectorsIndependent(t *testing.T) {
	conn1 := NewS3Connector()
	conn2 := NewS3Connector()

	conn1.SetName("s3-prod")
	conn2.SetName("s3-staging")
	conn1.defaultBucket = "prod-bucket"
	conn2.defaultBucket = "staging-bucket"

	if conn1.Name() != "s3-prod" {
		t.Errorf("expected s3-prod, got %s", conn1.Name())
	}
	if conn2.Name() != "s3-staging" {
		t.Errorf("expected s3-staging, got %s", conn2.Name())
	}

	if conn1.getBucket(nil) != "prod-bucket" {
		t.Errorf("expected prod-bucket, got %s", conn1.getBucket(nil))
	}
	if conn2.getBucket(nil) != "staging-bucket" {
		t.Errorf("expected staging-bucket, got %s", conn2.getBucket(nil))
	}
}

func TestQueryListObjectsNilClient(t *testing.T) {
	// list_objects (and "list" alias) require a client. With client nil,
	// the nil-client check at the top of Query should fire.
	conn := NewS3Connector()
	conn.SetConnected(true)
	ctx := context.Background()

	for _, stmt := range []string{"list_objects", "list"} {
		t.Run(stmt, func(t *testing.T) {
			_, err := conn.Query(ctx, &base.Query{
				Statement:  stmt,
				Parameters: map[string]interface{}{"bucket": "test"},
			})
			if err == nil {
				t.Fatal("expected error with nil client")
			}
			connErr := err.(*base.ConnectorError)
			if connErr.Message != "S3 client not initialized" {
				t.Errorf("expected 'S3 client not initialized', got %q", connErr.Message)
			}
		})
	}
}

func TestQueryListBucketsNilClient(t *testing.T) {
	conn := NewS3Connector()
	conn.SetConnected(true)
	ctx := context.Background()

	_, err := conn.Query(ctx, &base.Query{
		Statement: "list_buckets",
	})
	if err == nil {
		t.Fatal("expected error with nil client")
	}
	connErr := err.(*base.ConnectorError)
	if connErr.Message != "S3 client not initialized" {
		t.Errorf("expected 'S3 client not initialized', got %q", connErr.Message)
	}
}

func TestHealthCheckWithFakeClient(t *testing.T) {
	ctx := context.Background()

	t.Run("no default bucket - ListBuckets fails", func(t *testing.T) {
		conn := newTestConnectorWithClient()
		conn.defaultBucket = ""

		status, err := conn.HealthCheck(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// The fake client has no real endpoint, so ListBuckets will fail.
		// This exercises the error branch of HealthCheck.
		if status.Healthy {
			t.Error("expected unhealthy with no real endpoint")
		}
		if status.Error == "" {
			t.Error("expected non-empty error message")
		}
		if status.Latency <= 0 {
			t.Error("expected positive latency")
		}
	})

	t.Run("with default bucket - HeadBucket fails", func(t *testing.T) {
		conn := newTestConnectorWithClient()
		conn.defaultBucket = "test-bucket"

		status, err := conn.HealthCheck(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// HeadBucket to a non-existent endpoint will fail.
		if status.Healthy {
			t.Error("expected unhealthy with no real endpoint")
		}
		if status.Error == "" {
			t.Error("expected non-empty error message")
		}
	})
}

func TestQueryListBucketsWithFakeClient(t *testing.T) {
	// Tests that list_buckets reaches the actual API call (and fails due to
	// no real endpoint), exercising more of the listBuckets method.
	conn := newTestConnectorWithClient()
	ctx := context.Background()

	_, err := conn.Query(ctx, &base.Query{
		Statement: "list_buckets",
	})
	if err == nil {
		t.Fatal("expected error with fake client (no real endpoint)")
	}
	connErr := err.(*base.ConnectorError)
	if connErr.Message != "failed to list buckets" {
		t.Errorf("expected 'failed to list buckets', got %q", connErr.Message)
	}
	if connErr.Cause == nil {
		t.Error("expected non-nil cause (underlying API error)")
	}
}

func TestQueryListObjectsWithFakeClient(t *testing.T) {
	// Tests that list_objects reaches the API call with proper params.
	conn := newTestConnectorWithClient()
	conn.defaultBucket = "test-bucket"
	ctx := context.Background()

	_, err := conn.Query(ctx, &base.Query{
		Statement: "list_objects",
		Parameters: map[string]interface{}{
			"prefix":    "docs/",
			"delimiter": "/",
			"max_keys":  50,
		},
	})
	if err == nil {
		t.Fatal("expected error with fake client (no real endpoint)")
	}
	connErr := err.(*base.ConnectorError)
	if connErr.Message != "failed to list objects" {
		t.Errorf("expected 'failed to list objects', got %q", connErr.Message)
	}
}

func TestQueryGetObjectWithFakeClient(t *testing.T) {
	conn := newTestConnectorWithClient()
	conn.defaultBucket = "test-bucket"
	ctx := context.Background()

	_, err := conn.Query(ctx, &base.Query{
		Statement: "get_object",
		Parameters: map[string]interface{}{
			"key": "test-file.txt",
		},
	})
	if err == nil {
		t.Fatal("expected error with fake client (no real endpoint)")
	}
	connErr := err.(*base.ConnectorError)
	expectedMsg := "failed to get object: test-file.txt"
	if connErr.Message != expectedMsg {
		t.Errorf("expected %q, got %q", expectedMsg, connErr.Message)
	}
}

func TestQueryHeadObjectWithFakeClient(t *testing.T) {
	conn := newTestConnectorWithClient()
	conn.defaultBucket = "test-bucket"
	ctx := context.Background()

	_, err := conn.Query(ctx, &base.Query{
		Statement: "head_object",
		Parameters: map[string]interface{}{
			"key": "test-file.txt",
		},
	})
	if err == nil {
		t.Fatal("expected error with fake client (no real endpoint)")
	}
	connErr := err.(*base.ConnectorError)
	expectedMsg := "failed to head object: test-file.txt"
	if connErr.Message != expectedMsg {
		t.Errorf("expected %q, got %q", expectedMsg, connErr.Message)
	}
}

func TestExecutePutObjectWithFakeClient(t *testing.T) {
	conn := newTestConnectorWithClient()
	conn.defaultBucket = "test-bucket"
	ctx := context.Background()

	_, err := conn.Execute(ctx, &base.Command{
		Action: "put_object",
		Parameters: map[string]interface{}{
			"key":          "test-file.txt",
			"content":      "hello world",
			"content_type": "text/plain",
		},
	})
	if err == nil {
		t.Fatal("expected error with fake client (no real endpoint)")
	}
	connErr := err.(*base.ConnectorError)
	expectedMsg := "failed to put object: test-file.txt"
	if connErr.Message != expectedMsg {
		t.Errorf("expected %q, got %q", expectedMsg, connErr.Message)
	}
}

func TestExecutePutObjectWithMetadata(t *testing.T) {
	conn := newTestConnectorWithClient()
	conn.defaultBucket = "test-bucket"
	ctx := context.Background()

	t.Run("metadata as map[string]string", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action: "put_object",
			Parameters: map[string]interface{}{
				"key":     "test-file.txt",
				"content": "hello",
				"metadata": map[string]string{
					"author": "test",
				},
			},
		})
		if err == nil {
			t.Fatal("expected error with fake client")
		}
		// The important thing is it reached the API call, not the param validation
		connErr := err.(*base.ConnectorError)
		if connErr.Message != "failed to put object: test-file.txt" {
			t.Errorf("expected 'failed to put object: test-file.txt', got %q", connErr.Message)
		}
	})

	t.Run("metadata as map[string]interface{}", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action: "put_object",
			Parameters: map[string]interface{}{
				"key":     "test-file.txt",
				"content": "hello",
				"metadata": map[string]interface{}{
					"author": "test",
					"count":  42, // non-string value, should be skipped
				},
			},
		})
		if err == nil {
			t.Fatal("expected error with fake client")
		}
		connErr := err.(*base.ConnectorError)
		if connErr.Message != "failed to put object: test-file.txt" {
			t.Errorf("expected 'failed to put object: test-file.txt', got %q", connErr.Message)
		}
	})
}

func TestExecuteDeleteObjectWithFakeClient(t *testing.T) {
	conn := newTestConnectorWithClient()
	conn.defaultBucket = "test-bucket"
	ctx := context.Background()

	t.Run("without version_id", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action: "delete_object",
			Parameters: map[string]interface{}{
				"key": "test-file.txt",
			},
		})
		if err == nil {
			t.Fatal("expected error with fake client")
		}
		connErr := err.(*base.ConnectorError)
		expectedMsg := "failed to delete object: test-file.txt"
		if connErr.Message != expectedMsg {
			t.Errorf("expected %q, got %q", expectedMsg, connErr.Message)
		}
	})

	t.Run("with version_id", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action: "delete_object",
			Parameters: map[string]interface{}{
				"key":        "test-file.txt",
				"version_id": "v123",
			},
		})
		if err == nil {
			t.Fatal("expected error with fake client")
		}
		connErr := err.(*base.ConnectorError)
		expectedMsg := "failed to delete object: test-file.txt"
		if connErr.Message != expectedMsg {
			t.Errorf("expected %q, got %q", expectedMsg, connErr.Message)
		}
	})
}

func TestExecuteDeleteObjectsWithFakeClient(t *testing.T) {
	conn := newTestConnectorWithClient()
	conn.defaultBucket = "test-bucket"
	ctx := context.Background()

	_, err := conn.Execute(ctx, &base.Command{
		Action: "delete_objects",
		Parameters: map[string]interface{}{
			"keys": []string{"file1.txt", "file2.txt", "file3.txt"},
		},
	})
	if err == nil {
		t.Fatal("expected error with fake client")
	}
	connErr := err.(*base.ConnectorError)
	if connErr.Message != "failed to delete objects" {
		t.Errorf("expected 'failed to delete objects', got %q", connErr.Message)
	}
}

func TestExecuteCopyObjectWithFakeClient(t *testing.T) {
	conn := newTestConnectorWithClient()
	conn.defaultBucket = "test-bucket"
	ctx := context.Background()

	_, err := conn.Execute(ctx, &base.Command{
		Action: "copy_object",
		Parameters: map[string]interface{}{
			"source_key":    "original.txt",
			"dest_key":      "copy.txt",
			"source_bucket": "source-bucket",
			"dest_bucket":   "dest-bucket",
		},
	})
	if err == nil {
		t.Fatal("expected error with fake client")
	}
	connErr := err.(*base.ConnectorError)
	if connErr.Message != "failed to copy object" {
		t.Errorf("expected 'failed to copy object', got %q", connErr.Message)
	}
}

func TestExecuteCreateBucketWithFakeClient(t *testing.T) {
	conn := newTestConnectorWithClient()
	ctx := context.Background()

	_, err := conn.Execute(ctx, &base.Command{
		Action: "create_bucket",
		Parameters: map[string]interface{}{
			"bucket": "new-bucket",
		},
	})
	if err == nil {
		t.Fatal("expected error with fake client")
	}
	connErr := err.(*base.ConnectorError)
	expectedMsg := "failed to create bucket: new-bucket"
	if connErr.Message != expectedMsg {
		t.Errorf("expected %q, got %q", expectedMsg, connErr.Message)
	}
}

func TestExecuteDeleteBucketWithFakeClient(t *testing.T) {
	conn := newTestConnectorWithClient()
	ctx := context.Background()

	_, err := conn.Execute(ctx, &base.Command{
		Action: "delete_bucket",
		Parameters: map[string]interface{}{
			"bucket": "old-bucket",
		},
	})
	if err == nil {
		t.Fatal("expected error with fake client")
	}
	connErr := err.(*base.ConnectorError)
	expectedMsg := "failed to delete bucket: old-bucket"
	if connErr.Message != expectedMsg {
		t.Errorf("expected %q, got %q", expectedMsg, connErr.Message)
	}
}

func TestQueryPresignGetWithFakeClient(t *testing.T) {
	conn := newTestConnectorWithClient()
	conn.defaultBucket = "test-bucket"
	ctx := context.Background()

	// presign_get with key present should reach the presign API call
	result, err := conn.Query(ctx, &base.Query{
		Statement: "presign_get",
		Parameters: map[string]interface{}{
			"key":    "test-file.txt",
			"expiry": 7200,
		},
	})
	// Presigning may succeed with a fake client since it doesn't make a real HTTP call.
	if err == nil {
		// Verify the result structure
		if result.RowCount != 1 {
			t.Errorf("expected 1 row, got %d", result.RowCount)
		}
		if len(result.Rows) != 1 {
			t.Fatalf("expected 1 row, got %d", len(result.Rows))
		}
		row := result.Rows[0]
		if _, ok := row["url"]; !ok {
			t.Error("expected url field in result")
		}
		if _, ok := row["method"]; !ok {
			t.Error("expected method field in result")
		}
		if _, ok := row["expires_at"]; !ok {
			t.Error("expected expires_at field in result")
		}
	}
	// If it errors, that's also acceptable for a fake client
}

func TestQueryPresignPutWithFakeClient(t *testing.T) {
	conn := newTestConnectorWithClient()
	conn.defaultBucket = "test-bucket"
	ctx := context.Background()

	result, err := conn.Query(ctx, &base.Query{
		Statement: "presign_put",
		Parameters: map[string]interface{}{
			"key":          "upload.txt",
			"content_type": "text/plain",
			"expiry":       3600,
		},
	})
	if err == nil {
		if result.RowCount != 1 {
			t.Errorf("expected 1 row, got %d", result.RowCount)
		}
		if len(result.Rows) != 1 {
			t.Fatalf("expected 1 row, got %d", len(result.Rows))
		}
		row := result.Rows[0]
		if _, ok := row["url"]; !ok {
			t.Error("expected url field in result")
		}
		if _, ok := row["method"]; !ok {
			t.Error("expected method field in result")
		}
		if _, ok := row["content_type"]; !ok {
			t.Error("expected content_type field in result")
		}
		if ct, ok := row["content_type"].(string); ok && ct != "text/plain" {
			t.Errorf("expected content_type text/plain, got %s", ct)
		}
	}
}

func TestQueryListObjectsWithContinuationToken(t *testing.T) {
	// Test that continuation_token and delimiter are properly handled
	conn := newTestConnectorWithClient()
	conn.defaultBucket = "test-bucket"
	ctx := context.Background()

	_, err := conn.Query(ctx, &base.Query{
		Statement: "list_objects",
		Parameters: map[string]interface{}{
			"prefix":             "data/",
			"delimiter":          "/",
			"max_keys":           10,
			"continuation_token": "abc123",
		},
	})
	// Will fail due to fake endpoint, but exercises the parameter handling paths
	if err == nil {
		t.Fatal("expected error with fake client")
	}
	connErr := err.(*base.ConnectorError)
	if connErr.Message != "failed to list objects" {
		t.Errorf("expected 'failed to list objects', got %q", connErr.Message)
	}
}
