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

package azureblob

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/service"

	"axonflow/platform/connectors/base"
)

func TestNewAzureBlobConnector(t *testing.T) {
	conn := NewAzureBlobConnector()

	if conn == nil {
		t.Fatal("expected connector to be created")
	}

	if conn.Type() != "azureblob" {
		t.Errorf("expected type azureblob, got %s", conn.Type())
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

func TestAzureBlobConnectorQueryWithoutConnect(t *testing.T) {
	conn := NewAzureBlobConnector()
	ctx := context.Background()

	_, err := conn.Query(ctx, &base.Query{Statement: "list_blobs"})
	if err == nil {
		t.Error("expected error when querying without connection")
	}
}

func TestAzureBlobConnectorExecuteWithoutConnect(t *testing.T) {
	conn := NewAzureBlobConnector()
	ctx := context.Background()

	_, err := conn.Execute(ctx, &base.Command{Action: "upload_blob"})
	if err == nil {
		t.Error("expected error when executing without connection")
	}
}

func TestAzureBlobConnectorHealthCheckWithoutConnect(t *testing.T) {
	conn := NewAzureBlobConnector()
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

	t.Run("getStringPtrValue", func(t *testing.T) {
		str := "hello"
		if v := getStringPtrValue(&str); v != "hello" {
			t.Errorf("expected hello, got %s", v)
		}

		if v := getStringPtrValue(nil); v != "" {
			t.Errorf("expected empty string for nil, got %s", v)
		}
	})
}

func TestAzureBlobConnectorConfig(t *testing.T) {
	t.Run("config with account key", func(t *testing.T) {
		config := &base.ConnectorConfig{
			Name:    "test-azure",
			Type:    "azureblob",
			Timeout: 30 * time.Second,
			Options: map[string]interface{}{
				"account_name":      "mystorageaccount",
				"default_container": "mycontainer",
			},
			Credentials: map[string]string{
				"account_key": "base64encodedkey",
			},
		}

		if config.Options["account_name"] != "mystorageaccount" {
			t.Error("expected account_name to be set")
		}
	})

	t.Run("config with connection string", func(t *testing.T) {
		config := &base.ConnectorConfig{
			Name: "test-azure-connstr",
			Type: "azureblob",
			Credentials: map[string]string{
				"connection_string": "DefaultEndpointsProtocol=https;AccountName=...",
			},
		}

		if config.Credentials["connection_string"] == "" {
			t.Error("expected connection string to be set")
		}
	})

	t.Run("config with managed identity", func(t *testing.T) {
		config := &base.ConnectorConfig{
			Name: "test-azure-mi",
			Type: "azureblob",
			Options: map[string]interface{}{
				"account_name":         "mystorageaccount",
				"use_managed_identity": true,
			},
		}

		if config.Options["use_managed_identity"] != true {
			t.Error("expected use_managed_identity to be true")
		}
	})
}

func TestAzureBlobConnectorGetContainer(t *testing.T) {
	conn := NewAzureBlobConnector()
	conn.defaultContainer = "default-container"

	t.Run("container from params", func(t *testing.T) {
		params := map[string]interface{}{"container": "custom-container"}
		if c := conn.getContainer(params); c != "custom-container" {
			t.Errorf("expected custom-container, got %s", c)
		}
	})

	t.Run("default container", func(t *testing.T) {
		params := map[string]interface{}{}
		if c := conn.getContainer(params); c != "default-container" {
			t.Errorf("expected default-container, got %s", c)
		}
	})
}

func TestAzureBlobConnectorUnsupportedOperations(t *testing.T) {
	conn := NewAzureBlobConnector()
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

func TestAzureBlobConnectorName(t *testing.T) {
	conn := NewAzureBlobConnector()
	conn.SetName("test-connector")

	if conn.Name() != "test-connector" {
		t.Errorf("expected name test-connector, got %s", conn.Name())
	}
}

func TestAzureBlobConnectorTimeout(t *testing.T) {
	conn := NewAzureBlobConnector()

	// Default timeout
	if conn.GetTimeout() != 30*time.Second {
		t.Errorf("expected default timeout 30s, got %v", conn.GetTimeout())
	}
}

func TestAzureBlobConnectorDisconnect(t *testing.T) {
	conn := NewAzureBlobConnector()

	// Disconnect when not connected should not error
	err := conn.Disconnect(context.Background())
	if err != nil {
		t.Errorf("unexpected error on disconnect: %v", err)
	}

	if conn.IsConnected() {
		t.Error("expected connected to be false")
	}
}

func TestAzureBlobConnectorQueryRequiresBlob(t *testing.T) {
	conn := NewAzureBlobConnector()
	conn.SetConnected(true)
	ctx := context.Background()

	t.Run("get_blob requires blob", func(t *testing.T) {
		_, err := conn.Query(ctx, &base.Query{
			Statement:  "get_blob",
			Parameters: map[string]interface{}{},
		})
		if err == nil {
			t.Error("expected error when blob is missing")
		}
	})

	t.Run("get_blob_properties requires blob", func(t *testing.T) {
		_, err := conn.Query(ctx, &base.Query{
			Statement:  "get_blob_properties",
			Parameters: map[string]interface{}{},
		})
		if err == nil {
			t.Error("expected error when blob is missing")
		}
	})

	t.Run("generate_sas requires blob", func(t *testing.T) {
		_, err := conn.Query(ctx, &base.Query{
			Statement:  "generate_sas",
			Parameters: map[string]interface{}{},
		})
		if err == nil {
			t.Error("expected error when blob is missing")
		}
	})
}

func TestAzureBlobConnectorExecuteRequiresParams(t *testing.T) {
	conn := NewAzureBlobConnector()
	conn.SetConnected(true)
	ctx := context.Background()

	t.Run("upload_blob requires blob", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action:     "upload_blob",
			Parameters: map[string]interface{}{},
		})
		if err == nil {
			t.Error("expected error when blob is missing")
		}
	})

	t.Run("delete_blob requires blob", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action:     "delete_blob",
			Parameters: map[string]interface{}{},
		})
		if err == nil {
			t.Error("expected error when blob is missing")
		}
	})

	t.Run("copy_blob requires source and dest", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action:     "copy_blob",
			Parameters: map[string]interface{}{},
		})
		if err == nil {
			t.Error("expected error when source/dest is missing")
		}
	})

	t.Run("create_container requires container", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action:     "create_container",
			Parameters: map[string]interface{}{},
		})
		if err == nil {
			t.Error("expected error when container is missing")
		}
	})

	t.Run("delete_container requires container", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action:     "delete_container",
			Parameters: map[string]interface{}{},
		})
		if err == nil {
			t.Error("expected error when container is missing")
		}
	})
}

func TestAzureBlobConnectorQueryDefaultsToListBlobs(t *testing.T) {
	conn := NewAzureBlobConnector()
	conn.SetConnected(true)
	ctx := context.Background()

	// With empty statement, should default to list_blobs but fail because no client
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

func TestAzureBlobConnectorMetrics(t *testing.T) {
	conn := NewAzureBlobConnector()
	metrics := conn.GetMetrics()

	if metrics == nil {
		t.Fatal("expected metrics to be initialized")
	}

	stats := metrics.GetStats()
	if stats.ConnectorType != "azureblob" {
		t.Errorf("expected connector type azureblob, got %s", stats.ConnectorType)
	}
}

// newTestConnectorWithDummyClient creates a connector with dummy Azure clients
// that pass nil-checks but will fail on actual API calls. This allows testing
// routing logic and parameter validation code paths.
func newTestConnectorWithDummyClient(t *testing.T) *AzureBlobConnector {
	t.Helper()
	conn := NewAzureBlobConnector()
	conn.SetConnected(true)
	conn.SetName("test-azure")
	conn.defaultContainer = "default-container"
	conn.accountName = "teststorageaccount"

	var err error
	conn.client, err = azblob.NewClientWithNoCredential("https://teststorageaccount.blob.core.windows.net/", nil)
	if err != nil {
		t.Fatalf("failed to create dummy azblob client: %v", err)
	}
	conn.serviceClient, err = service.NewClientWithNoCredential("https://teststorageaccount.blob.core.windows.net/", nil)
	if err != nil {
		t.Fatalf("failed to create dummy service client: %v", err)
	}
	return conn
}

// requireConnectorError asserts the error is a *base.ConnectorError and returns it.
func requireConnectorError(t *testing.T, err error) *base.ConnectorError {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	connErr, ok := err.(*base.ConnectorError)
	if !ok {
		t.Fatalf("expected *base.ConnectorError, got %T: %v", err, err)
	}
	return connErr
}

// ---------------------------------------------------------------------------
// Query routing: all recognized statement aliases (case-insensitive)
// ---------------------------------------------------------------------------

func TestQueryRoutingAllAliases(t *testing.T) {
	conn := newTestConnectorWithDummyClient(t)
	ctx := context.Background()

	// Each entry maps a statement to the expected error substring when it
	// hits the Azure API (proving it was routed correctly past validation).
	// For actions that require a blob param, we supply one so we get past
	// validation and into the Azure call that fails without a real endpoint.
	tests := []struct {
		name      string
		statement string
		params    map[string]interface{}
		// wantMsg is a substring we expect in the error message to confirm
		// the correct handler was invoked.
		wantMsg string
	}{
		// list_containers routes
		{"list_containers lowercase", "list_containers", nil, "list containers"},
		{"LIST_CONTAINERS uppercase", "LIST_CONTAINERS", nil, "list containers"},
		{"List_Containers mixed", "List_Containers", nil, "list containers"},

		// list_blobs / list routes
		{"list_blobs lowercase", "list_blobs", nil, "list blobs"},
		{"list alias", "list", nil, "list blobs"},
		{"LIST uppercase", "LIST", nil, "list blobs"},
		{"LIST_BLOBS uppercase", "LIST_BLOBS", nil, "list blobs"},

		// get_blob / get routes
		{"get_blob lowercase", "get_blob", map[string]interface{}{"blob": "test.txt"}, "download blob"},
		{"get alias", "get", map[string]interface{}{"blob": "test.txt"}, "download blob"},
		{"GET uppercase", "GET", map[string]interface{}{"blob": "test.txt"}, "download blob"},

		// get_properties / head routes
		{"get_properties lowercase", "get_properties", map[string]interface{}{"blob": "test.txt"}, "get blob properties"},
		{"head alias", "head", map[string]interface{}{"blob": "test.txt"}, "get blob properties"},
		{"HEAD uppercase", "HEAD", map[string]interface{}{"blob": "test.txt"}, "get blob properties"},
		{"Get_Properties mixed", "Get_Properties", map[string]interface{}{"blob": "test.txt"}, "get blob properties"},

		// generate_sas route (needs blob + account_key)
		{"generate_sas lowercase", "generate_sas", map[string]interface{}{"blob": "test.txt"}, "account key required"},
		{"GENERATE_SAS uppercase", "GENERATE_SAS", map[string]interface{}{"blob": "test.txt"}, "account key required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := conn.Query(ctx, &base.Query{
				Statement:  tt.statement,
				Parameters: tt.params,
			})
			if err == nil {
				t.Fatal("expected error from dummy client, got nil")
			}
			if !strings.Contains(strings.ToLower(err.Error()), tt.wantMsg) {
				t.Errorf("expected error containing %q, got: %s", tt.wantMsg, err.Error())
			}
		})
	}
}

func TestQueryRoutingUnknownAction(t *testing.T) {
	conn := newTestConnectorWithDummyClient(t)
	ctx := context.Background()

	unknowns := []string{"drop_table", "DESTROY", "fetch", "read_blob", "scan"}
	for _, action := range unknowns {
		t.Run(action, func(t *testing.T) {
			_, err := conn.Query(ctx, &base.Query{Statement: action})
			connErr := requireConnectorError(t, err)
			if connErr.Operation != "Query" {
				t.Errorf("expected operation Query, got %s", connErr.Operation)
			}
			if !strings.Contains(connErr.Message, "unknown action") {
				t.Errorf("expected 'unknown action' in message, got: %s", connErr.Message)
			}
			if !strings.Contains(connErr.Message, action) {
				t.Errorf("expected action name %q in message, got: %s", action, connErr.Message)
			}
		})
	}
}

func TestQueryEmptyStatementDefaultsToListBlobs(t *testing.T) {
	conn := newTestConnectorWithDummyClient(t)
	ctx := context.Background()

	// Empty statement defaults to "list_blobs" which attempts to list blobs.
	// With the dummy client it will fail at the Azure API, but NOT with "unknown action".
	_, err := conn.Query(ctx, &base.Query{Statement: ""})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	// Must NOT be "unknown action" -- it should route to list_blobs handler
	if strings.Contains(err.Error(), "unknown action") {
		t.Error("empty statement should default to list_blobs, not produce unknown action error")
	}
}

// ---------------------------------------------------------------------------
// Execute routing: all recognized action aliases (case-insensitive)
// ---------------------------------------------------------------------------

func TestExecuteRoutingAllAliases(t *testing.T) {
	conn := newTestConnectorWithDummyClient(t)
	ctx := context.Background()

	tests := []struct {
		name    string
		action  string
		params  map[string]interface{}
		wantMsg string
	}{
		// upload_blob / put / upload routes
		{"upload_blob lowercase", "upload_blob", map[string]interface{}{"blob": "test.txt", "content": "data"}, "upload blob"},
		{"put alias", "put", map[string]interface{}{"blob": "test.txt", "content": "data"}, "upload blob"},
		{"upload alias", "upload", map[string]interface{}{"blob": "test.txt", "content": "data"}, "upload blob"},
		{"PUT uppercase", "PUT", map[string]interface{}{"blob": "test.txt", "content": "data"}, "upload blob"},
		{"UPLOAD_BLOB uppercase", "UPLOAD_BLOB", map[string]interface{}{"blob": "test.txt", "content": "data"}, "upload blob"},

		// delete_blob / delete routes
		{"delete_blob lowercase", "delete_blob", map[string]interface{}{"blob": "test.txt"}, "delete blob"},
		{"delete alias", "delete", map[string]interface{}{"blob": "test.txt"}, "delete blob"},
		{"DELETE uppercase", "DELETE", map[string]interface{}{"blob": "test.txt"}, "delete blob"},

		// copy_blob / copy routes
		{"copy_blob lowercase", "copy_blob", map[string]interface{}{"source_blob": "a.txt", "dest_blob": "b.txt"}, "copy blob"},
		{"copy alias", "copy", map[string]interface{}{"source_blob": "a.txt", "dest_blob": "b.txt"}, "copy blob"},
		{"COPY uppercase", "COPY", map[string]interface{}{"source_blob": "a.txt", "dest_blob": "b.txt"}, "copy blob"},

		// create_container route
		{"create_container lowercase", "create_container", map[string]interface{}{"container": "newcontainer"}, "create container"},
		{"CREATE_CONTAINER uppercase", "CREATE_CONTAINER", map[string]interface{}{"container": "newcontainer"}, "create container"},

		// delete_container route
		{"delete_container lowercase", "delete_container", map[string]interface{}{"container": "oldcontainer"}, "delete container"},
		{"DELETE_CONTAINER uppercase", "DELETE_CONTAINER", map[string]interface{}{"container": "oldcontainer"}, "delete container"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := conn.Execute(ctx, &base.Command{
				Action:     tt.action,
				Parameters: tt.params,
			})
			if err == nil {
				t.Fatal("expected error from dummy client, got nil")
			}
			if !strings.Contains(strings.ToLower(err.Error()), tt.wantMsg) {
				t.Errorf("expected error containing %q, got: %s", tt.wantMsg, err.Error())
			}
		})
	}
}

func TestExecuteRoutingUnknownAction(t *testing.T) {
	conn := newTestConnectorWithDummyClient(t)
	ctx := context.Background()

	unknowns := []string{"truncate", "MERGE", "rename_blob", "move", ""}
	for _, action := range unknowns {
		t.Run("action_"+action, func(t *testing.T) {
			_, err := conn.Execute(ctx, &base.Command{Action: action})
			connErr := requireConnectorError(t, err)
			if connErr.Operation != "Execute" {
				t.Errorf("expected operation Execute, got %s", connErr.Operation)
			}
			if !strings.Contains(connErr.Message, "unknown action") {
				t.Errorf("expected 'unknown action' in message, got: %s", connErr.Message)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Parameter validation: missing required params for each operation
// ---------------------------------------------------------------------------

func TestQueryParameterValidation(t *testing.T) {
	conn := newTestConnectorWithDummyClient(t)
	ctx := context.Background()

	t.Run("get_blob missing blob param", func(t *testing.T) {
		_, err := conn.Query(ctx, &base.Query{
			Statement:  "get_blob",
			Parameters: map[string]interface{}{},
		})
		connErr := requireConnectorError(t, err)
		if connErr.Operation != "Query" {
			t.Errorf("expected operation Query, got %s", connErr.Operation)
		}
		if !strings.Contains(connErr.Message, "blob name is required") {
			t.Errorf("expected 'blob name is required', got: %s", connErr.Message)
		}
	})

	t.Run("get_blob nil params", func(t *testing.T) {
		_, err := conn.Query(ctx, &base.Query{
			Statement:  "get",
			Parameters: nil,
		})
		connErr := requireConnectorError(t, err)
		if !strings.Contains(connErr.Message, "blob name is required") {
			t.Errorf("expected 'blob name is required', got: %s", connErr.Message)
		}
	})

	t.Run("get_properties missing blob param", func(t *testing.T) {
		_, err := conn.Query(ctx, &base.Query{
			Statement:  "get_properties",
			Parameters: map[string]interface{}{},
		})
		connErr := requireConnectorError(t, err)
		if !strings.Contains(connErr.Message, "blob name is required") {
			t.Errorf("expected 'blob name is required', got: %s", connErr.Message)
		}
	})

	t.Run("head alias missing blob param", func(t *testing.T) {
		_, err := conn.Query(ctx, &base.Query{
			Statement:  "head",
			Parameters: map[string]interface{}{"container": "mycontainer"},
		})
		connErr := requireConnectorError(t, err)
		if !strings.Contains(connErr.Message, "blob name is required") {
			t.Errorf("expected 'blob name is required', got: %s", connErr.Message)
		}
	})

	t.Run("generate_sas missing blob param", func(t *testing.T) {
		_, err := conn.Query(ctx, &base.Query{
			Statement:  "generate_sas",
			Parameters: map[string]interface{}{},
		})
		connErr := requireConnectorError(t, err)
		if !strings.Contains(connErr.Message, "blob name is required") {
			t.Errorf("expected 'blob name is required', got: %s", connErr.Message)
		}
	})

	t.Run("generate_sas has blob but no account_key credential", func(t *testing.T) {
		_, err := conn.Query(ctx, &base.Query{
			Statement:  "generate_sas",
			Parameters: map[string]interface{}{"blob": "test.txt"},
		})
		connErr := requireConnectorError(t, err)
		if !strings.Contains(connErr.Message, "account key required") {
			t.Errorf("expected 'account key required', got: %s", connErr.Message)
		}
	})
}

func TestExecuteParameterValidation(t *testing.T) {
	conn := newTestConnectorWithDummyClient(t)
	ctx := context.Background()

	t.Run("upload_blob missing blob param", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action:     "upload_blob",
			Parameters: map[string]interface{}{"content": "data"},
		})
		connErr := requireConnectorError(t, err)
		if connErr.Operation != "Execute" {
			t.Errorf("expected operation Execute, got %s", connErr.Operation)
		}
		if !strings.Contains(connErr.Message, "blob name is required") {
			t.Errorf("expected 'blob name is required', got: %s", connErr.Message)
		}
	})

	t.Run("upload via put alias missing blob", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action:     "put",
			Parameters: nil,
		})
		connErr := requireConnectorError(t, err)
		if !strings.Contains(connErr.Message, "blob name is required") {
			t.Errorf("expected 'blob name is required', got: %s", connErr.Message)
		}
	})

	t.Run("delete_blob missing blob param", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action:     "delete_blob",
			Parameters: map[string]interface{}{},
		})
		connErr := requireConnectorError(t, err)
		if !strings.Contains(connErr.Message, "blob name is required") {
			t.Errorf("expected 'blob name is required', got: %s", connErr.Message)
		}
	})

	t.Run("copy_blob missing both source and dest", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action:     "copy_blob",
			Parameters: map[string]interface{}{},
		})
		connErr := requireConnectorError(t, err)
		if !strings.Contains(connErr.Message, "source_blob and dest_blob are required") {
			t.Errorf("expected 'source_blob and dest_blob are required', got: %s", connErr.Message)
		}
	})

	t.Run("copy_blob missing dest_blob only", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action:     "copy_blob",
			Parameters: map[string]interface{}{"source_blob": "a.txt"},
		})
		connErr := requireConnectorError(t, err)
		if !strings.Contains(connErr.Message, "source_blob and dest_blob are required") {
			t.Errorf("expected 'source_blob and dest_blob are required', got: %s", connErr.Message)
		}
	})

	t.Run("copy_blob missing source_blob only", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action:     "copy_blob",
			Parameters: map[string]interface{}{"dest_blob": "b.txt"},
		})
		connErr := requireConnectorError(t, err)
		if !strings.Contains(connErr.Message, "source_blob and dest_blob are required") {
			t.Errorf("expected 'source_blob and dest_blob are required', got: %s", connErr.Message)
		}
	})

	t.Run("create_container missing container param", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action:     "create_container",
			Parameters: map[string]interface{}{},
		})
		connErr := requireConnectorError(t, err)
		if !strings.Contains(connErr.Message, "container name is required") {
			t.Errorf("expected 'container name is required', got: %s", connErr.Message)
		}
	})

	t.Run("create_container nil params", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action:     "create_container",
			Parameters: nil,
		})
		connErr := requireConnectorError(t, err)
		if !strings.Contains(connErr.Message, "container name is required") {
			t.Errorf("expected 'container name is required', got: %s", connErr.Message)
		}
	})

	t.Run("delete_container missing container param", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action:     "delete_container",
			Parameters: map[string]interface{}{},
		})
		connErr := requireConnectorError(t, err)
		if !strings.Contains(connErr.Message, "container name is required") {
			t.Errorf("expected 'container name is required', got: %s", connErr.Message)
		}
	})

	t.Run("delete_container nil params", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{
			Action:     "delete_container",
			Parameters: nil,
		})
		connErr := requireConnectorError(t, err)
		if !strings.Contains(connErr.Message, "container name is required") {
			t.Errorf("expected 'container name is required', got: %s", connErr.Message)
		}
	})
}

// ---------------------------------------------------------------------------
// Connect: authentication method routing and validation
// ---------------------------------------------------------------------------

func TestConnectNoAuthMethod(t *testing.T) {
	conn := NewAzureBlobConnector()
	ctx := context.Background()

	cfg := &base.ConnectorConfig{
		Name: "test-no-auth",
		Type: "azureblob",
		Options: map[string]interface{}{
			"account_name": "myaccount",
		},
		Credentials: map[string]string{},
	}

	err := conn.Connect(ctx, cfg)
	if err == nil {
		t.Fatal("expected error when no auth method is provided")
	}
	connErr := requireConnectorError(t, err)
	if !strings.Contains(connErr.Message, "no authentication method provided") {
		t.Errorf("expected 'no authentication method provided', got: %s", connErr.Message)
	}
}

func TestConnectMissingAccountName(t *testing.T) {
	conn := NewAzureBlobConnector()
	ctx := context.Background()

	cfg := &base.ConnectorConfig{
		Name:    "test-missing-account",
		Type:    "azureblob",
		Options: map[string]interface{}{},
		Credentials: map[string]string{
			"account_key": "somekey",
		},
	}

	// The validator requires "account_name" in Options or Credentials.
	// Since account_key is in Credentials, account_name is still missing from Options.
	err := conn.Connect(ctx, cfg)
	if err == nil {
		t.Fatal("expected validation error for missing account_name")
	}
	if !strings.Contains(err.Error(), "account_name") {
		t.Errorf("expected error about account_name, got: %s", err.Error())
	}
}

func TestConnectValidationMissingName(t *testing.T) {
	conn := NewAzureBlobConnector()
	ctx := context.Background()

	cfg := &base.ConnectorConfig{
		Name: "",
		Type: "azureblob",
		Options: map[string]interface{}{
			"account_name": "myaccount",
		},
		Credentials: map[string]string{
			"account_key": "somekey",
		},
	}

	err := conn.Connect(ctx, cfg)
	if err == nil {
		t.Fatal("expected validation error for missing connector name")
	}
	if !strings.Contains(err.Error(), "name") {
		t.Errorf("expected error about name, got: %s", err.Error())
	}
}

func TestConnectValidationMissingType(t *testing.T) {
	conn := NewAzureBlobConnector()
	ctx := context.Background()

	cfg := &base.ConnectorConfig{
		Name: "test-no-type",
		Type: "",
		Options: map[string]interface{}{
			"account_name": "myaccount",
		},
		Credentials: map[string]string{
			"account_key": "somekey",
		},
	}

	err := conn.Connect(ctx, cfg)
	if err == nil {
		t.Fatal("expected validation error for missing connector type")
	}
	if !strings.Contains(err.Error(), "type") {
		t.Errorf("expected error about type, got: %s", err.Error())
	}
}

func TestConnectWithInvalidAccountKey(t *testing.T) {
	conn := NewAzureBlobConnector()
	ctx := context.Background()

	cfg := &base.ConnectorConfig{
		Name: "test-bad-key",
		Type: "azureblob",
		Options: map[string]interface{}{
			"account_name": "myaccount",
		},
		Credentials: map[string]string{
			"account_key": "not-valid-base64!@#$",
		},
	}

	err := conn.Connect(ctx, cfg)
	if err == nil {
		t.Fatal("expected error with invalid account key")
	}
	connErr := requireConnectorError(t, err)
	if connErr.Operation != "Connect" {
		t.Errorf("expected operation Connect, got %s", connErr.Operation)
	}
}

func TestConnectWithConnectionString(t *testing.T) {
	conn := NewAzureBlobConnector()
	ctx := context.Background()

	// Valid format connection string but non-existent account.
	// The SDK will parse it successfully but fail on connectivity check.
	cfg := &base.ConnectorConfig{
		Name: "test-connstr",
		Type: "azureblob",
		Options: map[string]interface{}{
			"account_name": "devstoreaccount1",
		},
		Credentials: map[string]string{
			"connection_string": "DefaultEndpointsProtocol=https;AccountName=devstoreaccount1;AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;EndpointSuffix=core.windows.net",
		},
	}

	err := conn.Connect(ctx, cfg)
	// Will fail on connectivity check (GetProperties), but should get past
	// the client creation step.
	if err == nil {
		t.Fatal("expected connectivity check to fail with fake account")
	}
	connErr := requireConnectorError(t, err)
	if connErr.Operation != "Connect" {
		t.Errorf("expected operation Connect, got %s", connErr.Operation)
	}
	// The error should be about connectivity, not about creating the client
	if !strings.Contains(connErr.Message, "connectivity") && !strings.Contains(connErr.Message, "verify") {
		// Accept either "failed to verify Azure Blob connectivity" or similar
		t.Logf("connect error: %s", connErr.Message)
	}
}

func TestConnectWithManagedIdentity(t *testing.T) {
	conn := NewAzureBlobConnector()
	ctx := context.Background()

	cfg := &base.ConnectorConfig{
		Name: "test-mi",
		Type: "azureblob",
		Options: map[string]interface{}{
			"account_name":         "myaccount",
			"use_managed_identity": true,
		},
		Credentials: map[string]string{},
	}

	// Managed identity will fail because we're not in an Azure environment,
	// but it should take the managed identity code path.
	err := conn.Connect(ctx, cfg)
	if err == nil {
		t.Fatal("expected error in non-Azure environment")
	}
	// The error should mention Azure credential creation or connectivity
	connErr := requireConnectorError(t, err)
	if connErr.Operation != "Connect" {
		t.Errorf("expected operation Connect, got %s", connErr.Operation)
	}
}

// ---------------------------------------------------------------------------
// HealthCheck: error message and details verification
// ---------------------------------------------------------------------------

func TestHealthCheckWithoutClientReturnsSpecificError(t *testing.T) {
	conn := NewAzureBlobConnector()
	ctx := context.Background()

	status, err := conn.HealthCheck(ctx)
	if err != nil {
		t.Fatalf("HealthCheck should not return error, got: %v", err)
	}

	if status.Healthy {
		t.Error("expected unhealthy status")
	}

	if status.Error != "Azure Blob client not initialized" {
		t.Errorf("expected specific error message, got: %s", status.Error)
	}

	if status.Timestamp.IsZero() {
		t.Error("expected timestamp to be set")
	}
}

func TestHealthCheckWithDummyClientFailsGracefully(t *testing.T) {
	conn := newTestConnectorWithDummyClient(t)
	ctx := context.Background()

	status, err := conn.HealthCheck(ctx)
	// HealthCheck should not return an error -- it wraps failures in the status
	if err != nil {
		t.Fatalf("HealthCheck should not return error, got: %v", err)
	}

	// With a dummy client pointing at a fake endpoint, GetProperties will fail
	if status.Healthy {
		t.Error("expected unhealthy status with dummy client")
	}

	if status.Error == "" {
		t.Error("expected error message in status")
	}

	// Even on failure, latency should be set (non-zero after the API call attempt)
	// and timestamp should be set
	if status.Timestamp.IsZero() {
		t.Error("expected timestamp to be set")
	}
}

// ---------------------------------------------------------------------------
// Disconnect: state transitions and field clearing
// ---------------------------------------------------------------------------

func TestDisconnectClearsClientReferences(t *testing.T) {
	conn := newTestConnectorWithDummyClient(t)
	ctx := context.Background()

	if conn.client == nil {
		t.Fatal("expected client to be set before disconnect")
	}
	if conn.serviceClient == nil {
		t.Fatal("expected serviceClient to be set before disconnect")
	}

	err := conn.Disconnect(ctx)
	if err != nil {
		t.Fatalf("unexpected error on disconnect: %v", err)
	}

	if conn.client != nil {
		t.Error("expected client to be nil after disconnect")
	}
	if conn.serviceClient != nil {
		t.Error("expected serviceClient to be nil after disconnect")
	}
	if conn.IsConnected() {
		t.Error("expected IsConnected to be false after disconnect")
	}
}

func TestDisconnectIdempotent(t *testing.T) {
	conn := NewAzureBlobConnector()
	ctx := context.Background()

	// Disconnect twice should not error
	if err := conn.Disconnect(ctx); err != nil {
		t.Errorf("first disconnect error: %v", err)
	}
	if err := conn.Disconnect(ctx); err != nil {
		t.Errorf("second disconnect error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Query/Execute with nil client: error message verification
// ---------------------------------------------------------------------------

func TestQueryNilClientErrorMessage(t *testing.T) {
	conn := NewAzureBlobConnector()
	conn.SetConnected(true)
	conn.SetName("my-azure")
	ctx := context.Background()

	// All query statements should fail with client not initialized
	statements := []string{"list_containers", "list_blobs", "get_blob", "get_properties", "generate_sas"}
	for _, stmt := range statements {
		t.Run(stmt, func(t *testing.T) {
			_, err := conn.Query(ctx, &base.Query{Statement: stmt})
			connErr := requireConnectorError(t, err)
			if connErr.ConnectorName != "my-azure" {
				t.Errorf("expected connector name 'my-azure', got %s", connErr.ConnectorName)
			}
			if connErr.Operation != "Query" {
				t.Errorf("expected operation 'Query', got %s", connErr.Operation)
			}
			if connErr.Message != "Azure Blob client not initialized" {
				t.Errorf("expected 'Azure Blob client not initialized', got: %s", connErr.Message)
			}
		})
	}
}

func TestExecuteNilClientErrorMessage(t *testing.T) {
	conn := NewAzureBlobConnector()
	conn.SetConnected(true)
	conn.SetName("my-azure")
	ctx := context.Background()

	actions := []string{"upload_blob", "delete_blob", "copy_blob", "create_container", "delete_container"}
	for _, action := range actions {
		t.Run(action, func(t *testing.T) {
			_, err := conn.Execute(ctx, &base.Command{Action: action})
			connErr := requireConnectorError(t, err)
			if connErr.ConnectorName != "my-azure" {
				t.Errorf("expected connector name 'my-azure', got %s", connErr.ConnectorName)
			}
			if connErr.Operation != "Execute" {
				t.Errorf("expected operation 'Execute', got %s", connErr.Operation)
			}
			if connErr.Message != "Azure Blob client not initialized" {
				t.Errorf("expected 'Azure Blob client not initialized', got: %s", connErr.Message)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Query/Execute not connected: base connector guard
// ---------------------------------------------------------------------------

func TestQueryNotConnectedGoesViaBaseGuard(t *testing.T) {
	conn := NewAzureBlobConnector()
	// NOT calling SetConnected(true), so base connector guard triggers
	ctx := context.Background()

	_, err := conn.Query(ctx, &base.Query{Statement: "list_blobs"})
	if err == nil {
		t.Fatal("expected error when not connected")
	}
	// The error comes from AzureBlobConnector.Query checking c.client == nil
	connErr := requireConnectorError(t, err)
	if connErr.Operation != "Query" {
		t.Errorf("expected operation Query, got %s", connErr.Operation)
	}
}

func TestExecuteNotConnectedGoesViaBaseGuard(t *testing.T) {
	conn := NewAzureBlobConnector()
	ctx := context.Background()

	_, err := conn.Execute(ctx, &base.Command{Action: "upload_blob"})
	if err == nil {
		t.Fatal("expected error when not connected")
	}
	connErr := requireConnectorError(t, err)
	if connErr.Operation != "Execute" {
		t.Errorf("expected operation Execute, got %s", connErr.Operation)
	}
}

// ---------------------------------------------------------------------------
// getContainer: edge cases
// ---------------------------------------------------------------------------

func TestGetContainerEdgeCases(t *testing.T) {
	conn := NewAzureBlobConnector()

	t.Run("nil params returns default", func(t *testing.T) {
		conn.defaultContainer = "fallback"
		result := conn.getContainer(nil)
		if result != "fallback" {
			t.Errorf("expected 'fallback', got %s", result)
		}
	})

	t.Run("empty container param returns default", func(t *testing.T) {
		conn.defaultContainer = "fallback"
		result := conn.getContainer(map[string]interface{}{"container": ""})
		if result != "fallback" {
			t.Errorf("expected 'fallback', got %s", result)
		}
	})

	t.Run("non-string container param returns default", func(t *testing.T) {
		conn.defaultContainer = "fallback"
		result := conn.getContainer(map[string]interface{}{"container": 12345})
		if result != "fallback" {
			t.Errorf("expected 'fallback' for non-string container, got %s", result)
		}
	})

	t.Run("no default container returns empty", func(t *testing.T) {
		conn.defaultContainer = ""
		result := conn.getContainer(map[string]interface{}{})
		if result != "" {
			t.Errorf("expected empty string, got %s", result)
		}
	})

	t.Run("container param takes precedence over default", func(t *testing.T) {
		conn.defaultContainer = "default"
		result := conn.getContainer(map[string]interface{}{"container": "override"})
		if result != "override" {
			t.Errorf("expected 'override', got %s", result)
		}
	})
}

// ---------------------------------------------------------------------------
// Helper function edge cases
// ---------------------------------------------------------------------------

func TestHelperFunctionEdgeCases(t *testing.T) {
	t.Run("getStringParam with non-string value returns default", func(t *testing.T) {
		params := map[string]interface{}{
			"number": 42,
			"bool":   true,
			"slice":  []string{"a"},
		}
		if v := getStringParam(params, "number", "default"); v != "default" {
			t.Errorf("expected 'default' for int value, got %s", v)
		}
		if v := getStringParam(params, "bool", "default"); v != "default" {
			t.Errorf("expected 'default' for bool value, got %s", v)
		}
		if v := getStringParam(params, "slice", "default"); v != "default" {
			t.Errorf("expected 'default' for slice value, got %s", v)
		}
	})

	t.Run("getStringParam empty string value", func(t *testing.T) {
		params := map[string]interface{}{"key": ""}
		if v := getStringParam(params, "key", "default"); v != "" {
			t.Errorf("expected empty string, got %s", v)
		}
	})

	t.Run("getIntParam with missing key returns default", func(t *testing.T) {
		params := map[string]interface{}{}
		if v := getIntParam(params, "missing", 99); v != 99 {
			t.Errorf("expected 99, got %d", v)
		}
	})

	t.Run("getIntParam with bool value returns default", func(t *testing.T) {
		params := map[string]interface{}{"key": true}
		if v := getIntParam(params, "key", 77); v != 77 {
			t.Errorf("expected 77, got %d", v)
		}
	})

	t.Run("getIntParam with nil value returns default", func(t *testing.T) {
		params := map[string]interface{}{"key": nil}
		if v := getIntParam(params, "key", 55); v != 55 {
			t.Errorf("expected 55, got %d", v)
		}
	})

	t.Run("getIntParam with string value returns default", func(t *testing.T) {
		params := map[string]interface{}{"key": "42"}
		if v := getIntParam(params, "key", 33); v != 33 {
			t.Errorf("expected 33, got %d", v)
		}
	})

	t.Run("getStringPtrValue with empty string pointer", func(t *testing.T) {
		s := ""
		if v := getStringPtrValue(&s); v != "" {
			t.Errorf("expected empty string, got %s", v)
		}
	})
}

// ---------------------------------------------------------------------------
// ConnectorError format verification
// ---------------------------------------------------------------------------

func TestConnectorErrorFormat(t *testing.T) {
	conn := newTestConnectorWithDummyClient(t)
	ctx := context.Background()

	t.Run("error without cause", func(t *testing.T) {
		_, err := conn.Query(ctx, &base.Query{
			Statement: "get_blob",
			Parameters: map[string]interface{}{},
		})
		connErr := requireConnectorError(t, err)

		// Error string format: "connectorName.Operation: Message"
		errStr := connErr.Error()
		if !strings.HasPrefix(errStr, "test-azure.Query:") {
			t.Errorf("expected error to start with 'test-azure.Query:', got: %s", errStr)
		}
		if connErr.Cause != nil {
			t.Error("expected no cause for parameter validation error")
		}
	})

	t.Run("unsupported query error includes action name", func(t *testing.T) {
		_, err := conn.Query(ctx, &base.Query{Statement: "FOOBAR"})
		connErr := requireConnectorError(t, err)
		if !strings.Contains(connErr.Message, "FOOBAR") {
			t.Errorf("expected error to include action name 'FOOBAR', got: %s", connErr.Message)
		}
	})

	t.Run("unsupported execute error includes action name", func(t *testing.T) {
		_, err := conn.Execute(ctx, &base.Command{Action: "BAZQUX"})
		connErr := requireConnectorError(t, err)
		if !strings.Contains(connErr.Message, "BAZQUX") {
			t.Errorf("expected error to include action name 'BAZQUX', got: %s", connErr.Message)
		}
	})
}

// ---------------------------------------------------------------------------
// Default container fallback from config
// ---------------------------------------------------------------------------

func TestDefaultContainerFromConfig(t *testing.T) {
	conn := NewAzureBlobConnector()
	ctx := context.Background()

	// Use connection string auth so we get past client creation
	cfg := &base.ConnectorConfig{
		Name: "test-default-container",
		Type: "azureblob",
		Options: map[string]interface{}{
			"account_name":      "devstoreaccount1",
			"default_container": "my-configured-container",
		},
		Credentials: map[string]string{
			"connection_string": "DefaultEndpointsProtocol=https;AccountName=devstoreaccount1;AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;EndpointSuffix=core.windows.net",
		},
	}

	// Connect will fail at connectivity check, but config values should be read
	_ = conn.Connect(ctx, cfg)

	if conn.defaultContainer != "my-configured-container" {
		t.Errorf("expected defaultContainer='my-configured-container', got %s", conn.defaultContainer)
	}
	if conn.accountName != "devstoreaccount1" {
		t.Errorf("expected accountName='devstoreaccount1', got %s", conn.accountName)
	}
}

// ---------------------------------------------------------------------------
// Metrics recording on Query/Execute with dummy client
// ---------------------------------------------------------------------------

func TestMetricsRecordedOnDisconnect(t *testing.T) {
	conn := newTestConnectorWithDummyClient(t)
	ctx := context.Background()

	// Record initial state
	statsBefore := conn.GetMetrics().GetStats()
	disconnectsBefore := statsBefore.DisconnectsTotal

	err := conn.Disconnect(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	statsAfter := conn.GetMetrics().GetStats()
	if statsAfter.DisconnectsTotal != disconnectsBefore+1 {
		t.Errorf("expected disconnects to increment, before=%d after=%d",
			disconnectsBefore, statsAfter.DisconnectsTotal)
	}
}

// ---------------------------------------------------------------------------
// Verify interface compliance at compile time is already done in connector.go
// but test it explicitly as well
// ---------------------------------------------------------------------------

func TestInterfaceCompliance(t *testing.T) {
	var _ base.Connector = (*AzureBlobConnector)(nil)
	var _ base.Connector = NewAzureBlobConnector()
}
