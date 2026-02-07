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
	"testing"
	"time"

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
