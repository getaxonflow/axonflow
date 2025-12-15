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

package http

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"axonflow/platform/connectors/base"
)

func TestNewHTTPConnector(t *testing.T) {
	c := NewHTTPConnector()
	if c == nil {
		t.Fatal("NewHTTPConnector returned nil")
	}
	if c.maxResponseSize != DefaultMaxResponseSize {
		t.Errorf("expected maxResponseSize %d, got %d", DefaultMaxResponseSize, c.maxResponseSize)
	}
	if c.maxRetries != DefaultMaxRetries {
		t.Errorf("expected maxRetries %d, got %d", DefaultMaxRetries, c.maxRetries)
	}
	if c.allowPrivateIPs {
		t.Error("expected allowPrivateIPs to be false by default")
	}
}

func TestHTTPConnector_Connect(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tests := []struct {
		name    string
		config  *base.ConnectorConfig
		wantErr bool
	}{
		{
			name: "valid config with public URL",
			config: &base.ConnectorConfig{
				Name: "test-http",
				Options: map[string]interface{}{
					"base_url":         server.URL,
					"allow_private_ips": true, // Allow for testing with localhost
				},
			},
			wantErr: false,
		},
		{
			name: "missing base_url",
			config: &base.ConnectorConfig{
				Name:    "test-http",
				Options: map[string]interface{}{},
			},
			wantErr: true,
		},
		{
			name: "invalid URL scheme",
			config: &base.ConnectorConfig{
				Name: "test-http",
				Options: map[string]interface{}{
					"base_url": "ftp://example.com",
				},
			},
			wantErr: true,
		},
		{
			name: "private IP blocked by default",
			config: &base.ConnectorConfig{
				Name: "test-http",
				Options: map[string]interface{}{
					"base_url": "http://192.168.1.1",
				},
			},
			wantErr: true,
		},
		{
			name: "config with auth",
			config: &base.ConnectorConfig{
				Name: "test-http",
				Options: map[string]interface{}{
					"base_url":         server.URL,
					"auth_type":        "bearer",
					"allow_private_ips": true,
				},
				Credentials: map[string]string{
					"token": "test-token",
				},
			},
			wantErr: false,
		},
		{
			name: "config with custom headers",
			config: &base.ConnectorConfig{
				Name: "test-http",
				Options: map[string]interface{}{
					"base_url":         server.URL,
					"allow_private_ips": true,
					"headers": map[string]interface{}{
						"X-Custom-Header": "custom-value",
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewHTTPConnector()
			err := c.Connect(context.Background(), tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("Connect() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil {
				_ = c.Disconnect(context.Background())
			}
		})
	}
}

func TestHTTPConnector_Query(t *testing.T) {
	// Create a test server that returns JSON
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/users" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 1, "name": "Alice"},
				{"id": 2, "name": "Bob"},
			})
			return
		}
		if r.URL.Path == "/user/1" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id": 1, "name": "Alice",
			})
			return
		}
		if r.URL.Path == "/error" {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Internal Server Error"))
			return
		}
		if r.URL.Path == "/text" {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte("Hello, World!"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	c := NewHTTPConnector()
	err := c.Connect(context.Background(), &base.ConnectorConfig{
		Name: "test-http",
		Options: map[string]interface{}{
			"base_url":         server.URL,
			"allow_private_ips": true,
		},
	})
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer c.Disconnect(context.Background())

	tests := []struct {
		name       string
		query      *base.Query
		wantErr    bool
		wantRows   int
	}{
		{
			name: "query array response",
			query: &base.Query{
				Statement: "/users",
			},
			wantErr:  false,
			wantRows: 2,
		},
		{
			name: "query single object",
			query: &base.Query{
				Statement: "/user/1",
			},
			wantErr:  false,
			wantRows: 1,
		},
		{
			name: "query with parameters",
			query: &base.Query{
				Statement: "/users",
				Parameters: map[string]interface{}{
					"page": 1,
					"size": 10,
				},
			},
			wantErr:  false,
			wantRows: 2,
		},
		{
			name: "query text response",
			query: &base.Query{
				Statement: "/text",
			},
			wantErr:  false,
			wantRows: 1,
		},
		{
			name: "query error response",
			query: &base.Query{
				Statement: "/error",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := c.Query(context.Background(), tt.query)
			if (err != nil) != tt.wantErr {
				t.Errorf("Query() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && result.RowCount != tt.wantRows {
				t.Errorf("Query() rows = %d, want %d", result.RowCount, tt.wantRows)
			}
		})
	}
}

func TestHTTPConnector_Execute(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "POST":
			if r.URL.Path == "/users" {
				w.WriteHeader(http.StatusCreated)
				json.NewEncoder(w).Encode(map[string]interface{}{"id": 3})
				return
			}
		case "PUT":
			if r.URL.Path == "/users/1" {
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]interface{}{"updated": true})
				return
			}
		case "DELETE":
			if r.URL.Path == "/users/1" {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		case "PATCH":
			if r.URL.Path == "/users/1" {
				w.WriteHeader(http.StatusOK)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	c := NewHTTPConnector()
	err := c.Connect(context.Background(), &base.ConnectorConfig{
		Name: "test-http",
		Options: map[string]interface{}{
			"base_url":         server.URL,
			"allow_private_ips": true,
		},
	})
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer c.Disconnect(context.Background())

	tests := []struct {
		name        string
		cmd         *base.Command
		wantSuccess bool
	}{
		{
			name: "POST request",
			cmd: &base.Command{
				Action:    "POST",
				Statement: "/users",
				Parameters: map[string]interface{}{
					"name": "Charlie",
				},
			},
			wantSuccess: true,
		},
		{
			name: "PUT request",
			cmd: &base.Command{
				Action:    "PUT",
				Statement: "/users/1",
				Parameters: map[string]interface{}{
					"name": "Alice Updated",
				},
			},
			wantSuccess: true,
		},
		{
			name: "DELETE request",
			cmd: &base.Command{
				Action:    "DELETE",
				Statement: "/users/1",
			},
			wantSuccess: true,
		},
		{
			name: "PATCH request",
			cmd: &base.Command{
				Action:    "PATCH",
				Statement: "/users/1",
				Parameters: map[string]interface{}{
					"status": "active",
				},
			},
			wantSuccess: true,
		},
		{
			name: "invalid method",
			cmd: &base.Command{
				Action:    "INVALID",
				Statement: "/users",
			},
			wantSuccess: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := c.Execute(context.Background(), tt.cmd)
			if err != nil && tt.wantSuccess {
				t.Errorf("Execute() unexpected error: %v", err)
				return
			}
			if err == nil && result.Success != tt.wantSuccess {
				t.Errorf("Execute() success = %v, want %v", result.Success, tt.wantSuccess)
			}
		})
	}
}

func TestHTTPConnector_HealthCheck(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	tests := []struct {
		name        string
		healthPath  string
		wantHealthy bool
	}{
		{
			name:        "healthy with default path",
			healthPath:  "",
			wantHealthy: false, // 404 on /
		},
		{
			name:        "healthy with custom path",
			healthPath:  "/health",
			wantHealthy: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewHTTPConnector()
			opts := map[string]interface{}{
				"base_url":         server.URL,
				"allow_private_ips": true,
			}
			if tt.healthPath != "" {
				opts["health_path"] = tt.healthPath
			}
			err := c.Connect(context.Background(), &base.ConnectorConfig{
				Name:    "test-http",
				Options: opts,
			})
			if err != nil {
				t.Fatalf("Connect failed: %v", err)
			}
			defer c.Disconnect(context.Background())

			status, err := c.HealthCheck(context.Background())
			if err != nil {
				t.Fatalf("HealthCheck failed: %v", err)
			}
			if status.Healthy != tt.wantHealthy {
				t.Errorf("HealthCheck() healthy = %v, want %v", status.Healthy, tt.wantHealthy)
			}
		})
	}
}

func TestHTTPConnector_Authentication(t *testing.T) {
	tests := []struct {
		name       string
		authType   string
		creds      map[string]string
		wantHeader string
		wantValue  string
	}{
		{
			name:       "bearer auth",
			authType:   "bearer",
			creds:      map[string]string{"token": "my-token"},
			wantHeader: "Authorization",
			wantValue:  "Bearer my-token",
		},
		{
			name:       "api-key auth",
			authType:   "api-key",
			creds:      map[string]string{"api_key": "my-api-key"},
			wantHeader: "X-API-Key",
			wantValue:  "my-api-key",
		},
		{
			name:       "api-key with custom header",
			authType:   "api-key",
			creds:      map[string]string{"api_key": "my-api-key", "header_name": "X-Custom-Key"},
			wantHeader: "X-Custom-Key",
			wantValue:  "my-api-key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var receivedHeader string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				receivedHeader = r.Header.Get(tt.wantHeader)
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			}))
			defer server.Close()

			c := NewHTTPConnector()
			err := c.Connect(context.Background(), &base.ConnectorConfig{
				Name: "test-http",
				Options: map[string]interface{}{
					"base_url":         server.URL,
					"auth_type":        tt.authType,
					"allow_private_ips": true,
				},
				Credentials: tt.creds,
			})
			if err != nil {
				t.Fatalf("Connect failed: %v", err)
			}
			defer c.Disconnect(context.Background())

			_, err = c.Query(context.Background(), &base.Query{Statement: "/"})
			if err != nil {
				t.Fatalf("Query failed: %v", err)
			}

			if receivedHeader != tt.wantValue {
				t.Errorf("expected %s header value %q, got %q", tt.wantHeader, tt.wantValue, receivedHeader)
			}
		})
	}
}

func TestHTTPConnector_Retry(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	c := NewHTTPConnector()
	err := c.Connect(context.Background(), &base.ConnectorConfig{
		Name: "test-http",
		Options: map[string]interface{}{
			"base_url":         server.URL,
			"allow_private_ips": true,
			"max_retries":      float64(3),
			"retry_delay":      "10ms",
		},
	})
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer c.Disconnect(context.Background())

	result, err := c.Query(context.Background(), &base.Query{Statement: "/"})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
	if result.RowCount != 1 {
		t.Errorf("expected 1 row, got %d", result.RowCount)
	}
}

func TestHTTPConnector_ResponseSizeLimit(t *testing.T) {
	// Create a server that returns a large response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Generate a large response
		large := strings.Repeat("x", 1024*1024) // 1MB
		json.NewEncoder(w).Encode(map[string]string{"data": large})
	}))
	defer server.Close()

	c := NewHTTPConnector()
	err := c.Connect(context.Background(), &base.ConnectorConfig{
		Name: "test-http",
		Options: map[string]interface{}{
			"base_url":          server.URL,
			"allow_private_ips":  true,
			"max_response_size": float64(1024), // 1KB limit
		},
	})
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer c.Disconnect(context.Background())

	_, err = c.Query(context.Background(), &base.Query{Statement: "/"})
	if err == nil {
		t.Error("expected error for large response, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds limit") {
		t.Errorf("expected size limit error, got: %v", err)
	}
}

func TestHTTPConnector_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c := NewHTTPConnector()
	err := c.Connect(context.Background(), &base.ConnectorConfig{
		Name:    "test-http",
		Timeout: 100 * time.Millisecond,
		Options: map[string]interface{}{
			"base_url":         server.URL,
			"allow_private_ips": true,
			"max_retries":      float64(0),
		},
	})
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer c.Disconnect(context.Background())

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_, err = c.Query(ctx, &base.Query{Statement: "/"})
	if err == nil {
		t.Error("expected timeout error, got nil")
	}
}

func TestHTTPConnector_IsPrivateIP(t *testing.T) {
	c := NewHTTPConnector()

	tests := []struct {
		ip        string
		isPrivate bool
	}{
		{"127.0.0.1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"192.168.1.1", true},
		{"169.254.169.254", true}, // AWS metadata
		{"0.0.0.0", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"::1", true},
		{"fe80::1", true},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP: %s", tt.ip)
			}
			result := c.isPrivateIP(ip)
			if result != tt.isPrivate {
				t.Errorf("isPrivateIP(%s) = %v, want %v", tt.ip, result, tt.isPrivate)
			}
		})
	}
}

func TestHTTPConnector_Metadata(t *testing.T) {
	c := NewHTTPConnector()

	if c.Type() != "http" {
		t.Errorf("Type() = %s, want http", c.Type())
	}
	if c.Version() != "1.0.0" {
		t.Errorf("Version() = %s, want 1.0.0", c.Version())
	}

	caps := c.Capabilities()
	expectedCaps := []string{"query", "execute", "rest-api", "retry", "ssrf-protection"}
	if len(caps) != len(expectedCaps) {
		t.Errorf("Capabilities() length = %d, want %d", len(caps), len(expectedCaps))
	}
}

func TestHTTPConnector_ConvertToRows(t *testing.T) {
	c := NewHTTPConnector()

	tests := []struct {
		name     string
		input    interface{}
		wantRows int
	}{
		{
			name:     "array of objects",
			input:    []interface{}{map[string]interface{}{"a": 1}, map[string]interface{}{"b": 2}},
			wantRows: 2,
		},
		{
			name:     "single object",
			input:    map[string]interface{}{"a": 1},
			wantRows: 1,
		},
		{
			name:     "array of primitives",
			input:    []interface{}{1, 2, 3},
			wantRows: 3,
		},
		{
			name:     "primitive value",
			input:    "hello",
			wantRows: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rows := c.convertToRows(tt.input)
			if len(rows) != tt.wantRows {
				t.Errorf("convertToRows() returned %d rows, want %d", len(rows), tt.wantRows)
			}
		})
	}
}

func TestHTTPConnector_CalculateBackoff(t *testing.T) {
	c := NewHTTPConnector()
	c.retryDelay = 100 * time.Millisecond

	tests := []struct {
		attempt  int
		expected time.Duration
	}{
		{1, 100 * time.Millisecond},
		{2, 200 * time.Millisecond},
		{3, 400 * time.Millisecond},
		{4, 800 * time.Millisecond},
		{10, MaxRetryDelay}, // Should cap at max
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			result := c.calculateBackoff(tt.attempt)
			if result != tt.expected {
				t.Errorf("calculateBackoff(%d) = %v, want %v", tt.attempt, result, tt.expected)
			}
		})
	}
}

func TestHTTPConnector_IsRetryableStatusCode(t *testing.T) {
	c := NewHTTPConnector()

	retryable := []int{408, 429, 500, 502, 503, 504}
	nonRetryable := []int{200, 201, 400, 401, 403, 404, 405}

	for _, code := range retryable {
		if !c.isRetryableStatusCode(code) {
			t.Errorf("expected %d to be retryable", code)
		}
	}

	for _, code := range nonRetryable {
		if c.isRetryableStatusCode(code) {
			t.Errorf("expected %d to not be retryable", code)
		}
	}
}
