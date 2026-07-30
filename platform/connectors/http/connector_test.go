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
					"base_url":          server.URL,
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
					"base_url":          server.URL,
					"auth_type":         "bearer",
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
					"base_url":          server.URL,
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
			"base_url":          server.URL,
			"allow_private_ips": true,
		},
	})
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer c.Disconnect(context.Background())

	tests := []struct {
		name     string
		query    *base.Query
		wantErr  bool
		wantRows int
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
			"base_url":          server.URL,
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
				"base_url":          server.URL,
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
					"base_url":          server.URL,
					"auth_type":         tt.authType,
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
			"base_url":          server.URL,
			"allow_private_ips": true,
			"max_retries":       float64(3),
			"retry_delay":       "10ms",
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
			"allow_private_ips": true,
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
			"base_url":          server.URL,
			"allow_private_ips": true,
			"max_retries":       float64(0),
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

// TestHTTPConnector_IsPrivateIP exercises the canonical classifier the HTTP
// connector now delegates to. The connector no longer has a private copy.
func TestHTTPConnector_IsPrivateIP(t *testing.T) {
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
			result := base.IsPrivateIP(ip)
			if result != tt.isPrivate {
				t.Errorf("base.IsPrivateIP(%s) = %v, want %v", tt.ip, result, tt.isPrivate)
			}
		})
	}
}

// reservedRangeCases is the shared table used to pin the SSRF classifier that
// guards HTTP-connector egress. It covers every IANA special-purpose range the
// canonical classifier rejects, the boundary addresses immediately outside each
// one (so a range can never be silently widened or narrowed), and the IPv6
// families the classifier handles.
//
// 198.18.0.0/15 (RFC 2544 / RFC 6815 inter-network benchmarking) is
// deliberately NOT rejected and is pinned as permitted here: runtime-e2e suites
// carve sentinel networks out of it precisely because it is reachable under the
// egress guard. Changing that is a deliberate, breaking decision, not a drift.
var reservedRangeCases = []struct {
	ip      string
	blocked bool
	why     string
}{
	// Loopback / unspecified / link-local.
	{"127.0.0.1", true, "loopback 127.0.0.0/8"},
	{"127.255.255.255", true, "loopback 127.0.0.0/8 upper"},
	{"0.0.0.0", true, "unspecified"},
	{"0.1.2.3", true, "this-network 0.0.0.0/8"},
	{"169.254.169.254", true, "link-local 169.254.0.0/16 (cloud IMDS)"},

	// RFC 1918.
	{"10.0.0.1", true, "RFC1918 10.0.0.0/8"},
	{"172.16.0.1", true, "RFC1918 172.16.0.0/12"},
	{"192.168.1.1", true, "RFC1918 192.168.0.0/16"},

	// 100.64.0.0/10 carrier-grade NAT, plus both boundaries.
	{"100.63.255.255", false, "just below CGNAT 100.64.0.0/10"},
	{"100.64.0.0", true, "CGNAT 100.64.0.0/10 first address"},
	{"100.64.0.1", true, "CGNAT 100.64.0.0/10"},
	{"100.127.255.255", true, "CGNAT 100.64.0.0/10 last address"},
	{"100.128.0.0", false, "just above CGNAT 100.64.0.0/10"},

	// 192.0.0.0/24 IETF protocol assignments and 192.0.2.0/24 TEST-NET-1.
	{"192.0.0.0", true, "IETF protocol assignments 192.0.0.0/24"},
	{"192.0.0.255", true, "IETF protocol assignments 192.0.0.0/24 last"},
	{"192.0.1.1", false, "192.0.1.0/24 is ordinary public space"},
	{"192.0.2.0", true, "TEST-NET-1 192.0.2.0/24 first"},
	{"192.0.2.255", true, "TEST-NET-1 192.0.2.0/24 last"},
	{"192.0.3.1", false, "just above TEST-NET-1"},

	// 198.51.100.0/24 TEST-NET-2.
	{"198.51.99.255", false, "just below TEST-NET-2"},
	{"198.51.100.0", true, "TEST-NET-2 198.51.100.0/24 first"},
	{"198.51.100.255", true, "TEST-NET-2 198.51.100.0/24 last"},
	{"198.51.101.0", false, "just above TEST-NET-2"},

	// 203.0.113.0/24 TEST-NET-3.
	{"203.0.112.255", false, "just below TEST-NET-3"},
	{"203.0.113.0", true, "TEST-NET-3 203.0.113.0/24 first"},
	{"203.0.113.255", true, "TEST-NET-3 203.0.113.0/24 last"},
	{"203.0.114.0", false, "just above TEST-NET-3"},

	// 224.0.0.0/4 multicast and 240.0.0.0/4 reserved, plus boundaries.
	{"223.255.255.255", false, "just below multicast 224.0.0.0/4"},
	{"224.0.0.0", true, "multicast 224.0.0.0/4 first"},
	{"224.0.0.1", true, "multicast 224.0.0.0/4"},
	{"239.255.255.255", true, "multicast 224.0.0.0/4 last"},
	{"240.0.0.0", true, "reserved 240.0.0.0/4 first"},
	{"255.255.255.255", true, "reserved 240.0.0.0/4 (broadcast)"},

	// 198.18.0.0/15 must stay reachable — runtime-e2e sentinel backends live here.
	{"198.17.255.255", false, "just below benchmarking 198.18.0.0/15"},
	{"198.18.0.0", false, "benchmarking 198.18.0.0/15 first — must stay permitted"},
	{"198.19.255.255", false, "benchmarking 198.18.0.0/15 last — must stay permitted"},
	{"198.20.0.0", false, "just above benchmarking 198.18.0.0/15"},

	// Ordinary public IPv4 — the vacuity control for the whole table.
	{"8.8.8.8", false, "public"},
	{"1.1.1.1", false, "public"},
	{"52.94.76.1", false, "public"},

	// IPv6 families the classifier handles today.
	{"::1", true, "IPv6 loopback"},
	{"::", true, "IPv6 unspecified"},
	{"fe80::1", true, "IPv6 link-local unicast fe80::/10"},
	{"ff02::1", true, "IPv6 link-local multicast"},
	{"fc00::1", true, "IPv6 unique-local fc00::/7"},
	{"fd00::1", true, "IPv6 unique-local fd00::/8"},
	{"2001:4860:4860::8888", false, "public IPv6"},
	// IPv4-mapped IPv6 must be classified on its embedded IPv4 address.
	{"::ffff:100.64.0.1", true, "IPv4-mapped CGNAT"},
	{"::ffff:198.18.0.1", false, "IPv4-mapped benchmarking — must stay permitted"},
	// Closed deliberately in #3104: the IPv6 documentation range 2001:db8::/32
	// was rejected by none of the nine pre-#3104 classifiers. It was pinned as
	// permitted by #3101 so that closing it would be a visible edit — this is
	// that edit.
	{"2001:db8::1", true, "IPv6 documentation 2001:db8::/32 — closed in #3104"},
	{"2001:db9::1", false, "immediately above 2001:db8::/32 — still public"},

	// Also closed in #3104: four IPv6 encodings that carry an IPv4 address.
	// Every pre-#3104 classifier called these public even though they encode
	// 127.0.0.1. Classification happens on the address actually reached, so a
	// wrapped public address stays permitted.
	{"64:ff9b::7f00:1", true, "NAT64 well-known prefix wrapping 127.0.0.1"},
	{"64:ff9b::808:808", false, "NAT64 wrapping 8.8.8.8 — still public"},
	{"2002:7f00:1::", true, "6to4 wrapping 127.0.0.1"},
	{"2002:808:808::", false, "6to4 wrapping 8.8.8.8 — still public"},
	{"::7f00:1", true, "deprecated IPv4-compatible wrapping 127.0.0.1"},
	{"::ffff:0:7f00:1", true, "deprecated IPv4-translated (RFC 2765) wrapping 127.0.0.1"},
	{"::ffff:0:808:808", false, "IPv4-translated wrapping 8.8.8.8 — still public"},
}

// TestHTTPConnector_ValidateHost_ReservedRanges drives the real egress guard
// (validateHost) rather than a helper, so it fails if the connector ever stops
// consulting the canonical classifier. IP literals are resolved by the Go
// resolver without any network I/O, so this test is hermetic.
func TestHTTPConnector_ValidateHost_ReservedRanges(t *testing.T) {
	c := NewHTTPConnector()

	const minAssertions = 45
	if len(reservedRangeCases) < minAssertions {
		t.Fatalf("reservedRangeCases has %d entries, expected at least %d — the table was gutted",
			len(reservedRangeCases), minAssertions)
	}

	asserted := 0
	blockedSeen, allowedSeen := 0, 0
	for _, tt := range reservedRangeCases {
		t.Run(tt.ip, func(t *testing.T) {
			err := c.validateHost(tt.ip)
			if tt.blocked && err == nil {
				t.Errorf("validateHost(%s) = nil, want error (%s)", tt.ip, tt.why)
			}
			if !tt.blocked && err != nil {
				t.Errorf("validateHost(%s) = %v, want nil (%s)", tt.ip, err, tt.why)
			}
		})
		asserted++
		if tt.blocked {
			blockedSeen++
		} else {
			allowedSeen++
		}
	}

	if asserted != len(reservedRangeCases) {
		t.Fatalf("asserted %d cases, table has %d", asserted, len(reservedRangeCases))
	}
	if blockedSeen == 0 || allowedSeen == 0 {
		t.Fatalf("vacuity control failed: blocked=%d allowed=%d — the table must exercise both outcomes",
			blockedSeen, allowedSeen)
	}
}

// TestHTTPConnector_ClassifierIsCanonical asserts the HTTP connector's egress
// guard and the canonical base classifier agree on every case in the shared
// table. If someone reintroduces a connector-local copy of the predicate, this
// fails the moment the two disagree.
func TestHTTPConnector_ClassifierIsCanonical(t *testing.T) {
	c := NewHTTPConnector()

	for _, tt := range reservedRangeCases {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP: %s", tt.ip)
			}
			canonical := base.IsPrivateIP(ip)
			viaConnector := c.validateHost(tt.ip) != nil
			if canonical != viaConnector {
				t.Errorf("classifier divergence for %s (%s): base.IsPrivateIP=%v, connector blocks=%v",
					tt.ip, tt.why, canonical, viaConnector)
			}
		})
	}
}

// TestHTTPConnector_AllowPrivateIPsEscapeHatchUnchanged pins the semantics of
// the documented allow_private_ips option: when set, the SSRF guard is skipped
// entirely; when unset, it runs. This change must not alter that.
func TestHTTPConnector_AllowPrivateIPsEscapeHatchUnchanged(t *testing.T) {
	ctx := context.Background()

	c := NewHTTPConnector()
	err := c.Connect(ctx, &base.ConnectorConfig{
		Name: "escape-hatch-on",
		Options: map[string]interface{}{
			"base_url":          "http://100.64.0.1:8080",
			"allow_private_ips": true,
		},
	})
	if err != nil {
		t.Fatalf("allow_private_ips=true should permit a CGNAT base_url, got: %v", err)
	}
	if !c.allowPrivateIPs {
		t.Error("allowPrivateIPs should be true after opting in")
	}

	c2 := NewHTTPConnector()
	err = c2.Connect(ctx, &base.ConnectorConfig{
		Name: "escape-hatch-off",
		Options: map[string]interface{}{
			"base_url": "http://100.64.0.1:8080",
		},
	})
	if err == nil {
		t.Fatal("allow_private_ips unset should reject a CGNAT base_url, got nil error")
	}
	if !strings.Contains(err.Error(), "SSRF") {
		t.Errorf("expected an SSRF protection error, got: %v", err)
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

// TestHTTPConnector_TransportDialerIsEgressGuarded pins the fix for the gap
// R3 round 2 found: validateHost runs ONCE inside Connect, and the transport
// dialer used to be a bare net.Dialer, so every request after Connect
// re-resolved base_url's host with nothing checking the answer. A host that
// resolved public at Connect and into a reserved range afterwards was dialled.
//
// It drives the REAL transport the connector built, so it fails if the wiring
// is removed. No socket is opened: the guard refuses before any dial.
func TestHTTPConnector_TransportDialerIsEgressGuarded(t *testing.T) {
	dialerOf := func(t *testing.T, allowPrivate bool) func(context.Context, string, string) (net.Conn, error) {
		t.Helper()
		c := NewHTTPConnector()
		opts := map[string]interface{}{"base_url": "http://198.18.67.10:18967"}
		if allowPrivate {
			opts["allow_private_ips"] = true
		}
		if err := c.Connect(context.Background(), &base.ConnectorConfig{Name: "dialer-probe", Options: opts}); err != nil {
			t.Fatalf("Connect failed: %v", err)
		}
		tr, ok := c.httpClient.Transport.(*http.Transport)
		if !ok {
			t.Fatal("transport is not *http.Transport")
		}
		if tr.DialContext == nil {
			t.Fatal("transport has no DialContext; it would use the default bare dialer")
		}
		return tr.DialContext
	}

	t.Run("guarded by default", func(t *testing.T) {
		dial := dialerOf(t, false)
		for _, addr := range []string{
			"169.254.169.254:80", // cloud instance metadata
			"127.0.0.1:80",       // loopback
			"10.0.0.1:80",        // RFC1918
			"100.64.0.1:80",      // CGNAT
			"0.0.0.0:80",         // dial-routed to loopback
		} {
			_, err := dial(context.Background(), "tcp", addr)
			if err == nil {
				t.Errorf("transport dialled %s; post-Connect dials must be egress-guarded", addr)
				continue
			}
			if !strings.Contains(err.Error(), "SSRF protection") {
				t.Errorf("dial(%s) failed with %v, want an SSRF refusal", addr, err)
			}
		}
	})

	t.Run("benchmarking range stays dialable for runtime-e2e/3067", func(t *testing.T) {
		dial := dialerOf(t, false)
		// Cancelled context: proves the guard let it through without opening a
		// socket to the sentinel range from a unit test.
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := dial(ctx, "tcp", "198.18.67.10:18967")
		if err != nil && strings.Contains(err.Error(), "SSRF protection") {
			t.Errorf("transport refused the runtime-e2e/3067 sentinel address: %v", err)
		}
	})

	t.Run("allow_private_ips bypasses the dialer guard too", func(t *testing.T) {
		dial := dialerOf(t, true)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := dial(ctx, "tcp", "169.254.169.254:80")
		if err != nil && strings.Contains(err.Error(), "SSRF protection") {
			t.Errorf("allow_private_ips=true but the dialer still refused on SSRF grounds: %v", err)
		}
	})
}
