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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAPIKeyAuth(t *testing.T) {
	t.Run("header authentication", func(t *testing.T) {
		auth := NewAPIKeyAuth("test-api-key", APIKeyInHeader, "X-API-Key")

		req := httptest.NewRequest("GET", "http://example.com", nil)
		err := auth.Authenticate(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got := req.Header.Get("X-API-Key"); got != "test-api-key" {
			t.Errorf("expected header X-API-Key=test-api-key, got %s", got)
		}
	})

	t.Run("query parameter authentication", func(t *testing.T) {
		auth := NewAPIKeyAuth("test-api-key", APIKeyInQuery, "api_key")

		req := httptest.NewRequest("GET", "http://example.com?existing=param", nil)
		err := auth.Authenticate(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got := req.URL.Query().Get("api_key"); got != "test-api-key" {
			t.Errorf("expected query param api_key=test-api-key, got %s", got)
		}

		// Verify existing params are preserved
		if got := req.URL.Query().Get("existing"); got != "param" {
			t.Errorf("expected existing param to be preserved, got %s", got)
		}
	})

	t.Run("default key name", func(t *testing.T) {
		auth := NewAPIKeyAuth("test-api-key", APIKeyInHeader, "")

		req := httptest.NewRequest("GET", "http://example.com", nil)
		err := auth.Authenticate(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got := req.Header.Get("X-API-Key"); got != "test-api-key" {
			t.Errorf("expected default header name, got %s", got)
		}
	})

	t.Run("empty API key error", func(t *testing.T) {
		auth := NewAPIKeyAuth("", APIKeyInHeader, "X-API-Key")

		req := httptest.NewRequest("GET", "http://example.com", nil)
		err := auth.Authenticate(context.Background(), req)
		if err == nil {
			t.Error("expected error for empty API key")
		}
	})

	t.Run("type and expiration", func(t *testing.T) {
		auth := NewAPIKeyAuth("test-api-key", APIKeyInHeader, "X-API-Key")

		if auth.Type() != "api_key" {
			t.Errorf("expected type api_key, got %s", auth.Type())
		}

		if auth.IsExpired() {
			t.Error("API key should never expire")
		}

		if err := auth.Refresh(context.Background()); err != nil {
			t.Errorf("refresh should be no-op: %v", err)
		}
	})

	t.Run("set API key", func(t *testing.T) {
		auth := NewAPIKeyAuth("old-key", APIKeyInHeader, "X-API-Key")
		auth.SetAPIKey("new-key")

		req := httptest.NewRequest("GET", "http://example.com", nil)
		err := auth.Authenticate(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got := req.Header.Get("X-API-Key"); got != "new-key" {
			t.Errorf("expected new-key, got %s", got)
		}
	})

	t.Run("body injection", func(t *testing.T) {
		auth := NewAPIKeyAuth("test-key", APIKeyInBody, "api_key")

		req := httptest.NewRequest("POST", "http://example.com", nil)
		err := auth.Authenticate(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got := req.Header.Get("X-API-Key-Body-Injection"); got == "" {
			t.Error("expected body injection header to be set")
		}
	})
}

func TestBasicAuth(t *testing.T) {
	t.Run("basic authentication", func(t *testing.T) {
		auth := NewBasicAuth("username", "password")

		req := httptest.NewRequest("GET", "http://example.com", nil)
		err := auth.Authenticate(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		user, pass, ok := req.BasicAuth()
		if !ok {
			t.Fatal("expected basic auth to be set")
		}
		if user != "username" || pass != "password" {
			t.Errorf("expected username:password, got %s:%s", user, pass)
		}
	})

	t.Run("empty username error", func(t *testing.T) {
		auth := NewBasicAuth("", "password")

		req := httptest.NewRequest("GET", "http://example.com", nil)
		err := auth.Authenticate(context.Background(), req)
		if err == nil {
			t.Error("expected error for empty username")
		}
	})

	t.Run("type and expiration", func(t *testing.T) {
		auth := NewBasicAuth("user", "pass")

		if auth.Type() != "basic" {
			t.Errorf("expected type basic, got %s", auth.Type())
		}

		if auth.IsExpired() {
			t.Error("basic auth should never expire")
		}
	})
}

func TestBearerTokenAuth(t *testing.T) {
	t.Run("bearer token authentication", func(t *testing.T) {
		auth := NewBearerTokenAuth("my-token", time.Now().Add(time.Hour))

		req := httptest.NewRequest("GET", "http://example.com", nil)
		err := auth.Authenticate(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got := req.Header.Get("Authorization"); got != "Bearer my-token" {
			t.Errorf("expected Bearer my-token, got %s", got)
		}
	})

	t.Run("empty token error", func(t *testing.T) {
		auth := NewBearerTokenAuth("", time.Time{})

		req := httptest.NewRequest("GET", "http://example.com", nil)
		err := auth.Authenticate(context.Background(), req)
		if err == nil {
			t.Error("expected error for empty token")
		}
	})

	t.Run("token expiration", func(t *testing.T) {
		// Expired token
		auth := NewBearerTokenAuth("token", time.Now().Add(-time.Hour))
		if !auth.IsExpired() {
			t.Error("expected token to be expired")
		}

		// Valid token
		auth = NewBearerTokenAuth("token", time.Now().Add(time.Hour))
		if auth.IsExpired() {
			t.Error("expected token to not be expired")
		}

		// No expiration
		auth = NewBearerTokenAuth("token", time.Time{})
		if auth.IsExpired() {
			t.Error("expected token without expiration to not be expired")
		}
	})

	t.Run("set token", func(t *testing.T) {
		auth := NewBearerTokenAuth("old-token", time.Now().Add(-time.Hour))
		auth.SetToken("new-token", time.Now().Add(time.Hour))

		if auth.GetToken() != "new-token" {
			t.Errorf("expected new-token, got %s", auth.GetToken())
		}

		if auth.IsExpired() {
			t.Error("new token should not be expired")
		}
	})

	t.Run("type", func(t *testing.T) {
		auth := NewBearerTokenAuth("token", time.Time{})
		if auth.Type() != "bearer" {
			t.Errorf("expected type bearer, got %s", auth.Type())
		}
	})
}

func TestOAuthAuth(t *testing.T) {
	t.Run("oauth configuration", func(t *testing.T) {
		config := &OAuthConfig{
			ClientID:     "client-id",
			ClientSecret: "client-secret",
			TokenURL:     "http://example.com/token",
			Scopes:       []string{"read", "write"},
		}

		auth := NewOAuthAuth(config)

		if auth.Type() != "oauth2" {
			t.Errorf("expected type oauth2, got %s", auth.Type())
		}
	})

	t.Run("set token manually", func(t *testing.T) {
		config := &OAuthConfig{
			ClientID:     "client-id",
			ClientSecret: "client-secret",
			TokenURL:     "http://example.com/token",
		}

		auth := NewOAuthAuth(config)
		auth.SetToken("manual-token", time.Now().Add(time.Hour))

		req := httptest.NewRequest("GET", "http://example.com", nil)
		err := auth.Authenticate(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got := req.Header.Get("Authorization"); got != "Bearer manual-token" {
			t.Errorf("expected Bearer manual-token, got %s", got)
		}
	})

	t.Run("token expiration check", func(t *testing.T) {
		config := &OAuthConfig{}
		auth := NewOAuthAuth(config)

		// No token set
		if !auth.IsExpired() {
			t.Error("expected expired when no token set")
		}

		// Valid token
		auth.SetToken("token", time.Now().Add(time.Hour))
		if auth.IsExpired() {
			t.Error("expected not expired with valid token")
		}

		// Expired token
		auth.SetToken("token", time.Now().Add(-time.Hour))
		if !auth.IsExpired() {
			t.Error("expected expired with old token")
		}
	})

	t.Run("oauth token refresh", func(t *testing.T) {
		// Create a test server that returns tokens
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" {
				t.Errorf("expected POST, got %s", r.Method)
			}

			contentType := r.Header.Get("Content-Type")
			if contentType != "application/x-www-form-urlencoded" {
				t.Errorf("expected form content type, got %s", contentType)
			}

			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"access_token":"new-token","expires_in":3600,"token_type":"bearer"}`))
		}))
		defer server.Close()

		config := &OAuthConfig{
			ClientID:     "client-id",
			ClientSecret: "client-secret",
			TokenURL:     server.URL,
			Scopes:       []string{"read"},
		}

		auth := NewOAuthAuth(config)
		err := auth.Refresh(context.Background())
		if err != nil {
			t.Fatalf("refresh failed: %v", err)
		}

		// Verify the token was set
		req := httptest.NewRequest("GET", "http://example.com", nil)
		err = auth.Authenticate(context.Background(), req)
		if err != nil {
			t.Fatalf("authenticate failed: %v", err)
		}

		if got := req.Header.Get("Authorization"); got != "Bearer new-token" {
			t.Errorf("expected Bearer new-token, got %s", got)
		}
	})
}

func TestIAMAuth(t *testing.T) {
	t.Run("iam authentication", func(t *testing.T) {
		creds := &IAMCredentials{
			AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
			SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			Region:          "us-east-1",
			Service:         "s3",
		}

		auth := NewIAMAuth(creds)

		req := httptest.NewRequest("GET", "http://s3.us-east-1.amazonaws.com/bucket/key", nil)
		req.Host = "s3.us-east-1.amazonaws.com"

		err := auth.Authenticate(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Check that required headers are set
		if req.Header.Get("Authorization") == "" {
			t.Error("expected Authorization header to be set")
		}
		if req.Header.Get("X-Amz-Date") == "" {
			t.Error("expected X-Amz-Date header to be set")
		}
	})

	t.Run("iam with session token", func(t *testing.T) {
		creds := &IAMCredentials{
			AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
			SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			SessionToken:    "session-token",
			Region:          "us-east-1",
			Service:         "s3",
		}

		auth := NewIAMAuth(creds)

		req := httptest.NewRequest("GET", "http://s3.us-east-1.amazonaws.com/bucket/key", nil)
		req.Host = "s3.us-east-1.amazonaws.com"

		err := auth.Authenticate(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if req.Header.Get("X-Amz-Security-Token") != "session-token" {
			t.Error("expected X-Amz-Security-Token header to be set")
		}
	})

	t.Run("missing credentials error", func(t *testing.T) {
		creds := &IAMCredentials{}
		auth := NewIAMAuth(creds)

		req := httptest.NewRequest("GET", "http://example.com", nil)
		err := auth.Authenticate(context.Background(), req)
		if err == nil {
			t.Error("expected error for missing credentials")
		}
	})

	t.Run("type and expiration", func(t *testing.T) {
		creds := &IAMCredentials{}
		auth := NewIAMAuth(creds)

		if auth.Type() != "iam" {
			t.Errorf("expected type iam, got %s", auth.Type())
		}

		if auth.IsExpired() {
			t.Error("IAM credentials should not report expired by default")
		}
	})

	t.Run("set credentials", func(t *testing.T) {
		creds := &IAMCredentials{}
		auth := NewIAMAuth(creds)

		newCreds := &IAMCredentials{
			AccessKeyID:     "NEW_ACCESS_KEY",
			SecretAccessKey: "new_secret_key",
			Region:          "eu-west-1",
			Service:         "dynamodb",
		}
		auth.SetCredentials(newCreds)

		req := httptest.NewRequest("GET", "http://example.com", nil)
		req.Host = "dynamodb.eu-west-1.amazonaws.com"

		err := auth.Authenticate(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestChainedAuth(t *testing.T) {
	t.Run("chain multiple providers", func(t *testing.T) {
		apiKey := NewAPIKeyAuth("api-key", APIKeyInHeader, "X-API-Key")
		bearer := NewBearerTokenAuth("bearer-token", time.Now().Add(time.Hour))

		chain := NewChainedAuth(apiKey, bearer)

		req := httptest.NewRequest("GET", "http://example.com", nil)
		err := chain.Authenticate(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Both should be applied
		if req.Header.Get("X-API-Key") != "api-key" {
			t.Error("expected API key header")
		}
		if req.Header.Get("Authorization") != "Bearer bearer-token" {
			t.Error("expected Bearer token header")
		}
	})

	t.Run("chain with failure", func(t *testing.T) {
		apiKey := NewAPIKeyAuth("", APIKeyInHeader, "X-API-Key") // Will fail
		bearer := NewBearerTokenAuth("token", time.Now().Add(time.Hour))

		chain := NewChainedAuth(apiKey, bearer)

		req := httptest.NewRequest("GET", "http://example.com", nil)
		err := chain.Authenticate(context.Background(), req)
		if err == nil {
			t.Error("expected error from failing provider")
		}
	})

	t.Run("chain expiration check", func(t *testing.T) {
		apiKey := NewAPIKeyAuth("key", APIKeyInHeader, "X-API-Key")
		bearer := NewBearerTokenAuth("token", time.Now().Add(-time.Hour)) // Expired

		chain := NewChainedAuth(apiKey, bearer)

		if !chain.IsExpired() {
			t.Error("expected chain to report expired when one provider is expired")
		}
	})

	t.Run("chain type", func(t *testing.T) {
		chain := NewChainedAuth()
		if chain.Type() != "chained" {
			t.Errorf("expected type chained, got %s", chain.Type())
		}
	})
}
