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
	"encoding/base64"
	"net/http"
)

// AuthProvider provides authentication for HTTP requests.
type AuthProvider interface {
	// Apply adds authentication to an HTTP request.
	Apply(req *http.Request) error
}

// APIKeyLocation specifies where to place the API key.
type APIKeyLocation int

const (
	// APIKeyHeader places the API key in a header.
	APIKeyHeader APIKeyLocation = iota
	// APIKeyQuery places the API key in a query parameter.
	APIKeyQuery
)

// APIKeyAuth provides API key authentication.
type APIKeyAuth struct {
	key      string
	name     string
	location APIKeyLocation
}

// NewAPIKeyAuth creates a new API key authenticator.
// By default, the key is placed in the Authorization header as "Bearer <key>".
func NewAPIKeyAuth(key string) *APIKeyAuth {
	return &APIKeyAuth{
		key:      key,
		name:     "Authorization",
		location: APIKeyHeader,
	}
}

// NewAPIKeyAuthWithHeader creates an API key auth with a custom header name.
func NewAPIKeyAuthWithHeader(key, headerName string) *APIKeyAuth {
	return &APIKeyAuth{
		key:      key,
		name:     headerName,
		location: APIKeyHeader,
	}
}

// NewAPIKeyAuthWithQuery creates an API key auth as a query parameter.
func NewAPIKeyAuthWithQuery(key, paramName string) *APIKeyAuth {
	return &APIKeyAuth{
		key:      key,
		name:     paramName,
		location: APIKeyQuery,
	}
}

// Apply adds the API key to the request.
func (a *APIKeyAuth) Apply(req *http.Request) error {
	switch a.location {
	case APIKeyHeader:
		if a.name == "Authorization" {
			req.Header.Set(a.name, "Bearer "+a.key)
		} else {
			req.Header.Set(a.name, a.key)
		}
	case APIKeyQuery:
		q := req.URL.Query()
		q.Set(a.name, a.key)
		req.URL.RawQuery = q.Encode()
	}
	return nil
}

// BearerTokenAuth provides bearer token authentication.
type BearerTokenAuth struct {
	token string
}

// NewBearerTokenAuth creates a bearer token authenticator.
func NewBearerTokenAuth(token string) *BearerTokenAuth {
	return &BearerTokenAuth{token: token}
}

// Apply adds the bearer token to the request.
func (a *BearerTokenAuth) Apply(req *http.Request) error {
	req.Header.Set("Authorization", "Bearer "+a.token)
	return nil
}

// BasicAuth provides HTTP basic authentication.
type BasicAuth struct {
	username string
	password string
}

// NewBasicAuth creates a basic auth authenticator.
func NewBasicAuth(username, password string) *BasicAuth {
	return &BasicAuth{
		username: username,
		password: password,
	}
}

// Apply adds basic auth to the request.
func (a *BasicAuth) Apply(req *http.Request) error {
	auth := base64.StdEncoding.EncodeToString([]byte(a.username + ":" + a.password))
	req.Header.Set("Authorization", "Basic "+auth)
	return nil
}

// NoAuth is a no-op authentication provider for unauthenticated requests.
type NoAuth struct{}

// NewNoAuth creates a no-op authenticator.
func NewNoAuth() *NoAuth {
	return &NoAuth{}
}

// Apply does nothing.
func (a *NoAuth) Apply(req *http.Request) error {
	return nil
}

// ChainedAuth tries multiple auth providers in order.
type ChainedAuth struct {
	providers []AuthProvider
}

// NewChainedAuth creates a chained authenticator.
func NewChainedAuth(providers ...AuthProvider) *ChainedAuth {
	return &ChainedAuth{providers: providers}
}

// Apply applies all auth providers in order.
func (a *ChainedAuth) Apply(req *http.Request) error {
	for _, p := range a.providers {
		if err := p.Apply(req); err != nil {
			return err
		}
	}
	return nil
}

// Ensure implementations satisfy the interface.
var (
	_ AuthProvider = (*APIKeyAuth)(nil)
	_ AuthProvider = (*BearerTokenAuth)(nil)
	_ AuthProvider = (*BasicAuth)(nil)
	_ AuthProvider = (*NoAuth)(nil)
	_ AuthProvider = (*ChainedAuth)(nil)
)
