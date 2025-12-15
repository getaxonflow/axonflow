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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// AuthProvider defines the interface for authentication mechanisms
type AuthProvider interface {
	// Authenticate applies authentication to the given request
	Authenticate(ctx context.Context, req *http.Request) error

	// IsExpired checks if the current credentials have expired
	IsExpired() bool

	// Refresh refreshes the credentials if possible
	Refresh(ctx context.Context) error

	// Type returns the authentication type name
	Type() string
}

// APIKeyLocation specifies where the API key should be placed
type APIKeyLocation int

const (
	// APIKeyInHeader places the API key in a header
	APIKeyInHeader APIKeyLocation = iota
	// APIKeyInQuery places the API key in query parameters
	APIKeyInQuery
	// APIKeyInBody places the API key in the request body (for POST requests)
	APIKeyInBody
)

// APIKeyAuth provides API key authentication
type APIKeyAuth struct {
	apiKey   string
	location APIKeyLocation
	keyName  string
	mu       sync.RWMutex
}

// NewAPIKeyAuth creates a new API key authentication provider
func NewAPIKeyAuth(apiKey string, location APIKeyLocation, keyName string) *APIKeyAuth {
	if keyName == "" {
		keyName = "X-API-Key"
	}
	return &APIKeyAuth{
		apiKey:   apiKey,
		location: location,
		keyName:  keyName,
	}
}

// Authenticate applies the API key to the request
func (a *APIKeyAuth) Authenticate(ctx context.Context, req *http.Request) error {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.apiKey == "" {
		return fmt.Errorf("API key is not set")
	}

	switch a.location {
	case APIKeyInHeader:
		req.Header.Set(a.keyName, a.apiKey)
	case APIKeyInQuery:
		q := req.URL.Query()
		q.Set(a.keyName, a.apiKey)
		req.URL.RawQuery = q.Encode()
	case APIKeyInBody:
		// For body injection, the caller should handle this based on content type
		// We set a header that the HTTP client can interpret
		req.Header.Set("X-API-Key-Body-Injection", a.keyName+"="+a.apiKey)
	default:
		req.Header.Set(a.keyName, a.apiKey)
	}

	return nil
}

// IsExpired returns false for API keys as they don't expire automatically
func (a *APIKeyAuth) IsExpired() bool {
	return false
}

// Refresh is a no-op for API keys
func (a *APIKeyAuth) Refresh(ctx context.Context) error {
	return nil
}

// Type returns the authentication type
func (a *APIKeyAuth) Type() string {
	return "api_key"
}

// SetAPIKey updates the API key
func (a *APIKeyAuth) SetAPIKey(apiKey string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.apiKey = apiKey
}

// BasicAuth provides HTTP Basic authentication
type BasicAuth struct {
	username string
	password string
	mu       sync.RWMutex
}

// NewBasicAuth creates a new Basic authentication provider
func NewBasicAuth(username, password string) *BasicAuth {
	return &BasicAuth{
		username: username,
		password: password,
	}
}

// Authenticate applies Basic auth to the request
func (b *BasicAuth) Authenticate(ctx context.Context, req *http.Request) error {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.username == "" {
		return fmt.Errorf("username is not set")
	}

	req.SetBasicAuth(b.username, b.password)
	return nil
}

// IsExpired returns false for Basic auth
func (b *BasicAuth) IsExpired() bool {
	return false
}

// Refresh is a no-op for Basic auth
func (b *BasicAuth) Refresh(ctx context.Context) error {
	return nil
}

// Type returns the authentication type
func (b *BasicAuth) Type() string {
	return "basic"
}

// BearerTokenAuth provides Bearer token authentication
type BearerTokenAuth struct {
	token     string
	expiresAt time.Time
	mu        sync.RWMutex
}

// NewBearerTokenAuth creates a new Bearer token authentication provider
func NewBearerTokenAuth(token string, expiresAt time.Time) *BearerTokenAuth {
	return &BearerTokenAuth{
		token:     token,
		expiresAt: expiresAt,
	}
}

// Authenticate applies the Bearer token to the request
func (b *BearerTokenAuth) Authenticate(ctx context.Context, req *http.Request) error {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.token == "" {
		return fmt.Errorf("bearer token is not set")
	}

	req.Header.Set("Authorization", "Bearer "+b.token)
	return nil
}

// IsExpired checks if the token has expired
func (b *BearerTokenAuth) IsExpired() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.expiresAt.IsZero() {
		return false
	}
	return time.Now().After(b.expiresAt)
}

// Refresh is a no-op for static Bearer tokens
func (b *BearerTokenAuth) Refresh(ctx context.Context) error {
	return nil
}

// Type returns the authentication type
func (b *BearerTokenAuth) Type() string {
	return "bearer"
}

// SetToken updates the bearer token
func (b *BearerTokenAuth) SetToken(token string, expiresAt time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.token = token
	b.expiresAt = expiresAt
}

// GetToken returns the current token
func (b *BearerTokenAuth) GetToken() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.token
}

// OAuthConfig holds OAuth 2.0 configuration
type OAuthConfig struct {
	ClientID     string
	ClientSecret string
	TokenURL     string
	Scopes       []string
	RedirectURL  string
	AuthURL      string
}

// OAuthAuth provides OAuth 2.0 client credentials authentication
type OAuthAuth struct {
	config      *OAuthConfig
	accessToken string
	expiresAt   time.Time
	httpClient  *http.Client
	mu          sync.RWMutex
}

// NewOAuthAuth creates a new OAuth 2.0 authentication provider
func NewOAuthAuth(config *OAuthConfig) *OAuthAuth {
	return &OAuthAuth{
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Authenticate applies the OAuth token to the request
func (o *OAuthAuth) Authenticate(ctx context.Context, req *http.Request) error {
	o.mu.RLock()
	token := o.accessToken
	expired := o.isExpiredUnlocked()
	o.mu.RUnlock()

	if token == "" || expired {
		if err := o.Refresh(ctx); err != nil {
			return fmt.Errorf("failed to refresh OAuth token: %w", err)
		}
		o.mu.RLock()
		token = o.accessToken
		o.mu.RUnlock()
	}

	req.Header.Set("Authorization", "Bearer "+token)
	return nil
}

// IsExpired checks if the token has expired
func (o *OAuthAuth) IsExpired() bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.isExpiredUnlocked()
}

// isExpiredUnlocked checks expiration without acquiring lock (caller must hold lock)
func (o *OAuthAuth) isExpiredUnlocked() bool {
	if o.expiresAt.IsZero() {
		return o.accessToken == ""
	}
	// Consider token expired 30 seconds before actual expiry for safety
	return time.Now().Add(30 * time.Second).After(o.expiresAt)
}

// Refresh obtains a new access token using client credentials
func (o *OAuthAuth) Refresh(ctx context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", o.config.ClientID)
	data.Set("client_secret", o.config.ClientSecret)
	if len(o.config.Scopes) > 0 {
		data.Set("scope", strings.Join(o.config.Scopes, " "))
	}

	req, err := http.NewRequestWithContext(ctx, "POST", o.config.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("token request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("token request returned status %d", resp.StatusCode)
	}

	// Parse OAuth token response
	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}

	if err := parseOAuthResponse(resp, &tokenResp); err != nil {
		return fmt.Errorf("failed to parse token response: %w", err)
	}

	o.accessToken = tokenResp.AccessToken
	if tokenResp.ExpiresIn > 0 {
		o.expiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	}

	return nil
}

// Type returns the authentication type
func (o *OAuthAuth) Type() string {
	return "oauth2"
}

// SetToken manually sets the access token (useful for testing or external token management)
func (o *OAuthAuth) SetToken(token string, expiresAt time.Time) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.accessToken = token
	o.expiresAt = expiresAt
}

// parseOAuthResponse parses the OAuth token response
func parseOAuthResponse(resp *http.Response, result interface{}) error {
	decoder := json.NewDecoder(resp.Body)
	return decoder.Decode(result)
}

// IAMCredentials holds AWS IAM credentials
type IAMCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Region          string
	Service         string
}

// IAMAuth provides AWS Signature Version 4 authentication
type IAMAuth struct {
	credentials *IAMCredentials
	mu          sync.RWMutex
}

// NewIAMAuth creates a new IAM authentication provider
func NewIAMAuth(credentials *IAMCredentials) *IAMAuth {
	return &IAMAuth{
		credentials: credentials,
	}
}

// Authenticate applies AWS Signature V4 to the request
func (i *IAMAuth) Authenticate(ctx context.Context, req *http.Request) error {
	i.mu.RLock()
	defer i.mu.RUnlock()

	if i.credentials.AccessKeyID == "" || i.credentials.SecretAccessKey == "" {
		return fmt.Errorf("AWS credentials are not set")
	}

	// Sign the request using AWS Signature Version 4
	return i.signRequest(req)
}

// signRequest implements AWS Signature Version 4 signing
func (i *IAMAuth) signRequest(req *http.Request) error {
	now := time.Now().UTC()
	datestamp := now.Format("20060102")
	amzdate := now.Format("20060102T150405Z")

	// Set required headers
	req.Header.Set("X-Amz-Date", amzdate)
	if i.credentials.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", i.credentials.SessionToken)
	}

	// Create canonical request
	canonicalURI := req.URL.Path
	if canonicalURI == "" {
		canonicalURI = "/"
	}

	canonicalQueryString := req.URL.Query().Encode()

	// Get signed headers
	signedHeaders, canonicalHeaders := i.getCanonicalHeaders(req)

	// Create payload hash
	payloadHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" // Empty payload hash

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI,
		canonicalQueryString,
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	// Create string to sign
	algorithm := "AWS4-HMAC-SHA256"
	credentialScope := strings.Join([]string{datestamp, i.credentials.Region, i.credentials.Service, "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		algorithm,
		amzdate,
		credentialScope,
		sha256Hash(canonicalRequest),
	}, "\n")

	// Calculate signature
	signingKey := i.getSignatureKey(datestamp)
	signature := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))

	// Build authorization header
	authHeader := fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		algorithm,
		i.credentials.AccessKeyID,
		credentialScope,
		signedHeaders,
		signature,
	)

	req.Header.Set("Authorization", authHeader)

	return nil
}

// getCanonicalHeaders returns signed headers string and canonical headers
func (i *IAMAuth) getCanonicalHeaders(req *http.Request) (string, string) {
	headers := make(map[string]string)
	signedHeadersList := []string{}

	// Always include host
	headers["host"] = req.Host
	signedHeadersList = append(signedHeadersList, "host")

	// Include x-amz-* headers
	for key, values := range req.Header {
		lowerKey := strings.ToLower(key)
		if strings.HasPrefix(lowerKey, "x-amz-") {
			headers[lowerKey] = strings.TrimSpace(values[0])
			signedHeadersList = append(signedHeadersList, lowerKey)
		}
	}

	// Sort headers
	sort.Strings(signedHeadersList)

	// Build canonical headers string
	var canonicalHeaders strings.Builder
	for _, key := range signedHeadersList {
		canonicalHeaders.WriteString(key)
		canonicalHeaders.WriteString(":")
		canonicalHeaders.WriteString(headers[key])
		canonicalHeaders.WriteString("\n")
	}

	return strings.Join(signedHeadersList, ";"), canonicalHeaders.String()
}

// getSignatureKey derives the signing key
func (i *IAMAuth) getSignatureKey(datestamp string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+i.credentials.SecretAccessKey), datestamp)
	kRegion := hmacSHA256(kDate, i.credentials.Region)
	kService := hmacSHA256(kRegion, i.credentials.Service)
	kSigning := hmacSHA256(kService, "aws4_request")
	return kSigning
}

// IsExpired returns false for static IAM credentials
func (i *IAMAuth) IsExpired() bool {
	return false
}

// Refresh is a no-op for static IAM credentials
func (i *IAMAuth) Refresh(ctx context.Context) error {
	return nil
}

// Type returns the authentication type
func (i *IAMAuth) Type() string {
	return "iam"
}

// SetCredentials updates the IAM credentials
func (i *IAMAuth) SetCredentials(credentials *IAMCredentials) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.credentials = credentials
}

// hmacSHA256 computes HMAC-SHA256
func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

// sha256Hash computes SHA256 hash and returns hex string
func sha256Hash(data string) string {
	h := sha256.New()
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// ChainedAuth chains multiple auth providers
type ChainedAuth struct {
	providers []AuthProvider
}

// NewChainedAuth creates a chained authentication provider
func NewChainedAuth(providers ...AuthProvider) *ChainedAuth {
	return &ChainedAuth{providers: providers}
}

// Authenticate applies all auth providers in order
func (c *ChainedAuth) Authenticate(ctx context.Context, req *http.Request) error {
	for _, provider := range c.providers {
		if err := provider.Authenticate(ctx, req); err != nil {
			return fmt.Errorf("auth provider %s failed: %w", provider.Type(), err)
		}
	}
	return nil
}

// IsExpired returns true if any provider has expired
func (c *ChainedAuth) IsExpired() bool {
	for _, provider := range c.providers {
		if provider.IsExpired() {
			return true
		}
	}
	return false
}

// Refresh refreshes all providers that support it
func (c *ChainedAuth) Refresh(ctx context.Context) error {
	for _, provider := range c.providers {
		if err := provider.Refresh(ctx); err != nil {
			return fmt.Errorf("refresh failed for %s: %w", provider.Type(), err)
		}
	}
	return nil
}

// Type returns the authentication type
func (c *ChainedAuth) Type() string {
	return "chained"
}
