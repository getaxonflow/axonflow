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

// Package sdk provides the AxonFlow Connector SDK for building custom MCP connectors.
//
// The SDK provides base implementations, utilities, and testing tools to help developers
// create production-quality connectors that integrate with the AxonFlow platform.
//
// # Quick Start
//
// To create a custom connector, embed BaseConnector and implement the required interface methods:
//
//	type MyConnector struct {
//	    sdk.BaseConnector
//	    client *myapi.Client
//	}
//
//	func (c *MyConnector) Connect(ctx context.Context, config *base.ConnectorConfig) error {
//	    if err := c.BaseConnector.Connect(ctx, config); err != nil {
//	        return err
//	    }
//	    // Custom connection logic
//	    return nil
//	}
//
// # Features
//
// The SDK provides:
//   - BaseConnector: Embeddable base implementation with common functionality
//   - Authentication: API key, OAuth 2.0, and IAM authentication providers
//   - Rate Limiting: Token bucket rate limiter with configurable limits
//   - Retry Logic: Exponential backoff with jitter for transient failures
//   - Metrics: Prometheus-compatible metrics collection
//   - Testing: Mock connector and test harness for unit/integration tests
//
// # Authentication
//
// The SDK supports multiple authentication methods:
//
//	// API Key authentication
//	auth := sdk.NewAPIKeyAuth("my-api-key", sdk.APIKeyInHeader, "X-API-Key")
//
//	// OAuth 2.0 authentication
//	auth := sdk.NewOAuthAuth(&sdk.OAuthConfig{
//	    ClientID:     "client-id",
//	    ClientSecret: "client-secret",
//	    TokenURL:     "https://oauth.example.com/token",
//	    Scopes:       []string{"read", "write"},
//	})
//
//	// IAM authentication (AWS)
//	auth := sdk.NewIAMAuth(&sdk.IAMCredentials{
//	    AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
//	    SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
//	    Region:          "us-east-1",
//	    Service:         "execute-api",
//	})
//
// # Rate Limiting
//
// Built-in rate limiting prevents API overload:
//
//	limiter := sdk.NewRateLimiter(100, 10) // 100 requests/second, burst of 10
//	if err := limiter.Wait(ctx); err != nil {
//	    return err // Context cancelled or deadline exceeded
//	}
//
// # Retry Logic
//
// Automatic retry with exponential backoff:
//
//	result, err := sdk.RetryWithBackoff(ctx, sdk.DefaultRetryConfig(), func() (any, error) {
//	    return client.DoRequest()
//	})
//
// # Testing
//
// The SDK provides testing utilities:
//
//	func TestMyConnector(t *testing.T) {
//	    harness := sdk.NewTestHarness(t)
//	    mock := harness.NewMockConnector()
//	    mock.SetQueryResult(expectedResult)
//
//	    result, err := mock.Query(ctx, query)
//	    harness.AssertNoError(err)
//	    harness.AssertRowCount(result, 5)
//	}
package sdk
