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
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"axonflow/platform/connectors/base"
)

// BaseConnector provides a foundation for building custom connectors.
// Embed this struct and override methods as needed.
type BaseConnector struct {
	name         string
	connType     string
	version      string
	capabilities []string
	config       *base.ConnectorConfig
	connected    bool
	logger       *log.Logger
	authProvider AuthProvider
	rateLimiter  *RateLimiter
	retryConfig  *RetryConfig
	validator    ConfigValidator
	hooks        *LifecycleHooks
	metrics      *ConnectorMetrics
	mu           sync.RWMutex
}

// NewBaseConnector creates a new base connector with the given type
func NewBaseConnector(connType string) *BaseConnector {
	return &BaseConnector{
		connType:     connType,
		version:      "1.0.0",
		capabilities: []string{"query", "execute"},
		logger:       log.New(os.Stdout, fmt.Sprintf("[MCP_%s] ", connType), log.LstdFlags),
		metrics:      NewConnectorMetrics(connType),
	}
}

// Connect establishes the connection. Override this method in your connector.
func (c *BaseConnector) Connect(ctx context.Context, config *base.ConnectorConfig) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Validate configuration
	if c.validator != nil {
		if err := c.validator.Validate(config); err != nil {
			return base.NewConnectorError(config.Name, "Connect", "configuration validation failed", err)
		}

		// Apply defaults
		if defaultValidator, ok := c.validator.(*DefaultConfigValidator); ok {
			defaultValidator.ApplyDefaults(config)
		}
	}

	// Store configuration
	c.config = config
	c.name = config.Name

	// Set default timeout if not specified
	if c.config.Timeout == 0 {
		c.config.Timeout = 30 * time.Second
	}

	// Call connect hook
	if c.hooks != nil && c.hooks.OnConnect != nil {
		if err := c.hooks.OnConnect(ctx, config); err != nil {
			return base.NewConnectorError(config.Name, "Connect", "hook failed", err)
		}
	}

	c.connected = true
	c.logger.Printf("Base connector initialized: %s (type: %s)", config.Name, c.connType)

	return nil
}

// Disconnect closes the connection. Override this method in your connector.
func (c *BaseConnector) Disconnect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return nil
	}

	// Call disconnect hook
	if c.hooks != nil && c.hooks.OnDisconnect != nil {
		if err := c.hooks.OnDisconnect(ctx); err != nil {
			c.logger.Printf("Warning: disconnect hook failed: %v", err)
		}
	}

	c.connected = false

	if c.config != nil {
		c.logger.Printf("Disconnected: %s", c.config.Name)
	}

	return nil
}

// HealthCheck verifies the connection is healthy. Override in your connector.
func (c *BaseConnector) HealthCheck(ctx context.Context) (*base.HealthStatus, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	status := &base.HealthStatus{
		Healthy:   c.connected,
		Timestamp: time.Now(),
		Details:   make(map[string]string),
	}

	if !c.connected {
		status.Error = "not connected"
		return status, nil
	}

	status.Details["connector_type"] = c.connType
	status.Details["version"] = c.version

	// Call health check hook
	if c.hooks != nil && c.hooks.OnHealthCheck != nil {
		if err := c.hooks.OnHealthCheck(ctx, status); err != nil {
			status.Healthy = false
			status.Error = err.Error()
		}
	}

	return status, nil
}

// Query executes a read operation. Override this method in your connector.
func (c *BaseConnector) Query(ctx context.Context, query *base.Query) (*base.QueryResult, error) {
	c.mu.RLock()
	if !c.connected {
		c.mu.RUnlock()
		return nil, base.NewConnectorError(c.name, "Query", "not connected", nil)
	}
	c.mu.RUnlock()

	// Apply rate limiting
	if c.rateLimiter != nil {
		if err := c.rateLimiter.Wait(ctx); err != nil {
			return nil, base.NewConnectorError(c.name, "Query", "rate limit exceeded", err)
		}
	}

	// Call query hook
	if c.hooks != nil && c.hooks.OnQuery != nil {
		if err := c.hooks.OnQuery(ctx, query); err != nil {
			return nil, base.NewConnectorError(c.name, "Query", "query hook failed", err)
		}
	}

	// Record metrics - base implementation always succeeds
	start := time.Now()
	c.metrics.RecordQuery(time.Since(start), nil)

	// Base implementation returns empty result - override in your connector
	return &base.QueryResult{
		Rows:      []map[string]interface{}{},
		RowCount:  0,
		Duration:  time.Since(start),
		Cached:    false,
		Connector: c.name,
	}, nil
}

// Execute runs a write operation. Override this method in your connector.
func (c *BaseConnector) Execute(ctx context.Context, cmd *base.Command) (*base.CommandResult, error) {
	c.mu.RLock()
	if !c.connected {
		c.mu.RUnlock()
		return nil, base.NewConnectorError(c.name, "Execute", "not connected", nil)
	}
	c.mu.RUnlock()

	// Apply rate limiting
	if c.rateLimiter != nil {
		if err := c.rateLimiter.Wait(ctx); err != nil {
			return nil, base.NewConnectorError(c.name, "Execute", "rate limit exceeded", err)
		}
	}

	// Call execute hook
	if c.hooks != nil && c.hooks.OnExecute != nil {
		if err := c.hooks.OnExecute(ctx, cmd); err != nil {
			return nil, base.NewConnectorError(c.name, "Execute", "execute hook failed", err)
		}
	}

	// Record metrics - base implementation always succeeds
	start := time.Now()
	c.metrics.RecordExecute(time.Since(start), nil)

	// Base implementation returns success - override in your connector
	return &base.CommandResult{
		Success:      true,
		RowsAffected: 0,
		Duration:     time.Since(start),
		Message:      "base connector execute",
		Connector:    c.name,
	}, nil
}

// Name returns the connector instance name
func (c *BaseConnector) Name() string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.name != "" {
		return c.name
	}
	return c.connType
}

// Type returns the connector type
func (c *BaseConnector) Type() string {
	return c.connType
}

// Version returns the connector version
func (c *BaseConnector) Version() string {
	return c.version
}

// Capabilities returns the list of supported capabilities
func (c *BaseConnector) Capabilities() []string {
	return c.capabilities
}

// SetLogger sets a custom logger
func (c *BaseConnector) SetLogger(logger *log.Logger) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.logger = logger
}

// GetLogger returns the logger
func (c *BaseConnector) GetLogger() *log.Logger {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.logger
}

// SetAuthProvider sets the authentication provider
func (c *BaseConnector) SetAuthProvider(auth AuthProvider) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.authProvider = auth
}

// GetAuthProvider returns the authentication provider
func (c *BaseConnector) GetAuthProvider() AuthProvider {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.authProvider
}

// SetRateLimiter sets the rate limiter
func (c *BaseConnector) SetRateLimiter(limiter *RateLimiter) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rateLimiter = limiter
}

// SetRetryConfig sets the retry configuration
func (c *BaseConnector) SetRetryConfig(config *RetryConfig) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.retryConfig = config
}

// GetRetryConfig returns the retry configuration
func (c *BaseConnector) GetRetryConfig() *RetryConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.retryConfig
}

// SetValidator sets the configuration validator
func (c *BaseConnector) SetValidator(validator ConfigValidator) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.validator = validator
}

// SetHooks sets lifecycle hooks
func (c *BaseConnector) SetHooks(hooks *LifecycleHooks) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.hooks = hooks
}

// GetMetrics returns the connector metrics
func (c *BaseConnector) GetMetrics() *ConnectorMetrics {
	return c.metrics
}

// IsConnected returns the connection status
func (c *BaseConnector) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}

// GetConfig returns the connector configuration
func (c *BaseConnector) GetConfig() *base.ConnectorConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.config
}

// SetCapabilities sets the connector capabilities
func (c *BaseConnector) SetCapabilities(caps []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.capabilities = caps
}

// SetVersion sets the connector version
func (c *BaseConnector) SetVersion(version string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.version = version
}

// Log writes a log message with the connector prefix
func (c *BaseConnector) Log(format string, args ...interface{}) {
	c.logger.Printf(format, args...)
}

// GetTimeout returns the configured timeout or default
func (c *BaseConnector) GetTimeout() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.config != nil && c.config.Timeout > 0 {
		return c.config.Timeout
	}
	return 30 * time.Second
}

// GetOption retrieves an option value from config with type assertion
func (c *BaseConnector) GetOption(key string, defaultValue interface{}) interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.config == nil || c.config.Options == nil {
		return defaultValue
	}

	if val, ok := c.config.Options[key]; ok {
		return val
	}
	return defaultValue
}

// GetStringOption retrieves a string option
func (c *BaseConnector) GetStringOption(key, defaultValue string) string {
	val := c.GetOption(key, defaultValue)
	if s, ok := val.(string); ok {
		return s
	}
	return defaultValue
}

// GetIntOption retrieves an integer option
func (c *BaseConnector) GetIntOption(key string, defaultValue int) int {
	val := c.GetOption(key, defaultValue)
	switch v := val.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	}
	return defaultValue
}

// GetBoolOption retrieves a boolean option
func (c *BaseConnector) GetBoolOption(key string, defaultValue bool) bool {
	val := c.GetOption(key, defaultValue)
	if b, ok := val.(bool); ok {
		return b
	}
	return defaultValue
}

// GetCredential retrieves a credential value
func (c *BaseConnector) GetCredential(key string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.config == nil || c.config.Credentials == nil {
		return ""
	}
	return c.config.Credentials[key]
}

// WithTimeout creates a context with the connector's configured timeout
func (c *BaseConnector) WithTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, c.GetTimeout())
}

// SetConnected sets the connection status. Primarily useful for testing.
func (c *BaseConnector) SetConnected(connected bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.connected = connected
}

// SetName sets the connector name. Primarily useful for testing.
func (c *BaseConnector) SetName(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.name = name
}
