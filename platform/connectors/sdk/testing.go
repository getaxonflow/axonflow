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
	"strings"
	"sync"
	"testing"
	"time"

	"axonflow/platform/connectors/base"
)

// MockConnector provides a mock implementation for testing
type MockConnector struct {
	name         string
	connType     string
	version      string
	capabilities []string
	connected    bool

	// Mock responses
	queryResult   *base.QueryResult
	queryError    error
	executeResult *base.CommandResult
	executeError  error
	healthStatus  *base.HealthStatus
	healthError   error
	connectError  error
	disconnectError error

	// Call tracking
	connectCalls    []ConnectCall
	disconnectCalls int
	queryCalls      []QueryCall
	executeCalls    []ExecuteCall
	healthCalls     int

	// Hooks for custom behavior
	onQuery   func(context.Context, *base.Query) (*base.QueryResult, error)
	onExecute func(context.Context, *base.Command) (*base.CommandResult, error)

	mu sync.RWMutex
}

// ConnectCall records a Connect call
type ConnectCall struct {
	Config *base.ConnectorConfig
	Time   time.Time
}

// QueryCall records a Query call
type QueryCall struct {
	Query *base.Query
	Time  time.Time
}

// ExecuteCall records an Execute call
type ExecuteCall struct {
	Command *base.Command
	Time    time.Time
}

// NewMockConnector creates a new mock connector
func NewMockConnector(name, connType string) *MockConnector {
	return &MockConnector{
		name:         name,
		connType:     connType,
		version:      "1.0.0-mock",
		capabilities: []string{"query", "execute"},
		queryResult: &base.QueryResult{
			Rows:      []map[string]interface{}{},
			RowCount:  0,
			Connector: name,
		},
		executeResult: &base.CommandResult{
			Success:   true,
			Connector: name,
		},
		healthStatus: &base.HealthStatus{
			Healthy:   true,
			Timestamp: time.Now(),
		},
	}
}

// Connect implements base.Connector
func (m *MockConnector) Connect(ctx context.Context, config *base.ConnectorConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.connectCalls = append(m.connectCalls, ConnectCall{
		Config: config,
		Time:   time.Now(),
	})

	if m.connectError != nil {
		return m.connectError
	}

	m.connected = true
	if config != nil {
		m.name = config.Name
	}
	return nil
}

// Disconnect implements base.Connector
func (m *MockConnector) Disconnect(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.disconnectCalls++

	if m.disconnectError != nil {
		return m.disconnectError
	}

	m.connected = false
	return nil
}

// HealthCheck implements base.Connector
func (m *MockConnector) HealthCheck(ctx context.Context) (*base.HealthStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.healthCalls++

	if m.healthError != nil {
		return nil, m.healthError
	}

	return m.healthStatus, nil
}

// Query implements base.Connector
func (m *MockConnector) Query(ctx context.Context, query *base.Query) (*base.QueryResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.queryCalls = append(m.queryCalls, QueryCall{
		Query: query,
		Time:  time.Now(),
	})

	if m.onQuery != nil {
		return m.onQuery(ctx, query)
	}

	if m.queryError != nil {
		return nil, m.queryError
	}

	result := *m.queryResult
	result.Duration = time.Millisecond
	return &result, nil
}

// Execute implements base.Connector
func (m *MockConnector) Execute(ctx context.Context, cmd *base.Command) (*base.CommandResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.executeCalls = append(m.executeCalls, ExecuteCall{
		Command: cmd,
		Time:    time.Now(),
	})

	if m.onExecute != nil {
		return m.onExecute(ctx, cmd)
	}

	if m.executeError != nil {
		return nil, m.executeError
	}

	result := *m.executeResult
	result.Duration = time.Millisecond
	return &result, nil
}

// Name implements base.Connector
func (m *MockConnector) Name() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.name
}

// Type implements base.Connector
func (m *MockConnector) Type() string {
	return m.connType
}

// Version implements base.Connector
func (m *MockConnector) Version() string {
	return m.version
}

// Capabilities implements base.Connector
func (m *MockConnector) Capabilities() []string {
	return m.capabilities
}

// SetQueryResult sets the mock query result
func (m *MockConnector) SetQueryResult(result *base.QueryResult) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.queryResult = result
}

// SetQueryError sets the mock query error
func (m *MockConnector) SetQueryError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.queryError = err
}

// SetExecuteResult sets the mock execute result
func (m *MockConnector) SetExecuteResult(result *base.CommandResult) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.executeResult = result
}

// SetExecuteError sets the mock execute error
func (m *MockConnector) SetExecuteError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.executeError = err
}

// SetHealthStatus sets the mock health status
func (m *MockConnector) SetHealthStatus(status *base.HealthStatus) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.healthStatus = status
}

// SetHealthError sets the mock health error
func (m *MockConnector) SetHealthError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.healthError = err
}

// SetConnectError sets the mock connect error
func (m *MockConnector) SetConnectError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connectError = err
}

// SetDisconnectError sets the mock disconnect error
func (m *MockConnector) SetDisconnectError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.disconnectError = err
}

// SetOnQuery sets a custom query handler
func (m *MockConnector) SetOnQuery(fn func(context.Context, *base.Query) (*base.QueryResult, error)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onQuery = fn
}

// SetOnExecute sets a custom execute handler
func (m *MockConnector) SetOnExecute(fn func(context.Context, *base.Command) (*base.CommandResult, error)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onExecute = fn
}

// GetConnectCalls returns all connect calls
func (m *MockConnector) GetConnectCalls() []ConnectCall {
	m.mu.RLock()
	defer m.mu.RUnlock()
	calls := make([]ConnectCall, len(m.connectCalls))
	copy(calls, m.connectCalls)
	return calls
}

// GetQueryCalls returns all query calls
func (m *MockConnector) GetQueryCalls() []QueryCall {
	m.mu.RLock()
	defer m.mu.RUnlock()
	calls := make([]QueryCall, len(m.queryCalls))
	copy(calls, m.queryCalls)
	return calls
}

// GetExecuteCalls returns all execute calls
func (m *MockConnector) GetExecuteCalls() []ExecuteCall {
	m.mu.RLock()
	defer m.mu.RUnlock()
	calls := make([]ExecuteCall, len(m.executeCalls))
	copy(calls, m.executeCalls)
	return calls
}

// GetDisconnectCalls returns the number of disconnect calls
func (m *MockConnector) GetDisconnectCalls() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.disconnectCalls
}

// GetHealthCalls returns the number of health check calls
func (m *MockConnector) GetHealthCalls() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.healthCalls
}

// Reset clears all recorded calls
func (m *MockConnector) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connectCalls = nil
	m.disconnectCalls = 0
	m.queryCalls = nil
	m.executeCalls = nil
	m.healthCalls = 0
}

// IsConnected returns the connection state
func (m *MockConnector) IsConnected() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.connected
}

// TestHarness provides testing utilities for connectors
type TestHarness struct {
	t       *testing.T
	ctx     context.Context
	cancel  context.CancelFunc
	timeout time.Duration
}

// NewTestHarness creates a new test harness
func NewTestHarness(t *testing.T) *TestHarness {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	return &TestHarness{
		t:       t,
		ctx:     ctx,
		cancel:  cancel,
		timeout: 30 * time.Second,
	}
}

// WithTimeout sets a custom timeout
func (h *TestHarness) WithTimeout(d time.Duration) *TestHarness {
	h.cancel()
	h.timeout = d
	h.ctx, h.cancel = context.WithTimeout(context.Background(), d)
	return h
}

// Context returns the test context
func (h *TestHarness) Context() context.Context {
	return h.ctx
}

// Cleanup should be called at the end of tests
func (h *TestHarness) Cleanup() {
	h.cancel()
}

// NewMockConnector creates a new mock connector
func (h *TestHarness) NewMockConnector() *MockConnector {
	return NewMockConnector("test-connector", "mock")
}

// NewConfig creates a test configuration
func (h *TestHarness) NewConfig(name, connType string) *base.ConnectorConfig {
	return &base.ConnectorConfig{
		Name:          name,
		Type:          connType,
		ConnectionURL: "test://localhost",
		Timeout:       h.timeout,
		Options:       make(map[string]interface{}),
		Credentials:   make(map[string]string),
	}
}

// AssertNoError fails the test if err is not nil
func (h *TestHarness) AssertNoError(err error) {
	h.t.Helper()
	if err != nil {
		h.t.Fatalf("unexpected error: %v", err)
	}
}

// AssertError fails the test if err is nil
func (h *TestHarness) AssertError(err error) {
	h.t.Helper()
	if err == nil {
		h.t.Fatal("expected error but got nil")
	}
}

// AssertErrorContains fails if err doesn't contain the expected message
func (h *TestHarness) AssertErrorContains(err error, msg string) {
	h.t.Helper()
	if err == nil {
		h.t.Fatalf("expected error containing %q but got nil", msg)
	}
	if errMsg := err.Error(); !strings.Contains(errMsg, msg) {
		h.t.Fatalf("expected error containing %q but got %q", msg, errMsg)
	}
}

// AssertEqual fails the test if expected != actual
func (h *TestHarness) AssertEqual(expected, actual interface{}) {
	h.t.Helper()
	if expected != actual {
		h.t.Fatalf("expected %v but got %v", expected, actual)
	}
}

// AssertTrue fails the test if condition is false
func (h *TestHarness) AssertTrue(condition bool, msg string) {
	h.t.Helper()
	if !condition {
		h.t.Fatalf("assertion failed: %s", msg)
	}
}

// AssertFalse fails the test if condition is true
func (h *TestHarness) AssertFalse(condition bool, msg string) {
	h.t.Helper()
	if condition {
		h.t.Fatalf("assertion failed (expected false): %s", msg)
	}
}

// AssertRowCount validates the query result has expected row count
func (h *TestHarness) AssertRowCount(result *base.QueryResult, expected int) {
	h.t.Helper()
	if result == nil {
		h.t.Fatal("result is nil")
	}
	if result.RowCount != expected {
		h.t.Fatalf("expected %d rows but got %d", expected, result.RowCount)
	}
}

// AssertSuccess validates the command result is successful
func (h *TestHarness) AssertSuccess(result *base.CommandResult) {
	h.t.Helper()
	if result == nil {
		h.t.Fatal("result is nil")
	}
	if !result.Success {
		h.t.Fatalf("expected success but got failure: %s", result.Message)
	}
}

// AssertHealthy validates the health status is healthy
func (h *TestHarness) AssertHealthy(status *base.HealthStatus) {
	h.t.Helper()
	if status == nil {
		h.t.Fatal("health status is nil")
	}
	if !status.Healthy {
		h.t.Fatalf("expected healthy but got unhealthy: %s", status.Error)
	}
}

// AssertUnhealthy validates the health status is unhealthy
func (h *TestHarness) AssertUnhealthy(status *base.HealthStatus) {
	h.t.Helper()
	if status == nil {
		h.t.Fatal("health status is nil")
	}
	if status.Healthy {
		h.t.Fatal("expected unhealthy but got healthy")
	}
}

// ConnectAndTest connects a connector and runs the test function
func (h *TestHarness) ConnectAndTest(connector base.Connector, config *base.ConnectorConfig, fn func()) {
	h.t.Helper()

	err := connector.Connect(h.ctx, config)
	h.AssertNoError(err)

	defer func() {
		err := connector.Disconnect(h.ctx)
		if err != nil {
			h.t.Logf("warning: disconnect error: %v", err)
		}
	}()

	fn()
}

// TestQuery runs a query and validates the result
func (h *TestHarness) TestQuery(connector base.Connector, query *base.Query, validate func(*base.QueryResult)) {
	h.t.Helper()

	result, err := connector.Query(h.ctx, query)
	h.AssertNoError(err)

	if validate != nil {
		validate(result)
	}
}

// TestExecute runs a command and validates the result
func (h *TestHarness) TestExecute(connector base.Connector, cmd *base.Command, validate func(*base.CommandResult)) {
	h.t.Helper()

	result, err := connector.Execute(h.ctx, cmd)
	h.AssertNoError(err)

	if validate != nil {
		validate(result)
	}
}

// IntegrationTest provides utilities for integration testing
type IntegrationTest struct {
	*TestHarness
	connector base.Connector
	config    *base.ConnectorConfig
}

// NewIntegrationTest creates a new integration test
func NewIntegrationTest(t *testing.T, connector base.Connector, config *base.ConnectorConfig) *IntegrationTest {
	return &IntegrationTest{
		TestHarness: NewTestHarness(t),
		connector:   connector,
		config:      config,
	}
}

// Run executes the integration test
func (it *IntegrationTest) Run(tests ...func(*IntegrationTest)) {
	it.t.Helper()

	err := it.connector.Connect(it.ctx, it.config)
	it.AssertNoError(err)

	defer func() {
		err := it.connector.Disconnect(it.ctx)
		if err != nil {
			it.t.Logf("warning: disconnect error: %v", err)
		}
		it.Cleanup()
	}()

	for _, test := range tests {
		test(it)
	}
}

// Query runs a query through the connector
func (it *IntegrationTest) Query(statement string, params map[string]interface{}) *base.QueryResult {
	it.t.Helper()

	query := &base.Query{
		Statement:  statement,
		Parameters: params,
	}

	result, err := it.connector.Query(it.ctx, query)
	it.AssertNoError(err)
	return result
}

// Execute runs a command through the connector
func (it *IntegrationTest) Execute(action, statement string, params map[string]interface{}) *base.CommandResult {
	it.t.Helper()

	cmd := &base.Command{
		Action:     action,
		Statement:  statement,
		Parameters: params,
	}

	result, err := it.connector.Execute(it.ctx, cmd)
	it.AssertNoError(err)
	return result
}

// HealthCheck runs a health check on the connector
func (it *IntegrationTest) HealthCheck() *base.HealthStatus {
	it.t.Helper()

	status, err := it.connector.HealthCheck(it.ctx)
	it.AssertNoError(err)
	return status
}

// BenchmarkHarness provides benchmarking utilities
type BenchmarkHarness struct {
	b         *testing.B
	ctx       context.Context
	cancel    context.CancelFunc
	connector base.Connector
}

// NewBenchmarkHarness creates a new benchmark harness
func NewBenchmarkHarness(b *testing.B, connector base.Connector) *BenchmarkHarness {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	return &BenchmarkHarness{
		b:         b,
		ctx:       ctx,
		cancel:    cancel,
		connector: connector,
	}
}

// Cleanup cleans up resources
func (bh *BenchmarkHarness) Cleanup() {
	bh.cancel()
}

// BenchmarkQuery benchmarks a query operation
func (bh *BenchmarkHarness) BenchmarkQuery(query *base.Query) {
	bh.b.Helper()
	bh.b.ResetTimer()

	for i := 0; i < bh.b.N; i++ {
		_, err := bh.connector.Query(bh.ctx, query)
		if err != nil {
			bh.b.Fatalf("query failed: %v", err)
		}
	}
}

// BenchmarkExecute benchmarks an execute operation
func (bh *BenchmarkHarness) BenchmarkExecute(cmd *base.Command) {
	bh.b.Helper()
	bh.b.ResetTimer()

	for i := 0; i < bh.b.N; i++ {
		_, err := bh.connector.Execute(bh.ctx, cmd)
		if err != nil {
			bh.b.Fatalf("execute failed: %v", err)
		}
	}
}

// TableDrivenTest represents a single test case
type TableDrivenTest struct {
	Name     string
	Query    *base.Query
	Command  *base.Command
	Expected interface{}
	WantErr  bool
}

// RunTableTests runs table-driven tests
func RunTableTests(t *testing.T, connector base.Connector, config *base.ConnectorConfig, tests []TableDrivenTest) {
	harness := NewTestHarness(t)
	defer harness.Cleanup()

	err := connector.Connect(harness.Context(), config)
	harness.AssertNoError(err)

	defer func() {
		_ = connector.Disconnect(harness.Context())
	}()

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			if tt.Query != nil {
				result, err := connector.Query(harness.Context(), tt.Query)
				if tt.WantErr {
					if err == nil {
						t.Error("expected error but got nil")
					}
					return
				}
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if result == nil {
					t.Fatal("result is nil")
				}
			}

			if tt.Command != nil {
				result, err := connector.Execute(harness.Context(), tt.Command)
				if tt.WantErr {
					if err == nil {
						t.Error("expected error but got nil")
					}
					return
				}
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if result == nil {
					t.Fatal("result is nil")
				}
			}
		})
	}
}

// Verify MockConnector implements base.Connector
var _ base.Connector = (*MockConnector)(nil)

// FailingConnector always fails - useful for testing error handling
type FailingConnector struct {
	err error
}

// NewFailingConnector creates a connector that always returns errors
func NewFailingConnector(err error) *FailingConnector {
	if err == nil {
		err = fmt.Errorf("intentional failure")
	}
	return &FailingConnector{err: err}
}

func (f *FailingConnector) Connect(ctx context.Context, config *base.ConnectorConfig) error {
	return f.err
}

func (f *FailingConnector) Disconnect(ctx context.Context) error {
	return f.err
}

func (f *FailingConnector) HealthCheck(ctx context.Context) (*base.HealthStatus, error) {
	return nil, f.err
}

func (f *FailingConnector) Query(ctx context.Context, query *base.Query) (*base.QueryResult, error) {
	return nil, f.err
}

func (f *FailingConnector) Execute(ctx context.Context, cmd *base.Command) (*base.CommandResult, error) {
	return nil, f.err
}

func (f *FailingConnector) Name() string     { return "failing" }
func (f *FailingConnector) Type() string     { return "failing" }
func (f *FailingConnector) Version() string  { return "1.0.0" }
func (f *FailingConnector) Capabilities() []string { return nil }

// Verify FailingConnector implements base.Connector
var _ base.Connector = (*FailingConnector)(nil)
