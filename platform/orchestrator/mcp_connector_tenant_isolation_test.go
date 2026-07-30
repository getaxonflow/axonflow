// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Cross-tenant isolation of the connector-call workflow step (#3067 S-1).
//
// This is the CRITICAL path of the finding: `step.connector` arrives verbatim
// from the POST /api/v1/workflows/execute and MAP plan-execute request bodies,
// and used to be handed to a flat, deployment-wide, name-keyed registry. A
// tenant could name another tenant's connector and have its statement executed
// against it with the victim's ConnectionURL and decrypted Credentials.
//
// Vacuity: against the pre-fix code `connectorRegistry.Get(connectorName)`
// resolved tenant A's connector for tenant B, so `victim.queryCalls` would be
// 1 and the assertions below would fail.

package orchestrator

import (
	"context"
	"sync"
	"testing"
	"time"

	"axonflow/platform/connectors/base"
	"axonflow/platform/connectors/registry"
)

// countingConnector records whether it was ever driven, so a test can assert
// that the VICTIM's connector was never touched — not merely that the
// attacker got an error back.
type countingConnector struct {
	mu          sync.Mutex
	queryCalls  int
	executeCall int
	rows        []map[string]interface{}
}

func (c *countingConnector) Connect(ctx context.Context, config *base.ConnectorConfig) error {
	return nil
}
func (c *countingConnector) Disconnect(ctx context.Context) error { return nil }
func (c *countingConnector) HealthCheck(ctx context.Context) (*base.HealthStatus, error) {
	return &base.HealthStatus{Healthy: true, Timestamp: time.Now()}, nil
}
func (c *countingConnector) Query(ctx context.Context, q *base.Query) (*base.QueryResult, error) {
	c.mu.Lock()
	c.queryCalls++
	c.mu.Unlock()
	return &base.QueryResult{Rows: c.rows, RowCount: len(c.rows), Connector: "counting"}, nil
}
func (c *countingConnector) Execute(ctx context.Context, cmd *base.Command) (*base.CommandResult, error) {
	c.mu.Lock()
	c.executeCall++
	c.mu.Unlock()
	return &base.CommandResult{Success: true, Connector: "counting"}, nil
}
func (c *countingConnector) Type() string           { return "postgres" }
func (c *countingConnector) Version() string        { return "1.0.0" }
func (c *countingConnector) Capabilities() []string { return []string{"query"} }
func (c *countingConnector) Name() string           { return "counting" }

func (c *countingConnector) queries() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.queryCalls
}

// execFor builds a workflow execution whose UserContext carries the tenancy
// the orchestrator's handlers overlay from the agent's authenticated headers.
func execFor(tenantID string) *WorkflowExecution {
	return &WorkflowExecution{
		ID:          "exec-" + tenantID,
		Status:      "running",
		Input:       map[string]interface{}{},
		Output:      map[string]interface{}{},
		UserContext: UserContext{TenantID: tenantID, OrgID: tenantID},
	}
}

func TestMCPConnectorStep_CannotExecuteAgainstAnotherTenantsConnector(t *testing.T) {
	originalRegistry := connectorRegistry
	originalRouter := mcpQueryRouter
	defer func() {
		connectorRegistry = originalRegistry
		mcpQueryRouter = originalRouter
	}()

	// No agent router: a miss must be a hard failure, not a silent re-route.
	mcpQueryRouter = nil
	connectorRegistry = registry.NewRegistry()

	victim := &countingConnector{rows: []map[string]interface{}{{"ssn": "123-45-6789"}}}
	if err := connectorRegistry.Register("customer-db", victim, &base.ConnectorConfig{
		Name:          "customer-db",
		Type:          "postgres",
		TenantID:      "org-victim",
		ConnectionURL: "postgres://victim@victim-db/victim",
		Credentials:   map[string]string{"password": "victim-password"},
		Timeout:       5 * time.Second,
	}); err != nil {
		t.Fatalf("register victim connector: %v", err)
	}

	processor := NewMCPConnectorProcessor()
	step := WorkflowStep{
		Name:      "exfiltrate",
		Type:      "connector-call",
		Connector: "customer-db", // names the VICTIM's connector explicitly
		Operation: "query",
		Statement: "SELECT * FROM customers",
	}

	out, err := processor.ExecuteStep(context.Background(), step, map[string]interface{}{}, execFor("org-attacker"))
	if err == nil {
		t.Fatalf("cross-tenant connector step must fail, got output: %v", out)
	}
	if out != nil {
		t.Errorf("cross-tenant connector step must return no data, got: %v", out)
	}

	// The load-bearing assertion: the victim's connector was never driven, so
	// no connection was opened with the victim's credentials.
	if got := victim.queries(); got != 0 {
		t.Fatalf("victim connector was queried %d time(s) by another tenant", got)
	}
}

func TestMCPConnectorStep_OwnTenantStillExecutes(t *testing.T) {
	originalRegistry := connectorRegistry
	originalRouter := mcpQueryRouter
	defer func() {
		connectorRegistry = originalRegistry
		mcpQueryRouter = originalRouter
	}()

	mcpQueryRouter = nil
	connectorRegistry = registry.NewRegistry()

	own := &countingConnector{rows: []map[string]interface{}{{"id": 1}}}
	if err := connectorRegistry.Register("customer-db", own, &base.ConnectorConfig{
		Name:     "customer-db",
		Type:     "postgres",
		TenantID: "org-owner",
		Timeout:  5 * time.Second,
	}); err != nil {
		t.Fatalf("register: %v", err)
	}

	processor := NewMCPConnectorProcessor()
	step := WorkflowStep{
		Name:      "read-own",
		Type:      "connector-call",
		Connector: "customer-db",
		Operation: "query",
		Statement: "SELECT 1",
	}

	out, err := processor.ExecuteStep(context.Background(), step, map[string]interface{}{}, execFor("org-owner"))
	if err != nil {
		t.Fatalf("positive control: a tenant must still reach its own connector: %v", err)
	}
	if out == nil || out["row_count"] != 1 {
		t.Fatalf("positive control: expected 1 row, got %v", out)
	}
	if got := own.queries(); got != 1 {
		t.Fatalf("positive control: expected 1 query on the owner's connector, got %d", got)
	}
}

// TestMCPConnectorStep_SharedConnectorStillReachable pins the deliberately
// preserved wildcard semantic: connectors the OPERATOR registered for the
// deployment (tenant_id '*', e.g. from a config file) stay reachable by every
// tenant, exactly as ValidateTenantAccess has always allowed.
func TestMCPConnectorStep_SharedConnectorStillReachable(t *testing.T) {
	originalRegistry := connectorRegistry
	originalRouter := mcpQueryRouter
	defer func() {
		connectorRegistry = originalRegistry
		mcpQueryRouter = originalRouter
	}()

	mcpQueryRouter = nil
	connectorRegistry = registry.NewRegistry()

	shared := &countingConnector{rows: []map[string]interface{}{{"ok": true}}}
	if err := connectorRegistry.Register("operator-http", shared, &base.ConnectorConfig{
		Name:     "operator-http",
		Type:     "http",
		TenantID: registry.SharedTenant,
		Timeout:  5 * time.Second,
	}); err != nil {
		t.Fatalf("register: %v", err)
	}

	processor := NewMCPConnectorProcessor()
	step := WorkflowStep{
		Name:      "call-shared",
		Type:      "connector-call",
		Connector: "operator-http",
		Operation: "query",
		Statement: "ping",
	}

	if _, err := processor.ExecuteStep(context.Background(), step, map[string]interface{}{}, execFor("org-any")); err != nil {
		t.Fatalf("deployment-shared connectors must remain reachable: %v", err)
	}
	if got := shared.queries(); got != 1 {
		t.Fatalf("expected the shared connector to be driven once, got %d", got)
	}
}

// TestExecutionTenantID_MatchesTheRegistryWriterWhenOrgAndTenantDiverge (R3):
// OrgID and TenantID come from INDEPENDENT sources — the license payload
// (auth.go `OrgID: validationResult.OrgID`) versus the client/customer record
// (`TenantID: clientAuth.TenantID`) — so a deployment can legitimately have
// them differ. The connector registry's writer (installConnectorHandler via
// resolveTenantID) keys on X-Tenant-ID, and every other reader is tenant-first
// too, so this reader must be as well: an org-first reader would miss the
// tenant's OWN connector. That is a lockout, not a leak, and it is exactly the
// class a "make the two scope helpers agree" tidy-up introduces.
func TestExecutionTenantID_MatchesTheRegistryWriterWhenOrgAndTenantDiverge(t *testing.T) {
	originalRegistry := connectorRegistry
	originalRouter := mcpQueryRouter
	defer func() {
		connectorRegistry = originalRegistry
		mcpQueryRouter = originalRouter
	}()

	mcpQueryRouter = nil
	connectorRegistry = registry.NewRegistry()

	// The connector is installed under the TENANT id, as resolveTenantID does.
	own := &countingConnector{rows: []map[string]interface{}{{"id": 1}}}
	if err := connectorRegistry.Register("crm", own, &base.ConnectorConfig{
		Name: "crm", Type: "http", TenantID: "customer-tenant", Timeout: 5 * time.Second,
	}); err != nil {
		t.Fatalf("register: %v", err)
	}

	// The execution carries BOTH identifiers, and they differ.
	exec := &WorkflowExecution{
		ID:          "exec-divergent",
		Status:      "running",
		Input:       map[string]interface{}{},
		Output:      map[string]interface{}{},
		UserContext: UserContext{TenantID: "customer-tenant", OrgID: "license-org"},
	}

	if got := executionTenantID(exec); got != "customer-tenant" {
		t.Fatalf("executionTenantID = %q, want customer-tenant (the registry's writer keys on X-Tenant-ID)", got)
	}

	processor := NewMCPConnectorProcessor()
	step := WorkflowStep{Name: "read", Type: "connector-call", Connector: "crm", Operation: "query", Statement: "/"}
	if _, err := processor.ExecuteStep(context.Background(), step, map[string]interface{}{}, exec); err != nil {
		t.Fatalf("the owner must reach its own connector when OrgID != TenantID: %v", err)
	}
	if own.queries() != 1 {
		t.Fatalf("owner's connector was not driven (queries=%d) — org/tenant divergence locked the owner out", own.queries())
	}

	// And the divergence does not become a second way in: an execution
	// carrying ONLY the foreign org still resolves nothing.
	foreign := &WorkflowExecution{
		ID:          "exec-foreign",
		Status:      "running",
		Input:       map[string]interface{}{},
		Output:      map[string]interface{}{},
		UserContext: UserContext{TenantID: "other-tenant", OrgID: "license-org"},
	}
	if _, err := processor.ExecuteStep(context.Background(), step, map[string]interface{}{}, foreign); err == nil {
		t.Fatal("a different tenant sharing the same license org must not reach the connector")
	}
	if own.queries() != 1 {
		t.Fatalf("the foreign execution drove the owner's connector (queries=%d)", own.queries())
	}
}

// TestExecutionTenantID_IgnoresForgeableInput proves the tenancy comes from
// UserContext (header-derived, authoritative) and NEVER from execution.Input,
// which is the client-supplied request body.
func TestExecutionTenantID_IgnoresForgeableInput(t *testing.T) {
	exec := &WorkflowExecution{
		ID:          "exec-1",
		Input:       map[string]interface{}{"tenant_id": "org-victim"},
		UserContext: UserContext{TenantID: "org-attacker", OrgID: "org-attacker"},
	}
	if got := executionTenantID(exec); got != "org-attacker" {
		t.Fatalf("tenancy must come from UserContext, got %q", got)
	}

	// OrgID is the fallback when TenantID is absent.
	exec2 := &WorkflowExecution{UserContext: UserContext{OrgID: "org-only"}}
	if got := executionTenantID(exec2); got != "org-only" {
		t.Fatalf("expected OrgID fallback, got %q", got)
	}

	if got := executionTenantID(nil); got != "" {
		t.Fatalf("nil execution must yield no tenancy, got %q", got)
	}
}
