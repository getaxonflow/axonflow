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

package main

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"axonflow/platform/connectors/base"
	"axonflow/platform/connectors/registry"
)

// Mock connector for testing
type mockConnector struct {
	name         string
	shouldFail   bool
	queryResult  *base.QueryResult
	commandResult *base.CommandResult
}

func (m *mockConnector) Connect(ctx context.Context, config *base.ConnectorConfig) error {
	return nil
}

func (m *mockConnector) Disconnect(ctx context.Context) error {
	return nil
}

func (m *mockConnector) HealthCheck(ctx context.Context) (*base.HealthStatus, error) {
	return &base.HealthStatus{Healthy: true}, nil
}

func (m *mockConnector) Query(ctx context.Context, query *base.Query) (*base.QueryResult, error) {
	if m.shouldFail {
		return nil, fmt.Errorf("mock query failure")
	}
	if m.queryResult != nil {
		return m.queryResult, nil
	}
	// Default result
	return &base.QueryResult{
		Rows: []map[string]interface{}{
			{"id": 1, "name": "test"},
		},
		RowCount:  1,
		Duration:  10 * time.Millisecond,
		Cached:    false,
		Connector: m.name,
	}, nil
}

func (m *mockConnector) Execute(ctx context.Context, cmd *base.Command) (*base.CommandResult, error) {
	if m.shouldFail {
		return nil, fmt.Errorf("mock execute failure")
	}
	if m.commandResult != nil {
		return m.commandResult, nil
	}
	// Default result
	return &base.CommandResult{
		Success:      true,
		RowsAffected: 1,
		Duration:     5 * time.Millisecond,
		Message:      "success",
		Connector:    m.name,
	}, nil
}

func (m *mockConnector) Name() string        { return m.name }
func (m *mockConnector) Type() string        { return "mock" }
func (m *mockConnector) Version() string     { return "1.0.0" }
func (m *mockConnector) Capabilities() []string { return []string{"query", "execute"} }

// Mock fallback provider
type mockFallbackProvider struct {
	shouldFail bool
}

func (m *mockFallbackProvider) GenerateFlightFallback(destination, budget string, days, adults int) map[string]interface{} {
	return map[string]interface{}{
		"type":        "flight",
		"destination": destination,
		"price": map[string]interface{}{
			"total": "500.00",
		},
		"fallback": true,
	}
}

func (m *mockFallbackProvider) GenerateHotelFallback(destination, budget string, days, adults int) map[string]interface{} {
	return map[string]interface{}{
		"type":        "hotel",
		"name":        "Mock Hotel",
		"price":       "150",
		"destination": destination,
		"fallback":    true,
	}
}

func (m *mockFallbackProvider) GenerateLLMFallback(ctx context.Context, query, destination, budget string, days, adults int) (map[string]interface{}, error) {
	if m.shouldFail {
		return nil, fmt.Errorf("mock LLM fallback failure")
	}
	return map[string]interface{}{
		"result":   "Mock LLM fallback result",
		"fallback": true,
	}, nil
}

// Test NewMCPConnectorProcessor
func TestMCPConnector_NewMCPConnectorProcessor(t *testing.T) {
	processor := NewMCPConnectorProcessor()

	if processor == nil {
		t.Fatal("NewMCPConnectorProcessor() returned nil")
	}
	// Note: fallbackProvider removed - business logic moved to clients
}

// Note: TestMCPConnector_SetFallbackProvider removed - SetFallbackProvider method no longer exists

// Test ExecuteStep - missing connector name
func TestMCPConnector_ExecuteStep_MissingConnectorName(t *testing.T) {
	processor := NewMCPConnectorProcessor()
	ctx := context.Background()

	step := WorkflowStep{
		Name:      "test-step",
		Connector: "", // Missing connector name
	}

	execution := &WorkflowExecution{
		ID: "test-workflow",
	}

	_, err := processor.ExecuteStep(ctx, step, map[string]interface{}{}, execution)

	if err == nil {
		t.Error("ExecuteStep() should return error for missing connector name")
	}

	if !strings.Contains(err.Error(), "connector name not specified") {
		t.Errorf("Error should mention missing connector name, got: %s", err.Error())
	}
}

// Test ExecuteStep - registry not initialized
func TestMCPConnector_ExecuteStep_RegistryNotInitialized(t *testing.T) {
	// Save original registry and restore after test
	originalRegistry := connectorRegistry
	defer func() { connectorRegistry = originalRegistry }()

	connectorRegistry = nil

	processor := NewMCPConnectorProcessor()
	ctx := context.Background()

	step := WorkflowStep{
		Name:      "test-step",
		Connector: "test-connector",
	}

	execution := &WorkflowExecution{
		ID: "test-workflow",
	}

	_, err := processor.ExecuteStep(ctx, step, map[string]interface{}{}, execution)

	if err == nil {
		t.Error("ExecuteStep() should return error when registry not initialized")
	}

	if !strings.Contains(err.Error(), "registry not initialized") {
		t.Errorf("Error should mention registry not initialized, got: %s", err.Error())
	}
}

// Test ExecuteStep - connector not found
func TestMCPConnector_ExecuteStep_ConnectorNotFound(t *testing.T) {
	// Save original registry and restore after test
	originalRegistry := connectorRegistry
	defer func() { connectorRegistry = originalRegistry }()

	// Create empty registry
	connectorRegistry = registry.NewRegistry()

	processor := NewMCPConnectorProcessor()
	ctx := context.Background()

	step := WorkflowStep{
		Name:      "test-step",
		Connector: "nonexistent-connector",
	}

	execution := &WorkflowExecution{
		ID: "test-workflow",
	}

	_, err := processor.ExecuteStep(ctx, step, map[string]interface{}{}, execution)

	if err == nil {
		t.Error("ExecuteStep() should return error for nonexistent connector")
	}

	if !strings.Contains(err.Error(), "failed to get connector") {
		t.Errorf("Error should mention failed to get connector, got: %s", err.Error())
	}
}

// Test ExecuteStep - successful query operation
func TestMCPConnector_ExecuteStep_QuerySuccess(t *testing.T) {
	// Save original registry and restore after test
	originalRegistry := connectorRegistry
	defer func() { connectorRegistry = originalRegistry }()

	// Create registry with mock connector
	connectorRegistry = registry.NewRegistry()
	mockConn := &mockConnector{
		name: "test-connector",
		queryResult: &base.QueryResult{
			Rows: []map[string]interface{}{
				{"id": 1, "name": "result1"},
				{"id": 2, "name": "result2"},
			},
			RowCount:  2,
			Duration:  20 * time.Millisecond,
			Connector: "test-connector",
		},
	}
	_ = connectorRegistry.Register("test-connector", mockConn, &base.ConnectorConfig{Name: "test-connector"})

	processor := NewMCPConnectorProcessor()
	ctx := context.Background()

	step := WorkflowStep{
		Name:      "test-step",
		Connector: "test-connector",
		Operation: "query",
		Statement: "SELECT * FROM test",
	}

	execution := &WorkflowExecution{
		ID: "test-workflow",
	}

	output, err := processor.ExecuteStep(ctx, step, map[string]interface{}{}, execution)

	if err != nil {
		t.Fatalf("ExecuteStep() error = %v", err)
	}

	if output == nil {
		t.Fatal("ExecuteStep() returned nil output")
	}

	if rowCount, ok := output["row_count"].(int); !ok || rowCount != 2 {
		t.Errorf("Expected row_count=2, got %v", output["row_count"])
	}

	if rows, ok := output["rows"].([]map[string]interface{}); !ok || len(rows) != 2 {
		t.Errorf("Expected 2 rows, got %v", output["rows"])
	}
}

// Test ExecuteStep - successful execute operation
func TestMCPConnector_ExecuteStep_ExecuteSuccess(t *testing.T) {
	// Save original registry and restore after test
	originalRegistry := connectorRegistry
	defer func() { connectorRegistry = originalRegistry }()

	// Create registry with mock connector
	connectorRegistry = registry.NewRegistry()
	mockConn := &mockConnector{
		name: "test-connector",
		commandResult: &base.CommandResult{
			Success:      true,
			RowsAffected: 3,
			Duration:     15 * time.Millisecond,
			Message:      "3 rows inserted",
			Connector:    "test-connector",
		},
	}
	_ = connectorRegistry.Register("test-connector", mockConn, &base.ConnectorConfig{Name: "test-connector"})

	processor := NewMCPConnectorProcessor()
	ctx := context.Background()

	step := WorkflowStep{
		Name:      "test-step",
		Connector: "test-connector",
		Operation: "execute",
		Action:    "INSERT",
		Statement: "INSERT INTO test VALUES (...)",
	}

	execution := &WorkflowExecution{
		ID: "test-workflow",
	}

	output, err := processor.ExecuteStep(ctx, step, map[string]interface{}{}, execution)

	if err != nil {
		t.Fatalf("ExecuteStep() error = %v", err)
	}

	if output == nil {
		t.Fatal("ExecuteStep() returned nil output")
	}

	if success, ok := output["success"].(bool); !ok || !success {
		t.Errorf("Expected success=true, got %v", output["success"])
	}

	if rowsAffected, ok := output["rows_affected"].(int); !ok || rowsAffected != 3 {
		t.Errorf("Expected rows_affected=3, got %v", output["rows_affected"])
	}
}

// Test buildParameters
func TestMCPConnector_BuildParameters(t *testing.T) {
	processor := NewMCPConnectorProcessor()

	step := WorkflowStep{
		Parameters: map[string]interface{}{
			"param1": "value1",
			"param2": 42,
		},
	}

	input := map[string]interface{}{
		"param2": 100, // Override
		"param3": "value3",
	}

	execution := &WorkflowExecution{
		ID: "test-workflow",
	}

	params := processor.buildParameters(step, input, execution)

	if params["param1"] != "value1" {
		t.Errorf("Expected param1=value1, got %v", params["param1"])
	}

	if params["param2"] != 100 {
		t.Errorf("Expected param2=100 (overridden), got %v", params["param2"])
	}

	if params["param3"] != "value3" {
		t.Errorf("Expected param3=value3, got %v", params["param3"])
	}
}

// Test replaceTemplateVars - input variables
func TestMCPConnector_ReplaceTemplateVars_InputVars(t *testing.T) {
	processor := NewMCPConnectorProcessor()

	template := "Hello {{input.name}}, your ID is {{input.id}}"
	stepInput := map[string]interface{}{
		"name": "John",
		"id":   "12345",
	}

	execution := &WorkflowExecution{
		ID: "test-workflow",
	}

	result := processor.replaceTemplateVars(template, stepInput, execution)

	expected := "Hello John, your ID is 12345"
	if result != expected {
		t.Errorf("Expected %q, got %q", expected, result)
	}
}

// Test replaceTemplateVars - step output variables
func TestMCPConnector_ReplaceTemplateVars_StepOutputVars(t *testing.T) {
	processor := NewMCPConnectorProcessor()

	template := "Previous result: {{steps.step1.output.result}}"

	execution := &WorkflowExecution{
		ID: "test-workflow",
		Steps: []StepExecution{
			{
				Name:   "step1",
				Status: "completed",
				Output: map[string]interface{}{
					"result": "success",
				},
			},
		},
	}

	result := processor.replaceTemplateVars(template, map[string]interface{}{}, execution)

	expected := "Previous result: success"
	if result != expected {
		t.Errorf("Expected %q, got %q", expected, result)
	}
}

// Test replaceTemplateVars - workflow input variables
func TestMCPConnector_ReplaceTemplateVars_WorkflowInputVars(t *testing.T) {
	processor := NewMCPConnectorProcessor()

	template := "Processing {{workflow.input.document_id}}"

	execution := &WorkflowExecution{
		ID: "test-workflow",
		Input: map[string]interface{}{
			"document_id": "DOC-12345",
		},
	}

	result := processor.replaceTemplateVars(template, map[string]interface{}{}, execution)

	expected := "Processing DOC-12345"
	if result != expected {
		t.Errorf("Expected %q, got %q", expected, result)
	}
}

// Test formatResponse - generic formatting
func TestMCPConnector_FormatResponse_Generic(t *testing.T) {
	processor := NewMCPConnectorProcessor()

	rows := []map[string]interface{}{
		{"id": 1, "name": "test1"},
		{"id": 2, "name": "test2"},
	}

	result := processor.formatResponse("generic-step", rows)

	if !strings.Contains(result, "2 result(s)") {
		t.Error("Result should mention result count")
	}

	if !strings.Contains(result, "test1") || !strings.Contains(result, "test2") {
		t.Error("Result should contain row data")
	}
}

// Test formatResponse - empty results
func TestMCPConnector_FormatResponse_Empty(t *testing.T) {
	processor := NewMCPConnectorProcessor()

	result := processor.formatResponse("test-step", []map[string]interface{}{})

	expected := "No results found"
	if result != expected {
		t.Errorf("Expected %q, got %q", expected, result)
	}
}

// Test formatFlightResults
func TestMCPConnector_FormatFlightResults(t *testing.T) {
	processor := NewMCPConnectorProcessor()

	rows := []map[string]interface{}{
		{
			"price": map[string]interface{}{
				"total": "500.00",
			},
			"itineraries": []interface{}{
				"NYC to Paris departure",
			},
		},
		{
			"price": map[string]interface{}{
				"total": "600.00",
			},
		},
	}

	result := processor.formatFlightResults(rows)

	if !strings.Contains(result, "2 flight option(s)") {
		t.Error("Result should mention flight count")
	}

	if !strings.Contains(result, "500.00") {
		t.Error("Result should contain price")
	}
}

// Test formatHotelResults
func TestMCPConnector_FormatHotelResults(t *testing.T) {
	processor := NewMCPConnectorProcessor()

	rows := []map[string]interface{}{
		{
			"name":  "Grand Hotel",
			"price": "150",
		},
		{
			"name":  "Budget Inn",
			"price": "80",
		},
	}

	result := processor.formatHotelResults(rows)

	if !strings.Contains(result, "2 hotel option(s)") {
		t.Error("Result should mention hotel count")
	}

	if !strings.Contains(result, "Grand Hotel") {
		t.Error("Result should contain hotel name")
	}

	if !strings.Contains(result, "$150/night") {
		t.Error("Result should contain formatted price")
	}
}

// Note: isTravelQuery tests removed - business logic moved to clients

// Test formatResponse dispatches to flight formatter
func TestMCPConnector_FormatResponse_DispatchToFlight(t *testing.T) {
	processor := NewMCPConnectorProcessor()

	rows := []map[string]interface{}{
		{"price": map[string]interface{}{"total": "500.00"}},
	}

	result := processor.formatResponse("search-flights", rows)

	if !strings.Contains(result, "flight option") {
		t.Error("Should dispatch to flight formatter for flight-related step")
	}
}

// Test formatResponse dispatches to hotel formatter
func TestMCPConnector_FormatResponse_DispatchToHotel(t *testing.T) {
	processor := NewMCPConnectorProcessor()

	rows := []map[string]interface{}{
		{"name": "Test Hotel", "price": "100"},
	}

	result := processor.formatResponse("search-hotels", rows)

	if !strings.Contains(result, "hotel option") {
		t.Error("Should dispatch to hotel formatter for hotel-related step")
	}
}
