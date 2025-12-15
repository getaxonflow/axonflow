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

package orchestrator

import (
	"context"
	"strings"
	"testing"
	"time"

	"axonflow/platform/connectors/base"
	"axonflow/platform/connectors/registry"
)

// Additional tests to reach 80%+ coverage for mcp_connector_processor.go
// Focus on ExecuteStep edge cases and tryFallback function

// Test ExecuteStep - write operation (synonym for execute)
func TestMCPConnector_ExecuteStep_WriteOperation(t *testing.T) {
	// Save original registry and restore after test
	originalRegistry := connectorRegistry
	defer func() { connectorRegistry = originalRegistry }()

	// Create registry with mock connector
	connectorRegistry = registry.NewRegistry()
	mockConn := &mockConnector{
		name: "test-connector",
		commandResult: &base.CommandResult{
			Success:      true,
			RowsAffected: 5,
			Duration:     10 * time.Millisecond,
			Message:      "5 rows updated",
			Connector:    "test-connector",
		},
	}
	_ = connectorRegistry.Register("test-connector", mockConn, &base.ConnectorConfig{Name: "test-connector"})

	processor := NewMCPConnectorProcessor()
	ctx := context.Background()

	step := WorkflowStep{
		Name:      "test-step",
		Connector: "test-connector",
		Operation: "write", // Test "write" synonym
		Action:    "UPDATE",
		Statement: "UPDATE test SET ...",
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

	if rowsAffected, ok := output["rows_affected"].(int); !ok || rowsAffected != 5 {
		t.Errorf("Expected rows_affected=5, got %v", output["rows_affected"])
	}
}

// Test ExecuteStep - default operation (should default to "query")
func TestMCPConnector_ExecuteStep_DefaultOperation(t *testing.T) {
	// Save original registry and restore after test
	originalRegistry := connectorRegistry
	defer func() { connectorRegistry = originalRegistry }()

	// Create registry with mock connector
	connectorRegistry = registry.NewRegistry()
	mockConn := &mockConnector{
		name: "test-connector",
	}
	_ = connectorRegistry.Register("test-connector", mockConn, &base.ConnectorConfig{Name: "test-connector"})

	processor := NewMCPConnectorProcessor()
	ctx := context.Background()

	step := WorkflowStep{
		Name:      "test-step",
		Connector: "test-connector",
		Operation: "", // Empty operation - should default to "query"
		Statement: "SELECT * FROM test",
	}

	execution := &WorkflowExecution{
		ID: "test-workflow",
	}

	output, err := processor.ExecuteStep(ctx, step, map[string]interface{}{}, execution)

	if err != nil {
		t.Fatalf("ExecuteStep() error = %v", err)
	}

	// Should execute as query (default)
	if rows, ok := output["rows"].([]map[string]interface{}); !ok || len(rows) == 0 {
		t.Error("Expected query results with rows")
	}
}

// Test ExecuteStep - empty results for non-travel query
func TestMCPConnector_ExecuteStep_EmptyResults(t *testing.T) {
	// Save original registry and restore after test
	originalRegistry := connectorRegistry
	defer func() { connectorRegistry = originalRegistry }()

	// Create registry with mock connector that returns empty results
	connectorRegistry = registry.NewRegistry()
	mockConn := &mockConnector{
		name: "test-connector",
		queryResult: &base.QueryResult{
			Rows:      []map[string]interface{}{}, // Empty results
			RowCount:  0,
			Duration:  10 * time.Millisecond,
			Connector: "test-connector",
		},
	}
	_ = connectorRegistry.Register("test-connector", mockConn, &base.ConnectorConfig{Name: "test-connector"})

	processor := NewMCPConnectorProcessor()
	ctx := context.Background()

	step := WorkflowStep{
		Name:      "database-query", // Non-travel step
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

	// Should return empty results
	if rows, ok := output["rows"].([]map[string]interface{}); !ok || len(rows) != 0 {
		t.Error("Expected empty rows in output")
	}

	if rowCount, ok := output["row_count"].(int); !ok || rowCount != 0 {
		t.Errorf("Expected row_count=0, got %v", output["row_count"])
	}
}

// Test buildParameters with template variables
func TestMCPConnector_BuildParameters_WithTemplates(t *testing.T) {
	processor := NewMCPConnectorProcessor()

	step := WorkflowStep{
		Parameters: map[string]interface{}{
			"query":  "Find {{input.destination}}",
			"count":  "{{input.max_results}}",
			"static": "static_value",
		},
	}

	input := map[string]interface{}{
		"destination":  "Paris",
		"max_results":  "10",
		"extra_param": "extra",
	}

	execution := &WorkflowExecution{
		ID: "test-workflow",
	}

	params := processor.buildParameters(step, input, execution)

	// Template should be replaced
	if params["query"] != "Find Paris" {
		t.Errorf("Expected query='Find Paris', got %v", params["query"])
	}

	if params["count"] != "10" {
		t.Errorf("Expected count='10', got %v", params["count"])
	}

	// Static value should remain
	if params["static"] != "static_value" {
		t.Errorf("Expected static='static_value', got %v", params["static"])
	}

	// Extra param should be included
	if params["extra_param"] != "extra" {
		t.Errorf("Expected extra_param='extra', got %v", params["extra_param"])
	}
}

// Test replaceTemplateVars with non-string values (should be ignored)
func TestMCPConnector_ReplaceTemplateVars_NonStringValues(t *testing.T) {
	processor := NewMCPConnectorProcessor()

	template := "Value: {{input.number}}"
	stepInput := map[string]interface{}{
		"number": 42, // Integer, not string - should not be replaced
	}

	execution := &WorkflowExecution{
		ID: "test-workflow",
	}

	result := processor.replaceTemplateVars(template, stepInput, execution)

	// Non-string values should not be replaced
	expected := "Value: {{input.number}}"
	if result != expected {
		t.Errorf("Expected %q (non-string should not be replaced), got %q", expected, result)
	}
}

// Test replaceTemplateVars with incomplete steps (non-completed status)
func TestMCPConnector_ReplaceTemplateVars_IncompleteSteps(t *testing.T) {
	processor := NewMCPConnectorProcessor()

	template := "Result: {{steps.step1.output.result}}"

	execution := &WorkflowExecution{
		ID: "test-workflow",
		Steps: []StepExecution{
			{
				Name:   "step1",
				Status: "failed", // Not completed
				Output: map[string]interface{}{
					"result": "should_not_be_used",
				},
			},
		},
	}

	result := processor.replaceTemplateVars(template, map[string]interface{}{}, execution)

	// Failed step output should not be used
	expected := "Result: {{steps.step1.output.result}}"
	if result != expected {
		t.Errorf("Expected %q (failed step should not be replaced), got %q", expected, result)
	}
}

// Test formatResponse with flight keyword in step name
func TestMCPConnector_FormatResponse_FlightKeyword(t *testing.T) {
	processor := NewMCPConnectorProcessor()

	rows := []map[string]interface{}{
		{"price": map[string]interface{}{"total": "400.00"}},
	}

	// Test with "flight" keyword (lowercase)
	result := processor.formatResponse("find-flight-options", rows)

	if !strings.Contains(result, "flight option") {
		t.Error("Should recognize 'flight' keyword in step name")
	}
}

// Test formatResponse with hotel keyword in step name
func TestMCPConnector_FormatResponse_HotelKeyword(t *testing.T) {
	processor := NewMCPConnectorProcessor()

	rows := []map[string]interface{}{
		{"name": "Hotel Test", "price": "100"},
	}

	// Test with "hotel" keyword (lowercase)
	result := processor.formatResponse("hotel-query", rows)

	if !strings.Contains(result, "hotel option") {
		t.Error("Should recognize 'hotel' keyword in step name")
	}
}

// Test formatFlightResults with missing price information
func TestMCPConnector_FormatFlightResults_MissingPrice(t *testing.T) {
	processor := NewMCPConnectorProcessor()

	rows := []map[string]interface{}{
		{
			"itineraries": []interface{}{"NYC to Paris"},
			// No price field
		},
	}

	result := processor.formatFlightResults(rows)

	// Should not crash, should still format
	if !strings.Contains(result, "Option 1") {
		t.Error("Should format flight even without price")
	}
}

// Test formatHotelResults with missing name
func TestMCPConnector_FormatHotelResults_MissingName(t *testing.T) {
	processor := NewMCPConnectorProcessor()

	rows := []map[string]interface{}{
		{
			"price": "120",
			// No name field
		},
	}

	result := processor.formatHotelResults(rows)

	// Should not crash, should still show price
	if !strings.Contains(result, "$120/night") {
		t.Error("Should format hotel even without name")
	}
}

// Test ExecuteStep with formatted response for successful query
func TestMCPConnector_ExecuteStep_WithFormattedResponse(t *testing.T) {
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
			},
			RowCount:  1,
			Duration:  10 * time.Millisecond,
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
	}

	execution := &WorkflowExecution{
		ID: "test-workflow",
	}

	output, err := processor.ExecuteStep(ctx, step, map[string]interface{}{}, execution)

	if err != nil {
		t.Fatalf("ExecuteStep() error = %v", err)
	}

	// Should include formatted response
	if response, ok := output["response"].(string); !ok || response == "" {
		t.Error("Expected formatted response in output")
	}
}
