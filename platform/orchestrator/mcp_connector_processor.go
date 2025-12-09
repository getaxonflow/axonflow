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

package orchestrator

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"axonflow/platform/connectors/base"
)

// Prometheus metrics for MCP connectors
var (
	promConnectorCalls = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "axonflow_connector_calls_total",
			Help: "Total number of MCP connector calls",
		},
		[]string{"connector", "operation", "status"},
	)
	promConnectorDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "axonflow_connector_duration_milliseconds",
			Help:    "MCP connector call duration in milliseconds",
			Buckets: []float64{1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500},
		},
		[]string{"connector", "operation"},
	)
	promConnectorErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "axonflow_connector_errors_total",
			Help: "Total number of MCP connector errors",
		},
		[]string{"connector", "operation", "error_type"},
	)
)

func init() {
	// Register metrics
	prometheus.MustRegister(promConnectorCalls)
	prometheus.MustRegister(promConnectorDuration)
	prometheus.MustRegister(promConnectorErrors)
}

// MCPConnectorProcessor handles workflow steps that call MCP connectors
type MCPConnectorProcessor struct {
	// No direct connector access - use global registry
	// Note: Business logic fallbacks removed - clients handle their own fallback logic
}

func NewMCPConnectorProcessor() *MCPConnectorProcessor {
	return &MCPConnectorProcessor{}
}

// ExecuteStep executes a connector call step
func (p *MCPConnectorProcessor) ExecuteStep(ctx context.Context, step WorkflowStep, input map[string]interface{}, execution *WorkflowExecution) (map[string]interface{}, error) {
	connectorName := step.Connector
	if connectorName == "" {
		promConnectorErrors.WithLabelValues("unknown", "unknown", "missing_connector_name").Inc()
		return nil, fmt.Errorf("connector name not specified in step %s", step.Name)
	}

	// Get connector from registry
	if connectorRegistry == nil {
		promConnectorErrors.WithLabelValues(connectorName, "unknown", "registry_not_initialized").Inc()
		return nil, fmt.Errorf("connector registry not initialized")
	}

	connector, err := connectorRegistry.Get(connectorName)
	if err != nil {
		promConnectorErrors.WithLabelValues(connectorName, "unknown", "connector_not_found").Inc()
		return nil, fmt.Errorf("failed to get connector '%s': %v", connectorName, err)
	}

	// Build parameters from step configuration and input
	params := p.buildParameters(step, input, execution)

	// Determine if this is a query (read) or execute (write) operation
	operation := step.Operation
	if operation == "" {
		operation = "query" // Default to query
	}

	log.Printf("[MCP] Executing connector '%s' operation '%s' with params: %v", connectorName, operation, params)

	// Track metrics
	startTime := time.Now()
	var output map[string]interface{}
	var execErr error

	if operation == "execute" || operation == "write" {
		// Execute command (write operation)
		cmd := &base.Command{
			Action:     step.Action, // e.g., "POST", "PUT", "DELETE" for HTTP
			Statement:  step.Statement,
			Parameters: params,
		}

		result, execErr := connector.Execute(ctx, cmd)
		if execErr != nil {
			log.Printf("connector execute failed: %v", execErr)
		} else {
			output = map[string]interface{}{
				"success":       result.Success,
				"rows_affected": result.RowsAffected,
				"duration":      result.Duration.String(),
				"message":       result.Message,
				"connector":     result.Connector,
			}
		}
	} else {
		// Query operation (read)
		query := &base.Query{
			Statement:  step.Statement,  // e.g., "search_flights" for Amadeus
			Parameters: params,
		}

		result, execErr := connector.Query(ctx, query)
		if execErr != nil {
			// Note: Clients handle their own fallback logic - orchestrator returns errors
			log.Printf("connector query failed: %v", execErr)
		} else if len(result.Rows) == 0 {
			// No results from connector - return empty results (clients handle fallbacks)
			log.Printf("[MCP] Connector returned no results for step '%s'", step.Name)
			output = map[string]interface{}{
				"rows":      result.Rows,
				"row_count": result.RowCount,
				"duration":  result.Duration.String(),
				"cached":    result.Cached,
				"connector": result.Connector,
			}
		} else {
			output = map[string]interface{}{
				"rows":      result.Rows,
				"row_count": result.RowCount,
				"duration":  result.Duration.String(),
				"cached":    result.Cached,
				"connector": result.Connector,
			}

			// Also add a formatted response for easy access
			if len(result.Rows) > 0 {
				output["response"] = p.formatResponse(step.Name, result.Rows)
			}
		}
	}

	// Record metrics
	duration := time.Since(startTime)
	promConnectorDuration.WithLabelValues(connectorName, operation).Observe(float64(duration.Milliseconds()))

	if execErr != nil {
		promConnectorCalls.WithLabelValues(connectorName, operation, "error").Inc()
		promConnectorErrors.WithLabelValues(connectorName, operation, "execution_failed").Inc()
		return nil, execErr
	}

	promConnectorCalls.WithLabelValues(connectorName, operation, "success").Inc()
	log.Printf("[MCP] Connector '%s' operation completed successfully in %v", connectorName, duration)
	return output, nil
}

// buildParameters constructs parameters from step config and runtime inputs
func (p *MCPConnectorProcessor) buildParameters(step WorkflowStep, input map[string]interface{}, execution *WorkflowExecution) map[string]interface{} {
	params := make(map[string]interface{})

	// Start with step's configured parameters
	for k, v := range step.Parameters {
		params[k] = v
	}

	// Apply runtime input overrides
	for k, v := range input {
		params[k] = v
	}

	// Replace template variables in parameter values
	for k, v := range params {
		if strVal, ok := v.(string); ok {
			params[k] = p.replaceTemplateVars(strVal, input, execution)
		}
	}

	return params
}

// replaceTemplateVars replaces template variables in strings
func (p *MCPConnectorProcessor) replaceTemplateVars(template string, stepInput map[string]interface{}, execution *WorkflowExecution) string {
	result := template

	// Replace {{input.key}} variables
	for key, value := range stepInput {
		placeholder := fmt.Sprintf("{{input.%s}}", key)
		if str, ok := value.(string); ok {
			result = strings.ReplaceAll(result, placeholder, str)
		}
	}

	// Replace {{steps.stepname.output.key}} variables
	for _, stepExec := range execution.Steps {
		if stepExec.Status == "completed" {
			for key, value := range stepExec.Output {
				placeholder := fmt.Sprintf("{{steps.%s.output.%s}}", stepExec.Name, key)
				if str, ok := value.(string); ok {
					result = strings.ReplaceAll(result, placeholder, str)
				}
			}
		}
	}

	// Replace {{workflow.input.key}} variables
	for key, value := range execution.Input {
		placeholder := fmt.Sprintf("{{workflow.input.%s}}", key)
		if str, ok := value.(string); ok {
			result = strings.ReplaceAll(result, placeholder, str)
		}
	}

	return result
}

// formatResponse formats connector response rows into a human-readable string
func (p *MCPConnectorProcessor) formatResponse(stepName string, rows []map[string]interface{}) string {
	if len(rows) == 0 {
		return "No results found"
	}

	// For travel-related queries, format nicely
	if strings.Contains(stepName, "flight") || strings.Contains(stepName, "search-flights") {
		return p.formatFlightResults(rows)
	} else if strings.Contains(stepName, "hotel") || strings.Contains(stepName, "search-hotels") {
		return p.formatHotelResults(rows)
	}

	// Generic formatting
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("Found %d result(s):\n\n", len(rows)))

	for i, row := range rows {
		builder.WriteString(fmt.Sprintf("%d. ", i+1))
		for k, v := range row {
			builder.WriteString(fmt.Sprintf("%s: %v, ", k, v))
		}
		builder.WriteString("\n")
	}

	return builder.String()
}

// formatFlightResults formats flight search results
func (p *MCPConnectorProcessor) formatFlightResults(rows []map[string]interface{}) string {
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("Found %d flight option(s):\n\n", len(rows)))

	for i, row := range rows {
		builder.WriteString(fmt.Sprintf("Option %d:\n", i+1))

		if price, ok := row["price"].(map[string]interface{}); ok {
			if total, ok := price["total"].(string); ok {
				builder.WriteString(fmt.Sprintf("  Price: %s\n", total))
			}
		}

		if itineraries, ok := row["itineraries"].([]interface{}); ok && len(itineraries) > 0 {
			builder.WriteString("  Itinerary:\n")
			// Format first itinerary
			// (In production, would parse full Amadeus response structure)
			builder.WriteString(fmt.Sprintf("    %v\n", itineraries[0]))
		}

		builder.WriteString("\n")
	}

	return builder.String()
}

// formatHotelResults formats hotel search results
func (p *MCPConnectorProcessor) formatHotelResults(rows []map[string]interface{}) string {
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("Found %d hotel option(s):\n\n", len(rows)))

	for i, row := range rows {
		builder.WriteString(fmt.Sprintf("%d. ", i+1))

		if name, ok := row["name"].(string); ok {
			builder.WriteString(fmt.Sprintf("%s - ", name))
		}

		if price, ok := row["price"].(string); ok {
			builder.WriteString(fmt.Sprintf("$%s/night", price))
		}

		builder.WriteString("\n")
	}

	return builder.String()
}

// Note: Travel-specific fallback methods removed - business logic moved to clients
