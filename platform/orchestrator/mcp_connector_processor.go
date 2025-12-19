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
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"axonflow/platform/connectors/base"
)

// Internal service authentication constants for orchestrator-to-agent routing.
// These are used when the orchestrator needs to call MCP connectors on the agent
// without full user authentication context.
const (
	// InternalServiceClientID is the client ID used for internal orchestrator calls
	InternalServiceClientID = "orchestrator-internal"

	// InternalServiceTokenFallback is used when AXONFLOW_INTERNAL_SERVICE_SECRET is not configured.
	// This provides backwards compatibility for Community/development environments.
	// Production deployments should always set AXONFLOW_INTERNAL_SERVICE_SECRET.
	InternalServiceTokenFallback = "orchestrator-internal-token"

	// InternalServiceTenantID is the wildcard tenant ID for internal calls
	InternalServiceTenantID = "*"

	// InternalServiceSecretEnvVar is the environment variable for the shared secret
	InternalServiceSecretEnvVar = "AXONFLOW_INTERNAL_SERVICE_SECRET"

	// InternalServiceSecretMinLength is the recommended minimum length for the shared secret.
	// Secrets shorter than this will trigger a security warning at startup.
	InternalServiceSecretMinLength = 32
)

// internalServiceAuthWarningLogged tracks if we've already logged the fallback warning
// to avoid spamming logs on every call.
var internalServiceAuthWarningLogged bool

// LogInternalServiceAuthWarning logs a warning if fallback mode is being used.
// This should be called during startup to alert operators about security configuration.
// It only logs once per process lifetime to avoid log spam.
func LogInternalServiceAuthWarning() {
	if internalServiceAuthWarningLogged {
		return
	}
	secret := os.Getenv(InternalServiceSecretEnvVar)
	if secret == "" {
		log.Printf("[SECURITY WARNING] %s not configured - using fallback token for internal service auth. This is acceptable for development but NOT recommended for production. Set %s to a secure random string (minimum %d characters).",
			InternalServiceSecretEnvVar, InternalServiceSecretEnvVar, InternalServiceSecretMinLength)
	} else if len(secret) < InternalServiceSecretMinLength {
		log.Printf("[SECURITY WARNING] %s is only %d characters - recommend at least %d characters for production security.",
			InternalServiceSecretEnvVar, len(secret), InternalServiceSecretMinLength)
	}
	internalServiceAuthWarningLogged = true
}

// getInternalServiceToken returns the token to use for internal service auth.
// If AXONFLOW_INTERNAL_SERVICE_SECRET is set, uses that for secure auth.
// Otherwise falls back to the hardcoded token for Community/dev environments.
func getInternalServiceToken() string {
	if secret := os.Getenv(InternalServiceSecretEnvVar); secret != "" {
		return secret
	}
	return InternalServiceTokenFallback
}

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

	// Log security warning if internal service auth is using fallback token
	LogInternalServiceAuthWarning()
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

	// Try local registry first
	var connector base.Connector
	var localConnectorErr error

	if connectorRegistry != nil {
		connector, localConnectorErr = connectorRegistry.Get(connectorName)
	}

	// If connector not found locally, route to agent via MCPQueryRouter
	if connector == nil || localConnectorErr != nil {
		if mcpQueryRouter != nil {
			log.Printf("[MCP] Connector '%s' not found locally, routing to agent", connectorName)
			return p.routeToAgent(ctx, step, input, execution)
		}
		// No local connector and no router - return error
		promConnectorErrors.WithLabelValues(connectorName, "unknown", "connector_not_found").Inc()
		return nil, fmt.Errorf("connector '%s' not found (local registry: %v, agent router unavailable)", connectorName, localConnectorErr)
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

// routeToAgent routes a connector call to the agent via MCPQueryRouter
// This is used when the connector is not registered locally but may be available on the agent
func (p *MCPConnectorProcessor) routeToAgent(ctx context.Context, step WorkflowStep, input map[string]interface{}, execution *WorkflowExecution) (map[string]interface{}, error) {
	connectorName := step.Connector
	operation := step.Operation
	if operation == "" {
		operation = "query"
	}

	startTime := time.Now()

	// Build parameters
	params := p.buildParameters(step, input, execution)

	// Build OrchestratorRequest for routing
	req := OrchestratorRequest{
		RequestID:   execution.ID,
		Query:       step.Statement,
		RequestType: "mcp-query",
		User:        UserContext{}, // Will be populated from execution context if available
		Client:      ClientContext{},
		Context: map[string]interface{}{
			"connector":  connectorName,
			"params":     params,
			"operation":  operation,
			"step_name":  step.Name,
		},
		Timestamp: time.Now(),
	}

	// Extract client/user context from execution if available
	// Default to internal service credentials for orchestrator-to-agent routing
	req.Client.ID = InternalServiceClientID
	req.Client.TenantID = InternalServiceTenantID
	req.User.TenantID = InternalServiceTenantID
	// Set internal service token for orchestrator-to-agent routing
	// Uses AXONFLOW_INTERNAL_SERVICE_SECRET if configured, otherwise falls back to hardcoded token
	req.Context["user_token"] = getInternalServiceToken()

	if execution.Input != nil {
		if clientID, ok := execution.Input["client_id"].(string); ok && clientID != "" {
			req.Client.ID = clientID
		}
		if tenantID, ok := execution.Input["tenant_id"].(string); ok && tenantID != "" {
			req.Client.TenantID = tenantID
			req.User.TenantID = tenantID
		}
		if userToken, ok := execution.Input["user_token"].(string); ok && userToken != "" {
			req.Context["user_token"] = userToken
		}
	}

	log.Printf("[MCP] Routing connector '%s' operation '%s' to agent - step: %s", connectorName, operation, step.Name)

	// Route to agent
	resp, err := mcpQueryRouter.RouteToAgent(ctx, req)

	duration := time.Since(startTime)
	promConnectorDuration.WithLabelValues(connectorName, operation).Observe(float64(duration.Milliseconds()))

	if err != nil {
		promConnectorCalls.WithLabelValues(connectorName, operation, "error").Inc()
		promConnectorErrors.WithLabelValues(connectorName, operation, "agent_routing_failed").Inc()
		return nil, fmt.Errorf("failed to route connector '%s' to agent: %w", connectorName, err)
	}

	if !resp.Success {
		promConnectorCalls.WithLabelValues(connectorName, operation, "error").Inc()
		promConnectorErrors.WithLabelValues(connectorName, operation, "agent_returned_error").Inc()
		return nil, fmt.Errorf("agent connector call failed: %s", resp.Error)
	}

	promConnectorCalls.WithLabelValues(connectorName, operation, "success").Inc()
	log.Printf("[MCP] Agent connector '%s' operation completed successfully in %v", connectorName, duration)

	// Extract response data
	if data, ok := resp.Data.(map[string]interface{}); ok {
		// Add formatted response for easy access
		if rows, ok := data["rows"].([]interface{}); ok && len(rows) > 0 {
			rowMaps := make([]map[string]interface{}, 0, len(rows))
			for _, row := range rows {
				if rowMap, ok := row.(map[string]interface{}); ok {
					rowMaps = append(rowMaps, rowMap)
				}
			}
			if len(rowMaps) > 0 {
				data["response"] = p.formatResponse(step.Name, rowMaps)
			}
		}
		return data, nil
	}

	// Return raw data if not a map
	return map[string]interface{}{
		"data":      resp.Data,
		"connector": connectorName,
		"duration":  duration.String(),
	}, nil
}
