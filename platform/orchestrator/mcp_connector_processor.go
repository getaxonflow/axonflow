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
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"axonflow/platform/connectors/base"
	"axonflow/platform/shared/secretenv"
	"axonflow/platform/shared/serviceauth"
)

// internalTokenGenerator is initialized at startup if AXONFLOW_INTERNAL_SERVICE_SECRET is configured.
// It generates HMAC-signed tokens for orchestrator-to-agent routing.
var internalTokenGenerator *serviceauth.TokenGenerator

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

	// Initialize HMAC token generator if secret is configured. Read via
	// secretenv.Get so the SM-derived value's trailing whitespace doesn't
	// produce a different digest from the agent-side validator.
	if secret := secretenv.Get(serviceauth.SecretEnvVar); secret != "" {
		internalTokenGenerator = serviceauth.NewTokenGenerator(secret, serviceauth.RealClock{})
	}
	serviceauth.LogAuthWarning()
}

// executionTenantID returns the tenancy a workflow execution is authorized to
// resolve connectors under.
//
// It reads ONLY UserContext — never `execution.Input`, which is the
// client-supplied request body and therefore forgeable. An empty result maps
// to the deployment-shared scope in the registry, i.e. an identity-less
// execution can reach the operator's own connectors and nothing tenant-owned.
//
// Be precise about where UserContext comes from, because it is NOT
// unconditionally authoritative. Both execution entrypoints overlay it from
// the agent's authenticated headers WHEN THOSE HEADERS ARE PRESENT:
// executeWorkflowHandler re-derives User.TenantID/User.OrgID from
// X-Tenant-ID/X-Org-ID inside `if header != ""` guards (run.go), and
// executePlanHandler calls applyAuthoritativeIdentity, which returns early
// when both headers are empty. `req.User` is itself a JSON body field, so a
// caller that reaches the orchestrator directly with NO identity headers still
// picks its own tenancy out of the body.
//
// That residual path is not this function's to close, and it is not a
// regression: before #3066 (C3-1) the body was preferred OVER the header, so
// the agent-proxied path is now strictly closed. What guarantees a
// caller cannot reach the orchestrator without an authenticated identity in
// the first place is the router-level gate in #3073 (#3064/#3068) — do not
// read the paragraph above as the whole security argument.
//
// Precedence is TENANT-first, matching the connector registry's WRITER and its
// other readers — not normalizeHITLScope, which is org-first (R3).
//
// The rule is "agree with the structure you are keying into", and the two
// structures have different writers:
//   - Connector registry: written by installConnectorHandler via
//     resolveTenantID, which prefers X-Tenant-ID; read by
//     gateway_handlers (user.TenantID), GetConnectorForTenant(tenantID, …) and
//     the marketplace handlers. All tenant-first.
//   - HITL execution store: written AND read through normalizeHITLScope itself,
//     so that one is self-consistently org-first.
//
// OrgID and TenantID come from independent sources (the license payload vs the
// client/customer record), so on a deployment where they diverge an org-first
// reader here would miss the tenant's OWN connector — a lockout, not a leak.
func executionTenantID(execution *WorkflowExecution) string {
	if execution == nil {
		return ""
	}
	if execution.UserContext.TenantID != "" {
		return execution.UserContext.TenantID
	}
	return execution.UserContext.OrgID
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

	// Try local registry first.
	//
	// #3067 (S-1, CRITICAL): connectorName is caller-supplied — it arrives
	// verbatim from `step.connector` in the POST /api/v1/workflows/execute and
	// MAP plan-execute bodies. It used to be handed to a flat, deployment-wide,
	// name-keyed map, so a tenant could name ANOTHER tenant's connector and
	// have the statement executed against it with the victim's ConnectionURL
	// and decrypted Credentials. The lookup is now scoped to the execution's
	// authenticated tenancy, which the handlers overlay from the agent's auth
	// chain (X-Tenant-ID / X-Org-ID) before the workflow is built — so naming
	// a foreign connector simply resolves nothing.
	var connector base.Connector
	var localConnectorErr error

	if connectorRegistry != nil {
		connector, localConnectorErr = connectorRegistry.Get(executionTenantID(execution), connectorName)
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
			Statement:  step.Statement, // e.g., "search_flights" for Amadeus
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
	fmt.Fprintf(&builder, "Found %d result(s):\n\n", len(rows))

	for i, row := range rows {
		fmt.Fprintf(&builder, "%d. ", i+1)
		for k, v := range row {
			fmt.Fprintf(&builder, "%s: %v, ", k, v)
		}
		builder.WriteString("\n")
	}

	return builder.String()
}

// formatFlightResults formats flight search results
func (p *MCPConnectorProcessor) formatFlightResults(rows []map[string]interface{}) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "Found %d flight option(s):\n\n", len(rows))

	for i, row := range rows {
		fmt.Fprintf(&builder, "Option %d:\n", i+1)

		if price, ok := row["price"].(map[string]interface{}); ok {
			if total, ok := price["total"].(string); ok {
				fmt.Fprintf(&builder, "  Price: %s\n", total)
			}
		}

		if itineraries, ok := row["itineraries"].([]interface{}); ok && len(itineraries) > 0 {
			builder.WriteString("  Itinerary:\n")
			// Format first itinerary
			// (In production, would parse full Amadeus response structure)
			fmt.Fprintf(&builder, "    %v\n", itineraries[0])
		}

		builder.WriteString("\n")
	}

	return builder.String()
}

// formatHotelResults formats hotel search results
func (p *MCPConnectorProcessor) formatHotelResults(rows []map[string]interface{}) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "Found %d hotel option(s):\n\n", len(rows))

	for i, row := range rows {
		fmt.Fprintf(&builder, "%d. ", i+1)

		if name, ok := row["name"].(string); ok {
			fmt.Fprintf(&builder, "%s - ", name)
		}

		if price, ok := row["price"].(string); ok {
			fmt.Fprintf(&builder, "$%s/night", price)
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
			"connector": connectorName,
			"params":    params,
			"operation": operation,
			"step_name": step.Name,
		},
		Timestamp: time.Now(),
	}

	// Extract client/user context from execution if available
	// Default to internal service credentials for orchestrator-to-agent routing
	req.Client.ID = serviceauth.ClientID
	req.Client.TenantID = serviceauth.TenantID
	req.User.TenantID = serviceauth.TenantID
	// Set internal service token for orchestrator-to-agent routing
	// Uses HMAC-signed token if secret is configured, otherwise falls back to hardcoded token
	req.Context["user_token"] = serviceauth.GetInternalServiceToken(internalTokenGenerator)

	// #3067 (R3 BLOCKER): the tenancy of a routed connector call comes from the
	// execution's AUTHENTICATED identity, never from execution.Input.
	//
	// This is the bypass of the local fix above. When the tenant-scoped local
	// lookup misses — which is precisely what happens when a caller names
	// ANOTHER tenant's connector — control lands here, and this block used to
	// let the request body pick the tenancy. The agent's internal-service auth
	// path adopts that value verbatim (authenticator.go: `tenantID :=
	// hints.TenantID`), so `{"input": {"tenant_id": "<victim>"}}` re-acquired
	// the victim's connector on the agent side, with the victim's decrypted
	// credentials — the very execution the local re-keying denies.
	if tenantID := executionTenantID(execution); tenantID != "" {
		req.Client.TenantID = tenantID
		req.User.TenantID = tenantID
	}

	// Nothing else is read from execution.Input. The previous `client_id` and
	// `user_token` overrides were already dead — RouteToAgent hardcodes
	// serviceauth.ClientID and re-derives the internal-service token — and
	// leaving them in place would arm a body-supplied service token the day
	// RouteToAgent started honouring them (R3).

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
