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

package policy

import (
	"fmt"

	"axonflow/platform/agent/license"
)

// PermissionEvaluator checks service permissions for MCP operations
// This is the core of the service identity permission system
type PermissionEvaluator struct {
	// Can add caching, logging, metrics here later
}

// NewPermissionEvaluator creates a new permission evaluator
func NewPermissionEvaluator() *PermissionEvaluator {
	return &PermissionEvaluator{}
}

// EvaluateMCPPermission checks if a service has permission for an MCP operation
//
// Permission format: "mcp:connector:operation"
// Examples:
//   - "mcp:amadeus:search_flights" - Specific operation
//   - "mcp:amadeus:*" - All Amadeus operations
//   - "mcp:*" - All MCP operations (admin)
//
// Returns:
//   - allowed: true if permission is granted
//   - error: descriptive error if permission denied or validation failed
func (pe *PermissionEvaluator) EvaluateMCPPermission(
	validationResult *license.ValidationResult,
	connector string,
	operation string,
) (bool, error) {
	// Validate inputs
	if validationResult == nil {
		return false, fmt.Errorf("license validation result is nil")
	}

	if !validationResult.Valid {
		return false, fmt.Errorf("license is not valid")
	}

	if connector == "" {
		return false, fmt.Errorf("connector name cannot be empty")
	}

	if operation == "" {
		return false, fmt.Errorf("operation name cannot be empty")
	}

	// Non-service licenses have no MCP permissions
	if validationResult.ServiceName == "" {
		return false, fmt.Errorf(
			"permission denied: regular org licenses cannot access MCP connectors directly (tenant=%s, connector=%s, operation=%s)",
			validationResult.OrgID,
			connector,
			operation,
		)
	}

	// Build required permission string
	requiredPerm := fmt.Sprintf("mcp:%s:%s", connector, operation)

	// Check exact permission
	if hasPermission(validationResult.Permissions, requiredPerm) {
		return true, nil
	}

	// Check wildcard connector permission: "mcp:amadeus:*"
	wildcardConnectorPerm := fmt.Sprintf("mcp:%s:*", connector)
	if hasPermission(validationResult.Permissions, wildcardConnectorPerm) {
		return true, nil
	}

	// Check global MCP wildcard: "mcp:*"
	if hasPermission(validationResult.Permissions, "mcp:*") {
		return true, nil
	}

	// Check absolute wildcard: "*"
	if hasPermission(validationResult.Permissions, "*") {
		return true, nil
	}

	// Permission denied
	return false, fmt.Errorf(
		"permission denied: service '%s' (tenant=%s, type=%s) does not have permission '%s' (has: %v)",
		validationResult.ServiceName,
		validationResult.OrgID,
		validationResult.ServiceType,
		requiredPerm,
		validationResult.Permissions,
	)
}

// hasPermission checks if a permission exists in the list
// Helper function for exact matching
func hasPermission(permissions []string, permission string) bool {
	for _, p := range permissions {
		if p == permission {
			return true
		}
	}
	return false
}

// ValidatePermissionFormat validates that a permission string follows the correct format
// Permission format: "resource:connector:operation" or "resource:connector:*"
//
// Valid examples:
//   - "mcp:amadeus:search_flights"
//   - "mcp:amadeus:*"
//   - "mcp:*"
//   - "*"
//
// Invalid examples:
//   - "amadeus:search_flights" (missing resource prefix)
//   - "mcp:" (incomplete)
//   - "::" (empty parts)
func ValidatePermissionFormat(permission string) error {
	if permission == "" {
		return fmt.Errorf("permission cannot be empty")
	}

	// Special cases: global wildcards
	if permission == "*" || permission == "mcp:*" {
		return nil
	}

	// Expected format: "mcp:connector:operation"
	// Must have at least 2 colons
	count := 0
	for _, c := range permission {
		if c == ':' {
			count++
		}
	}

	if count < 2 {
		return fmt.Errorf(
			"invalid permission format: '%s' (expected 'mcp:connector:operation', got %d colons, need at least 2)",
			permission,
			count,
		)
	}

	// Check for empty parts
	if permission[0] == ':' || permission[len(permission)-1] == ':' {
		return fmt.Errorf(
			"invalid permission format: '%s' (cannot start or end with colon)",
			permission,
		)
	}

	// Check for consecutive colons
	for i := 0; i < len(permission)-1; i++ {
		if permission[i] == ':' && permission[i+1] == ':' {
			return fmt.Errorf(
				"invalid permission format: '%s' (cannot have consecutive colons)",
				permission,
			)
		}
	}

	return nil
}

// GetRequiredPermission builds the required permission string for an MCP operation
// This is a helper function for error messages and logging
func GetRequiredPermission(connector, operation string) string {
	return fmt.Sprintf("mcp:%s:%s", connector, operation)
}
