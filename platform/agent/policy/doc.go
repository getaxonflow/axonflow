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

/*
Package policy provides permission evaluation for MCP connector operations
in AxonFlow.

# Overview

The policy package implements the service identity permission system that
controls access to MCP connectors. It evaluates whether a service (identified
by its license) has permission to perform specific operations on connectors.

# Permission Format

Permissions follow a hierarchical format:

	mcp:connector:operation

Examples:
  - "mcp:amadeus:search_flights" - Specific operation on Amadeus connector
  - "mcp:amadeus:*" - All operations on Amadeus connector
  - "mcp:*" - All MCP operations (admin access)
  - "*" - Global wildcard (superuser)

# Usage

Create a permission evaluator:

	evaluator := policy.NewPermissionEvaluator()

Check if a service has permission:

	allowed, err := evaluator.EvaluateMCPPermission(
	    validationResult,  // From license validation
	    "amadeus",         // Connector name
	    "search_flights",  // Operation name
	)

	if !allowed {
	    return fmt.Errorf("permission denied: %v", err)
	}

# Permission Evaluation Order

The evaluator checks permissions in this order:
 1. Exact match: "mcp:amadeus:search_flights"
 2. Connector wildcard: "mcp:amadeus:*"
 3. MCP wildcard: "mcp:*"
 4. Global wildcard: "*"

# Service vs Organization Licenses

Only service licenses (with ServiceName set) can access MCP connectors.
Regular organization licenses are denied with an explicit error message.

# Validation

Validate permission strings before storage:

	err := policy.ValidatePermissionFormat("mcp:amadeus:search_flights")
	if err != nil {
	    return fmt.Errorf("invalid permission: %v", err)
	}

# Thread Safety

PermissionEvaluator is safe for concurrent use from multiple goroutines.
*/
package policy
