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
	"strings"
	"testing"

	"axonflow/platform/agent/license"
)

func TestPermissionEvaluator_EvaluateMCPPermission(t *testing.T) {
	pe := NewPermissionEvaluator()

	tests := []struct {
		name             string
		validationResult *license.ValidationResult
		connector        string
		operation        string
		wantAllowed      bool
		wantErrorContains string
	}{
		// Success cases - exact permission
		{
			name: "exact permission match",
			validationResult: &license.ValidationResult{
				Valid:       true,
				OrgID:       "travel-eu",
				ServiceName: "trip-planner",
				ServiceType: "client-application",
				Permissions: []string{"mcp:amadeus:search_flights"},
			},
			connector:   "amadeus",
			operation:   "search_flights",
			wantAllowed: true,
		},
		{
			name: "wildcard connector permission",
			validationResult: &license.ValidationResult{
				Valid:       true,
				OrgID:       "travel-eu",
				ServiceName: "trip-planner",
				Permissions: []string{"mcp:amadeus:*"},
			},
			connector:   "amadeus",
			operation:   "search_hotels",
			wantAllowed: true,
		},
		{
			name: "global MCP wildcard",
			validationResult: &license.ValidationResult{
				Valid:       true,
				OrgID:       "admin-org",
				ServiceName: "admin-service",
				Permissions: []string{"mcp:*"},
			},
			connector:   "salesforce",
			operation:   "query_contacts",
			wantAllowed: true,
		},
		{
			name: "absolute wildcard",
			validationResult: &license.ValidationResult{
				Valid:       true,
				OrgID:       "super-admin",
				ServiceName: "super-admin-service",
				Permissions: []string{"*"},
			},
			connector:   "any-connector",
			operation:   "any-operation",
			wantAllowed: true,
		},

		// Failure cases - permission denied
		{
			name: "no matching permission",
			validationResult: &license.ValidationResult{
				Valid:       true,
				OrgID:       "travel-eu",
				ServiceName: "trip-planner",
				Permissions: []string{"mcp:amadeus:search_flights"},
			},
			connector:         "amadeus",
			operation:         "search_hotels",
			wantAllowed:       false,
			wantErrorContains: "permission denied",
		},
		{
			name: "wrong connector permission",
			validationResult: &license.ValidationResult{
				Valid:       true,
				OrgID:       "travel-eu",
				ServiceName: "trip-planner",
				Permissions: []string{"mcp:slack:*"},
			},
			connector:         "amadeus",
			operation:         "search_flights",
			wantAllowed:       false,
			wantErrorContains: "does not have permission",
		},
		{
			name: "empty permissions list",
			validationResult: &license.ValidationResult{
				Valid:       true,
				OrgID:       "travel-eu",
				ServiceName: "limited-service",
				Permissions: []string{},
			},
			connector:         "amadeus",
			operation:         "search_flights",
			wantAllowed:       false,
			wantErrorContains: "does not have permission",
		},

		// Failure cases - non-service licenses
		{
			name: "regular org license - no service name",
			validationResult: &license.ValidationResult{
				Valid:       true,
				OrgID:       "acme",
				ServiceName: "", // Regular org license
				Permissions: []string{"mcp:amadeus:*"}, // Has permissions but not a service
			},
			connector:         "amadeus",
			operation:         "search_flights",
			wantAllowed:       false,
			wantErrorContains: "regular org licenses cannot access MCP connectors",
		},

		// Validation errors
		{
			name:              "nil validation result",
			validationResult:  nil,
			connector:         "amadeus",
			operation:         "search_flights",
			wantAllowed:       false,
			wantErrorContains: "validation result is nil",
		},
		{
			name: "invalid license",
			validationResult: &license.ValidationResult{
				Valid:       false, // Invalid license
				OrgID:       "travel-eu",
				ServiceName: "trip-planner",
			},
			connector:         "amadeus",
			operation:         "search_flights",
			wantAllowed:       false,
			wantErrorContains: "license is not valid",
		},
		{
			name: "empty connector name",
			validationResult: &license.ValidationResult{
				Valid:       true,
				OrgID:       "travel-eu",
				ServiceName: "trip-planner",
				Permissions: []string{"mcp:amadeus:*"},
			},
			connector:         "",
			operation:         "search_flights",
			wantAllowed:       false,
			wantErrorContains: "connector name cannot be empty",
		},
		{
			name: "empty operation name",
			validationResult: &license.ValidationResult{
				Valid:       true,
				OrgID:       "travel-eu",
				ServiceName: "trip-planner",
				Permissions: []string{"mcp:amadeus:*"},
			},
			connector:         "amadeus",
			operation:         "",
			wantAllowed:       false,
			wantErrorContains: "operation name cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, err := pe.EvaluateMCPPermission(tt.validationResult, tt.connector, tt.operation)

			if allowed != tt.wantAllowed {
				t.Errorf("EvaluateMCPPermission() allowed = %v, want %v", allowed, tt.wantAllowed)
			}

			if tt.wantAllowed {
				// Success case - should have no error
				if err != nil {
					t.Errorf("EvaluateMCPPermission() unexpected error = %v", err)
				}
			} else {
				// Failure case - should have error with expected message
				if err == nil {
					t.Error("EvaluateMCPPermission() expected error but got nil")
				} else if !strings.Contains(err.Error(), tt.wantErrorContains) {
					t.Errorf("EvaluateMCPPermission() error = %v, want error containing %q", err, tt.wantErrorContains)
				}
			}
		})
	}
}

func TestValidatePermissionFormat(t *testing.T) {
	tests := []struct {
		name       string
		permission string
		wantError  bool
		errorSubstr string
	}{
		// Valid formats
		{
			name:       "valid full permission",
			permission: "mcp:amadeus:search_flights",
			wantError:  false,
		},
		{
			name:       "valid wildcard connector",
			permission: "mcp:amadeus:*",
			wantError:  false,
		},
		{
			name:       "valid global MCP wildcard",
			permission: "mcp:*",
			wantError:  false,
		},
		{
			name:       "valid absolute wildcard",
			permission: "*",
			wantError:  false,
		},
		{
			name:       "valid four-part permission",
			permission: "mcp:connector:resource:operation",
			wantError:  false,
		},

		// Invalid formats
		{
			name:        "empty permission",
			permission:  "",
			wantError:   true,
			errorSubstr: "cannot be empty",
		},
		{
			name:        "missing resource prefix",
			permission:  "amadeus:search_flights",
			wantError:   true,
			errorSubstr: "expected 'mcp:connector:operation'",
		},
		{
			name:        "incomplete permission - one colon",
			permission:  "mcp:amadeus",
			wantError:   true,
			errorSubstr: "expected 'mcp:connector:operation'",
		},
		{
			name:        "starts with colon",
			permission:  ":mcp:amadeus:search",
			wantError:   true,
			errorSubstr: "cannot start or end with colon",
		},
		{
			name:        "ends with colon",
			permission:  "mcp:amadeus:search:",
			wantError:   true,
			errorSubstr: "cannot start or end with colon",
		},
		{
			name:        "consecutive colons",
			permission:  "mcp::amadeus:search",
			wantError:   true,
			errorSubstr: "cannot have consecutive colons",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePermissionFormat(tt.permission)

			if tt.wantError {
				if err == nil {
					t.Error("ValidatePermissionFormat() expected error but got nil")
				} else if tt.errorSubstr != "" && !strings.Contains(err.Error(), tt.errorSubstr) {
					t.Errorf("ValidatePermissionFormat() error = %v, want error containing %q", err, tt.errorSubstr)
				}
			} else {
				if err != nil {
					t.Errorf("ValidatePermissionFormat() unexpected error = %v", err)
				}
			}
		})
	}
}

func TestGetRequiredPermission(t *testing.T) {
	tests := []struct {
		name      string
		connector string
		operation string
		want      string
	}{
		{
			name:      "standard permission",
			connector: "amadeus",
			operation: "search_flights",
			want:      "mcp:amadeus:search_flights",
		},
		{
			name:      "different connector",
			connector: "salesforce",
			operation: "query_contacts",
			want:      "mcp:salesforce:query_contacts",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetRequiredPermission(tt.connector, tt.operation)
			if got != tt.want {
				t.Errorf("GetRequiredPermission() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewPermissionEvaluator(t *testing.T) {
	pe := NewPermissionEvaluator()
	if pe == nil {
		t.Error("NewPermissionEvaluator() returned nil")
	}
}

// Benchmark tests
func BenchmarkPermissionEvaluator_EvaluateMCPPermission(b *testing.B) {
	pe := NewPermissionEvaluator()
	validationResult := &license.ValidationResult{
		Valid:       true,
		OrgID:       "travel-eu",
		ServiceName: "trip-planner",
		Permissions: []string{"mcp:amadeus:search_flights", "mcp:amadeus:search_hotels", "mcp:slack:send_message"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = pe.EvaluateMCPPermission(validationResult, "amadeus", "search_flights")
	}
}

func BenchmarkPermissionEvaluator_EvaluateMCPPermission_Wildcard(b *testing.B) {
	pe := NewPermissionEvaluator()
	validationResult := &license.ValidationResult{
		Valid:       true,
		OrgID:       "travel-eu",
		ServiceName: "trip-planner",
		Permissions: []string{"mcp:amadeus:*"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = pe.EvaluateMCPPermission(validationResult, "amadeus", "search_flights")
	}
}
