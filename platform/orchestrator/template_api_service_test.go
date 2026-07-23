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
	"testing"
)

func TestTemplateService_ValidateApplyRequest(t *testing.T) {
	service := &TemplateService{}

	tests := []struct {
		name     string
		template *PolicyTemplate
		req      *ApplyTemplateRequest
		wantErr  bool
		errField string
	}{
		{
			name: "valid request with all required variables",
			template: &PolicyTemplate{
				Variables: []TemplateVariable{
					{Name: "threshold", Required: true, Type: "number"},
					{Name: "window", Required: false, Type: "number", Default: 60},
				},
			},
			req: &ApplyTemplateRequest{
				PolicyName: "My Policy",
				Variables:  map[string]interface{}{"threshold": 100},
			},
			wantErr: false,
		},
		{
			name: "missing policy name",
			template: &PolicyTemplate{
				Variables: []TemplateVariable{},
			},
			req: &ApplyTemplateRequest{
				PolicyName: "",
				Variables:  map[string]interface{}{},
			},
			wantErr:  true,
			errField: "policy_name",
		},
		{
			name: "policy name too short",
			template: &PolicyTemplate{
				Variables: []TemplateVariable{},
			},
			req: &ApplyTemplateRequest{
				PolicyName: "ab",
				Variables:  map[string]interface{}{},
			},
			wantErr:  true,
			errField: "policy_name",
		},
		{
			name: "policy name too long",
			template: &PolicyTemplate{
				Variables: []TemplateVariable{},
			},
			req: &ApplyTemplateRequest{
				PolicyName: string(make([]byte, 101)), // 101 characters
				Variables:  map[string]interface{}{},
			},
			wantErr:  true,
			errField: "policy_name",
		},
		{
			name: "description too long",
			template: &PolicyTemplate{
				Variables: []TemplateVariable{},
			},
			req: &ApplyTemplateRequest{
				PolicyName:  "Valid Name",
				Description: string(make([]byte, 501)), // 501 characters
				Variables:   map[string]interface{}{},
			},
			wantErr:  true,
			errField: "description",
		},
		{
			name: "missing required variable",
			template: &PolicyTemplate{
				Variables: []TemplateVariable{
					{Name: "threshold", Required: true, Type: "number"},
				},
			},
			req: &ApplyTemplateRequest{
				PolicyName: "My Policy",
				Variables:  map[string]interface{}{},
			},
			wantErr:  true,
			errField: "variables.threshold",
		},
		{
			name: "variable fails validation pattern",
			template: &PolicyTemplate{
				Variables: []TemplateVariable{
					{Name: "email", Required: true, Type: "string", Validation: `^[\w.]+@[\w.]+$`},
				},
			},
			req: &ApplyTemplateRequest{
				PolicyName: "My Policy",
				Variables:  map[string]interface{}{"email": "invalid-email"},
			},
			wantErr:  true,
			errField: "variables.email",
		},
		{
			name: "variable passes validation pattern",
			template: &PolicyTemplate{
				Variables: []TemplateVariable{
					{Name: "email", Required: true, Type: "string", Validation: `^[\w.]+@[\w.]+$`},
				},
			},
			req: &ApplyTemplateRequest{
				PolicyName: "My Policy",
				Variables:  map[string]interface{}{"email": "user@example.com"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := service.validateApplyRequest(tt.template, tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateApplyRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != nil {
				validationErr, ok := err.(*TemplateValidationError)
				if !ok {
					t.Errorf("Expected TemplateValidationError, got %T", err)
					return
				}
				// Check that the expected field is in the errors
				found := false
				for _, fieldErr := range validationErr.Errors {
					if fieldErr.Field == tt.errField {
						found = true
						break
					}
				}
				if !found && tt.errField != "" {
					t.Errorf("Expected error for field %s, got errors: %v", tt.errField, validationErr.Errors)
				}
			}
		})
	}
}

func TestTemplateService_SubstituteString(t *testing.T) {
	service := &TemplateService{}

	tests := []struct {
		name      string
		input     string
		variables map[string]interface{}
		expected  interface{}
	}{
		{
			name:      "simple string substitution",
			input:     "Hello, {{name}}!",
			variables: map[string]interface{}{"name": "World"},
			expected:  "Hello, World!",
		},
		{
			name:      "multiple substitutions",
			input:     "{{greeting}}, {{name}}!",
			variables: map[string]interface{}{"greeting": "Hello", "name": "World"},
			expected:  "Hello, World!",
		},
		{
			name:      "entire string is variable - preserves type (number)",
			input:     "{{count}}",
			variables: map[string]interface{}{"count": 42},
			expected:  42,
		},
		{
			name:      "entire string is variable - preserves type (boolean)",
			input:     "{{enabled}}",
			variables: map[string]interface{}{"enabled": true},
			expected:  true,
		},
		{
			name:      "entire string is variable - preserves type (array)",
			input:     "{{items}}",
			variables: map[string]interface{}{"items": []string{"a", "b", "c"}},
			expected:  []string{"a", "b", "c"},
		},
		{
			name:      "missing variable - unchanged",
			input:     "Hello, {{unknown}}!",
			variables: map[string]interface{}{},
			expected:  "Hello, {{unknown}}!",
		},
		{
			name:      "no variables in string",
			input:     "Plain text with no variables",
			variables: map[string]interface{}{"foo": "bar"},
			expected:  "Plain text with no variables",
		},
		{
			name:      "number in string context",
			input:     "Value is {{value}} units",
			variables: map[string]interface{}{"value": 100},
			expected:  "Value is 100 units",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := service.substituteString(tt.input, tt.variables)

			// Handle slice comparison
			switch expected := tt.expected.(type) {
			case []string:
				gotSlice, ok := got.([]string)
				if !ok {
					t.Errorf("substituteString() type = %T, want []string", got)
					return
				}
				if len(gotSlice) != len(expected) {
					t.Errorf("substituteString() = %v, want %v", got, tt.expected)
					return
				}
				for i := range expected {
					if gotSlice[i] != expected[i] {
						t.Errorf("substituteString() = %v, want %v", got, tt.expected)
						return
					}
				}
			default:
				if got != tt.expected {
					t.Errorf("substituteString() = %v, want %v", got, tt.expected)
				}
			}
		})
	}
}

func TestTemplateService_DeepSubstitute(t *testing.T) {
	service := &TemplateService{}

	variables := map[string]interface{}{
		"threshold":    100,
		"window":       60,
		"action_type":  "rate_limit",
		"message":      "Rate limited",
		"field_name":   "requests",
		"numeric_list": []int{1, 2, 3},
	}

	tests := []struct {
		name    string
		input   interface{}
		checkFn func(result interface{}) bool
		desc    string
	}{
		{
			name: "nested map substitution",
			input: map[string]interface{}{
				"type": "{{action_type}}",
				"config": map[string]interface{}{
					"limit":   "{{threshold}}",
					"window":  "{{window}}",
					"message": "{{message}}",
				},
			},
			checkFn: func(result interface{}) bool {
				m, ok := result.(map[string]interface{})
				if !ok {
					return false
				}
				if m["type"] != "rate_limit" {
					return false
				}
				config, ok := m["config"].(map[string]interface{})
				if !ok {
					return false
				}
				return config["limit"] == 100 && config["window"] == 60 && config["message"] == "Rate limited"
			},
			desc: "nested map with variable substitutions",
		},
		{
			name: "array of maps substitution",
			input: []interface{}{
				map[string]interface{}{
					"field":    "{{field_name}}",
					"operator": "gt",
					"value":    "{{threshold}}",
				},
			},
			checkFn: func(result interface{}) bool {
				arr, ok := result.([]interface{})
				if !ok || len(arr) != 1 {
					return false
				}
				m, ok := arr[0].(map[string]interface{})
				if !ok {
					return false
				}
				return m["field"] == "requests" && m["value"] == 100
			},
			desc: "array of maps with substitutions",
		},
		{
			name:  "primitive value unchanged",
			input: 42,
			checkFn: func(result interface{}) bool {
				return result == 42
			},
			desc: "primitive number unchanged",
		},
		{
			name:  "boolean unchanged",
			input: true,
			checkFn: func(result interface{}) bool {
				return result == true
			},
			desc: "boolean unchanged",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := service.deepSubstitute(tt.input, variables)
			if err != nil {
				t.Errorf("deepSubstitute() error = %v", err)
				return
			}
			if !tt.checkFn(result) {
				t.Errorf("deepSubstitute() failed check for: %s, got: %v", tt.desc, result)
			}
		})
	}
}

func TestTemplateService_SubstituteVariables(t *testing.T) {
	service := &TemplateService{}

	template := map[string]interface{}{
		"type":     "rate_limit",
		"priority": "{{priority}}",
		"conditions": []interface{}{
			map[string]interface{}{
				"field":    "requests",
				"operator": "gt",
				"value":    "{{threshold}}",
			},
		},
		"actions": []interface{}{
			map[string]interface{}{
				"type": "rate_limit",
				"config": map[string]interface{}{
					"limit":  "{{threshold}}",
					"window": "{{window}}",
				},
			},
		},
	}

	varDefs := []TemplateVariable{
		{Name: "threshold", Required: true, Default: nil},
		{Name: "window", Required: false, Default: 60},
		{Name: "priority", Required: false, Default: 50},
	}

	values := map[string]interface{}{
		"threshold": 100,
		// window not provided - should use default
		// priority not provided - should use default
	}

	result, err := service.substituteVariables(template, varDefs, values)
	if err != nil {
		t.Fatalf("substituteVariables() error = %v", err)
	}

	// Verify priority used default
	if result["priority"] != 50 {
		t.Errorf("Expected priority default 50, got %v", result["priority"])
	}

	// Verify conditions
	conditions, ok := result["conditions"].([]interface{})
	if !ok || len(conditions) != 1 {
		t.Fatalf("Expected conditions array with 1 element, got %v", result["conditions"])
	}
	condMap, ok := conditions[0].(map[string]interface{})
	if !ok {
		t.Fatal("Expected condition to be a map")
	}
	if condMap["value"] != 100 {
		t.Errorf("Expected condition value 100, got %v", condMap["value"])
	}

	// Verify actions
	actions, ok := result["actions"].([]interface{})
	if !ok || len(actions) != 1 {
		t.Fatalf("Expected actions array with 1 element, got %v", result["actions"])
	}
	actMap, ok := actions[0].(map[string]interface{})
	if !ok {
		t.Fatal("Expected action to be a map")
	}
	config, ok := actMap["config"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected action config to be a map")
	}
	if config["limit"] != 100 {
		t.Errorf("Expected limit 100, got %v", config["limit"])
	}
	if config["window"] != 60 {
		t.Errorf("Expected window 60 (default), got %v", config["window"])
	}
}

func TestTemplateService_ExtractPolicyFields(t *testing.T) {
	service := &TemplateService{}

	tests := []struct {
		name         string
		template     map[string]interface{}
		wantType     string
		wantPriority int
		wantCondLen  int
		wantActLen   int
		wantErr      bool
	}{
		{
			name: "valid template",
			template: map[string]interface{}{
				"type":     "content",
				"priority": float64(75),
				"conditions": []interface{}{
					map[string]interface{}{
						"field":    "query",
						"operator": "contains",
						"value":    "password",
					},
				},
				"actions": []interface{}{
					map[string]interface{}{
						"type": "block",
						"config": map[string]interface{}{
							"message": "Blocked",
						},
					},
				},
			},
			wantType:     "content",
			wantPriority: 75,
			wantCondLen:  1,
			wantActLen:   1,
			wantErr:      false,
		},
		{
			name: "default type and priority",
			template: map[string]interface{}{
				"conditions": []interface{}{
					map[string]interface{}{
						"field":    "query",
						"operator": "contains",
						"value":    "test",
					},
				},
				"actions": []interface{}{
					map[string]interface{}{
						"type":   "log",
						"config": map[string]interface{}{},
					},
				},
			},
			wantType:     "content",
			wantPriority: 50,
			wantCondLen:  1,
			wantActLen:   1,
			wantErr:      false,
		},
		{
			name: "multiple conditions and actions",
			template: map[string]interface{}{
				"type":     "security",
				"priority": float64(90),
				"conditions": []interface{}{
					map[string]interface{}{"field": "query", "operator": "contains", "value": "password"},
					map[string]interface{}{"field": "query", "operator": "regex", "value": "\\d{3}-\\d{2}-\\d{4}"},
				},
				"actions": []interface{}{
					map[string]interface{}{"type": "block", "config": map[string]interface{}{}},
					map[string]interface{}{"type": "alert", "config": map[string]interface{}{}},
				},
			},
			wantType:     "security",
			wantPriority: 90,
			wantCondLen:  2,
			wantActLen:   2,
			wantErr:      false,
		},
		{
			name: "missing conditions",
			template: map[string]interface{}{
				"type": "content",
				"actions": []interface{}{
					map[string]interface{}{"type": "block", "config": map[string]interface{}{}},
				},
			},
			wantErr: true,
		},
		{
			name: "missing actions",
			template: map[string]interface{}{
				"type": "content",
				"conditions": []interface{}{
					map[string]interface{}{"field": "query", "operator": "contains", "value": "test"},
				},
			},
			wantErr: true,
		},
		{
			name: "empty conditions array",
			template: map[string]interface{}{
				"type":       "content",
				"conditions": []interface{}{},
				"actions": []interface{}{
					map[string]interface{}{"type": "block", "config": map[string]interface{}{}},
				},
			},
			wantErr: true,
		},
		{
			name: "empty actions array",
			template: map[string]interface{}{
				"type": "content",
				"conditions": []interface{}{
					map[string]interface{}{"field": "query", "operator": "contains", "value": "test"},
				},
				"actions": []interface{}{},
			},
			wantErr: true,
		},
		{
			name: "integer priority",
			template: map[string]interface{}{
				"type":     "content",
				"priority": 25,
				"conditions": []interface{}{
					map[string]interface{}{"field": "query", "operator": "contains", "value": "test"},
				},
				"actions": []interface{}{
					map[string]interface{}{"type": "log", "config": map[string]interface{}{}},
				},
			},
			wantType:     "content",
			wantPriority: 25,
			wantCondLen:  1,
			wantActLen:   1,
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policyType, conditions, actions, priority, err := service.extractPolicyFields(tt.template)

			if (err != nil) != tt.wantErr {
				t.Errorf("extractPolicyFields() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if policyType != tt.wantType {
					t.Errorf("extractPolicyFields() type = %v, want %v", policyType, tt.wantType)
				}
				if priority != tt.wantPriority {
					t.Errorf("extractPolicyFields() priority = %v, want %v", priority, tt.wantPriority)
				}
				if len(conditions) != tt.wantCondLen {
					t.Errorf("extractPolicyFields() conditions len = %v, want %v", len(conditions), tt.wantCondLen)
				}
				if len(actions) != tt.wantActLen {
					t.Errorf("extractPolicyFields() actions len = %v, want %v", len(actions), tt.wantActLen)
				}
			}
		})
	}
}

func TestTemplateValidationError_Error(t *testing.T) {
	err := &TemplateValidationError{
		Errors: []TemplateFieldError{
			{Field: "policy_name", Message: "Policy name is required"},
			{Field: "variables.threshold", Message: "Threshold must be positive"},
		},
	}

	errStr := err.Error()

	if errStr == "" {
		t.Error("Expected non-empty error string")
	}

	// Check that both field errors are in the string
	if !containsSubstring(errStr, "policy_name") {
		t.Error("Expected error string to contain 'policy_name'")
	}
	if !containsSubstring(errStr, "variables.threshold") {
		t.Error("Expected error string to contain 'variables.threshold'")
	}
}

func TestGetStringFromMap(t *testing.T) {
	tests := []struct {
		name     string
		m        map[string]interface{}
		key      string
		expected string
	}{
		{
			name:     "existing string key",
			m:        map[string]interface{}{"name": "test"},
			key:      "name",
			expected: "test",
		},
		{
			name:     "missing key",
			m:        map[string]interface{}{"name": "test"},
			key:      "missing",
			expected: "",
		},
		{
			name:     "non-string value",
			m:        map[string]interface{}{"count": 42},
			key:      "count",
			expected: "",
		},
		{
			name:     "empty map",
			m:        map[string]interface{}{},
			key:      "anything",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getStringFromMap(tt.m, tt.key)
			if got != tt.expected {
				t.Errorf("getStringFromMap() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// Helper function
func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstringHelper(s, substr))
}

func containsSubstringHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestTemplateService_SubstituteString_Float64(t *testing.T) {
	service := &TemplateService{}

	// Test that float64 values in strings are properly converted
	tests := []struct {
		name      string
		input     string
		variables map[string]interface{}
		expected  interface{}
	}{
		{
			name:      "float64 in string context",
			input:     "Value: {{rate}}%",
			variables: map[string]interface{}{"rate": float64(99.5)},
			expected:  "Value: 99.5%",
		},
		{
			name:      "entire string is float64 variable",
			input:     "{{rate}}",
			variables: map[string]interface{}{"rate": float64(0.5)},
			expected:  float64(0.5),
		},
		{
			name:      "boolean false in string",
			input:     "Enabled: {{flag}}",
			variables: map[string]interface{}{"flag": false},
			expected:  "Enabled: false",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := service.substituteString(tt.input, tt.variables)
			if got != tt.expected {
				t.Errorf("substituteString() = %v (%T), want %v (%T)", got, got, tt.expected, tt.expected)
			}
		})
	}
}

func TestTemplateService_DeepSubstitute_EdgeCases(t *testing.T) {
	service := &TemplateService{}
	variables := map[string]interface{}{"x": "y"}

	tests := []struct {
		name    string
		input   interface{}
		wantNil bool
	}{
		{
			name:    "nil input",
			input:   nil,
			wantNil: true,
		},
		{
			name:  "empty slice",
			input: []interface{}{},
		},
		{
			name:  "empty map",
			input: map[string]interface{}{},
		},
		{
			name:  "nested nil in slice",
			input: []interface{}{nil, "test"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := service.deepSubstitute(tt.input, variables)
			if err != nil {
				t.Errorf("deepSubstitute() unexpected error = %v", err)
				return
			}
			if tt.wantNil && result != nil {
				t.Errorf("deepSubstitute() = %v, want nil", result)
			}
		})
	}
}

func TestTemplateService_SubstituteVariables_NilDefaults(t *testing.T) {
	service := &TemplateService{}

	template := map[string]interface{}{
		"value": "{{optional}}",
	}

	varDefs := []TemplateVariable{
		{Name: "optional", Required: false, Default: nil},
	}

	values := map[string]interface{}{}

	result, err := service.substituteVariables(template, varDefs, values)
	if err != nil {
		t.Fatalf("substituteVariables() error = %v", err)
	}

	// When no value and no default, variable should remain unsubstituted
	if result["value"] != "{{optional}}" {
		t.Errorf("Expected unsubstituted variable, got %v", result["value"])
	}
}

func TestTemplateService_ValidateApplyRequest_WithPriority(t *testing.T) {
	service := &TemplateService{}

	template := &PolicyTemplate{
		Variables: []TemplateVariable{},
	}

	// Valid priority should pass
	priority := 50
	req := &ApplyTemplateRequest{
		PolicyName: "Valid Name",
		Priority:   &priority,
	}

	err := service.validateApplyRequest(template, req)
	if err != nil {
		t.Errorf("Expected no error for valid priority, got %v", err)
	}
}

// =============================================================================
// Additional edge case tests to improve coverage
// =============================================================================

func TestValidateApplyRequest_MultipleErrors(t *testing.T) {
	service := &TemplateService{}

	template := &PolicyTemplate{
		Variables: []TemplateVariable{
			{Name: "required_var", Required: true, Type: "string"},
			{Name: "another_required", Required: true, Type: "number"},
		},
	}

	// Empty name AND missing required variables should produce multiple errors
	req := &ApplyTemplateRequest{
		PolicyName:  "",
		Description: string(make([]byte, 501)),
		Variables:   map[string]interface{}{},
	}

	err := service.validateApplyRequest(template, req)
	if err == nil {
		t.Fatal("Expected validation error, got nil")
	}

	validationErr, ok := err.(*TemplateValidationError)
	if !ok {
		t.Fatalf("Expected *TemplateValidationError, got %T", err)
	}

	// Should have at least 4 errors: policy_name, description, required_var, another_required
	if len(validationErr.Errors) < 4 {
		t.Errorf("Expected at least 4 errors, got %d: %v", len(validationErr.Errors), validationErr.Errors)
	}

	// The Error() method should join them with semicolons
	errStr := validationErr.Error()
	if !containsSubstring(errStr, ";") {
		t.Errorf("Expected semicolons in multi-error string, got: %s", errStr)
	}
}

func TestValidateApplyRequest_ExactBoundaryLengths(t *testing.T) {
	service := &TemplateService{}

	template := &PolicyTemplate{
		Variables: []TemplateVariable{},
	}

	tests := []struct {
		name    string
		req     *ApplyTemplateRequest
		wantErr bool
	}{
		{
			name: "exactly 3-char policy name is valid",
			req: &ApplyTemplateRequest{
				PolicyName: "abc",
				Variables:  map[string]interface{}{},
			},
			wantErr: false,
		},
		{
			name: "exactly 100-char policy name is valid",
			req: &ApplyTemplateRequest{
				PolicyName: string(make([]byte, 100)),
				Variables:  map[string]interface{}{},
			},
			// NOTE: make([]byte, 100) produces null bytes - depends on implementation
			// The actual string has 100 characters of \x00, still length 100
			wantErr: false,
		},
		{
			name: "exactly 500-char description is valid",
			req: &ApplyTemplateRequest{
				PolicyName:  "Valid Name",
				Description: string(make([]byte, 500)),
				Variables:   map[string]interface{}{},
			},
			wantErr: false,
		},
		{
			name: "non-string variable skips pattern validation",
			req: &ApplyTemplateRequest{
				PolicyName: "Valid Name",
				Variables:  map[string]interface{}{"count": 42},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := service.validateApplyRequest(template, tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateApplyRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateApplyRequest_NonStringVariableSkipsPatternValidation(t *testing.T) {
	service := &TemplateService{}

	// A variable with a validation pattern, but the value provided is a number (not a string)
	// Should not fail — pattern validation only applies to string values
	template := &PolicyTemplate{
		Variables: []TemplateVariable{
			{Name: "threshold", Required: true, Type: "number", Validation: `^\d+$`},
		},
	}

	req := &ApplyTemplateRequest{
		PolicyName: "Valid Name",
		Variables:  map[string]interface{}{"threshold": 100},
	}

	err := service.validateApplyRequest(template, req)
	if err != nil {
		t.Errorf("Expected no error for non-string variable with pattern, got %v", err)
	}
}

func TestValidateApplyRequest_OptionalVariableNotProvided(t *testing.T) {
	service := &TemplateService{}

	template := &PolicyTemplate{
		Variables: []TemplateVariable{
			{Name: "optional_var", Required: false, Type: "string", Validation: `^[a-z]+$`},
		},
	}

	// Optional variable not provided — should pass without checking pattern
	req := &ApplyTemplateRequest{
		PolicyName: "Valid Name",
		Variables:  map[string]interface{}{},
	}

	err := service.validateApplyRequest(template, req)
	if err != nil {
		t.Errorf("Expected no error for missing optional variable, got %v", err)
	}
}

func TestSubstituteVariables_OverrideDefaults(t *testing.T) {
	service := &TemplateService{}

	template := map[string]interface{}{
		"limit":  "{{max_limit}}",
		"window": "{{time_window}}",
	}

	varDefs := []TemplateVariable{
		{Name: "max_limit", Required: false, Default: 100},
		{Name: "time_window", Required: false, Default: 60},
	}

	// Override one default, leave the other
	values := map[string]interface{}{
		"max_limit": 200,
	}

	result, err := service.substituteVariables(template, varDefs, values)
	if err != nil {
		t.Fatalf("substituteVariables() error = %v", err)
	}

	if result["limit"] != 200 {
		t.Errorf("Expected overridden limit 200, got %v", result["limit"])
	}
	if result["window"] != 60 {
		t.Errorf("Expected default window 60, got %v", result["window"])
	}
}

func TestSubstituteVariables_EmptyVarDefs(t *testing.T) {
	service := &TemplateService{}

	template := map[string]interface{}{
		"static_field": "no variables here",
	}

	result, err := service.substituteVariables(template, nil, nil)
	if err != nil {
		t.Fatalf("substituteVariables() error = %v", err)
	}

	if result["static_field"] != "no variables here" {
		t.Errorf("Expected static field unchanged, got %v", result["static_field"])
	}
}

func TestSubstituteVariables_AllDefaults(t *testing.T) {
	service := &TemplateService{}

	template := map[string]interface{}{
		"a": "{{alpha}}",
		"b": "{{beta}}",
	}

	varDefs := []TemplateVariable{
		{Name: "alpha", Required: false, Default: "first"},
		{Name: "beta", Required: false, Default: "second"},
	}

	// No user values provided, all should come from defaults
	result, err := service.substituteVariables(template, varDefs, map[string]interface{}{})
	if err != nil {
		t.Fatalf("substituteVariables() error = %v", err)
	}

	if result["a"] != "first" {
		t.Errorf("Expected 'first', got %v", result["a"])
	}
	if result["b"] != "second" {
		t.Errorf("Expected 'second', got %v", result["b"])
	}
}

func TestDeepSubstitute_DeeplyNested(t *testing.T) {
	service := &TemplateService{}

	variables := map[string]interface{}{
		"val": "replaced",
	}

	// Three levels of nesting
	input := map[string]interface{}{
		"level1": map[string]interface{}{
			"level2": map[string]interface{}{
				"level3": "{{val}}",
			},
		},
	}

	result, err := service.deepSubstitute(input, variables)
	if err != nil {
		t.Fatalf("deepSubstitute() error = %v", err)
	}

	m1, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("Expected map at level 0")
	}
	m2, ok := m1["level1"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected map at level 1")
	}
	m3, ok := m2["level2"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected map at level 2")
	}
	if m3["level3"] != "replaced" {
		t.Errorf("Expected 'replaced' at level 3, got %v", m3["level3"])
	}
}

func TestDeepSubstitute_MixedSlice(t *testing.T) {
	service := &TemplateService{}

	variables := map[string]interface{}{
		"name": "world",
	}

	input := []interface{}{
		"{{name}}",
		42,
		true,
		nil,
		map[string]interface{}{"key": "{{name}}"},
		[]interface{}{"{{name}}", "static"},
	}

	result, err := service.deepSubstitute(input, variables)
	if err != nil {
		t.Fatalf("deepSubstitute() error = %v", err)
	}

	arr, ok := result.([]interface{})
	if !ok {
		t.Fatalf("Expected []interface{}, got %T", result)
	}

	if len(arr) != 6 {
		t.Fatalf("Expected 6 elements, got %d", len(arr))
	}

	// String variable preserves type (entire string is variable)
	if arr[0] != "world" {
		t.Errorf("arr[0]: expected 'world', got %v", arr[0])
	}
	// Primitives unchanged
	if arr[1] != 42 {
		t.Errorf("arr[1]: expected 42, got %v", arr[1])
	}
	if arr[2] != true {
		t.Errorf("arr[2]: expected true, got %v", arr[2])
	}
	if arr[3] != nil {
		t.Errorf("arr[3]: expected nil, got %v", arr[3])
	}
	// Nested map
	nestedMap, ok := arr[4].(map[string]interface{})
	if !ok {
		t.Fatalf("arr[4]: expected map, got %T", arr[4])
	}
	if nestedMap["key"] != "world" {
		t.Errorf("arr[4][key]: expected 'world', got %v", nestedMap["key"])
	}
	// Nested slice
	nestedSlice, ok := arr[5].([]interface{})
	if !ok {
		t.Fatalf("arr[5]: expected slice, got %T", arr[5])
	}
	if nestedSlice[0] != "world" {
		t.Errorf("arr[5][0]: expected 'world', got %v", nestedSlice[0])
	}
	if nestedSlice[1] != "static" {
		t.Errorf("arr[5][1]: expected 'static', got %v", nestedSlice[1])
	}
}

func TestDeepSubstitute_FloatAndOtherPrimitives(t *testing.T) {
	service := &TemplateService{}

	variables := map[string]interface{}{}

	tests := []struct {
		name  string
		input interface{}
		want  interface{}
	}{
		{"float64", float64(3.14), float64(3.14)},
		{"int", 42, 42},
		{"int64", int64(999), int64(999)},
		{"bool true", true, true},
		{"bool false", false, false},
		{"nil", nil, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := service.deepSubstitute(tt.input, variables)
			if err != nil {
				t.Fatalf("deepSubstitute() error = %v", err)
			}
			if result != tt.want {
				t.Errorf("deepSubstitute(%v) = %v, want %v", tt.input, result, tt.want)
			}
		})
	}
}

func TestSubstituteString_SingleVariableNotFound(t *testing.T) {
	service := &TemplateService{}

	// Entire string is a single variable, but variable is not in the map
	result := service.substituteString("{{missing}}", map[string]interface{}{})

	// Should return the original string unchanged
	if result != "{{missing}}" {
		t.Errorf("Expected '{{missing}}', got %v", result)
	}
}

func TestSubstituteString_PartialMatchMissing(t *testing.T) {
	service := &TemplateService{}

	// Multiple variables, one present and one missing
	result := service.substituteString("{{found}} and {{missing}}", map[string]interface{}{
		"found": "here",
	})

	expected := "here and {{missing}}"
	if result != expected {
		t.Errorf("Expected '%s', got %v", expected, result)
	}
}

func TestSubstituteString_EmptyString(t *testing.T) {
	service := &TemplateService{}

	result := service.substituteString("", map[string]interface{}{"foo": "bar"})
	if result != "" {
		t.Errorf("Expected empty string, got %v", result)
	}
}

func TestSubstituteString_MapVariable(t *testing.T) {
	service := &TemplateService{}

	config := map[string]interface{}{"key": "value"}
	result := service.substituteString("{{config}}", map[string]interface{}{
		"config": config,
	})

	// Single variable should preserve the map type
	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected map[string]interface{}, got %T", result)
	}
	if resultMap["key"] != "value" {
		t.Errorf("Expected map with key=value, got %v", resultMap)
	}
}

func TestExtractPolicyFields_ActionWithoutConfig(t *testing.T) {
	service := &TemplateService{}

	template := map[string]interface{}{
		"type":     "security",
		"priority": float64(80),
		"conditions": []interface{}{
			map[string]interface{}{
				"field":    "query",
				"operator": "contains",
				"value":    "DROP TABLE",
			},
		},
		"actions": []interface{}{
			map[string]interface{}{
				"type": "block",
				// No "config" key
			},
		},
	}

	policyType, conditions, actions, priority, err := service.extractPolicyFields(template)
	if err != nil {
		t.Fatalf("extractPolicyFields() error = %v", err)
	}

	if policyType != "security" {
		t.Errorf("type = %v, want 'security'", policyType)
	}
	if priority != 80 {
		t.Errorf("priority = %v, want 80", priority)
	}
	if len(conditions) != 1 {
		t.Errorf("conditions len = %v, want 1", len(conditions))
	}
	if len(actions) != 1 {
		t.Errorf("actions len = %v, want 1", len(actions))
	}
	if actions[0].Type != "block" {
		t.Errorf("action type = %v, want 'block'", actions[0].Type)
	}
	if actions[0].Config != nil {
		t.Errorf("action config = %v, want nil", actions[0].Config)
	}
}

func TestExtractPolicyFields_ConditionFieldExtraction(t *testing.T) {
	service := &TemplateService{}

	template := map[string]interface{}{
		"conditions": []interface{}{
			map[string]interface{}{
				"field":    "user.role",
				"operator": "equals",
				"value":    "admin",
			},
		},
		"actions": []interface{}{
			map[string]interface{}{
				"type":   "alert",
				"config": map[string]interface{}{"channel": "slack"},
			},
		},
	}

	policyType, conditions, actions, priority, err := service.extractPolicyFields(template)
	if err != nil {
		t.Fatalf("extractPolicyFields() error = %v", err)
	}

	// Check defaults
	if policyType != "content" {
		t.Errorf("type = %v, want default 'content'", policyType)
	}
	if priority != 50 {
		t.Errorf("priority = %v, want default 50", priority)
	}

	// Verify condition fields
	if conditions[0].Field != "user.role" {
		t.Errorf("condition field = %v, want 'user.role'", conditions[0].Field)
	}
	if conditions[0].Operator != "equals" {
		t.Errorf("condition operator = %v, want 'equals'", conditions[0].Operator)
	}
	if conditions[0].Value != "admin" {
		t.Errorf("condition value = %v, want 'admin'", conditions[0].Value)
	}

	// Verify action config
	if actions[0].Type != "alert" {
		t.Errorf("action type = %v, want 'alert'", actions[0].Type)
	}
	if actions[0].Config["channel"] != "slack" {
		t.Errorf("action config channel = %v, want 'slack'", actions[0].Config["channel"])
	}
}

func TestExtractPolicyFields_StringPriorityFallsToDefault(t *testing.T) {
	service := &TemplateService{}

	// Priority is a string (not float64 or int) — should fall to default 50
	template := map[string]interface{}{
		"type":     "content",
		"priority": "high",
		"conditions": []interface{}{
			map[string]interface{}{"field": "q", "operator": "eq", "value": "x"},
		},
		"actions": []interface{}{
			map[string]interface{}{"type": "log", "config": map[string]interface{}{}},
		},
	}

	_, _, _, priority, err := service.extractPolicyFields(template)
	if err != nil {
		t.Fatalf("extractPolicyFields() error = %v", err)
	}
	if priority != 50 {
		t.Errorf("priority = %v, want default 50 for string priority", priority)
	}
}

func TestExtractPolicyFields_NonMapConditionIgnored(t *testing.T) {
	service := &TemplateService{}

	// A condition that is not a map[string]interface{} should be skipped
	template := map[string]interface{}{
		"conditions": []interface{}{
			"not a map",
			map[string]interface{}{"field": "q", "operator": "eq", "value": "x"},
		},
		"actions": []interface{}{
			map[string]interface{}{"type": "log", "config": map[string]interface{}{}},
		},
	}

	_, conditions, _, _, err := service.extractPolicyFields(template)
	if err != nil {
		t.Fatalf("extractPolicyFields() error = %v", err)
	}
	// Only the valid map condition should be extracted
	if len(conditions) != 1 {
		t.Errorf("Expected 1 condition (non-map skipped), got %d", len(conditions))
	}
}

func TestExtractPolicyFields_NonMapActionIgnored(t *testing.T) {
	service := &TemplateService{}

	// An action that is not a map[string]interface{} should be skipped
	template := map[string]interface{}{
		"conditions": []interface{}{
			map[string]interface{}{"field": "q", "operator": "eq", "value": "x"},
		},
		"actions": []interface{}{
			"not a map",
			map[string]interface{}{"type": "log", "config": map[string]interface{}{}},
		},
	}

	_, _, actions, _, err := service.extractPolicyFields(template)
	if err != nil {
		t.Fatalf("extractPolicyFields() error = %v", err)
	}
	// Only the valid map action should be extracted
	if len(actions) != 1 {
		t.Errorf("Expected 1 action (non-map skipped), got %d", len(actions))
	}
}

func TestExtractPolicyFields_ConditionsNotSlice(t *testing.T) {
	service := &TemplateService{}

	// conditions key exists but is not a slice — treated as empty
	template := map[string]interface{}{
		"conditions": "not a slice",
		"actions": []interface{}{
			map[string]interface{}{"type": "log", "config": map[string]interface{}{}},
		},
	}

	_, _, _, _, err := service.extractPolicyFields(template)
	if err == nil {
		t.Fatal("Expected error for non-slice conditions")
	}
	if !containsSubstring(err.Error(), "condition") {
		t.Errorf("Expected error about conditions, got: %v", err)
	}
}

func TestExtractPolicyFields_ActionsNotSlice(t *testing.T) {
	service := &TemplateService{}

	// actions key exists but is not a slice
	template := map[string]interface{}{
		"conditions": []interface{}{
			map[string]interface{}{"field": "q", "operator": "eq", "value": "x"},
		},
		"actions": "not a slice",
	}

	_, _, _, _, err := service.extractPolicyFields(template)
	if err == nil {
		t.Fatal("Expected error for non-slice actions")
	}
	if !containsSubstring(err.Error(), "action") {
		t.Errorf("Expected error about actions, got: %v", err)
	}
}

func TestGetStringFromMap_NilMap(t *testing.T) {
	// Passing nil map should not panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("getStringFromMap panicked on nil map: %v", r)
		}
	}()

	// Note: nil map works for read operations in Go, returns zero value
	var m map[string]interface{}
	result := getStringFromMap(m, "any")
	if result != "" {
		t.Errorf("Expected empty string for nil map, got %v", result)
	}
}

func TestTemplateValidationError_SingleError(t *testing.T) {
	err := &TemplateValidationError{
		Errors: []TemplateFieldError{
			{Field: "name", Message: "is required"},
		},
	}

	errStr := err.Error()
	expected := "name: is required"
	if errStr != expected {
		t.Errorf("Error() = %q, want %q", errStr, expected)
	}
}

func TestTemplateValidationError_EmptyErrors(t *testing.T) {
	err := &TemplateValidationError{
		Errors: []TemplateFieldError{},
	}

	errStr := err.Error()
	if errStr != "" {
		t.Errorf("Error() with empty errors = %q, want empty string", errStr)
	}
}

func TestSubstituteVariablesAndExtractPolicyFields_Integration(t *testing.T) {
	service := &TemplateService{}

	// Simulate a complete template application flow using only pure functions
	template := map[string]interface{}{
		"type":     "{{policy_type}}",
		"priority": "{{priority}}",
		"conditions": []interface{}{
			map[string]interface{}{
				"field":    "{{field}}",
				"operator": "contains",
				"value":    "{{pattern}}",
			},
		},
		"actions": []interface{}{
			map[string]interface{}{
				"type": "{{action}}",
				"config": map[string]interface{}{
					"message": "Blocked: {{reason}}",
				},
			},
		},
	}

	varDefs := []TemplateVariable{
		{Name: "policy_type", Required: true},
		{Name: "priority", Required: false, Default: 50},
		{Name: "field", Required: true},
		{Name: "pattern", Required: true},
		{Name: "action", Required: false, Default: "block"},
		{Name: "reason", Required: false, Default: "policy violation"},
	}

	values := map[string]interface{}{
		"policy_type": "security",
		"priority":    75,
		"field":       "query",
		"pattern":     "DROP TABLE",
	}

	// Step 1: Substitute variables
	processed, err := service.substituteVariables(template, varDefs, values)
	if err != nil {
		t.Fatalf("substituteVariables() error = %v", err)
	}

	// Step 2: Extract policy fields
	policyType, conditions, actions, priority, err := service.extractPolicyFields(processed)
	if err != nil {
		t.Fatalf("extractPolicyFields() error = %v", err)
	}

	// Verify results
	if policyType != "security" {
		t.Errorf("type = %v, want 'security'", policyType)
	}
	if priority != 75 {
		t.Errorf("priority = %v, want 75", priority)
	}
	if len(conditions) != 1 {
		t.Fatalf("conditions len = %v, want 1", len(conditions))
	}
	if conditions[0].Field != "query" {
		t.Errorf("condition field = %v, want 'query'", conditions[0].Field)
	}
	if conditions[0].Value != "DROP TABLE" {
		t.Errorf("condition value = %v, want 'DROP TABLE'", conditions[0].Value)
	}
	if len(actions) != 1 {
		t.Fatalf("actions len = %v, want 1", len(actions))
	}
	if actions[0].Type != "block" {
		t.Errorf("action type = %v, want 'block' (default)", actions[0].Type)
	}
	if actions[0].Config["message"] != "Blocked: policy violation" {
		t.Errorf("action message = %v, want 'Blocked: policy violation'", actions[0].Config["message"])
	}
}

// TestNewTemplateService tests the constructor returns a properly initialized service
func TestNewTemplateService(t *testing.T) {
	templateRepo := &TemplateRepository{}
	policyRepo := &PolicyRepository{}

	service := NewTemplateService(templateRepo, policyRepo)

	if service == nil {
		t.Fatal("NewTemplateService() returned nil")
	}
	if service.templateRepo != templateRepo {
		t.Error("Expected service.templateRepo to match the provided template repository")
	}
	if service.policyRepo != policyRepo {
		t.Error("Expected service.policyRepo to match the provided policy repository")
	}
}

func TestNewTemplateService_NilRepos(t *testing.T) {
	service := NewTemplateService(nil, nil)

	if service == nil {
		t.Fatal("NewTemplateService(nil, nil) returned nil")
	}
	if service.templateRepo != nil {
		t.Error("Expected service.templateRepo to be nil")
	}
	if service.policyRepo != nil {
		t.Error("Expected service.policyRepo to be nil")
	}
}
