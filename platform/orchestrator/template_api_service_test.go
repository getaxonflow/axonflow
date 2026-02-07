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
		name     string
		input    interface{}
		checkFn  func(result interface{}) bool
		desc     string
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
