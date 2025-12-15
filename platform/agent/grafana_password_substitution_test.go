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

package agent

import (
	"os"
	"testing"
)

// TestGrafanaPasswordSubstitution tests the GRAFANA_PASSWORD template substitution logic
// This validates the security fix for migration 017 where hardcoded passwords were replaced
// with runtime substitution from AWS Secrets Manager
func TestGrafanaPasswordSubstitution(t *testing.T) {
	tests := []struct {
		name           string
		sqlContent     string
		envValue       string
		expectEmpty    bool   // empty result means skip
		expectError    bool
		expectedResult string
	}{
		{
			name:           "valid password substitution",
			sqlContent:     "CREATE USER grafana WITH PASSWORD '{{GRAFANA_PASSWORD}}';",
			envValue:       "secure-password-32-chars-long!",
			expectEmpty:    false,
			expectError:    false,
			expectedResult: "CREATE USER grafana WITH PASSWORD 'secure-password-32-chars-long!';",
		},
		{
			name:        "password too short",
			sqlContent:  "CREATE USER grafana WITH PASSWORD '{{GRAFANA_PASSWORD}}';",
			envValue:    "short",
			expectEmpty: true, // errors return empty string
			expectError: true,
		},
		{
			name:        "password not set",
			sqlContent:  "CREATE USER grafana WITH PASSWORD '{{GRAFANA_PASSWORD}}';",
			envValue:    "",
			expectEmpty: true,
			expectError: false,
		},
		{
			name:        "grafana not deployed",
			sqlContent:  "CREATE USER grafana WITH PASSWORD '{{GRAFANA_PASSWORD}}';",
			envValue:    "not-deployed",
			expectEmpty: true,
			expectError: false,
		},
		{
			name:           "no placeholder - no substitution",
			sqlContent:     "CREATE USER other WITH PASSWORD 'static';",
			envValue:       "secure-password-32-chars-long!",
			expectEmpty:    false,
			expectError:    false,
			expectedResult: "CREATE USER other WITH PASSWORD 'static';",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variable
			if tt.envValue != "" {
				os.Setenv("GRAFANA_PASSWORD", tt.envValue)
				defer os.Unsetenv("GRAFANA_PASSWORD")
			} else {
				os.Unsetenv("GRAFANA_PASSWORD")
			}

			// Call the actual function from main.go
			resultSQL, err := substituteGrafanaPassword(tt.sqlContent)

			// Validate expectations
			isEmpty := (resultSQL == "")
			if isEmpty != tt.expectEmpty {
				t.Errorf("expected empty=%v, got empty=%v", tt.expectEmpty, isEmpty)
			}

			hasError := (err != nil)
			if hasError != tt.expectError {
				t.Errorf("expected error=%v, got error=%v (err: %v)", tt.expectError, hasError, err)
			}

			if !isEmpty && !hasError && tt.expectedResult != "" {
				if resultSQL != tt.expectedResult {
					t.Errorf("expected:\n%s\ngot:\n%s", tt.expectedResult, resultSQL)
				}
			}
		})
	}
}
