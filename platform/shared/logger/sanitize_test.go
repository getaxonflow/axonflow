// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package logger

import (
	"strings"
	"testing"
)

func TestSanitize(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "clean string",
			input:    "hello world",
			expected: "hello world",
		},
		{
			name:     "newline injection",
			input:    "legit\n[FAKE] Injected log entry",
			expected: "legit\\n[FAKE] Injected log entry",
		},
		{
			name:     "carriage return injection",
			input:    "legit\r\n[FAKE] Injected",
			expected: "legit\\r\\n[FAKE] Injected",
		},
		{
			name:     "tab injection",
			input:    "value\twith\ttabs",
			expected: "value\\twith\\ttabs",
		},
		{
			name:     "ANSI escape sequence",
			input:    "normal\x1b[31mred text\x1b[0m",
			expected: "normalred text",
		},
		{
			name:     "null byte injection",
			input:    "before\x00after",
			expected: "beforeafter",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "truncation",
			input:    strings.Repeat("a", 600),
			expected: strings.Repeat("a", 500) + "...[truncated]",
		},
		{
			name:     "combined attack",
			input:    "user\ninput\r\x1b[31m\tattack",
			expected: "user\\ninput\\r\\tattack",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Sanitize(tt.input)
			if result != tt.expected {
				t.Errorf("Sanitize(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestMaskSecret(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		visibleChars int
		expected     string
	}{
		{
			name:         "normal secret",
			input:        "AXON-eyJhbGciOiJFZDI1NTE5In0.signature",
			visibleChars: 10,
			expected:     "AXON-eyJhb****",
		},
		{
			name:         "short secret",
			input:        "abc",
			visibleChars: 10,
			expected:     "****",
		},
		{
			name:         "exact length",
			input:        "1234567890",
			visibleChars: 10,
			expected:     "****",
		},
		{
			name:         "empty",
			input:        "",
			visibleChars: 5,
			expected:     "****",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MaskSecret(tt.input, tt.visibleChars)
			if result != tt.expected {
				t.Errorf("MaskSecret(%q, %d) = %q, want %q", tt.input, tt.visibleChars, result, tt.expected)
			}
		})
	}
}

func BenchmarkSanitize(b *testing.B) {
	input := "user\ninput\r\x1b[31m\tattack value with some length"
	for i := 0; i < b.N; i++ {
		Sanitize(input)
	}
}
