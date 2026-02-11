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
	"regexp"
	"strings"
)

var ansiRegex = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

const maxLogFieldLength = 500

// Sanitize removes characters that could be used for log injection attacks.
// It escapes newlines, carriage returns, tabs, and ANSI escape sequences,
// and truncates to prevent log flooding.
func Sanitize(s string) string {
	s = strings.ReplaceAll(s, "\x00", "")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\t", "\\t")
	s = ansiRegex.ReplaceAllString(s, "")
	if len(s) > maxLogFieldLength {
		s = s[:maxLogFieldLength] + "...[truncated]"
	}
	return s
}

// MaskSecret masks a secret value for safe logging, showing only a short prefix.
// Returns something like "AXON-eyJ...****" (first 10 chars + mask).
func MaskSecret(s string, visibleChars int) string {
	if len(s) <= visibleChars {
		return "****"
	}
	return s[:visibleChars] + "****"
}
