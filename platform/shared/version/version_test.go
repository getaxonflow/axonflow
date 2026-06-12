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

package version

import "testing"

// setBaked temporarily sets the package-level baked Version and restores it,
// simulating a binary built with the -X ldflag.
func setBaked(t *testing.T, v string) {
	t.Helper()
	prev := Version
	Version = v
	t.Cleanup(func() { Version = prev })
}

// TestResolve_BakedWinsOverEnv is the #2662 anti-spoof guard: when a version is
// baked into the binary it MUST win over a conflicting AXONFLOW_VERSION env var,
// so /health reports the true shipped binary version and cannot be overridden at
// runtime.
func TestResolve_BakedWinsOverEnv(t *testing.T) {
	setBaked(t, "8.7.0")
	t.Setenv("AXONFLOW_VERSION", "1.2.3-spoofed")

	if got := Resolve(); got != "8.7.0" {
		t.Errorf("Resolve() = %q, want baked 8.7.0 (env must NOT win)", got)
	}
	if !Baked() {
		t.Error("Baked() = false, want true when Version is set")
	}
}

// TestResolve_EnvFallbackWhenUnbaked covers the dev path: an unbaked binary
// (Version == "") falls back to the AXONFLOW_VERSION env var.
func TestResolve_EnvFallbackWhenUnbaked(t *testing.T) {
	setBaked(t, "")
	t.Setenv("AXONFLOW_VERSION", "9.9.9-dev")

	if got := Resolve(); got != "9.9.9-dev" {
		t.Errorf("Resolve() = %q, want env fallback 9.9.9-dev", got)
	}
	if Baked() {
		t.Error("Baked() = true, want false when Version is empty")
	}
}

// TestResolve_EmptyWhenNeitherSet returns "" so callers can apply their own
// default + format validation.
func TestResolve_EmptyWhenNeitherSet(t *testing.T) {
	setBaked(t, "")
	t.Setenv("AXONFLOW_VERSION", "")

	if got := Resolve(); got != "" {
		t.Errorf("Resolve() = %q, want empty string", got)
	}
}
