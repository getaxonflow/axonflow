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

// Package plugincompat is the single source of truth for the plugin version
// floors and recommendations both planes advertise on /health.
//
// # Why this package exists
//
// The two maps used to be duplicated literals in platform/agent/capabilities.go
// and platform/orchestrator/capabilities.go, and BOTH are served on /health. The
// duplication produced two real incidents:
//
//   - the orchestrator drifted alone (claude-code 1.8.0 while the agent had
//     1.9.0), so the same question got two answers depending on which plane a
//     client asked; and
//   - on the v9.10.0 train NEITHER file was touched, so released plugin versions
//     were advertised nowhere (#2962).
//
// A test comparing the two copies was tried first and is not sufficient. It
// cannot see the second shape at all — two files that agree at a stale value
// agree — and a source-parsing implementation was defeated by four separate
// shapes that compile cleanly, including a decoy map literal earlier in the same
// function. The only durable answer is to stop having two copies.
//
// # What this package does NOT solve
//
// It makes the two planes agree by construction. It does NOT and cannot tell
// anyone that a value has gone stale relative to what is actually published on
// npm / ClawHub / the GitHub marketplace — that is a fact about a registry, not
// about this repository, and no in-repo test can observe it. That check belongs
// to the release runbook.
package plugincompat

// minVersion is the floor each client must meet. Below it a client receives the
// actionable downgrade-warning header on every governed call, so these move only
// on a deliberate compatibility break.
//
// Bumped from {2.0.0, 1.0.0x3} to {2.4.0, 1.4.0x3} during the **v7.9.0
// release-train prep (#2102)**: openclaw 2.0-2.3.x carried bugs we no longer
// support, and claude-code/cursor/codex 1.0-1.3.x predate the v8 list_decisions
// integration. Anything below this floor speaks an out-of-contract version. The
// plugin tags shipped within ~15-30 minutes of the v7.9.0 community sync per the
// release-train order locked at #2047.
//
// The attribution matters and is test-guarded (TestPluginFloorCommentAttribution,
// mirrored in both planes). Two historically false framings have been written here
// before and both are banned by substring: attributing the bump to the v8.0.0
// platform release-train (#2308) rather than v7.9.0, and describing the plugin
// tags as still pending publication. Do not restate either banned wording here
// even to forbid it — the guard is a substring check over this file, so quoting
// the phrase trips it. Describe the property instead, as this paragraph does.
//
// claude-desktop joined the registry in the 9.7.0 release-train. Its floor is
// 0.2.0 rather than 1.4.0/2.4.0 because the desktop proxy's version line started
// at 0.x, and 0.2.0 is the first release whose response redaction goes through
// the authoritative engine.
var minVersion = map[string]string{
	"openclaw":       "2.4.0",
	"claude-code":    "1.4.0",
	"cursor":         "1.4.0",
	"codex":          "1.4.0",
	"claude-desktop": "0.2.0",
}

// recommendedVersion is the newest release of each client that is live on its
// registry. A client below it keeps working and receives an upgrade hint; the
// MinPluginVersion floor above is what actually gates.
//
// Same attribution as the floor: the original recommended-version bump landed
// during the **v7.9.0 release-train (#2102)**, not the v8.0.0 platform bump
// (#2308) — see PR #2311, which corrected the wording. This block was missed by
// both of the sessions that fixed the floor block above, which is why the guard
// requires the #2102 citation in both. Every plugin tag is live on its registry
// (openclaw on npm + ClawHub, claude-code and cursor on the GitHub marketplace,
// codex on ClawHub).
//
// Release-train history, newest first:
//
//   - openclaw 2.8.4 -> 2.8.5 (openclaw-plugin#167/#169, published 2026-07-30):
//     the status surfaces report the endpoint and identity the governance
//     runtime actually uses, a governed call that proceeds because the endpoint
//     is unreachable says so instead of running ungoverned in silence, and an
//     error response's own reason is rendered instead of a bare status line.
//   - the 9.11.0 train took claude-code to 1.11.0 and cursor/codex to 1.7.0.
//   - the 9.10.0 train (#2919 fleet RBAC per-user identity) moved all four so
//     each sends the per-user token header on every governed surface; below the
//     recommended version a client keeps working but reads the shared-identity
//     zero-rows fallback until upgraded.
var recommendedVersion = map[string]string{
	"openclaw":       "2.8.5",
	"claude-code":    "1.11.0",
	"cursor":         "1.7.0",
	"codex":          "1.7.0",
	"claude-desktop": "0.3.1",
}

// MinVersions returns the floor map.
//
// A copy, not the map itself: a map is a reference, so handing out the original
// would let any caller — including a JSON encoder's consumer or a future handler
// that "normalises" its input — mutate the source of truth for the whole
// process. The two callers serve it on /health and do not currently write to it;
// that is not a property to depend on.
func MinVersions() map[string]string { return copyOf(minVersion) }

// RecommendedVersions returns the recommendation map, copied for the same reason
// as MinVersions.
func RecommendedVersions() map[string]string { return copyOf(recommendedVersion) }

// IDs returns the client ids both maps carry. Callers that need to cross-check
// against their own registry of known integrations use this rather than ranging
// over one of the maps, so the check does not silently depend on which map was
// picked.
func IDs() []string {
	out := make([]string, 0, len(recommendedVersion))
	for id := range recommendedVersion {
		out = append(out, id)
	}
	return out
}

func copyOf(src map[string]string) map[string]string {
	// make+copy rather than a nil-appended literal: an empty source must yield
	// an empty map, never nil, or the JSON shape changes from {} to null
	// depending on the contents.
	out := make(map[string]string, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}
