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

package audit

import "sort"

// Spellings returns every raw policy_decision spelling that Normalize maps to
// the given canonical verdict — the canonical value itself plus every known
// legacy/defensive alias for it. It is the read-side companion to Normalize: a
// reader that filters audit_logs by a canonical verdict uses it to build a
// `policy_decision = ANY(...)` / `IN (...)` predicate that matches BOTH the
// canonical value every forward writer emits today AND any pre-canonical
// legacy/historical row a backfill may not have reached (e.g. "deny",
// "denied", "pending_approval", "require_approval"). The returned slice always
// contains the canonical value and is sorted so the SQL and its tests are
// deterministic.
//
// The argument must be a canonical verdict (one of All()) or the recognized
// non-verdict marker DecisionOverrideLifecycle. For anything else — a phantom
// label, an alias spelling rather than the canonical, or an unknown value — it
// returns nil. A nil/empty expansion is the safe default: a `= ANY('{}')`
// predicate matches no rows, so a reader must validate its filter input with
// IsCanonical and reject phantoms up front rather than rely on Spellings to
// silently widen the filter. Passing an alias such as "require_approval"
// returns nil ON PURPOSE — normalize it to the canonical "needs_approval"
// first, then expand.
func Spellings(canonical string) []string {
	c := canonicalize(canonical)
	if _, ok := canonicalSet[c]; !ok && c != DecisionOverrideLifecycle {
		return nil
	}
	out := make([]string, 0, 4)
	for raw, mapped := range legacyAliases {
		if mapped == c {
			out = append(out, raw)
		}
	}
	sort.Strings(out)
	return out
}
