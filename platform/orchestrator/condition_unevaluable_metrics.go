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

package orchestrator

import (
	sharedpolicy "axonflow/platform/shared/policy"
)

// planeUnevaluableRecorder adapts promPolicyConditionUnevaluableTotal
// (run.go) to sharedpolicy.UnevaluableRecorder, binding a fixed "plane"
// label per call site. This is the only place platform/shared/policy's
// evaluator touches Prometheus, and it touches it indirectly: the shared
// package only ever sees the UnevaluableRecorder interface, never this type
// or the prometheus import it carries. See condition_evaluator.go's
// "Unevaluable conditions" doc section and unevaluable_recorder.go for why
// that boundary matters (the evaluator is a pure function, deliberately
// dependency-free).
type planeUnevaluableRecorder struct {
	plane string
}

// RecordUnevaluable implements sharedpolicy.UnevaluableRecorder.
func (r planeUnevaluableRecorder) RecordUnevaluable(reason string) {
	promPolicyConditionUnevaluableTotal.WithLabelValues(reason, r.plane).Inc()
}

// One recorder per call site named in condition_evaluator.go's convergence
// record (1a-1e) — the same four package-level ConditionEvaluator values
// (memoryConditionEvaluator, dbConditionEvaluator, mcpConditionEvaluator,
// policyTestEvaluator) this file's siblings already declare. Package-level,
// not per-request, for the same reason those evaluators are: no per-call
// state, constructed once.
var (
	memoryUnevaluableRecorder     sharedpolicy.UnevaluableRecorder = planeUnevaluableRecorder{plane: "memory"}
	dbUnevaluableRecorder         sharedpolicy.UnevaluableRecorder = planeUnevaluableRecorder{plane: "database"}
	mcpUnevaluableRecorder        sharedpolicy.UnevaluableRecorder = planeUnevaluableRecorder{plane: "mcp"}
	policyTestUnevaluableRecorder sharedpolicy.UnevaluableRecorder = planeUnevaluableRecorder{plane: "policy_test"}
)
