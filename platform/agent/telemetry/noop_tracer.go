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

package telemetry

import "context"

// noopTracer is returned when AXONFLOW_OTEL_ENDPOINT is empty.
// It is the Community-tier default: no network, no required infra,
// no allocations beyond the interface dispatch. Empty trace_id signals
// "OTel disabled" to callers who echo it back in response bodies.
type noopTracer struct{}

func (noopTracer) RecordDecision(context.Context, DecisionEvent) string {
	return ""
}

// NewNoopTracer returns a DecisionTracer that does nothing. Exported so
// tests and callers that explicitly want noop semantics (e.g. unit
// tests that never want to spin up the OTel SDK) can request it
// without going through the env-var-driven NewDecisionTracer path.
func NewNoopTracer() DecisionTracer { return noopTracer{} }
