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
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestSetPolicySetSourceMetric_DrivesTheOtherLabelToZero is the #3319
// cardinality/consistency guarantee: axonflow_policy_set_source must never
// be observed with both label values at 1 (or both at 0) — exactly one
// source is ever "current."
func TestSetPolicySetSourceMetric_DrivesTheOtherLabelToZero(t *testing.T) {
	setPolicySetSourceMetric(policySetSourceDatabase)
	if got := testutil.ToFloat64(policySetSourceGauge.WithLabelValues(policySourceLabelDatabase)); got != 1 {
		t.Errorf("source=database: database gauge = %v, want 1", got)
	}
	if got := testutil.ToFloat64(policySetSourceGauge.WithLabelValues(policySourceLabelDefaults)); got != 0 {
		t.Errorf("source=database: defaults gauge = %v, want 0", got)
	}

	setPolicySetSourceMetric(policySetSourceDefaults)
	if got := testutil.ToFloat64(policySetSourceGauge.WithLabelValues(policySourceLabelDatabase)); got != 0 {
		t.Errorf("source=defaults: database gauge = %v, want 0", got)
	}
	if got := testutil.ToFloat64(policySetSourceGauge.WithLabelValues(policySourceLabelDefaults)); got != 1 {
		t.Errorf("source=defaults: defaults gauge = %v, want 1", got)
	}
}

// TestSetPolicySetSourceMetric_UnknownValueFailsTowardDefaults documents
// the fail-safe for an unexpected source string: it must resolve to
// "defaults" (the more visible, more conservative signal), never silently
// leave both label values stale or ambiguous.
func TestSetPolicySetSourceMetric_UnknownValueFailsTowardDefaults(t *testing.T) {
	setPolicySetSourceMetric(policySetSourceDatabase) // start from the opposite state
	setPolicySetSourceMetric("unexpected-value")

	if got := testutil.ToFloat64(policySetSourceGauge.WithLabelValues(policySourceLabelDefaults)); got != 1 {
		t.Errorf("unknown source: defaults gauge = %v, want 1", got)
	}
	if got := testutil.ToFloat64(policySetSourceGauge.WithLabelValues(policySourceLabelDatabase)); got != 0 {
		t.Errorf("unknown source: database gauge = %v, want 0", got)
	}
}

// TestSetPolicyCacheAgeSeconds_PublishesDurationInSeconds.
func TestSetPolicyCacheAgeSeconds_PublishesDurationInSeconds(t *testing.T) {
	setPolicyCacheAgeSeconds(90 * time.Second)
	if got := testutil.ToFloat64(policyCacheAgeSeconds); got != 90 {
		t.Errorf("policyCacheAgeSeconds = %v, want 90", got)
	}

	setPolicyCacheAgeSeconds(0)
	if got := testutil.ToFloat64(policyCacheAgeSeconds); got != 0 {
		t.Errorf("policyCacheAgeSeconds = %v, want 0", got)
	}
}

// TestRecordPolicyRefreshFailure_IncrementsByReason confirms the counter is
// keyed by reason — two different reasons must not share a time series,
// and the same reason recorded twice must accumulate.
func TestRecordPolicyRefreshFailure_IncrementsByReason(t *testing.T) {
	before := testutil.ToFloat64(policyRefreshFailuresTotal.WithLabelValues(reasonDatabaseUnreachable))
	otherBefore := testutil.ToFloat64(policyRefreshFailuresTotal.WithLabelValues(reasonQueryFailed))

	recordPolicyRefreshFailure(reasonDatabaseUnreachable)
	recordPolicyRefreshFailure(reasonDatabaseUnreachable)

	if got := testutil.ToFloat64(policyRefreshFailuresTotal.WithLabelValues(reasonDatabaseUnreachable)); got != before+2 {
		t.Errorf("policyRefreshFailuresTotal{reason=%q} = %v, want %v", reasonDatabaseUnreachable, got, before+2)
	}
	if got := testutil.ToFloat64(policyRefreshFailuresTotal.WithLabelValues(reasonQueryFailed)); got != otherBefore {
		t.Errorf("policyRefreshFailuresTotal{reason=%q} changed from an unrelated reason's increment: before=%v after=%v", reasonQueryFailed, otherBefore, got)
	}
}

// TestRecordPolicyZeroRowLoad_Increments.
func TestRecordPolicyZeroRowLoad_Increments(t *testing.T) {
	before := testutil.ToFloat64(policyZeroRowLoadsTotal)
	recordPolicyZeroRowLoad()
	if got := testutil.ToFloat64(policyZeroRowLoadsTotal); got != before+1 {
		t.Errorf("policyZeroRowLoadsTotal = %v, want %v", got, before+1)
	}
}

// TestPolicyRefreshFailureReasons_AreAClosedLowCardinalitySet documents the
// full reason label set at a glance — a reviewer adding a new failure path
// should extend this list deliberately, not discover it's missing later
// from a cardinality alert.
func TestPolicyRefreshFailureReasons_AreAClosedLowCardinalitySet(t *testing.T) {
	reasons := []string{
		reasonDatabaseNotConfigured,
		reasonDatabaseUnreachable,
		reasonQueryFailed,
		reasonRowIterationFailed,
	}
	seen := make(map[string]bool, len(reasons))
	for _, r := range reasons {
		if r == "" {
			t.Fatal("reason constant must not be empty")
		}
		if seen[r] {
			t.Fatalf("duplicate reason constant value %q", r)
		}
		seen[r] = true
	}
}
