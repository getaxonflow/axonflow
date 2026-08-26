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

import (
	"strings"
	"testing"
	"time"
)

// TestMeasuredLatencyMs pins the write-side contract for
// audit_logs.response_time_ms (#3424). The distinction under test is between a
// MEASUREMENT and the ABSENCE of one, and it is not cosmetic in either
// direction:
//
//   - binding a 0 for a writer that measured nothing is what let the portal
//     render a confident "Avg Latency: 0ms" for traffic nothing had timed;
//   - refusing a 0 from a writer that DID measure is what made 19 of 20
//     ordinary ALLOW decisions record no sample at all, leaving the tile to
//     average the slow tail.
func TestMeasuredLatencyMs(t *testing.T) {
	cases := []struct {
		name    string
		ms      int64
		wantNil bool
		want    int64
	}{
		{"a measured millisecond binds as itself", 1, false, 1},
		{"a measured duration binds as itself", 137, false, 137},
		{
			// time.Duration.Milliseconds() truncates, so a writer that measured
			// a 400us decision hands us a 0. The column is BIGINT milliseconds:
			// 0 is the closest true value it can hold, and the row IS a sample.
			// Storing NULL instead would erase a real, fast decision.
			"a sub-millisecond duration truncates to 0 and is STILL a measurement",
			(400 * time.Microsecond).Milliseconds(),
			false, 0,
		},
		{"the explicit unmeasured sentinel binds as SQL NULL", LatencyUnmeasured, true, 0},
		{"any negative value is unmeasured (a duration cannot be negative)", -5, true, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := MeasuredLatencyMs(tc.ms)
			if tc.wantNil {
				if got != nil {
					t.Fatalf("MeasuredLatencyMs(%d) = %v, want nil (SQL NULL). Binding a value here "+
						"puts an unmeasurable row into the reader's sample set.", tc.ms, got)
				}
				return
			}
			v, ok := got.(int64)
			if !ok {
				t.Fatalf("MeasuredLatencyMs(%d) = %T, want int64 so lib/pq binds BIGINT", tc.ms, got)
			}
			if v != tc.want {
				t.Fatalf("MeasuredLatencyMs(%d) = %d, want %d", tc.ms, v, tc.want)
			}
		})
	}
}

// TestLatencyUnmeasuredIsNotAValueAWriterCanMeasure pins the sentinel's sign.
// A positive or zero sentinel would collide with a real measurement, which is
// the whole reason it is -1.
func TestLatencyUnmeasuredIsNotAValueAWriterCanMeasure(t *testing.T) {
	if LatencyUnmeasured >= 0 {
		t.Fatalf("LatencyUnmeasured = %d; a duration is never negative, so the sentinel must be, "+
			"or a real measurement of that length would be silently dropped", LatencyUnmeasured)
	}
	if MeasuredLatencyMs(LatencyUnmeasured) != nil {
		t.Fatal("MeasuredLatencyMs(LatencyUnmeasured) must be SQL NULL")
	}
}

// TestLatencyValue pins the pointer form used by orchestrator.AuditEntry, whose
// producers signal "nothing measured" by leaving the field nil rather than by
// passing a sentinel (#3424 round-2 blocker: while it was a plain int64 the
// seven producers that measure nothing were indistinguishable from one that
// measured zero, on the INSERT and on the JSON alike).
func TestLatencyValue(t *testing.T) {
	if LatencyValue(nil) != nil {
		t.Fatal("LatencyValue(nil) must be SQL NULL: a nil pointer is the absence of a measurement")
	}
	zero := int64(0)
	got := LatencyValue(&zero)
	if v, ok := got.(int64); !ok || v != 0 {
		t.Fatalf("LatencyValue(&0) = %v (%T), want int64(0): a POINTED-TO zero is a measured zero", got, got)
	}
	ms := int64(42)
	if v, ok := LatencyValue(&ms).(int64); !ok || v != 42 {
		t.Fatalf("LatencyValue(&42) = %v, want int64(42)", LatencyValue(&ms))
	}
}

// TestNullIfUnmeasuredLatency pins the CLIENT-ASSERTED variant, used only by
// the OTLP ingest plane. There a duration_ms of 0 is indistinguishable from a
// missing span attribute, so non-positive means absent. It must not be reused
// for a duration the platform measured itself.
func TestNullIfUnmeasuredLatency(t *testing.T) {
	if NullIfUnmeasuredLatency(0) != nil {
		t.Error("a client-asserted 0 is an absent attribute, not a sub-millisecond claim we can vouch for")
	}
	if NullIfUnmeasuredLatency(-1) != nil {
		t.Error("a negative client-asserted duration must be NULL")
	}
	if v, ok := NullIfUnmeasuredLatency(9).(int64); !ok || v != 9 {
		t.Error("a positive client-asserted duration binds as itself")
	}
}

// TestLatencyMeasuredPredicate_AdmitsExactlyWhatTheWriterCanStore is the
// pairing test: the SQL every reader filters with must admit exactly the values
// MeasuredLatencyMs is willing to write. If the two ever disagree, an
// unmeasured row starts voting in the average (or a measured one stops
// counting) with nothing failing.
func TestLatencyMeasuredPredicate_AdmitsExactlyWhatTheWriterCanStore(t *testing.T) {
	if !strings.Contains(LatencyMeasuredPredicate, "IS NOT NULL") {
		t.Errorf("predicate must exclude NULL rows (the writer's absent value): %q", LatencyMeasuredPredicate)
	}
	// The `> 0` that used to live here is GONE on purpose: it discarded every
	// sub-millisecond decision. Migration core/161 clears the fabricated zeros
	// legacy writers stored, so a 0 in the column now means "measured, fast".
	if strings.Contains(LatencyMeasuredPredicate, "> 0") {
		t.Errorf("predicate must NOT re-add `> 0`: it silently drops every measured sub-millisecond "+
			"decision, which is the majority of ALLOW traffic. Got %q", LatencyMeasuredPredicate)
	}
	// No placeholders: the fragment is concatenated into queries whose other
	// arguments are numbered positionally, so a $n here would silently shift
	// every argument after it.
	if strings.Contains(LatencyMeasuredPredicate, "$") {
		t.Errorf("predicate must not carry placeholders; it composes into positionally-numbered queries: %q",
			LatencyMeasuredPredicate)
	}

	// Every value the writer can emit is admitted, and every value it refuses
	// is rejected. Structural here; executed against real Postgres by
	// TestAuditSummaryLatency_RealPostgres.
	for _, ms := range []int64{LatencyUnmeasured, -1, 0, 1, 42, 1 << 40} {
		bound := MeasuredLatencyMs(ms)
		admitted := bound != nil
		wantAdmitted := ms >= 0
		if admitted != wantAdmitted {
			t.Errorf("ms=%d: writer binds non-nil=%v but the reader's predicate expects %v", ms, admitted, wantAdmitted)
		}
	}
}

// TestLatencyEnforcementPredicate pins the two narrowings the operator-facing
// average depends on (#3424 round 2).
func TestLatencyEnforcementPredicate(t *testing.T) {
	if !strings.HasPrefix(LatencyEnforcementPredicate, LatencyMeasuredPredicate) {
		t.Fatalf("the enforcement predicate must be the measured one NARROWED, not a second "+
			"hand-written definition of measured: %q", LatencyEnforcementPredicate)
	}
	// plane='llm' is a PROVIDER round trip, orders of magnitude larger. Three
	// such rows among 53 moved a live tile from 5ms to 724ms.
	if !strings.Contains(LatencyEnforcementPredicate, LatencyProviderPlane) {
		t.Errorf("enforcement predicate must exclude the provider plane: %q", LatencyEnforcementPredicate)
	}
	// The NULL half is the load-bearing one. Migration core/119 added
	// audit_logs.plane and backfilled ONLY decision_id, so every LLM-forward
	// row older than it carries a provider round trip with a NULL plane. A
	// bare `plane <> 'llm'` never matches NULL and neither does the NULL-safe
	// IS DISTINCT FROM, so both let the entire historical population back into
	// the average the exclusion exists to protect.
	if !strings.Contains(LatencyEnforcementPredicate, "plane IS NOT NULL") {
		t.Errorf("enforcement predicate must exclude rows with NO plane: they predate the column's "+
			"backfill-less migration and are provider round trips. Got %q", LatencyEnforcementPredicate)
	}
	// Belt and braces, NOT a second known population: the BatchWriter binds
	// nullIfEmpty(entry.Plane) so its unstamped rows are NULL, and every other
	// writer binds a constant. '' is reachable only from hand-written SQL -- a
	// seed file, a fixture, an operator backfill -- which is the class this
	// predicate should not have to trust.
	if !strings.Contains(LatencyEnforcementPredicate, "plane <> ''") {
		t.Errorf("enforcement predicate must also exclude an EMPTY-STRING plane, which hand-written "+
			"SQL can produce even though no writer does: %q", LatencyEnforcementPredicate)
	}
	if strings.Contains(LatencyEnforcementPredicate, "IS DISTINCT FROM") {
		t.Errorf("IS DISTINCT FROM ADMITS a NULL plane, which is exactly the legacy provider-round-trip "+
			"population; use an explicit IS NOT NULL: %q", LatencyEnforcementPredicate)
	}
	// Lifecycle markers are not verdicts and are not in total_requests, so
	// admitting them here could make the sample count exceed the total the
	// portal shows it as a fraction of.
	if !strings.Contains(LatencyEnforcementPredicate, DecisionOverrideLifecycle) {
		t.Errorf("enforcement predicate must exclude override-lifecycle rows: %q", LatencyEnforcementPredicate)
	}
	if strings.Contains(LatencyEnforcementPredicate, "$") {
		t.Errorf("enforcement predicate must not carry placeholders: %q", LatencyEnforcementPredicate)
	}
}
