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

import (
	"sync"
	"testing"
	"time"
)

// fakeClock is a manually-advanced clock so breaker cooldown transitions are
// deterministic in tests (no sleeping on the wall clock).
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 6, 22, 0, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func TestCircuitBreaker_ClosedAllowsTraffic(t *testing.T) {
	b := newCircuitBreaker(3, time.Second, newFakeClock().Now)
	for i := 0; i < 10; i++ {
		if !b.Allow() {
			t.Fatalf("closed breaker must allow; denied on call %d", i)
		}
		b.Record(true)
	}
	if got := b.State(); got != breakerClosed {
		t.Fatalf("state = %v, want closed", got)
	}
}

func TestCircuitBreaker_TripsAfterThreshold(t *testing.T) {
	b := newCircuitBreaker(3, time.Second, newFakeClock().Now)

	// Two failures: still closed (under threshold).
	for i := 0; i < 2; i++ {
		if !b.Allow() {
			t.Fatalf("breaker tripped early on failure %d", i)
		}
		b.Record(false)
	}
	if b.State() != breakerClosed {
		t.Fatalf("breaker should still be closed after 2/3 failures")
	}

	// Third failure trips it open.
	if !b.Allow() {
		t.Fatal("third call should still be admitted (breaker not yet open)")
	}
	b.Record(false)
	if b.State() != breakerOpen {
		t.Fatalf("breaker should be open after 3/3 failures, got %v", b.State())
	}

	// Open breaker short-circuits.
	if b.Allow() {
		t.Fatal("open breaker must deny before cooldown")
	}
}

func TestCircuitBreaker_HalfOpenProbeSuccessCloses(t *testing.T) {
	clk := newFakeClock()
	b := newCircuitBreaker(1, 30*time.Second, clk.Now)

	// Trip it.
	b.Allow()
	b.Record(false)
	if b.State() != breakerOpen {
		t.Fatal("breaker should be open")
	}

	// Before cooldown: denied.
	clk.advance(29 * time.Second)
	if b.Allow() {
		t.Fatal("breaker must stay open before cooldown elapses")
	}

	// After cooldown: one probe admitted, breaker half-open.
	clk.advance(2 * time.Second)
	if !b.Allow() {
		t.Fatal("breaker must admit a probe after cooldown")
	}
	if b.State() != breakerHalfOpen {
		t.Fatalf("state = %v, want half-open", b.State())
	}
	// A second concurrent caller is denied while the probe is in flight.
	if b.Allow() {
		t.Fatal("half-open breaker must admit only one probe at a time")
	}

	// Probe succeeds → closed.
	b.Record(true)
	if b.State() != breakerClosed {
		t.Fatalf("successful probe must close the breaker, got %v", b.State())
	}
	if !b.Allow() {
		t.Fatal("closed breaker must allow after recovery")
	}
}

func TestCircuitBreaker_HalfOpenProbeFailureReopens(t *testing.T) {
	clk := newFakeClock()
	b := newCircuitBreaker(1, 10*time.Second, clk.Now)

	b.Allow()
	b.Record(false) // trip

	clk.advance(10 * time.Second)
	if !b.Allow() {
		t.Fatal("probe must be admitted after cooldown")
	}
	b.Record(false) // probe fails → reopen
	if b.State() != breakerOpen {
		t.Fatalf("failed probe must reopen the breaker, got %v", b.State())
	}
	// Cooldown restarts from the reopen instant.
	if b.Allow() {
		t.Fatal("reopened breaker must deny until the new cooldown elapses")
	}
	clk.advance(10 * time.Second)
	if !b.Allow() {
		t.Fatal("breaker must admit a probe again after the second cooldown")
	}
}

func TestCircuitBreaker_SuccessResetsFailureCount(t *testing.T) {
	b := newCircuitBreaker(3, time.Second, newFakeClock().Now)

	b.Allow()
	b.Record(false)
	b.Allow()
	b.Record(false) // 2 failures
	b.Allow()
	b.Record(true) // success resets

	// Two more failures should NOT trip (count was reset).
	b.Allow()
	b.Record(false)
	b.Allow()
	b.Record(false)
	if b.State() != breakerClosed {
		t.Fatalf("success must reset the failure count; breaker tripped at 2 post-reset failures")
	}
}

func TestNewCircuitBreaker_ClampsDegenerateConfig(t *testing.T) {
	// threshold < 1 clamps to 1; cooldown <= 0 clamps to the default.
	b := newCircuitBreaker(0, 0, nil)
	if b.threshold != 1 {
		t.Fatalf("threshold = %d, want clamped to 1", b.threshold)
	}
	if b.cooldown != defaultBreakerCooldown {
		t.Fatalf("cooldown = %s, want clamped to default %s", b.cooldown, defaultBreakerCooldown)
	}
	// nil clock falls back to time.Now (non-nil, usable).
	if b.now == nil {
		t.Fatal("nil clock must fall back to time.Now")
	}
	// One failure trips it (threshold clamped to 1).
	b.Allow()
	b.Record(false)
	if b.State() != breakerOpen {
		t.Fatal("clamped threshold=1 must trip on first failure")
	}
}
