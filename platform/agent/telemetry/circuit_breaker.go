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
	"time"
)

// breakerState is the classic three-state circuit-breaker machine.
type breakerState int

const (
	// breakerClosed: traffic flows; failures are counted.
	breakerClosed breakerState = iota
	// breakerOpen: traffic is short-circuited until the cooldown elapses.
	breakerOpen
	// breakerHalfOpen: a single probe is admitted to test recovery. The probe's
	// outcome closes the breaker (success) or re-opens it (failure).
	breakerHalfOpen
)

// circuitBreaker isolates a flaky downstream so repeated failures stop costing
// timeout latency and error spam. It is intentionally tiny (no third-party dep):
// the central-store worker is single-threaded so contention is nil, but the
// breaker is still fully mutex-guarded so it is safe to share.
//
// The clock is injected (now) so tests drive cooldown transitions
// deterministically instead of sleeping.
type circuitBreaker struct {
	mu        sync.Mutex
	state     breakerState
	failures  int
	threshold int
	cooldown  time.Duration
	openedAt  time.Time
	probing   bool // a half-open probe is currently in flight
	now       func() time.Time
}

// newCircuitBreaker returns a closed breaker. threshold is clamped to >=1 and
// cooldown to >0 so a degenerate config can never produce an always-open or
// never-recovering breaker.
func newCircuitBreaker(threshold int, cooldown time.Duration, now func() time.Time) *circuitBreaker {
	if threshold < 1 {
		threshold = 1
	}
	if cooldown <= 0 {
		cooldown = defaultBreakerCooldown
	}
	if now == nil {
		now = time.Now
	}
	return &circuitBreaker{
		state:     breakerClosed,
		threshold: threshold,
		cooldown:  cooldown,
		now:       now,
	}
}

// Allow reports whether a call may proceed and advances the state machine for
// the open→half-open transition. It admits exactly one probe per cooldown while
// open: the first caller after the cooldown elapses gets the probe slot, every
// other caller is short-circuited until that probe reports back via Record.
func (b *circuitBreaker) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	switch b.state {
	case breakerClosed:
		return true
	case breakerOpen:
		if b.now().Sub(b.openedAt) >= b.cooldown {
			b.state = breakerHalfOpen
			b.probing = true
			return true
		}
		return false
	case breakerHalfOpen:
		// A probe is already in flight; hold everyone else until it resolves.
		if b.probing {
			return false
		}
		b.probing = true
		return true
	default:
		return true
	}
}

// Record feeds a call outcome back into the breaker. A success closes the
// breaker and clears the failure count; a failure increments the count and trips
// the breaker open once it reaches the threshold (or immediately, if the failure
// was a half-open probe).
func (b *circuitBreaker) Record(success bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if success {
		b.state = breakerClosed
		b.failures = 0
		b.probing = false
		return
	}

	b.failures++
	b.probing = false
	if b.state == breakerHalfOpen {
		// Recovery probe failed: re-open and restart the cooldown.
		b.trip()
		return
	}
	if b.failures >= b.threshold {
		b.trip()
	}
}

// trip moves the breaker to open and stamps the cooldown start. Caller holds mu.
func (b *circuitBreaker) trip() {
	b.state = breakerOpen
	b.openedAt = b.now()
}

// State returns the current state (test/observability helper).
func (b *circuitBreaker) State() breakerState {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state
}
