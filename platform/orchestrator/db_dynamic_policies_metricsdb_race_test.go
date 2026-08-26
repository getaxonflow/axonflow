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

package orchestrator

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

// TestEvaluateDynamicPolicies_ConcurrentMetricsDBSwap_NoDataRace is the R3
// finding-1 regression test (#3319 hostile review): EvaluateDynamicPolicies
// spawned a background goroutine that read the struct field e.metricsDB
// directly, with no lock held, while connectDB (db_dynamic_policies.go)
// writes that same field under e.mu.Lock().
//
// Before #3319 this was impossible by construction: the engine was never
// handed to a caller until connectDB had already populated db/metricsDB
// synchronously in the constructor. #3319 deliberately removed that
// invariant — the engine now starts serving live traffic in "defaults" mode
// (metricsDB == nil) while the 30s background refresh tick's connectDB call
// can populate metricsDB concurrently with in-flight requests. This test
// drives exactly that window: one goroutine repeatedly swaps e.metricsDB
// under e.mu.Lock() (mirroring connectDB's write at db_dynamic_policies.go
// ~283-286) while many goroutines concurrently call
// EvaluateDynamicPolicies, each of which used to spawn a goroutine reading
// e.metricsDB unsynchronized.
//
// Run under `-race`: before the fix this reliably reports a DATA RACE
// between connectDB's write and the metrics goroutine's read; after the fix
// (metricsDB captured under e.mu.RLock() in the calling goroutine before
// the background goroutine is spawned) it does not. This test's own
// pass/fail assertions are secondary to the race detector's verdict — see
// the DoD's `go test -race` evidence.
func TestEvaluateDynamicPolicies_ConcurrentMetricsDBSwap_NoDataRace(t *testing.T) {
	db1, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock db1: %v", err)
	}
	defer func() { _ = db1.Close() }()

	db2, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock db2: %v", err)
	}
	defer func() { _ = db2.Close() }()

	engine := &DatabaseDynamicPolicyEngine{
		db:           db1,
		metricsDB:    db1,
		policies:     make(map[string]interface{}),
		cacheTimeout: 30 * time.Second,
	}
	engine.policies["race_policy"] = map[string]interface{}{
		"name": "race_policy",
		"_metadata": map[string]interface{}{
			"tenant_id": "global",
			"org_id":    "global",
		},
		"conditions": []interface{}{
			map[string]interface{}{"field": "query", "operator": "contains", "value": "test"},
		},
	}

	req := OrchestratorRequest{
		Client: ClientContext{ID: "race-client", TenantID: "race-tenant"},
		Query:  "test query",
	}

	var wg sync.WaitGroup

	// Simulates connectDB's write path (db_dynamic_policies.go:282-286):
	// e.mu.Lock() around a fresh metricsDB assignment. Alternates pools so
	// every iteration is a real mutation, not a no-op the race detector
	// could optimize away.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			engine.mu.Lock()
			if i%2 == 0 {
				engine.metricsDB = db2
			} else {
				engine.metricsDB = db1
			}
			engine.mu.Unlock()
		}
	}()

	// Concurrent evaluations — each spawns the metrics-recording goroutine
	// that used to read e.metricsDB with no lock held.
	const goroutines = 20
	const evalsPerGoroutine = 20
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < evalsPerGoroutine; j++ {
				result := engine.EvaluateDynamicPolicies(context.Background(), req)
				if result == nil {
					t.Error("EvaluateDynamicPolicies returned nil result")
					return
				}
			}
		}()
	}

	wg.Wait()

	// Give the last few background metrics goroutines a moment to run their
	// (unsynchronized-if-buggy) reads before the process exits, so -race has
	// a chance to observe them.
	time.Sleep(50 * time.Millisecond)
}
