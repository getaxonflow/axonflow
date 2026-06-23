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

package agent

import (
	"context"
	"crypto/ed25519"
	"sync"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// benchSigningKey builds a deterministic Ed25519 key from a testing.TB (the
// shared testSigningKey helper takes *testing.T, which benchmarks can't supply).
func benchSigningKey(tb testing.TB) ed25519.PrivateKey {
	tb.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	return ed25519.NewKeyFromSeed(seed)
}

// withMemoryChainTracker points the package-level decisionChainTracker at a
// fresh memory-mode signing tracker for the duration of one test, restoring the
// prior value on cleanup. Memory mode exercises the SAME sealEntry signing +
// VerifyChain/VerifyRecord path as production, synchronously, with no DB, so a
// live recordSignedDecision call produces a signed record we can verify inline.
func withMemoryChainTracker(t *testing.T) *DecisionChainTracker {
	t.Helper()
	prev := decisionChainTracker
	tr := newSigningTracker(t) // DB nil => useMemory, with a signing key
	decisionChainTracker = tr
	t.Cleanup(func() { decisionChainTracker = prev })
	return tr
}

// TestRecordSignedDecision_LiveToVerify is the end-to-end DoD assertion: a live
// decision recorded through the wiring helper becomes a signed, chained record
// that BOTH verify endpoints accept, chain-level (authorship proven) and
// single-record standalone.
func TestRecordSignedDecision_LiveToVerify(t *testing.T) {
	tr := withMemoryChainTracker(t)
	ctx := context.Background()
	const org, tenant, decisionID = "org-live", "tenant-live", "dec-abc-123"

	recordSignedDecision(ctx, decisionID, org, tenant, "llm", "deny",
		[]string{"policy-sqli", "policy-pii"}, []string{"blocked by policy-pii"}, 7)

	// Chain verify: ChainID == decisionID, so the chain resolves by decisionID.
	chainRes, found, err := tr.VerifyChain(ctx, org, decisionID)
	if err != nil || !found {
		t.Fatalf("VerifyChain found=%v err=%v", found, err)
	}
	if !chainRes.Valid || !chainRes.AuthorshipProven {
		t.Fatalf("chain not proven: valid=%v authorshipProven=%v break=%q",
			chainRes.Valid, chainRes.AuthorshipProven, chainRes.BreakReason)
	}
	if chainRes.TotalRecords != 1 || chainRes.SignedRecords != 1 {
		t.Errorf("records total=%d signed=%d, want 1/1", chainRes.TotalRecords, chainRes.SignedRecords)
	}

	// The single record must carry the mapped, SIGNED outcome (deny -> blocked)
	// and the triggering policy.
	entries := tr.memoryChainForOrg(org, decisionID)
	if len(entries) != 1 {
		t.Fatalf("chain len = %d, want 1", len(entries))
	}
	got := entries[0]
	if got.DecisionOutcome != DecisionOutcomeBlocked {
		t.Errorf("outcome = %q, want %q", got.DecisionOutcome, DecisionOutcomeBlocked)
	}
	if got.DecisionType != DecisionTypeLLMGeneration {
		t.Errorf("type = %q, want %q", got.DecisionType, DecisionTypeLLMGeneration)
	}
	if got.PolicyTriggered != "policy-pii" {
		t.Errorf("policy_triggered = %q, want last-evaluated policy-pii", got.PolicyTriggered)
	}
	if got.OrgID != org || got.TenantID != tenant {
		t.Errorf("org/tenant = %q/%q, want %q/%q", got.OrgID, got.TenantID, org, tenant)
	}
	if got.RecordSignature == "" || got.SigningKeyID == "" {
		t.Error("record is not signed (empty signature/key id)")
	}

	// Standalone single-record verify (the /records/{id}/verify endpoint).
	recRes, rFound, rErr := tr.VerifyRecord(ctx, org, got.ID)
	if rErr != nil || !rFound {
		t.Fatalf("VerifyRecord found=%v err=%v", rFound, rErr)
	}
	if !recRes.Valid || !recRes.Signed || !recRes.SignatureValid {
		t.Fatalf("record not proven: valid=%v signed=%v sigValid=%v reason=%q",
			recRes.Valid, recRes.Signed, recRes.SignatureValid, recRes.Reason)
	}
}

// TestRecordSignedDecision_TamperBreaksVerify proves the record is tamper-EVIDENT:
// mutating a persisted field after signing breaks chain verification.
func TestRecordSignedDecision_TamperBreaksVerify(t *testing.T) {
	tr := withMemoryChainTracker(t)
	ctx := context.Background()
	const org, decisionID = "org-tamper", "dec-tamper-1"

	recordSignedDecision(ctx, decisionID, org, "tenant", "tool", "allowed", []string{"p1"}, nil, 3)

	// Flip the recorded outcome in the store (an attacker altering the DB row).
	// The signature was computed over the ORIGINAL outcome, so verification must
	// now fail. memoryStore is keyed by ChainID (== decisionID); the slice
	// element is addressable, so this mutates in place.
	tr.mu.Lock()
	tr.memoryStore[decisionID][0].DecisionOutcome = DecisionOutcomeBlocked
	tr.mu.Unlock()

	res, found, err := tr.VerifyChain(ctx, org, decisionID)
	if err != nil || !found {
		t.Fatalf("VerifyChain found=%v err=%v", found, err)
	}
	if res.Valid || res.SignaturesValid {
		t.Fatalf("expected tamper to break verification, got valid=%v signaturesValid=%v",
			res.Valid, res.SignaturesValid)
	}
	if res.BreakReason == "" {
		t.Error("expected a populated BreakReason on tamper")
	}
}

// TestRecordSignedDecision_CrossOrgIsolation proves a chain recorded for org A
// is invisible to org B at the verify endpoint (RLS analogue in memory mode).
func TestRecordSignedDecision_CrossOrgIsolation(t *testing.T) {
	tr := withMemoryChainTracker(t)
	ctx := context.Background()
	const orgA, orgB, decisionID = "org-A", "org-B", "dec-shared-id"

	recordSignedDecision(ctx, decisionID, orgA, "tenant-A", "agent", "allow", nil, nil, 1)

	// Same chain id, different org: must not be found.
	_, found, err := tr.VerifyChain(ctx, orgB, decisionID)
	if err != nil {
		t.Fatalf("VerifyChain err=%v", err)
	}
	if found {
		t.Fatal("org B must not see org A's chain (cross-org isolation breached)")
	}

	// And org A still sees its own.
	_, foundA, err := tr.VerifyChain(ctx, orgA, decisionID)
	if err != nil || !foundA {
		t.Fatalf("org A must see its own chain: found=%v err=%v", foundA, err)
	}
}

// TestRecordSignedDecision_MissingOrgSkips proves an empty OrgID is skipped +
// metered rather than recorded (decision_chain is FORCE RLS; an empty OrgID
// would be rejected), and never panics or records.
func TestRecordSignedDecision_MissingOrgSkips(t *testing.T) {
	tr := withMemoryChainTracker(t)
	ctx := context.Background()

	before := testutil.ToFloat64(decisionChainRecordSkipped.WithLabelValues("missing_org"))
	recordSignedDecision(ctx, "dec-no-org", "", "tenant", "llm", "deny", []string{"p"}, nil, 2)
	after := testutil.ToFloat64(decisionChainRecordSkipped.WithLabelValues("missing_org"))

	if after-before != 1 {
		t.Errorf("missing_org skip metric delta = %v, want 1", after-before)
	}
	// Nothing recorded for any org.
	if got := tr.GetStats()["decisions_recorded"].(uint64); got != 0 {
		t.Errorf("decisions_recorded = %d, want 0 (nothing should be recorded)", got)
	}
}

// TestRecordSignedDecision_MissingDecisionIDSkips proves an empty decision id is
// skipped + metered (no chain key to record against).
func TestRecordSignedDecision_MissingDecisionIDSkips(t *testing.T) {
	withMemoryChainTracker(t)
	ctx := context.Background()

	before := testutil.ToFloat64(decisionChainRecordSkipped.WithLabelValues("missing_decision_id"))
	recordSignedDecision(ctx, "", "org-x", "tenant", "llm", "deny", nil, nil, 2)
	after := testutil.ToFloat64(decisionChainRecordSkipped.WithLabelValues("missing_decision_id"))

	if after-before != 1 {
		t.Errorf("missing_decision_id skip metric delta = %v, want 1", after-before)
	}
}

// TestRecordSignedDecision_NilTrackerNoop proves the helper is a safe no-op when
// signing is not wired (DB-less deployment), no panic, no metric movement.
func TestRecordSignedDecision_NilTrackerNoop(t *testing.T) {
	prev := decisionChainTracker
	decisionChainTracker = nil
	t.Cleanup(func() { decisionChainTracker = prev })

	before := testutil.ToFloat64(decisionChainRecordSkipped.WithLabelValues("missing_org"))
	// Even with a bad (empty-org) input, a nil tracker must short-circuit BEFORE
	// the guards, so no metric moves and nothing panics.
	recordSignedDecision(context.Background(), "", "", "", "llm", "deny", nil, nil, 0)
	after := testutil.ToFloat64(decisionChainRecordSkipped.WithLabelValues("missing_org"))
	if after != before {
		t.Errorf("nil tracker must not move skip metric: before=%v after=%v", before, after)
	}
}

// BenchmarkRecordSignedDecision_AsyncEnqueue measures the PRODUCTION hot-path
// cost: a writing async tracker (DB present) where recordSignedDecision only
// enqueues, the per-(org,chain) advisory lock, Ed25519 sign and INSERT happen
// in the background workers. The backing DB is a mock that fails writes fast, so
// the worker outcome is irrelevant; what we measure is the caller-side enqueue,
// which must be cheap and independent of the (signing) write.
func BenchmarkRecordSignedDecision_AsyncEnqueue(b *testing.B) {
	db, _, err := sqlmock.New()
	if err != nil {
		b.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()
	tr, err := NewDecisionChainTracker(DecisionChainTrackerConfig{
		DB:         db,
		SystemID:   "bench/1.0.0",
		SigningKey: benchSigningKey(b),
		// AsyncQueueSize:0 => default writing queue (1000) + 2 workers.
	})
	if err != nil {
		b.Fatalf("new tracker: %v", err)
	}
	prev := decisionChainTracker
	decisionChainTracker = tr
	b.Cleanup(func() { decisionChainTracker = prev; _ = tr.Shutdown(context.Background()) })

	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		recordSignedDecision(ctx, "dec-bench", "org-bench", "tenant", "llm", "allow", []string{"p1"}, nil, 1)
	}
}

// BenchmarkRecordSignedDecision_SyncSign is the contrast: a memory tracker signs
// SYNCHRONOUSLY inside the call (ed25519.Sign on the caller's goroutine). The gap
// between this and the async benchmark above is the per-decision signing cost the
// async design keeps OFF the decision hot path.
func BenchmarkRecordSignedDecision_SyncSign(b *testing.B) {
	tr, err := NewDecisionChainTracker(DecisionChainTrackerConfig{
		SystemID:   "bench/1.0.0",
		SigningKey: benchSigningKey(b),
	})
	if err != nil {
		b.Fatalf("new tracker: %v", err)
	}
	prev := decisionChainTracker
	decisionChainTracker = tr
	b.Cleanup(func() { decisionChainTracker = prev })

	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Unique chain id per iter so this is genesis-append work, not unbounded
		// in-memory chain growth that would skew the per-op cost.
		recordSignedDecision(ctx, "dec-bench", "org-bench", "tenant", "llm", "allow", []string{"p1"}, nil, 1)
	}
}

// TestRecordSignedDecision_RecordErrorMetered proves a failing persistence does
// NOT propagate to the caller (the decision verdict is independent) but IS
// metered. Uses a SYNCHRONOUS DB-backed tracker (AsyncQueueSize:-1) over a
// sqlmock with no expectations, so the write fails inside RecordDecision and the
// helper takes its record_error branch.
func TestRecordSignedDecision_RecordErrorMetered(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()
	tr, err := NewDecisionChainTracker(DecisionChainTrackerConfig{
		DB:             db,
		SystemID:       "test/1.0.0",
		AsyncQueueSize: -1, // synchronous: the write (and its failure) happens in-call
		SigningKey:     benchSigningKey(t),
	})
	if err != nil {
		t.Fatalf("new tracker: %v", err)
	}
	prev := decisionChainTracker
	decisionChainTracker = tr
	t.Cleanup(func() { decisionChainTracker = prev })

	before := testutil.ToFloat64(decisionChainRecordSkipped.WithLabelValues("record_error"))
	// Must not panic / must not propagate despite the DB write failing.
	recordSignedDecision(context.Background(), "dec-err", "org-err", "tenant", "llm", "deny", []string{"p"}, nil, 1)
	after := testutil.ToFloat64(decisionChainRecordSkipped.WithLabelValues("record_error"))

	if after-before != 1 {
		t.Errorf("record_error metric delta = %v, want 1", after-before)
	}
}

// TestRecordDecision_ConcurrentShutdownNoPanic proves the producer/closer race
// is closed: many goroutines call RecordDecision (the live decision path) while
// another calls Shutdown, exactly the SIGTERM-flush-while-still-serving window
// this change activates. Before the queueMu guard, a producer could send to the
// just-closed asyncQueue and panic. Run under -race. A failure here surfaces as
// a "send on closed channel" panic, not an assertion.
func TestRecordDecision_ConcurrentShutdownNoPanic(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()
	tr, err := NewDecisionChainTracker(DecisionChainTrackerConfig{
		DB:         db,
		SystemID:   "test/1.0.0",
		SigningKey: benchSigningKey(t),
		// default writing queue + workers; mock writes fail fast, irrelevant here
	})
	if err != nil {
		t.Fatalf("new tracker: %v", err)
	}

	ctx := context.Background()
	var wg sync.WaitGroup
	const producers = 16
	for i := 0; i < producers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				// Any panic (send on closed channel) fails the test by crashing it.
				_ = tr.RecordDecision(ctx, DecisionEntry{
					ChainID: "c", RequestID: "r", OrgID: "o", TenantID: "tn",
					DecisionType: DecisionTypeLLMGeneration, DecisionOutcome: DecisionOutcomeApproved,
				})
			}
		}()
	}
	// Close mid-flight: producers above are actively sending.
	if err := tr.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	wg.Wait()
}

func TestDecisionTypeForStage(t *testing.T) {
	cases := map[string]DecisionType{
		"llm":     DecisionTypeLLMGeneration,
		"tool":    DecisionTypeDataRetrieval,
		"agent":   DecisionTypeSystemAction,
		"unknown": DecisionTypeSystemAction,
		"":        DecisionTypeSystemAction,
	}
	for stage, want := range cases {
		if got := decisionTypeForStage(stage); got != want {
			t.Errorf("decisionTypeForStage(%q) = %q, want %q", stage, got, want)
		}
	}
}

func TestDecisionOutcomeForVerdict(t *testing.T) {
	cases := map[string]DecisionOutcome{
		"allow":          DecisionOutcomeApproved,
		"allowed":        DecisionOutcomeApproved,
		"deny":           DecisionOutcomeBlocked,
		"blocked":        DecisionOutcomeBlocked,
		"redacted":       DecisionOutcomeModified,
		"needs_approval": DecisionOutcomePendingReview,
		"error":          DecisionOutcomeError,
		"garbage":        DecisionOutcomeError, // unknown is NEVER silently "approved"
		"":               DecisionOutcomeError,
	}
	for verdict, want := range cases {
		if got := decisionOutcomeForVerdict(verdict); got != want {
			t.Errorf("decisionOutcomeForVerdict(%q) = %q, want %q", verdict, got, want)
		}
	}
}
