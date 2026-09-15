// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package admission

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"axonflow/platform/agent/license"
)

// The node dimension's Field-Level rows (master ruling, 2026-09-08):
//   lease expired / unexpired; two nodes concurrent on Community (the second
//   refused with the distinct code); the same node restarting inside the TTL
//   (one node); the heartbeat write failing (existing node keeps serving);
//   store unreachable at boot (reported as dependency_unreachable, never
//   over_limit); a foreign EXPIRED lease (the new node takes over).

// fakeLeases is an in-memory NodeLeases with a movable clock.
type fakeLeases struct {
	mu    sync.Mutex
	now   time.Time
	rows  map[string]map[string]time.Time // org -> node -> last_seen
	down  bool
	calls int
}

func newFakeLeases() *fakeLeases {
	return &fakeLeases{now: time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC), rows: map[string]map[string]time.Time{}}
}

func (f *fakeLeases) Renew(_ context.Context, org, node string, ttl time.Duration, limit int) (Outcome, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.down {
		return Outcome{}, errors.New("lease store down")
	}
	if limit < 0 {
		return Outcome{}, errors.New("unlimited sentinel reached the lease store")
	}
	leases := f.rows[org]
	if leases == nil {
		leases = map[string]time.Time{}
		f.rows[org] = leases
	}
	out := Outcome{}
	for id, seen := range leases {
		if id != node && !seen.Before(f.now.Add(-ttl)) {
			out.Count++
		}
	}
	// HELD = holds an UNEXPIRED lease, mirroring the SQL. A fake that answers
	// "held" for a stale row hides exactly the defect the store had.
	if seen, held := leases[node]; held && !seen.Before(f.now.Add(-ttl)) {
		leases[node] = f.now
		out.Existing = true
		return out, nil
	}
	if out.Count >= limit {
		return out, nil
	}
	leases[node] = f.now
	out.Admitted = true
	return out, nil
}

func (f *fakeLeases) advance(d time.Duration) { f.mu.Lock(); f.now = f.now.Add(d); f.mu.Unlock() }

// setDown flips the kill switch under the lock; see fakeLedger.setDown.
func (f *fakeLeases) setDown(v bool) { f.mu.Lock(); f.down = v; f.mu.Unlock() }

func nodeAdmitter(leases NodeLeases, tier license.Tier, state string, audit AuditSink) *Admitter {
	opts := []Option{WithTierReader(readerFor(tier, state)), WithNodeLeases(leases)}
	if audit != nil {
		opts = append(opts, WithAuditSink(audit))
	}
	return New(newFakeLedger(), opts...)
}

// TestNodeDirectionOnCommunity: limit 1. The first node is admitted; a second
// concurrent node is refused with ERR_TIER_LIMIT_NODE and count 1; the first
// keeps renewing.
func TestNodeDirectionOnCommunity(t *testing.T) {
	leases := newFakeLeases()
	audit := &fakeAudit{}
	a := nodeAdmitter(leases, license.TierCommunity, LicenceAbsent, audit)
	before := refusals(t, Node, "community", ReasonOverLimit)

	first, err := a.Admit(context.Background(), Request{Dimension: Node, OrgID: "o", PrincipalID: "node-a"})
	if err != nil || !first.Allowed || first.Source != SourceLedgerAdmitted || first.Limit != 1 || first.Count != 0 {
		t.Fatalf("first node: %+v err=%v", first, err)
	}
	second, err := a.Admit(context.Background(), Request{Dimension: Node, OrgID: "o", PrincipalID: "node-b"})
	if err != nil || second.Allowed {
		t.Fatalf("second concurrent node on Community must be REFUSED: %+v err=%v", second, err)
	}
	if second.Reason != ReasonOverLimit || second.Code != "ERR_TIER_LIMIT_NODE" || second.Count != 1 || second.Limit != 1 {
		t.Errorf("refusal: %+v", second)
	}
	if got := refusals(t, Node, "community", ReasonOverLimit) - before; got != 1 {
		t.Errorf("metric moved %v, want 1", got)
	}
	a.WaitForRecording()
	if audit.len() != 1 || audit.rows[0].Dimension != Node {
		t.Errorf("audit rows=%d", audit.len())
	}
	if msg := second.Message(); !contains(msg, "AXONFLOW_NODE_ID") || !contains(msg, "ERR_TIER_LIMIT_NODE") {
		t.Errorf("node refusal must name the code and AXONFLOW_NODE_ID: %q", msg)
	}
	// The first node's heartbeat keeps renewing whatever the count.
	renew, err := a.Admit(context.Background(), Request{Dimension: Node, OrgID: "o", PrincipalID: "node-a"})
	if err != nil || !renew.Allowed || renew.Source != SourceLedgerExisting {
		t.Fatalf("existing node renewal: %+v err=%v", renew, err)
	}
	// N-1 / N / N+1 direction with a planted limit of 2: the 2nd is admitted,
	// the 3rd refused.
	b := New(newFakeLedger(), WithTierReader(readerFor(license.TierCommunity, LicenceAbsent)), WithNodeLeases(newFakeLeases()),
		WithLimits(func(license.Tier) license.TierLimits { return license.TierLimits{MaxNodes: 2} }))
	for i, id := range []string{"n1", "n2"} {
		if dec, err := b.Admit(context.Background(), Request{Dimension: Node, OrgID: "o", PrincipalID: id}); err != nil || !dec.Allowed || dec.Count != i {
			t.Fatalf("node %s under limit 2: %+v err=%v", id, dec, err)
		}
	}
	if dec, err := b.Admit(context.Background(), Request{Dimension: Node, OrgID: "o", PrincipalID: "n3"}); err != nil || dec.Allowed || dec.Count != 2 {
		t.Fatalf("3rd node under limit 2 must be refused with count 2: %+v err=%v", dec, err)
	}
}

// TestNodeEvaluationAndEnterpriseAreUnlimitedWithZeroIO: the node limit is -1
// on Evaluation and every Enterprise tier; the lease store is DOWN to prove
// no call is made.
func TestNodeEvaluationAndEnterpriseAreUnlimitedWithZeroIO(t *testing.T) {
	for _, tier := range []license.Tier{license.TierEvaluation, license.TierProfessional, license.TierEnterprise, license.TierEnterprisePlus} {
		leases := newFakeLeases()
		leases.setDown(true)
		a := nodeAdmitter(leases, tier, LicenceValid, nil)
		for _, id := range []string{"n1", "n2", "n3"} {
			dec, err := a.Admit(context.Background(), Request{Dimension: Node, OrgID: "o", PrincipalID: id})
			if err != nil || !dec.Allowed || dec.Source != SourceUnlimitedTier {
				t.Fatalf("%s node %s: %+v err=%v", tier, id, dec, err)
			}
		}
		if leases.calls != 0 {
			t.Fatalf("%s: lease store called %d times", tier, leases.calls)
		}
	}
}

// TestNodeSameNodeRestartingInsideTTLIsOneNode: a node that restarts and
// renews inside the TTL holds ONE lease, and a second node is still refused.
func TestNodeSameNodeRestartingInsideTTLIsOneNode(t *testing.T) {
	leases := newFakeLeases()
	a := nodeAdmitter(leases, license.TierCommunity, LicenceAbsent, nil)
	if dec, _ := a.Admit(context.Background(), Request{Dimension: Node, OrgID: "o", PrincipalID: "node-a"}); !dec.Allowed {
		t.Fatalf("first boot: %+v", dec)
	}
	leases.advance(NodeLeaseTTL / 2)
	// A NEW process for the same node id (fresh Admitter = fresh seen-set).
	restarted := nodeAdmitter(leases, license.TierCommunity, LicenceAbsent, nil)
	dec, err := restarted.Admit(context.Background(), Request{Dimension: Node, OrgID: "o", PrincipalID: "node-a"})
	if err != nil || !dec.Allowed || dec.Source != SourceLedgerExisting || dec.Count != 0 {
		t.Fatalf("same node after restart inside the TTL must renew as ONE node: %+v err=%v", dec, err)
	}
	if len(leases.rows["o"]) != 1 {
		t.Fatalf("%d lease rows for one node", len(leases.rows["o"]))
	}
	if dec, _ := restarted.Admit(context.Background(), Request{Dimension: Node, OrgID: "o", PrincipalID: "node-b"}); dec.Allowed {
		t.Fatalf("a second node is still refused while node-a's lease is unexpired: %+v", dec)
	}
}

// TestNodeExpiredForeignLeaseIsNotCounted: lease unexpired -> refused; the
// clock passes the TTL -> the new node takes over.
func TestNodeExpiredForeignLeaseIsNotCounted(t *testing.T) {
	leases := newFakeLeases()
	a := nodeAdmitter(leases, license.TierCommunity, LicenceAbsent, nil)
	if dec, _ := a.Admit(context.Background(), Request{Dimension: Node, OrgID: "o", PrincipalID: "old-pod"}); !dec.Allowed {
		t.Fatalf("old pod: %+v", dec)
	}
	// Unexpired (one second short of the TTL): refused.
	leases.advance(NodeLeaseTTL - time.Second)
	if dec, _ := a.Admit(context.Background(), Request{Dimension: Node, OrgID: "o", PrincipalID: "new-pod"}); dec.Allowed || dec.Reason != ReasonOverLimit {
		t.Fatalf("foreign UNEXPIRED lease must refuse the new node: %+v", dec)
	}
	// Expired (past the TTL): the new node takes over.
	leases.advance(2 * time.Second)
	dec, err := a.Admit(context.Background(), Request{Dimension: Node, OrgID: "o", PrincipalID: "new-pod"})
	if err != nil || !dec.Allowed || dec.Source != SourceLedgerAdmitted || dec.Count != 0 {
		t.Fatalf("foreign EXPIRED lease must not be counted; the new node takes over: %+v err=%v", dec, err)
	}
	// AND THE OLD POD, COMING BACK, IS NOW THE ONE REFUSED. Its row still
	// exists but its lease is EXPIRED, and an expired row is not "held": if it
	// were, both pods would renew for ever and the Community ceiling of one
	// would be permanently bypassed with no refusal, no metric and no audit
	// row. R3 round 1 found exactly that, and found this assertion written as
	// `if dec.Allowed { if dec.Source != ... }` - a branch that passed
	// whichever way it went. It is now a definite outcome.
	back, err := a.Admit(context.Background(), Request{Dimension: Node, OrgID: "o", PrincipalID: "old-pod"})
	if err != nil {
		t.Fatal(err)
	}
	if back.Allowed {
		t.Fatalf("the old pod came back to an EXPIRED lease while new-pod holds the only slot; it must be REFUSED, got %+v", back)
	}
	if back.Reason != ReasonOverLimit || back.Count != 1 {
		t.Fatalf("old pod's refusal: reason=%s count=%d, want over_limit with count 1", back.Reason, back.Count)
	}
	// And new-pod, which does hold an unexpired lease, still renews.
	if dec, _ := a.Admit(context.Background(), Request{Dimension: Node, OrgID: "o", PrincipalID: "new-pod"}); !dec.Allowed || dec.Source != SourceLedgerExisting {
		t.Fatalf("new-pod must keep renewing: %+v", dec)
	}
}

// TestNodeAStaleOwnLeaseDoesNotRenewPastTheCeiling is R3 round 1's H1 as its
// own test: the sequence that bypassed the limit permanently.
func TestNodeAStaleOwnLeaseDoesNotRenewPastTheCeiling(t *testing.T) {
	leases := newFakeLeases()
	a := nodeAdmitter(leases, license.TierCommunity, LicenceAbsent, nil)
	// A takes the lease, then stops heartbeating.
	if dec, _ := a.Admit(context.Background(), Request{Dimension: Node, OrgID: "o", PrincipalID: "A"}); !dec.Allowed {
		t.Fatalf("A: %+v", dec)
	}
	// Past the TTL, B takes over legitimately.
	leases.advance(NodeLeaseTTL + time.Second)
	if dec, _ := a.Admit(context.Background(), Request{Dimension: Node, OrgID: "o", PrincipalID: "B"}); !dec.Allowed {
		t.Fatalf("B must take over an expired lease: %+v", dec)
	}
	// A comes back with its row still in the table but its lease expired.
	dec, err := a.Admit(context.Background(), Request{Dimension: Node, OrgID: "o", PrincipalID: "A"})
	if err != nil {
		t.Fatal(err)
	}
	if dec.Allowed {
		t.Fatal("A renewed a STALE row while B holds the only slot: the Community node ceiling is bypassed for as long as both keep heartbeating, and nothing refuses, counts or audits it")
	}
	if dec.Reason != ReasonOverLimit {
		t.Fatalf("A's refusal reason: %s, want over_limit", dec.Reason)
	}
}

// TestNodeStoreUnreachableIsNeverOverLimit: at boot and mid-run, an
// unreachable lease store reports dependency_unreachable (counted, audited,
// Retry-After) and NEVER over_limit; the wiring boots / keeps serving on it.
func TestNodeStoreUnreachableIsNeverOverLimit(t *testing.T) {
	for _, ed := range limitedEditions {
		if ed.tier == license.TierEvaluation {
			continue // unlimited on nodes; covered above
		}
		leases := newFakeLeases()
		audit := &fakeAudit{}
		a := nodeAdmitter(leases, ed.tier, LicenceAbsent, audit)
		// Mid-run: admitted, then the store goes down at the next heartbeat.
		if dec, _ := a.Admit(context.Background(), Request{Dimension: Node, OrgID: "o", PrincipalID: "n"}); !dec.Allowed {
			t.Fatalf("boot: %+v", dec)
		}
		leases.setDown(true)
		over := refusals(t, Node, ed.edition, ReasonOverLimit)
		unreach := refusals(t, Node, ed.edition, ReasonDependencyUnreachable)
		dec, err := a.Admit(context.Background(), Request{Dimension: Node, OrgID: "o", PrincipalID: "n"})
		if err != nil || dec.Allowed || dec.Reason != ReasonDependencyUnreachable || dec.RetryAfter != RetryAfter {
			t.Fatalf("heartbeat with the store down: %+v err=%v", dec, err)
		}
		if refusals(t, Node, ed.edition, ReasonOverLimit) != over {
			t.Error("an unreachable store must not count as over_limit")
		}
		a.WaitForRecording()
		if refusals(t, Node, ed.edition, ReasonDependencyUnreachable)-unreach != 1 || audit.len() != 1 {
			t.Errorf("unreachable must be counted once and audited once: audit=%d", audit.len())
		}
		if a.Health().LedgerHealthy {
			t.Error("health must report degraded")
		}
		// At boot (a fresh process) with the store down: same answer, so the
		// wiring can tell "boot anyway" from "a second node".
		cold := nodeAdmitter(leases, ed.tier, LicenceAbsent, nil)
		if dec, _ := cold.Admit(context.Background(), Request{Dimension: Node, OrgID: "o", PrincipalID: "n2"}); dec.Allowed || dec.Reason != ReasonDependencyUnreachable {
			t.Fatalf("boot with the store down: %+v", dec)
		}
		// No store configured at all is the same posture.
		none := New(newFakeLedger(), WithTierReader(readerFor(ed.tier, LicenceAbsent)))
		if dec, _ := none.Admit(context.Background(), Request{Dimension: Node, OrgID: "o", PrincipalID: "n"}); dec.Allowed || dec.Reason != ReasonDependencyUnreachable {
			t.Fatalf("no lease store: %+v", dec)
		}
		// Recovery: the next heartbeat renews.
		leases.setDown(false)
		if dec, _ := a.Admit(context.Background(), Request{Dimension: Node, OrgID: "o", PrincipalID: "n"}); !dec.Allowed || dec.Source != SourceLedgerExisting {
			t.Fatalf("after recovery: %+v", dec)
		}
	}
}

// TestNodeZeroLimitRefusesNewButRenewsHeld: 0 nodes admits no NEW node and
// still renews a lease already held (an existing node is never refused).
func TestNodeZeroLimitRefusesNewButRenewsHeld(t *testing.T) {
	leases := newFakeLeases()
	leases.rows["o"] = map[string]time.Time{"held": leases.now}
	a := New(newFakeLedger(), WithTierReader(readerFor(license.TierCommunity, LicenceAbsent)), WithNodeLeases(leases),
		WithLimits(func(license.Tier) license.TierLimits { return license.TierLimits{MaxNodes: 0} }))
	if dec, _ := a.Admit(context.Background(), Request{Dimension: Node, OrgID: "o", PrincipalID: "new"}); dec.Allowed || dec.Reason != ReasonOverLimit || dec.Limit != 0 {
		t.Fatalf("limit 0 new node: %+v", dec)
	}
	if dec, _ := a.Admit(context.Background(), Request{Dimension: Node, OrgID: "o", PrincipalID: "held"}); !dec.Allowed || dec.Source != SourceLedgerExisting {
		t.Fatalf("limit 0 held lease must renew: %+v", dec)
	}
}

// TestNodeNeverTouchesTheLedgerOrTheSeenSet: every node call goes to the
// lease store; the ledger fake sees nothing and the seen-set stays empty.
func TestNodeNeverTouchesTheLedgerOrTheSeenSet(t *testing.T) {
	ledger := newFakeLedger()
	leases := newFakeLeases()
	a := New(ledger, WithTierReader(readerFor(license.TierCommunity, LicenceAbsent)), WithNodeLeases(leases))
	for i := 0; i < 3; i++ {
		if dec, _ := a.Admit(context.Background(), Request{Dimension: Node, OrgID: "o", PrincipalID: "n"}); !dec.Allowed || dec.SeenSetAnswered {
			t.Fatalf("call %d: %+v", i, dec)
		}
	}
	if ledger.calls != 0 || leases.calls != 3 || a.Health().SeenSetSize != 0 {
		t.Fatalf("ledger=%d leases=%d seen=%d", ledger.calls, leases.calls, a.Health().SeenSetSize)
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
