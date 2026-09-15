// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package pdp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/open-policy-agent/opa/v1/rego"

	"axonflow/platform/decision/contract"
)

// The cache's behaviour is asserted on a COMPILE COUNTER, not on elapsed time.
// "The second activation is faster" passes on a machine that compiled twice and
// happened to be warm; "the second activation did not reach the compiler" is
// the property the change actually makes.

func TestASecondActivationOfTheSameDigestDoesNotCompile(t *testing.T) {
	c := newPreparedQueryCache()
	b, err := BuildBundle(testDoc())
	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}
	key, err := keyFor(b)
	if err != nil {
		t.Fatalf("keyFor: %v", err)
	}

	compile := func() (rego.PreparedEvalQuery, error) { return rego.PreparedEvalQuery{}, nil }
	if _, err := c.get(key, compile); err != nil {
		t.Fatalf("first activation: %v", err)
	}
	if got := c.compileCount(); got != 1 {
		t.Fatalf("the first activation compiled %d times, want 1", got)
	}
	for i := 0; i < 5; i++ {
		if _, err := c.get(key, compile); err != nil {
			t.Fatalf("activation %d: %v", i+2, err)
		}
	}
	if got := c.compileCount(); got != 1 {
		t.Fatalf("six activations of one digest reached the compiler %d times, want 1; the cache is not holding", got)
	}
	if got := c.len(); got != 1 {
		t.Fatalf("the cache holds %d entries for one digest, want 1", got)
	}
}

func TestADifferentDigestCompiles(t *testing.T) {
	c := newPreparedQueryCache()

	first, err := BuildBundle(testDoc())
	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}
	// A different document: one more policy, so the module text, the manifest
	// and therefore the content digest all differ.
	other := testDoc()
	other.Policies = append(other.Policies, Policy{
		ID: "P2", Authority: contract.AuthorityPermission, Root: RootSystem,
		Scope:   Scope{Organization: true},
		Actions: ActionSelector{RequiredTags: []string{"spend"}},
		Where:   Compare("args.amount_cents", OpLe, 1),
	})
	second, err := BuildBundle(other)
	if err != nil {
		t.Fatalf("BuildBundle(other): %v", err)
	}

	k1, err := keyFor(first)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := keyFor(second)
	if err != nil {
		t.Fatal(err)
	}
	if k1 == k2 {
		t.Fatal("two different documents produced the same cache key; this test would prove nothing")
	}

	compile := func() (rego.PreparedEvalQuery, error) { return rego.PreparedEvalQuery{}, nil }
	if _, err := c.get(k1, compile); err != nil {
		t.Fatal(err)
	}
	if _, err := c.get(k2, compile); err != nil {
		t.Fatal(err)
	}
	if got := c.compileCount(); got != 2 {
		t.Fatalf("two different digests reached the compiler %d times, want 2; the cache is serving one bundle's query for another", got)
	}
	// And the first is still a hit.
	if _, err := c.get(k1, compile); err != nil {
		t.Fatal(err)
	}
	if got := c.compileCount(); got != 2 {
		t.Fatalf("re-activating the first digest compiled again (%d)", got)
	}
}

// THE POISON CASE. The key must come from CONTENT, never from the advertised
// Bundle.Digest, which is outside the signed view and can therefore be a lie
// on a bundle whose signature verifies.
func TestTheKeyIsTheContentDigestAndNotTheAdvertisedOne(t *testing.T) {
	honest, err := BuildBundle(testDoc())
	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}
	// Same content, a different label.
	mislabelled, err := BuildBundle(testDoc())
	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}
	mislabelled.Digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

	kh, err := keyFor(honest)
	if err != nil {
		t.Fatal(err)
	}
	km, err := keyFor(mislabelled)
	if err != nil {
		t.Fatal(err)
	}
	if kh != km {
		t.Fatal("two bundles with IDENTICAL content produced different cache keys; the key is reading the advertised label, so the same policy set would be compiled twice - and worse, a label could select the entry")
	}
	if km.digest == mislabelled.Digest {
		t.Fatal("the cache key IS the advertised digest; a mislabelled bundle would collect the entry its label names, which is one bundle's policies enforcing under another's name")
	}

	// The mirror: different content that happens to carry the SAME advertised
	// label must NOT share an entry.
	other := testDoc()
	other.Version = 2
	differing, err := BuildBundle(other)
	if err != nil {
		t.Fatal(err)
	}
	differing.Digest = honest.Digest // the same label over different content
	kd, err := keyFor(differing)
	if err != nil {
		t.Fatal(err)
	}
	if kd == kh {
		t.Fatal("two bundles with DIFFERENT content shared a cache key because they carried the same advertised digest; the mislabelled one would be served the other's compiled policies")
	}
}

// A FAILED compile is reported to every caller and is NOT cached, so the next
// activation compiles again.
//
// The reversal from "cache failures too" is deliberate and is the point of the
// next test: a cache cannot tell a bad bundle from a bad moment, and the
// failure it would enshrine is not always a property of the bundle.
func TestAFailedCompileIsReportedAndNotCached(t *testing.T) {
	c := newPreparedQueryCache()
	b, err := BuildBundle(testDoc())
	if err != nil {
		t.Fatal(err)
	}
	key, err := keyFor(b)
	if err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("strict compilation failed")
	fails := func() (rego.PreparedEvalQuery, error) { return rego.PreparedEvalQuery{}, sentinel }

	for i := 0; i < 3; i++ {
		if _, err := c.get(key, fails); !errors.Is(err, sentinel) {
			t.Fatalf("activation %d returned %v, want the compile error", i+1, err)
		}
	}
	if got := c.compileCount(); got != 3 {
		t.Fatalf("a failing compile ran %d times over three activations, want 3; a failure that is not a property of the bundle - a cancelled context, memory pressure - must not poison the digest for the life of the process", got)
	}
	if got := c.len(); got != 0 {
		t.Fatalf("the cache retained %d entr(ies) for a failed compile", got)
	}

	// And a later SUCCESS for the same digest is cached normally, so the
	// forgetting does not disable the cache for that bundle.
	ok := func() (rego.PreparedEvalQuery, error) { return rego.PreparedEvalQuery{}, nil }
	if _, err := c.get(key, ok); err != nil {
		t.Fatal(err)
	}
	before := c.compileCount()
	if _, err := c.get(key, ok); err != nil {
		t.Fatal(err)
	}
	if c.compileCount() != before {
		t.Error("a digest that failed and then succeeded is not being cached")
	}
}

// A PANICKING compile must not leave a usable-looking entry (#3693, R3 round 1).
//
// sync.Once counts a panicking call as done, so an entry whose compile panicked
// would keep its ZERO value: a PreparedEvalQuery that looks fine and a nil
// error. Every later activation of that digest would then get a
// successful-looking Runtime whose first Eval segfaults inside OPA - a loud
// boot-time panic turned into a silent bad activation that crashes on a
// decision request.
func TestAPanickingCompileDoesNotLeaveAUsableEntry(t *testing.T) {
	c := newPreparedQueryCache()
	b, err := BuildBundle(testDoc())
	if err != nil {
		t.Fatal(err)
	}
	key, err := keyFor(b)
	if err != nil {
		t.Fatal(err)
	}

	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Error("the panic did not propagate to the caller; an activation that panicked must not look like it returned")
			}
		}()
		_, _ = c.get(key, func() (rego.PreparedEvalQuery, error) { panic("the compiler exploded") })
	}()

	if got := c.len(); got != 0 {
		t.Fatalf("the cache retained %d entr(ies) after a panicking compile; a later activation would inherit a zero-valued query that looks like success", got)
	}

	// The next activation must genuinely compile, and must get a real result.
	compiled := 0
	got, err := c.get(key, func() (rego.PreparedEvalQuery, error) {
		compiled++
		return rego.PreparedEvalQuery{}, nil
	})
	if err != nil {
		t.Fatalf("the activation after a panic failed: %v", err)
	}
	_ = got
	if compiled != 1 {
		t.Fatalf("the activation after a panic reached the compiler %d times, want 1", compiled)
	}
}

// The map is BOUNDED, and the bound is enforced by EVICTING the least recently
// used entry. An earlier draft of this comment said the opposite - that past
// the cap a bundle is compiled without being cached - which described a design
// that was considered and not taken, over a body that has always asserted
// eviction. It is the last copy of that sentence, and it ships to the
// community mirror.
func TestThePreparedQueryCacheIsBounded(t *testing.T) {
	c := newPreparedQueryCache()
	compile := func() (rego.PreparedEvalQuery, error) { return rego.PreparedEvalQuery{}, nil }
	mk := func(i int) preparedKey {
		return preparedKey{root: RootSystem, digest: "sha256:" + strings.Repeat("0", 60) + string(rune('a'+i%26)) + string(rune('a'+i/26))}
	}
	for i := 0; i < maxPreparedQueries; i++ {
		if _, err := c.get(mk(i), compile); err != nil {
			t.Fatal(err)
		}
	}
	if got := c.len(); got != maxPreparedQueries {
		t.Fatalf("the cache holds %d entries after %d distinct digests", got, maxPreparedQueries)
	}
	// Past the cap the map stays at the cap and the LEAST RECENTLY USED entry
	// is dropped, so a caller that keeps producing new digests keeps a warm
	// working set instead of being locked out by the first sixteen.
	//
	// R3 round 2 found the design this replaced going inert: refusing to cache
	// past the cap meant authoring/gauntlet.go, which activates a fresh digest
	// for every draft it validates, would never get a hit again while sixteen
	// dead queries stayed pinned. That design is gone; what remains of it here
	// is the reason the cap evicts rather than refuses.
	before := c.len()
	if _, err := c.get(mk(maxPreparedQueries), compile); err != nil {
		t.Fatal(err)
	}
	if c.len() != before {
		t.Fatalf("the cache holds %d entries, want %d; it must stay AT the cap, not grow past it or shrink", c.len(), before)
	}
	if c.evictionCount() != 1 {
		t.Fatalf("%d eviction(s) recorded after one insert past the cap, want 1", c.evictionCount())
	}
	// mk(0) was the least recently used, so it is the one that went.
	at := c.compileCount()
	if _, err := c.get(mk(0), compile); err != nil {
		t.Fatal(err)
	}
	if c.compileCount() != at+1 {
		t.Error("the least recently used entry was not the one evicted")
	}
}

// EVICTION FOLLOWS USE, NOT INSERTION ORDER - asserted, because the previous
// test could not tell the difference.
//
// R3 round 3 deleted the lastUsed bump on a cache HIT, turning the policy from
// LRU into FIFO, and the whole package stayed green - including the test whose
// comment claimed to assert this. Insertion order and use order agree unless
// something is USED out of order, so the property needs a probe that touches
// an old entry and then forces an eviction.
//
// WHICH LINE CARRIES IT HAS SINCE MOVED, and this comment named the old one
// for a while after it stopped mattering. There were two bumps - one in get()
// on a hit, one in settleAndTrim - and deleting the first changed nothing,
// because a hit reaches settleAndTrim too. So round 3's mutant stopped being
// killed by anything while this comment still cited it. The redundant bump is
// gone; settleAndTrim is the single carrier, for hits and misses alike, and
// deleting ITS bump is the mutation this test now catches.
func TestEvictionFollowsUseRatherThanInsertionOrder(t *testing.T) {
	c := newPreparedQueryCache()
	compile := func() (rego.PreparedEvalQuery, error) { return rego.PreparedEvalQuery{}, nil }
	mk := func(i int) preparedKey {
		return preparedKey{root: RootSystem, digest: fmt.Sprintf("sha256:%060d", i)}
	}
	for i := 0; i < maxPreparedQueries; i++ {
		if _, err := c.get(mk(i), compile); err != nil {
			t.Fatal(err)
		}
	}
	// TOUCH the oldest-inserted entry, making it the most recently USED.
	if _, err := c.get(mk(0), compile); err != nil {
		t.Fatal(err)
	}
	// Insert one more. Under LRU the victim is mk(1) - the oldest USE - and
	// mk(0) survives. Under FIFO the victim is mk(0), which was inserted first.
	if _, err := c.get(mk(maxPreparedQueries), compile); err != nil {
		t.Fatal(err)
	}

	at := c.compileCount()
	if _, err := c.get(mk(0), compile); err != nil {
		t.Fatal(err)
	}
	if c.compileCount() != at {
		t.Error("the entry that was USED most recently was evicted; the policy is insertion-ordered (FIFO), not least-recently-used, so a hot digest is dropped while a cold one is kept")
	}
	at = c.compileCount()
	if _, err := c.get(mk(1), compile); err != nil {
		t.Fatal(err)
	}
	if c.compileCount() != at+1 {
		t.Error("the least recently USED entry survived the eviction; something other than use order chose the victim")
	}
}

// A FAILING activation must not evict a healthy entry.
//
// R3 round 3: a doomed entry was charged against the cap BEFORE its compile
// ran, so it evicted a neighbour and then removed itself - sixteen concurrent
// failures emptied a full warm cache. That is reachable on the authoring
// gauntlet, where an invalid draft is the normal case.
func TestAFailingActivationDoesNotEvictAHealthyEntry(t *testing.T) {
	c := newPreparedQueryCache()
	ok := func() (rego.PreparedEvalQuery, error) { return rego.PreparedEvalQuery{}, nil }
	fails := func() (rego.PreparedEvalQuery, error) { return rego.PreparedEvalQuery{}, errors.New("nope") }
	mk := func(i int) preparedKey {
		return preparedKey{root: RootSystem, digest: fmt.Sprintf("sha256:%060d", i)}
	}
	for i := 0; i < maxPreparedQueries; i++ {
		if _, err := c.get(mk(i), ok); err != nil {
			t.Fatal(err)
		}
	}
	before := c.len()
	evictionsBefore := c.evictionCount()
	for i := 0; i < maxPreparedQueries; i++ {
		if _, err := c.get(mk(1000+i), fails); err == nil {
			t.Fatal("the failing compile reported success")
		}
	}
	if c.len() != before {
		t.Errorf("the cache holds %d entries after %d failed activations, want %d; a compile that never succeeded displaced entries that had",
			c.len(), maxPreparedQueries, before)
	}
	if c.evictionCount() != evictionsBefore {
		t.Errorf("%d eviction(s) were charged to failed activations; the counter is meant to say the cache is too small, and a larger cache would have prevented none of these",
			c.evictionCount()-evictionsBefore)
	}
	// Every original entry is still a hit.
	at := c.compileCount()
	for i := 0; i < maxPreparedQueries; i++ {
		if _, err := c.get(mk(i), ok); err != nil {
			t.Fatal(err)
		}
	}
	if c.compileCount() != at {
		t.Errorf("%d of the %d warm entries were recompiled after a burst of failures", c.compileCount()-at, maxPreparedQueries)
	}
}

// A HIT ARRIVING DURING A BURST OF DOOMED COMPILES EVICTS NOTHING.
//
// This is the case that separates "the miss path declines to evict" from the
// property the CHANGELOG claims, which is that a failing activation cannot
// displace an entry that earned its place. Declining on the miss path leaves
// the map sitting over the cap while doomed compiles run, and trimToCap fires
// from EVERY successful caller - including an ordinary cache hit that has
// nothing to do with the burst. R3 round 4 measured exactly that: 24 compiles
// in flight put 40 entries in a map with a cap of 16, one hit arrived, and a
// warm entry was recompiled.
//
// The distinguishing input is therefore a hit that lands WHILE the doomed
// compiles are still in flight. The earlier test runs its failures to
// completion first, so the map is already back under the cap by the time
// anything succeeds, and it passes under both designs.
func TestAHitDuringInFlightCompilesEvictsNothing(t *testing.T) {
	c := newPreparedQueryCache()
	okCompile := func() (rego.PreparedEvalQuery, error) { return rego.PreparedEvalQuery{}, nil }
	mk := func(i int) preparedKey {
		return preparedKey{root: RootSystem, digest: fmt.Sprintf("sha256:%060d", i)}
	}
	for i := 0; i < maxPreparedQueries; i++ {
		if _, err := c.get(mk(i), okCompile); err != nil {
			t.Fatal(err)
		}
	}
	warm := c.compileCount()
	evictionsBefore := c.evictionCount()

	// Park a burst of compiles inside the compiler, so they are IN FLIGHT
	// rather than finished, then let them all fail.
	const inFlight = 24
	entered := make(chan struct{}, inFlight)
	release := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < inFlight; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _ = c.get(mk(1000+i), func() (rego.PreparedEvalQuery, error) {
				entered <- struct{}{}
				<-release
				return rego.PreparedEvalQuery{}, errors.New("nope")
			})
		}(i)
	}
	for i := 0; i < inFlight; i++ {
		<-entered
	}
	// PRECONDITION: the map really is over the cap right now. Without this the
	// assertion below could pass because the burst had already drained.
	if c.len() <= maxPreparedQueries {
		t.Fatalf("the map holds %d entries with %d compiles parked inside the compiler; this test needs it to be over the cap of %d or it is asserting nothing",
			c.len(), inFlight, maxPreparedQueries)
	}

	// The hit. It succeeds, so it trims - and must find nothing to evict.
	if _, err := c.get(mk(0), okCompile); err != nil {
		t.Fatal(err)
	}
	if got := c.evictionCount() - evictionsBefore; got != 0 {
		t.Errorf("a cache HIT arriving during %d in-flight compiles evicted %d entry(ies); a compile that has not returned has not earned a place and must not cost one",
			inFlight, got)
	}

	close(release)
	wg.Wait()

	// And every warm entry is still a hit. Measured against the count AFTER
	// the burst: those 24 doomed compiles each reached the compiler once by
	// design, and charging them to the warm set would make this assertion fail
	// for a reason that has nothing to do with eviction.
	afterBurst := c.compileCount()
	if afterBurst != warm+inFlight {
		t.Fatalf("the burst reached the compiler %d time(s), want %d; this test's arithmetic below assumes each doomed activation compiled exactly once",
			afterBurst-warm, inFlight)
	}
	for i := 0; i < maxPreparedQueries; i++ {
		if _, err := c.get(mk(i), okCompile); err != nil {
			t.Fatal(err)
		}
	}
	if c.compileCount() != afterBurst {
		t.Errorf("%d of the %d warm entries were recompiled after the burst", c.compileCount()-afterBurst, maxPreparedQueries)
	}
}

// AN IN-FLIGHT COMPILE IS NEVER THE VICTIM, EVEN WHEN IT IS THE LEAST
// RECENTLY USED.
//
// The test above cannot show this: there the settled population sits exactly
// AT the cap when the hit lands, so the trim loop never runs a single
// iteration and an eviction rule that ignored `settled` would pass it. The
// distinguishing input needs the settled population to go OVER the cap while
// an unsettled entry is the oldest thing in the map - which is the ordinary
// shape of the hazard, because an entry's lastUsed is set when it is created
// and a twelve-second compile does nothing to refresh it. The longer a compile
// takes, the older its entry looks.
func TestAnInFlightCompileIsNotEvictedEvenWhenItIsTheOldest(t *testing.T) {
	c := newPreparedQueryCache()
	okCompile := func() (rego.PreparedEvalQuery, error) { return rego.PreparedEvalQuery{}, nil }
	mk := func(i int) preparedKey {
		return preparedKey{root: RootSystem, digest: fmt.Sprintf("sha256:%060d", i)}
	}
	slow := mk(999)

	// The slow entry is created FIRST, so it is the oldest thing in the map,
	// and it is still compiling when everything below happens.
	entered := make(chan struct{})
	release := make(chan struct{})
	compiles := 0
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = c.get(slow, func() (rego.PreparedEvalQuery, error) {
			compiles++
			close(entered)
			<-release
			return rego.PreparedEvalQuery{}, nil
		})
	}()
	<-entered

	// Fill to the cap, then one more, so the SETTLED population goes over it
	// and the trim loop actually runs.
	for i := 0; i <= maxPreparedQueries; i++ {
		if _, err := c.get(mk(i), okCompile); err != nil {
			t.Fatal(err)
		}
	}

	// PRECONDITIONS, both of them. The trim must have run, and the slow entry
	// must genuinely be the oldest - otherwise this passes for the wrong
	// reason.
	if c.evictionCount() == 0 {
		t.Fatal("no eviction happened, so the trim loop never ran and this test is asserting nothing")
	}
	c.mu.Lock()
	slowEntry, present := c.entries[slow]
	var oldest bool
	if present {
		oldest = true
		for k, e := range c.entries {
			if k != slow && e.lastUsed < slowEntry.lastUsed {
				oldest = false
			}
		}
	}
	c.mu.Unlock()
	if !present {
		t.Fatal("the in-flight compile's entry was EVICTED; an activation still inside the compiler has not earned its place and cannot lose one, and discarding it throws away work already under way")
	}
	if !oldest {
		t.Fatal("the in-flight entry is not the oldest in the map, so this test no longer distinguishes an eviction rule that skips unsettled entries from one that does not")
	}

	close(release)
	wg.Wait()

	// And it was compiled exactly once: nothing forced a redo.
	if compiles != 1 {
		t.Errorf("the slow bundle reached the compiler %d time(s), want 1", compiles)
	}
}

// A FRESHLY COMPILED ENTRY DOES NOT EVICT ITSELF.
//
// An entry's lastUsed is stamped when it is CREATED, which for a miss is
// before a compile that the profile in this PR measures at twelve seconds for
// 500 policies. Any hit landing during that window gets a higher lastUsed, so
// by the time the compile returns its own entry can be the least recently used
// thing in the map - and it is that entry's own trim that runs next. It would
// evict itself, and the very next activation of that bundle would pay the
// twelve seconds again.
//
// settleAndTrim bumps lastUsed before trimming, which is also just true: the
// entry HAS only now been used. This is the assertion that keeps that from
// being a comment. It is also what replaced an explicit "never evict the entry
// the caller just settled" guard, which was unreachable once the bump existed
// and so was a branch nothing could test.
func TestAFreshlyCompiledEntryDoesNotEvictItself(t *testing.T) {
	c := newPreparedQueryCache()
	okCompile := func() (rego.PreparedEvalQuery, error) { return rego.PreparedEvalQuery{}, nil }
	mk := func(i int) preparedKey {
		return preparedKey{root: RootSystem, digest: fmt.Sprintf("sha256:%060d", i)}
	}
	slow := mk(999)

	entered := make(chan struct{})
	release := make(chan struct{})
	compiles := 0
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = c.get(slow, func() (rego.PreparedEvalQuery, error) {
			compiles++
			close(entered)
			<-release
			return rego.PreparedEvalQuery{}, nil
		})
	}()
	<-entered

	// Fill the cache while the slow compile runs, then TOUCH every warm entry
	// so each one's lastUsed is above the slow entry's creation stamp. Without
	// this the slow entry is not the oldest and the test proves nothing.
	for i := 0; i < maxPreparedQueries; i++ {
		if _, err := c.get(mk(i), okCompile); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < maxPreparedQueries; i++ {
		if _, err := c.get(mk(i), okCompile); err != nil {
			t.Fatal(err)
		}
	}
	c.mu.Lock()
	slowEntry := c.entries[slow]
	stale := slowEntry != nil
	if stale {
		for k, e := range c.entries {
			if k != slow && e.lastUsed < slowEntry.lastUsed {
				stale = false
			}
		}
	}
	c.mu.Unlock()
	if !stale {
		t.Fatal("the slow entry is not the oldest in the map before it settles; this test cannot distinguish a lastUsed bump at settle time from its absence")
	}

	// Now let it finish. Settling takes the population to cap+1, so its own
	// trim runs, and it must not choose itself.
	close(release)
	wg.Wait()

	c.mu.Lock()
	_, present := c.entries[slow]
	c.mu.Unlock()
	if !present {
		t.Fatal("the entry evicted ITSELF the moment it finished compiling; lastUsed must be bumped when an entry settles, or the slowest bundle in the process is the one that is never cached")
	}
	at := c.compileCount()
	if _, err := c.get(slow, okCompile); err != nil {
		t.Fatal(err)
	}
	if c.compileCount() != at {
		t.Error("the bundle that had just been compiled was compiled again on the very next activation")
	}
	if compiles != 1 {
		t.Errorf("the slow bundle reached the compiler %d time(s), want 1", compiles)
	}
}

// Concurrent activations of one digest compile ONCE. The compile is the
// twelve-second half, so two goroutines racing it is the case the cache exists
// to prevent, not merely a tidiness concern.
func TestConcurrentActivationsOfOneDigestCompileOnce(t *testing.T) {
	c := newPreparedQueryCache()
	b, err := BuildBundle(testDoc())
	if err != nil {
		t.Fatal(err)
	}
	key, err := keyFor(b)
	if err != nil {
		t.Fatal(err)
	}
	var started sync.WaitGroup
	started.Add(1)
	compile := func() (rego.PreparedEvalQuery, error) {
		started.Done()
		return rego.PreparedEvalQuery{}, nil
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.get(key, compile); err != nil {
				t.Errorf("concurrent activation: %v", err)
			}
		}()
	}
	wg.Wait()
	if got := c.compileCount(); got != 1 {
		t.Fatalf("eight concurrent activations of one digest compiled %d times, want 1", got)
	}
}

// END TO END through NewRuntime: the real compiler, the real bundle, and the
// process-wide cache the engine uses. This is the one that would catch the
// cache being wired up but never consulted.
func TestNewRuntimeCompilesOncePerDigest(t *testing.T) {
	ctx := context.Background()
	// A document unique to THIS test. Using the shared fixture made the named
	// assertion vacuous whenever another test had already warmed the global
	// cache for it: the first activation here would be a hit, so "the second
	// did not compile" was true without proving anything.
	doc := testDoc()
	doc.Version = 4242
	b, err := BuildBundle(doc)
	if err != nil {
		t.Fatal(err)
	}
	// -count=2 runs this test twice in one process, so the global cache may
	// already hold these digests. Both are forgotten first: this test is about
	// what NewRuntime does on a COLD digest, and inheriting a warm one from a
	// previous iteration made its assertions vacuous - the "same digest does
	// not recompile" one trivially, and the "a different bundle does" one by
	// failing outright.
	other := testDoc()
	other.Version = 4243
	ob, err := BuildBundle(other)
	if err != nil {
		t.Fatal(err)
	}
	forget := func(bundle *Bundle) {
		key, err := keyFor(bundle)
		if err != nil {
			t.Fatal(err)
		}
		globalPreparedQueries.mu.Lock()
		delete(globalPreparedQueries.entries, key)
		globalPreparedQueries.mu.Unlock()
	}
	forget(b)
	forget(ob)
	before := globalPreparedQueries.compileCount()

	first, err := NewRuntime(ctx, b, DefaultLimits())
	if err != nil {
		t.Fatalf("first NewRuntime: %v", err)
	}
	afterFirst := globalPreparedQueries.compileCount()

	second, err := NewRuntime(ctx, b, DefaultLimits())
	if err != nil {
		t.Fatalf("second NewRuntime: %v", err)
	}
	afterSecond := globalPreparedQueries.compileCount()

	if afterSecond != afterFirst {
		t.Errorf("the second activation of the same digest reached the compiler (%d -> %d)", afterFirst, afterSecond)
	}
	if afterFirst-before > 1 {
		t.Errorf("the first activation compiled %d times", afterFirst-before)
	}
	if first == nil || second == nil {
		t.Fatal("NewRuntime returned a nil runtime")
	}
	// Two runtimes, one prepared query: the Runtime value is per activation
	// (it carries its own limits and manifest) and only the compiled query is
	// shared, which is what makes sharing safe.
	if first == second {
		t.Error("the two activations returned the SAME *Runtime; limits and manifest are per activation and must not be shared")
	}
	if first.limits != second.limits {
		t.Error("the two runtimes disagree about their limits")
	}

	// A different bundle still compiles, through the real path.
	if _, err := NewRuntime(ctx, ob, DefaultLimits()); err != nil {
		t.Fatalf("NewRuntime(other): %v", err)
	}
	if globalPreparedQueries.compileCount() != afterSecond+1 {
		t.Errorf("a different bundle did not reach the compiler (%d -> %d)", afterSecond, globalPreparedQueries.compileCount())
	}
}
