// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package pdp

import (
	"errors"
	"fmt"
	"sync"

	"github.com/open-policy-agent/opa/v1/rego"
)

// THE PREPARED-QUERY CACHE (#3693).
//
// Gate 17 measured bundle activation at 5.3 ms / 238 ms / 12.3 s for 10 / 100 /
// 500 policies: five times the policies for roughly fifty times the time. The
// profile in gate17_activation_profile_test.go splits NewRuntime's two halves
// and names the term. THE STABLE FIGURE IS THE SPLIT, NOT THE RATIO: on an M4
// Pro at 500 policies, lint is ~12 ms of a ~11.94 s activation, so the lint is
// 0.1% of the cost. The growth RATIOS are ratios of two noisy small numbers at
// the 10-policy end and vary run to run - three runs on the same machine class
// put the lint ratio between 34x and 49x - so they are reported by the profile
// and deliberately not quoted here as if they were constants. Whichever run
// you take, the compile is the curve and the lint is not.
//
// So the cache is on the compile. An activation of a digest this process has
// already compiled is a map hit rather than a second twelve-second compile,
// which is what a deployment pays on every restart, per bundle root, today.
//
// # WHY THE KEY IS THE CONTENT DIGEST AND NOTHING ELSE
//
// The key is (root, content digest of the bundle) where the digest is
// RECOMPUTED from the bundle's signed view, never read from the advertised
// Bundle.Digest field. Digest is outside the signed view, so a bundle whose
// content does not hash to its advertised digest still carries a valid
// signature; keying on the advertised value would let a mislabelled bundle
// collect another bundle's compiled query, which is the worst failure this
// cache could have - one bundle's policies enforcing under another's name.
// contract.ExactDigest over the same view TrustStore.Verify hashes is the only
// key that means "this exact policy content".
//
// The ROOT is in the key as well, even though the module text already differs
// per root: the prepared query is compiled against `data.<package>.result` and
// the package is derived from the root, so two roots are two different queries
// even in the impossible case that their content digests collided.
//
// # WHAT THE CACHE DOES NOT CHANGE
//
// The lint still runs on every activation. It is 12 ms at 500 policies, it is
// a correctness check on the bundle rather than on the process, and skipping it
// on a cache hit would mean a bundle hand-edited between two activations in one
// process was linted once. Moving it to publish time is a proposal on #3693
// with the numbers above, not a change made here: the profile says it would buy
// 0.1% of the activation cost, so it is a tidiness argument rather than a
// performance one, and it would remove a check from the load path.
//
// The cache is per PROCESS and BOUNDED: maxPreparedQueries entries, with the
// least recently used evicted to make room. Every entry is a bundle this
// process has already verified.
//
// This paragraph said "unbounded" and "it is not an LRU" for two revisions
// after it became both, which is why it now states the mechanism rather than
// the reasoning that produced it - a headline comment that argues against the
// code beneath it is worse than none, and this is the comment the CHANGELOG
// and NewRuntime both point a reader at. The bound and the eviction policy are
// argued where they are implemented, in get().

// preparedQueryCache holds compiled queries by (root, content digest).
type preparedQueryCache struct {
	mu      sync.Mutex
	entries map[preparedKey]*preparedEntry
	// compiles counts cache MISSES that reached rego.PrepareForEval. It is
	// what the tests assert on: "the second activation of the same digest does
	// no compile" is a statement about this counter, and a test that only
	// timed the two activations would pass on a fast machine that compiled
	// twice.
	compiles int
	// evictions counts entries dropped because the map was full. A rising
	// count in a long-lived process is the signal that maxPreparedQueries is
	// too small for that deployment: digests are being recompiled that a
	// slightly larger cache would have held. It is READ by evictionCount,
	// which the tests assert on - an unread counter is a comment with a type,
	// which is what R3 round 2 found the previous one to be.
	evictions int
	// clock orders entries for eviction. A counter rather than a timestamp:
	// it needs only an order, and a monotonic integer cannot go backwards
	// when the wall clock does.
	clock uint64
}

// maxPreparedQueries bounds the map. A prepared query retains roughly 1.7 MB
// at 100 policies and 6.8 MB at 500, so 16 entries is about 27 MB at the
// hundred-policy scale a deployment actually runs and about 109 MB at the
// 500-policy scale the gate 17 measurements use. A deployment holds a handful
// of roots and rolls forward through digests slowly; an AUTHORING surface does
// not, which is why the bound exists.
const maxPreparedQueries = 16

type preparedKey struct {
	root   Root
	digest string
}

// preparedEntry is one compiled query plus the sync.Once that compiled it.
//
// The Once is what keeps two goroutines activating the same digest from both
// paying the compile. The outer mutex is held only while the entry is created,
// never while it is compiled, so a twelve-second compile of one bundle does not
// block an activation of a different one.
type preparedEntry struct {
	// lastUsed orders this entry against the others for eviction.
	lastUsed uint64
	// settled marks an entry whose compile RETURNED SUCCESSFULLY. Only
	// settled entries count against the cap and only settled entries are
	// evicted, so an activation that is still compiling - and may be about to
	// fail - can neither displace a warm entry nor be displaced by one.
	//
	// This is the field that makes "a failing activation cannot displace an
	// entry that earned its place" TRUE rather than nearly true. Declining to
	// evict on the miss path is not enough on its own: the map still sat over
	// the cap while doomed compiles ran, and trimToCap fires from every
	// successful caller, so a single ordinary cache HIT arriving during those
	// compiles evicted warm entries on their behalf. R3 round 4 measured it -
	// 24 compiles in flight put 40 entries in a map with a cap of 16, and one
	// hit recompiled a warm bundle. Counting settled entries only removes the
	// mechanism instead of narrowing the sentence.
	//
	// Written under mu, never inside the Once, so the race detector has a
	// happens-before edge for every reader.
	settled  bool
	once     sync.Once
	prepared rego.PreparedEvalQuery
	err      error
}

// globalPreparedQueries is the process-wide cache. NewRuntime uses it; tests
// that need isolation build their own with newPreparedQueryCache.
var globalPreparedQueries = newPreparedQueryCache()

func newPreparedQueryCache() *preparedQueryCache {
	return &preparedQueryCache{entries: map[preparedKey]*preparedEntry{}}
}

// get returns the compiled query for key, compiling it with compile on the
// first call for that key and returning the same value afterwards.
//
// ONLY SUCCESS IS CACHED. An earlier version cached failures too, arguing that
// the inputs are fixed so a compile that failed once fails identically every
// time. R3 round 1 falsified that in the sharpest possible way: if the compiler
// PANICS, sync.Once still counts the call as done, so the entry keeps its zero
// value - a usable-looking PreparedEvalQuery and a nil error. Every later
// activation of that digest then gets a successful-looking Runtime whose first
// Eval segfaults inside OPA. A loud boot-time panic would have become a silent
// bad activation that crashes on a decision request, which is a strictly worse
// failure than the repeated work the caching was avoiding.
//
// The same reasoning retires the other half of that argument: a compile can
// fail for a reason that is NOT a property of the bundle - a cancelled context,
// memory pressure - and caching that poisons the digest for the life of the
// process. So a failed or panicking compile forgets its entry and the next
// activation retries. The bounded-work concern is real but belongs to the
// caller's retry policy, not to a cache that cannot tell a bad bundle from a
// bad moment.
func (c *preparedQueryCache) get(key preparedKey, compile func() (rego.PreparedEvalQuery, error)) (rego.PreparedEvalQuery, error) {
	c.mu.Lock()
	entry, ok := c.entries[key]
	// NO BUMP HERE, and its removal is the point. A hit used to stamp lastUsed
	// on this line and then stamp it again in settleAndTrim moments later, and
	// review found the consequence: deleting THIS line changed nothing, so a
	// mutant that had been verified as killed now survived, and the test whose
	// doc comment named that mutation no longer caught it. settleAndTrim is the
	// single carrier of LRU-on-use for hits and misses alike - a hit reaches it
	// because a settled entry's compile returns nil - which is the same "a
	// branch that can no longer fire is a branch nothing tests" argument that
	// removed the explicit `keep` parameter, applied to the other half of this
	// function.
	if !ok {
		// NO EVICTION HERE. An entry whose compile has not run yet may be
		// about to fail or panic, and evicting a healthy neighbour on its
		// behalf costs a real recompile for a bundle that was never cached.
		// R3 round 3 measured the consequence: sixteen concurrent failing
		// activations emptied a full warm cache and left nothing, which is
		// reachable on the authoring gauntlet, where invalid drafts are the
		// normal case. The map may therefore hold MORE than the cap - by
		// exactly the number of compiles in flight, which is 24 extra under 24
		// concurrent activations, not one - and that is why the cap is counted
		// over SETTLED entries rather than over len(entries). See the note on
		// preparedEntry.settled.
		c.clock++
		entry = &preparedEntry{lastUsed: c.clock}
		c.entries[key] = entry
	}
	c.mu.Unlock()

	entry.once.Do(func() {
		c.mu.Lock()
		c.compiles++
		c.mu.Unlock()
		// The entry starts as a FAILURE and becomes a success only if compile
		// returns normally. If it panics, this value is what a concurrent
		// waiter sees, and the deferred forget below removes the entry so the
		// next activation compiles again instead of inheriting a corpse.
		entry.err = errCompileDidNotReturn
		defer func() {
			if entry.err != nil {
				c.forget(key, entry)
			}
		}()
		entry.prepared, entry.err = compile()
	})
	if entry.err == nil {
		c.settleAndTrim(key, entry)
	}
	return entry.prepared, entry.err
}

// settleAndTrim marks an entry as having earned its place and then brings the
// SETTLED population back within the cap.
//
// The two happen under one lock because they are one fact: this entry has just
// been used, so it becomes the most recently used, and only then can the
// eviction that follows be reasoned about. Bumping lastUsed here is also what
// makes the caller's own entry safe without a special case: a miss sets
// lastUsed at CREATION, before a compile that can take twelve seconds, so any
// hit during that compile would otherwise leave the freshly compiled entry as
// the least recently used and therefore its own trim's first victim.
func (c *preparedQueryCache) settleAndTrim(key preparedKey, entry *preparedEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// REACHED OFTEN, AND THE COMMENT THAT SAID OTHERWISE WAS WRONG. An earlier
	// version of this called the branch "unreachable today" and argued that
	// nothing can remove an entry while its compile runs. Review instrumented
	// it: taken 103 times in 202 rounds under -race.
	//
	// THREE CALLERS REACH IT, not one. The waiter on the sync.Once is the
	// commonest and was the one the earlier reasoning missed - it runs this
	// function after the winner returns, by which time the entry is settled and
	// therefore evictable, so a waiter whose entry has since been evicted and
	// replaced finds a different pointer under the key. But sync.Once orders
	// the FUNCTION, not the callers' returns, so the winner can arrive here
	// last; and a plain hit reaches it too. Instrumented over 1,057 takes:
	// waiter 990, winner 60, plain hit 7. Naming only the waiter would be the
	// same over-precision as the "unreachable" claim it replaced, one step
	// smaller.
	//
	// DELETING it has no killable mutant: both paths leave the map correct,
	// because the write it skips would be to an entry nobody holds. INVERTING
	// it reds three tests. So the honest claim is about the deletion
	// specifically, not about the branch in general. It is a guard whose value
	// is that it cannot go wrong, not a branch under test - and the
	// distinction is worth stating, because "no mutant kills it" and
	// "unreachable" look the same from the outside and are not the same fact.
	if c.entries[key] != entry {
		return
	}
	c.clock++
	entry.lastUsed = c.clock
	entry.settled = true
	for c.settledLocked() > maxPreparedQueries {
		if !c.evictLRULocked() {
			return
		}
	}
}

// settledLocked counts the entries that count against the cap. The caller
// holds mu.
func (c *preparedQueryCache) settledLocked() int {
	n := 0
	for _, e := range c.entries {
		if e.settled {
			n++
		}
	}
	return n
}

// A NOTE ON CONTEXTS, because the cached closure captures one. The compile is
// invoked by whichever caller wins the sync.Once, with THAT caller's context,
// so a goroutine waiting on the Once inherits a failure caused by someone
// else's cancellation. It is bounded - failures are not cached, so the next
// activation compiles again - and it is latent today because OPA's
// PrepareForEval does not consult the context at all. Nothing pins that, so it
// is written here rather than assumed away.

// errCompileDidNotReturn is what an entry holds while its compile is running
// and what it keeps if that compile panics.
var errCompileDidNotReturn = errors.New("pdp: the policy compiler did not return (it panicked); this bundle was not activated")

// forget removes an entry, but only if it is still the entry it was handed -
// a later activation may already have installed a fresh one.
func (c *preparedQueryCache) forget(key preparedKey, entry *preparedEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries[key] == entry {
		delete(c.entries, key)
	}
}

// evictLRULocked drops the least recently used SETTLED entry, and returns
// false when there is none. The caller holds mu.
//
// UNSETTLED ENTRIES ARE NOT CANDIDATES. An in-flight compile has not earned a
// place and cannot lose one; evicting it would make a neighbour's trim cause a
// recompile of work already under way, and the longer the compile the more
// certain it would be to be chosen, because its lastUsed only gets older.
//
// There is no `keep` parameter any more. It existed to stop a caller evicting
// the entry it had just compiled, and settleAndTrim now bumps that entry's
// lastUsed before trimming, so it is the most recently used by construction.
// A guard that can no longer fire is a branch nothing tests.
func (c *preparedQueryCache) evictLRULocked() bool {
	var oldestKey preparedKey
	var oldest uint64
	first := true
	for k, e := range c.entries {
		if !e.settled {
			continue
		}
		if first || e.lastUsed < oldest {
			oldestKey, oldest, first = k, e.lastUsed, false
		}
	}
	if first {
		return false
	}
	delete(c.entries, oldestKey)
	c.evictions++
	return true
}

// evictionCount reports how many entries were dropped to stay under the cap.
//
// EVERY CALLER IS A TEST, and that is a stated limit rather than an oversight
// waiting to be noticed. The number means "the cap is too small for this
// process's working set", which is the operational question a cache like this
// raises - and nothing observes it: no metric, no log, no boot-time report.
// So a deployment whose activation cost is dominated by thrashing looks
// exactly like one whose cache is comfortable.
//
// It is not wired up here because this package has no metrics surface, and
// adding one is a decision about what the decision plane exports rather than a
// detail of a cache. REVISIT WHEN anything in platform/decision starts
// exporting a counter - at that point this is one of the first two numbers
// worth exporting, alongside compileCount.
func (c *preparedQueryCache) evictionCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.evictions
}

// compileCount reports how many cache misses reached the compiler.
func (c *preparedQueryCache) compileCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.compiles
}

// len reports how many distinct keys the cache holds.
func (c *preparedQueryCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// keyFor derives the cache key from a bundle's CONTENT, recomputing the digest
// rather than trusting the advertised one.
func keyFor(b *Bundle) (preparedKey, error) {
	if b == nil {
		return preparedKey{}, fmt.Errorf("pdp: bundle is nil")
	}
	// ContentDigest, which #3700 landed on main while this branch was open.
	//
	// This branch carried its own contentDigestOf doing the identical
	// recomputation for the cache key. Keeping both would have been a second
	// implementation of "what does this bundle actually hash to" - the exact
	// duplication #3711 spent the day removing from identity comparison, one
	// package over. The rebase surfaced it as a conflict; the resolution is to
	// use theirs, not to merge two copies.
	//
	// The reason the key must be the CONTENT digest is unchanged and is worth
	// keeping here: the advertised Bundle.Digest sits outside view(), so it is
	// not covered by the signature, and keying a compiled query on a label
	// would let a mislabelled bundle collect another bundle's policies - one
	// bundle enforcing under another's name.
	digest, err := b.ContentDigest()
	if err != nil {
		return preparedKey{}, err
	}
	return preparedKey{root: b.Root, digest: digest}, nil
}
