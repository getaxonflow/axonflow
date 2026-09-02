// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package planeshadow

import (
	"container/list"
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/legacycompile/shadow"
)

// ErrNotComparable reports that the policy set the plane evaluated against and
// the one available to compile a bundle from are not the same set.
//
// It is a distinct error, and it is deliberately NOT a failure: a policy edit
// between the plane's cached load and the shadow's read is ordinary operation,
// not a defect. It is counted on its own so that neither of the two wrong
// readings is possible - counting it as a match would inflate agreement with
// comparisons that never happened, and counting it as unexplained would red
// ADR-065 gate 18 every time an operator saves a policy.
type ErrNotComparable struct{ Detail string }

func (e *ErrNotComparable) Error() string {
	return "planeshadow: not comparable: " + e.Detail
}

// worldKey addresses one compiled, signed, verified evaluation environment.
//
// EVERY COMPONENT IS LOAD-BEARING and each one, omitted, produces a specific
// wrong answer:
//
//   - orgScope: one org's policies must never reach another's request
//     (ADR-065 invariant 1). Omitting it is the isolation failure that
//     #3577's round-2 review found in the offline harness.
//   - snapshot: the digest of the plane's own loaded rows. Omitting it serves
//     a bundle compiled from a policy set the plane never evaluated.
//   - posture: the deployment detection posture DISPLACES stored actions at
//     compile time, so two postures compile to two different documents. A
//     shared entry would evaluate one org's requests against another's
//     posture.
//   - plane and phase: a plane reads one substrate through one column set and
//     runs one pass per phase. A world built from both phases' policies
//     evaluates two passes as one.
type worldKey struct {
	orgScope string
	snapshot string
	posture  string
	plane    legacycompile.Plane
	phase    legacycompile.Phase
}

// reportKey addresses one compilation, which several planes share.
type reportKey struct {
	orgScope string
	snapshot string
	posture  string
}

// compiled is a report plus the options it was compiled with. The options
// travel WITH the report because a case built against different options
// silently drops every segment-scoped constraint from the ADR-065 side - the
// #3577 round-2 fail-open - and pairing them makes that mismatch
// unrepresentable rather than merely unlikely.
type compiled struct {
	report *legacycompile.Report
	opts   legacycompile.Options
}

// worldCache builds and memoizes evaluation environments.
//
// Building one is expensive: compile the legacy rows into typed documents,
// render Rego, build and sign a bundle, verify it, and start an OPA engine.
// That cost is why the shadow is asynchronous, and why the cache is bounded
// rather than unbounded - an unbounded map keyed partly on a policy snapshot
// grows by one entry per policy edit per org and never shrinks, which is a
// slow leak that only shows up on a deployment that edits policy often.
type worldCache struct {
	rows RowSource
	opts legacycompile.Options
	max  int

	mu       sync.Mutex
	reports  map[reportKey]*compiled
	worlds   map[worldKey]*shadow.World
	order    *list.List // worldKey, least-recently-used first
	elements map[worldKey]*list.Element
	// THERE IS DELIBERATELY NO RAW-ROW CACHE.
	//
	// There was one, keyed on reportKey, described as memoizing the read "so
	// twelve planes sharing a policy set read the tables once rather than
	// twelve times". It could never hit: it was written on the same line as
	// c.reports[rk] and read only in the branch reached when c.reports[rk] is
	// ABSENT, so haveRaw was false every time the code looked. The
	// memoization it claimed is actually delivered by c.reports, which the
	// twelve planes share; all the raw map added was a full retained copy of
	// both policy tables per cached report - the largest thing this cache
	// held, kept alive for nothing.
	// buildReport and buildWorld serialise construction PER KEY.
	//
	// Without them the pool thunders on a cold miss: N workers dequeue N
	// observations for one key, all miss, and all read the policy tables and
	// compile the same bundle. The double-checks below keep exactly one
	// result, so the duplicates were never a correctness problem - but they
	// are N table reads and N Rego compilations for one answer, at exactly the
	// moment a deployment turns the shadow on, which is the worst time to
	// spend them. Measured: five observations over one snapshot caused two
	// table reads before this existed.
	//
	// Keyed rather than global so two DIFFERENT organizations still build
	// concurrently; a global build lock would serialise the whole pool behind
	// whichever tenant arrived first.
	buildReport map[reportKey]*buildLock
	buildWorld  map[worldKey]*buildLock

	builds    uint64
	evictions uint64
}

func newWorldCache(rows RowSource, opts legacycompile.Options, max int) *worldCache {
	if max < 1 {
		max = 1
	}
	return &worldCache{
		rows:        rows,
		opts:        opts,
		max:         max,
		reports:     map[reportKey]*compiled{},
		worlds:      map[worldKey]*shadow.World{},
		order:       list.New(),
		elements:    map[worldKey]*list.Element{},
		buildReport: map[reportKey]*buildLock{},
		buildWorld:  map[worldKey]*buildLock{},
	}
}

// buildLock is a per-key mutex with a REFERENCE COUNT.
//
// The count is what stops two failure modes that a bare map produces:
//
//  1. UNBOUNDED GROWTH. An entry created on a miss that ends in
//     ErrNotComparable or a compile failure would never be removed, because
//     the only remover ran after a world was successfully inserted. The keys
//     include a policy-snapshot digest, so the key space grows with every
//     policy edit - and ErrNotComparable is documented as ORDINARY operation,
//     so the leaking path is the path the design says is normal.
//  2. A LOCK DELETED WHILE HELD. Eviction removing the entry a builder is
//     inside lets the next arrival mint a second mutex and build
//     concurrently - two OPA engines and two Rego compiles for one key, which
//     is exactly the cost the single-flight was added to remove.
//
// So a lock is released by the goroutine that took it, and removed only when
// the last holder lets go.
type buildLock struct {
	mu   sync.Mutex
	refs int
}

// acquire takes the per-key lock, creating it if necessary. The returned
// function releases it and reaps the entry when nobody else holds it.
func acquire[K comparable](c *worldCache, locks map[K]*buildLock, key K) func() {
	c.mu.Lock()
	l, ok := locks[key]
	if !ok {
		l = &buildLock{}
		locks[key] = l
	}
	l.refs++
	c.mu.Unlock()

	l.mu.Lock()
	return func() {
		l.mu.Unlock()
		c.mu.Lock()
		l.refs--
		if l.refs == 0 {
			delete(locks, key)
		}
		c.mu.Unlock()
	}
}

// postureKey renders a posture as a cache key. Sorted and length-prefixed, so
// two different postures cannot encode identically through a category name
// that contains the separator.
func postureKey(p legacycompile.Posture) string {
	if len(p) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(p))
	for k, v := range p {
		parts = append(parts, fmt.Sprintf("%d:%s=%d:%s", len(k), k, len(v), v))
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// worldFor returns the evaluation environment for one observation, building it
// if necessary.
//
// It returns ErrNotComparable when the plane's policy set is not the one the
// tables now hold. That check happens BEFORE any compilation, so a policy edit
// costs a cheap comparison rather than a bundle build.
func (c *worldCache) worldFor(ctx context.Context, obs Observation, post legacycompile.Posture) (*shadow.World, *compiled, error) {
	rk := reportKey{orgScope: obs.OrgScope, snapshot: obs.Snapshot(), posture: postureKey(post)}
	wk := worldKey{orgScope: rk.orgScope, snapshot: rk.snapshot, posture: rk.posture, plane: obs.Plane, phase: obs.Phase}

	c.mu.Lock()
	if w, ok := c.worlds[wk]; ok {
		comp := c.reports[rk]
		c.touch(wk)
		c.mu.Unlock()
		return w, comp, nil
	}
	c.mu.Unlock()

	// Serialise the build for THIS world. The second arrival waits and then
	// takes the first's result off the double-check below, rather than
	// compiling a second bundle and starting a second OPA engine for one key.
	release := acquire(c, c.buildWorld, wk)
	defer release()

	c.mu.Lock()
	if w, ok := c.worlds[wk]; ok {
		comp := c.reports[rk]
		c.touch(wk)
		c.mu.Unlock()
		return w, comp, nil
	}
	comp, haveReport := c.reports[rk]
	c.mu.Unlock()

	if !haveReport {
		var err error
		comp, err = c.compile(ctx, obs, post, rk)
		if err != nil {
			return nil, nil, err
		}
	}

	opts := []shadow.WorldOption{shadow.WithRealm(comp.opts.Realm)}
	if obs.Phase != "" {
		opts = append(opts, shadow.WithPhase(obs.Phase))
	}
	w, err := shadow.NewWorld(ctx, comp.report, obs.Plane, obs.OrgScope, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("planeshadow: building the %s world: %w", obs.Plane, err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	// A concurrent builder may have won; keep theirs so two workers cannot
	// hand out two engines for one key and double the resident OPA instances.
	if existing, ok := c.worlds[wk]; ok {
		c.touch(wk)
		return existing, comp, nil
	}
	c.worlds[wk] = w
	c.elements[wk] = c.order.PushBack(wk)
	c.builds++
	c.evictLocked()
	return w, comp, nil
}

// compile reads the rows, proves they are the plane's rows, and compiles.
func (c *worldCache) compile(ctx context.Context, obs Observation, post legacycompile.Posture, rk reportKey) (*compiled, error) {
	release := acquire(c, c.buildReport, rk)
	defer release()

	c.mu.Lock()
	if existing, ok := c.reports[rk]; ok {
		c.mu.Unlock()
		return existing, nil
	}
	c.mu.Unlock()

	raw, err := c.rows.RawRows(ctx, obs.OrgScope)
	if err != nil {
		return nil, err
	}
	if detail := coversPlaneRows(raw, obs.Rows); detail != "" {
		return nil, &ErrNotComparable{Detail: detail}
	}

	// NORMALIZED BEFORE IT IS STORED, NOT AFTER IT IS USED.
	//
	// Compile normalizes internally, so compiling with an un-normalized copy is
	// correct - but this copy is KEPT on `compiled` and read again to build the
	// LEGACY side of the comparison (legacyVerdictFor takes
	// comp.opts.ContentTarget). If it is stored un-normalized, the two sides of
	// every static redaction name different fields: the compiled ADR-065 effect
	// targets response.content and the legacy effect targets "". Nothing
	// explains that, so it classifies UNEXPLAINED - on every plane, on every
	// deployment that has not set AXONFLOW_DECISION_SHADOW_CONTENT_TARGET,
	// which is all of them, and including 100% of the cowork_ingest plane
	// because it forces redact.
	//
	// This is the same class as the action-identity defect one statement below
	// in translate.go: a value that must be IDENTICAL on both sides, derived
	// independently on each.
	opts := c.opts.Normalized()
	opts.Posture = post
	rep, cerr := legacycompile.Compile(raw, opts)
	if cerr != nil {
		return nil, fmt.Errorf("planeshadow: compiling the legacy policy set for org scope %q: %w", obs.OrgScope, cerr)
	}
	out := &compiled{report: rep, opts: opts}

	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, ok := c.reports[rk]; ok {
		return existing, nil
	}
	c.reports[rk] = out
	return out, nil
}

// coversPlaneRows returns a non-empty description when the rows the plane
// evaluated are not all present, unchanged, in the rows just read.
//
// It is one-directional on purpose. EXTRA rows in the read are fine and are
// expected: the plane loads one phase and may narrow by category or by
// capability scoping (#2801), while the read takes the whole table. Those rows
// reach the ADR-065 side as detectors that DID NOT RUN, which is exactly what
// they were, and the tri-state carries that correctly. A MISSING or EDITED row
// is the other thing entirely: it means the bundle would describe a policy the
// plane did not evaluate.
func coversPlaneRows(raw []legacycompile.RawRow, planeRows []RowFact) string {
	if len(planeRows) == 0 {
		return ""
	}
	have := make(map[string]string, len(raw))
	for _, r := range raw {
		have[r.Table+"|"+policyIDOf(r)] = updatedAtOf(r)
	}
	for _, pr := range planeRows {
		key := pr.RowKey()
		stamp, ok := have[key]
		if !ok {
			return fmt.Sprintf("the plane evaluated row %s and the policy tables no longer hold it; it was deleted between the plane's cached load and this read", key)
		}
		if pr.UpdatedAt == "" || stamp == "" {
			// One side could not render a version. Comparing against a bundle
			// whose provenance cannot be established is exactly the shape this
			// check exists to refuse, so it refuses rather than assuming they
			// match - an assumption that would be invisible and would hold
			// most of the time, which is the worst combination.
			return fmt.Sprintf("row %s carries no comparable updated_at (plane %q, table %q), so the two policy sets cannot be proven to be the same set", key, pr.UpdatedAt, stamp)
		}
		if stamp != pr.UpdatedAt {
			return fmt.Sprintf("row %s was edited between the plane's cached load (%s) and this read (%s)", key, pr.UpdatedAt, stamp)
		}
	}
	return ""
}

// touch marks a key most-recently-used. Callers hold c.mu.
func (c *worldCache) touch(k worldKey) {
	if el, ok := c.elements[k]; ok {
		c.order.MoveToBack(el)
	}
}

// evictLocked drops least-recently-used worlds down to the cap, and drops a
// report once no world references it. Callers hold c.mu.
func (c *worldCache) evictLocked() {
	for c.order.Len() > c.max {
		front := c.order.Front()
		if front == nil {
			return
		}
		k := front.Value.(worldKey)
		c.order.Remove(front)
		delete(c.elements, k)
		delete(c.worlds, k)
		c.evictions++
		// The build locks are NOT touched here: they are refcounted and are
		// reaped by their last holder. Deleting one under a goroutine that is
		// inside it would let the next arrival mint a second and build the
		// same key twice.
		rk := reportKey{orgScope: k.orgScope, snapshot: k.snapshot, posture: k.posture}
		if !c.reportStillUsedLocked(rk) {
			delete(c.reports, rk)
		}
	}
}

func (c *worldCache) reportStillUsedLocked(rk reportKey) bool {
	for k := range c.worlds {
		if k.orgScope == rk.orgScope && k.snapshot == rk.snapshot && k.posture == rk.posture {
			return true
		}
	}
	return false
}

// stats reports build and eviction counts, for tests and diagnostics.
func (c *worldCache) stats() (builds, evictions uint64, worlds int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.builds, c.evictions, len(c.worlds)
}
