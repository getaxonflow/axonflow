// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package planeshadow

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/shared/identity"
	logutil "axonflow/platform/shared/logger"
)

// The per-ORGANIZATION, per-PLANE narrowing (#3552 gap 3).
//
// # WHY A THIRD ROLLBACK WIDTH
//
// The decision axis already has two: AXONFLOW_DECISION_SHADOW_PLANES withdraws
// a plane across the whole deployment, and a per-organization decision_shadow_mode
// record withdraws every plane for one organization. Neither is the shape of
// the failure that actually arrives, which is ONE PLANE, FOR ONE TENANT: a
// customer whose mcp traffic floods the not-comparable counter, an organization
// whose policy set makes one plane's bundle compilation expensive. Withdrawing
// that plane deployment-wide discards every other tenant's evidence for it, and
// withdrawing the organization discards its evidence on the eleven planes that
// were fine. ADR-065 gate 18 is stated PER PLANE, so both remedies throw away
// exactly the measurements v11 is waiting for.
//
// # THE RECORD CAN ONLY NARROW, NEVER WIDEN
//
// This is the one place this axis's composition rule differs from the mode's,
// and the difference is deliberate rather than an oversight.
//
// The MODE wins in both directions - a record raises one organization to shadow
// on an off deployment, which is how a staged rollout starts. A PLANE LIST does
// not: the resolved set is the INTERSECTION of the deployment's list and the
// organization's. A deployment withdraws a plane for reasons that belong to the
// deployment - its worker pool cannot afford that plane's compilations, or that
// plane's comparisons are known-bad on this build - and a per-tenant row that
// could re-enable it would let one tenant's settings spend the deployment's
// money and reopen a plane the operator switched off. That is the same argument
// #3633 made for refusing a process-wide enforce, one axis over.
//
// It costs nothing in the common case: the deployment list is unset on almost
// every deployment, unset means every implemented plane, and intersecting that
// with an organization's list is the organization's list exactly.
//
// # THE RAW STRING IS PARSED HERE, NOT IN identity
//
// identity stores the value uninterpreted because the plane vocabulary lives in
// this package and this package imports identity - the parse cannot happen
// there without an import cycle. So there is exactly ONE parser in the tree,
// ParsePlanes, used by the settings writer to validate and by this reader to
// apply. A second copy would be one edit from disagreeing about which strings
// are planes, and the disagreement would be silent in the direction that
// matters: a value the writer accepted and the reader dropped narrows a window
// nobody meant to narrow.

// planeSetCache memoizes ParsePlanes by its raw input.
//
// The parse is on the REQUEST PATH - Observe resolves the set for every
// observation - and it splits a string and allocates a map. The cache is keyed
// on the raw stored value, so it is bounded by the number of DISTINCT plane
// lists configured across the deployment's organizations, which is a handful:
// operators narrow to the same two or three shapes. Entries are never evicted
// because there is nothing to evict - a bounded set of short strings - and a
// map guarded by an RWMutex is what the read side wants, since after the first
// observation for a given spelling every read is a shared-lock hit.
//
// The parsed maps are handed out by reference and MUST NOT be mutated by any
// caller. observesForOrg never does - it only asks for membership - and the
// intersection with the deployment's list is expressed as two membership
// questions in sequence rather than as a new map, so there is no set to build
// per observation and nothing to mutate.
type planeSetCache struct {
	mu     sync.RWMutex
	parsed map[string]map[legacycompile.Plane]bool
	failed map[string]string
	// logged records the (organization, value) pairs whose failure has already
	// been logged once. It is bounded by the number of organizations that hold
	// an unusable value, which is a configuration fault an operator is expected
	// to fix - not by request volume, and not by anything a caller can drive.
	logged map[string]bool
}

func newPlaneSetCache() *planeSetCache {
	return &planeSetCache{
		parsed: map[string]map[legacycompile.Plane]bool{},
		failed: map[string]string{},
		logged: map[string]bool{},
	}
}

// firstFailureFor reports whether this (organization, value) pair has not been
// logged yet, and marks it.
//
// SEPARATE FROM THE COUNTER, DELIBERATELY. The counter must move on every
// observation: it is a RATE, and an operator sizing the blast radius of a bad
// row needs to know whether it is one request an hour or every request. The LOG
// is a diagnosis, and the second identical ~400-byte line adds nothing while
// the ten-thousandth costs a log budget. One line names the organization, the
// raw value and the parser's message; the counter carries the volume.
func (c *planeSetCache) firstFailureFor(orgID, raw string) bool {
	key := orgID + "\x00" + raw
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.logged[key] {
		return false
	}
	c.logged[key] = true
	return true
}

// get returns the parsed set for raw, or the reason it could not be parsed.
//
// BOTH OUTCOMES ARE CACHED. Caching only the successes would re-parse every
// malformed value on every observation, which is the case where the extra work
// lands on the organization already misconfigured.
//
// IT DOES NOT, BY ITSELF, STOP THE LOGGING. An earlier version of this comment
// claimed it did, and it was measured wrong: ten observations for one
// misconfigured organization produced ten counter increments AND ten ~400-byte
// log lines, because the cache suppresses the PARSE and the log line is written
// by the caller either way. The counter as a rate is what an operator wants;
// the log volume is not, and a comment that says the problem is handled is
// worse than no comment. The suppression is in noteOrgPlanesFailure, keyed on
// the (organization, value) pair.
func (c *planeSetCache) get(raw string) (map[legacycompile.Plane]bool, string) {
	c.mu.RLock()
	set, ok := c.parsed[raw]
	why, bad := c.failed[raw]
	c.mu.RUnlock()
	if ok {
		return set, ""
	}
	if bad {
		return nil, why
	}
	set, err := ParsePlanes(raw)
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		c.failed[raw] = err.Error()
		return nil, err.Error()
	}
	c.parsed[raw] = set
	return set, ""
}

// WithOrgPlanes wires the per-organization plane narrowing (#3552 gap 3). Nil
// (the default, and every community build) means the deployment's plane list is
// the whole answer for every organization.
//
// It is a SEPARATE option from WithOrgModes although one store answers both, so
// that a deployment can wire the mode source without acquiring this behaviour,
// and so that a test can exercise one axis with the other absent. The concrete
// store answers both from one memoized row read, so wiring both costs one
// query, not two.
func WithOrgPlanes(src identity.DecisionShadowPlanesSource) Option {
	return func(o *Observer) { o.orgPlanes = src }
}

// observesForOrg is THE ONE FUNCTION THAT DECIDES WHETHER A PLANE IS IN SCOPE.
//
// Every call site asks this and never Config.Observes directly, for the reason
// effectiveMode is the only mode reader: "the narrowing is honored on some
// planes and not others" is indistinguishable, from outside, from a clean
// window.
func (o *Observer) observesForOrg(ctx context.Context, orgID string, p legacycompile.Plane) bool {
	if o.orgPlanes == nil || orgID == "" {
		return o.cfg.Observes(p)
	}
	if !o.cfg.Observes(p) {
		// THE DEPLOYMENT'S ANSWER IS CHECKED FIRST, AND IT IS FINAL.
		//
		// Not merely an ordering for speed: a plane the deployment withdrew is
		// out for every organization, so there is no per-org read to make and
		// no failure to count. Reading the record first and intersecting after
		// would produce the same verdict while charging every observation on a
		// withdrawn plane a settings lookup.
		return false
	}
	// The request's cancellation is dropped for the reason effectiveMode drops
	// it: this is a CONFIGURATION read whose result is memoized in a store the
	// identity axis reads too, and caching a client disconnect as a read
	// failure would move a whole organization onto the process configuration on
	// both axes for the rest of the TTL window.
	octx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	raw, found, err := o.orgPlanes.OrgDecisionShadowPlanes(octx, orgID)
	if err != nil {
		o.noteOrgPlanesFailure(orgID, "", err.Error())
		return o.cfg.Observes(p)
	}
	if !found {
		// The ordinary answer: no narrowing recorded, so the deployment's list
		// decides. Not a failure and not counted as one.
		return o.cfg.Observes(p)
	}
	set, why := o.planeSets.get(raw)
	if why != "" {
		// A STORED VALUE THIS BUILD CANNOT PARSE FALLS BACK TO THE DEPLOYMENT'S
		// LIST, COUNTED AND LOGGED. It does not silence the organization, and
		// the argument is worth having at the branch rather than in a review
		// thread, because "fall back to nothing" is the choice that LOOKS safe.
		//
		// THE TWO DIRECTIONS ARE NOT SYMMETRIC.
		//
		// Falling back to NO PLANES under-measures, and it does so SILENTLY:
		// the organization's series simply stops moving, and an absent series
		// is exactly what a clean window looks like. An operator reading a
		// per-plane zero concludes agreement. Gate 18 is read off that quiet
		// signal, so a silent under-measure is indistinguishable from the
		// result the gate is looking for.
		//
		// Falling back to the DEPLOYMENT'S LIST over-measures, and it does so
		// LOUDLY: it inflates a denominator while incrementing a counter named
		// for precisely that failure and logging the organization, the raw
		// value and the parser's own message. That cannot be mistaken for
		// agreement by anyone reading either surface.
		//
		// AND THE BRANCH IS ONLY REACHABLE THREE WAYS, which is what makes
		// over-measuring the cheap direction: the value is refused at the write
		// path by the same parser that reads it here, and again by the column's
		// CHECK, so getting here means a restore from backup, a row written by
		// hand, or a plane WITHDRAWN from the vocabulary by a later build. In
		// all three the organization was measuring a moment ago, and continuing
		// to measure what the deployment measures is the smaller change.
		//
		// The consequence to expect, stated so it is not read as a regression:
		// an organization that narrowed specifically to exclude a diverging
		// plane will see that plane's divergences REAPPEAR here. That is the
		// intended, loud outcome. It cannot silently unlock anything, because
		// this axis has no enforcement before v11 - and the identity axis's
		// enforce precondition reads a different metric family entirely
		// (identity.compatOrgComparisons / compatOrgDivergences, written by the
		// identity adapter's recorder), so nothing on this path can widen or
		// clean the denominator that gate reads.
		o.noteOrgPlanesFailure(orgID, raw, describeParseFailure(orgID, raw, why))
		return o.cfg.Observes(p)
	}
	// INTERSECTION. cfg.Observes(p) is already true here, so membership in the
	// organization's set is the whole remaining question.
	return set[p]
}

// noteOrgPlanesFailure counts EVERY fall-back and logs the FIRST one per
// (organization, value). See planeSetCache.firstFailureFor for why the two are
// separated.
//
// dedupeKey is the value the suppression is keyed on. It is empty for a failure
// that has no stored value to key on - a read error rather than a parse error -
// and an empty key suppresses nothing, which is correct: a store that is down
// is a condition that resolves, and its recurrence is news.
func (o *Observer) noteOrgPlanesFailure(orgID, dedupeKey, why string) {
	o.orgPlanesFailures.Add(1)
	shadowOrgPlanesFailures.Inc()
	if dedupeKey != "" && !o.planeSets.firstFailureFor(orgID, dedupeKey) {
		return
	}
	log.Printf("[DECISION-SHADOW] component=%s org=%s per-org plane narrowing unavailable, using the deployment's plane list: %s",
		logutil.Sanitize(o.component), logutil.Sanitize(orgID), logutil.Sanitize(why))
}

// describeParseFailure states WHERE the unusable value came from.
//
// ParsePlanes is shared with the deployment flag and names EnvPlanes in every
// message it writes, which is right for its other caller and actively
// misleading here: an operator reading "AXONFLOW_DECISION_SHADOW_PLANES names
// plane "gatewayrequest"" on a line about one organization would go and inspect
// a deployment variable that is fine. The row is what is wrong, and the fix is
// an admin write, so the sentence says so before the parser's own text.
func describeParseFailure(orgID, raw, why string) string {
	return fmt.Sprintf("the value recorded for this organization (%q) is not a usable plane list, so the "+
		"deployment's list decides for org %s until the record is corrected through the identity settings "+
		"surface. The parser's message names the deployment variable because ONE parser serves both, and the "+
		"value here came from the organization's record: %s", raw, orgID, why)
}

// OrgPlanesFailures reports how many per-organization plane reads fell back to
// the deployment's list.
//
// A DIAGNOSTIC WITH A DIRECTION: a deployment expecting a per-organization
// narrowing that sees this climbing is measuring more planes for that
// organization than its record says, which inflates a denominator rather than
// emptying one - the opposite failure from OrgModeFailures, and worth being
// able to tell apart.
func (o *Observer) OrgPlanesFailures() uint64 {
	if o == nil {
		return 0
	}
	return o.orgPlanesFailures.Load()
}

// HasPerOrgPlanes reports whether a per-organization plane source is wired.
//
// A one-line accessor rather than an inline nil check, for the reason
// HasPerOrgSource exists: the package's census statements have to stay
// literally true, and a startup log line is not a reason to add a second
// reader of the field.
func (o *Observer) HasPerOrgPlanes() bool {
	return o != nil && o.orgPlanes != nil
}
