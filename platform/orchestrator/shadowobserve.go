// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// The dynamic substrate's ADR-065 shadow observation site (#3564, session
// v10.3-A).
//
// # ONE SITE, FOUR PLANES
//
// wcp, map, policy_simulation and policy_test reach the dynamic substrate
// through DatabaseDynamicPolicyEngine.EvaluateDynamicPolicies, across five call
// sites. The observation is emitted from inside that one function - the
// function the call sites share - for the reason the static site gives: a call
// site that forgets to observe cannot exist if there is nothing at the call
// site to forget.
//
// Which plane a call is FOR is the one thing the function cannot know, so it is
// carried on the request as OrchestratorRequest.ShadowPlane. Data, not a
// decision; its zero value is refused rather than defaulted.
package orchestrator

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"slices"
	"sort"

	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/shared/planeshadow"
)

// This file's own source, digested and stamped onto every comparison it emits
// (#3564 round 2). The dynamic substrate's half of the per-site reset stamp;
// see the static site's copy in platform/shared/policy/shadowobserve.go for
// the argument, which is identical and which each site has to make for itself
// because go:embed cannot reach across a package directory.
//
//go:embed shadowobserve.go
var shadowSiteSource []byte

var shadowSiteVersion = func() string {
	sum := sha256.Sum256(shadowSiteSource)
	return hex.EncodeToString(sum[:])
}()

// dynamicShadowTrace accumulates what the shadow needs while the dynamic
// evaluation loop runs. A nil trace is the off state and every method is a
// no-op.
type dynamicShadowTrace struct {
	// rows is one entry per policy in the cache, in evaluation order.
	rows []planeshadow.RowFact
	// index maps a cache key to its position, so the loop can mark a row
	// without re-scanning.
	index map[string]int
	// fields are the condition field values the resolver returned, exactly as
	// the legacy engine read them.
	fields map[string]any
	// movedFields names every field the legacy engine read at TWO DIFFERENT
	// VALUES during one evaluation.
	//
	// # WHY THIS EXISTS AND WHY IT MAKES THE PAIR NOT COMPARABLE
	//
	// The dynamic engine's risk_score is mutable mid-loop: a matched policy's
	// modify_risk action raises result.RiskScore, and a later policy's
	// condition reads the raised value. So one evaluation can read one field
	// at 0 for the first row and at 50 for the third.
	//
	// The ADR-065 request carries ONE value per attribute and the PDP
	// evaluates every compiled row against it. Whichever value we sent, some
	// row would be evaluated against a number the legacy engine never showed
	// it, and the determining sets would differ - on EVERY request of that
	// shape, in the numerator ADR-065 gate 18 is read from.
	//
	// That difference is manufactured by the harness rather than caused by the
	// migration, so it must not be classified. It is NOT COMPARABLE, which is
	// the disposition that already exists for exactly this: a pair the two
	// sides cannot be asked the same question about. Sending the last value
	// and hoping is the alternative, and it is the one that quietly fills the
	// gate with noise.
	movedFields map[string]bool
}

// newDynamicShadowTrace returns a trace when the shadow could observe.
//
// It enumerates the rows of the cache that BELONG TO THIS TENANT rather than
// only the rows this request evaluates, because the tenant's policy set is what
// this evaluation ran against and its (policy_id, updated_at) pairs are what
// identify that set. A row the SEGMENT gate excludes is still part of the
// version; it simply did not run, which the tri-state records as unknown rather
// than as a non-match.
//
// THE TENANT FILTER IS NOT OPTIONAL AND IS NOT DEFENCE IN DEPTH. e.policies is
// an explicitly ALL-TENANTS cache, loaded on the BYPASSRLS refresh pool with no
// org predicate. Passing it through unfiltered breaks the shadow in two ways at
// once:
//
//   - dbRowSource.RawRows reads only `org_id = orgScope` plus 'global', and
//     coversPlaneRows is a one-directional cover of planeRows ⊆ raw. Every
//     OTHER tenant's row is therefore reported MISSING, and every observation
//     from all four dynamic planes returns ErrNotComparable - permanently, on
//     any deployment with two organizations holding dynamic policies, which is
//     both of ours. Four of twelve planes would contribute zero comparisons for
//     the whole window while blaming a deletion that never happened.
//   - and one tenant's policy_ids would ride into another tenant's
//     Observation.Rows, its Comparison.PolicySnapshot, and its "not comparable"
//     log line. worlds.go states the invariant this violates in as many words:
//     one org's policies must never reach another's request.
//
// The filter is the applicability gate the evaluation loop itself uses, not a
// second implementation of it, so the two cannot disagree about what belongs to
// a tenant. Segment scoping is deliberately NOT applied here: a segment-scoped
// row the caller is not in is part of the tenant's policy version and did not
// run, which is precisely the unknown the tri-state exists to carry.
func newDynamicShadowTrace(entries []dynamicPolicyCacheEntry, orgID string) *dynamicShadowTrace {
	if !planeshadow.Enabled() {
		return nil
	}
	t := &dynamicShadowTrace{
		rows:   make([]planeshadow.RowFact, 0, len(entries)),
		index:  make(map[string]int, len(entries)),
		fields: map[string]any{},
	}
	for _, e := range entries {
		if !dbCachedPolicyBelongsToOrg(e.policyMap, orgID, e.cacheKey) {
			continue
		}
		policyID, _ := e.policyMap["policy_id"].(string)
		if policyID == "" {
			// A cache entry with no policy_id cannot be keyed against a
			// compiled row. It is skipped from the row set rather than keyed
			// on the cache key, because the cache key is not the column the
			// compiler keys on and a wrong key would silently mark a DIFFERENT
			// row as exercised.
			continue
		}
		updatedAt, _ := e.policyMap["updated_at"].(string)
		category, _ := e.policyMap["category"].(string)
		t.index[e.cacheKey] = len(t.rows)
		t.rows = append(t.rows, planeshadow.RowFact{
			Table:     "dynamic_policies",
			PolicyID:  policyID,
			Category:  category,
			UpdatedAt: updatedAt,
		})
	}
	return t
}

// markRan records that a policy's CONDITIONS were evaluated.
//
// It is called at the point the loop commits to evaluating conditions, after
// the applicability gate and after the conditions parse. A row excluded before
// that point never had its conditions looked at, and reporting it as "ran and
// did not match" would tell the PDP a condition positively did not hold when
// nothing evaluated it.
func (t *dynamicShadowTrace) markRan(cacheKey string) {
	if t == nil {
		return
	}
	if i, ok := t.index[cacheKey]; ok {
		t.rows[i].Ran = true
	}
}

// appliedAction is one instruction a matched row produced: an action type and,
// for a redaction, the field it names.
type appliedAction struct {
	action string
	target string
}

// markMatched records that a policy's conditions HELD and names EVERY
// instruction the engine's switch produced for it.
//
// # WHY A LIST AND NOT AN ACTION
//
// A dynamic row's actions JSONB is an ARRAY, and the engine's switch applies
// every arm it has a case for: a row can block AND log, or redact three
// different fields. The effect comparison is a MULTISET for exactly that
// reason - three redactions of three fields are three instructions, and
// collapsing them lets a compiler that dropped two of three targets correspond
// cleanly (shadow.Verdict.Canonical's own argument for not de-duplicating
// effects). Recording only the first action would under-report the legacy side
// and turn a dropped obligation into an apparent match.
//
// One RowFact carries one instruction, so a row with N instructions becomes N
// sibling facts. They share a row key, which is what the effect multiset and
// the determining SET each need: SourceDetermining de-duplicates, so the
// determining comparison is unaffected.
func (t *dynamicShadowTrace) markMatched(cacheKey string, applied []appliedAction) {
	if t == nil {
		return
	}
	i, ok := t.index[cacheKey]
	if !ok {
		return
	}
	t.rows[i].Ran = true
	t.rows[i].Matched = true
	if len(applied) == 0 {
		// Matched and produced no instruction the switch has an arm for. That
		// is a real legacy shape - an inert action type - and it stays in the
		// determining set with no effect rather than being given one.
		return
	}
	t.rows[i].Action = applied[0].action
	t.rows[i].Target = applied[0].target
	for _, extra := range applied[1:] {
		sibling := t.rows[i]
		sibling.Action = extra.action
		sibling.Target = extra.target
		t.rows = append(t.rows, sibling)
	}
}

// noteField records one condition field value the legacy resolver returned,
// and notices when a field is read at two different values in one evaluation.
func (t *dynamicShadowTrace) noteField(name string, value any) {
	if t == nil || name == "" {
		return
	}
	if prev, seen := t.fields[name]; seen && !sameFieldValue(prev, value) {
		if t.movedFields == nil {
			t.movedFields = map[string]bool{}
		}
		t.movedFields[name] = true
	}
	t.fields[name] = value
}

// sameFieldValue compares two resolver readings.
//
// getFieldValue returns only scalars and strings, so == is well defined and
// cannot panic on an uncomparable type. It is written as a switch rather than
// a bare == anyway, because a future field returning a slice or a map would
// otherwise panic at runtime on the request path - and this is a diagnostic,
// so an unfamiliar type must degrade to "assume it moved" rather than crash.
func sameFieldValue(a, b any) bool {
	switch av := a.(type) {
	case nil:
		return b == nil
	case string, bool, int, int64, float64:
		switch b.(type) {
		case string, bool, int, int64, float64:
			return av == b
		default:
			return false
		}
	default:
		return false
	}
}

// emit builds the observation and hands it to the shadow. It returns nothing.
func (t *dynamicShadowTrace) emit(ctx context.Context, req OrchestratorRequest, orgID string, segmentIDs []string, result *PolicyEvaluationResult) {
	if t == nil {
		return
	}
	// THE PLANE CHECK RUNS FIRST, AND THE ORDER IS THE POINT.
	//
	// It used to run after the movedFields branch, so a call site that named NO
	// plane - the likely new-site mistake, since ShadowPlane is json:"-" and
	// its zero value is the empty plane - was reported as `not_comparable`
	// whenever the request also happened to use modify_risk. That reads as
	// ordinary operation. A malformed call site is a DEFECT and must be
	// reported as one on every request, not on the subset that avoids an
	// unrelated branch.
	if !shadowPlaneIsDynamic(req.ShadowPlane) {
		// A call site that named a STATIC plane on this engine would attribute
		// dynamic-substrate rows to a surface that never reads them, and the
		// bundle built for it would be compiled from the wrong column set.
		//
		// COUNTED, not merely logged. Returning here without moving a counter
		// is the one shape that makes a plane's window silently empty while
		// every other plane reads healthy, which is precisely what this whole
		// mechanism exists to make impossible.
		planeshadow.NoteRefusedFor(ctx, orgID, req.ShadowPlane, fmt.Sprintf(
			"the dynamic engine was called with a plane that does not evaluate the dynamic substrate; the call site must name one of %v",
			legacycompile.PlanesFor(legacycompile.SubstrateDynamic)))
		return
	}
	if len(t.movedFields) > 0 {
		// See dynamicShadowTrace.movedFields. Counted under its own
		// disposition rather than dropped, because a deployment whose dynamic
		// policies use modify_risk heavily would otherwise see its wcp and map
		// windows quietly thin out with nothing saying why.
		planeshadow.NoteNotComparableFor(ctx, orgID, req.ShadowPlane, fmt.Sprintf(
			"the legacy engine read condition field(s) %v at more than one value during this "+
				"evaluation (modify_risk mutates risk_score mid-loop); one request carries one "+
				"value per attribute, so some row would be evaluated against a number the legacy "+
				"engine never showed it", sortedFieldNames(t.movedFields)))
		return
	}
	planeshadow.Observe(ctx, planeshadow.Observation{
		Plane: req.ShadowPlane,
		// The dynamic substrate has no phase concept: dynamic_policies has no
		// phase column and the engine runs one pass.
		Phase:       "",
		OrgScope:    orgID,
		OrgID:       orgID,
		Principal:   req.User.Email,
		SiteVersion: shadowSiteVersion,
		// CLONED, NOT ALIASED - the static site's argument, one substrate
		// over: this slice belongs to the caller, the observation is read on a
		// worker goroutine, and a caller free to reuse its backing array would
		// silently change the segment set the comparison ran against.
		Groups: slices.Clone(segmentIDs),
		// A resolver FAILURE never reaches here - EvaluateDynamicPolicies
		// returns before this point with EvaluationError set - so an empty
		// closure at this point is a resolved empty closure.
		SegmentsUnresolved: false,
		Action:             req.RequestType,
		Legacy: planeshadow.LegacyOutcome{
			Executable:      result.Allowed,
			EvaluationError: result.EvaluationError,
		},
		Rows:   t.rows,
		Fields: t.fields,
		// The dynamic substrate has NO posture lever. BuildActionOverrides
		// reaches the shared static engine only; the census records every
		// dynamic call site as passing no ActionOverrides, and the compiler's
		// plane model gives every dynamic plane PostureLever=false. Passing a
		// posture here would displace stored actions on a substrate the
		// deployment posture cannot reach.
		Posture: nil,
	})
}

// sortedFieldNames renders a set for a log line, in a stable order.
func sortedFieldNames(in map[string]bool) []string {
	out := make([]string, 0, len(in))
	for k := range in {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// shadowPlaneIsDynamic reports whether a plane evaluates the dynamic
// substrate, so a call site that names a static plane on this engine is
// refused rather than counted against the wrong surface.
func shadowPlaneIsDynamic(p legacycompile.Plane) bool {
	spec, err := legacycompile.SpecFor(p)
	if err != nil {
		return false
	}
	for _, s := range spec.Substrates {
		if s == legacycompile.SubstrateDynamic {
			return true
		}
	}
	return false
}
