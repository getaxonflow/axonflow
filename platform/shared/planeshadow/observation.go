// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package planeshadow

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"axonflow/platform/decision/legacycompile"
)

// Observation is one plane's report of what it just decided, and of the inputs
// it decided from.
//
// It carries the LEGACY OUTCOME and the EVALUATION FACTS as separate fields
// even though a runtime plane sources both from one evaluation, because they
// answer different questions and the ADR-065 side must be built from the facts
// rather than from the outcome. Deriving the request from the verdict would
// make the two sides of the diff share a step, and a shared step is where a
// differential harness starts agreeing with itself.
//
// Every field is a policy identifier, a category, a resolved action, a field
// path or an organization id. NO CONTENT. The matched text, the request body,
// the redacted values and the caller's prompt are all deliberately absent: this
// struct is queued, and a queue that can hold prompt content is a queue that
// can leak it into a log line, a heap dump or a crash report. The consequence
// is stated rather than hidden - see UnmodelledContent in Limitations.
type Observation struct {
	// Plane is the enforcement plane. Its zero value is REFUSED, never
	// defaulted: an unattributed observation counted against some plane is
	// worse than none, because it moves a denominator an operator is reading.
	Plane legacycompile.Plane
	// Phase is the legacy evaluation phase, set on a plane that evaluates more
	// than one. A two-phase plane runs one pass per phase in production, each
	// resolving its own action column, so one observation must describe one
	// pass. Empty on single-phase planes and on the dynamic substrate.
	Phase legacycompile.Phase

	// OrgScope is the organization whose policy rows the plane LOADED under.
	// It is the key the shadow's own policy read and bundle cache use, so the
	// two sides compare the same organization's policy set. Empty means the
	// unbound/global load.
	OrgScope string
	// OrgID is the AUTHENTICATED organization, and it is the key the
	// per-organization mode is resolved for. It is deliberately distinct from
	// OrgScope: three call sites set a policy load scope without setting an
	// authenticated organization (#3490), and resolving a mode from a load
	// scope would let the policy a request was evaluated against select the
	// mode that request is observed under.
	OrgID string
	// Principal is the canonical-ish subject the plane resolved, used to
	// address the ADR-065 request. Empty is legitimate - an unauthenticated
	// plane - and produces the anonymous principal rather than a refusal, so
	// that the unhappy paths are measured rather than dropped.
	Principal string
	// Groups is the resolved ADR-060 segment set, which is also the group
	// closure the ADR-065 request carries.
	//
	// A nil slice and an empty slice are the SAME resolved fact here - the
	// caller belongs to no segment - and both compile to a known empty array
	// on the ADR-065 side, matching AppliesToSegments' contract. A FAILURE to
	// resolve segments is a different fact and is carried by
	// SegmentsUnresolved.
	Groups []string
	// SegmentsUnresolved reports that segment resolution FAILED, as opposed to
	// resolving to an empty set. The two are opposite in the fail-open
	// direction and conflating them is #3482's whole shape: an unresolved
	// closure must not be presented to the PDP as a resolved empty one, which
	// would silently exclude every segment-scoped constraint.
	SegmentsUnresolved bool
	// Action is the governed tool or connector identity, used as the ADR-065
	// action. Empty falls back to the corpus's single registered action.
	Action string

	// SiteVersion is the emitting observation site's own semantic version,
	// stamped onto the comparison as one of the three ADR-065 gate-18 reset
	// stamps (see versions.go).
	//
	// IT HAS TO COME FROM THE CALLER, and that is the whole point. The other
	// two stamps are computed inside this package because this package's own
	// source is what they cover; the observation SITE lives in another package
	// (platform/shared/policy, platform/orchestrator) and its changes - which
	// row facts it reports, which phase it attributes, whether it marks a
	// capped redaction as shadowed - move what both sides of the diff see
	// while every digest computed in here stays byte-identical. A site's
	// changes would otherwise be the one reset boundary nothing observed.
	//
	// Empty is permitted rather than refused; see Comparison.SiteVersion.
	SiteVersion string

	// Legacy is what the plane actually decided.
	Legacy LegacyOutcome
	// Rows are the per-row evaluation facts.
	Rows []RowFact
	// Fields are the dynamic substrate's condition field values, exactly as
	// the orchestrator's resolver returned them. A field absent from the map
	// resolves to nil, as a context key the caller did not supply does
	// (#3515). Nil on the static substrate.
	Fields map[string]any
	// Posture is the deployment detection posture in force, which is the
	// EvalOptions.ActionOverrides map the plane was called with. It is carried
	// because the compiler needs it: a posture lever displaces the stored
	// action on every plane but the proxy tier, and compiling one global
	// translation would be wrong for exactly that plane.
	Posture map[string]string

	// mode is the mode Observe resolved for this observation's organization,
	// and seq is its sequence number. Both are stamped by Observe and are
	// unexported so a caller cannot construct an Observation that claims a
	// mode: the mode a comparison ran under has to be the one the single read
	// site produced, or a record from an organization shadowing on a
	// process-off deployment cannot be told apart from the deployment default.
	mode Mode
	seq  uint64
}

// Snapshot identifies the policy set this plane evaluated against.
//
// # WHY THE PLANE'S SET IS THE KEY, AND NOT A VERSION THE SHADOW INVENTS
//
// The two sides read the policy tables at different instants: the plane reads
// through a loader cache with a multi-minute TTL, and the shadow reads rows of
// its own when it builds a bundle. A comparison across two different policy
// sets is not a finding about the migration, it is a timing artifact - and on
// a deployment whose policy cache is minutes stale it would be a timing
// artifact on EVERY request in the window, which is the shape that would fill
// the gate's numerator with noise and make an operator distrust a real
// unexplained difference when one arrived.
//
// So the plane's own loaded set is the authority. Its digest is the bundle
// cache key, and the shadow builds a bundle only from a raw read in which
// every one of these rows is present at exactly this updated_at. A row that
// has since been edited or deleted makes the pair NOT COMPARABLE - counted on
// its own, never as a match (which would inflate agreement) and never as
// unexplained (which would red the gate on an ordinary policy edit).
//
// It is a digest rather than the set itself so it can be a map key and a
// metric-free cache key. Collision would silently reuse the wrong bundle, so
// it is SHA-256 over an unambiguous encoding rather than a join of values that
// could be re-parsed into a different set.
func (o Observation) Snapshot() string {
	// DE-DUPLICATED, BECAUSE THIS IS THE IDENTITY OF A SET AND Rows IS NOT ONE.
	//
	// A dynamic row whose actions JSONB is an array becomes N sibling RowFacts
	// sharing a row key - one per instruction - which the effect MULTISET needs
	// and this digest must not see. Without the de-duplication, sha256("k") and
	// sha256("k\nk") are different digests for the SAME policy set, so:
	//
	//	a request that does not match a [block, log] row -> 1 fact  -> digest D1
	//	a request that DOES match it                     -> 2 facts -> digest D2
	//	a redact row naming a variable field list        -> one digest per count
	//
	// Each distinct digest is a distinct worldKey AND reportKey, so each buys a
	// fresh legacy compile, Rego render, bundle build-sign-verify and OPA engine
	// against a 256-entry cache. Worse than the cost, the digest is documented
	// as identifying "the policy set this plane evaluated against" and would
	// instead vary with request CONTENT - so two comparisons of one policy set
	// would be attributed to two sets, and the comparability argument above
	// would be about something other than what it claims.
	seen := make(map[string]struct{}, len(o.Rows))
	keys := make([]string, 0, len(o.Rows))
	for _, r := range o.Rows {
		// Length-prefixed rather than delimiter-joined: policy_id is
		// VARCHAR(100) with no character constraint, so any delimiter is a
		// character an id may contain, and two different sets could otherwise
		// encode identically.
		k := fmt.Sprintf("%d:%s|%d:%s|%d:%s",
			len(r.Table), r.Table, len(r.PolicyID), r.PolicyID, len(r.UpdatedAt), r.UpdatedAt)
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	sum := sha256.Sum256([]byte(strings.Join(keys, "\n")))
	return hex.EncodeToString(sum[:])
}

// LegacyOutcome is the verdict the plane already computed. It is never
// recomputed here.
type LegacyOutcome struct {
	// Executable is the one field that decides fail-open versus fail-closed:
	// RequestResult.Blocked inverted, ResponseResult.Blocked inverted, or
	// PolicyEvaluationResult.Allowed.
	Executable bool
	// EvaluationError reports that the plane could not evaluate at all - a
	// policy-load failure, a segment-resolution failure. It is NOT a policy
	// verdict, and an observation carrying it is dropped from the comparison
	// population under its own counter: comparing an availability failure
	// against a policy decision would report a difference the migration did
	// not cause.
	EvaluationError bool
}

// THERE IS DELIBERATELY NO APPROVAL-CLAUSE COUNT ON THE LEGACY SIDE.
//
// shadow.Verdict has an ApprovalClauses field and the classifier reads it on
// the ADR-065 side ONLY: what it expects there is DERIVED from the legacy
// side's require_approval effects (classify.go's wantApprovalClauses), because
// the legacy engines have no clause concept at all - require_approval sets
// Allowed=false and appends a RequiredActions marker. A count on this side
// would therefore be a number nothing compares against, invented by this
// package and reported as though the running system produced it. The effects
// carry the fact; the classifier does the deriving.

// RowFact is one legacy policy row's participation in this evaluation.
//
// It carries BOTH what the row's detector did and what the row resolved to,
// because those feed the two different sides: the detector verdict becomes an
// attribute on the ADR-065 request, and the resolved action becomes an effect
// on the legacy verdict.
type RowFact struct {
	// Table is "static_policies" or "dynamic_policies".
	Table string
	// PolicyID is the row's policy_id, as stored - never sanitized here. The
	// row key an operator reads in a diff record has to be the one they can
	// find in the database.
	PolicyID string
	// Ran reports that this row's detector or conditions were actually
	// evaluated for this request.
	//
	// IT IS THE FIELD THAT MAKES THE TRI-STATE HONEST, and it is the reason
	// the engines report an evaluated set at all. A row skipped by a category
	// filter or by capability scoping (#2801) did NOT run, and ADR-065 treats
	// that as an UNKNOWN attribute rather than a known false. Collapsing the
	// two would make every skipped detector read as "ran and did not match" on
	// the legacy side against an unknown on the new side - a difference
	// manufactured by the harness on every request with a category filter.
	Ran bool
	// Matched reports that it ran AND fired. Meaningless when Ran is false,
	// and the constructor refuses that combination rather than ignoring it.
	//
	// IT IS ABOUT THE DETECTOR, NOT ABOUT THE OUTCOME. See Shadowed.
	Matched bool
	// Shadowed reports that this row fired but the plane's combiner discarded
	// it - the first-match or strictest-wins reduction picked another row.
	//
	// MATCHED AND SHADOWED ARE TWO FACTS AND MUST NOT BE COLLAPSED, which is
	// the whole reason this field exists. The ADR-065 side needs "this
	// pattern matched" for the detector attribute; the legacy side needs "this
	// row determined the outcome" for the determining set. The proxy-tier plane
	// originally expressed a shadowed row by setting Matched back to false, and
	// that is a fail-open in both directions at once:
	//
	//   - the compiled detector attribute becomes FALSE, so
	//     EC6_PROXY_TIER_FIRST_MATCH_SHADOWING - whose evidence predicate
	//     requires the denying constraint's detector verdict to be TRUE -
	//     becomes UNREACHABLE. Measured: the one plane-specific divergence the
	//     harness declares, the deny ADR-065 will start issuing at cutover on
	//     proxy_tier, classified as `match`. A real tightening recorded as
	//     perfect agreement.
	//   - and keeping Matched true without this field is equally wrong the
	//     other way: legacyVerdictFor would put a row the running system never
	//     acted on into the legacy determining set.
	//
	// So a shadowed row is Ran=true, Matched=true, Shadowed=true, Action="":
	// its detector fired, it contributed no effect, and it is not determining.
	Shadowed bool
	// Action is the action this row RESOLVED to for this evaluation, after any
	// posture lever displaced the stored value. Empty when the row did not
	// fire.
	Action string
	// Target is the field path a redaction named, empty for every other
	// action. It is part of the effect key: three redactions of three
	// different fields are three instructions, and rendering them identically
	// would let a compiler that dropped two of three targets compare as equal.
	Target string
	// Category is the row's policy category, carried for the posture lever and
	// for diagnostics.
	Category string
	// UpdatedAt is the row's updated_at as the plane loaded it, in a stable
	// textual rendering. It is half of the identity of the policy SET this
	// evaluation ran against (see Observation.Snapshot): a bundle built from a
	// row that has since been edited is a bundle describing a different
	// policy, and comparing against it would report a difference the migration
	// did not cause.
	UpdatedAt string
}

// RowKey renders the row key the diff records and the coverage accounting use.
func (r RowFact) RowKey() string { return r.Table + "|" + r.PolicyID }

// Validate returns a non-empty description of an observation this package
// cannot act on, or "".
//
// These are OUR defects, not the caller's request being unusual, and they are
// recorded loudly under their own reason rather than dropped: an observation
// that silently disappears is a hole in a denominator an operator is reading
// as complete. The one thing they never do is affect the request - there is
// nothing here that could.
func (o Observation) Validate() string {
	if strings.TrimSpace(string(o.Plane)) == "" {
		return "the call site named no plane; an observation attributed to no plane cannot be counted, and attributing it to some plane would move a denominator an operator is reading"
	}
	if _, err := legacycompile.SpecFor(o.Plane); err != nil {
		if _, unimplemented := legacycompile.UnimplementedPlanes[o.Plane]; unimplemented {
			return fmt.Sprintf("plane %q has no policy-evaluation call site in this tree, so an observation from it means the census is now wrong (see #3564)", o.Plane)
		}
		return fmt.Sprintf("plane %q is not a declared enforcement plane", o.Plane)
	}
	spec := legacycompile.MustSpecFor(o.Plane)
	if len(spec.Phases) > 1 && o.Phase == "" {
		return fmt.Sprintf("plane %q evaluates %d phases and the call site named none; one observation must describe one pass, or the two passes are conflated into a single comparison", o.Plane, len(spec.Phases))
	}
	if o.Phase != "" && !spec.EvaluatesPhase(o.Phase) && !spec.EvaluatesPhase(legacycompile.PhaseBoth) {
		// A phase the plane does not evaluate means the call site and the
		// model disagree about what this plane does, which is exactly the
		// class TestPlaneModelMatchesTheCensus exists to catch one level up.
		if len(spec.Phases) > 0 {
			return fmt.Sprintf("plane %q does not evaluate phase %q (it evaluates %v)", o.Plane, o.Phase, spec.Phases)
		}
	}
	for i, r := range o.Rows {
		if strings.TrimSpace(r.PolicyID) == "" {
			return fmt.Sprintf("row %d carries no policy_id", i)
		}
		if r.Table != "static_policies" && r.Table != "dynamic_policies" {
			return fmt.Sprintf("row %q names table %q, which is not a legacy policy table", r.PolicyID, r.Table)
		}
		if r.Matched && !r.Ran {
			return fmt.Sprintf("row %q reports Matched without Ran; a detector that did not run cannot have fired, and the pair would compile to a known-true attribute for a detector the ADR-065 side must see as unknown", r.PolicyID)
		}
	}
	return ""
}
