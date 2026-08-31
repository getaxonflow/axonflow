package shadow

import (
	"fmt"
	"sort"
	"time"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
)

// Now is the fixed evaluation instant. Replay reproduces sampled decisions
// from pinned inputs, so freshness verdicts have to be a function of the case
// rather than of when the harness ran.
var Now = time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)

// Case is one replay case: everything both engines need to decide, and
// nothing either of them can source from ambient state.
//
// It carries the legacy inputs (detector verdicts, condition field values) and
// the ADR-065 inputs (attributes) as SEPARATE fields rather than deriving one
// from the other at evaluation time. Deriving would make the two sides share a
// step, and a shared step is where a differential harness starts agreeing with
// itself.
type Case struct {
	// ID is a stable case identifier used in diff records and coverage.
	ID string
	// Plane is the enforcement plane this case exercises.
	Plane legacycompile.Plane
	// Phase is the legacy evaluation phase this case exercises, set only on a
	// plane that evaluates more than one. A two-phase plane runs one pass per
	// phase in production, each resolving its own action column, so one case
	// must compare one pass - a case with no phase on such a plane conflated
	// both passes into a single comparison. Empty on single-phase planes and
	// on the dynamic substrate, which has no phase concept.
	Phase legacycompile.Phase
	// Org, Principal, Action, Resource address the request.
	Org       string
	Principal string
	Action    string
	Resource  string
	// Groups is the principal's resolved group closure, which is also the
	// ADR-060 segment set the legacy engines resolve.
	Groups []string

	// DetectorVerdicts is the legacy static engine's input: which policy
	// patterns matched this content. A policy id ABSENT from the map means the
	// detector did not run, which is what produces an unknown attribute on the
	// ADR-065 side and a plain non-match on the legacy side. That asymmetry is
	// intended and is one of the enumerated expected changes.
	DetectorVerdicts map[string]bool
	// Fields is the legacy dynamic engine's input: the value getFieldValue
	// would return for each condition field. A field absent from the map
	// resolves to nil, exactly as a context key the caller did not supply
	// does - there is no unresolvable field, only caller-controlled ones
	// (#3515).
	Fields map[string]any
	// ContentVerdicts is the dynamic substrate's detector input, keyed by
	// DynamicContentDetectorPath: whether each dynamic row's content
	// conditions - the contains/contains_any/regex family, compiled as a
	// per-row detector - held for this case's content. A path absent from the
	// map is a detector that did not run, which is UNKNOWN on the ADR-065
	// side, exactly as an absent static DetectorVerdict is.
	//
	// The corpus builder derives each verdict from the SAME final field map
	// the legacy model will read, using the legacy operator semantics, so the
	// two sides cannot disagree for a corpus reason: on the all-rows case,
	// where two rows' satisfying values clobber each other in Fields, the
	// verdict reflects what the surviving values actually match.
	ContentVerdicts map[string]bool

	// Attributes are extra shared attributes for the ADR-065 request, merged
	// over the ones derived from DetectorVerdicts and Fields. A nil value
	// REMOVES an attribute, which is how a case says "the Policy Information
	// Point never produced this at all".
	Attributes map[string]*contract.Attribute
	// PrincipalAttributes are the actor-scoped identity attributes.
	PrincipalAttributes map[string]*contract.Attribute

	// Posture is the deployment detection posture in force for this case.
	Posture legacycompile.Posture
	// Options are the COMPILATION options this case was generated against.
	//
	// They are carried rather than defaulted because two of them change the
	// identifiers the request must use: Realm qualifies the group ids a
	// segment-scoped policy is scoped to, and FieldPaths remaps a legacy
	// condition field onto its attribute path. Building the request from a
	// zero Options while the compiler used a real one made every
	// segment-scoped constraint stop matching on the ADR-065 side while the
	// legacy model still applied it - a silent fail-open, armed the moment an
	// operator sets the Realm the compiler's own doc tells them to set.
	Options legacycompile.Options
	// ExercisesRows names the source rows this case is intended to exercise.
	// Coverage is reported against it, so a case that claims a row and does
	// not reach it is visible.
	ExercisesRows []string
}

// realm is the trust realm this case's identifiers resolve in, taken from the
// compilation options so the corpus and the compiler cannot disagree.
func (c Case) realm() string {
	if c.Options.Realm != "" {
		return c.Options.Realm
	}
	return legacycompile.DefaultRealm
}

// Request builds the normalized ADR-065 request for a case.
//
// Attribute construction is explicit about the three tri-states, because the
// whole ADR-065 correction is that they are not the same thing:
//   - a detector that ran and did not match is KNOWN false;
//   - a detector that did not run is UNKNOWN with reason resolution_failed;
//   - a field the resolver established has no value is ABSENT.
func (c Case) Request(rep *legacycompile.Report, bundleDigest string) (*contract.Request, error) {
	org, err := contract.ParseID(contract.KindOrganization, "Organization::"+c.Org)
	if err != nil {
		return nil, fmt.Errorf("shadow: case %q organization: %w", c.ID, err)
	}
	principal, err := contract.ParseID(contract.KindPrincipal, "User::"+c.realm()+":"+c.Principal)
	if err != nil {
		return nil, fmt.Errorf("shadow: case %q principal: %w", c.ID, err)
	}
	action, err := contract.ParseID(contract.KindAction, "Action::"+c.Action)
	if err != nil {
		return nil, fmt.Errorf("shadow: case %q action: %w", c.ID, err)
	}
	resourceRaw := c.Resource
	if resourceRaw == "" {
		// A legacy static policy has no resource: it inspects content. The
		// action's own identifier is what a tool declaring no resource mapping
		// gets, and it is realm-qualified because a resource identifier is a
		// qualified kind.
		resourceRaw = "Content::" + c.realm() + ":" + c.Action
	}
	resource, err := contract.ParseID(contract.KindResource, resourceRaw)
	if err != nil {
		return nil, fmt.Errorf("shadow: case %q resource: %w", c.ID, err)
	}

	shared := contract.AttributeSet{}
	// Detector signals. A verdict the case supplies is a detector that RAN and
	// reported; every other detector path the plane's policies reference is a
	// detector that did NOT run, and that is unknown rather than false.
	//
	// The order matters: supplied verdicts first, then unknowns for whatever
	// is left. Doing it the other way round would let "did not run" overwrite
	// a real verdict whenever the two spellings of a policy id disagreed, and
	// an unknown that quietly replaces a known false is a decision flipped
	// from permit to indeterminate for no reason anybody could see.
	for policyID, verdict := range c.DetectorVerdicts {
		shared[legacycompile.DetectorSignalPath(policyID)] = contract.Known(verdict, contract.ProvDetector, 1, Now)
	}
	// Dynamic content detectors, by path. Their paths live in the same
	// signal.detector.* family, so the unknown-fill below covers whichever
	// the case did not supply.
	for path, verdict := range c.ContentVerdicts {
		shared[path] = contract.Known(verdict, contract.ProvDetector, 1, Now)
	}
	for _, p := range rep.PoliciesForPhase(c.Plane, c.Phase, c.Org) {
		for _, path := range p.Where.Paths() {
			if contract.NamespaceOf(path) != contract.NsSignal {
				continue
			}
			if !isDetectorPath(path) {
				continue
			}
			if _, already := shared[path]; already {
				continue
			}
			shared[path] = contract.Unknown(contract.ReasonResolutionFailed, contract.ProvDetector, 1, Now)
		}
	}
	// Legacy condition field values, mapped onto their ADR-065 paths.
	for field, val := range c.Fields {
		path := c.Options.AttributePathFor(field)
		ns := contract.NamespaceOf(path)
		if ns == contract.NsPrincipal {
			continue // placed on the actor below
		}
		if val == nil {
			shared[path] = contract.Absent(ns.DefaultProvenance(), 1, Now)
			continue
		}
		shared[path] = contract.Known(val, ns.DefaultProvenance(), 1, Now)
	}
	for path, attr := range c.Attributes {
		if attr == nil {
			delete(shared, path)
			continue
		}
		shared[path] = *attr
	}

	actorAttrs := contract.AttributeSet{
		"principal.id": contract.Known(principal.String(), contract.ProvAuthentication, 1, Now),
	}
	if len(c.Groups) > 0 {
		groups := make([]any, 0, len(c.Groups))
		sorted := append([]string(nil), c.Groups...)
		sort.Strings(sorted)
		for _, g := range sorted {
			groups = append(groups, c.Options.GroupIDFor(g))
		}
		actorAttrs["principal.groups"] = contract.Known(groups, contract.ProvDirectory, 1, Now)
	} else {
		// An empty closure is a RESOLVED empty closure here, not a failure to
		// resolve. The legacy AppliesToSegments contract treats nil caller
		// segments as excluding every segment-scoped policy, which the ADR-065
		// side reproduces as a known empty array producing NO_MATCH.
		actorAttrs["principal.groups"] = contract.Known([]any{}, contract.ProvDirectory, 1, Now)
	}
	for field, val := range c.Fields {
		path := c.Options.AttributePathFor(field)
		if contract.NamespaceOf(path) != contract.NsPrincipal {
			continue
		}
		if val == nil {
			actorAttrs[path] = contract.Absent(contract.ProvAuthentication, 1, Now)
			continue
		}
		actorAttrs[path] = contract.Known(val, contract.ProvAuthentication, 1, Now)
	}
	for path, attr := range c.PrincipalAttributes {
		if attr == nil {
			delete(actorAttrs, path)
			continue
		}
		actorAttrs[path] = *attr
	}

	req := &contract.Request{
		RequestID:    "shadow-" + c.ID,
		Organization: org,
		Principal:    principal,
		Action:       action,
		Resource:     resource,
		Context: contract.Context{
			ActorChain: []contract.Actor{{ID: principal, Attributes: actorAttrs}},
		},
		Snapshot: contract.Snapshot{
			IdentityEpoch: 1, ResourceEpoch: 1, RegistryVersion: 1, PolicyEpoch: 1,
			PolicyBundle: bundleDigest, SchemaVersion: contract.SchemaVersion,
		},
		Attributes:  shared,
		EvaluatedAt: Now,
	}
	return req, nil
}

// isDetectorPath reports whether an attribute path is a compiled static
// policy's detector signal.
func isDetectorPath(path string) bool {
	const prefix = "signal.detector."
	return len(path) > len(prefix) && path[:len(prefix)] == prefix
}
