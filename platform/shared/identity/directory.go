// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// ADR-065 normalized directory contract and group-closure results (#3557).
//
// This file is the EDITION-NEUTRAL contract: the entity and edge model, the
// closure result and its states, the bounds, the resolver interface, and
// NoGraphOnlyResolver. The graph implementation and the SCIM ingestion adapter
// are Enterprise and live in directory_closure.go and directory_scim.go.
//
// There is deliberately no `_community.go` twin of those two. The usual pairing
// exists so a community build still compiles against symbols an Enterprise file
// declares, and nothing untagged references DirectoryGraph, GraphClosureResolver
// or the SCIM adapter: the untagged code depends only on the GroupClosureResolver
// interface below. A stub declaring those symbols would be dead code in the
// community build AND would have to answer the closure question somehow, and the
// answer it would most naturally give, an empty group set, is the fail-open this
// file is arranged to prevent. NoGraphOnlyResolver answers it correctly instead.
//
// THREE CLOSURE OUTCOMES THAT MUST NEVER SHARE A CODE PATH
//
//	no graph      the realm declares no group concept. The empty set is a
//	              FACT about the realm. EX-45. Collapsing this into the
//	              others makes every cloud-IAM service account permanently
//	              indeterminate.
//	unreachable   the realm HAS a graph and it could not be read. EX-15's
//	              family, and the SCIM-outage case. INDETERMINATE.
//	truncated     the traversal hit a bound, so the result may be missing the
//	              very ancestor a ceiling is scoped to. EX-14. INDETERMINATE,
//	              and never evaluated partially.
//
// The failure this separation exists to prevent runs in both directions.
// Collapsing "no graph" into "unreachable" denies every machine principal
// forever. Collapsing "unreachable" or "truncated" into "no graph" turns a
// directory outage into a silent fail-open, because an empty closure removes
// every segment-scoped ceiling while looking exactly like a legitimate
// non-member.
//
// The zero ClosureState is Unspecified and is INDETERMINATE, not authoritative.
// A result that was never populated must not read as "this subject is in no
// groups".
package identity

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// NewGroupID builds a realm-qualified group identifier.
//
// Group identifiers are realm-qualified without exception. A bare group name
// collides across realms: two directories can both have a group called
// "security", and a policy naming the bare string would silently target
// whichever one resolved first.
func NewGroupID(realm RealmID, name string) (PrincipalID, error) {
	return NewPrincipalID(realm, SubjectGroup, name)
}

// MustNewGroupID is NewGroupID for fixtures. It panics on invalid input.
func MustNewGroupID(realm RealmID, name string) PrincipalID {
	g, err := NewGroupID(realm, name)
	if err != nil {
		panic(err)
	}
	return g
}

// DirectoryEntityType classifies a node in the normalized directory graph.
type DirectoryEntityType string

const (
	// DirectoryEntitySubject is a user, service, workload, or agent node.
	DirectoryEntitySubject DirectoryEntityType = "subject"
	// DirectoryEntityGroup is a group node.
	DirectoryEntityGroup DirectoryEntityType = "group"
)

// AttributeFreshness is the tri-state result of a freshness check.
type AttributeFreshness int

const (
	// FreshnessUndeclared is the zero value: the attribute declares no maximum
	// age. It is NOT "fresh forever". ADR-065 requires every policy-visible
	// attribute to carry a maximum acceptable age, so an attribute without one
	// is not usable as a policy input, and IsUsable says so.
	FreshnessUndeclared AttributeFreshness = iota
	// FreshnessFresh means the attribute is within its declared bound.
	FreshnessFresh
	// FreshnessStale means the attribute is outside it. A stale security
	// attribute is UNKNOWN, not its last known value.
	FreshnessStale
)

// String renders the freshness state.
func (f AttributeFreshness) String() string {
	switch f {
	case FreshnessFresh:
		return "fresh"
	case FreshnessStale:
		return "stale"
	case FreshnessUndeclared:
		return "undeclared"
	default:
		return fmt.Sprintf("AttributeFreshness(%d)", int(f))
	}
}

// DirectoryAttribute is one typed, provenance-bearing directory fact.
type DirectoryAttribute struct {
	// Name is the attribute's canonical name.
	Name string
	// Value is its value, as normalized from the source.
	Value string
	// Provenance records where it came from.
	Provenance Provenance
	// ObservedAt is when the source asserted it.
	ObservedAt time.Time
	// SourceVersion is the source record's own version.
	SourceVersion string
	// MaxAge is the maximum acceptable age. Non-positive means undeclared,
	// which makes the attribute unusable as a policy input rather than
	// permanently fresh.
	MaxAge time.Duration
	// Classification drives audit redaction.
	Classification string
}

// Freshness reports whether the attribute is within its declared bound.
func (a DirectoryAttribute) Freshness(now time.Time) AttributeFreshness {
	if a.MaxAge <= 0 || a.ObservedAt.IsZero() {
		return FreshnessUndeclared
	}
	if now.Sub(a.ObservedAt) > a.MaxAge {
		return FreshnessStale
	}
	return FreshnessFresh
}

// IsUsable reports whether policy may read this attribute. Only a fresh
// attribute with a declared bound qualifies.
func (a DirectoryAttribute) IsUsable(now time.Time) bool {
	return a.Freshness(now) == FreshnessFresh
}

// DirectoryEntity is a normalized node: a subject or a group, realm-qualified.
type DirectoryEntity struct {
	// ID is the canonical, realm-qualified identifier.
	ID PrincipalID
	// Type classifies the node.
	Type DirectoryEntityType
	// ExternalID is the provider's own identifier, carried as an alias.
	ExternalID string
	// Attributes are the typed, provenance-bearing facts about this node.
	Attributes []DirectoryAttribute
	// SourceVersion is the provider record's version.
	SourceVersion string
	// ObservedAt is when the record was ingested.
	ObservedAt time.Time
}

// MembershipKind distinguishes a fact the provider stated from one AxonFlow
// derived.
//
// RFC 7643 leaves nested group semantics to the provider. A provider that does
// not define nesting cannot have nesting inferred on its behalf: doing so
// invents ancestors, and an invented ancestor either grants a segment the
// customer never wrote or hides a ceiling they did.
type MembershipKind string

const (
	// MembershipDirect is a membership the provider stated: this subject is a
	// member of this group.
	MembershipDirect MembershipKind = "direct"
	// MembershipNested is a group-in-group edge the provider stated. Only a
	// provider that declares nesting support may produce these.
	MembershipNested MembershipKind = "nested"
)

// DirectoryEdge is a normalized membership edge: Child is a member of Parent.
//
// Both endpoints are realm-qualified and both must be in the same realm. A
// cross-realm edge is rejected at ingestion: it would let one directory assert
// membership in another's group, which is the graph-poisoning case.
type DirectoryEdge struct {
	// Parent is the containing group.
	Parent PrincipalID
	// Child is the member: a subject, or a group when Kind is
	// MembershipNested.
	Child PrincipalID
	// Kind records whether the provider stated this as a direct membership or
	// a nested one.
	Kind MembershipKind
	// SourceVersion is the provider record's version for this edge.
	SourceVersion string
	// ObservedAt is when the edge was ingested.
	ObservedAt time.Time
}

// ClosureState is the outcome class of a group-closure resolution. See the
// file doc for why the three non-trivial states may never share a code path.
type ClosureState int

const (
	// ClosureStateUnspecified is the zero value. It is INDETERMINATE: an
	// unpopulated result must never read as "this subject is in no groups".
	ClosureStateUnspecified ClosureState = iota
	// ClosureStateAuthoritative means the realm has a graph and it was
	// traversed completely. The set may legitimately be empty.
	ClosureStateAuthoritative
	// ClosureStateNoGraph means the realm declares no group concept, so the
	// empty set is a fact about the realm. EX-45.
	ClosureStateNoGraph
	// ClosureStateUnreachable means the realm has a graph that could not be
	// read. INDETERMINATE.
	ClosureStateUnreachable
	// ClosureStateTruncated means a bound was hit before the traversal
	// finished. INDETERMINATE. EX-14.
	ClosureStateTruncated
)

// String renders the closure state.
func (s ClosureState) String() string {
	switch s {
	case ClosureStateAuthoritative:
		return "AUTHORITATIVE"
	case ClosureStateNoGraph:
		return "NO_GRAPH"
	case ClosureStateUnreachable:
		return "UNREACHABLE"
	case ClosureStateTruncated:
		return "TRUNCATED"
	case ClosureStateUnspecified:
		return "UNSPECIFIED"
	default:
		return fmt.Sprintf("ClosureState(%d)", int(s))
	}
}

// IsAuthoritative reports whether the result may be used as a policy input.
// True for a completed traversal and for a realm with no graph; false for
// everything else, including the zero value.
func (s ClosureState) IsAuthoritative() bool {
	return s == ClosureStateAuthoritative || s == ClosureStateNoGraph
}

// ClosureWarningCode names an operational signal that does not change the
// result's correctness.
type ClosureWarningCode string

const (
	// WarnGroupCycleDetected is EX-13: the traversal met a group it had
	// already visited. The closure is still correct and complete, because a
	// visited set makes the closure of a cyclic digraph well defined. The
	// warning is raised anyway, because the customer's directory does not mean
	// what they think it means.
	WarnGroupCycleDetected ClosureWarningCode = "GROUP_CYCLE_DETECTED"
	// WarnOrphanEdgeSkipped means an edge referenced a node the graph does not
	// contain. The edge is skipped, not followed into a synthesized node. It is
	// usually benign: a stale row, or a member removed between two pages of an
	// export.
	WarnOrphanEdgeSkipped ClosureWarningCode = "ORPHAN_EDGE_SKIPPED"
	// WarnCrossRealmEdgeRejected means an edge's endpoints were not both in the
	// snapshot's realm: one directory asserting membership in another's group.
	//
	// It has its own code because it is NOT the orphan case, however similar
	// the handling looks. An orphan is a stale reference; this is the
	// graph-poisoning shape, and an operator seeing a wave of them is looking
	// at an attempted cross-realm assertion rather than at cleanup lag. Sharing
	// one code makes those two indistinguishable in exactly the situation where
	// telling them apart matters most.
	WarnCrossRealmEdgeRejected ClosureWarningCode = "CROSS_REALM_EDGE_REJECTED"
	// WarnFanOutClamped means one group had more parents than the fan-out
	// bound allows. Unlike the other two this one accompanies a TRUNCATED
	// state, because parents were left unexpanded.
	WarnFanOutClamped ClosureWarningCode = "FAN_OUT_CLAMPED"
)

// ClosureWarning is one operational signal from a traversal.
type ClosureWarning struct {
	// Code names the signal.
	Code ClosureWarningCode
	// Members names the principals involved, sorted for determinism.
	Members []PrincipalID
	// Detail is a short, audit-safe explanation.
	Detail string
}

// String renders the warning.
func (w ClosureWarning) String() string {
	names := make([]string, len(w.Members))
	for i, m := range w.Members {
		names[i] = m.String()
	}
	return fmt.Sprintf("%s[%s]", w.Code, strings.Join(names, ","))
}

// WitnessPath is the shortest path from the subject to a resolved group,
// subject first. BFS produces it for free, and an operator answering "why is
// this person governed by that segment" needs it.
type WitnessPath []PrincipalID

// String renders the path.
func (p WitnessPath) String() string {
	names := make([]string, len(p))
	for i, n := range p {
		names[i] = n.String()
	}
	return strings.Join(names, " -> ")
}

// ClosureResult is the outcome of resolving a subject's group closure.
//
// The resolved set is UNEXPORTED. The only way to obtain a policy-usable set
// is AuthoritativeGroups, which refuses unless the state is authoritative. A
// public field would let a caller read a truncated set with an ordinary field
// access and no compiler or reviewer prompt, which is exactly how a partial
// closure becomes a missing ceiling.
type ClosureResult struct {
	// State is the outcome class.
	State ClosureState
	// Subject is the principal the closure was resolved for.
	Subject PrincipalID
	// Reason is the admission reason when the state is not authoritative.
	Reason AdmissionReason
	// Detail is a short, audit-safe explanation.
	Detail string
	// Warnings are operational signals that do not change correctness.
	Warnings []ClosureWarning
	// Depth is the greatest number of edges traversed from the subject.
	Depth int
	// SourceVersion identifies the directory snapshot this was resolved
	// against.
	SourceVersion string
	// ObservedAt is when the resolution ran.
	ObservedAt time.Time

	// groups is the resolved set, sorted. Unexported on purpose: see the type
	// doc.
	groups []PrincipalID
	// witnesses maps each resolved group to its shortest path.
	witnesses map[PrincipalID]WitnessPath
}

// AuthoritativeGroups returns the resolved group set, and true, only when the
// state is authoritative.
//
// On any other state it returns (nil, false) and the caller must NOT proceed
// as though the subject had no groups. Use MustBeAuthoritative to get the
// Admission that goes with the refusal.
func (r ClosureResult) AuthoritativeGroups() ([]PrincipalID, bool) {
	if !r.State.IsAuthoritative() {
		return nil, false
	}
	return append([]PrincipalID(nil), r.groups...), true
}

// PartialGroups returns whatever the traversal managed to resolve, regardless
// of state.
//
// DIAGNOSTICS ONLY. It exists so an operator report can show what a truncated
// traversal saw before it stopped. It must never reach a policy input: a
// partial closure may be missing the very ancestor a ceiling is scoped to, and
// a missing ceiling fails open.
func (r ClosureResult) PartialGroups() []PrincipalID {
	return append([]PrincipalID(nil), r.groups...)
}

// Witness returns the shortest path from the subject to group.
func (r ClosureResult) Witness(group PrincipalID) (WitnessPath, bool) {
	p, ok := r.witnesses[group]
	if !ok {
		return nil, false
	}
	return append(WitnessPath(nil), p...), true
}

// MustBeAuthoritative returns the resolved groups, or the Admission that a
// non-authoritative closure produces.
//
// The second return value is the whole point: a caller writes
//
//	groups, adm := result.MustBeAuthoritative()
//	if !adm.State.IsAdmitted() { return adm }
//
// and cannot reach `groups` without having handled the refusal.
func (r ClosureResult) MustBeAuthoritative() ([]PrincipalID, Admission) {
	if groups, ok := r.AuthoritativeGroups(); ok {
		return groups, AcceptAdmission(r.Subject)
	}
	reason := r.Reason
	if reason == ReasonNone {
		// A non-authoritative result built without a reason. Report the
		// conservative one rather than a determinate-looking empty reason.
		reason = ReasonClosureUnavailable
	}
	detail := r.Detail
	if detail == "" {
		detail = fmt.Sprintf("group closure for %s is %s", r.Subject, r.State)
	}
	return nil, IndeterminateAdmission(reason, detail)
}

// ClosureAttribute is a closure rendered as the tri-state policy attribute the
// PDP consumes (#3554).
//
// The PDP does not implement closure resolution: group membership reaches it as
// an ordinary attribute per actor hop, and Kleene logic does the rest with no
// special case. A group-scoped constraint over an unknown closure is unknown,
// so the request is indeterminate; over an authoritative empty closure the same
// constraint is a clean non-match and organization-scoped constraints still
// bind. That is EX-45 falling out of the logic rather than being special-cased,
// which is only possible if the producer distinguishes the two, so this is the
// contract between the identity plane and the PDP.
//
// # TWO REASONS UNDER ONE UNKNOWN, DELIBERATELY
//
// Truncated and unreachable are both Unknown and the PDP treats them
// identically, which is correct. They carry DIFFERENT reasons anyway, and the
// cost of not doing so is paid entirely by whoever is on call: CLOSURE_UNAVAILABLE
// means look at the directory provider, CLOSURE_TRUNCATED means look at the
// bounds against a directory that has outgrown them. Same evaluation, different
// page, different day.
type ClosureAttribute struct {
	// Known reports whether the group set is a fact. True for a completed
	// traversal AND for a realm with no group concept.
	Known bool
	// Groups is the canonical group set, sorted, when Known. A nil slice with
	// Known true is the legitimate empty set, not an absence.
	Groups []string
	// UnknownReason names why the set could not be established. Empty when
	// Known.
	UnknownReason AdmissionReason
}

// GroupsAttribute renders this closure as the PDP's tri-state attribute.
//
// It is the only sanctioned conversion. A consumer building the attribute from
// the exported fields would have to decide for itself what an unpopulated
// result means, and the answer it would most naturally reach, an empty group
// list, is the fail-open this whole file exists to prevent.
func (r ClosureResult) GroupsAttribute() ClosureAttribute {
	if groups, ok := r.AuthoritativeGroups(); ok {
		var out []string
		for _, g := range groups {
			out = append(out, g.String())
		}
		return ClosureAttribute{Known: true, Groups: out}
	}
	reason := r.Reason
	if reason == ReasonNone {
		// A non-authoritative result with no reason, which includes the zero
		// value. Report the conservative reason rather than an empty one: an
		// empty reason beside Known false invites a consumer to treat the
		// attribute as merely absent.
		reason = ReasonClosureUnavailable
	}
	return ClosureAttribute{Known: false, UnknownReason: reason}
}

// NewAuthoritativeClosure builds a completed traversal result.
func NewAuthoritativeClosure(
	subject PrincipalID, groups []PrincipalID, witnesses map[PrincipalID]WitnessPath,
	warnings []ClosureWarning, depth int, sourceVersion string, observedAt time.Time,
) ClosureResult {
	return ClosureResult{
		State:         ClosureStateAuthoritative,
		Subject:       subject,
		Warnings:      warnings,
		Depth:         depth,
		SourceVersion: sourceVersion,
		ObservedAt:    observedAt,
		groups:        sortedPrincipals(groups),
		witnesses:     witnesses,
	}
}

// NewNoGraphClosure builds the EX-45 result: this realm has no group concept,
// so the empty set is a fact.
//
// It takes the REALM rather than a source-version string, because the version
// this result should carry is the realm configuration's own: there is no
// directory snapshot behind a no-graph closure, and the realm's declaration is
// the thing that could change and invalidate the answer. The earlier signature
// invited its two callers to pass an explanatory sentence where a version
// belongs, which is what both of them did, so a decision proof over a no-graph
// realm recorded prose in a version field and left Detail empty.
func NewNoGraphClosure(subject PrincipalID, realm TrustRealm, observedAt time.Time) ClosureResult {
	return ClosureResult{
		State:   ClosureStateNoGraph,
		Subject: subject,
		Detail: fmt.Sprintf("realm %q declares directory source %s, so it has no group concept",
			realm.RealmID, realm.Directory),
		SourceVersion: fmt.Sprintf("realm/%s/v%d", realm.RealmID, realm.Version),
		ObservedAt:    observedAt,
		groups:        nil,
	}
}

// NewUnreachableClosure builds the outage result.
func NewUnreachableClosure(subject PrincipalID, detail string, observedAt time.Time) ClosureResult {
	return ClosureResult{
		State:      ClosureStateUnreachable,
		Subject:    subject,
		Reason:     ReasonClosureUnavailable,
		Detail:     detail,
		ObservedAt: observedAt,
	}
}

// NewTruncatedClosure builds the EX-14 result. partial is retained for
// diagnostics and is unreachable through AuthoritativeGroups.
func NewTruncatedClosure(
	subject PrincipalID, partial []PrincipalID, witnesses map[PrincipalID]WitnessPath,
	warnings []ClosureWarning, depth int, detail string, sourceVersion string, observedAt time.Time,
) ClosureResult {
	return ClosureResult{
		State:         ClosureStateTruncated,
		Subject:       subject,
		Reason:        ReasonClosureTruncated,
		Detail:        detail,
		Warnings:      warnings,
		Depth:         depth,
		SourceVersion: sourceVersion,
		ObservedAt:    observedAt,
		groups:        sortedPrincipals(partial),
		witnesses:     witnesses,
	}
}

// sortedPrincipals returns a sorted copy. Sorted output makes closures
// comparable across runs, which a decision proof over the resolved set needs.
func sortedPrincipals(in []PrincipalID) []PrincipalID {
	if len(in) == 0 {
		return nil
	}
	out := append([]PrincipalID(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// ClosureBounds bounds a traversal.
//
// A zero value means "not configured" and is replaced by the defaults, never
// treated as unlimited. An unlimited traversal over a hostile or merely
// misconfigured directory is a request that never returns.
type ClosureBounds struct {
	// MaxDepth is the greatest number of edges from the subject.
	MaxDepth int
	// MaxGroups is the greatest number of groups the closure may contain.
	MaxGroups int
	// MaxFanOut is the greatest number of parents expanded from one node.
	MaxFanOut int
}

// Default closure bounds. Depth 16 is far above any real directory nesting
// (three to five levels is typical); the bound exists to stop a pathological
// graph, not to shape ordinary ones.
const (
	defaultClosureMaxDepth  = 16
	defaultClosureMaxGroups = 1024
	defaultClosureMaxFanOut = 256
)

// DefaultClosureBounds returns the bounds used when none are configured.
func DefaultClosureBounds() ClosureBounds {
	return ClosureBounds{
		MaxDepth:  defaultClosureMaxDepth,
		MaxGroups: defaultClosureMaxGroups,
		MaxFanOut: defaultClosureMaxFanOut,
	}
}

// Normalized replaces non-positive bounds with the defaults.
func (b ClosureBounds) Normalized() ClosureBounds {
	d := DefaultClosureBounds()
	if b.MaxDepth <= 0 {
		b.MaxDepth = d.MaxDepth
	}
	if b.MaxGroups <= 0 {
		b.MaxGroups = d.MaxGroups
	}
	if b.MaxFanOut <= 0 {
		b.MaxFanOut = d.MaxFanOut
	}
	return b
}

// GroupClosureResolver resolves a subject's realm-qualified group closure.
//
// It returns a ClosureResult and NO error, deliberately. An (result, error)
// signature invites the shape
//
//	res, err := resolve(...)
//	if err != nil { return nil }
//
// which is precisely the SCIM-outage fail-open: an outage becomes an empty
// group set indistinguishable from a legitimate non-member. Here the outage IS
// a state, it travels with the result, and AuthoritativeGroups refuses to hand
// out a set for it.
type GroupClosureResolver interface {
	ResolveClosure(ctx context.Context, orgID string, realm TrustRealm, subject PrincipalID, bounds ClosureBounds) ClosureResult
}

// closureRealmAdmissible reports whether a realm handed to a resolver is one a
// closure may be resolved against, and returns the refusal when it is not.
//
// EVERY RESOLVER MUST CALL THIS FIRST, AND HERE IS WHY.
//
// RealmRegistry.Lookup and LookupByIssuer return (TrustRealm{}, false) on a
// miss. A caller that ignores the boolean hands a ZERO TrustRealm to a
// resolver, and a zero realm's DirectorySource is Unspecified, whose
// HasGroupGraph is false. Without this check that lands in the no-graph branch
// and produces an AUTHORITATIVE EMPTY closure: EX-47 reconstructed exactly,
// through the resolver's front door rather than through the credential path,
// with every segment-scoped ceiling silently skipped and the PDP told the
// answer is known.
//
// Registration refusing underspecified realms does not close this, because the
// zero realm was never registered. Denying an undeclared issuer does not close
// it either, because this path never consulted an issuer. The three mechanisms
// guard three different doors and all three are needed.
//
// The refusal is UNREACHABLE rather than a no-graph result, and that is the
// whole point: the plane cannot say anything about the groups of a subject in a
// realm it was not given, so the honest answer is that the closure could not be
// established.
func closureRealmAdmissible(orgID string, realm TrustRealm, subject PrincipalID, at time.Time) (ClosureResult, bool) {
	if realm.RealmID == "" {
		return NewUnreachableClosure(subject,
			"a closure was requested against a zero TrustRealm, which is what a registry lookup returns on a miss; an undeclared realm has no group answer",
			at), false
	}
	if !realm.Directory.IsValid() {
		return NewUnreachableClosure(subject, fmt.Sprintf(
			"realm %q was handed to a closure resolver with directory source %s; an undeclared or unrecognized source is not the same fact as no group graph",
			realm.RealmID, realm.Directory), at), false
	}
	if !realm.Enabled {
		// Every other plane refuses a disabled realm. The first draft of this
		// guard checked two fields and left this one out, so the closure plane
		// alone answered for a realm an operator had switched off, which is
		// worse than inconsistent: disabling a realm is how a compromised
		// directory is taken out of service.
		return NewUnreachableClosure(subject, fmt.Sprintf(
			"realm %q is declared but administratively disabled", realm.RealmID), at), false
	}
	if realm.OrgID != orgID {
		// The graph is keyed on the ARGUMENT organization while the
		// declaration comes from the caller's TrustRealm. Without this, one
		// organization's realm declaration resolves against another's
		// directory, which is a tenancy crossing dressed as a lookup.
		return NewUnreachableClosure(subject, fmt.Sprintf(
			"realm %q is declared in a different organization than the closure was requested for", realm.RealmID), at), false
	}
	if subject.Realm != realm.RealmID {
		// The subject and the realm must agree, or the answer comes from the
		// wrong directory. An empty set from the WRONG directory is
		// indistinguishable from a legitimate non-member in the right one.
		return NewUnreachableClosure(subject, fmt.Sprintf(
			"subject is in realm %q and the closure was requested against realm %q", subject.Realm, realm.RealmID), at), false
	}
	if subject.Type == SubjectGroup {
		return NewUnreachableClosure(subject,
			"a Group principal was passed where a subject is required; resolve group ancestry through the graph directly", at), false
	}
	return ClosureResult{}, true
}

// NoGraphOnlyResolver is the resolver for a deployment with no directory
// integration wired.
//
// It is edition-neutral and it is the community build's only resolver, because
// directory ingestion is Enterprise. It is not a stub that returns nothing: it
// answers the two cases correctly and DIFFERENTLY, which is the whole point.
//
//   - A realm declaring no group graph resolves to an AUTHORITATIVE empty set.
//     That is a fact about the realm and it is as true here as under an
//     Enterprise build. A cloud-IAM service-account realm is fully governable
//     on a community deployment.
//   - A realm declaring a group graph resolves to UNREACHABLE. It is NOT
//     resolved to an empty set. An operator who configured a SCIM realm on a
//     build that cannot read one has a misconfiguration, and reporting it as
//     "this subject is in no groups" would silently drop every segment-scoped
//     ceiling that realm's groups appear in. That is the fail-open this whole
//     file is arranged to prevent, and it would be reintroduced by the most
//     natural possible stub.
type NoGraphOnlyResolver struct {
	// Now overrides the clock. Nil means time.Now.
	Now func() time.Time
}

// ResolveClosure implements GroupClosureResolver.
func (r NoGraphOnlyResolver) ResolveClosure(
	_ context.Context, orgID string, realm TrustRealm, subject PrincipalID, _ ClosureBounds,
) ClosureResult {
	now := time.Now
	if r.Now != nil {
		now = r.Now
	}
	at := now()
	if refusal, ok := closureRealmAdmissible(orgID, realm, subject, at); !ok {
		return refusal
	}
	if !realm.HasGroupGraph() {
		return NewNoGraphClosure(subject, realm, at)
	}
	return NewUnreachableClosure(subject, fmt.Sprintf(
		"realm %q declares directory source %s and no directory integration is wired in this deployment",
		realm.RealmID, realm.Directory), at)
}
