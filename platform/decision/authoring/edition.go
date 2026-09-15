// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoring

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// The edition boundary for typed authoring (#3907, #3592), as ruled by #3906.
//
// # The ruling this file implements, and the one it replaces
//
// ADR-066's 2026-09-08 amendment set organization-root policies to 0 on
// Community and Evaluation. #3906 withdrew that value and replaced it with
// 20 / 50 / unlimited, because the word "organization" changed meaning when
// the model went from three tiers to two signing roots: in the new model
// EVERY customer-authored policy is organization-root, so the old sentence
// read as "Community and Evaluation author nothing".
//
// What #3906 put in its place is the sentence this file exists to make true:
//
//	The edition boundary is which CONSTRUCTS a policy may use - scope kinds,
//	the condition allowlist, obligation families - not which signing root it
//	is written to.
//
// So there is no root check here, no build tag, and no second document format.
// One vocabulary, one evaluator, one signing root for every customer; the
// editions differ in which parts of that vocabulary they may spend.
//
// # Every row cites a ruling, and the ones with no ruling say so
//
// The failure mode this file is most exposed to is inventing an edition
// boundary nobody ruled and having it read as product policy six months later
// because it is in code. So each entry in each table below names the PRD row
// it implements, by section, and a reviewer can check the table against
// technical-docs/product/PRD_EDITION_CAPABILITY_BOUNDARIES.md rather than
// against the judgement of whoever wrote it.
//
// Where no ruling exists the entry says UNRULED and is RESERVED - permitted on
// Enterprise, refused below it, under its own finding code that names the
// absence rather than pretending to a decision. Reserving is the fail-safe
// direction here and only here: Community and Evaluation can author NOTHING
// today, so withholding an unruled construct cannot regress a deployment,
// while granting one would be a boundary set by accident. RESERVED is a
// question for the operator, and CodeConstructUnruled is what makes it visible
// instead of silent.
//
// # Totality is enforced, not intended
//
// Both classifications are held TOTAL over the closed vocabularies they read -
// contract.AllObligationFamilies() and contract.AllNamespaces() - by
// edition_test.go. A family or a namespace added to the contract without a row
// here fails a named test rather than defaulting to permitted, which is the
// direction an omission would otherwise take: the zero value of a bool map is
// false, but a missing key in a table nobody enumerates is a construct nobody
// classified, and the test is what turns that into a build failure.
//
// # What is deliberately NOT a dimension here
//
// BREAK-GLASS PIERCING. pdp.RuleOrgPolicyPiercesSystem already rejects any
// organization-root policy that declares PierceableBy, and every
// customer-authored document is organization-root. So the construct is
// unreachable on every edition by an invariant that predates this file, and an
// edition row for it would be a control that can never fire - indistinguishable
// in a test report from one that works.
//
// RAW REGO. PRD section 5.1 rules it None / None / "not in the initial ADR-065
// release". ADR-065 admits no raw Rego from any customer on any edition, so
// there is no construct to gate.

// Edition is the licensed edition a publication is bound by.
//
// It is the EDITION and not the tier: license.Tier has five self-hosted values
// plus the SaaS plugin tiers, and several of them map onto one boundary.
// EditionFor performs that fold in exactly one place.
type Edition string

const (
	// EditionCommunity is the unlicensed or Community-licensed deployment.
	EditionCommunity Edition = "community"
	// EditionEvaluation is the time-boxed Evaluation licence.
	EditionEvaluation Edition = "evaluation"
	// EditionEnterprise is every paid tier: Professional, Enterprise and
	// Enterprise Plus all resolve here.
	EditionEnterprise Edition = "enterprise"
)

// AllEditions returns the closed set, weakest first.
func AllEditions() []Edition {
	return []Edition{EditionCommunity, EditionEvaluation, EditionEnterprise}
}

// rank orders the editions so a table can be written as "from this edition
// upwards" rather than as a set literal per row. Community 0, Evaluation 1,
// Enterprise 2.
var editionRank = map[Edition]int{
	EditionCommunity:  0,
	EditionEvaluation: 1,
	EditionEnterprise: 2,
}

// Valid reports whether e is one of the three declared editions.
func (e Edition) Valid() bool {
	_, ok := editionRank[e]
	return ok
}

// atLeast reports whether e is the named edition or a higher one.
func (e Edition) atLeast(floor Edition) bool {
	mine, ok := editionRank[e]
	if !ok {
		// Unreachable for a Valid edition; ProfileFor refuses an invalid one
		// before any table is read. false rather than true so a future edition
		// that forgets its rank is refused every gated construct instead of
		// granted all of them.
		return false
	}
	return mine >= editionRank[floor]
}

// reserved is the sentinel floor for a construct with NO ruling. It is
// deliberately not an Edition value: nothing can be "at least reserved", so a
// row carrying it is refused on every edition by the table and then permitted
// on Enterprise by the one explicit branch in constructFloorAllows, which is
// where the reservation is stated once and can be read.
const reservedFloor Edition = "__unruled__"

// obligationFamilyFloor is the lowest edition that may author each obligation
// family. TOTAL over contract.AllObligationFamilies(); see the file header.
//
//	FamilyDisclosure  PRD 5.1 "Basic deny, block, and redact - Full/Full/Full".
//	                  Redaction, masking, removal and response filtering are the
//	                  substance of a basic policy and are ruled Full everywhere.
//	FamilyAuditNotify PRD 5.3 "Enforce basic local obligations - Full/Full/Full".
//	                  An immutable audit record and a notification are local
//	                  obligations; the ENTERPRISE obligation COORDINATORS that
//	                  PRD 5.3 rules None/None/Full are a different row and a
//	                  different mechanism, and are not gated here.
//	FamilyRouting     PRD 5.1 "Route restriction obligations - None/Full/Full".
//	FamilyApproval    PRD 5.3 "Human approval and rejection - None / Resolve
//	                  legacy entries only / Full". Resolving a legacy entry is
//	                  not authoring a new approval obligation, so Evaluation is
//	                  refused the CONSTRUCT while keeping the legacy surface.
//	FamilyBudget      PRD 5.3 "Budget and quota reservation - None/None/Full".
//	FamilyStepUp      UNRULED. No PRD row names step-up authentication or the
//	                  assurance ladder. RESERVED rather than granted; see the
//	                  file header for why the unruled direction is reservation,
//	                  and #3907 for the question routed to the operator.
var obligationFamilyFloor = map[contract.ObligationFamily]Edition{
	contract.FamilyDisclosure:  EditionCommunity,
	contract.FamilyAuditNotify: EditionCommunity,
	contract.FamilyRouting:     EditionEvaluation,
	contract.FamilyApproval:    EditionEnterprise,
	contract.FamilyBudget:      EditionEnterprise,
	contract.FamilyStepUp:      reservedFloor,
}

// namespaceFloor is the lowest edition that may read each attribute namespace.
// TOTAL over contract.AllNamespaces(); see the file header.
//
// This is PRD 5.1's "Basic request-context predicates - Bounded allowlist /
// Broader bounded allowlist / Full trusted-attribute model" expressed against
// the vocabulary the decision contract already declares. contract.Namespace is
// a CLOSED set whose whole purpose is that "the trust class of a term is
// lexically visible in the policy text", so an edition allowlist over
// namespaces is a bound on trust classes rather than a hand-kept list of paths
// that would drift the first time an attribute was added.
//
//	principal PRD 5.2 "Canonical local principal and realm contract -
//	          Full/Full/Full".
//	action    PRD 5.1 "Deterministic PDP and canonical contracts -
//	          Full/Full/Full". The registered action and its registry metadata.
//	resource  PRD 5.1, same row. The resource under decision.
//	args      PRD 5.1 "Basic request-context predicates". Caller-supplied
//	          argument data is the untrusted class the bounded allowlist is
//	          ABOUT, and pdp.RuleAuthorityFromUntrusted already forbids using it
//	          to establish authority on every edition, so admitting it at
//	          Community bounds a predicate rather than granting an authority.
//	env      PRD 5.1, the "broader bounded allowlist" half. Gateway observation
//	          - time, network zone, device posture - is the context a basic
//	          predicate set does not carry and a broader one does.
//	signal    PRD 5.1 "Tuning the shipped system controls - None/Full/Full".
//	          signal.* IS the shipped detectors' output, so a condition reading
//	          it is a policy tuned against a shipped control.
//	agent     PRD 5.2 "Delegation and actor-chain policy - None/None/Full". The
//	          calling agent established by attestation is the actor half of an
//	          actor chain.
//	state     PRD 5.3 "Budget and quota reservation - None/None/Full". state.*
//	          is platform counter state, "for example a reserved budget total",
//	          which is the same ruling FamilyBudget reads.
var namespaceFloor = map[contract.Namespace]Edition{
	contract.NsPrincipal: EditionCommunity,
	contract.NsAction:    EditionCommunity,
	contract.NsResource:  EditionCommunity,
	contract.NsArgs:      EditionCommunity,
	contract.NsEnv:       EditionEvaluation,
	contract.NsSignal:    EditionEvaluation,
	contract.NsAgent:     EditionEnterprise,
	contract.NsState:     EditionEnterprise,
}

// groupScopeFloor is the lowest edition that may scope a policy to a group.
//
// PRD 5.2 "Nested group graph and closure - None/None/Full". pdp.Scope.Groups
// is resolved through the principal.groups closure, which is that graph; a
// deployment without it has no membership to resolve. Scope.Principals and
// Scope.Organization are NOT gated - PRD 5.2 rules the canonical local
// principal Full on every edition, and organization scope is the base case a
// document with no narrower selector already has.
const groupScopeFloor = EditionEnterprise

// separationOfDutiesFloor is the lowest edition on which publication and
// activation require a second person.
//
// PRD 5.3 "Compound approvals and separation of duties - None/None/Full".
//
// THIS IS THE ROW THAT MADE THE LADDER UNSPENDABLE (#3907). checkSeparationOfDuties
// refuses any publication whose approvers do not include somebody other than
// the author, and Store's checkActivationActor refuses activation by the
// author while checkActivationAuthority additionally requires the activator to
// be a recorded approver. None of the three was conditional on anything, so a
// single-admin Community deployment could not publish one policy - and could
// not have with a route and a durable store handed to it, because the refusal
// is upstream of both. The ladder's 20 was unspendable for a reason that had
// nothing to do with the number.
//
// WHAT RELAXING IT DOES NOT DO. Below this floor a publication may name no
// approver and the author may activate their own version. Everything else is
// unchanged: the document is still validated, still runs the full gauntlet,
// is still signed, is still admitted only after verification, still advances a
// version, still follows the parent chain, and every activation is still an
// audited record naming a non-zero principal. checkActivationActor's
// requirement that the actor be a named principal of the right KIND is not
// part of separation of duties and is not relaxed: an unattributed activation
// defeats the audit trail on every edition. What goes is the requirement for a
// SECOND person, which is the capability PRD 5.3 rules Enterprise-only, and
// nothing else.
const separationOfDutiesFloor = EditionEnterprise

// Profile is the construct and publication boundary for one edition.
//
// It is a VALUE rather than an interface and its fields are unexported: a
// profile is produced by ProfileFor and by ProfileForUnestablishedTier and by
// nothing else, so there is no struct literal anywhere that can assemble an
// edition boundary this file did not declare. That is the same structural
// argument Artifact makes about the gauntlet, for the same reason - a second
// construction path is a second opinion about the boundary.
//
// THE ZERO VALUE IS NOT A PROFILE. Its edition is the empty string, which is
// not Valid, so every construct table refuses it - and tierEstablished is
// false, so the duty rule is ON. Both directions of the zero value therefore
// fail closed, and every entry point below refuses it by name anyway rather
// than relying on that.
type Profile struct {
	edition Edition
	// tierEstablished reports that the process which built this profile was
	// able to DETERMINE the deployment's licensed tier, as opposed to falling
	// back to Community because it could not.
	//
	// See RequiresSeparationOfDuties for why the two are not the same question
	// and why exactly one rule reads this field.
	tierEstablished bool
}

// ProfileFor returns the profile for an ESTABLISHED edition: one a caller
// determined, rather than one it fell back to.
//
// A caller that resolved its edition from a licence read which could not
// establish the deployment's tier must use ProfileForUnestablishedTier
// instead. platform/shared/authoringedition is the only resolver in the tree
// that makes that choice, and a census holds it to being the only one.
func ProfileFor(e Edition) (Profile, error) {
	if !e.Valid() {
		return Profile{}, fmt.Errorf(
			"authoring: %q is not a declared edition; the declared editions are %v", e, AllEditions())
	}
	return Profile{edition: e, tierEstablished: true}, nil
}

// ProfileForUnestablishedTier returns the boundary for a deployment whose
// licensed tier its own process could NOT establish.
//
// # THE ASYMMETRY IS THE POINT, AND IT IS NOT UNIFORMITY DEFERRED
//
// This profile carries the COMMUNITY construct set and the ENTERPRISE duty
// rule, which looks inconsistent until the two are read as answering different
// questions:
//
//   - A CONSTRUCT is a capability. Failing soft to Community costs an author a
//     construct they may be entitled to, and costs the deployment no control:
//     EditionFor's own comment makes that case, and it is right. Refusing
//     instead would take a deployment from "the smallest boundary" to "no
//     authoring at all", which is the failure #3907 exists to end.
//
//   - A DUTY RULE is a control. "Fewer capabilities" and "fewer approvers"
//     point in OPPOSITE directions, so the same fallback that is conservative
//     for the first is permissive for the second. Reading Community for an
//     Enterprise deployment turns the two-person rule OFF exactly where it is
//     meant to be on, and one person can then publish and activate alone.
//
// So the fallback is kept for constructs and inverted for the duty rule: an
// unestablished tier is treated as the LOWEST edition for what may be
// authored and as the HIGHEST for who must sign it off. Collapsing the two
// into one policy because uniformity is tidier would reintroduce whichever
// half it dropped.
//
// # WHAT THIS COSTS WHEN IT FIRES WRONGLY
//
// A deployment that really is Community but whose process cannot say so gets
// the two-person rule it does not owe, and a single administrator cannot
// publish. That is a visible, nameable refusal an operator can fix by giving
// the process its licence input - the opposite of the silent grant this
// replaces. The resolver is what keeps it from firing on a genuine Community
// deployment; see its own doc for the three signals it separates.
func ProfileForUnestablishedTier() Profile {
	return Profile{edition: EditionCommunity, tierEstablished: false}
}

// validate refuses a Profile no constructor here produced.
//
// It exists because Profile is now the value the surface entry points take,
// and the zero value of a struct is always constructible by a caller. Without
// this the compile error that NewAPI's doc promises would be a runtime
// boundary of "no valid edition, duties on" - which fails closed, but silently,
// and a boundary nobody declared is not one this package will enforce.
func (p Profile) validate() error {
	if !p.edition.Valid() {
		return fmt.Errorf(
			"authoring: %q is not a declared edition; the declared editions are %v "+
				"(a zero-value Profile reaches here: build one with ProfileFor or ProfileForUnestablishedTier)",
			p.edition, AllEditions())
	}
	return nil
}

// EditionFor folds a licence tier onto the three edition boundaries.
//
// It takes a STRING rather than a license.Tier because platform/decision
// carries no dependency on the licence package and must not acquire one: the
// decision module is the half of the product a community deployment runs, and
// a policy vocabulary that imports a licence reader is a vocabulary that
// cannot be reasoned about without one. The orchestrator performs the verified
// read and hands the resolved tier name here.
//
// AN UNRECOGNISED TIER RESOLVES TO COMMUNITY, which is the same fold
// license.ReadCurrentTier performs for an absent, forged or expired key. The
// alternative - refusing - would take a deployment whose licence string this
// build does not recognise from "the smallest boundary" to "no authoring at
// all", which is the failure #3907 exists to end.
func EditionFor(tier string) Edition {
	switch strings.ToLower(strings.TrimSpace(tier)) {
	case "evaluation":
		return EditionEvaluation
	case "professional", "enterprise", "enterprise_plus", "enterprise-plus", "enterpriseplus":
		return EditionEnterprise
	default:
		return EditionCommunity
	}
}

// Edition returns the edition this profile bounds.
func (p Profile) Edition() Edition { return p.edition }

// TierEstablished reports whether the edition above was DETERMINED by the
// process that built this profile, or fallen back to because it could not be.
//
// A transport serves this beside the edition so an author refused a construct
// on a deployment they believe is Enterprise can tell "this deployment is
// Community" from "this process cannot see its licence", which are the same
// refusal and completely different remedies.
func (p Profile) TierEstablished() bool { return p.tierEstablished }

// RequiresSeparationOfDuties reports whether a publication under this profile
// needs an approver other than the author, and whether an activation needs an
// actor other than that author.
//
// AN UNESTABLISHED TIER REQUIRES IT REGARDLESS OF THE EDITION, and this is the
// ONE rule in this file that reads tierEstablished. Every construct rule below
// deliberately does not: see ProfileForUnestablishedTier for why a fallback
// that is conservative for a capability is permissive for a control.
func (p Profile) RequiresSeparationOfDuties() bool {
	if !p.tierEstablished {
		return true
	}
	return p.edition.atLeast(separationOfDutiesFloor)
}

// constructFloorAllows answers one table row for this profile.
//
// The reservation is stated HERE, once. A row carrying reservedFloor is
// permitted on Enterprise and refused below it, and the second return value
// says which of the two reasons applied so the caller can raise the finding
// that names the absence of a ruling rather than one that implies there was
// one.
func (p Profile) constructFloorAllows(floor Edition) (allowed bool, unruled bool) {
	if floor == reservedFloor {
		return p.edition == EditionEnterprise, true
	}
	return p.edition.atLeast(floor), false
}

// AllowsObligationFamily reports whether this edition may author an obligation
// of the given family, and whether the family has no ruling.
//
// A family absent from the table is refused on every edition INCLUDING
// Enterprise, and reports unruled. That is deliberate and is the one place the
// totality test is not the only guard: a family added to the contract and not
// classified here is a construct nobody ruled, and permitting it on the widest
// edition because it was forgotten is exactly the accident this file is
// written to prevent.
func (p Profile) AllowsObligationFamily(f contract.ObligationFamily) (allowed bool, unruled bool) {
	floor, ok := obligationFamilyFloor[f]
	if !ok {
		return false, true
	}
	return p.constructFloorAllows(floor)
}

// AllowsNamespace reports whether this edition may read attributes in the
// given namespace, and whether the namespace has no ruling.
//
// contract.NsUnknown - a path whose head is not a declared namespace - is
// refused here with unruled=false rather than reported as a missing row,
// because it is not an unclassified construct: pdp.RuleFieldNotInSchema and
// CodeArgumentNotInActionSchema already refuse an undeclared path on every
// edition, so this arm is unreachable through Validate and exists so that a
// direct caller of this method gets the fail-closed answer.
func (p Profile) AllowsNamespace(ns contract.Namespace) (allowed bool, unruled bool) {
	if ns == contract.NsUnknown {
		return false, false
	}
	floor, ok := namespaceFloor[ns]
	if !ok {
		return false, true
	}
	return p.constructFloorAllows(floor)
}

// AllowsGroupScope reports whether this edition may scope a policy to a group.
func (p Profile) AllowsGroupScope() bool {
	allowed, _ := p.constructFloorAllows(groupScopeFloor)
	return allowed
}

// NOTE ON THE ACTIVATION REFUSAL'S CODE. ADR-066's enforcement response quotes
// CAPABILITY_REQUIRES_*, and that code is declared in the activation package
// rather than in this file's check table. The table is the SAVE-TIME check
// list: every entry needs a case that provokes it and a mutant proving the case
// can fail, and an operator-facing check list is generated from it. An
// activation refusal is neither a save-time check nor produced by newFinding -
// it CARRIES the findings this package raised - so declaring it here would add
// a row to that list that no save-time case can ever fire.

// Validate refuses a Profile no constructor in this package produced.
//
// It is the exported form of validate, and it exists because Profile is now
// carried ACROSS a package boundary: activation takes one in its Inputs and has
// to refuse a zero value rather than silently treat it as an edition. Without
// this, a caller that forgot to set the field would get "no valid edition,
// duties on", which fails closed but silently - and a boundary nobody declared
// is not one this package will enforce.
func (p Profile) Validate() error { return p.validate() }

// CheckConstructs refuses a document that spends a construct this profile's
// edition does not carry, and is the exported form of checkEditionConstructs.
//
// # WHY THE SAME CHECK RUNS IN TWO PLACES, AND WHY THAT IS NOT DUPLICATION
//
// checkEditionConstructs runs inside Publish, which is the only function that
// produces an Artifact, so no SIGNED document can miss it. That is a complete
// guarantee about this package's own door, and it says nothing about a document
// that reached an engine without passing through here: one imported by
// ee/platform/policy/cmd/axonflow-policy-import, whose edition comes from an
// operator FLAG rather than the licence, or one INSERTed straight into
// typed_policy_artifacts, which migrations/core/176 grants the application role
// permission to do (its triggers block UPDATE and DELETE, not INSERT).
//
// pdp.refuseBlanketPermission already states this shape for the blanket rule:
// publication guards what an author can SAVE, and the engine guards what it
// will ENFORCE, because the two doors admit different traffic. This is that
// second door for the edition boundary, and activation is where it stands.
//
// The findings are the same findings, carrying the same codes, so an operator
// reading a refusal at activation sees the sentence the author would have seen
// at publication.
func (p Profile) CheckConstructs(d *Document) Findings { return checkEditionConstructs(d, p) }

// checkEditionConstructs refuses a document that spends a construct its
// edition does not carry.
//
// It runs in Publish beside checkSeparationOfDuties rather than in Validate,
// and the placement is the difference between a boundary and a suggestion.
// Validate answers "is this document well formed", which is an edition-free
// question a portal asks on every keystroke; Publish answers "may this become
// a signed artifact", which is where an entitlement belongs. Putting it here
// also means it cannot be skipped: Publish is the only function that produces
// an Artifact, so there is no path to a signed document that misses it.
//
// Findings are complete rather than first-error, in the package's own idiom:
// an author who has spent three constructs their edition does not carry should
// see three, not one per publication attempt.
func checkEditionConstructs(d *Document, p Profile) Findings {
	if d == nil {
		return nil
	}
	carried := templateCarried(d)
	var out Findings
	for _, pol := range d.Policy.Policies {
		out = append(out, checkPolicyConstructs(pol, p, carried[pol.ID])...)
	}
	return out
}

// # A policy carried from the organization template (PRD §1.4, K12)
//
// The shipped organization template is deployment-authored: every new
// organization draft is seeded from it, and it must validate and activate on
// every edition regardless of the authoring floors, or a Community
// organization could not publish the draft it was seeded with without losing
// the destructive-command blocks. All 22 of its policies read signal.*, which
// is Evaluation-and-up for an organization's OWN constraints, and stays so.
//
// THE EXEMPTION IS PER CONSTRUCT, BOUNDED BY WHAT THE TEMPLATE ITSELF SPENDS.
// A policy whose id names a shipped template policy is exempt from the floor
// for exactly the constructs that template policy spends: each attribute path
// it reads, each obligation family it attaches, and group scope if it is
// group-scoped. So:
//
//   - an edit that tunes the carried policy - its effect, its actions, its
//     condition over the same paths, its description - keeps the exemption,
//     which is what per-policy re-action and enable/disable need (§1.5);
//   - an edit that reads a path, attaches an obligation family or scopes to a
//     group the template policy does not is refused for that construct below
//     its floor, exactly as the organization's own policy would be;
//   - a template policy copied under a new id is the organization's own.
//
// The id locates the policy's origin; it grants nothing the origin does not
// spend. Naming a new policy with a template id buys exactly the constructs the
// deployment already ships under that id, which is why this is not an id-string
// exemption. Exact content equality was the other candidate and is wrong: it
// would withdraw the exemption the moment an organization re-actioned a shipped
// policy, which is the edit §1.5 exists to allow.
//
// Only an ORGANIZATION-root document carries it: the template is an
// organization seed, and no other root is seeded from it.
type templateSpend struct {
	paths    map[string]bool
	families map[contract.ObligationFamily]bool
	groups   bool
}

func (s *templateSpend) readsPath(path string) bool { return s != nil && s.paths[path] }

func (s *templateSpend) attaches(f contract.ObligationFamily) bool { return s != nil && s.families[f] }

func (s *templateSpend) spendsGroupScope() bool { return s != nil && s.groups }

var shippedTemplateSpend struct {
	once sync.Once
	byID map[string]*templateSpend
	err  error
}

// templateCarried returns what each shipped organization-template policy
// spends, keyed by policy id, for an organization-root document, and nil for
// any other root.
//
// The template is embedded in this binary, so a load failure is a build defect
// every corpus test reds on. The exemption then does not apply and the floors
// decide: the failure refuses rather than admits.
func templateCarried(d *Document) map[string]*templateSpend {
	if d.Policy.Root != pdp.RootOrganization {
		return nil
	}
	shippedTemplateSpend.once.Do(func() {
		tmpl, err := pdp.SystemCorpusOrganizationTemplate()
		if err != nil {
			shippedTemplateSpend.err = err
			return
		}
		shippedTemplateSpend.byID = indexTemplateSpend(tmpl)
	})
	if shippedTemplateSpend.err != nil {
		return nil
	}
	return shippedTemplateSpend.byID
}

// indexTemplateSpend records what each policy of a template spends against the
// authoring floors, derived the way checkPolicyConstructs reads a policy.
func indexTemplateSpend(tmpl *pdp.Document) map[string]*templateSpend {
	out := make(map[string]*templateSpend, len(tmpl.Policies))
	for _, pol := range tmpl.Policies {
		s := &templateSpend{
			paths:    map[string]bool{},
			families: map[contract.ObligationFamily]bool{},
			groups:   len(pol.Scope.Groups) > 0,
		}
		for _, path := range pol.ReferencedPaths() {
			s.paths[path] = true
		}
		for _, ob := range pol.Obligations {
			if fam, err := ob.Family(); err == nil {
				s.families[fam] = true
			}
		}
		out[pol.ID] = s
	}
	return out
}

// checkPolicyConstructs raises one finding per construct pol spends that the
// edition does not carry, except the constructs carried from the organization
// template (nil when pol carries none; see templateSpend).
func checkPolicyConstructs(pol pdp.Policy, p Profile, carried *templateSpend) Findings {
	var out Findings

	if len(pol.Scope.Groups) > 0 && !p.AllowsGroupScope() && !carried.spendsGroupScope() {
		out = append(out, newFinding(CodeGroupScopeNotInEdition, pol.ID, fmt.Sprintf(
			"this policy is scoped to group(s) %v, and group scope resolves through the nested group graph, which the %s edition does not carry; scope it to the principals directly, or to the organization",
			idStrings(pol.Scope.Groups), p.edition)))
	}

	// Obligations, de-duplicated BY FAMILY per policy. A policy attaching four
	// disclosure transforms has one boundary question, not four, and repeating
	// the same sentence per obligation would bury the other findings under it.
	seenFamily := map[contract.ObligationFamily]bool{}
	for _, ob := range pol.Obligations {
		fam, err := ob.Family()
		if err != nil {
			// An unregistered obligation type. pdp.RuleMalformedCondition and
			// contract validation already refuse it on every edition; raising a
			// SECOND finding here would report an edition boundary for what is
			// a malformed document, and "your edition may not use this" is the
			// wrong sentence to put in front of a typo.
			continue
		}
		if seenFamily[fam] {
			continue
		}
		seenFamily[fam] = true
		if carried.attaches(fam) {
			continue
		}
		allowed, unruled := p.AllowsObligationFamily(fam)
		if allowed {
			continue
		}
		if unruled {
			out = append(out, newFinding(CodeConstructUnruled, pol.ID, fmt.Sprintf(
				"this policy attaches a %q obligation (%q), and no edition ruling covers that obligation family; it is reserved to Enterprise until one is made, and the %s edition cannot publish it",
				fam, ob.Type, p.edition)))
			continue
		}
		out = append(out, newFinding(CodeObligationFamilyNotInEdition, pol.ID, fmt.Sprintf(
			"this policy attaches a %q obligation (%q), which the %s edition does not carry",
			fam, ob.Type, p.edition)))
	}

	// Attribute namespaces, de-duplicated BY NAMESPACE per policy, for the same
	// reason. ReferencedPaths is the DERIVED population: it walks Where, Unless,
	// ResourceScope and both selectors, so a condition shape added to pdp.Policy
	// is covered here without this function changing. Reading the paths off the
	// document's declared Attributes instead would check what the author said
	// they would read rather than what the policy reads.
	seenNs := map[contract.Namespace]bool{}
	for _, path := range pol.ReferencedPaths() {
		if carried.readsPath(path) {
			continue
		}
		ns := contract.NamespaceOf(path)
		if seenNs[ns] {
			continue
		}
		seenNs[ns] = true
		if ns == contract.NsUnknown {
			// Already refused, on every edition, by the schema rules named in
			// AllowsNamespace. Not this check's finding to raise.
			continue
		}
		allowed, unruled := p.AllowsNamespace(ns)
		if allowed {
			continue
		}
		if unruled {
			out = append(out, newFinding(CodeConstructUnruled, pol.ID, fmt.Sprintf(
				"this policy reads %q, and no edition ruling covers the %q attribute namespace; it is reserved to Enterprise until one is made, and the %s edition cannot publish it",
				path, ns, p.edition)))
			continue
		}
		out = append(out, newFinding(CodeAttributeNamespaceNotInEdition, pol.ID, fmt.Sprintf(
			"this policy reads %q, and the %s edition's request-context predicates do not include the %q namespace",
			path, p.edition, ns)))
	}

	return out
}

// EditionConstructReport is the machine-readable boundary for one edition: what
// a caller may spend before it tries to.
//
// It exists because a route that can only say NO after a publication attempt
// makes an author discover the boundary one refusal at a time. The portal's
// catalog endpoint answers "what actions exist"; this answers "what of the
// vocabulary is mine", which is the other half of the same question and is the
// only thing a Community author has instead of a UI that greys a control out.
type EditionConstructReport struct {
	Edition Edition `json:"edition"`
	// ObligationFamilies and Namespaces are the permitted values, sorted.
	ObligationFamilies []string `json:"obligation_families"`
	Namespaces         []string `json:"attribute_namespaces"`
	GroupScope         bool     `json:"group_scope"`
	// SeparationOfDuties reports whether publication and activation require a
	// second person on this edition.
	SeparationOfDuties bool `json:"separation_of_duties"`
	// TierEstablished reports whether Edition above was determined or fallen
	// back to. It is reported rather than left implicit because false makes
	// SeparationOfDuties true while Edition reads "community", and those two
	// together are otherwise a contradiction the reader has to guess at.
	TierEstablished bool `json:"tier_established"`
	// Reserved names the constructs withheld for want of a ruling rather than
	// by one. It is reported rather than folded into the exclusions above
	// because the two have different remedies: an excluded construct is an
	// upgrade, a reserved one is a question.
	Reserved []string `json:"reserved,omitempty"`
}

// Constructs describes this profile for a caller.
func (p Profile) Constructs() EditionConstructReport {
	rep := EditionConstructReport{
		Edition:            p.edition,
		GroupScope:         p.AllowsGroupScope(),
		SeparationOfDuties: p.RequiresSeparationOfDuties(),
		TierEstablished:    p.tierEstablished,
	}
	for _, f := range contract.AllObligationFamilies() {
		allowed, unruled := p.AllowsObligationFamily(f)
		switch {
		case unruled:
			rep.Reserved = append(rep.Reserved, "obligation_family:"+string(f))
			if allowed {
				rep.ObligationFamilies = append(rep.ObligationFamilies, string(f))
			}
		case allowed:
			rep.ObligationFamilies = append(rep.ObligationFamilies, string(f))
		}
	}
	for _, ns := range contract.AllNamespaces() {
		allowed, unruled := p.AllowsNamespace(ns)
		switch {
		case unruled:
			rep.Reserved = append(rep.Reserved, "attribute_namespace:"+string(ns))
			if allowed {
				rep.Namespaces = append(rep.Namespaces, string(ns))
			}
		case allowed:
			rep.Namespaces = append(rep.Namespaces, string(ns))
		}
	}
	sort.Strings(rep.ObligationFamilies)
	sort.Strings(rep.Namespaces)
	sort.Strings(rep.Reserved)
	return rep
}
