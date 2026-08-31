// Package conformance is the executable specification for ADR-065 Phase 0.
//
// It carries three things that have to stay in step with each other: the
// fixture world of the source proposal translated into ADR-065's model, the
// 47-row source-case disposition ledger, and the table-driven case corpus that
// executes every non-dropped case against a contract.Decider. The ledger guard
// fails if the three disagree, which is what stops a case quietly losing its
// coverage while the ledger still claims it has some.
//
// The translation into ADR-065's four policy authorities is the substantive
// part and is worth stating once here, because every case depends on it:
//
//   - A grant becomes a PERMISSION policy.
//   - A ceiling capping at Deny becomes a CONSTRAINT policy.
//   - A ceiling capping at Escalate becomes a REQUIREMENT policy attaching an
//     approval_challenge obligation. Approval is a stateful requirement, not a
//     value in a flattened verdict lattice, which is the correction that makes
//     compound approval clauses composable at all.
//   - A ceiling with no cap and only obligations becomes a REQUIREMENT policy.
//   - A ceiling carrying a budget becomes a REQUIREMENT policy attaching a
//     quota_reservation obligation, discharged by a reservation coordinator
//     outside the pure evaluator.
//   - A detector becomes an INSPECTION policy, which cannot grant and cannot
//     deny. Its accumulated score arrives as the tri-state attribute
//     signal.risk_score, and the threshold policies that ACT on that score are
//     ordinary constraint and requirement policies. That is how ADR-065's
//     assurance classes are expressed: a detector plane that cannot answer
//     makes a gating-risk requirement UNKNOWN and therefore fails closed, while
//     an individual advisory detector that cannot answer is skipped with a
//     warning.
package conformance

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"sort"
	"time"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/registry"
)

// Now is the fixed evaluation instant every case is decided at. A fixed instant
// is not cosmetic: freshness bounds, approval expiry and the decision binding
// digest all read it, and a wall clock would make the corpus non-reproducible
// in exactly the dimension ADR-065 requires reproducibility.
var Now = time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)

// Realm identifiers. The workspace realm has a group graph and can be asked a
// question; the gcp-iam realm has neither.
const (
	RealmWorkspace = "realm_ws"
	RealmGCP       = "realm_gcp"
	RealmConnector = "connector"
)

// group builds a realm-qualified group identifier.
func group(name string) contract.ID {
	return contract.MustParseID(contract.KindGroup, "Group::"+RealmWorkspace+":"+name)
}

func user(name string) contract.ID {
	return contract.MustParseID(contract.KindPrincipal, "User::"+RealmWorkspace+":"+name)
}

func machine(name string) contract.ID {
	return contract.MustParseID(contract.KindPrincipal, "Workload::"+RealmGCP+":"+name)
}

func action(name string) contract.ID {
	return contract.MustParseID(contract.KindAction, "Action::"+name)
}

func resource(typ, id string) contract.ID {
	return contract.MustParseID(contract.KindResource, typ+"::"+RealmConnector+":"+id)
}

// groupParents is the directory graph. Membership is set membership, never
// specialization: a nearer group does not override a farther one, because the
// graph is a DAG and "most specific" is undefined when a group has two parents.
// Meet and join are commutative and associative, so traversal order, diamonds
// and duplicate paths are all irrelevant to the answer.
var groupParents = map[string][]string{
	"support-tier2":    {"support"},
	"support":          {"all-staff"},
	"contractors-emea": {"all-contractors"},
	"finance":          {"all-staff"},
	"legal":            {"all-staff"},
	"oncall-sre":       {"all-staff"},
	"all-contractors":  {},
	"all-staff":        {},
	"compliance":       {"all-staff"},
	"security-leads":   {},
	"support-leads":    {},
	"staff-managers":   {},
	"legal-leads":      {},
	"fraud-team":       {},
}

// Principal is a fixture subject.
type Principal struct {
	ID contract.ID
	// DirectGroups are the direct memberships. The closure is computed.
	DirectGroups []string
	// HasGroupGraph is false for a realm with no group concept at all. The
	// closure is then an authoritative empty set rather than a failure, and
	// collapsing the two would make every IAM-sourced service account
	// permanently indeterminate.
	HasGroupGraph bool
	// Interactive is false where no person can answer a question. A pool
	// resolving only in a non-interactive realm cannot discharge an approval
	// however many members it has.
	Interactive bool
}

// Principals is the fixture principal set.
var Principals = map[string]Principal{
	"alice": {ID: user("alice"), DirectGroups: []string{"support-tier2"}, HasGroupGraph: true, Interactive: true},
	"bob":   {ID: user("bob"), DirectGroups: []string{"support-tier2", "contractors-emea"}, HasGroupGraph: true, Interactive: true},
	"carol": {ID: user("carol"), DirectGroups: []string{"support-tier2", "finance"}, HasGroupGraph: true, Interactive: true},
	"dana":  {ID: user("dana"), DirectGroups: []string{"legal"}, HasGroupGraph: true, Interactive: true},
	"frank": {ID: user("frank"), DirectGroups: []string{"legal", "contractors-emea"}, HasGroupGraph: true, Interactive: true},
	"erin":  {ID: user("erin"), DirectGroups: []string{"oncall-sre"}, HasGroupGraph: true, Interactive: true},
	// mia is a member of two approver pools AND of legal, so a case can put a
	// senior approver in the position of requesting the very action she would
	// otherwise be eligible to approve.
	"mia":     {ID: user("mia"), DirectGroups: []string{"security-leads", "staff-managers", "legal"}, HasGroupGraph: true, Interactive: true},
	"agent-A": {ID: machine("agent-A"), HasGroupGraph: false, Interactive: false},
	"sub-B":   {ID: machine("sub-B"), HasGroupGraph: false, Interactive: false},
	"sub-C":   {ID: machine("sub-C"), HasGroupGraph: false, Interactive: false},
}

// Closure computes the transitive group closure with a visited set.
//
// The transitive closure of a cyclic digraph is well defined; it is the
// reachable set, and breadth-first search with a visited set computes it
// correctly. Cycles are therefore a correctness non-issue and an operational
// signal: they mean the customer's directory does not mean what they think it
// means. Truncation is the dangerous one, because a truncated closure may be
// missing a constraint, and a missing constraint fails open.
func (p Principal) Closure(extraEdges map[string][]string) []string {
	if !p.HasGroupGraph {
		return []string{}
	}
	parents := map[string][]string{}
	for k, v := range groupParents {
		parents[k] = v
	}
	for k, v := range extraEdges {
		parents[k] = append(append([]string(nil), parents[k]...), v...)
	}
	visited := map[string]struct{}{}
	frontier := append([]string(nil), p.DirectGroups...)
	for len(frontier) > 0 {
		var next []string
		for _, g := range frontier {
			if _, seen := visited[g]; seen {
				continue
			}
			visited[g] = struct{}{}
			next = append(next, parents[g]...)
		}
		frontier = next
	}
	out := make([]string, 0, len(visited))
	for g := range visited {
		out = append(out, group(g).String())
	}
	sort.Strings(out)
	return out
}

// Actions is the fixture action registry, carrying the tags, delegation depth,
// argument schema and response leaf schema of each tool.
var Actions = map[string]pdp.ActionEntry{
	"T1": {
		ID: action("stripe.create_refund"), Tags: []string{"irreversible", "spend"},
		MaxDelegationDepth: 3, Irreversible: true,
		Arguments:         map[string]pdp.ValueType{"amount_cents": pdp.TypeNumber},
		RequiredArguments: []string{"amount_cents"},
		PayloadLeaves:     []string{"response.refund_id", "response.status"},
	},
	"T2": {
		ID: action("crm.export_contacts"), Tags: []string{"pii_egress", "irreversible", "pii"},
		MaxDelegationDepth: 2, Irreversible: true, DataEgress: true,
		Arguments:     map[string]pdp.ValueType{"segment": pdp.TypeString},
		PayloadLeaves: []string{"response.ssn", "response.dob", "response.phone", "response.email", "response.name"},
	},
	"T3": {
		ID: action("docs.search"), Tags: []string{"read_only"},
		MaxDelegationDepth: 5,
		Arguments:          map[string]pdp.ValueType{"query": pdp.TypeString},
		PayloadLeaves:      []string{"response.title", "response.snippet"},
	},
	"T4": {
		ID: action("crm.get_contact"), Tags: []string{"pii"},
		MaxDelegationDepth: 5,
		Arguments:          map[string]pdp.ValueType{"contact_id": pdp.TypeString},
		PayloadLeaves:      []string{"response.ssn", "response.dob", "response.phone", "response.email", "response.name"},
	},
	"T5": {
		ID: action("jira.transition_issue"), Tags: []string{"reversible"},
		MaxDelegationDepth: 3,
		Arguments:          map[string]pdp.ValueType{"ticket_id": pdp.TypeString, "to_status": pdp.TypeString},
		PayloadLeaves:      []string{"response.status"},
	},
	"T6": {
		ID: action("confluence.export_page"), Tags: []string{"pii_egress", "irreversible", "pii"},
		MaxDelegationDepth: 2, Irreversible: true, DataEgress: true,
		Arguments:     map[string]pdp.ValueType{"page_id": pdp.TypeString},
		PayloadLeaves: []string{"response.ssn", "response.body", "response.phone"},
	},
}

// Resource is a fixture business entity with its resolver-materialized
// ancestors. Ancestors are always resolver-fetched and never read from caller
// arguments, even when the caller helpfully supplies a project key: containment
// is an authority fact, and the authority rule forbids establishing authority
// from untrusted input.
type Resource struct {
	ID contract.ID
	// Owner is present on ticket-like resources.
	Owner string
	// Project and ProjectClassification are named-level projections. They are
	// AUTHORITATIVELY ABSENT on a resource type that declares no project
	// level, which is different from unresolvable.
	Project               string
	ProjectClassification string
	Instance              string
	// Closure is the containment closure for a recursive resource type. It is
	// authoritatively absent for a non-recursive type, where partial
	// resolution is structurally impossible.
	Closure []string
	// HasClosure distinguishes "recursive type, closure resolved" from
	// "non-recursive type, no closure exists".
	HasClosure bool
	// CustomerRiskTier is present only where the resource has a customer.
	CustomerRiskTier string
}

// Resources is the fixture instance set.
var Resources = map[string]Resource{
	"SUP-42": {
		ID: resource("Ticket", "SUP-42"), Owner: user("alice").String(),
		Project: resource("Project", "SUPPORT").String(), ProjectClassification: "internal",
		Instance: resource("Instance", "acme").String(),
	},
	// SUP-43 is byte-identical to SUP-42 except for its owner. It exists so a
	// case can be identical to another apart from the principal, which is the
	// only way to show that adding a group changed the outcome.
	"SUP-43": {
		ID: resource("Ticket", "SUP-43"), Owner: user("bob").String(),
		Project: resource("Project", "SUPPORT").String(), ProjectClassification: "internal",
		Instance: resource("Instance", "acme").String(),
	},
	"SUP-99": {
		ID: resource("Ticket", "SUP-99"), Owner: user("dana").String(),
		Project: resource("Project", "SUPPORT").String(), ProjectClassification: "internal",
		Instance: resource("Instance", "acme").String(),
	},
	"LEG-7": {
		ID: resource("Ticket", "LEG-7"), Owner: user("dana").String(),
		Project: resource("Project", "LEGAL").String(), ProjectClassification: "restricted",
		Instance: resource("Instance", "acme").String(),
	},
	"P-900": {
		ID: resource("Page", "P-900"), HasClosure: true,
		Closure: []string{
			resource("Page", "P-410").String(), resource("Page", "P-77").String(),
			resource("Space", "LEGAL").String(), resource("Instance", "acme").String(),
		},
	},
	"P-311": {
		ID: resource("Page", "P-311"), HasClosure: true,
		Closure: []string{resource("Space", "ENG").String(), resource("Instance", "acme").String()},
	},
	// P-500 has two parents. Reachability by ANY path is enough: a page
	// reachable from a restricted space IS restricted even though it is also
	// filed somewhere benign. Intersecting the scopes along each path instead
	// would let anything escape any constraint by also being linked into an
	// open folder.
	"P-500": {
		ID: resource("Page", "P-500"), HasClosure: true,
		Closure: []string{
			resource("Page", "P-77").String(), resource("Space", "LEGAL").String(),
			resource("Page", "P-200").String(), resource("Space", "ENG").String(),
			resource("Instance", "acme").String(),
		},
	},
	// P-deep nests past the declared maximum depth. Its closure is
	// unresolvable rather than partial: never evaluate against a partial
	// closure, because the missing ancestor may be the one a constraint is
	// scoped to.
	"P-deep": {ID: resource("Page", "P-deep"), HasClosure: true},
	"CONTACTS": {
		ID: resource("Segment", "all-contacts"),
	},
	// A ticket in a quarantined project, so a policy reading the project level
	// itself has a resource that makes it match.
	"QRT-1": {
		ID: resource("Ticket", "QRT-1"), Owner: user("alice").String(),
		Project: resource("Project", "QUARANTINE").String(), ProjectClassification: "internal",
		Instance: resource("Instance", "acme").String(),
	},
}

// SpaceLegal is the restricted space C12 is scoped to.
var SpaceLegal = resource("Space", "LEGAL")

// Attribute paths used across the fixture policies.
const (
	PathPrincipalID     = "principal.id"
	PathPrincipalGroups = "principal.groups"
	PathActionID        = "action.id"
	PathActionTags      = "action.tags"
	PathArgsAmount      = "args.amount_cents"
	PathResourceOwner   = "resource.owner"
	PathResourceProject = "resource.project"
	PathResourceClass   = "resource.project.classification"
	PathResourceClosure = "resource.closure"
	PathResourceRisk    = "resource.customer.risk_tier"
	PathStateVelocity   = "state.velocity_10m"
	PathStateAnomaly    = "state.amount_anomaly_threshold"
	PathEnvNewDevice    = "env.new_device"
	PathSignalRisk      = "signal.risk_score"
	PathAgentTrust      = "agent.trust_level"
)

// attributeSchema declares every policy-visible attribute once.
//
// Optionality is load bearing. A named level that a resource TYPE does not
// declare is authoritatively absent, and a constraint scoped to that level must
// then be NO_MATCH rather than UNKNOWN; without that distinction, a constraint
// about projects would make every decision about a page indeterminate. An
// attribute that is required and absent is a data defect and stays unknown.
func attributeSchema() []pdp.AttributeSchema {
	return []pdp.AttributeSchema{
		{Path: PathPrincipalID, Type: pdp.TypeString},
		{Path: PathPrincipalGroups, Type: pdp.TypeArray},
		{Path: PathActionID, Type: pdp.TypeString},
		{Path: PathActionTags, Type: pdp.TypeArray},
		{Path: PathArgsAmount, Type: pdp.TypeNumber, Optional: true},
		{Path: PathResourceOwner, Type: pdp.TypeString, Optional: true},
		{Path: PathResourceProject, Type: pdp.TypeString, Optional: true},
		{Path: PathResourceClass, Type: pdp.TypeString, Optional: true},
		{Path: PathResourceClosure, Type: pdp.TypeArray, Optional: true},
		{Path: PathResourceRisk, Type: pdp.TypeString, Optional: true},
		{Path: PathStateVelocity, Type: pdp.TypeNumber, Optional: true},
		{Path: PathStateAnomaly, Type: pdp.TypeNumber, Optional: true},
		{Path: PathEnvNewDevice, Type: pdp.TypeBoolean, Optional: true},
		{Path: PathSignalRisk, Type: pdp.TypeNumber},
		{Path: PathAgentTrust, Type: pdp.TypeString},
	}
}

func approvalObligation(policyID string, quorum int, groups ...string) contract.Obligation {
	eligible := make([]string, 0, len(groups))
	for _, g := range groups {
		eligible = append(eligible, group(g).String())
	}
	joined := eligible[0]
	for _, e := range eligible[1:] {
		joined += "," + e
	}
	return contract.Obligation{
		Type: contract.ObApprovalChallenge,
		Params: map[string]string{
			"quorum": fmt.Sprintf("%d", quorum), "eligible": joined,
			// Separation of duties is declared on every approval clause in
			// this world. It is the contract-level statement that no member of
			// the actor chain may discharge the request they made, which is
			// the property self-approval exclusion protects.
			"separation_of_duties": "true",
		},
		SourcePolicy:  policyID,
		SchemaVersion: 1,
	}
}

// SystemDocument holds the constraints and requirements. It is a separate
// signed root from the permissions so that an organization permission can never
// modify, remove or shadow a system constraint.
func SystemDocument() *pdp.Document {
	return &pdp.Document{
		Root: pdp.RootSystem, Version: 1, Attributes: attributeSchema(),
		InteractiveRealms: map[string]bool{RealmWorkspace: true, RealmGCP: false},
		Policies: []pdp.Policy{
			{
				ID: "C1", Authority: contract.AuthorityRequirement, Root: pdp.RootSystem, Mandatory: true,
				Scope: pdp.Scope{Organization: true}, Actions: pdp.ActionSelector{RequiredTags: []string{"spend"}},
				Where:        pdp.Compare(PathArgsAmount, pdp.OpGt, 100000).HandlingAbsence(pdp.AbsentIsUnknown),
				Obligations:  []contract.Obligation{approvalObligation("C1", 1, "support-leads")},
				PierceableBy: []contract.ID{group("oncall-sre")},
				Description:  "spend above 100000 cents requires one support lead to approve",
			},
			{
				ID: "C2", Authority: contract.AuthorityConstraint, Root: pdp.RootSystem,
				Scope: pdp.Scope{Organization: true}, Actions: pdp.ActionSelector{RequiredTags: []string{"pii_egress"}},
				Where:  pdp.True(),
				Unless: ptr(pdp.Intersects(PathPrincipalGroups, group("legal").String(), group("compliance").String())),
				// pierceable_by is nil: this constraint encodes a regulatory
				// boundary and is unbreakable by construction, which is the
				// difference between a control and a suggestion.
				Description: "personal-data egress is denied outside legal and compliance",
			},
			{
				ID: "C3", Authority: contract.AuthorityRequirement, Root: pdp.RootSystem, Mandatory: true,
				Scope:       pdp.Scope{Organization: true},
				Actions:     pdp.ActionSelector{RequiredTags: []string{"irreversible", "pii_egress"}},
				Where:       pdp.True(),
				Obligations: []contract.Obligation{approvalObligation("C3", 2, "security-leads")},
				Description: "irreversible personal-data egress requires two security leads",
			},
			{
				ID: "C4", Authority: contract.AuthorityRequirement, Root: pdp.RootSystem, Mandatory: true,
				Scope:       pdp.Scope{Groups: []contract.ID{group("all-contractors")}},
				Actions:     pdp.ActionSelector{Any: true},
				Where:       pdp.True(),
				Obligations: []contract.Obligation{approvalObligation("C4", 1, "staff-managers")},
				Description: "every contractor action requires one staff manager to approve",
			},
			{
				ID: "C5", Authority: contract.AuthorityRequirement, Root: pdp.RootSystem, Mandatory: true,
				Scope: pdp.Scope{Organization: true}, Actions: pdp.ActionSelector{RequiredTags: []string{"pii"}},
				Where: pdp.True(),
				Obligations: []contract.Obligation{
					{Type: contract.ObFieldRedact, Target: "response.ssn", SourcePolicy: "C5", SchemaVersion: 1},
					{Type: contract.ObFieldRedact, Target: "response.dob", SourcePolicy: "C5", SchemaVersion: 1},
				},
				Description: "social security number and date of birth are redacted on personal-data reads",
			},
			{
				ID: "C6", Authority: contract.AuthorityRequirement, Root: pdp.RootSystem, Mandatory: true,
				Scope: pdp.Scope{Organization: true}, Actions: pdp.ActionSelector{RequiredTags: []string{"pii"}},
				Where: pdp.True(),
				Obligations: []contract.Obligation{
					{Type: contract.ObFieldMask, Target: "response.phone", Params: map[string]string{"keep": "last4"}, SourcePolicy: "C6", SchemaVersion: 1},
				},
				Description: "telephone numbers are masked to the last four digits",
			},
			{
				ID: "C8", Authority: contract.AuthorityRequirement, Root: pdp.RootSystem, Mandatory: true,
				Scope: pdp.Scope{Organization: true}, Actions: pdp.ActionSelector{RequiredTags: []string{"spend"}},
				Where: pdp.True(),
				Obligations: []contract.Obligation{{
					Type: contract.ObQuotaReservation,
					Params: map[string]string{
						"counter": "daily_spend", "unit": "cents",
						"limit": "5000000", "window": "P1D", "amount_from": PathArgsAmount,
					},
					SourcePolicy: "C8", SchemaVersion: 1,
				}},
				Description: "daily spend is capped at 5000000 cents per principal",
			},
			{
				ID: "C10", Authority: contract.AuthorityConstraint, Root: pdp.RootSystem,
				Scope: pdp.Scope{Organization: true}, Actions: pdp.ActionSelector{RequiredTags: []string{"spend"}},
				Where:       pdp.Compare(PathResourceRisk, pdp.OpEq, "high").HandlingAbsence(pdp.AbsentIsNoMatch),
				Description: "spend against a high-risk customer is denied",
			},
			{
				ID: "C12", Authority: contract.AuthorityConstraint, Root: pdp.RootSystem,
				Scope: pdp.Scope{Organization: true}, Actions: pdp.ActionSelector{RequiredTags: []string{"pii_egress"}},
				ResourceScope: ptr(pdp.Member(PathResourceClosure, SpaceLegal.String()).HandlingAbsence(pdp.AbsentIsNoMatch)),
				Where:         pdp.True(),
				Description:   "nothing under the legal space may leave the organization",
			},
			{
				ID: "C13", Authority: contract.AuthorityRequirement, Root: pdp.RootSystem, Mandatory: true,
				Scope: pdp.Scope{Organization: true}, Actions: pdp.ActionSelector{Any: true},
				ResourceScope: ptr(pdp.Compare(PathResourceClass, pdp.OpEq, "restricted").HandlingAbsence(pdp.AbsentIsNoMatch)),
				Where:         pdp.True(),
				Obligations:   []contract.Obligation{approvalObligation("C13", 1, "legal-leads")},
				Description:   "actions on restricted projects require one legal lead",
			},
			// S1 splits the source's scoring policy into the two policies that
			// ACT on the score. The score itself is a tri-state attribute
			// produced by the inspection plane, so a detection plane that
			// cannot answer makes S1-APPROVE unknown and fails closed, which is
			// what "gating risk" means in ADR-065's assurance table.
			{
				// A named-level projection that is not the classification. It
				// exists so that resource.project is READ by a policy rather
				// than merely declared in the schema: an attribute no policy
				// reads generates no tri-state corpus entries, so declaring one
				// without reading it is a silent hole in gate 4.
				ID: "C17", Authority: contract.AuthorityConstraint, Root: pdp.RootSystem,
				Scope: pdp.Scope{Organization: true}, Actions: pdp.ActionSelector{Any: true},
				ResourceScope: ptr(pdp.Compare(PathResourceProject, pdp.OpEq,
					resource("Project", "QUARANTINE").String()).HandlingAbsence(pdp.AbsentIsNoMatch)),
				Where:       pdp.True(),
				Description: "no action is permitted against a quarantined project",
			},
			{
				// The attesting agent is a namespace of its own. A policy that
				// reads it exists here so that the tri-state corpus covers
				// every declared namespace rather than only the ones the
				// source proposal's fixtures happened to use.
				ID: "C16", Authority: contract.AuthorityConstraint, Root: pdp.RootSystem,
				Scope: pdp.Scope{Organization: true}, Actions: pdp.ActionSelector{Any: true},
				Where:       pdp.Compare(PathAgentTrust, pdp.OpEq, "untrusted"),
				Description: "an agent whose attestation reports it untrusted is denied",
			},
			{
				ID: "S1-DENY", Authority: contract.AuthorityConstraint, Root: pdp.RootSystem,
				Scope: pdp.Scope{Organization: true}, Actions: pdp.ActionSelector{Any: true},
				Where:       pdp.Compare(PathSignalRisk, pdp.OpGe, 90),
				Description: "a risk score at or above 90 denies",
			},
			{
				ID: "S1-APPROVE", Authority: contract.AuthorityRequirement, Root: pdp.RootSystem, Mandatory: true,
				Scope: pdp.Scope{Organization: true}, Actions: pdp.ActionSelector{Any: true},
				Where:       pdp.Compare(PathSignalRisk, pdp.OpGe, 70),
				Obligations: []contract.Obligation{approvalObligation("S1-APPROVE", 1, "fraud-team")},
				Description: "a risk score at or above 70 requires a fraud team approval",
			},
		},
	}
}

// OrganizationDocument holds the permissions and the inspection policies.
func OrganizationDocument() *pdp.Document {
	return &pdp.Document{
		Root: pdp.RootOrganization, Version: 1, Attributes: attributeSchema(),
		Policies: []pdp.Policy{
			{
				ID: "G1", Authority: contract.AuthorityPermission, Root: pdp.RootOrganization,
				Scope:   pdp.Scope{Groups: []contract.ID{group("support-tier2")}},
				Actions: pdp.ActionSelector{Actions: []contract.ID{Actions["T1"].ID}},
				// The ownership term compares two TRUSTED attributes. The
				// caller chooses which ticket to ask about; it cannot choose
				// what is true about that ticket, and that asymmetry is what
				// makes an ownership check meaningful at all.
				Where: pdp.And(
					pdp.Compare(PathArgsAmount, pdp.OpLe, 500000).HandlingAbsence(pdp.AbsentIsUnknown),
					pdp.AttrEq(PathResourceOwner, PathPrincipalID),
				),
				Description: "tier two support may refund up to 500000 cents on their own tickets",
			},
			{
				ID: "G2", Authority: contract.AuthorityPermission, Root: pdp.RootOrganization,
				Scope:   pdp.Scope{Groups: []contract.ID{group("finance")}},
				Actions: pdp.ActionSelector{Actions: []contract.ID{Actions["T1"].ID}},
				Where:   pdp.Compare(PathArgsAmount, pdp.OpLe, 5000000).HandlingAbsence(pdp.AbsentIsUnknown),
				// Note the absence of an ownership term. A more permissive
				// permission from another group simply also applies: a
				// condition on when a permission applies is not a limit on the
				// people it applies to.
				Description: "finance may refund up to 5000000 cents",
			},
			{
				ID: "G3", Authority: contract.AuthorityPermission, Root: pdp.RootOrganization,
				Scope: pdp.Scope{Groups: []contract.ID{group("legal")}}, Where: pdp.True(),
				Actions:     pdp.ActionSelector{Actions: []contract.ID{Actions["T2"].ID}},
				Description: "legal may export contacts",
			},
			{
				ID: "G4", Authority: contract.AuthorityPermission, Root: pdp.RootOrganization,
				Scope: pdp.Scope{Groups: []contract.ID{group("all-staff")}}, Where: pdp.True(),
				Actions:     pdp.ActionSelector{Actions: []contract.ID{Actions["T4"].ID}},
				Description: "all staff may read a contact",
			},
			{
				ID: "G6", Authority: contract.AuthorityPermission, Root: pdp.RootOrganization,
				Scope:       pdp.Scope{Groups: []contract.ID{group("oncall-sre")}},
				Actions:     pdp.ActionSelector{RequiredTags: []string{"spend"}},
				Where:       pdp.Compare(PathArgsAmount, pdp.OpLe, 10000000).HandlingAbsence(pdp.AbsentIsUnknown),
				Description: "on-call site reliability may spend up to 10000000 cents",
			},
			{
				ID: "G8", Authority: contract.AuthorityPermission, Root: pdp.RootOrganization,
				Scope: pdp.Scope{Groups: []contract.ID{group("support-tier2")}}, Where: pdp.True(),
				Actions:     pdp.ActionSelector{Actions: []contract.ID{Actions["T5"].ID}},
				Description: "tier two support may transition an issue",
			},
			{
				ID: "G9", Authority: contract.AuthorityPermission, Root: pdp.RootOrganization,
				Scope: pdp.Scope{Groups: []contract.ID{group("all-staff")}}, Where: pdp.True(),
				Actions:     pdp.ActionSelector{Actions: []contract.ID{Actions["T6"].ID}},
				Description: "all staff may export a page",
			},
			{
				ID: "G10", Authority: contract.AuthorityPermission, Root: pdp.RootOrganization,
				Scope:   pdp.Scope{Principals: []contract.ID{Principals["agent-A"].ID}},
				Actions: pdp.ActionSelector{Actions: []contract.ID{Actions["T1"].ID}},
				Where:   pdp.Compare(PathArgsAmount, pdp.OpLe, 5000000).HandlingAbsence(pdp.AbsentIsUnknown),
				// Principal-scoped, because agent-A resolves in a realm with no
				// group concept. An empty closure costs it nothing.
				Description: "the support agent workload may refund up to 5000000 cents",
			},
			{
				ID: "D1", Authority: contract.AuthorityInspection, Root: pdp.RootOrganization,
				Scope: pdp.Scope{Organization: true}, Actions: pdp.ActionSelector{RequiredTags: []string{"spend"}},
				Where: pdp.AttrCompare(PathArgsAmount, pdp.OpGt, PathStateAnomaly),
				Obligations: []contract.Obligation{{
					Type:          contract.ObImmutableAudit,
					Params:        map[string]string{"level": "elevated", "channel": "fraud", "delivery": string(contract.DeliveryDurable)},
					SourcePolicy:  "D1",
					SchemaVersion: 1,
				}},
				Description: "an unusually large refund is recorded at elevated audit level",
			},
			{
				ID: "D2", Authority: contract.AuthorityInspection, Root: pdp.RootOrganization,
				Scope: pdp.Scope{Organization: true}, Actions: pdp.ActionSelector{Any: true},
				Where:       pdp.Compare(PathStateVelocity, pdp.OpGt, 5).HandlingAbsence(pdp.AbsentIsNoMatch),
				Description: "call velocity above five in ten minutes is evidence",
			},
			{
				ID: "D3", Authority: contract.AuthorityInspection, Root: pdp.RootOrganization,
				Scope: pdp.Scope{Organization: true}, Actions: pdp.ActionSelector{Any: true},
				Where:       pdp.Compare(PathEnvNewDevice, pdp.OpEq, true).HandlingAbsence(pdp.AbsentIsNoMatch),
				Description: "a previously unseen device is evidence",
			},
		},
	}
}

func ptr[T any](v T) *T { return &v }

// DefaultPEP advertises every obligation the fixture policies can attach,
// except field_tokenize, which no build in this world implements. That gap is
// deliberate: it is what makes "an unsupported mandatory obligation denies"
// executable rather than asserted.
func DefaultPEP() *contract.PEPProfile {
	return &contract.PEPProfile{
		ID: "fixture-pep",
		Capabilities: []contract.Capability{
			{Type: contract.ObApprovalChallenge, Version: 1},
			{Type: contract.ObFieldRedact, Version: 1},
			{Type: contract.ObFieldMask, Version: 1},
			{Type: contract.ObFieldHash, Version: 1},
			{Type: contract.ObFieldAnnotate, Version: 1},
			{Type: contract.ObFieldRemove, Version: 1},
			{Type: contract.ObQuotaReservation, Version: 1},
			{Type: contract.ObImmutableAudit, Version: 1},
			{Type: contract.ObNotification, Version: 1},
		},
	}
}

// actionSpend declares the spend risk class per fixture action.
//
// It is the ONE risk class the merged ActionEntry does not already carry;
// irreversible, data egress and privileged are read from the entry itself, so
// no class is declared twice. Deriving spend from the presence of the "spend"
// tag would be an inference, and the registry exists to refuse exactly that:
// a tag is a policy selector, not a statement about what the action does.
var actionSpend = map[string]registry.Declaration{
	"T1": registry.DeclarationYes,
	"T2": registry.DeclarationNo,
	"T3": registry.DeclarationNo,
	"T4": registry.DeclarationNo,
	"T5": registry.DeclarationNo,
	"T6": registry.DeclarationNo,
}

// actionResourceType binds a fixture action to the resource type it operates
// on. An action absent from this map declares none, which is what a tool with
// no resource mapping gets.
var actionResourceType = map[string]string{
	"T5": "Ticket",
	"T6": "Page",
}

// governedTags are the tags a policy in this world SELECTS on, and are
// therefore a policy channel. read_only and reversible are descriptive: no
// policy here reads them, so a change to one reaches no evaluator.
var governedTags = map[string]string{
	"spend":        "finance",
	"pii_egress":   "security",
	"pii":          "security",
	"irreversible": "security",
}

// Catalog builds the fixture world's registry catalog through the real
// registration path.
//
// It exists so the corpus runs against the registry the product uses rather
// than against a hand-assembled map that happens to look like one. EX-36's
// unregistered action, EX-37's argument schema, EX-43's resource depth and
// EX-46's realm binding are all registry facts, and a fixture that declared
// them directly would prove the cases against a second implementation.
func Catalog() (*registry.Catalog, error) {
	c := registry.NewCatalog(Now)
	seen := map[string]bool{}
	for _, a := range Actions {
		for _, tag := range a.Tags {
			if seen[tag] {
				continue
			}
			seen[tag] = true
			rec := registry.TagRecord{
				Tag: tag, Governance: registry.TagGovernanceUngoverned,
				Description: "fixture vocabulary entry " + tag,
			}
			if owner, governed := governedTags[tag]; governed {
				rec.Governance = registry.TagGovernanceGoverned
				rec.Owner = owner
			}
			if err := c.RegisterTag(rec); err != nil {
				return nil, err
			}
		}
	}
	for _, rt := range []registry.ResourceTypeRecord{
		{Type: "Ticket", Ancestors: []string{"project", "instance"}, Recursion: registry.RecursionNone,
			PayloadLeaves: []string{"response.status"}},
		{Type: "Page", Ancestors: []string{"space", "instance"}, Recursion: registry.RecursionBounded,
			MaxDepth: 32, PayloadLeaves: []string{"response.body"}},
	} {
		if err := c.RegisterResourceType(rt); err != nil {
			return nil, err
		}
	}
	for _, realm := range []string{RealmWorkspace, RealmGCP, RealmConnector} {
		if err := c.RegisterRealm(realm); err != nil {
			return nil, err
		}
	}
	for _, key := range sortedFixtureKeys(Actions) {
		a := Actions[key]
		spend, ok := actionSpend[key]
		if !ok {
			return nil, fmt.Errorf("conformance: fixture action %q declares no spend risk class", key)
		}
		if err := c.RegisterAction(registry.ActionRecord{
			ID:                 a.ID,
			Tags:               a.Tags,
			Posture:            registry.FailClosedPosture(),
			MaxDelegationDepth: a.MaxDelegationDepth,
			Arguments:          a.Arguments,
			RequiredArguments:  a.RequiredArguments,
			PayloadLeaves:      a.PayloadLeaves,
			ResourceType:       actionResourceType[key],
			Effects: registry.Effects{
				Irreversible: declare(a.Irreversible),
				DataEgress:   declare(a.DataEgress),
				Privileged:   declare(a.Privileged),
				Spend:        spend,
			},
		}); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func declare(b bool) registry.Declaration {
	if b {
		return registry.DeclarationYes
	}
	return registry.DeclarationNo
}

func sortedFixtureKeys(m map[string]pdp.ActionEntry) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Registry builds the action and realm registry the engine admits against.
//
// It is the registry catalog's projection rather than a map built here, so the
// registry a request is admitted against and the registry an operator governs
// are one object rendered twice. A catalog that fails a registration rule
// cannot be projected, so this panics rather than returning a partial registry:
// a fixture world with half a catalog would run the corpus against something
// nobody declared.
func Registry() *pdp.Registry {
	c, err := Catalog()
	if err != nil {
		panic(fmt.Sprintf("conformance: building the fixture catalog: %v", err))
	}
	r, err := c.PDPRegistry()
	if err != nil {
		panic(fmt.Sprintf("conformance: projecting the fixture catalog: %v", err))
	}
	return r
}

// World is one fully built decision environment.
type World struct {
	System   *pdp.Document
	Org      *pdp.Document
	Registry *pdp.Registry
	Engine   *pdp.Engine
	PEP      *contract.PEPProfile
	Compat   *pdp.CompatibilityProfile
	Bundles  []*pdp.Bundle
}

// WorldOption customises a world before its bundles are built.
type WorldOption func(*worldConfig)

type worldConfig struct {
	system     *pdp.Document
	org        *pdp.Document
	registry   *pdp.Registry
	pep        *contract.PEPProfile
	compat     *pdp.CompatibilityProfile
	breakGlass pdp.BreakGlassLookup
}

// WithSystemDocument replaces the system document. Mutation proofs use it.
func WithSystemDocument(d *pdp.Document) WorldOption {
	return func(c *worldConfig) { c.system = d }
}

// WithOrganizationDocument replaces the organization document.
func WithOrganizationDocument(d *pdp.Document) WorldOption {
	return func(c *worldConfig) { c.org = d }
}

// WithPEP replaces the advertised enforcement profile.
func WithPEP(p *contract.PEPProfile) WorldOption { return func(c *worldConfig) { c.pep = p } }

// WithCompatibility installs a temporary compatibility profile.
func WithCompatibility(p *pdp.CompatibilityProfile) WorldOption {
	return func(c *worldConfig) { c.compat = p }
}

// WithBreakGlass installs an active break-glass lookup.
func WithBreakGlass(f pdp.BreakGlassLookup) WorldOption {
	return func(c *worldConfig) { c.breakGlass = f }
}

// WithRegistry replaces the action registry.
func WithRegistry(r *pdp.Registry) WorldOption { return func(c *worldConfig) { c.registry = r } }

// NewWorld builds, signs, verifies and activates the fixture bundles and
// returns a ready engine.
func NewWorld(ctx context.Context, opts ...WorldOption) (*World, error) {
	cfg := worldConfig{
		system: SystemDocument(), org: OrganizationDocument(),
		registry: Registry(), pep: DefaultPEP(),
	}
	for _, o := range opts {
		o(&cfg)
	}
	ts := pdp.NewTrustStore()
	var bundles []*pdp.Bundle
	for _, d := range []*pdp.Document{cfg.system, cfg.org} {
		b, err := pdp.BuildBundle(d)
		if err != nil {
			return nil, fmt.Errorf("conformance: building the %s bundle: %w", d.Root, err)
		}
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			return nil, err
		}
		keyID := string(d.Root) + "-key"
		if err := b.Sign(keyID, priv); err != nil {
			return nil, err
		}
		ts.Authorize(d.Root, keyID, pub)
		bundles = append(bundles, b)
	}
	engine, err := pdp.NewEngine(ctx, pdp.EngineConfig{
		Bundles:     bundles,
		Documents:   []*pdp.Document{cfg.system, cfg.org},
		TrustStore:  ts,
		ApprovalTTL: 15 * time.Minute,
		PEP:         cfg.pep,
		Registry:    cfg.registry,
		Compat:      cfg.compat,
		BreakGlass:  cfg.breakGlass,
	})
	if err != nil {
		return nil, err
	}
	return &World{
		System: cfg.system, Org: cfg.org, Registry: cfg.registry,
		Engine: engine, PEP: cfg.pep, Compat: cfg.compat, Bundles: bundles,
	}, nil
}
