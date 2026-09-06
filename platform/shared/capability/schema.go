// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package capability

import "sort"

// SchemaVersion is the registry schema version. It is stated in the registry
// file itself and checked on load: a reader compiled against one schema and
// handed a file written for another must refuse rather than silently read
// fields that have moved.
//
// Bump the MINOR component for an additive field; bump MAJOR when a field
// changes meaning or is removed, and update Loader compatibility below.
const SchemaVersion = "1.0"

// Edition is the minimum edition a deployment needs for a capability to be
// available. This is the ADR-066 vocabulary (the enforcement response quotes
// `minimum_edition: "enterprise"`), which is deliberately COARSER than the
// licence tier vocabulary in platform/agent/license: Professional and
// Enterprise Plus both satisfy EditionEnterprise, and there is no edition
// corresponding to the SaaS Plugin Free/Pro/Premium tiers, which are a
// per-tenant axis on the Community SaaS deployment rather than an edition.
//
// A capability whose edition cannot be stated is NOT representable. There is
// deliberately no "unknown" or "tbd" member: ADR-066 requires that an
// unclassified capability fail rather than encode its own indecision.
type Edition string

const (
	// EditionCommunity means every build has it, licensed or not.
	EditionCommunity Edition = "community"
	// EditionEvaluation means a signed licence of Evaluation tier or higher
	// is required. Per ADR-066 decision 6 an Evaluation deployment may reach
	// higher limits and previews, but never an enterprise_implementation.
	EditionEvaluation Edition = "evaluation"
	// EditionEnterprise means a paid tier is required (Professional,
	// Enterprise or Enterprise Plus in licence-tier terms).
	EditionEnterprise Edition = "enterprise"
)

// Editions returns the vocabulary in increasing order of entitlement.
func Editions() []Edition { return []Edition{EditionCommunity, EditionEvaluation, EditionEnterprise} }

// rank orders the vocabulary. It is unexported and only ever reached through
// ValidEdition, so an unrecognised value cannot silently rank as community —
// the map lookup's zero value would otherwise make every unknown edition the
// most permissive one.
var editionRank = map[Edition]int{EditionCommunity: 0, EditionEvaluation: 1, EditionEnterprise: 2}

// ValidEdition reports whether e is a member of the vocabulary.
func ValidEdition(e Edition) bool { _, ok := editionRank[e]; return ok }

// Classification is the ADR-066 decision 2 source classification: where the
// implementation is allowed to live, which is a stronger statement than which
// edition may run it.
type Classification string

const (
	// ClassCommunityCore: complete implementation may sync publicly.
	ClassCommunityCore Classification = "community_core"
	// ClassEvaluationPreview: implementation may sync publicly and be softly
	// gated at runtime.
	ClassEvaluationPreview Classification = "evaluation_preview"
	// ClassEnterpriseProtocol: Community may receive types, schemas or an
	// unavailable stub, but not the operational implementation.
	ClassEnterpriseProtocol Classification = "enterprise_protocol"
	// ClassEnterpriseImplementation: source exists only under ee/ or an
	// enterprise build constraint.
	ClassEnterpriseImplementation Classification = "enterprise_implementation"
)

// Classifications returns the vocabulary.
func Classifications() []Classification {
	return []Classification{
		ClassCommunityCore, ClassEvaluationPreview,
		ClassEnterpriseProtocol, ClassEnterpriseImplementation,
	}
}

var validClassification = func() map[Classification]bool {
	m := map[Classification]bool{}
	for _, c := range Classifications() {
		m[c] = true
	}
	return m
}()

// ValidClassification reports whether c is a member of the vocabulary.
func ValidClassification(c Classification) bool { return validClassification[c] }

// MinimumEditionFor returns the least edition that can run a capability of
// this classification. It is the consistency rule the validator applies
// between the two axes: an implementation that only exists under an enterprise
// build constraint cannot be available to a Community deployment, because in a
// Community build it is not in the binary at all.
//
// The reverse is NOT a rule and must not be added: a community_core
// classification says the SOURCE may sync publicly, and says nothing about the
// licence gate the shipped code applies. Evidence export is community_core
// source under an Evaluation runtime gate, and that is a legitimate pair.
func MinimumEditionFor(c Classification) Edition {
	switch c {
	case ClassEnterpriseImplementation, ClassEnterpriseProtocol:
		return EditionEnterprise
	case ClassCommunityCore, ClassEvaluationPreview:
		return EditionCommunity
	default:
		// Unreachable through the validator, which rejects an unknown
		// classification before this is called. Returning the most
		// restrictive member means a future member added to the vocabulary
		// without a rule here fails closed rather than admitting everything.
		return EditionEnterprise
	}
}

// BuildTag records how a capability's implementation is selected at compile
// time.
type BuildTag string

const (
	// TagNone: the implementation carries no build constraint and compiles
	// into both editions.
	TagNone BuildTag = "none"
	// TagEnterprise: at least one implementation file carries
	// `//go:build enterprise`, or lives under ee/, which the community mirror
	// excludes wholesale.
	TagEnterprise BuildTag = "enterprise"
	// TagSplit: the capability has BOTH a community and an enterprise file for
	// the same symbol (the ADR-029 build-tag replacement pattern), so both
	// editions have an implementation and they differ.
	TagSplit BuildTag = "split"
)

var validBuildTag = map[BuildTag]bool{TagNone: true, TagEnterprise: true, TagSplit: true}

// Sync records the capability's disposition towards the community mirror,
// which .github/workflows/sync-community-repo.yml produces.
type Sync string

const (
	// SyncMirrored: the implementation reaches the public mirror.
	SyncMirrored Sync = "mirrored"
	// SyncExcluded: the implementation does not reach the mirror, either by a
	// path exclusion (ee/, migrations/enterprise/, ...) or by the build-tag
	// strip that removes the enterprise half of every tag pair.
	SyncExcluded Sync = "excluded"
	// SyncStub: the mirror receives a compiling stub or an unavailable-error
	// implementation in place of the operational one (ADR-029 extension
	// hooks). The types and the symbol are public; the behaviour is not.
	SyncStub Sync = "stub"
)

var validSync = map[Sync]bool{SyncMirrored: true, SyncExcluded: true, SyncStub: true}

// Availability is how much of a capability an edition gets.
type Availability string

const (
	// AvailFull: the edition has the capability with no capability-specific cap.
	AvailFull Availability = "full"
	// AvailLimited: the edition has the capability subject to a numeric cap or
	// a reduced mode. The cap must be named in LicenseGate or Notes.
	AvailLimited Availability = "limited"
	// AvailNone: the edition does not have the capability.
	AvailNone Availability = "none"
)

var availabilityWeight = map[Availability]float64{AvailFull: 1, AvailLimited: 0.5, AvailNone: 0}

// Weight returns the score contribution of an availability, and whether the
// availability is a member of the vocabulary. Callers MUST check the second
// return: a bare map read would score an unrecognised value as 0, which is
// indistinguishable from an honest "not available" and would quietly deflate
// every band this registry exists to derive.
func (a Availability) Weight() (float64, bool) { w, ok := availabilityWeight[a]; return w, ok }

// Basis records whether a scored figure was read off the tree or decided by a
// human. The census prints it beside every number, so a reader can tell a
// measurement from a judgement without leaving the page.
type Basis string

const (
	// BasisMeasured: the figure follows from something this repository
	// enforces — a build tag, an `ee/` path, a licence-limit literal — and the
	// validator checks it against that source.
	BasisMeasured Basis = "MEASURED"
	// BasisChosen: the figure is a human judgement. Reason is mandatory.
	BasisChosen Basis = "CHOSEN"
	// BasisUnscorable: the capability cannot be scored honestly. Reason is
	// mandatory and the capability is excluded from the bands rather than
	// being given a made-up number.
	BasisUnscorable Basis = "UNSCORABLE"
)

var validBasis = map[Basis]bool{BasisMeasured: true, BasisChosen: true, BasisUnscorable: true}

// Health is a capability's projection onto the /health capability list.
//
// A capability with no Health block is not advertised, and HealthAbsentReason
// must then say why — ADR-066's "absent is a recorded decision, not a
// default". The distinction matters because /health is a DISCOVERY surface: an
// SDK reads an omission as "this platform does not support it".
type Health struct {
	// Name is the wire name. It is the stable identifier clients branch on,
	// and is deliberately separate from the registry ID: several /health names
	// predate this registry and cannot be renamed without breaking clients.
	Name string `json:"name"`
	// Since is the platform version that first advertised it.
	Since string `json:"since"`
	// Description is the wire description, served verbatim.
	Description string `json:"description"`
	// DescriptionOverrides lets one plane serve a different description from
	// the other, keyed by plane name.
	//
	// It exists because exactly one entry needs it: on main the two planes
	// serve byte-identical text for all 29 shared names except
	// platform_identity_discovery, whose orchestrator copy carries an extra
	// paragraph about serving both planes from one implementation. Converging
	// them would be an improvement to one plane's wire, and this PR is a
	// census: it reproduces what is served rather than deciding what should
	// be. The census records the divergence as a row.
	DescriptionOverrides map[string]string `json:"description_overrides,omitempty"`
	// Planes are the /health planes that advertise it: "agent", "orchestrator",
	// or both. The orchestrator list is a deliberate subset — it advertises
	// only what that plane serves.
	Planes []string `json:"planes"`
	// Order is the position within the served list. The list is a wire
	// artifact whose order clients have observed since 1.0.0; an explicit
	// order keeps the registry free to be sorted by ID without reordering the
	// response.
	Order int `json:"order"`
}

// Score is one capability's availability in each edition, with the basis for
// each figure.
type Score struct {
	Community  Availability `json:"community"`
	Evaluation Availability `json:"evaluation"`
	Enterprise Availability `json:"enterprise"`
	Basis      Basis        `json:"basis"`
	// Reason is mandatory unless Basis is MEASURED. It says what the judgement
	// was and why, so the next reader argues with the reason rather than
	// re-deriving the number.
	Reason string `json:"reason,omitempty"`
}

// Entry is one capability.
//
// Every field is populated for every entry; the omitempty tags exist so the
// checked-in file stays readable, not so a field may be skipped. The validator
// requires each one that is not explicitly optional, and the optional ones are
// each optional for a stated reason recorded on the field.
type Entry struct {
	// ID is the stable capability identifier, `family.name` in lower snake
	// case. It is what ADR-066's enforcement response quotes and what an
	// upgrade reason code is keyed on, so it must not change once shipped.
	ID string `json:"id"`
	// Title is the human-readable name used in the generated census.
	Title string `json:"title"`
	// Family groups capabilities for band scoring. It is the first segment of
	// the ID and the validator checks that.
	Family string `json:"family"`
	// Summary is one sentence on what the capability is.
	Summary string `json:"summary"`

	MinimumEdition Edition        `json:"minimum_edition"`
	Classification Classification `json:"source_classification"`
	BuildTag       BuildTag       `json:"build_tag"`
	Sync           Sync           `json:"sync"`

	// Implementation are repo-relative paths or directories holding the
	// backing code. At least one is required; the derivation checks that the
	// enterprise-tagged ones agree with BuildTag.
	Implementation []string `json:"implementation"`
	// Owner is the repo-relative path of the test that owns this capability's
	// behaviour. ADR-066 conformance item 10 wants every enterprise capability
	// EXERCISED by a test rather than merely compiled, and this names the one
	// to look at. Required; the validator checks the file exists.
	Owner string `json:"owner"`

	// Routes are the HTTP path patterns this capability registers, in the
	// gorilla/mux spelling used at the call site. A prefix entry covers the
	// paths beneath it. May be empty for a capability with no route (a
	// coordinator, a store, an operator control), in which case the derivation
	// simply has nothing to attribute to it.
	Routes []string `json:"routes,omitempty"`
	// Planes are the binaries that serve those routes: "agent",
	// "orchestrator", or a named separate service. Required when Routes is
	// non-empty.
	Planes []string `json:"planes,omitempty"`

	// LicenseGate names the runtime entitlement the shipped code applies:
	// TierLimits field names, or a gate function. Empty means the capability
	// applies no runtime licence check of its own, which is itself a fact the
	// census reports rather than an omission.
	LicenseGate []string `json:"license_gate,omitempty"`
	// Migrations are the migration directories/numbers the capability's state
	// needs. Empty means stateless or riding on shared tables.
	Migrations []string `json:"migrations,omitempty"`
	// Portal names the customer-portal control that exposes it, or is empty
	// when there is none.
	Portal string `json:"portal,omitempty"`
	// Docs is the public documentation path, or empty when undocumented
	// publicly. Undocumented is a legitimate state for an internal control and
	// the census reports it as such.
	Docs string `json:"docs,omitempty"`
	// Matrix are the headings of COMMUNITY_ENTERPRISE_FEATURE_MATRIX.md that
	// cover this capability, empty when the matrix is silent about it.
	//
	// It is a LIST because the matrix's sections are not a partition: connector
	// registration and connector routing are two sections describing one
	// capability, and forcing a single heading would leave the other
	// unaccounted for and push it into the out-of-scope list, where it would
	// read as "the registry does not model this".
	Matrix []string `json:"matrix,omitempty"`

	Health *Health `json:"health,omitempty"`
	// HealthAbsentReason is required when Health is nil, and forbidden when it
	// is not. It is the recorded decision that this capability is deliberately
	// not advertised on /health.
	HealthAbsentReason string `json:"health_absent_reason,omitempty"`
	// HealthGap distinguishes the two very different things a
	// HealthAbsentReason can say. False (the default) means "settled": this
	// capability should not be advertised and here is why. True means
	// "unsettled": it arguably should be, and the reason says what stopped
	// this PR adding it.
	//
	// It is a FIELD rather than a marker phrase inside the reason on purpose. A
	// census that found its own gaps by grepping its own prose for "GAP" is
	// satisfied by the word appearing anywhere, including in a sentence
	// explaining that something is NOT a gap.
	HealthGap bool `json:"health_gap,omitempty"`

	// MatrixDisagreement CLASSIFIES a place where
	// COMMUNITY_ENTERPRISE_FEATURE_MATRIX.md and the tree say different things.
	// It is a member of a closed vocabulary, not prose.
	//
	// The narrative — which row, which mechanism, which of the two is wrong —
	// lives in technical-docs/capability-census-disagreements.tsv, keyed by
	// capability id, and the census renders the two together. THE SPLIT IS
	// DELIBERATE AND IT IS NOT A STYLE CHOICE. This file reaches the community
	// mirror, because the community build projects its own /health from it;
	// technical-docs/ does not. A class such as `matrix_stricter_than_tree` is
	// structural and already implied by the row beside it (an entry with
	// minimum_edition `enterprise`, build_tag `none` and sync `mirrored` says
	// as much). A sentence spelling out which Enterprise-marked feature a
	// Community build can in fact serve is a different artifact, and whether
	// that publishes is the operator's call rather than a side effect of where
	// this file happens to sync. Conservative default; reversible either way;
	// the question is on #3590.
	//
	// The census records a disagreement and does not resolve it either way:
	// editing the matrix to match a reading of the code would launder exactly
	// the discrepancy #3590 exists to surface, and changing the code would be
	// an entitlement change, which #3590's acceptance criterion forbids.
	MatrixDisagreement Disagreement `json:"matrix_disagreement,omitempty"`

	Score Score `json:"score"`
	// Notes carries anything a reader needs that no other field holds,
	// including a recorded disagreement between the code and the matrix.
	Notes string `json:"notes,omitempty"`
}

// RouteExemption records a route-registration site the derivation finds but
// cannot attribute to a capability, together with the reason it is allowed.
//
// It exists so that "the scanner could not resolve this" is a declared,
// reviewed fact with an owner rather than a silent hole. The validator fails on
// an exemption that no longer matches anything, so a stale one cannot linger.
type RouteExemption struct {
	// Pattern is the route pattern, or the unresolved source expression when
	// the call site does not name a constant the scanner can follow.
	Pattern string `json:"pattern"`
	Reason  string `json:"reason"`
}

// Disagreement classifies how the living feature matrix and the tree differ.
type Disagreement string

const (
	// DisagreeMatrixStricter: the matrix marks a capability as needing a
	// higher edition than anything in the tree enforces.
	DisagreeMatrixStricter Disagreement = "matrix_stricter_than_tree"
	// DisagreeWrongMechanism: the matrix reaches the right conclusion by
	// naming a mechanism that is not the one holding it.
	DisagreeWrongMechanism Disagreement = "matrix_cites_wrong_mechanism"
	// DisagreeStaleCitation: the matrix cites a file, a line or a value that
	// has moved.
	DisagreeStaleCitation Disagreement = "matrix_stale_citation"
	// DisagreeMatrixInconsistent: the matrix disagrees with itself, and the
	// tree settles which half is right.
	DisagreeMatrixInconsistent Disagreement = "matrix_internally_inconsistent"
	// DisagreeADRTarget: ADR-066's classification table states a TARGET the
	// tree does not yet implement, or implements in the other direction.
	DisagreeADRTarget Disagreement = "adr_target_differs_from_tree"
)

// Disagreements returns the vocabulary.
func Disagreements() []Disagreement {
	return []Disagreement{
		DisagreeMatrixStricter, DisagreeWrongMechanism, DisagreeStaleCitation,
		DisagreeMatrixInconsistent, DisagreeADRTarget,
	}
}

var validDisagreement = func() map[Disagreement]bool {
	m := map[Disagreement]bool{}
	for _, d := range Disagreements() {
		m[d] = true
	}
	return m
}()

// ValidDisagreement reports whether d is a member of the vocabulary.
func ValidDisagreement(d Disagreement) bool { return validDisagreement[d] }

// MatrixSection is one heading of the living feature matrix that the registry
// deliberately does not model.
type MatrixSection struct {
	Heading string `json:"heading"`
	Reason  string `json:"reason"`
}

// Registry is the whole file.
type Registry struct {
	// Schema is the schema version this file was written for.
	Schema string `json:"schema"`
	// Platform is the platform version the census was taken against.
	Platform string `json:"platform_version"`
	// Generated is the ISO date the census was taken.
	Generated string `json:"generated"`
	// Entries are the capabilities, sorted by ID.
	Entries []Entry `json:"capabilities"`
	// RouteExemptions are the declared holes in the route derivation.
	RouteExemptions []RouteExemption `json:"route_exemptions"`
	// MatrixSectionsOutOfScope are the headings of
	// COMMUNITY_ENTERPRISE_FEATURE_MATRIX.md that no capability claims, each
	// with the reason it is not a capability.
	//
	// The reconciliation is two-sided on purpose. Checking only that every
	// entry's `matrix` heading exists would accept a registry that ignored half
	// the matrix; checking only the reverse would accept one that invented
	// headings. A section here is a declared, reasoned exclusion — and the
	// reconciliation fails if a heading listed here comes back into scope, or
	// if it disappears from the matrix entirely.
	MatrixSectionsOutOfScope []MatrixSection `json:"matrix_sections_out_of_scope"`
	// ScanRoots are the repo-relative directories the route and build-tag
	// derivation walks. Declaring them in the data rather than hard-coding
	// them in the test means the scope of the census is reviewable in the
	// same diff as the census.
	ScanRoots []string `json:"scan_roots"`
}

// ByID returns the entry with the given ID, or nil.
func (r *Registry) ByID(id string) *Entry {
	for i := range r.Entries {
		if r.Entries[i].ID == id {
			return &r.Entries[i]
		}
	}
	return nil
}

// Families returns the distinct family names, sorted.
func (r *Registry) Families() []string {
	seen := map[string]bool{}
	for _, e := range r.Entries {
		seen[e.Family] = true
	}
	out := make([]string, 0, len(seen))
	for f := range seen {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}
