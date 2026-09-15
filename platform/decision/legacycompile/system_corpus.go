// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package legacycompile

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/registry"
)

// THE SYSTEM CORPUS (#3884)
//
// The rest of this package is a SHADOW compiler: it reproduces the legacy
// engines faithfully, per plane, defects included, so a diff harness can
// compare two answers to the same request. This file is the other thing the
// same mapping is needed for - the MIGRATION - and the difference between the
// two is the substance of what follows.
//
// # WHY THE CORPUS IS PLANE-INDEPENDENT AND THE SHADOW COMPILATION IS NOT
//
// ADR-065's problem table names the split itself as the defect: "policy type
// is determined by execution location, not semantics". `PolicyIDFor` embeds
// the plane, so a shadow compilation of one legacy row produces up to nine
// policies, one per plane, and carrying that into the target model would
// migrate the defect rather than the corpus.
//
// So the corpus emits ONE policy per row. Where the legacy engines resolve
// different actions on different planes - and forty rows do - the corpus
// resolves once, and every one of those rows is enumerated as a declared
// divergence rather than averaged away. That enumeration is a product of this
// file, not a side effect of it: `Corpus.Divergences` is the row-by-row answer
// to "where does the new model decide differently, and why".
//
// # WHAT IS DELIBERATELY NOT REBUILT HERE
//
// The legacy action to ADR-065 authority mapping is `ApplyLegacyAction`, which
// `policyFor` also calls. A second spelling of it would be the migration's
// substance written down twice.

// CorpusPolicyIDFor renders the plane-independent policy identifier for one
// migrated legacy row.
//
// It is deliberately NOT `PolicyIDFor`, whose format embeds the plane and the
// phase. A corpus policy identifier that carried a plane would be a policy
// identity that depends on where it is enforced, which is the thing ADR-065
// exists to remove.
func CorpusPolicyIDFor(table, policyID string) string {
	return fmt.Sprintf("corpus:%s:%s", table, SanitizePolicyID(policyID))
}

// CorpusVariantIDFor renders the identifier of one per-scope variant of a split
// control (#4046). A shipped row whose legacy engines resolve a different action
// depending on the enforcement scope ships as one policy per action, and each
// variant carries the control's identifier followed by that action. The
// identifier says WHAT the variant decides and never WHERE: which scopes each
// variant binds on is the corpus's scope bindings, so the ADR-065 rule that
// execution location is not policy identity holds for a variant too.
func CorpusVariantIDFor(table, policyID, action string) string {
	return CorpusPolicyIDFor(table, policyID) + ":" + action
}

// CorpusControlOf reads a corpus policy identifier back to its control - the
// identifier with any per-scope variant action and any "#n" multi-policy suffix
// removed - and the variant's action, which is empty for a control the corpus
// did not split. ok is false for an identifier that is not a corpus identifier.
//
// It is unambiguous because an encoded row identifier cannot carry the
// separator: SanitizePolicyID encodes every character outside [A-Za-z0-9], a
// colon included, so a third segment can only ever be a variant action.
func CorpusControlOf(id string) (control, action string, ok bool) {
	rest, isCorpus := strings.CutPrefix(id, "corpus:")
	if !isCorpus {
		return "", "", false
	}
	rest, _, _ = strings.Cut(rest, "#")
	parts := strings.Split(rest, ":")
	for _, part := range parts {
		if part == "" {
			return "", "", false
		}
	}
	switch len(parts) {
	case 2:
		return "corpus:" + parts[0] + ":" + parts[1], "", true
	case 3:
		return "corpus:" + parts[0] + ":" + parts[1], parts[2], true
	}
	return "", "", false
}

// DivergenceKind classifies a way the corpus decides differently from the
// legacy engines.
type DivergenceKind string

const (
	// DivergencePlaneActionCollapsed is a row whose legacy engines resolve
	// more than one action across the planes it runs on. The corpus resolves
	// one, and this names every action that was in play and which one won.
	DivergencePlaneActionCollapsed DivergenceKind = "plane_action_collapsed"
	// DivergenceRowNotRepresented is a row that contributes no corpus policy.
	// It is recorded rather than dropped: a row that vanishes from a migration
	// is indistinguishable from a row nobody had.
	DivergenceRowNotRepresented DivergenceKind = "row_not_represented"
	// DivergenceRootDisagreesWithTier is a row whose compiled authority root
	// and whose census tier do not agree about whether it is the platform's
	// own. The tier decides, because the tier is what a customer can edit.
	DivergenceRootDisagreesWithTier DivergenceKind = "root_disagrees_with_tier"
	// DivergenceActionUnrankable is a resolved action the corpus collapse has
	// no rank for. It is a refusal rather than a default, because a default
	// here would silently order an unranked action below `log`.
	DivergenceActionUnrankable DivergenceKind = "action_unrankable"
	// DivergenceTierNotRecorded is a row for which no captured row carried a
	// tier. It is deliberately NOT DivergenceRootDisagreesWithTier: nothing
	// disagreed, because nothing was found to disagree with.
	DivergenceTierNotRecorded DivergenceKind = "tier_not_recorded"
	// DivergenceDetectorRanBareOnSomePlanes is a row whose detector is
	// algorithmic and whose implementation did not gate on every plane the row
	// ran on, stated per row rather than inherited: the migrated policy reads
	// ONE detector verdict, and on those planes the legacy answer was the bare
	// pattern's.
	//
	// The direction is OVER-detection (#3963). A validator can only remove a
	// match, so an ungated plane reports a superset - on `proxy_tier` before
	// #3963 any sixteen-digit string was a credit card. The row fired MORE often
	// there, not less.
	DivergenceDetectorRanBareOnSomePlanes DivergenceKind = "detector_ran_bare_on_some_planes"
	// DivergenceLegacyDefectReproduced is a row whose compilation carried a
	// known legacy defect forward rather than repairing it - Status
	// preserved_defect, the census's own disposition. The corpus imports it AS
	// the defect, and says so per row with the compiler's defect reasons
	// verbatim: a repair made here would make the shadow comparison disagree
	// with the legacy engine for a reason nobody could name, and a defect
	// imported without saying so is the same repair seen from the other side.
	DivergenceLegacyDefectReproduced DivergenceKind = "legacy_defect_reproduced"
	// DivergenceRedactionBoundByDischarge is an organization-template row
	// whose compiled redaction is bound per scope by whether the scope can
	// carry a redaction out (#4131): redact where it can, warn where a
	// mandatory redaction would refuse every request it matches. See
	// template_discharge.go.
	DivergenceRedactionBoundByDischarge DivergenceKind = "redaction_bound_by_discharge"
	// DivergenceDynamicRedactionShipsAsWarn is a dynamic_policies row whose
	// compiled redaction binds on scopes none of which can carry a redaction
	// out, so it ships as the dynamic substrate's warn under the same id and
	// masks nothing (#4254). See dynamic_discharge.go.
	DivergenceDynamicRedactionShipsAsWarn DivergenceKind = "dynamic_redaction_ships_as_warn"
)

// Divergence is one row-level statement that the corpus decides differently
// from the legacy engines, or does not decide at all.
type Divergence struct {
	PolicyID string         `json:"policy_id"`
	Table    string         `json:"table"`
	Kind     DivergenceKind `json:"kind"`
	// LegacyActions is every action the legacy engines resolve for this row,
	// across planes, in a stable order.
	LegacyActions []string `json:"legacy_actions,omitempty"`
	// Chosen is the action the corpus resolved, empty when none was.
	Chosen string `json:"chosen,omitempty"`
	// Fields are the payload fields a dynamic redaction named before it
	// shipped as a warn (DivergenceDynamicRedactionShipsAsWarn), sorted. The
	// deployment vocabulary keeps them as payload leaves, so shipping the
	// redaction as a warn narrows no organization's authoring surface (#4254).
	Fields []string `json:"fields,omitempty"`
	// FromRoot and ToRoot are the authority roots a root-change divergence
	// moves between, and they exist because the KIND alone does not say which
	// way.
	//
	// `DivergenceRootDisagreesWithTier` fires whenever the compiled root and
	// the tier root differ, in EITHER direction. Every row moves org-ward
	// today, so a test asserting "every root change is in the organization
	// template" passed on a coincidence; a correct system-ward move would have
	// made it red with a message blaming the wrong thing.
	FromRoot string `json:"from_root,omitempty"`
	ToRoot   string `json:"to_root,omitempty"`
	// CompilerReasons are the shadow compiler's own per-row reason codes and
	// details, carried verbatim.
	//
	// WITHOUT THEM THE ARTIFACT TOLD AN AUDITOR A GENERIC STORY ABOUT THE ONE
	// ROW THAT NEEDED THE SPECIFIC ONE. `sensitive_data_control` is an
	// ENABLED dynamic row redacting salary, SSN and medical-record fields; it
	// produces no corpus policy, and the compiled record says exactly why -
	// `legacy_scan_drop` (#3397), "the row is dropped by the dynamic refresh's
	// scan and is enforced nowhere". The divergence had no field for that, so
	// the reason was discarded and replaced with a sentence about disabled
	// integration seeds that is false of this row in both of its halves.
	CompilerReasons []string `json:"compiler_reasons,omitempty"`
	Detail          string   `json:"detail"`
}

// Corpus is the migrated shipped corpus: the platform's own controls as typed
// documents, plus the enumeration of every place the migration is not exact.
type Corpus struct {
	// System is the platform's own document. Every policy in it comes from a
	// row a customer cannot edit.
	System *pdp.Document `json:"system"`
	// OrganizationTemplate is the seed a deployment instantiates per
	// organization.
	//
	// It exists because the corpus splits on EDITABILITY rather than on
	// convenience: 31 of the 101 shipped static rows are tenant-tier, which
	// means a customer may change them today. A build-invariant artifact
	// cannot hold a row a customer edits without taking that right away, and
	// an artifact that varied per deployment would give "the platform's
	// corpus" one digest per deployment, which destroys the only property the
	// digest exists to provide. Recorded on #3786 as the answer to operator
	// question 1.
	OrganizationTemplate *pdp.Document `json:"organization_template"`
	// ScopeBindings names the enforcement scopes a shipped control binds on,
	// for a control whose legacy action differs by scope (#4046, #4016): each
	// of its actions is bound to the scopes whose legacy engines resolve it,
	// and activation.RestrictToScope keeps a bound policy on those scopes only.
	// A control with no entry binds wherever the restriction's other arms keep
	// it. Always present, and empty when no control is split, so a dropped
	// section cannot pass for "none split" (pdp.SystemCorpusScopeBindings).
	ScopeBindings map[string][]string `json:"scope_bindings"`
	// Divergences is the row-by-row enumeration.
	Divergences []Divergence `json:"divergences"`
}

// corpusRestrictiveness ranks a legacy action for the corpus collapse.
//
// IT IS TOTAL OVER EVERY DECLARED LEGACY ACTION, AND THAT IS THE ONE PLACE
// THIS FILE DELIBERATELY DOES NOT MIRROR THE ENGINE.
//
// `shadow.restrictiveness` mirrors `agent.ActionRestrictiveness` exactly,
// including its `default: return 0` - so `deny`, `log_only`, `alert`, `route`
// and `allow`, all five declared legacy actions the engine does not rank, sit
// at zero and therefore BELOW `log`. Mirroring that is
// right for a shadow model, whose job is to reproduce the engine. It is wrong
// for a migration: a corpus that collapsed `deny` and `log` to `log` would
// ship a weaker control than the row it came from, and nothing in the output
// would say so.
//
// The second return value says whether the rank is DERIVED from the engine's
// own ordering or DECLARED here. The five actions the engine ranks keep their
// relative order untouched; the four it does not are placed by this file, and
// a collapse decided by one of them says so in its divergence rather than
// presenting a judgement as a measurement.
//
// The placements, with their reasons:
//
//	deny      = block      the same outcome under the spelling migration 070
//	                       widened policy_overrides to
//	log_only  = log        likewise
//	route     < redact     a routing restriction narrows where a request may
//	           > warn      go without changing what it contains
//	alert     < warn       a dynamic-side notification; both notify, and warn
//	           > log       is the one the enforcing engines return as an action
//
// A DYNAMIC ROW'S RESOLVED ACTION IS A COMMA-JOINED LIST, NOT ONE ACTION.
//
// `dynamic.go` joins every applied action into one string and puts the same
// string on every plane, because a dynamic row applies ALL of its actions
// together rather than resolving one. So this ranks the list by its strongest
// member: for a static row, whose resolved action is a single value, that is
// the same computation. Discovered by measurement rather than by reading -
// four dynamic rows came back unrankable against a real capture, and the
// values were "redact,log" and "alert,log".
func corpusRestrictiveness(a string) (rank int, engineRanked bool, ok bool) {
	parts := strings.Split(a, ",")
	if len(parts) > 1 {
		best, allEngine := -1, true
		for _, one := range parts {
			r, eng, k := corpusRestrictiveness(strings.TrimSpace(one))
			if !k {
				return 0, false, false
			}
			if !eng {
				allEngine = false
			}
			if r > best {
				best = r
			}
		}
		return best, allEngine, true
	}
	switch LegacyAction(a) {
	case ActionBlock:
		return 7, true, true
	case ActionDeny:
		return 7, false, true
	case ActionRequireApproval:
		return 6, true, true
	case ActionRedact:
		return 5, true, true
	case ActionRoute:
		return 4, false, true
	case ActionWarn:
		return 3, true, true
	case ActionAlert:
		return 2, false, true
	case ActionLog:
		return 1, true, true
	case ActionLogOnly:
		return 1, false, true
	case ActionAllow:
		return 0, false, true
	default:
		return 0, false, false
	}
}

// CorpusOptions carries what the corpus build needs that the report does not.
type CorpusOptions struct {
	// ContentTarget is the redaction target for a `redact` row, since
	// static_policies stores no field path for one.
	ContentTarget string
	// Rows are the captured rows the report was compiled from.
	//
	// They are here for ONE fact the compiled report does not carry: the row's
	// TIER, which is what decides whether a control is the platform's own or
	// the customer's, and therefore which document it lands in.
	//
	// The first version of this file read the tier from the detector census
	// instead. That is wrong in a way a reader would not catch: the census
	// covers `static_policies` ONLY, so every dynamic row missed the lookup
	// and defaulted to the organization root - including five `tier='system'`
	// media controls, which would have shipped as customer-editable seeds.
	// Measured against a real capture, not reasoned about.
	Rows []RawRow
	// Census is the shipped detector census. It is a CROSS-CHECK rather than
	// an input: the corpus must represent every censused static row as its
	// enabled state says (CheckCorpusRepresentsTheCensus), and a census row with
	// no captured row is a control the capture did not contain. It is also what
	// the detector registry is seeded from, so the corpus can state per row
	// whether the detector it reads gated on every plane the row ran on.
	//
	// SEEDED FROM THIS FIELD, NOT FROM THE EMBEDDED CENSUS. The build used to
	// seed the embedded one and ignore this, so the plane rule could only ever
	// be driven with the shipped rows - which, since #3963, contain no
	// plane-dependent detector at all. A per-plane divergence the builder
	// stopped declaring was then invisible to every test that can run without
	// a database.
	Census []registry.CensusRow
	// Ledger is the supersession ledger. Every decision is checked against the
	// census before the corpus is built, so a regeneration cannot carry a
	// decision whose ground the database no longer supports.
	Ledger []registry.SupersessionRow
}

// BuildCorpus migrates a compiled legacy report into the typed corpus.
func BuildCorpus(rep Report, opts CorpusOptions) (*Corpus, error) {
	if opts.ContentTarget == "" {
		return nil, fmt.Errorf("legacycompile: the corpus build declares no content target; a redact row would then carry an obligation with an empty target, which discloses everything it was meant to hide")
	}
	if len(opts.Rows) == 0 {
		return nil, fmt.Errorf("legacycompile: the corpus build was handed no rows; the tier is what decides whether a row is the platform's own, and without the rows every control would land in one document by default")
	}
	if len(opts.Rows) != len(rep.Records) {
		return nil, fmt.Errorf("legacycompile: the corpus build was handed %d row(s) and a report over %d record(s); the two must be the same capture, because the tier comes from one and everything else from the other",
			len(opts.Rows), len(rep.Records))
	}
	if len(opts.Census) == 0 {
		return nil, fmt.Errorf("legacycompile: the corpus build was handed no census; the detector registry is seeded from it and the corpus is checked against it, so without one neither happens")
	}
	if err := registry.CheckSupersessionLedgerAgainstCensus(opts.Ledger, opts.Census); err != nil {
		return nil, err
	}
	if err := CheckSupersessionDecisions(opts.Ledger, opts.Census); err != nil {
		return nil, err
	}
	tierOf := map[string]string{}
	for _, r := range opts.Rows {
		tierOf[corpusRowKey(r.Table, r.OrgScope, r.stringOr("policy_id", ""))] = r.stringOr("tier", "")
	}
	// THE REGISTRY IS CONSULTED HERE, WHICH IS WHAT MAKES THE PLANE RULE A
	// RULE RATHER THAN AN API NOBODY CALLS.
	//
	// `Catalog.CheckDetectorSelection` refuses a selection of a plane that
	// cannot run a detector's implementation. Nothing in the TYPED model
	// selects a plane - ADR-065 removed execution location from policy
	// identity, which is the point - so the only surface that can ask the
	// question today is this migration, where the planes a legacy row ran on
	// are still known. Asking it per row turns a plane difference - #3963's, on
	// the tier plane #4253 retired, was the first - from a sentence in a design
	// document into an enumerated divergence carrying the detector's own
	// implementation name.
	censusedIDs := map[string]bool{}
	for _, r := range opts.Census {
		// The census covers `static_policies` only, and its own rows carry no
		// org scope; every censused row is seeded globally.
		censusedIDs[corpusRowKey("static_policies", "global", r.PolicyID)] = true
	}
	cat := registry.NewCatalog(time.Now())
	for _, r := range opts.Census {
		if err := cat.RegisterDetector(registry.RecordFor(r)); err != nil {
			return nil, fmt.Errorf("legacycompile: seeding the detector registry for the corpus build with %q: %w", r.PolicyID, err)
		}
	}

	c := &Corpus{
		System:               &pdp.Document{Root: pdp.RootSystem, Version: 1},
		OrganizationTemplate: &pdp.Document{Root: pdp.RootOrganization, Version: 1},
		ScopeBindings:        map[string][]string{},
	}
	for _, rec := range rep.Records {
		policies, bindings, div, err := corpusPolicyFor(rec, tierOf, censusedIDs, cat, opts)
		if err != nil {
			return nil, err
		}
		c.Divergences = append(c.Divergences, div...)
		for id, scopes := range bindings {
			c.ScopeBindings[id] = scopes
		}
		for _, policy := range policies {
			switch policy.Root {
			case pdp.RootSystem:
				c.System.Policies = append(c.System.Policies, policy)
			case pdp.RootOrganization:
				c.OrganizationTemplate.Policies = append(c.OrganizationTemplate.Policies, policy)
			default:
				return nil, fmt.Errorf("legacycompile: corpus policy %q declares root %q", policy.ID, policy.Root)
			}
		}
	}

	for _, doc := range []*pdp.Document{c.System, c.OrganizationTemplate} {
		sort.Slice(doc.Policies, func(i, j int) bool { return doc.Policies[i].ID < doc.Policies[j].ID })
		// deriveSchema is the COMPILER'S OWN schema derivation, called rather
		// than reproduced. A hand-rolled "one boolean per detector" schema
		// would be right for the static half and wrong for the dynamic one,
		// whose policies read budget, time and role attributes of several
		// types - and it would silently disagree with deriveSchema about a
		// path two policies read at two types, which that function widens to
		// TypeAny.
		doc.Attributes = deriveSchema(doc.Policies, nil)
	}
	// STABLE, WITH A TOTAL TIE-BREAK. `sort.Slice` is not stable, so two
	// divergences with an equal key would order nondeterministically and move
	// the artifact's bytes between runs - which would turn the regeneration
	// check into a coin toss rather than a comparison. No equal key exists in
	// the captured corpus; the sort is made total anyway, because "unreachable
	// today" is what every nondeterminism says before it is reached.
	sort.SliceStable(c.Divergences, func(i, j int) bool {
		a, b := c.Divergences[i], c.Divergences[j]
		if a.PolicyID != b.PolicyID {
			return a.PolicyID < b.PolicyID
		}
		if a.Table != b.Table {
			return a.Table < b.Table
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Detail < b.Detail
	})
	if err := CheckCorpusRepresentsTheCensus(c, opts.Census); err != nil {
		return nil, err
	}
	return c, nil
}

// corpusPolicyFor migrates one record.
//
// # IT RE-KEYS THE SHADOW COMPILATION RATHER THAN RE-DERIVING IT
//
// The obvious build - read the row's action and map it again here - is a
// SECOND legacy-to-ADR-065 mapping, and the design's reuse census says in as
// many words that a second one must not exist. Worse, it is wrong for half the
// corpus: `dynamic.go` compiles a dynamic row from its CONDITIONS into grants,
// ceilings and requirements, and a second mapping written against
// `static_policies` would turn a budget rule into a detector signal. The first
// version of this file did exactly that and produced a policy reading
// `signal.detector.sys_dyn_llm_cost` for a row that inspects no content.
//
// So the corpus takes the policies the shadow compiler already emitted, on the
// plane whose resolved action is the most restrictive, and re-keys them to a
// plane-independent identity. Everything a policy SAYS is legacycompile's own
// answer; the only thing this file decides is WHICH plane's answer survives
// the collapse, and every collapse is declared.
func corpusPolicyFor(rec Record, tierOf map[string]string, censusedIDs map[string]bool, cat *registry.Catalog, opts CorpusOptions) ([]pdp.Policy, map[string][]string, []Divergence, error) {
	id := rec.Source.PolicyID
	table := rec.Source.Table
	var divs []Divergence

	// The per-plane resolved actions, deduplicated. This is what the legacy
	// engines DECIDE, which is not the same as what the action column SAYS:
	// the two read paths resolve independently and forty rows carry
	// read_path_action_divergence because of it.
	seen := map[string]bool{}
	var actions []string
	for _, p := range rec.Planes {
		if p.ResolvedAction == "" {
			continue
		}
		if !seen[p.ResolvedAction] {
			seen[p.ResolvedAction] = true
			actions = append(actions, p.ResolvedAction)
		}
	}
	sort.Strings(actions)

	var unrankable, declaredOrder []string
	for _, a := range actions {
		_, engineRanked, ok := corpusRestrictiveness(a)
		if !ok {
			unrankable = append(unrankable, a)
			continue
		}
		if !engineRanked {
			declaredOrder = append(declaredOrder, a)
		}
	}
	if len(unrankable) > 0 {
		return nil, nil, append(divs, Divergence{
			PolicyID: id, Table: table, Kind: DivergenceActionUnrankable,
			LegacyActions: actions,
			Detail: fmt.Sprintf("the legacy engines resolve action(s) %v for this row, which the corpus collapse has no rank for. "+
				"It is refused rather than defaulted: `shadow.restrictiveness` mirrors the engine's own `default: return 0`, which puts an "+
				"unranked action BELOW `log`, and collapsing to a rank nobody chose would ship a weaker control than the row it came from", unrankable),
		}), nil
	}

	// The winning plane result: the most restrictive resolved action, and among
	// equally restrictive ones the first in (plane, phase) order, which is a
	// stable ordering rather than map order.
	ordered := append([]PlaneResult(nil), rec.Planes...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].Plane != ordered[j].Plane {
			return ordered[i].Plane < ordered[j].Plane
		}
		return ordered[i].Phase < ordered[j].Phase
	})
	var winner *PlaneResult
	bestRank := -1
	for i := range ordered {
		p := &ordered[i]
		if len(p.Policies) == 0 {
			continue
		}
		rank, _, ok := corpusRestrictiveness(p.ResolvedAction)
		if !ok {
			continue
		}
		if rank > bestRank {
			winner, bestRank = p, rank
		}
	}
	if winner == nil {
		// WHAT SURVIVES DEPENDS ON WHETHER THE ROW IS A CENSUSED DETECTOR, AND
		// SAYING SO PER ROW IS THE POINT. The nine disabled integration seeds
		// are censused, so they survive as registered records with
		// `enabled=false` and enabling one is a configuration change. A row
		// the census does not cover - the census is static-only - survives as
		// NEITHER a policy nor a record, and telling an auditor otherwise is
		// worse than telling them nothing.
		survives := "It survives the migration as a registered detector record with enabled=false rather than as a policy, so " +
			"enabling it is a configuration change rather than the arrival of a control nothing described."
		// KEYED ON THE TABLE TOO, for the reason `detectorPlaneDivergence`
		// twenty lines down states: `policy_id` is unique per table, not
		// across them, so a dynamic row sharing a static row's identifier
		// would otherwise be told it survives as a registered detector record
		// when nothing carries it.
		if !censusedIDs[corpusRowKey(table, rec.Source.OrgScope, id)] {
			survives = "It survives as NEITHER a policy nor a registered detector record: the detector census covers " +
				"static_policies only, so nothing in the new model carries this row at all. That is a gap in the migration " +
				"and is stated as one."
		}
		divs = append(divs, Divergence{
			PolicyID: id, Table: table, Kind: DivergenceRowNotRepresented,
			LegacyActions: actions, CompilerReasons: compilerReasons(rec),
			Detail: "the shadow compilation emitted no policy for this row on any plane, so there is nothing for the corpus to carry. " + survives,
		})
		return nil, nil, append(divs, defectReproducedDivergence(rec, nil, nil)...), nil
	}
	// WHETHER THE ROW IS SPLIT is decided here, before the collapse is declared,
	// and on the same terms the split below applies (the comment there says
	// why): a SYSTEM row whose compiled planes ENFORCE more than one action. A
	// row that is not split keeps the collapse, and declares it whenever its
	// planes resolve more than one action - including a system row whose weaker
	// plane compiled nothing, so only one action reached a policy.
	enforced := map[string]bool{}
	for i := range ordered {
		if r := &ordered[i]; len(r.Policies) > 0 && enforcedActionOf(r) != "" {
			enforced[enforcedActionOf(r)] = true
		}
	}
	split := tierOf[corpusRowKey(table, rec.Source.OrgScope, id)] == "system" && len(enforced) > 1
	if len(actions) > 1 && !split {
		detail := fmt.Sprintf("the legacy engines resolve %d different actions for this row depending on which plane asked (%s); "+
			"the corpus carries one policy and takes the most restrictive, %q, from plane %q. On every plane whose legacy action "+
			"was weaker than that, this row now decides more strictly than it did",
			len(actions), strings.Join(actions, ", "), winner.ResolvedAction, winner.Plane)
		if len(declaredOrder) > 0 {
			detail += fmt.Sprintf(". The comparison involved %v, which the enforcing engines' own restrictiveness ranking does not "+
				"order at all - it returns zero for them, below `log`. Their place in the collapse is DECLARED by the migration "+
				"rather than derived from the engine, so this row's winner is a judgement and is named as one", declaredOrder)
		}
		divs = append(divs, Divergence{
			PolicyID: id, Table: table, Kind: DivergencePlaneActionCollapsed,
			LegacyActions: actions, Chosen: winner.ResolvedAction, Detail: detail,
		})
	}

	root := pdp.RootOrganization
	tier, known := tierOf[corpusRowKey(table, rec.Source.OrgScope, id)]
	if tier == "system" {
		root = pdp.RootSystem
	}
	// AN EMPTY TIER IS NOT A TENANT TIER, AND CONFLATING THEM PUTS A PLATFORM
	// CONTROL IN THE CUSTOMER-EDITABLE DOCUMENT WITH NOTHING TO SEE.
	//
	// `known` answers "a captured row matched this key", not "that row carried
	// a tier". `migrations/core/030` declares `tier VARCHAR(20) DEFAULT
	// 'tenant' CHECK (tier IN (...))` with NO NOT NULL, and a Postgres CHECK
	// passes on NULL - so a NULL tier reaches here as `known=true, tier=""`,
	// falls through to the organization root, and emits no divergence of any
	// kind. R3 drove it. The sharpest case is a dynamic row, which the
	// static-only census cannot catch either.
	if known && tier == "" {
		known = false
		divs = append(divs, Divergence{
			PolicyID: id, Table: table, Kind: DivergenceTierNotRecorded, ToRoot: string(root),
			Detail: "the captured row carries an EMPTY tier, so the corpus placed it on the organization root. That is not the " +
				"same as a tenant-tier row: the tier column is nullable in the schema and a NULL passes its own CHECK, so a " +
				"platform-owned control can arrive here indistinguishable from a customer-editable one. It is reported rather " +
				"than defaulted, because the default is the direction that gives an edit right away",
		})
	}
	// The shadow compilation has its own answer to the same question, and where
	// the two disagree the TIER wins, because the tier is what a customer can
	// edit and editability is what the split is for. Recorded rather than
	// resolved silently: `staticRootFor` also routes a row whose tenant is
	// `global` to the system root, so a global-tenant row at tenant tier is
	// exactly the shape that disagrees, and there are enough of them that a
	// reader must not meet this for the first time in a diff.
	if compiled := winner.Policies[0].Root; known && compiled != root {
		divs = append(divs, Divergence{
			PolicyID: id, Table: table, Kind: DivergenceRootDisagreesWithTier,
			FromRoot: string(compiled), ToRoot: string(root),
			Detail: fmt.Sprintf("the shadow compilation puts this row on the %q root and its census tier is %q, so the corpus puts it on the %q root. "+
				"The tier decides because the tier is what a customer may edit, and a customer-editable row inside a build-invariant artifact "+
				"would lose an edit right it has today", compiled, tier, root),
		})
	}
	if !known {
		// A DIFFERENT FACT UNDER ITS OWN KIND. This is not a root CHANGE - no
		// disagreement was observed, because no tier was found - and giving it
		// the same kind as a real move made one name cover two conditions,
		// only one of which a reader can act on. It is reachable when the rows
		// and the report come from different captures, which the length check
		// in BuildCorpus narrows but cannot exclude.
		divs = append(divs, Divergence{
			PolicyID: id, Table: table, Kind: DivergenceTierNotRecorded,
			ToRoot: string(root),
			Detail: "no captured row carries a tier for this record, so the corpus placed it on the organization root. " +
				"A control whose editability nobody recorded must not land in the platform's own document by default, and " +
				"the rows and the compiled report may not be the same capture",
		})
	}

	divs = append(divs, detectorPlaneDivergence(rec, cat)...)
	// ONE PLANE'S COMPILATION PER ACTION (#4046).
	//
	// A row whose planes resolve one action, and every organization-template
	// row, keeps the collapse: one policy, from the most restrictive plane. A
	// SYSTEM row whose planes resolve different actions is SPLIT instead - one
	// policy per resolved action, each bound to the scopes that resolve it - so
	// a scope enforces the action its own legacy engine took. Collapsing it
	// would hand every plane the strictest plane's answer: decide demanding a
	// mandatory redaction for sixteen PII controls its request phase only ever
	// warned or logged, and the MCP response pass withholding a response the
	// legacy pass released with a span stripped (#4016). The template keeps the
	// collapse because no restriction applies to an organization document; the
	// organization decides what it activates.
	//
	// THE SPLIT IS DECIDED BY WHAT EACH PLANE'S COMPILATION ENFORCES, not by what
	// it resolved. A plane that COERCES an action - cowork_ingest masks every
	// pii-* match before it persists, whatever the row resolves - compiles the
	// coerced action, so two planes can both resolve `log` and compile `log` and
	// `redact`. Grouping by the resolved action put those two compilations in
	// one group and the build refused it (measured on sys_pii_singapore_postal);
	// deciding the split by the resolved set would also leave a row that
	// resolves `log` everywhere and is coerced to `redact` on cowork_ingest
	// (sys_pii_booking_ref) collapsed to whichever plane sorts first.
	groups := []corpusActionGroup{{action: enforcedActionOf(winner), results: []*PlaneResult{winner}}}
	if split {
		groups = nil
		index := map[string]int{}
		for i := range ordered {
			r := &ordered[i]
			action := enforcedActionOf(r)
			if len(r.Policies) == 0 || action == "" {
				continue
			}
			g, seen := index[action]
			if !seen {
				g = len(groups)
				index[action] = g
				groups = append(groups, corpusActionGroup{action: action})
			}
			groups[g].results = append(groups[g].results, r)
		}
	}
	// The corpus imports each group's representative compilation, and binds it
	// to every plane in the group, whose compilations are the same content (the
	// loud refusal below holds that). So a defect any member plane's compilation
	// carries is carried by the variant; an unsplit row imports the winner's
	// compilation alone.
	imported := make([]Plane, 0, len(groups))
	var carriers []Plane
	for _, g := range groups {
		imported = append(imported, g.results[0].Plane)
		for _, r := range g.results {
			if !slices.Contains(carriers, r.Plane) {
				carriers = append(carriers, r.Plane)
			}
		}
	}
	divs = append(divs, defectReproducedDivergence(rec, imported, carriers)...)

	var out []pdp.Policy
	bindings := map[string][]string{}
	for _, g := range groups {
		rep := g.results[0]
		var scopes []string
		if split {
			// THE LOUD REFUSAL. Two planes that resolve one action and compiled
			// different policies for it cannot share one variant: binding the
			// representative's policy to the other plane's scope would enforce
			// there a policy that plane never compiled, and nothing downstream
			// would notice two planes' content quietly becoming one.
			for _, other := range g.results[1:] {
				same, err := sameCompiledContent(rep.Policies, other.Policies)
				if err != nil {
					return nil, nil, nil, err
				}
				if !same {
					return nil, nil, nil, fmt.Errorf("legacycompile: %s %s enforces %q on both the %s and %s planes and the two compiled different "+
						"policies for it; a split by scope would bind one plane's policy where the other plane's was compiled, so the build refuses "+
						"rather than merge two planes' content into one control", table, id, g.action, rep.Plane, other.Plane)
				}
			}
			seen := map[string]bool{}
			for _, r := range g.results {
				scope, err := ScopeFor(r.Plane, r.Phase)
				if err != nil {
					return nil, nil, nil, fmt.Errorf("legacycompile: %s %s enforces %q on plane %s phase %q, which is not a declared enforcement "+
						"scope, so its split cannot be bound: %w", table, id, g.action, r.Plane, r.Phase, err)
				}
				if !seen[scope.String()] {
					seen[scope.String()] = true
					scopes = append(scopes, scope.String())
				}
			}
			sort.Strings(scopes)
		}
		for i, src := range rep.Policies {
			p := src
			p.Root = root
			p.ID = CorpusPolicyIDFor(table, id)
			// The row's own name (#4127). Every split and #n variant of one row
			// shares it: they are one control an operator knows by one name.
			p.Name = rec.Source.Name
			if split {
				p.ID = CorpusVariantIDFor(table, id, g.action)
			}
			if len(rep.Policies) > 1 {
				p.ID = fmt.Sprintf("%s#%d", p.ID, i+1)
			}
			// The obligations point back at the policy that attached them, and the
			// re-key would otherwise leave them naming an identifier that is not in
			// this document. A dangling SourcePolicy is how an obligation stops
			// being traceable to the rule that required it.
			p.Obligations = append([]contract.Obligation(nil), src.Obligations...)
			for j := range p.Obligations {
				p.Obligations[j].SourcePolicy = p.ID
			}
			if split {
				p.Description = fmt.Sprintf("migrated from %s %s, from the %s plane's compilation of the %q the legacy engines enforce on %s. "+
					"The legacy engines enforce %d different actions for this row depending on the scope, so the corpus carries one policy per "+
					"action and binds this one to those scopes only. %s", table, id, rep.Plane, g.action, strings.Join(scopes, ", "), len(enforced), src.Description)
				bindings[p.ID] = append([]string(nil), scopes...)
			} else {
				p.Description = fmt.Sprintf("migrated from %s %s, from the %s plane's compilation, which is the most restrictive of the %d the legacy engines resolve. %s",
					table, id, winner.Plane, len(actions), src.Description)
			}
			// THE ASSURANCE CLASS IS DECLARED AT BUILD, from the compiled policy's
			// shape, so the artifact a reviewer reads states each control's failure
			// behaviour. pdp.RequireDeclaredAssurance refuses the artifact at load if
			// any control is missing one, and the combiner-driven test in pdp holds
			// the declared classes to what the engine actually does.
			if class, control := pdp.DeriveAssurance(p); control {
				p.Assurance = class
			}
			out = append(out, p)
		}
	}
	// A DYNAMIC REDACTION SHIPS AS A WARN WHERE NO SCOPE CAN CARRY IT OUT (#4254,
	// dynamic_discharge.go). Asked before the template rule, whose warn half is
	// compiled from a captured category and severity a dynamic row does not store.
	if table == "dynamic_policies" {
		return shipDynamicRedactionAsWarn(table, id, out, bindings, divs)
	}
	// A TEMPLATE REDACTION IS BOUND BY DISCHARGE (#4131, template_discharge.go).
	// The template is not split by what each legacy engine resolved, and its
	// collapsed redaction is bound redact where a scope can carry one out and
	// warn where it cannot.
	if root == pdp.RootOrganization && !split {
		return splitTemplateRedactionByDischarge(table, id, rec, winner, out, bindings, divs, opts)
	}
	return out, bindings, divs, nil
}

// enforcedActionOf is the action a plane result's compilation carries: the
// enforced action, which a plane coercion can make differ from the resolved
// one, and the resolved action where no enforced action was recorded.
func enforcedActionOf(r *PlaneResult) string {
	if r.EnforcedAction != "" {
		return r.EnforcedAction
	}
	return r.ResolvedAction
}

// corpusActionGroup is the plane results of one row that enforce one action.
type corpusActionGroup struct {
	action  string
	results []*PlaneResult
}

// sameCompiledContent reports whether two planes compiled the same policies for
// one resolved action, ignoring exactly what legitimately differs by plane: the
// plane-qualified identifier, the description that names the plane, and the
// obligation source that points at that identifier.
func sameCompiledContent(a, b []pdp.Policy) (bool, error) {
	if len(a) != len(b) {
		return false, nil
	}
	for i := range a {
		da, err := contract.ExactDigest(planeNeutral(a[i]))
		if err != nil {
			return false, fmt.Errorf("legacycompile: digesting a compiled policy for the split comparison: %w", err)
		}
		db, err := contract.ExactDigest(planeNeutral(b[i]))
		if err != nil {
			return false, fmt.Errorf("legacycompile: digesting a compiled policy for the split comparison: %w", err)
		}
		if da != db {
			return false, nil
		}
	}
	return true, nil
}

// planeNeutral is a compiled policy with its plane-qualified parts cleared.
func planeNeutral(p pdp.Policy) pdp.Policy {
	p.ID, p.Description = "", ""
	p.Obligations = append([]contract.Obligation(nil), p.Obligations...)
	for i := range p.Obligations {
		p.Obligations[i].SourcePolicy = ""
	}
	return p
}

// ShippedCorpusFileName is the artifact's name. It lives in `platform/decision/pdp`
// rather than here because that is the package a deployment's activation path
// reads it from, and because `pdp` is the layer with no dependency on the
// migration tool that produced it: the artifact outlives this package.
const ShippedCorpusFileName = "system_corpus.json"

// RenderCorpus renders the corpus to the exact bytes the artifact carries.
//
// Indented rather than compact, deliberately. This file is the platform's own
// controls, a change to it changes what every deployment ships, and the only
// review that can catch such a change is one a person can read. Determinism
// comes from the build - policies and divergences are sorted, and Go's encoder
// sorts the one map involved (obligation parameters) - so two builds of the
// same corpus produce identical bytes and the regeneration check means
// something.
func RenderCorpus(c *Corpus) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("legacycompile: cannot render a nil corpus")
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("legacycompile: rendering the corpus: %w", err)
	}
	return append(b, '\n'), nil
}

// Validate runs the authoring validation both documents must pass before
// anything digests or signs them.
func (c *Corpus) Validate() error {
	for _, d := range []*pdp.Document{c.System, c.OrganizationTemplate} {
		if d == nil {
			return fmt.Errorf("legacycompile: the corpus is missing a document")
		}
		if errs := d.Validate(); len(errs) > 0 {
			return fmt.Errorf("legacycompile: the %s corpus document does not validate: %v", d.Root, errs)
		}
	}
	return nil
}

// DivergenceCounts summarises the enumeration by kind, so a report can state
// the shape of the migration without restating every row.
func (c *Corpus) DivergenceCounts() map[DivergenceKind]int {
	out := map[DivergenceKind]int{
		DivergencePlaneActionCollapsed:        0,
		DivergenceRowNotRepresented:           0,
		DivergenceRootDisagreesWithTier:       0,
		DivergenceActionUnrankable:            0,
		DivergenceTierNotRecorded:             0,
		DivergenceDetectorRanBareOnSomePlanes: 0,
		DivergenceLegacyDefectReproduced:      0,
		DivergenceRedactionBoundByDischarge:   0,
		DivergenceDynamicRedactionShipsAsWarn: 0,
	}
	for _, d := range c.Divergences {
		out[d.Kind]++
	}
	return out
}

// defectReproducedDivergence states, for a row whose compilation preserved a
// legacy defect, that the corpus imports it as the defect - and whether the
// policy the corpus imported is itself the compilation that carries it.
//
// winnerPlane is empty when the row produced no corpus policy at all.
//
// The second half matters because the corpus takes ONE plane's compilation.
// A row can carry a defect on some planes and not on the one whose answer
// survived the collapse, and "reproduced" must not be read as "the imported
// policy embodies it" when it does not.
func defectReproducedDivergence(rec Record, importedPlanes, carrierPlanes []Plane) []Divergence {
	if rec.Status != StatusPreservedDefect {
		return nil
	}
	var carrying []string
	for _, plane := range carrierPlanes {
		if st, ok := rec.StatusForPlane(plane); ok && st == StatusPreservedDefect {
			carrying = append(carrying, string(plane))
		}
	}
	sort.Strings(carrying)
	var carried string
	switch {
	case len(importedPlanes) == 0:
		carried = "The corpus carries no policy for this row, which is the legacy behaviour reproduced: the migration does not " +
			"start enforcing a row the legacy engines do not enforce."
	case len(importedPlanes) == 1 && len(carrying) == 1:
		carried = fmt.Sprintf("The imported policy is the %s plane's compilation, and that compilation itself carries the defect.", importedPlanes[0])
	case len(importedPlanes) == 1:
		carried = fmt.Sprintf("The imported policy is the %s plane's compilation, which carries none of these defects; they are "+
			"reproduced on other planes' compilations of the row, which the corpus does not import.", importedPlanes[0])
	case len(carrying) == 0:
		carried = fmt.Sprintf("The row is split by scope, so the corpus imports one compilation per action, from the %v planes, and "+
			"none of those compilations carries these defects.", importedPlanes)
	default:
		carried = fmt.Sprintf("The row is split by scope, so the corpus imports one compilation per action, from the %v planes; "+
			"the compilations from %v carry the defect.", importedPlanes, carrying)
	}
	return []Divergence{{
		PolicyID: rec.Source.PolicyID, Table: rec.Source.Table, Kind: DivergenceLegacyDefectReproduced,
		CompilerReasons: defectReasonLines(rec),
		Detail: "the legacy compilation of this row reproduces a known defect rather than repairing it, and the corpus imports " +
			"it as reproduced rather than silently repaired. " + carried,
	}}
}

// defectReasonLines renders the row's defect reasons only, at row level and on
// every plane, deduplicated and in a stable order - the subset of
// compilerReasons that makes the row a preserved defect.
func defectReasonLines(rec Record) []string {
	seen := map[string]bool{}
	var out []string
	add := func(rs []Reason) {
		for _, r := range rs {
			if _, defect := IsDefectReason(r.Code); !defect {
				continue
			}
			line := string(r.Code) + ": " + r.Detail
			if !seen[line] {
				seen[line] = true
				out = append(out, line)
			}
		}
	}
	add(rec.Reasons)
	for _, p := range rec.Planes {
		add(p.Reasons)
	}
	sort.Strings(out)
	return out
}

// corpusRowKey identifies a captured row.
//
// The org scope is part of it, not decoration: under core/018's strict-equality
// row-level security a row is visible in exactly one scoped pass, and the same
// policy_id can legitimately exist under two org scopes. Keying on the
// identifier alone would let one organization's row supply another's tier.
func corpusRowKey(table, orgScope, policyID string) string {
	return table + "\x00" + orgScope + "\x00" + policyID
}

// detectorPlaneDivergence states, per row, whether the detector the migrated
// policy reads gated on every plane the legacy row ran on.
//
// It asks the registry rather than re-deriving the answer, and it asks by
// SELECTION - `CheckDetectorSelection` over the row's own planes - so the rule
// the registry enforces and the fact the corpus reports are the same
// computation rather than two that agree. A row whose detector gates
// everywhere produces nothing here, which is why an empty result is a
// statement and not a gap.
func detectorPlaneDivergence(rec Record, cat *registry.Catalog) []Divergence {
	id := rec.Source.PolicyID
	// THE CENSUS COVERS static_policies ONLY, so a dynamic row must never
	// reach a detector record - and `policy_id` is unique per table, not
	// across them. Without this a dynamic row sharing a static row's
	// identifier would inherit that detector's bare-plane divergence and be
	// told its conditions had failed a checksum. No collision exists in the
	// captured corpus; the guard is here because the identifier space permits
	// one.
	if rec.Source.Table != "static_policies" {
		return nil
	}
	det, ok := cat.Detector(registry.DetectorID(id))
	if !ok {
		// Not every migrated row is a censused detector: the census covers
		// static_policies, and a dynamic row inspects conditions rather than
		// content. Silence here is correct, and it is not the same claim as
		// "the implementation gated".
		return nil
	}
	if det.Class != registry.DetectorClassAlgorithmic {
		return nil
	}
	// Deduplicated: a plane repeats in Planes when one handler registers two
	// call sites on it, and the counts in the detail below are a count of
	// PLANES rather than of findings.
	seenPlane := map[string]bool{}
	var planes []string
	for _, p := range rec.Planes {
		if seenPlane[string(p.Plane)] {
			continue
		}
		seenPlane[string(p.Plane)] = true
		planes = append(planes, string(p.Plane))
	}
	var bare, mixed []string
	for _, one := range cat.CheckDetectorSelection(registry.DetectorID(id), planes) {
		switch one.Code {
		case registry.CodeDetectorPlaneCannotGate:
			bare = append(bare, one.Message)
		case registry.CodeDetectorPlanePartiallyGates:
			mixed = append(mixed, one.Message)
		}
	}
	if len(bare) == 0 && len(mixed) == 0 {
		return nil
	}
	detail := fmt.Sprintf("this row's detector is algorithmic (%s) and did not gate on every plane the row ran on, so the "+
		"legacy answer there was the bare pattern's. The migrated policy reads ONE detector verdict; which behaviour that "+
		"verdict carries is a property of the enforcement point and is declared on the registry entry's gating planes. "+
		"%d plane(s) ran it bare, %d partially.", det.Impl, len(bare), len(mixed))
	for _, m := range append(append([]string(nil), bare...), mixed...) {
		detail += " | " + m
	}
	return []Divergence{{
		PolicyID: id, Table: rec.Source.Table, Kind: DivergenceDetectorRanBareOnSomePlanes,
		Detail: detail,
	}}
}

// compilerReasons renders the shadow compiler's own per-row reasons, at row
// level and on every plane, in a stable order.
//
// It is deduplicated because a reason that resolves the same way on nine
// planes is one fact about the row, and nine copies of it in an operator-facing
// artifact is nine reasons to stop reading.
func compilerReasons(rec Record) []string {
	seen := map[string]bool{}
	var out []string
	add := func(rs []Reason) {
		for _, r := range rs {
			line := string(r.Code) + ": " + r.Detail
			if seen[line] {
				continue
			}
			seen[line] = true
			out = append(out, line)
		}
	}
	add(rec.Reasons)
	for _, p := range rec.Planes {
		add(p.Reasons)
	}
	sort.Strings(out)
	return out
}
