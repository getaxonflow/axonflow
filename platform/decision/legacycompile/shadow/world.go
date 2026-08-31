package shadow

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"regexp"
	"regexp/syntax"
	"sort"
	"strings"
	"time"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
)

// Realm is the DEFAULT trust realm the corpus's principals resolve in, used
// when the compilation options name none. A case takes its realm from the
// options it was generated against, so a compiled segment-scoped policy and a
// corpus principal's group closure always name the same identifiers.
const Realm = legacycompile.DefaultRealm

// ActionID is the single registered action the corpus exercises.
//
// One action, deliberately. The legacy static substrate is content inspection
// that applies to every request on its plane (ActionSelector.Any), and the
// dynamic substrate selects on request attributes rather than on a registered
// action, so enumerating actions would multiply cases without exercising a
// single additional policy row. Per-action coverage becomes meaningful at
// #3564, when planes cut over against the real action registry.
const ActionID = "legacy.plane.request"

// World is a compiled, signed, verified ADR-065 evaluation environment built
// from a compilation report.
type World struct {
	Plane legacycompile.Plane
	// Phase is the legacy phase this world evaluates, empty when the plane
	// evaluates only one (or none, on the dynamic substrate). A two-phase
	// plane gets one world PER PHASE, because that is how production runs it.
	Phase legacycompile.Phase
	// OrgScope is the org this world's documents belong to. One document set
	// per org, because the runtime reads policy under strict per-org RLS.
	OrgScope     string
	System       *pdp.Document
	Organization *pdp.Document
	Engine       *pdp.Engine
	Bundles      []*pdp.Bundle
	BundleDigest string
}

// NewWorld compiles one plane's policies into signed bundles and returns a
// ready engine.
//
// The bundles are really built, really signed and really verified, and the
// engine really runs OPA over the generated Rego. That is the point: the
// ADR-065 side of a shadow diff has to be the actual decision path, or the
// diff measures a description of it.
// WorldOption customises a world before its bundles are built.
type WorldOption func(*worldConfig)

type worldConfig struct {
	baselinePermission bool
	realm              string
	phase              legacycompile.Phase
}

// WithPhase scopes the world to one legacy evaluation phase. RunAll sets it
// for every plane whose spec evaluates more than one phase, because such a
// plane runs one pass per phase in production and a world built from both
// phases' policies evaluates two passes as one.
func WithPhase(ph legacycompile.Phase) WorldOption {
	return func(c *worldConfig) { c.phase = ph }
}

// WithoutBaselinePermission builds the world the way a plane looks at cutover
// BEFORE its ADR-065 permissions have been authored: constraints and
// requirements only, and nothing granting anything.
//
// It is not a test convenience. ADR-065 requires "a coverage report proves
// that expected principal, action, and resource classes have a matching
// permission before a plane can leave shadow mode", and this mode is that
// report: every case that lands on EC1_DEFAULT_DENY in it is a request the
// plane would refuse on the day it cut over. Running only the baseline mode
// would report a clean migration and hide the entire permission-authoring
// backlog.
func WithoutBaselinePermission() WorldOption {
	return func(c *worldConfig) { c.baselinePermission = false }
}

// WithRealm sets the trust realm the engine declares, which must be the one
// the compilation options used.
func WithRealm(realm string) WorldOption {
	return func(c *worldConfig) {
		if realm != "" {
			c.realm = realm
		}
	}
}

func NewWorld(ctx context.Context, rep *legacycompile.Report, plane legacycompile.Plane, orgScope string, opts ...WorldOption) (*World, error) {
	cfg := worldConfig{baselinePermission: true, realm: Realm}
	for _, o := range opts {
		o(&cfg)
	}
	system, org, err := rep.DocumentsForPhase(plane, cfg.phase, orgScope)
	if err != nil {
		return nil, err
	}
	// A permission is required for anything to be permitted at all: ADR-065
	// combines to NotApplicable when no permission matches, and NotApplicable
	// maps to deny. The legacy substrate has no permissions - it is entirely
	// constraints, requirements and inspections - so the migration has to
	// supply the baseline permission that the legacy engines expressed by
	// having no gate at all. Compiling one is a MIGRATION decision and it is
	// made here, visibly, rather than inside the row compiler where it would
	// look like a property of some row.
	if cfg.baselinePermission {
		system.Policies = append(system.Policies, baselinePermission())
	}
	if len(system.Attributes) == 0 && len(org.Attributes) == 0 {
		// A document with no attributes is legitimate (a plane whose rows all
		// compiled to nothing), and the baseline permission references none.
		system.Attributes = nil
		org.Attributes = nil
	}

	for _, d := range []*pdp.Document{system, org} {
		if errs := d.Validate(); len(errs) > 0 {
			return nil, fmt.Errorf("shadow: the %s document for plane %q does not validate: %v", d.Root, plane, errs)
		}
	}

	ts := pdp.NewTrustStore()
	var bundles []*pdp.Bundle
	for _, d := range []*pdp.Document{system, org} {
		b, err := pdp.BuildBundle(d)
		if err != nil {
			return nil, fmt.Errorf("shadow: building the %s bundle for plane %q: %w", d.Root, plane, err)
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
		Documents:   []*pdp.Document{system, org},
		TrustStore:  ts,
		ApprovalTTL: 15 * time.Minute,
		PEP:         PEP(),
		Registry:    RegistryForPhase(rep, plane, cfg.phase, orgScope, cfg.realm),
	})
	if err != nil {
		return nil, fmt.Errorf("shadow: building the engine for plane %q: %w", plane, err)
	}
	return &World{
		Plane: plane, Phase: cfg.phase, OrgScope: orgScope, System: system, Organization: org,
		Engine: engine, Bundles: bundles, BundleDigest: bundles[0].Digest,
	}, nil
}

// BaselinePermissionID is the identifier of the compiled baseline permission.
// It is exported so a diff record naming it is readable, and so a test can
// assert it is the ONLY permission in a compiled document - a second one would
// mean a legacy row had been compiled into a grant, which nothing in the legacy
// substrate is.
const BaselinePermissionID = "legacy:migration:baseline_permission"

func baselinePermission() pdp.Policy {
	return pdp.Policy{
		ID:        BaselinePermissionID,
		Root:      pdp.RootSystem,
		Authority: contract.AuthorityPermission,
		Scope:     pdp.Scope{Organization: true},
		Actions:   pdp.ActionSelector{Any: true},
		Where:     pdp.Condition{Kind: pdp.CondTrue},
		Description: "the legacy substrate has no permission policies: it never gated on authorization at all, only on content and context. " +
			"ADR-065 denies what no permission grants, so shadow evaluation supplies this baseline to keep the diff about the CONSTRAINTS. " +
			"It is a migration artifact and must not survive plane cutover (#3564).",
	}
}

// PEP is the advertised enforcement profile for the corpus. It advertises
// every obligation type the compiler can emit, so that an unsupported-
// obligation denial in a diff means the compiler emitted something new rather
// than that the fixture forgot to advertise it.
func PEP() *contract.PEPProfile {
	return &contract.PEPProfile{
		ID: "shadow-pep",
		Capabilities: []contract.Capability{
			{Type: contract.ObApprovalChallenge, Version: 1},
			{Type: contract.ObFieldRedact, Version: 1},
			{Type: contract.ObImmutableAudit, Version: 1},
			{Type: contract.ObNotification, Version: 1},
			{Type: contract.ObRouteRestriction, Version: 1},
		},
	}
}

// Registry is the action and realm registry the corpus evaluates against.
//
// The ARGUMENT schema is derived from the compiled plane rather than left
// empty. ADR-065 admission refuses a request carrying an `args.*` attribute the
// registry does not declare - correctly, because caller-supplied fields are the
// untrusted surface and an undeclared one is an unbounded input. The legacy
// dynamic conditions read caller-supplied fields (`query`, `request_type`, the
// whole `context.*` family), so the migration has to REGISTER them; an empty
// argument map turned every case on a plane carrying such a row into a schema
// violation, which reads as a decision when it is really a fixture defect.
//
// Every argument is declared `any`. The legacy substrate has no argument types
// - that is one of the things ADR-065's registry adds - and inventing one here
// would make the shadow diff assert a type the deployment does not have.
func Registry(rep *legacycompile.Report, plane legacycompile.Plane, orgScope, realm string) *pdp.Registry {
	return RegistryForPhase(rep, plane, "", orgScope, realm)
}

// RegistryForPhase is Registry scoped to one legacy phase, matching the world
// it serves.
func RegistryForPhase(rep *legacycompile.Report, plane legacycompile.Plane, ph legacycompile.Phase, orgScope, realm string) *pdp.Registry {
	id := contract.MustParseID(contract.KindAction, "Action::"+ActionID)
	args := map[string]pdp.ValueType{}
	// The payload leaf schema is DERIVED from what the compiled policies
	// actually redact, over a floor of the plane's content root. It was a
	// fixture constant of just the content root, and the consequence was
	// silent: field_redact is a disclosure obligation resolved PER PAYLOAD
	// LEAF, a mandatory transform whose target covers no declared leaf is
	// reported as unplaced and NOT APPLIED, and every dynamic redact names
	// response fields ("email", "ssn") rather than the content root - so the
	// engine permitted with zero of the redactions the legacy engine applied,
	// on a state the gate could only call UNEXPLAINED. The legacy substrate
	// has no leaf schema at all; the redact targets its rows store ARE the
	// response fields the enforcement point masks, which makes them the
	// honest leaf population for a migration registry.
	leaves := map[string]bool{legacycompile.DefaultContentTarget: true}
	if rep != nil {
		for _, path := range attributePathsFor(rep, plane, ph, orgScope) {
			if contract.NamespaceOf(path) != contract.NsArgs {
				continue
			}
			args[strings.TrimPrefix(path, "args.")] = pdp.TypeAny
		}
		for _, pol := range rep.PoliciesForPhase(plane, ph, orgScope) {
			for _, o := range pol.Obligations {
				if o.Type == contract.ObFieldRedact && o.Target != "" {
					leaves[o.Target] = true
				}
			}
		}
	}
	var leafList []string
	for l := range leaves {
		leafList = append(leafList, l)
	}
	sort.Strings(leafList)
	return &pdp.Registry{
		Actions: map[string]pdp.ActionEntry{
			id.String(): {
				ID: id, Tags: []string{"legacy_plane"},
				MaxDelegationDepth: 3,
				Arguments:          args,
				PayloadLeaves:      leafList,
			},
		},
		Realms: map[string]bool{realm: true},
	}
}

// attributePathsFor returns every attribute path any contributing row reads on
// a plane and phase, compiled or not.
func attributePathsFor(rep *legacycompile.Report, plane legacycompile.Plane, ph legacycompile.Phase, orgScope string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, rec := range rep.Records {
		if rec.Source.OrgScope != orgScope || !rec.ContributesOnPhase(plane, ph) {
			continue
		}
		for _, pr := range rec.Planes {
			if pr.Plane != plane {
				continue
			}
			if ph != "" && pr.Phase != "" && pr.Phase != ph {
				continue
			}
			for _, p := range pr.AttributePaths {
				add(p)
			}
			for _, pol := range pr.Policies {
				for _, p := range pol.Where.Paths() {
					add(p)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// BuildCorpus generates the replay cases for one plane.
//
// Coverage is per-plane AND per-policy-row BY CONSTRUCTION, not by sampling: a
// case is generated for every source row that compiled a policy on the plane,
// so an unexercised row can only appear when a case failed to reach the row it
// was generated for - which is exactly the condition the coverage report is
// there to surface. A sampling corpus would instead report clean coverage of
// whatever it happened to touch.
//
// Three case families per row:
//
//	fires      the row's detector matched, or its conditions hold
//	quiet      the row's detector ran and did not match
//	unrun      the row's detector did not run at all
//
// The third family exists because it is the one the legacy engines cannot
// express. It is where ADR-065's tri-state changes the answer, and a corpus
// without it would report a clean migration and then meet the change in
// production.
func BuildCorpus(rep *legacycompile.Report, plane legacycompile.Plane, orgScope string, rows map[string]RowFacts, opts legacycompile.Options) []Case {
	return BuildCorpusForPhase(rep, plane, "", orgScope, rows, opts)
}

// BuildCorpusForPhase generates the replay cases for one plane and one legacy
// phase. RunAll passes a phase only for a plane whose spec evaluates more than
// one, so a two-phase plane gets one corpus per phase against one world per
// phase - the shape production evaluates in - and every other caller passes ""
// and gets the whole plane.
func BuildCorpusForPhase(rep *legacycompile.Report, plane legacycompile.Plane, phase legacycompile.Phase, orgScope string, rows map[string]RowFacts, opts legacycompile.Options) []Case {
	var cases []Case
	statics, dynamics := rowsOnPlane(rep, plane, phase, orgScope)

	// The quiet baseline: every detector on the plane RAN and reported no
	// match, and every dynamic condition field the plane's rows read carries a
	// value that fails its condition.
	//
	// Populating the other rows' fields is what makes a case vary ONE thing.
	// Leaving them out would leave those attributes unknown, an unknown
	// constraint makes the whole decision Indeterminate, and every case on a
	// plane carrying a dynamic row would then differ for a reason that has
	// nothing to do with the row the case was generated for. The tri-state
	// behaviour is still exercised - deliberately, by the detector_did_not_run
	// family - rather than leaking into every other case as noise.
	allQuiet := map[string]bool{}
	for _, id := range statics {
		allQuiet[id] = false
	}
	baseFields := map[string]any{}
	for _, id := range dynamics {
		for k, v := range violatingFields(rows[RowKey("dynamic_policies", id)]) {
			baseFields[k] = v
		}
	}

	// The case id carries the org scope, because a plane now has one corpus
	// per org and two cases that differ only in org must not share an id. A
	// phase-scoped corpus carries the phase too, because the two phases of one
	// plane are two corpora and their cases must not collide.
	prefix := string(plane)
	if phase != "" {
		prefix += ":" + string(phase)
	}
	prefix += "@" + orgScope
	base := func(id string) Case {
		verdicts := map[string]bool{}
		for k, v := range allQuiet {
			verdicts[k] = v
		}
		fields := map[string]any{}
		for k, v := range baseFields {
			fields[k] = v
		}
		return Case{
			ID: id, Plane: plane, Phase: phase, Org: orgScope, Principal: "alice",
			Action: ActionID, DetectorVerdicts: verdicts,
			Fields: fields, Posture: opts.Posture, Options: opts,
		}
	}

	// The baseline: every detector ran, nothing matched, no dynamic condition
	// holds. This is the case that exercises default-deny, and it is generated
	// once per plane rather than per row.
	cases = append(cases, base(prefix+"/baseline_nothing_matches"))

	// EVERY row firing at once. Without it no case ever puts two rows in one
	// determining set, so the combining algebra is never exercised - and on the
	// proxy tier, where the engine returns ONE result out of a first-match and
	// a strictest-segment, the reduction that models it would never run on more
	// than one element. A corpus of one-row-at-a-time cases reports full
	// coverage of a policy set whose interactions it has not touched.
	if len(statics)+len(dynamics) > 1 {
		all := base(prefix + "/all_rows_fire")
		for _, id := range statics {
			all.DetectorVerdicts[id] = true
		}
		for _, id := range dynamics {
			for k, v := range satisfyingFields(rows[RowKeyFor("dynamic_policies", id)]) {
				all.Fields[k] = v
			}
		}
		// No ExercisesRows claim: two dynamic rows reading the same field with
		// incompatible requirements clobber each other in Fields, so this case
		// cannot promise to reach all of them. It is here to exercise
		// COMBINING, and the per-row cases carry the coverage claims.
		all.Groups = allSegments(rows)
		cases = append(cases, all)
	}

	for _, policyID := range statics {
		fires := base(prefix + "/static/" + policyID + "/fires")
		fires.DetectorVerdicts[policyID] = true
		fires.ExercisesRows = []string{RowKeyFor("static_policies", policyID)}
		fires.Groups = groupsForRow(rows, policyID)
		cases = append(cases, fires)

		unrun := base(prefix + "/static/" + policyID + "/detector_did_not_run")
		delete(unrun.DetectorVerdicts, policyID)
		// No ExercisesRows claim. This case exists to show the row NOT being
		// reached: the detector is unknown, so on the ADR-065 side the policy
		// lands in Determining.Unknown rather than in a matched set, and on the
		// legacy side it simply does not match. Claiming it would assert the
		// opposite of what the case is for.
		unrun.Groups = groupsForRow(rows, policyID)
		cases = append(cases, unrun)
	}

	for _, policyID := range dynamics {
		facts := rows[RowKeyFor("dynamic_policies", policyID)]
		fires := base(prefix + "/dynamic/" + policyID + "/fires")
		for k, v := range satisfyingFields(facts) {
			fires.Fields[k] = v
		}
		fires.ExercisesRows = []string{RowKeyFor("dynamic_policies", policyID)}
		fires.Groups = groupsForRow(rows, policyID)
		cases = append(cases, fires)

		quiet := base(prefix + "/dynamic/" + policyID + "/does_not_fire")
		for k, v := range violatingFields(facts) {
			quiet.Fields[k] = v
		}
		// Likewise no claim: this case is the row NOT firing.
		quiet.Groups = groupsForRow(rows, policyID)
		cases = append(cases, quiet)
	}

	// Content-detector verdicts, LAST, from each case's FINAL field map. The
	// dynamic substrate's content conditions compile to a per-row detector,
	// and the detector's verdict for a case must be exactly what the legacy
	// operators say about the fields the case ended up carrying - computed
	// after every family above has finished mutating Fields, because on the
	// all-rows case two rows' satisfying values clobber each other and a
	// verdict computed from a row's own values would then disagree with the
	// legacy side for a corpus reason rather than a migration one.
	for i := range cases {
		cases[i].ContentVerdicts = contentVerdictsFor(dynamics, rows, cases[i])
	}
	return cases
}

// contentVerdictsFor computes each dynamic row's content-detector verdict for
// one case, using the legacy condition semantics over the case's final fields.
func contentVerdictsFor(dynamics []string, rows map[string]RowFacts, c Case) map[string]bool {
	out := map[string]bool{}
	for _, policyID := range dynamics {
		conds, err := rows[RowKeyFor("dynamic_policies", policyID)].conditions()
		if err != nil {
			continue
		}
		verdict, has := true, false
		for _, cond := range conds {
			if !legacycompile.IsContentOperator(cond.Operator) {
				continue
			}
			has = true
			if !legacyConditionMatches(cond, c) {
				verdict = false
			}
		}
		if has {
			out[legacycompile.DynamicContentDetectorPath(policyID)] = verdict
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// allSegments returns every segment any row is scoped to, so the all-fire case
// is a member of all of them and a segment-scoped row is not excluded from the
// one case that exercises combining.
func allSegments(rows map[string]RowFacts) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range rows {
		if f.SegmentID != "" && !seen[f.SegmentID] {
			seen[f.SegmentID] = true
			out = append(out, f.SegmentID)
		}
	}
	sort.Strings(out)
	return out
}

func groupsForRow(rows map[string]RowFacts, policyID string) []string {
	for _, table := range []string{"static_policies", "dynamic_policies"} {
		if f, ok := rows[RowKey(table, policyID)]; ok && f.SegmentID != "" {
			return []string{f.SegmentID}
		}
	}
	return nil
}

func rowsOnPlane(rep *legacycompile.Report, plane legacycompile.Plane, phase legacycompile.Phase, orgScope string) (statics, dynamics []string) {
	seenS, seenD := map[string]bool{}, map[string]bool{}
	for _, rec := range rep.Records {
		if rec.Source.OrgScope != orgScope {
			continue
		}
		// Keyed on what the LEGACY engine enforces, not on what compiled. A
		// corpus generated only from compiled rows would never exercise the
		// rows the migration has not solved, which are the rows most likely to
		// produce a difference. Phase-scoped, because a phase-scoped corpus
		// must not claim - or carry attributes for - a row the pass it models
		// never evaluates.
		if !rec.ContributesOnPhase(plane, phase) {
			continue
		}
		switch rec.Source.Table {
		case "static_policies":
			if !seenS[rec.Source.PolicyID] {
				seenS[rec.Source.PolicyID] = true
				statics = append(statics, rec.Source.PolicyID)
			}
		case "dynamic_policies":
			if !seenD[rec.Source.PolicyID] {
				seenD[rec.Source.PolicyID] = true
				dynamics = append(dynamics, rec.Source.PolicyID)
			}
		}
	}
	sort.Strings(statics)
	sort.Strings(dynamics)
	return statics, dynamics
}

// satisfyingFields builds field values that make every condition of a row
// hold, so the row fires on the legacy side.
func satisfyingFields(f RowFacts) map[string]any {
	out := map[string]any{}
	conds, err := f.conditions()
	if err != nil {
		return out
	}
	for _, c := range conds {
		switch c.Operator {
		case "equals":
			out[c.Field] = c.Value
		case "not_equals":
			out[c.Field] = fmt.Sprintf("%v-not", c.Value)
		case "in":
			if items, ok := toAnyList(c.Value); ok && len(items) > 0 {
				out[c.Field] = items[0]
			}
		case "not_in":
			out[c.Field] = "value-outside-the-list"
		case "greater_than":
			if n, ok := toFloat(c.Value); ok {
				out[c.Field] = n + 1
			}
		case "less_than":
			if n, ok := toFloat(c.Value); ok {
				out[c.Field] = n - 1
			}
		case "contains", "contains_any":
			out[c.Field] = fmt.Sprintf("%v", c.Value)
		case "regex":
			// The pattern's own TEXT rarely matches the pattern: the seeded
			// tenant-isolation rule `tenant_id\s*[!=<>]+` does not match the
			// literal string "tenant_id\s*[!=<>]+", so a corpus that supplied
			// the text as the value generated a fires case neither engine
			// fired - a corpus defect the gate reported on every dynamic
			// plane. A matching example is DERIVED from the pattern's syntax
			// tree instead, and verified against the pattern before use.
			if pattern, ok := c.Value.(string); ok {
				if example, ok := regexExample(pattern); ok {
					out[c.Field] = example
				} else {
					// No example could be derived (or the pattern does not
					// compile, in which case the condition can never hold).
					// The pattern text keeps the field populated so the case
					// still varies one thing; the row simply does not fire,
					// and if it carried a coverage claim the gate says so.
					out[c.Field] = pattern
				}
			}
		case "not_contains":
			out[c.Field] = "zzz-nothing-in-common"
		}
	}
	return out
}

// regexExample derives a string matching a pattern by walking its parsed
// syntax tree, taking the first branch of every alternation and the minimum
// count of every repetition. The result is VERIFIED against the pattern; a
// derivation that does not actually match reports failure rather than handing
// the corpus a value that looks intentional.
func regexExample(pattern string) (string, bool) {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return "", false
	}
	var build func(r *syntax.Regexp) string
	build = func(r *syntax.Regexp) string {
		switch r.Op {
		case syntax.OpLiteral:
			return string(r.Rune)
		case syntax.OpCharClass:
			if len(r.Rune) > 0 {
				return string(r.Rune[0])
			}
			return ""
		case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
			return "a"
		case syntax.OpConcat:
			var b strings.Builder
			for _, sub := range r.Sub {
				b.WriteString(build(sub))
			}
			return b.String()
		case syntax.OpAlternate, syntax.OpCapture:
			if len(r.Sub) > 0 {
				return build(r.Sub[0])
			}
			return ""
		case syntax.OpStar, syntax.OpQuest:
			return ""
		case syntax.OpPlus:
			return build(r.Sub[0])
		case syntax.OpRepeat:
			var b strings.Builder
			for i := 0; i < r.Min; i++ {
				b.WriteString(build(r.Sub[0]))
			}
			return b.String()
		default:
			// Anchors, boundaries and the empty match contribute nothing.
			return ""
		}
	}
	example := build(re)
	matched, err := regexp.MatchString(pattern, example)
	if err != nil || !matched {
		return "", false
	}
	return example, true
}

// violatingFields builds field values that make the FIRST condition fail, so
// the row does not fire. The first is enough: the legacy engine short-circuits
// on the first non-match.
func violatingFields(f RowFacts) map[string]any {
	out := satisfyingFields(f)
	conds, err := f.conditions()
	if err != nil || len(conds) == 0 {
		return out
	}
	c := conds[0]
	switch c.Operator {
	case "equals":
		out[c.Field] = fmt.Sprintf("%v-different", c.Value)
	case "not_equals":
		out[c.Field] = c.Value
	case "in":
		out[c.Field] = "value-outside-the-list"
	case "not_in":
		if items, ok := toAnyList(c.Value); ok && len(items) > 0 {
			out[c.Field] = items[0]
		}
	case "greater_than":
		if n, ok := toFloat(c.Value); ok {
			out[c.Field] = n - 1
		}
	case "less_than":
		if n, ok := toFloat(c.Value); ok {
			out[c.Field] = n + 1
		}
	case "contains", "contains_any", "regex":
		out[c.Field] = "zzz-nothing-in-common"
	case "not_contains":
		out[c.Field] = fmt.Sprintf("%v", c.Value)
	}
	return out
}
