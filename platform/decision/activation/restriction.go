// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation

import (
	"fmt"
	"sort"
	"strings"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/registry"
)

// THE PLANE RESTRICTION (#3895)
//
// The shipped corpus is the UNION of the platform's controls across every
// enforcement plane: ADR-065 removed execution location from policy identity,
// deliberately, so a control says WHAT it governs and never WHERE. A plane
// enforcing it still has to produce the control's inputs, and no plane
// produces all of them.
//
// MEASURED on the decide plane with the whole corpus activated: four
// dynamic-substrate constraints resolve UNKNOWN and the engine answers
// ERROR/unknown_constraint on every request; supplying every signal as
// authoritatively absent leaves `sys_dyn_gdpr` unknown on `principal.region`
// and the answer is still ERROR. Both are correct behaviour from the engine -
// an unresolvable constraint must not become a permit - and both are the wrong
// question. `decide` runs the STATIC substrate only. It has no dynamic
// evaluator, no risk scorer, no media pipeline and no region resolver, so the
// twenty-one dynamic-derived controls are not controls it is failing to
// evaluate; they are controls that do not run there at all.
//
// So the engine on a plane activates the controls that BIND on that plane, and
// the set is DERIVED from the three declarations that already record it:
//
//   - the SUBSTRATE: legacycompile.SpecFor(plane).Substrates says whether the
//     plane reads static_policies, dynamic_policies or both, and a corpus
//     policy's identifier records which table it was compiled from;
//   - the DETECTOR's plane list: registry's shipped census carries a `planes`
//     column per detector, and Catalog.CheckDetectorSelection already refuses
//     a selection of a plane that cannot run one;
//   - the plane's CATEGORY ADMISSION (#3895 PR-A2):
//     legacycompile.SpecFor(plane).Admission says which categories the plane's
//     call sites pass to the evaluator, welded to the real Categories
//     expressions by guards in platform/agent and platform/orchestrator.
//
// THE THIRD ARM EXISTS BECAUSE THE SECOND IS A LOAD MODEL. The census `planes`
// column is derived from the compiler's per-row Record against a migrated
// database: a row is listed on every plane whose loader returns it. Every
// shared-engine call site then narrows that set by category before a pattern
// runs, so a loaded row outside the filter never evaluates. MEASURED on decide
// before this arm existed: the four system security-admin controls bound there,
// while decide's filter (mcpInputPolicyCategories plus the pii-* family) never
// admits category `security-admin` - so their detector signals are never
// produced, and an enforcing anchored engine answered ERROR on EVERY request.
// Dropping a loaded-but-unadmitted control is the restriction telling the truth
// about what the plane can produce, not a narrowing of enforcement: the legacy
// engine does not evaluate it there either.
//
// None is a list written here. A plane added to the model, a detector whose
// plane set changes, a call site whose category filter changes, or a control
// moved between substrates all move this set without anybody editing it - which
// is the property #3877's path triple and #3940's module-root list both lacked.
//
// WHAT THIS IS NOT: it is not a per-deployment ceiling. No configuration WIDENS
// it, because a plane cannot be configured into producing a signal it has no
// code for. But configuration can NARROW what a site actually evaluates below
// this admission, per deployment, and nothing here reads that: decide's site
// passes MCP_STATIC_POLICIES_SKIP_CATEGORIES as EvalOptions.SkipCategories, and
// skips the shared-engine evaluation entirely when detection is disabled for
// the connector. On an enforcing organization with an active document, a
// skipped category's signal is then absent, so every control reading it is
// UNKNOWN and the engine answers ERROR on every request that reaches one:
// fail-closed and opt-in, an availability hazard rather than a security one.
// The levers are #4027; tying them to an enforcing plane's admission is #4032.

// corpusPolicySubstrate recovers the legacy table a corpus policy was compiled
// from, out of its identifier.
//
// The identifier shape is `corpus:<table>:<sanitized policy id>` and is
// produced by legacycompile's corpus builder. It is parsed rather than carried
// as a field because the corpus artifact is the shipped one and adding a field
// to it would change every deployment's system-corpus digest - and the
// identifier already carries the fact losslessly.
//
// RestrictToScope REFUSES a policy whose identifier it cannot parse rather than
// treating it as out-of-plane, and the subtest
// "every shipped control names a substrate this package can read" (in
// activation/restriction_test.go, under TestTheRestrictionIsDerivedAndBothArmsFire)
// drives every declared plane through it. A corpus whose identifier shape
// changed therefore fails loudly instead of silently classifying every control
// as out-of-plane on every plane, which would empty the restriction and be
// caught a second time by the empty-restriction refusal.
func corpusPolicySubstrate(id string) (legacycompile.Substrate, bool) {
	rest, ok := strings.CutPrefix(id, "corpus:")
	if !ok {
		return "", false
	}
	table, _, ok := strings.Cut(rest, ":")
	if !ok {
		return "", false
	}
	switch table {
	case "static_policies":
		return legacycompile.SubstrateStatic, true
	case "dynamic_policies":
		return legacycompile.SubstrateDynamic, true
	default:
		return "", false
	}
}

// censusFact is what the shipped detector census records about one detector
// that the restriction reads: the planes that LOAD its row, and the category
// the row was seeded with, which is what a call site's filter admits or not -
// and what an organization's recorded override is keyed by (#4045), with the
// severity a replacement's obligations record.
type censusFact struct {
	planes   []string
	category string
	severity string
}

// detectorCensusBySignalPath indexes the shipped detector census by the
// attribute path a compiled policy reads it through.
//
// KEYED ON THE PATH, not on the policy id, because the path is what the corpus
// policy actually carries and the two are related by a sanitising encoding this
// package must not reimplement. registry.DetectorID.SignalPath is the function
// that BUILT the path, so asking it is asking the builder.
func detectorCensusBySignalPath() (map[string]censusFact, error) {
	rows, err := registry.ShippedCensus()
	if err != nil {
		return nil, fmt.Errorf("activation: reading the shipped detector census: %w", err)
	}
	out := make(map[string]censusFact, len(rows))
	for _, r := range rows {
		out[registry.DetectorID(r.PolicyID).SignalPath()] = censusFact{planes: r.Planes, category: r.Category, severity: r.Severity}
	}
	return out, nil
}

// RestrictToScope returns the shipped corpus restricted to the controls that
// bind on one enforcement scope - a plane, or one phase of a two-phase plane -
// and the reason that names what it left out.
//
// The returned document is a NEW document carrying the SAME policy values, so
// the anchor's subset check compares byte-identical policies; nothing here
// edits a control.
//
// # THE PHASE ARMS (#3564)
//
// A two-phase plane is two restrictions. The census `planes` column says a row
// loads on the plane in SOME phase, and per-site admission says what each phase
// evaluates. So for a named phase two arms narrow further:
//
//   - LOAD: the row must load in that phase. It is derived from the census
//     itself - a row loads on this plane in phase P exactly when a WITNESS
//     plane lists it: a single-phase plane on the same read path whose only
//     phase is P. compileStaticForPlane decides a row's presence on the
//     runtime-phase path from the row's stored phase and the evaluated phase
//     alone, so every plane on that path agrees about a phase, and
//     TestThePhaseWitnessesPartitionEveryTwoPhasePlanesLoad holds the census
//     to that in both directions. A phase with no witness is refused, not
//     assumed.
//   - CATEGORY: legacycompile.AdmissionFor(plane, phase), the union of the
//     sites that evaluate that phase.
//
// # THE BINDING ARM (#4046)
//
// A control whose legacy engines resolve a different action depending on the
// scope - the request phase's `warn` against the response phase's `redact` (the
// tier plane's action column was the other case, retired by #4253) - ships
// as one policy per action (legacycompile.CorpusVariantIDFor), and the shipped
// corpus binds each to the scopes that resolve it
// (pdp.SystemCorpusScopeBindings). A bound policy is kept only on its scopes,
// which is a leave-out like every other arm, so the anchor is unchanged. A
// split control a scope admits must keep exactly one action there, and a
// binding to an undeclared scope is refused.
func RestrictToScope(scope legacycompile.EnforcementScope) (*pdp.Document, string, error) {
	shipped, err := pdp.SystemCorpusDocument()
	if err != nil {
		return nil, "", err
	}
	bindings, err := pdp.SystemCorpusScopeBindings()
	if err != nil {
		return nil, "", err
	}
	return restrictToScope(scope, shipped, bindingsFor(shipped, bindings))
}

// OrganizationTemplateForScope is the organization template
// (pdp.SystemCorpusOrganizationTemplate) restricted to what scope evaluates, by
// the arms RestrictToScope applies to the shipped corpus. While no organization
// document is active the implicit bundle carries it, and a scope must never
// bind a control whose detector it does not run: that control would be UNKNOWN
// on every request and refuse it. Its binding arm reads the template's own
// scope bindings: a template redaction is split by discharge (#4131), redact
// where the scope can carry it out and warn where it cannot.
func OrganizationTemplateForScope(scope legacycompile.EnforcementScope) (*pdp.Document, error) {
	template, err := pdp.SystemCorpusOrganizationTemplate()
	if err != nil {
		return nil, err
	}
	bindings, err := pdp.SystemCorpusScopeBindings()
	if err != nil {
		return nil, err
	}
	doc, _, err := restrictToScope(scope, template, bindingsFor(template, bindings))
	return doc, err
}

// bindingsFor is the part of the shipped scope bindings that names doc's own
// policies. The system document and the organization template are restricted
// separately, and each is judged by the bindings of the policies it carries.
func bindingsFor(doc *pdp.Document, all map[string][]string) map[string][]string {
	out := map[string][]string{}
	for _, p := range doc.Policies {
		if scopes, bound := all[p.ID]; bound {
			out[p.ID] = scopes
		}
	}
	return out
}

// unboundTemplateControls names, in doc's order, the policies doc carries under
// an organization template id that OrganizationTemplateForScope does not keep on
// scope. A published document carries the template's controls by their ids, and
// its copy of one binds where the template's control binds: restrictToScope
// keeps or drops whole policies by what the shipped control reads and never
// rewrites one, so the restriction is keyed on the id.
func unboundTemplateControls(scope legacycompile.EnforcementScope, doc *pdp.Document) ([]string, error) {
	template, err := pdp.SystemCorpusOrganizationTemplate()
	if err != nil {
		return nil, err
	}
	scoped, err := OrganizationTemplateForScope(scope)
	if err != nil {
		return nil, err
	}
	bound := make(map[string]bool, len(scoped.Policies))
	for _, p := range scoped.Policies {
		bound[p.ID] = true
	}
	shipped := make(map[string]bool, len(template.Policies))
	for _, p := range template.Policies {
		shipped[p.ID] = true
	}
	var unbound []string
	for _, p := range doc.Policies {
		if shipped[p.ID] && !bound[p.ID] {
			unbound = append(unbound, p.ID)
		}
	}
	return unbound, nil
}

// TemplateOmissionReport says which of the organization template's policies a
// document does not carry. The document an organization activates replaces the
// implicit bundle's template, so each policy it omits stops deciding for that
// organization; until the authoring surface seeds every draft from the
// template, publish and activation return this report, so dropping a template
// control is a visible edit rather than a silent one. It counts POLICIES, not
// controls: a template redaction ships as two policies bound by discharge
// (#4131), and a document carrying only one of them drops the control on the
// other's scopes.
type TemplateOmissionReport struct {
	Omitted []string `json:"omitted"`
	Of      int      `json:"of"`
	Message string   `json:"message"`
}

// ReportTemplateOmissions is doc's report, nil when doc carries every control of
// the organization template.
func ReportTemplateOmissions(doc *pdp.Document) (*TemplateOmissionReport, error) {
	template, err := pdp.SystemCorpusOrganizationTemplate()
	if err != nil {
		return nil, err
	}
	carried := make(map[string]bool, len(doc.Policies))
	for _, p := range doc.Policies {
		carried[p.ID] = true
	}
	var omitted []string
	for _, p := range template.Policies {
		if !carried[p.ID] {
			omitted = append(omitted, p.ID)
		}
	}
	if len(omitted) == 0 {
		return nil, nil
	}
	sort.Strings(omitted)
	return &TemplateOmissionReport{
		Omitted: omitted, Of: len(template.Policies),
		Message: fmt.Sprintf("this document omits %d of the %d template policies: %s", len(omitted), len(template.Policies), strings.Join(omitted, ", ")),
	}, nil
}

// ReportArtifactTemplateOmissions is ReportTemplateOmissions over an artifact's
// document, the form a transport holds at publish and at activation.
func ReportArtifactTemplateOmissions(art *authoring.Artifact) (*TemplateOmissionReport, error) {
	doc, err := art.Document()
	if err != nil {
		return nil, err
	}
	return ReportTemplateOmissions(&doc.Policy)
}

// restrictToScope is RestrictToScope over a given shipped document and its
// scope bindings, so the binding arm can be driven with a split the embedded
// artifact does not carry.
func restrictToScope(scope legacycompile.EnforcementScope, shipped *pdp.Document, bindings map[string][]string) (*pdp.Document, string, error) {
	scope, err := legacycompile.ScopeFor(scope.Plane, scope.Phase)
	if err != nil {
		return nil, "", fmt.Errorf("activation: which of the platform's controls bind on %s cannot be derived: %w", scope, err)
	}
	plane := string(scope.Plane)
	spec := legacycompile.MustSpecFor(scope.Plane)
	substrates := map[legacycompile.Substrate]bool{}
	for _, s := range spec.Substrates {
		substrates[s] = true
	}
	// A static scope whose admission cannot be derived is REFUSED, not
	// restricted to nothing. The zero value admits no category, so it would
	// drop every judged control and read as a plane that evaluates nothing - a
	// missing declaration dressed as a fact about the plane.
	var admission legacycompile.CategoryAdmission
	if substrates[legacycompile.SubstrateStatic] {
		for _, ph := range scope.Phases() {
			a, err := legacycompile.AdmissionFor(scope.Plane, ph)
			if err != nil {
				return nil, "", fmt.Errorf("activation: %s evaluates the static substrate and its category admission cannot be "+
					"derived, so which of its loaded controls its call sites actually evaluate is unknown: %w", scope, err)
			}
			admission = admission.Union(a)
		}
	}
	var witnesses []string
	if scope.Phase != "" {
		witnesses = phaseWitnesses(spec, scope.Phase)
		if len(witnesses) == 0 {
			return nil, "", fmt.Errorf("activation: no single-phase plane on the %s read path evaluates the %s phase, so which "+
				"of %s's loaded controls load in that phase cannot be derived from the census", spec.StaticReadPath, scope.Phase, scope)
		}
	}
	census, err := detectorCensusBySignalPath()
	if err != nil {
		return nil, "", err
	}

	out := &pdp.Document{Root: shipped.Root, Version: shipped.Version, InteractiveRealms: shipped.InteractiveRealms}
	var droppedSubstrate, droppedDetector, droppedPhase, droppedCategory, droppedBinding []string
	// admitted are the controls every arm before the binding arm keeps.
	var admitted []pdp.Policy
	// uncensused counts the controls this plane KEEPS that the detector arm
	// could not judge, because no signal path they read is in the census. It is
	// reported separately from the drops for a reason the first version of this
	// function got wrong: saying "0 whose detector's registry record does not
	// list it" reads as "every one of these was checked and passed", and on a
	// dynamic-substrate plane NONE of them were checked at all - the census
	// covers static_policies only, so a dynamic control's signal path is never
	// in the index. A count of "did not fail" reported as "passed" is the
	// difference between a measurement and a claim.
	uncensused := 0
	for _, p := range shipped.Policies {
		sub, ok := corpusPolicySubstrate(p.ID)
		if !ok {
			return nil, "", fmt.Errorf("activation: shipped corpus policy %q does not name the substrate it was compiled "+
				"from, so whether it binds on plane %q cannot be derived; the corpus identifier shape has changed", p.ID, plane)
		}
		if !substrates[sub] {
			droppedSubstrate = append(droppedSubstrate, p.ID)
			continue
		}
		path, fact, judged := censusFactFor(p, census)
		if !judged {
			uncensused++
			admitted = append(admitted, p)
			continue
		}
		if !listsPlane(fact.planes, plane) {
			droppedDetector = append(droppedDetector, fmt.Sprintf("%s (detector %s runs on %v)", p.ID, path, fact.planes))
			continue
		}
		// THE PHASE ARM, on a scope that names one phase of a two-phase plane:
		// the row loads on the plane, and must load in THIS phase.
		if scope.Phase != "" && !listsAny(fact.planes, witnesses) {
			droppedPhase = append(droppedPhase, fmt.Sprintf("%s (detector %s runs on %v, none of which evaluates only the %s phase)", p.ID, path, fact.planes, scope.Phase))
			continue
		}
		// THE CATEGORY-ADMISSION ARM, after the load arms: a row the scope does
		// not load is dropped for that reason, and only a loaded row is asked
		// whether any call site in the scope evaluates its category.
		if !admission.Admits(fact.category) {
			droppedCategory = append(droppedCategory, fmt.Sprintf("%s (detector %s, category %q)", p.ID, path, fact.category))
			continue
		}
		admitted = append(admitted, p)
	}
	// THE BINDING ARM (#4046), LAST. A control whose legacy action differs by
	// scope ships as one policy per action, each bound to the scopes that
	// resolve it, and a bound policy is kept only on its scopes. It runs after
	// every other arm so a control this scope does not load, or whose category
	// it does not admit, is dropped for THAT reason, and only an admitted
	// control is asked which of its variants this scope resolves.
	declared := map[string]bool{}
	for _, s := range legacycompile.AllScopes() {
		declared[s.String()] = true
	}
	// A SPLIT IS RECOGNISED FROM THE VARIANTS THE DOCUMENT CARRIES, not from the
	// bindings, and two facts about the artifact are checked before any scope
	// keeps anything: every per-scope variant is bound, and no scope is bound to
	// two actions of one control. A variant whose binding was dropped would
	// otherwise be kept on every scope beside its siblings, and a scope named by
	// two of a control's variants would let two actions decide it.
	split := map[string]bool{}
	boundAction := map[string]string{}
	ids := make([]string, 0, len(bindings))
	for id := range bindings {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		control, action, ok := legacycompile.CorpusControlOf(id)
		if !ok {
			return nil, "", fmt.Errorf("activation: the shipped corpus binds %q, which is not a corpus policy identifier", id)
		}
		split[control] = true
		for _, s := range bindings[id] {
			if !declared[s] {
				return nil, "", fmt.Errorf("activation: the shipped corpus binds %q to scope %q, which the model does not declare; "+
					"a control bound to a scope nothing enforces would be left out of every declared one", id, s)
			}
			key := control + "\x00" + s
			if prior, seen := boundAction[key]; seen && prior != action {
				return nil, "", fmt.Errorf("activation: the shipped corpus binds scope %q to two actions of %s (%q and %q); "+
					"a scope enforces one action per control", s, control, prior, action)
			}
			boundAction[key] = action
		}
	}
	whole, variants := map[string]bool{}, map[string]bool{}
	for _, p := range shipped.Policies {
		control, action, ok := legacycompile.CorpusControlOf(p.ID)
		if !ok {
			continue
		}
		if action == "" {
			whole[control] = true
			continue
		}
		split[control] = true
		variants[control] = true
		if _, bound := bindings[p.ID]; !bound {
			return nil, "", fmt.Errorf("activation: the shipped corpus carries %s, a per-scope variant of %s, with no scope binding; "+
				"an unbound variant would be kept on every scope beside the control's other actions", p.ID, control)
		}
	}
	splitControls := make([]string, 0, len(variants))
	for control := range variants {
		splitControls = append(splitControls, control)
	}
	sort.Strings(splitControls)
	for _, control := range splitControls {
		if whole[control] {
			return nil, "", fmt.Errorf("activation: the shipped corpus carries %s whole beside its per-scope variants; a scope a variant is "+
				"bound to would keep two policies for one control", control)
		}
	}
	admittedControls := map[string]bool{}
	keptControls := map[string]bool{}
	for _, p := range admitted {
		control, _, ok := legacycompile.CorpusControlOf(p.ID)
		if !ok {
			return nil, "", fmt.Errorf("activation: shipped corpus policy %q is not a corpus policy identifier, so which control it "+
				"belongs to cannot be derived", p.ID)
		}
		admittedControls[control] = true
		if scopes, bound := bindings[p.ID]; bound && !scopeListed(scopes, scope.String()) {
			droppedBinding = append(droppedBinding, fmt.Sprintf("%s (bound to %v)", p.ID, scopes))
			continue
		}
		keptControls[control] = true
		out.Policies = append(out.Policies, p)
	}
	// A SPLIT CONTROL THIS SCOPE ADMITS KEEPS ONE OF ITS ACTIONS. With every
	// variant bound and no scope bound to two actions, keeping none is the one
	// way left to get it wrong: the control would vanish from the scope with no
	// reason given, the silent leave-out the bindings exist to avoid.
	var problems []string
	for control := range split {
		if admittedControls[control] && !keptControls[control] {
			problems = append(problems, fmt.Sprintf("%s runs on %s and no policy the corpus split it into is bound there, "+
				"so it would vanish from this scope with no reason given", control, scope))
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return nil, "", fmt.Errorf("activation: the shipped corpus's scope bindings leave a control it runs out of %s:\n  %s",
			scope, strings.Join(problems, "\n  "))
	}
	// THE SCHEMA IS RESTRICTED WITH THE POLICIES. A document declaring an
	// attribute no remaining policy reads is harmless; one whose policies read
	// an attribute it does not declare is refused by Validate, and keeping the
	// full schema is the safe direction of the two. It is filtered anyway,
	// because an attribute nothing reads is an attribute a PIP would be asked
	// to produce for no reason.
	out.Attributes = schemasRead(out.Policies, shipped.Attributes)
	sort.Strings(droppedSubstrate)
	sort.Strings(droppedDetector)
	sort.Strings(droppedPhase)
	sort.Strings(droppedCategory)
	sort.Strings(droppedBinding)
	label := "the " + plane + " plane"
	if scope.Phase != "" {
		label = "the " + plane + " plane's " + string(scope.Phase) + " phase"
	}
	reason := fmt.Sprintf(
		"%s reads the %s substrate(s), so %d of the shipped corpus's %d controls do not run there: "+
			"%d compiled from a substrate this plane does not read, %d whose detector's registry record does not list it, "+
			"%d that do not load in the phase this scope evaluates, "+
			"%d whose detector's category no call site on this plane passes to the evaluator (category admission: %s), "+
			"%d whose legacy action differs by scope and is bound by the shipped corpus to other scopes (scope bindings). "+
			"Of the %d kept, %d were NOT judged by the detector arm at all because no signal path they read is in the "+
			"shipped census - the census covers static_policies only, so a dynamic control is never in it, and this is "+
			"reported rather than counted as a pass. "+
			"A plane cannot enforce a control whose inputs it has no code to produce, and asserting that such a "+
			"control did not fire would be a fail-open the tri-state exists to forbid",
		label, substrateNames(spec.Substrates), len(droppedSubstrate)+len(droppedDetector)+len(droppedPhase)+len(droppedCategory)+len(droppedBinding), len(shipped.Policies),
		len(droppedSubstrate), len(droppedDetector), len(droppedPhase), len(droppedCategory), admission, len(droppedBinding), len(out.Policies), uncensused)
	return out, reason, nil
}

// scopeListed reports whether a binding's scope list names this scope.
func scopeListed(scopes []string, scope string) bool {
	for _, s := range scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// RestrictToPlane is RestrictToScope for a single-phase plane, named in the
// plane vocabulary. A two-phase plane is refused: its phases bind different
// controls, so one answer for the plane would be wrong for one of them.
func RestrictToPlane(plane string) (*pdp.Document, string, error) {
	scope, err := legacycompile.ScopeFor(legacycompile.Plane(plane), "")
	if err != nil {
		return nil, "", fmt.Errorf("activation: which of the platform's controls bind on %s cannot be derived: %w", plane, err)
	}
	return RestrictToScope(scope)
}

func listsPlane(planes []string, plane string) bool {
	for _, p := range planes {
		if p == plane {
			return true
		}
	}
	return false
}

func listsAny(planes, candidates []string) bool {
	for _, c := range candidates {
		if listsPlane(planes, c) {
			return true
		}
	}
	return false
}

// phaseWitnesses are the planes whose listing of a row says it loads in one
// phase: single-phase planes on the same static read path whose only phase is
// that one. Derived from the plane model, so a plane added to it joins or
// leaves the witness set without an edit here.
func phaseWitnesses(spec legacycompile.PlaneSpec, ph legacycompile.Phase) []string {
	var out []string
	for _, p := range legacycompile.AllPlanes() {
		w := legacycompile.MustSpecFor(p)
		if p == spec.Plane || w.StaticReadPath != spec.StaticReadPath || len(w.Phases) != 1 || w.Phases[0] != ph {
			continue
		}
		out = append(out, string(p))
	}
	return out
}

// censusFactFor returns the census record of the censused detector a policy
// reads - its signal path and what the census says about it - and whether the
// census had an opinion at all.
//
// A policy reading NO censused detector path is KEPT, which is the permissive
// direction of the two, so the population it covers is measured rather than
// described. MEASURED against the shipped corpus at this writing: 21 of 118
// policies reference no censused detector, and they are 21 DYNAMIC and 0
// STATIC. The census covers `static_policies` only, so a dynamic-derived
// control's `signal.detector.dyn.*` path is never in it - which means this arm
// cannot judge a dynamic control at all, and on a dynamic plane every one of
// them is kept. That is correct: the SUBSTRATE arm is what places them, and it
// has already run.
//
// The consequence to keep in view is the static side being zero. It means no
// shipped static control currently reaches this fall-through, so a static
// control that acquires a condition over an environment or principal attribute
// would be the first - and it would be KEPT on every plane, to be visible as a
// failure to evaluate rather than silently dropped. The disjoint-and-total
// assertion in activation/restriction_test.go::TestTheRestrictionIsDerivedAndBothArmsFire
// is what notices if that population moves.
//
// The citation is on ONE LINE deliberately: an identifier wrapped across two
// comment lines resolves to no grep, which is the same failure as naming a test
// that does not exist.
// The caller counts the unjudged separately so the reason string cannot report
// them as checked, and it applies both census arms - the plane list and the
// category admission - to the SAME record, so the two can never be answered
// about two different detectors of one policy.
//
// IT IS FIRST-MATCH over the policy's signal paths, and that is a choice rather
// than an accident. MEASURED on the shipped corpus: no policy references more
// than one censused detector, so the choice is currently unobservable - and it
// is written down because the first control that references two is the one that
// would be classified by whichever path sorts first, in a direction nobody
// picked. When such a control lands, this needs to become an explicit ALL (keep
// only if every referenced detector lists the plane) or an explicit ANY, and
// TestNoShippedControlReferencesTwoCensusedDetectors is what fails on that day.
func censusFactFor(p pdp.Policy, census map[string]censusFact) (string, censusFact, bool) {
	for _, path := range p.ReferencedPaths() {
		if contract.NamespaceOf(path) != contract.NsSignal {
			continue
		}
		if fact, known := census[path]; known {
			return path, fact, true
		}
	}
	return "", censusFact{}, false
}

// schemasRead returns the schemas, in their order, of the attributes policies
// read. A restriction and an override's replacements each declare exactly what
// their own policies read.
func schemasRead(policies []pdp.Policy, schemas []pdp.AttributeSchema) []pdp.AttributeSchema {
	read := map[string]bool{}
	for _, p := range policies {
		for _, path := range p.ReferencedPaths() {
			read[path] = true
		}
	}
	var out []pdp.AttributeSchema
	for _, a := range schemas {
		if read[a.Path] {
			out = append(out, a)
		}
	}
	return out
}

func substrateNames(in []legacycompile.Substrate) string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, string(s))
	}
	sort.Strings(out)
	return strings.Join(out, "+")
}
