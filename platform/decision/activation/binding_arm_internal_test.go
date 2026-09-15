// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
)

// shippedAndBindings returns the embedded corpus and its bindings.
func shippedAndBindings(t *testing.T) (*pdp.Document, map[string][]string) {
	t.Helper()
	shipped, err := pdp.SystemCorpusDocument()
	if err != nil {
		t.Fatal(err)
	}
	bindings, err := pdp.SystemCorpusScopeBindings()
	if err != nil {
		t.Fatal(err)
	}
	return shipped, bindings
}

// policyIDs lists a document's policy identifiers in order.
func policyIDs(d *pdp.Document) []string {
	out := make([]string, 0, len(d.Policies))
	for _, p := range d.Policies {
		out = append(out, p.ID)
	}
	return out
}

// unsplitControlOnDecideAndElsewhere returns the table and row of a shipped
// control the corpus did NOT split, which decide keeps and at least one other
// declared scope keeps too. It is derived, so the tests below split a real
// control without naming one the corpus may split tomorrow.
func unsplitControlOnDecideAndElsewhere(t *testing.T, shipped *pdp.Document, bindings map[string][]string) (table, rowID string) {
	t.Helper()
	decide := legacycompile.MustScopeFor(legacycompile.PlaneDecide, "")
	keptBy, onDecide := map[string]int{}, map[string]bool{}
	for _, scope := range legacycompile.AllScopes() {
		doc, _, err := restrictToScope(scope, shipped, bindings)
		if err != nil {
			t.Fatalf("%s: %v", scope, err)
		}
		for _, p := range doc.Policies {
			keptBy[p.ID]++
			if scope.String() == decide.String() {
				onDecide[p.ID] = true
			}
		}
	}
	for _, p := range shipped.Policies {
		// A bare control: not a variant, not a "#n" sibling.
		if control, action, ok := legacycompile.CorpusControlOf(p.ID); !ok || action != "" || control != p.ID {
			continue
		}
		if !onDecide[p.ID] || keptBy[p.ID] < 2 {
			continue
		}
		parts := strings.SplitN(p.ID, ":", 3)
		if len(parts) != 3 {
			continue
		}
		row, ok := legacycompile.UnsanitizePolicyID(parts[2])
		if !ok || legacycompile.CorpusPolicyIDFor(parts[1], row) != p.ID {
			continue
		}
		return parts[1], row
	}
	t.Fatal("CONTROL: no shipped control is unsplit and kept by decide and by another scope; these tests would split nothing")
	return "", ""
}

// splitControl returns a copy of shipped in which one unsplit control is
// replaced by one variant per action pick names, and base's bindings plus the
// bindings that bind each variant to the scopes, among those keeping the
// unsplit control, pick names it for.
func splitControl(t *testing.T, shipped *pdp.Document, base map[string][]string, table, rowID string, pick func(legacycompile.EnforcementScope) string) (*pdp.Document, map[string][]string) {
	t.Helper()
	control := legacycompile.CorpusPolicyIDFor(table, rowID)
	var original *pdp.Policy
	out := &pdp.Document{Root: shipped.Root, Version: shipped.Version, InteractiveRealms: shipped.InteractiveRealms, Attributes: shipped.Attributes}
	for i := range shipped.Policies {
		if shipped.Policies[i].ID == control {
			original = &shipped.Policies[i]
			continue
		}
		out.Policies = append(out.Policies, shipped.Policies[i])
	}
	if original == nil {
		t.Fatalf("CONTROL: the shipped corpus carries no %s; this test splits a real control", control)
	}
	bindings := map[string][]string{}
	for id, scopes := range base {
		bindings[id] = append([]string(nil), scopes...)
	}
	variants := map[string]bool{}
	for _, scope := range legacycompile.AllScopes() {
		doc, _, err := restrictToScope(scope, shipped, base)
		if err != nil {
			t.Fatalf("%s: %v", scope, err)
		}
		if !slices.Contains(policyIDs(doc), control) {
			continue
		}
		id := legacycompile.CorpusVariantIDFor(table, rowID, pick(scope))
		variants[id] = true
		bindings[id] = append(bindings[id], scope.String())
	}
	for id := range variants {
		slices.Sort(bindings[id])
		v := *original
		v.ID = id
		out.Policies = append(out.Policies, v)
	}
	return out, bindings
}

// collapsedCorpus returns shipped with every split control's variants replaced
// by the policies of ONE of its actions, renamed to the control: the unsplit
// corpus a restriction with no bindings is the baseline for.
func collapsedCorpus(t *testing.T, shipped *pdp.Document) *pdp.Document {
	t.Helper()
	out := &pdp.Document{Root: shipped.Root, Version: shipped.Version, InteractiveRealms: shipped.InteractiveRealms, Attributes: shipped.Attributes}
	firstAction := map[string]string{}
	for _, p := range shipped.Policies {
		control, action, ok := legacycompile.CorpusControlOf(p.ID)
		if !ok {
			t.Fatalf("%s is not a corpus policy identifier", p.ID)
		}
		if action == "" {
			out.Policies = append(out.Policies, p)
			continue
		}
		if chosen, seen := firstAction[control]; seen && chosen != action {
			continue
		}
		firstAction[control] = action
		v := p
		v.ID = control
		if i := strings.Index(p.ID, "#"); i >= 0 {
			v.ID += p.ID[i:]
		}
		out.Policies = append(out.Policies, v)
	}
	if len(firstAction) == 0 {
		t.Fatal("CONTROL: the shipped corpus carries no per-scope variant; there is nothing to collapse")
	}
	return out
}

// TestTheBindingArmKeepsEachScopeTheControlsTheCollapsedCorpusKeeps holds the
// binding arm to what it adds to the restriction. Against the same corpus with
// every split collapsed back to one policy per control, and no bindings, every
// declared scope keeps the same CONTROLS, and every variant it keeps is bound to
// it. The EXPORTED restriction is compared, so a RestrictToScope that stopped
// reading the shipped bindings reds here; and every shipped variant must be kept
// by a scope it is bound to, or it is a policy no scope enforces.
func TestTheBindingArmKeepsEachScopeTheControlsTheCollapsedCorpusKeeps(t *testing.T) {
	shipped, bindings := shippedAndBindings(t)
	collapsed := collapsedCorpus(t, shipped)
	leftOut, keptWhereBound := 0, map[string]bool{}
	for _, scope := range legacycompile.AllScopes() {
		with, _, err := RestrictToScope(scope)
		if err != nil {
			t.Fatalf("%s: %v", scope, err)
		}
		// The template's redactions bound by discharge (#4131) are kept, or
		// not, by the template's own restriction.
		templateWith, err := OrganizationTemplateForScope(scope)
		if err != nil {
			t.Fatalf("%s: the template: %v", scope, err)
		}
		for _, p := range templateWith.Policies {
			if scopes, bound := bindings[p.ID]; bound {
				if !slices.Contains(scopes, scope.String()) {
					t.Errorf("%s keeps template policy %s, which is bound to %v", scope, p.ID, scopes)
				}
				keptWhereBound[p.ID] = true
			}
		}
		without, _, err := restrictToScope(scope, collapsed, map[string][]string{})
		if err != nil {
			t.Fatalf("%s over the collapsed corpus: %v", scope, err)
		}
		controlsWith, controlsWithout := map[string]bool{}, map[string]bool{}
		for _, p := range without.Policies {
			control, _, _ := legacycompile.CorpusControlOf(p.ID)
			controlsWithout[control] = true
		}
		for _, p := range with.Policies {
			control, _, _ := legacycompile.CorpusControlOf(p.ID)
			controlsWith[control] = true
			if scopes, bound := bindings[p.ID]; bound {
				if !slices.Contains(scopes, scope.String()) {
					t.Errorf("%s keeps %s, which is bound to %v", scope, p.ID, scopes)
				}
				keptWhereBound[p.ID] = true
			}
		}
		if fmt.Sprint(sortedKeys(controlsWith)) != fmt.Sprint(sortedKeys(controlsWithout)) {
			t.Errorf("%s keeps controls %v with the shipped bindings and %v from the collapsed corpus; binding a control's variants to their scopes must leave no control out and add none",
				scope, sortedKeys(controlsWith), sortedKeys(controlsWithout))
		}
		for _, p := range shipped.Policies {
			control, action, _ := legacycompile.CorpusControlOf(p.ID)
			if action != "" && controlsWith[control] && !slices.Contains(bindings[p.ID], scope.String()) {
				leftOut++
			}
		}
	}
	if leftOut == 0 {
		t.Fatal("no declared scope left out a variant bound elsewhere; the shipped bindings are not being read")
	}
	templatePolicy, census := templatePoliciesAndCensus(t)
	problems, dormant := unkeptBindingProblems(bindings, keptWhereBound, ReadDormantTemplateVariants(t), templatePolicy, census)
	for _, p := range problems {
		t.Error(p)
	}
	t.Logf("%d template variant(s) dormant by the ledger: %v", len(dormant), dormant)
}

// templatePoliciesAndCensus is the shipped template and, since #4253, the
// shipped system document, keyed by policy id, and the detector census the
// restriction reads.
func templatePoliciesAndCensus(t *testing.T) (map[string]pdp.Policy, map[string]censusFact) {
	t.Helper()
	template, err := pdp.SystemCorpusOrganizationTemplate()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]pdp.Policy{}
	for _, p := range template.Policies {
		out[p.ID] = p
	}
	// Since #4253 the ledger also lists system-document variants (the four
	// sys_admin_* :log policies), so the policies it may name include those.
	system, err := pdp.SystemCorpusDocument()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range system.Policies {
		out[p.ID] = p
	}
	census, err := detectorCensusBySignalPath()
	if err != nil {
		t.Fatal(err)
	}
	return out, census
}

// unkeptBindingProblems judges every binding no scope keeps against the ledger
// of dormant template variants (#4131, dormant_template_variants_test.go). An
// unkept binding is allowed only when the ledger lists it, it is an
// organization-template policy, its detector's category is the ledger's, and no
// scope it is bound to admits that category - the ledger row's own claim,
// checked. Every ledger row must name a binding no scope keeps, or it is stale.
func unkeptBindingProblems(bindings map[string][]string, kept map[string]bool, ledger map[string]DormantTemplateVariant,
	template map[string]pdp.Policy, census map[string]censusFact) (problems, dormant []string) {
	for id, scopes := range bindings {
		if kept[id] {
			continue
		}
		row, listed := ledger[id]
		p, isShipped := template[id]
		switch {
		case !listed:
			problems = append(problems, fmt.Sprintf("%s is bound to %v and none of those scopes keeps it; the corpus ships a policy no scope enforces", id, scopes))
		case !isShipped:
			problems = append(problems, fmt.Sprintf("the dormant ledger lists %s, which is not a shipped corpus policy", id))
		default:
			_, fact, judged := censusFactFor(p, census)
			switch {
			case !judged || fact.category != row.Category:
				problems = append(problems, fmt.Sprintf("the dormant ledger lists %s under category %q and its detector's category is %q", id, row.Category, fact.category))
			case admittedOnAnyScope(fact.category, scopes):
				problems = append(problems, fmt.Sprintf("the dormant ledger lists %s as admitted on no scope, and a scope it is bound to admits %q; the row is stale", id, fact.category))
			default:
				dormant = append(dormant, id)
			}
		}
	}
	for id := range ledger {
		if _, bound := bindings[id]; !bound {
			problems = append(problems, fmt.Sprintf("the dormant ledger lists %s, which the shipped corpus binds nowhere; the row is stale", id))
		} else if kept[id] {
			problems = append(problems, fmt.Sprintf("the dormant ledger lists %s, which a scope keeps; the row is stale", id))
		}
	}
	slices.Sort(problems)
	slices.Sort(dormant)
	return problems, dormant
}

// admittedOnAnyScope reports whether any of scopes admits category, by the
// category arm the restriction applies. A scope the model does not declare
// counts as admitting it, so it cannot excuse a binding as dormant.
func admittedOnAnyScope(category string, scopes []string) bool {
	declared := map[string]legacycompile.EnforcementScope{}
	for _, s := range legacycompile.AllScopes() {
		declared[s.String()] = s
	}
	for _, name := range scopes {
		s, ok := declared[name]
		if !ok {
			return true
		}
		for _, ph := range s.Phases() {
			if a, err := legacycompile.AdmissionFor(s.Plane, ph); err == nil && a.Admits(category) {
				return true
			}
		}
	}
	return false
}

// keptBoundPolicies is every bound policy some scope's restriction keeps: the
// system document's and the template's.
func keptBoundPolicies(t *testing.T, bindings map[string][]string) map[string]bool {
	t.Helper()
	kept := map[string]bool{}
	for _, scope := range legacycompile.AllScopes() {
		system, _, err := RestrictToScope(scope)
		if err != nil {
			t.Fatalf("%s: %v", scope, err)
		}
		template, err := OrganizationTemplateForScope(scope)
		if err != nil {
			t.Fatalf("%s: the template: %v", scope, err)
		}
		for _, doc := range []*pdp.Document{system, template} {
			for _, p := range doc.Policies {
				if _, bound := bindings[p.ID]; bound {
					kept[p.ID] = true
				}
			}
		}
	}
	return kept
}

// TestTheDormantLedgerIsTheOnlyExemption holds the exemption to the ledger by
// planting what it must refuse. On the shipped corpus it reports nothing and
// names exactly the ledger's ids as dormant. A FIFTH dormant variant - a copy of
// a listed one under an id the ledger does not carry, bound to the same scopes
// and reading the same detector - must be reported as a policy no scope
// enforces. A STALE row - the ledger naming a policy a scope keeps - must be
// reported as stale.
func TestTheDormantLedgerIsTheOnlyExemption(t *testing.T) {
	_, bindings := shippedAndBindings(t)
	kept := keptBoundPolicies(t, bindings)
	ledger := ReadDormantTemplateVariants(t)
	template, census := templatePoliciesAndCensus(t)

	problems, dormant := unkeptBindingProblems(bindings, kept, ledger, template, census)
	if len(problems) != 0 {
		t.Fatalf("the shipped corpus and ledger report %d problem(s): %v", len(problems), problems)
	}
	want := make([]string, 0, len(ledger))
	for id := range ledger {
		want = append(want, id)
	}
	slices.Sort(want)
	if fmt.Sprint(dormant) != fmt.Sprint(want) {
		t.Fatalf("dormant %v; want exactly the ledger's %v", dormant, want)
	}

	t.Run("a fifth dormant variant the ledger does not list is reported", func(t *testing.T) {
		listed := want[0]
		fifth := strings.Replace(listed, ":redact", "__planted_fifth:redact", 1)
		plantedBindings := map[string][]string{fifth: bindings[listed]}
		for id, scopes := range bindings {
			plantedBindings[id] = scopes
		}
		plantedTemplate := map[string]pdp.Policy{}
		for id, p := range template {
			plantedTemplate[id] = p
		}
		copied := template[listed]
		copied.ID = fifth
		plantedTemplate[fifth] = copied
		problems, _ := unkeptBindingProblems(plantedBindings, kept, ledger, plantedTemplate, census)
		if len(problems) != 1 || !strings.Contains(problems[0], fifth) || !strings.Contains(problems[0], "no scope enforces") {
			t.Fatalf("with a fifth dormant variant %s planted the check reported %v; want exactly the policy no scope enforces", fifth, problems)
		}
		t.Logf("PLANT reported: %s", problems[0])
	})

	t.Run("a ledger row naming a policy a scope keeps is reported as stale", func(t *testing.T) {
		var keptID string
		for id := range bindings {
			if kept[id] {
				if _, isTemplate := template[id]; isTemplate {
					keptID = id
					break
				}
			}
		}
		if keptID == "" {
			t.Fatal("PREMISE: no bound template policy is kept anywhere, so no stale row can be planted")
		}
		plantedLedger := map[string]DormantTemplateVariant{keptID: {PolicyID: keptID, Category: "pii_detection", Revisit: "#4230"}}
		for id, row := range ledger {
			plantedLedger[id] = row
		}
		problems, _ := unkeptBindingProblems(bindings, kept, plantedLedger, template, census)
		if len(problems) != 1 || !strings.Contains(problems[0], keptID) || !strings.Contains(problems[0], "stale") {
			t.Fatalf("with a stale row for %s planted the check reported %v; want exactly the stale row", keptID, problems)
		}
		t.Logf("PLANT reported: %s", problems[0])
	})

	// The check's other four branches, each planted alone and each reported as
	// exactly one problem naming what was planted.
	listed := want[0]
	plantedOnce := func(t *testing.T, b map[string][]string, l map[string]DormantTemplateVariant, id, phrase string) {
		t.Helper()
		problems, _ := unkeptBindingProblems(b, kept, l, template, census)
		if len(problems) != 1 || !strings.Contains(problems[0], id) || !strings.Contains(problems[0], phrase) {
			t.Fatalf("with %s planted the check reported %v; want exactly one problem naming it and saying %q", id, problems, phrase)
		}
		t.Logf("PLANT reported: %s", problems[0])
	}
	bindingsCopy := func() map[string][]string {
		b := map[string][]string{}
		for id, scopes := range bindings {
			b[id] = append([]string(nil), scopes...)
		}
		return b
	}
	ledgerCopy := func() map[string]DormantTemplateVariant {
		l := map[string]DormantTemplateVariant{}
		for id, row := range ledger {
			l[id] = row
		}
		return l
	}

	t.Run("a ledger row naming a bound policy outside the shipped corpus is reported", func(t *testing.T) {
		id := "corpus:static_policies:planted__not__template:redact"
		b, l := bindingsCopy(), ledgerCopy()
		b[id] = bindings[listed]
		l[id] = DormantTemplateVariant{PolicyID: id, Category: ledger[listed].Category, Revisit: "#4230"}
		plantedOnce(t, b, l, id, "not a shipped corpus policy")
	})

	t.Run("a ledger row under a category its detector does not have is reported", func(t *testing.T) {
		l := ledgerCopy()
		row := l[listed]
		row.Category = "sql_injection"
		l[listed] = row
		plantedOnce(t, bindings, l, listed, "its detector's category")
	})

	t.Run("a dormant variant also bound to a scope that admits its category is reported as stale", func(t *testing.T) {
		category := ledger[listed].Category
		var admitting string
		for _, s := range legacycompile.AllScopes() {
			if admittedOnAnyScope(category, []string{s.String()}) {
				admitting = s.String()
				break
			}
		}
		if admitting == "" {
			t.Fatalf("PREMISE: no declared scope admits %q, so the branch cannot be planted", category)
		}
		b := bindingsCopy()
		b[listed] = append(b[listed], admitting)
		plantedOnce(t, b, ledger, listed, "admits")
	})

	t.Run("a ledger row naming a policy the corpus binds nowhere is reported as stale", func(t *testing.T) {
		id := "corpus:static_policies:planted__unbound:redact"
		l := ledgerCopy()
		l[id] = DormantTemplateVariant{PolicyID: id, Category: ledger[listed].Category, Revisit: "#4230"}
		plantedOnce(t, bindings, l, id, "binds nowhere")
	})
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// TestSplittingAControlByScopeKeepsOneVariantAndMovesNoCount splits a real,
// unsplit shipped control the way the corpus build splits one whose action
// differs by scope - one action on decide, another everywhere else it binds -
// and holds every declared scope to two facts: its control count is the count
// the unsplit corpus gives it, and the policy it keeps for the control is the
// variant bound to it. The arm reads the bindings, not the actions, so which
// two actions are named does not matter.
func TestSplittingAControlByScopeKeepsOneVariantAndMovesNoCount(t *testing.T) {
	shipped, base := shippedAndBindings(t)
	table, rowID := unsplitControlOnDecideAndElsewhere(t, shipped, base)
	control := legacycompile.CorpusPolicyIDFor(table, rowID)
	decide := legacycompile.MustScopeFor(legacycompile.PlaneDecide, "")
	byScope := func(s legacycompile.EnforcementScope) string {
		if s.String() == decide.String() {
			return "log"
		}
		return "redact"
	}
	split, bindings := splitControl(t, shipped, base, table, rowID, byScope)

	judged := map[string]int{}
	for _, scope := range legacycompile.AllScopes() {
		unsplit, _, err := restrictToScope(scope, shipped, base)
		if err != nil {
			t.Fatalf("%s: %v", scope, err)
		}
		got, _, err := restrictToScope(scope, split, bindings)
		if err != nil {
			t.Errorf("%s: the split corpus did not restrict: %v", scope, err)
			continue
		}
		if len(got.Policies) != len(unsplit.Policies) {
			t.Errorf("%s keeps %d controls from the split corpus and %d from the unsplit one; splitting a control by scope must move no scope's count",
				scope, len(got.Policies), len(unsplit.Policies))
		}
		keptUnsplit := slices.Contains(policyIDs(unsplit), control)
		var variants []string
		for _, p := range got.Policies {
			if c, action, _ := legacycompile.CorpusControlOf(p.ID); c == control {
				variants = append(variants, action)
			}
		}
		switch {
		case !keptUnsplit && len(variants) > 0:
			t.Errorf("%s does not keep the unsplit control and keeps variant(s) %v of the split one", scope, variants)
		case keptUnsplit && (len(variants) != 1 || variants[0] != byScope(scope)):
			t.Errorf("%s keeps variant(s) %v of the split control; want exactly %q, the one bound to it", scope, variants, byScope(scope))
		case keptUnsplit:
			judged[variants[0]]++
		}
	}
	if judged["log"] == 0 || judged["redact"] == 0 {
		t.Fatalf("the split of %s was judged on %v; a variant no scope kept would prove nothing about it", control, judged)
	}
}

// TestTheBindingArmRefusesASplitThatLosesDoublesOrMisnamesAScope drives each
// refusal the binding arm makes, and asserts each by its REASON.
func TestTheBindingArmRefusesASplitThatLosesDoublesOrMisnamesAScope(t *testing.T) {
	shipped, base := shippedAndBindings(t)
	table, rowID := unsplitControlOnDecideAndElsewhere(t, shipped, base)
	decide := legacycompile.MustScopeFor(legacycompile.PlaneDecide, "")
	split, bindings := splitControl(t, shipped, base, table, rowID, func(legacycompile.EnforcementScope) string { return "log" })
	logID := legacycompile.CorpusVariantIDFor(table, rowID, "log")
	if !slices.Contains(bindings[logID], decide.String()) {
		t.Fatalf("CONTROL: decide does not keep %s unsplit; bindings %v", logID, bindings[logID])
	}
	if _, _, err := restrictToScope(decide, split, bindings); err != nil {
		t.Fatalf("CONTROL: a well-formed split was refused on decide: %v", err)
	}

	clone := func(in map[string][]string) map[string][]string {
		out := map[string][]string{}
		for k, v := range in {
			out[k] = append([]string(nil), v...)
		}
		return out
	}

	t.Run("a scope that admits the control and binds none of its variants", func(t *testing.T) {
		lost := clone(bindings)
		lost[logID] = slices.DeleteFunc(lost[logID], func(s string) bool { return s == decide.String() })
		_, _, err := restrictToScope(decide, split, lost)
		if err == nil || !strings.Contains(err.Error(), "would vanish from this scope") {
			t.Fatalf("got %v; want a refusal saying the control would vanish from decide", err)
		}
	})

	t.Run("two actions bound to one scope", func(t *testing.T) {
		doubled := clone(bindings)
		redactID := legacycompile.CorpusVariantIDFor(table, rowID, "redact")
		doubled[redactID] = []string{decide.String()}
		var redact pdp.Policy
		for _, p := range split.Policies {
			if p.ID == logID {
				redact = p
			}
		}
		redact.ID = redactID
		withBoth := *split
		withBoth.Policies = append(append([]pdp.Policy(nil), split.Policies...), redact)
		_, _, err := restrictToScope(decide, &withBoth, doubled)
		if err == nil || !strings.Contains(err.Error(), "to two actions of") {
			t.Fatalf("got %v; want a refusal saying decide is bound to two actions of the control", err)
		}
	})

	t.Run("a per-scope variant the document carries with no binding", func(t *testing.T) {
		unbound := clone(bindings)
		delete(unbound, logID)
		_, _, err := restrictToScope(decide, split, unbound)
		if err == nil || !strings.Contains(err.Error(), "with no scope binding") {
			t.Fatalf("got %v; want a refusal naming the unbound variant", err)
		}
	})

	t.Run("a control carried whole beside its per-scope variants", func(t *testing.T) {
		var original pdp.Policy
		for _, p := range shipped.Policies {
			if p.ID == legacycompile.CorpusPolicyIDFor(table, rowID) {
				original = p
			}
		}
		if original.ID == "" {
			t.Fatal("CONTROL: the shipped corpus does not carry the control whole; there is nothing to add beside its variants")
		}
		withWhole := *split
		withWhole.Policies = append(append([]pdp.Policy(nil), split.Policies...), original)
		_, _, err := restrictToScope(decide, &withWhole, bindings)
		if err == nil || !strings.Contains(err.Error(), "whole beside its per-scope variants") {
			t.Fatalf("got %v; want a refusal naming the control carried whole beside its variants", err)
		}
	})

	t.Run("a binding to a scope the model does not declare", func(t *testing.T) {
		misnamed := clone(bindings)
		misnamed[logID] = append(misnamed[logID], "decide:response")
		_, _, err := restrictToScope(decide, split, misnamed)
		if err == nil || !strings.Contains(err.Error(), "which the model does not declare") {
			t.Fatalf("got %v; want a refusal naming the undeclared scope", err)
		}
	})
}
