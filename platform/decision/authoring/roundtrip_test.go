package authoring

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"golang.org/x/text/unicode/norm"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// The round trip is a THEOREM about generated documents, not a demonstration
// on an example. An example proves that one document survived; the property
// below draws documents from the whole authoring vocabulary and holds every one
// of them to four conjuncts:
//
//  1. rendering is stable: render, parse, render again, byte-identical;
//  2. the digest is stable, which is what an artifact is pinned by;
//  3. the parsed document compiles to a byte-identical Rego module, which is
//     the half that makes it a statement about POLICY rather than about JSON;
//  4. the parsed document builds to a byte-identical bundle digest.
//
// Without (3) and (4) a render that silently dropped a field the compiler reads
// would pass: the JSON would round trip, and the policy being enforced would
// not be the policy anyone could read back.

// generator draws valid authoring documents. Every constraint it respects is a
// save-time rule, and it asserts that what it drew is actually clean, so a
// generator that drifts out of the valid region fails loudly instead of
// quietly narrowing the property to the documents that happen to survive.
type generator struct {
	rng *rand.Rand
}

// unicodePairs are strings that are equal after NFC normalization and different
// as bytes. They are seeded into descriptions, titles and string literals so
// that the round trip is exercised on exactly the input class that broke a
// signature in the layer below: a normalizing encoder maps both members of a
// pair onto one output, which is a digest collision between two documents that
// compile to different policy.
var unicodePairs = [][2]string{
	{"café refunds", "café refunds"},
	{"Ångström ledger", "Ångström ledger"},
	{"naïve reviewer", "naïve reviewer"},
}

func (g *generator) pick(n int) int { return g.rng.Intn(n) }

func (g *generator) text(prefix string) string {
	pair := unicodePairs[g.pick(len(unicodePairs))]
	return fmt.Sprintf("%s %s %d", prefix, pair[g.pick(2)], g.rng.Intn(1000))
}

// numberLiteral draws from the values that break a naive round trip: an integer
// beyond float64's exact range, a negative, a zero, a fraction, and an exponent
// form. 4611686018427387904 is the one that matters most: decode it into a
// float64 and it comes back as a different number, so a limit would change
// under the author without anyone touching it.
func (g *generator) numberLiteral() any {
	switch g.pick(6) {
	case 0:
		return json.Number("4611686018427387904")
	case 1:
		return json.Number("-9007199254740993")
	case 2:
		return json.Number("0")
	case 3:
		return json.Number("1.5")
	case 4:
		return json.Number("1e3")
	default:
		return json.Number(fmt.Sprintf("%d", g.rng.Intn(1_000_000)))
	}
}

type attrKind struct {
	path     string
	typ      pdp.ValueType
	optional bool
	args     bool
}

// generatorAttributes is the pool a generated document draws conditions from.
// It intentionally contains a required and an optional attribute in both the
// trusted and the caller-supplied namespaces, because the absence rules differ
// across that boundary and a pool missing one corner would never generate the
// condition shape that exercises it.
var generatorAttributes = []attrKind{
	{path: pdp.PrincipalIDPath, typ: pdp.TypeString},
	{path: pdp.PrincipalGroupsPath, typ: pdp.TypeArray},
	{path: pdp.ActionIDPath, typ: pdp.TypeString},
	{path: pdp.ActionTagsPath, typ: pdp.TypeArray},
	{path: pdp.ResourceAncestorsPath, typ: pdp.TypeArray},
	{path: "resource.project.owner", typ: pdp.TypeString},
	{path: "resource.space.label", typ: pdp.TypeString, optional: true},
	{path: "signal.pii_score", typ: pdp.TypeNumber},
	{path: "state.spend_cents", typ: pdp.TypeNumber},
	{path: "env.zone", typ: pdp.TypeString, optional: true},
	{path: "args.amount_cents", typ: pdp.TypeNumber, args: true},
	{path: "args.note", typ: pdp.TypeString, optional: true, args: true},
}

func generatorSchema() []pdp.AttributeSchema {
	out := make([]pdp.AttributeSchema, 0, len(generatorAttributes))
	for _, a := range generatorAttributes {
		out = append(out, pdp.AttributeSchema{Path: a.path, Type: a.typ, Optional: a.optional})
	}
	return out
}

// absence returns the handling a condition over this attribute must declare.
//
// Three rules meet here and all three are save-time rejections if broken: a
// required attribute must declare nothing, an optional one must declare
// something, and caller-supplied absence is always unknown because a caller who
// can suppress a condition by omitting a field can decide the condition does
// not apply.
func (g *generator) absence(a attrKind) pdp.AbsenceHandling {
	if !a.optional {
		return pdp.AbsentUnspecified
	}
	if a.args {
		return pdp.AbsentIsUnknown
	}
	if g.pick(2) == 0 {
		return pdp.AbsentIsNoMatch
	}
	return pdp.AbsentIsUnknown
}

func (g *generator) literalFor(a attrKind) any {
	switch a.typ {
	case pdp.TypeNumber:
		return g.numberLiteral()
	case pdp.TypeArray:
		return g.text("member")
	default:
		return g.text("value")
	}
}

var comparisonOps = []pdp.CompareOp{pdp.OpEq, pdp.OpNe, pdp.OpLt, pdp.OpLe, pdp.OpGt, pdp.OpGe}

// leaf draws one data-reading condition. It never draws the unconditional
// verdict, so a composite built from leaves is never structurally true or
// structurally false and cannot trip CONSTRAINT_NEVER_BINDS by accident.
func (g *generator) leaf() pdp.Condition {
	a := generatorAttributes[g.pick(len(generatorAttributes))]
	handling := g.absence(a)
	if a.typ == pdp.TypeArray {
		switch g.pick(3) {
		case 0:
			return pdp.Member(a.path, g.literalFor(a)).HandlingAbsence(handling)
		case 1:
			return pdp.Superset(a.path, g.literalFor(a), g.literalFor(a)).HandlingAbsence(handling)
		default:
			return pdp.Intersects(a.path, g.literalFor(a)).HandlingAbsence(handling)
		}
	}
	// An attribute-to-attribute comparison is legal only between two TRUSTED
	// terms. Against a caller-supplied one it is the authority rule's whole
	// subject, and the generator must not draw it or every document would be
	// refused.
	if !a.args && g.pick(4) == 0 {
		for _, b := range g.shuffledAttributes() {
			if b.args || b.path == a.path || b.typ != a.typ || b.optional || a.optional {
				continue
			}
			return pdp.AttrCompare(a.path, comparisonOps[g.pick(len(comparisonOps))], b.path)
		}
	}
	return pdp.Compare(a.path, comparisonOps[g.pick(len(comparisonOps))], g.literalFor(a)).HandlingAbsence(handling)
}

func (g *generator) shuffledAttributes() []attrKind {
	out := append([]attrKind(nil), generatorAttributes...)
	g.rng.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

func (g *generator) condition(depth int) pdp.Condition {
	if depth <= 0 {
		return g.leaf()
	}
	switch g.pick(5) {
	case 0:
		return pdp.And(g.condition(depth-1), g.condition(depth-1))
	case 1:
		return pdp.Or(g.condition(depth-1), g.condition(depth-1), g.condition(depth-1))
	case 2:
		return pdp.Not(g.condition(depth - 1))
	default:
		return g.leaf()
	}
}

func (g *generator) policy(t *testing.T, i int, cat *Catalog) pdp.Policy {
	t.Helper()
	authorities := contract.AllAuthorities()
	authority := authorities[g.pick(len(authorities))]
	actionIDs := []string{actionRefund, actionTicket, actionExport}
	action := actionIDs[g.pick(len(actionIDs))]

	p := pdp.Policy{
		ID:          fmt.Sprintf("gen.%s.%03d", authority, i),
		Authority:   authority,
		Root:        pdp.RootSystem,
		Actions:     pdp.ActionSelector{Actions: []contract.ID{aid(t, action)}},
		Where:       g.condition(2),
		Description: g.text("generated"),
	}
	switch g.pick(3) {
	case 0:
		p.Scope = pdp.Scope{Organization: true}
	case 1:
		p.Scope = pdp.Scope{Groups: []contract.ID{gid(t, groupFinance)}}
	default:
		p.Scope = pdp.Scope{Principals: []contract.ID{pid(t, principalAlice)}}
	}
	if g.pick(3) == 0 {
		rs := g.leaf()
		p.ResourceScope = &rs
	}
	if g.pick(4) == 0 {
		u := g.leaf()
		p.Unless = &u
	}

	leaves := cat.Actions[action].PayloadLeaves
	switch authority {
	case contract.AuthorityRequirement:
		p.Mandatory = g.pick(2) == 0
		p.Obligations = g.requirementObligations(p.ID, leaves)
	case contract.AuthorityInspection:
		p.Obligations = g.inspectionObligations(p.ID, leaves)
	case contract.AuthorityConstraint:
		if g.pick(3) == 0 {
			p.PierceableBy = []contract.ID{gid(t, groupIncident)}
		}
	}
	return p
}

// requirementObligations draws a non-conflicting obligation set. Disclosure
// transforms take DISTINCT leaves, because two equal-rank transforms on one
// leaf with different parameters are incomparable and the composition algebra
// refuses them, which is a save-time rejection rather than a round-trip fact.
func (g *generator) requirementObligations(source string, leaves []string) []contract.Obligation {
	out := []contract.Obligation{auditObligation(source)}
	switch g.pick(4) {
	case 0:
		out = append(out, contract.Obligation{
			Type:          contract.ObApprovalChallenge,
			Params:        map[string]string{"quorum": "2", "eligible": groupFinance},
			Mandatory:     true,
			SourcePolicy:  source,
			SchemaVersion: 1,
		})
	case 1:
		out = append(out, contract.Obligation{
			Type:          contract.ObStepUpAuth,
			Params:        map[string]string{"assurance": string(contract.AssuranceLevel2)},
			Mandatory:     true,
			SourcePolicy:  source,
			SchemaVersion: 1,
		})
	case 2:
		if len(leaves) > 0 {
			out = append(out, redactObligation(source, leaves[0], map[string]string{"style": g.text("style")}))
		}
	}
	return out
}

func (g *generator) inspectionObligations(source string, leaves []string) []contract.Obligation {
	if len(leaves) == 0 || g.pick(2) == 0 {
		o := auditObligation(source)
		o.Mandatory = false
		return []contract.Obligation{o}
	}
	o := redactObligation(source, leaves[g.pick(len(leaves))], map[string]string{"style": g.text("style")})
	o.Mandatory = false
	return []contract.Obligation{o}
}

func (g *generator) document(t *testing.T, cat *Catalog, seq int) *Document {
	t.Helper()
	n := 1 + g.pick(5)
	policies := make([]pdp.Policy, 0, n)
	for i := 0; i < n; i++ {
		policies = append(policies, g.policy(t, i, cat))
	}
	pair := unicodePairs[g.pick(len(unicodePairs))]
	meta := Metadata{
		DocumentID: fmt.Sprintf("generated-%03d", seq),
		Title:      pair[g.pick(2)],
		Author:     pid(t, principalAlice),
	}
	if g.pick(2) == 0 {
		meta.Supersedes = "sha256:" + strings.Repeat("ab", 32)
	}
	return &Document{
		APIVersion: APIVersion,
		Metadata:   meta,
		Policy: pdp.Document{
			Root:              pdp.RootSystem,
			Version:           1 + g.pick(50),
			Attributes:        generatorSchema(),
			Policies:          policies,
			InteractiveRealms: cat.InteractiveRealms(),
		},
	}
}

func TestPropertyDocumentsRenderBackWithoutLoss(t *testing.T) {
	cat := baseCatalog(t)
	// A fixed seed: a property test that draws a different corpus on every run
	// is a test whose failures cannot be reproduced, and the value here is in
	// the breadth of the vocabulary rather than in surprise.
	g := &generator{rng: rand.New(rand.NewSource(20260830))}
	const draws = 400
	drawn, checks := 0, 0
	for i := 0; i < draws; i++ {
		d := g.document(t, cat, i)
		findings := Validate(d, cat)
		if err := findings.Error(); err != nil {
			t.Fatalf("draw %d is outside the valid region, so the generator, not the property, is wrong: %v", i, err)
		}
		drawn++

		first, err := Render(d)
		if err != nil {
			t.Fatalf("draw %d did not render: %v", i, err)
		}
		back, err := Parse(first)
		if err != nil {
			t.Fatalf("draw %d did not parse back: %v\nrendered: %s", i, err, first)
		}
		second, err := Render(back)
		if err != nil {
			t.Fatalf("draw %d did not re-render: %v", i, err)
		}
		checks++
		if string(first) != string(second) {
			t.Fatalf("draw %d is lossy.\nfirst:  %s\nsecond: %s", i, first, second)
		}

		checks++
		d1, err := Digest(d)
		if err != nil {
			t.Fatal(err)
		}
		d2, err := Digest(back)
		if err != nil {
			t.Fatal(err)
		}
		if d1 != d2 {
			t.Fatalf("draw %d: the document digests to %s and the rendered-back document to %s", i, d1, d2)
		}

		checks++
		moduleBefore, err := pdp.Compile(&d.Policy)
		if err != nil {
			t.Fatalf("draw %d did not compile: %v", i, err)
		}
		moduleAfter, err := pdp.Compile(&back.Policy)
		if err != nil {
			t.Fatalf("draw %d did not compile after the round trip: %v", i, err)
		}
		if moduleBefore != moduleAfter {
			t.Fatalf("draw %d compiles to a different module after the round trip", i)
		}

		checks++
		bundleBefore, err := pdp.BuildBundle(&d.Policy)
		if err != nil {
			t.Fatal(err)
		}
		bundleAfter, err := pdp.BuildBundle(&back.Policy)
		if err != nil {
			t.Fatal(err)
		}
		if bundleBefore.Digest != bundleAfter.Digest {
			t.Fatalf("draw %d builds to bundle %s and the rendered-back document to %s", i, bundleBefore.Digest, bundleAfter.Digest)
		}
	}
	if drawn != draws || checks != draws*4 {
		t.Fatalf("the property performed %d checks over %d draws; %d draws with 4 conjuncts each was expected", checks, drawn, draws)
	}
	t.Logf("round-trip property: %d generated documents, %d conjuncts asserted, zero byte drift", drawn, checks)
}

// TestTheGeneratorReachesTheWholeVocabulary is the anti-vacuity gate for the
// property above.
//
// A generator that only ever drew one authority, one condition kind and no
// obligations would make the property pass while proving almost nothing, and
// the property itself cannot tell the difference: it would report 400 clean
// draws either way. This counts what was actually drawn and names anything the
// corpus never reached.
func TestTheGeneratorReachesTheWholeVocabulary(t *testing.T) {
	cat := baseCatalog(t)
	g := &generator{rng: rand.New(rand.NewSource(20260830))}
	authorities := map[contract.Authority]int{}
	kinds := map[pdp.CondKind]int{}
	obligations := map[contract.ObligationType]int{}
	features := map[string]int{}

	var walk func(pdp.Condition)
	walk = func(c pdp.Condition) {
		kinds[c.Kind]++
		if c.OnAbsent != pdp.AbsentUnspecified {
			features["absence:"+string(c.OnAbsent)]++
		}
		for _, o := range c.Operands {
			walk(o)
		}
	}
	for i := 0; i < 400; i++ {
		d := g.document(t, cat, i)
		if d.Metadata.Supersedes != "" {
			features["supersedes"]++
		}
		for _, p := range d.Policy.Policies {
			authorities[p.Authority]++
			walk(p.Where)
			if p.Unless != nil {
				features["unless"]++
				walk(*p.Unless)
			}
			if p.ResourceScope != nil {
				features["resource_scope"]++
				walk(*p.ResourceScope)
			}
			if len(p.PierceableBy) > 0 {
				features["pierceable"]++
			}
			if p.Scope.Organization {
				features["scope:organization"]++
			}
			if len(p.Scope.Groups) > 0 {
				features["scope:groups"]++
			}
			if len(p.Scope.Principals) > 0 {
				features["scope:principals"]++
			}
			for _, o := range p.Obligations {
				obligations[o.Type]++
			}
		}
	}

	for _, a := range contract.AllAuthorities() {
		if authorities[a] == 0 {
			t.Errorf("the generator never drew a %s policy", a)
		}
	}
	for _, k := range []pdp.CondKind{
		pdp.CondCompare, pdp.CondMember, pdp.CondSuperset, pdp.CondIntersects,
		pdp.CondAttrCompare, pdp.CondAnd, pdp.CondOr, pdp.CondNot,
	} {
		if kinds[k] == 0 {
			t.Errorf("the generator never drew a %s condition", k)
		}
	}
	for _, o := range []contract.ObligationType{
		contract.ObImmutableAudit, contract.ObApprovalChallenge, contract.ObStepUpAuth, contract.ObFieldRedact,
	} {
		if obligations[o] == 0 {
			t.Errorf("the generator never drew a %s obligation", o)
		}
	}
	for _, f := range []string{
		"unless", "resource_scope", "pierceable", "supersedes",
		"scope:organization", "scope:groups", "scope:principals",
		"absence:" + string(pdp.AbsentIsNoMatch), "absence:" + string(pdp.AbsentIsUnknown),
	} {
		if features[f] == 0 {
			t.Errorf("the generator never drew %s", f)
		}
	}
	t.Logf("vocabulary reached: authorities=%v condition kinds=%d obligation types=%d features=%d",
		len(authorities), len(kinds), len(obligations), len(features))
}

// TestUnicodeNormalizationCannotCollideTwoDocuments re-runs the attack shape
// that broke the bundle signature in the layer below, against THIS encoder.
//
// Two documents whose only difference is Unicode composition are different
// artifacts: they compile to different Rego, and a policy comparing a value
// against the composed form does not match the decomposed one. A digest over a
// normalized projection maps both onto one value, so a signature over the one
// the reviewer approved would verify the one that is enforced.
func TestUnicodeNormalizationCannotCollideTwoDocuments(t *testing.T) {
	cat := baseCatalog(t)
	composed := "café"
	decomposed := norm.NFD.String(composed)
	if composed == decomposed {
		t.Fatal("the fixture strings are byte-identical, so this test asserts nothing")
	}
	if norm.NFC.String(decomposed) != composed {
		t.Fatal("the fixture strings are not NFC-equivalent, so they are not the collision this test is about")
	}

	build := func(literal string) *Document {
		return documentWith(t, cat, func(_ *Metadata, d *pdp.Document) {
			p := policyByIDIn(d, "perm.refund")
			p.Where = pdp.And(
				pdp.Compare("args.amount_cents", pdp.OpLe, 500000),
				pdp.Compare("args.note", pdp.OpEq, literal).HandlingAbsence(pdp.AbsentIsUnknown),
			)
		})
	}
	a, b := build(composed), build(decomposed)
	for _, d := range []*Document{a, b} {
		if err := Validate(d, cat).Error(); err != nil {
			t.Fatalf("the attack fixture must itself be a valid document: %v", err)
		}
	}

	// The two documents compile to DIFFERENT policy. That is what makes the
	// collision a security problem rather than a curiosity.
	moduleA, err := pdp.Compile(&a.Policy)
	if err != nil {
		t.Fatal(err)
	}
	moduleB, err := pdp.Compile(&b.Policy)
	if err != nil {
		t.Fatal(err)
	}
	if moduleA == moduleB {
		t.Fatal("the two fixtures compile to one module, so they are not two policies and the test is vacuous")
	}

	digestA, err := Digest(a)
	if err != nil {
		t.Fatal(err)
	}
	digestB, err := Digest(b)
	if err != nil {
		t.Fatal(err)
	}
	if digestA == digestB {
		t.Fatalf("two documents that compile to different policy share the document digest %s; a normalizing encoder has been used for artifact integrity", digestA)
	}

	// And the counterfactual, which is what proves the choice is load bearing
	// rather than incidental: the NORMALIZING encoder, which is correct for
	// cross-gateway request agreement, does collide them. If this stopped
	// holding, the test above would keep passing for the wrong reason.
	normA, err := contract.Digest(a)
	if err != nil {
		t.Fatal(err)
	}
	normB, err := contract.Digest(b)
	if err != nil {
		t.Fatal(err)
	}
	if normA != normB {
		t.Fatal("the normalizing encoder no longer collides these two documents, so the exact encoder is no longer distinguishable from it here and this test has stopped proving the distinction")
	}
}

// TestParseRefusesAnUnknownField pins the direction of loss nobody checks: a
// document carrying a field this build ignores is a document whose author
// believes something is in force that is not.
func TestParseRefusesAnUnknownField(t *testing.T) {
	d := baseDocument(t)
	raw, err := Render(d)
	if err != nil {
		t.Fatal(err)
	}
	var tree map[string]any
	if err := json.Unmarshal(raw, &tree); err != nil {
		t.Fatal(err)
	}
	tree["enforcement_mode"] = "report_only"
	tampered, err := json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(tampered); err == nil {
		t.Fatal("a document carrying an undeclared top-level field was accepted, so the round trip silently drops it")
	}
}

// TestParseKeepsALargeIntegerLiteralExactly is the case a float64 decode loses.
// It is asserted on its own as well as inside the property, because the
// property would report it as "lossy" without saying which value moved.
func TestParseKeepsALargeIntegerLiteralExactly(t *testing.T) {
	const big = "4611686018427387904"
	cat := baseCatalog(t)
	d := documentWith(t, cat, func(_ *Metadata, doc *pdp.Document) {
		policyByIDIn(doc, "perm.refund").Where = pdp.Compare("args.amount_cents", pdp.OpLe, json.Number(big))
	})
	raw, err := Render(d)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), big) {
		t.Fatalf("the rendered document does not carry %s verbatim: %s", big, raw)
	}
	back, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	module, err := pdp.Compile(&back.Policy)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(module, big) {
		t.Fatalf("the rendered-back document compiles to a module that does not carry %s; the limit changed under the author:\n%s", big, module)
	}
}
