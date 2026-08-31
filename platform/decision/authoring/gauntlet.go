package authoring

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// GateName is one gate of the publication gauntlet. ADR-065's policy lifecycle
// lists them: "run fixtures, conformance, properties, security invariants, and
// decision-log replay" before a bundle is signed.
type GateName string

const (
	// GateCompile is strict Rego v1 compilation under the restricted
	// capabilities document, plus the structural bundle lint. It is the gate a
	// compile error blocks publication at.
	GateCompile GateName = "compile"
	// GateRoundTrip proves the document renders back without loss and that what
	// renders back recompiles to the identical module under the identical
	// bundle digest. Without the second half, "rendered back" would only mean
	// the JSON survived, and an operator reading the source in a portal would
	// have no way to detect that it is not the source being enforced.
	GateRoundTrip GateName = "round_trip"
	// GateFixtures runs the author's declared cases against the real prepared
	// runtime.
	GateFixtures GateName = "fixtures"
	// GateTriState degrades every referenced attribute through every declared
	// unknown reason and through authoritative absence, and requires that no
	// degradation widens a policy verdict and that none produces an evaluation
	// error. It is the executable form of ADR-065's "synthetic missing, absent,
	// stale, malformed, and resolver-failure inputs are generated for every
	// referenced attribute during bundle validation".
	GateTriState GateName = "tri_state"
	// GateDeterminism evaluates the prepared bundle twice on identical input
	// and requires identical results. A PDP that is not deterministic cannot be
	// replayed, and replay is what makes a decision auditable after the fact.
	GateDeterminism GateName = "determinism"
)

// AllGates returns every gate in execution order. It is data so that the
// publication record can be held to it: an artifact whose report is missing a
// gate is refused rather than trusted.
func AllGates() []GateName {
	return []GateName{GateCompile, GateRoundTrip, GateFixtures, GateTriState, GateDeterminism}
}

// Fixture is one author-declared unit test for a document. It is part of the
// document's publication input rather than of the document, because a fixture
// is evidence about a policy and not policy.
type Fixture struct {
	Name string `json:"name"`
	// Attributes is the complete tagged attribute surface the fixture
	// evaluates against.
	Attributes contract.AttributeSet `json:"attributes"`
	// Expect maps policy identifier to the verdict the author asserts.
	Expect map[string]pdp.Verdict `json:"expect"`
}

// GateResult is the outcome of one gate.
type GateResult struct {
	Gate GateName `json:"gate"`
	// Passed is the only value a publication may proceed on. There is no
	// "skipped": a gate that could not run is a gate that did not pass.
	Passed bool `json:"passed"`
	// Checks is the number of assertions the gate actually performed. It is
	// recorded rather than derived so that a gate which degenerates to zero
	// work is visible in the signed report instead of reading as a pass.
	Checks int    `json:"checks"`
	Detail string `json:"detail,omitempty"`
}

// GauntletReport is the complete, ordered evidence that a document was tested
// before it was signed.
//
// It is part of the SIGNED artifact view. That is the structural answer to a
// publication path that skips the gauntlet on trusted input: an artifact cannot
// carry a report it did not get, because changing the report invalidates the
// signature, and loading an artifact re-checks that every declared gate is
// present and passed.
type GauntletReport struct {
	Results []GateResult `json:"results"`
}

// Passed reports whether every declared gate ran and passed.
func (r GauntletReport) Passed() error {
	byGate := map[GateName]GateResult{}
	for _, res := range r.Results {
		if _, dup := byGate[res.Gate]; dup {
			return fmt.Errorf("gauntlet: gate %q is reported twice", res.Gate)
		}
		byGate[res.Gate] = res
	}
	var problems []string
	for _, want := range AllGates() {
		res, ok := byGate[want]
		if !ok {
			problems = append(problems, fmt.Sprintf("gate %q is missing from the report", want))
			continue
		}
		if !res.Passed {
			problems = append(problems, fmt.Sprintf("gate %q did not pass: %s", want, res.Detail))
			continue
		}
		if res.Checks <= 0 {
			// A gate that passed having performed nothing is not evidence. The
			// count is the anti-vacuity floor, and it is derived from the work
			// the gate did rather than compared against a number somebody
			// picked, because a hand-picked floor is beaten by the first input
			// that meets it.
			problems = append(problems, fmt.Sprintf("gate %q passed having performed no checks, which is not evidence", want))
		}
	}
	for gate := range byGate {
		if !isDeclaredGate(gate) {
			problems = append(problems, fmt.Sprintf("the report carries undeclared gate %q", gate))
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("gauntlet: %s", strings.Join(problems, "; "))
	}
	return nil
}

func isDeclaredGate(g GateName) bool {
	for _, d := range AllGates() {
		if d == g {
			return true
		}
	}
	return false
}

// runGauntlet builds the bundle and runs every gate against it.
//
// The bundle it returns is the one the gates ran against, not a rebuild. A
// pipeline that tests one artifact and signs another has tested nothing, and
// rebuilding between the two would be exactly that even though the compiler is
// deterministic.
func runGauntlet(ctx context.Context, d *Document, fixtures []Fixture) (*pdp.Bundle, GauntletReport, error) {
	var report GauntletReport
	record := func(gate GateName, checks int, err error) bool {
		if err != nil {
			report.Results = append(report.Results, GateResult{Gate: gate, Passed: false, Checks: checks, Detail: err.Error()})
			return false
		}
		report.Results = append(report.Results, GateResult{Gate: gate, Passed: true, Checks: checks})
		return true
	}

	bundle, err := pdp.BuildBundle(&d.Policy)
	if err != nil {
		record(GateCompile, 0, err)
		return nil, report, fmt.Errorf("gauntlet: %s: %w", GateCompile, err)
	}
	if err := pdp.LintBundleModule(bundle.Module, pdp.BundlePackage(bundle.Root)); err != nil {
		record(GateCompile, 1, err)
		return nil, report, fmt.Errorf("gauntlet: %s: %w", GateCompile, err)
	}
	runtime, err := pdp.NewRuntime(ctx, bundle, pdp.DefaultLimits())
	if err != nil {
		record(GateCompile, 2, err)
		return nil, report, fmt.Errorf("gauntlet: %s: %w", GateCompile, err)
	}
	record(GateCompile, 3, nil)

	checks, err := gateRoundTrip(d, bundle)
	if !record(GateRoundTrip, checks, err) {
		return nil, report, fmt.Errorf("gauntlet: %s: %w", GateRoundTrip, err)
	}

	checks, err = gateFixtures(ctx, runtime, fixtures)
	if !record(GateFixtures, checks, err) {
		return nil, report, fmt.Errorf("gauntlet: %s: %w", GateFixtures, err)
	}

	checks, err = gateTriState(ctx, runtime, &d.Policy, fixtures)
	if !record(GateTriState, checks, err) {
		return nil, report, fmt.Errorf("gauntlet: %s: %w", GateTriState, err)
	}

	checks, err = gateDeterminism(ctx, runtime, fixtures)
	if !record(GateDeterminism, checks, err) {
		return nil, report, fmt.Errorf("gauntlet: %s: %w", GateDeterminism, err)
	}
	return bundle, report, nil
}

// gateRoundTrip proves the loss-free round trip on this exact document.
//
// Four conjuncts, and the last two are the ones that make it a statement about
// policy rather than about JSON: the document that renders back must recompile
// to a byte-identical module and rebuild to a byte-identical bundle digest. A
// render that dropped a field the compiler reads would satisfy the first two
// and fail these.
func gateRoundTrip(d *Document, bundle *pdp.Bundle) (int, error) {
	rendered, err := Render(d)
	if err != nil {
		return 0, err
	}
	back, err := Parse(rendered)
	if err != nil {
		return 1, err
	}
	again, err := Render(back)
	if err != nil {
		return 2, err
	}
	if string(again) != string(rendered) {
		return 3, fmt.Errorf("the document does not render back byte-identically:\n  first:  %s\n  second: %s", rendered, again)
	}
	module, err := pdp.Compile(&back.Policy)
	if err != nil {
		return 4, fmt.Errorf("the rendered-back document does not compile: %w", err)
	}
	if module != bundle.Module {
		return 5, fmt.Errorf("the rendered-back document compiles to a different module than the one being published")
	}
	rebuilt, err := pdp.BuildBundle(&back.Policy)
	if err != nil {
		return 6, fmt.Errorf("the rendered-back document does not build: %w", err)
	}
	if rebuilt.Digest != bundle.Digest {
		return 7, fmt.Errorf("the rendered-back document builds to digest %s, the bundle being published is %s", rebuilt.Digest, bundle.Digest)
	}
	return 8, nil
}

// gateFixtures runs the author's declared cases against the prepared runtime.
func gateFixtures(ctx context.Context, rt *pdp.Runtime, fixtures []Fixture) (int, error) {
	if len(fixtures) == 0 {
		// A document published with no fixtures has no evidence that any of its
		// policies does what its author believes. Refusing is the whole reason
		// the gate exists; accepting an empty set would make the signed report
		// say "fixtures passed" about nothing.
		return 0, fmt.Errorf("the publication declares no fixtures, so no policy in this document has been shown to do anything")
	}
	checks := 0
	var problems []string
	for _, f := range fixtures {
		if len(f.Expect) == 0 {
			problems = append(problems, fmt.Sprintf("fixture %q asserts nothing", f.Name))
			continue
		}
		result, err := rt.Eval(ctx, f.Attributes)
		if err != nil {
			problems = append(problems, fmt.Sprintf("fixture %q did not evaluate: %v", f.Name, err))
			continue
		}
		for _, id := range sortedKeys(f.Expect) {
			checks++
			got, ok := result.Outcomes[id]
			if !ok {
				problems = append(problems, fmt.Sprintf("fixture %q expects policy %q, which this document does not declare", f.Name, id))
				continue
			}
			if got.Verdict != f.Expect[id] {
				problems = append(problems, fmt.Sprintf("fixture %q: policy %q returned %s, the author asserts %s",
					f.Name, id, got.Verdict, f.Expect[id]))
			}
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return checks, fmt.Errorf("%s", strings.Join(problems, "; "))
	}
	return checks, nil
}

// gateTriState degrades every referenced attribute and requires that no
// degradation widens a verdict.
//
// What counts as a widening depends on which of ADR-065's three states the
// degradation lands in, because the model separates data that could not be
// resolved from data that was resolved to be absent:
//
//   - The unknown/* degradations model UNRESOLVABLE data. With a correct
//     helper an unknown degradation strictly removes information, and the
//     Kleene connectives are information-monotone, so no policy verdict can
//     reach MATCH from a non-MATCH baseline; it can only hold or decay toward
//     UNKNOWN. Flagging `before != MATCH && after == MATCH` is therefore
//     false-positive-free for the unknown-class degradations, and it is what
//     catches a helper that resolves only SOME unknown reasons to MATCH: a
//     NO_MATCH-only predicate is blind to that fail-open whenever the
//     baseline is itself UNKNOWN.
//   - The absent degradation models RESOLVED data: the authoritative source
//     successfully established that an optional attribute has no value, which
//     ADR-065 treats as a fact rather than a failure. Where the policy
//     explicitly declares that absence is a non-match, a determinate verdict
//     flip (for example NO_MATCH to MATCH through a negation) is the author's
//     declared semantics and is not flagged. Where the policy declares no
//     such handling, absence resolves to unknown at every leaf that reads the
//     attribute, the same information-monotonicity argument applies, and the
//     strict predicate is used.
//
// MATCH becoming UNKNOWN is the correct and expected behaviour in every class
// and is never an error: a constraint that goes UNKNOWN is escalated to
// Indeterminate by the combining rule, which fails closed, and a permission
// going UNKNOWN loses coverage, which is a narrowing.
func gateTriState(ctx context.Context, rt *pdp.Runtime, doc *pdp.Document, fixtures []Fixture) (int, error) {
	paths := doc.ReferencedPaths()
	if len(paths) == 0 {
		return 0, fmt.Errorf("the document references no attributes, so there is nothing to degrade and nothing this gate could prove")
	}
	degradations := degradationSet()
	absentDeclared := make(map[string]map[string]bool, len(doc.Policies))
	for _, p := range doc.Policies {
		absentDeclared[p.ID] = absentNoMatchPaths(p)
	}
	checks := 0
	var problems []string
	for _, f := range fixtures {
		base, err := rt.Eval(ctx, f.Attributes)
		if err != nil {
			problems = append(problems, fmt.Sprintf("fixture %q did not evaluate at baseline: %v", f.Name, err))
			continue
		}
		for _, path := range paths {
			for _, deg := range degradations {
				degraded := degradeAttribute(f.Attributes, path, deg)
				got, err := rt.Eval(ctx, degraded)
				if err != nil {
					problems = append(problems, fmt.Sprintf(
						"fixture %q with %q degraded to %s did not evaluate: %v", f.Name, path, deg.label, err))
					continue
				}
				for id, before := range base.Outcomes {
					checks++
					after, ok := got.Outcomes[id]
					if !ok {
						problems = append(problems, fmt.Sprintf(
							"fixture %q with %q degraded to %s lost policy %q from the result", f.Name, path, deg.label, id))
						continue
					}
					if after.Verdict != pdp.VerdictMatch || before.Verdict == pdp.VerdictMatch {
						continue
					}
					if deg.unknown {
						problems = append(problems, fmt.Sprintf(
							"fixture %q: degrading %q to %s turned policy %q from %s into MATCH, which is a widening on unresolvable data",
							f.Name, path, deg.label, id, before.Verdict))
						continue
					}
					if absentDeclared[id][path] {
						// The policy declares that absence of this attribute is
						// a non-match, so the determinate flip is its declared
						// semantics: authoritative absence is resolved data,
						// not a degradation the verdict must survive.
						continue
					}
					problems = append(problems, fmt.Sprintf(
						"fixture %q: degrading %q to %s turned policy %q from %s into MATCH, which is a widening: the policy does not declare what absence of %q means, so authoritative absence resolves to unknown there",
						f.Name, path, deg.label, id, before.Verdict, path))
				}
			}
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		if len(problems) > 12 {
			problems = append(problems[:12], fmt.Sprintf("and %d more", len(problems)-12))
		}
		return checks, fmt.Errorf("%s", strings.Join(problems, "; "))
	}
	if checks == 0 {
		return 0, fmt.Errorf("no degradation was evaluated, so this gate proved nothing")
	}
	return checks, nil
}

type degradation struct {
	label string
	// unknown marks the degradations that land in the UNKNOWN state. They get
	// the strict widening predicate in gateTriState; the absent degradation
	// does not, because absence is resolved data whose meaning the policy may
	// legitimately declare.
	unknown bool
	apply   func(contract.Attribute) contract.Attribute
}

// absentNoMatchPaths returns the attribute paths whose authoritative absence
// this policy explicitly interprets as a non-match, via a declared
// AbsentIsNoMatch on a condition that reads them. The authoring validator has
// already enforced ADR-065's pairing (the schema marks the attribute optional
// AND the policy declares the handling), so a declaration found here is an
// author's explicit decision rather than a default.
func absentNoMatchPaths(p pdp.Policy) map[string]bool {
	out := map[string]bool{}
	var walk func(c pdp.Condition)
	walk = func(c pdp.Condition) {
		if c.Path != "" && c.OnAbsent == pdp.AbsentIsNoMatch {
			out[c.Path] = true
		}
		for _, o := range c.Operands {
			walk(o)
		}
	}
	walk(p.Where)
	if p.ResourceScope != nil {
		walk(*p.ResourceScope)
	}
	if p.Unless != nil {
		walk(*p.Unless)
	}
	return out
}

// degradationSet enumerates one degradation per declared unknown reason plus
// authoritative absence, and it is DERIVED from contract.AllUnknownReasons
// rather than listed. A reason added to the contract becomes a degradation here
// with no edit, which is what stops the set going quietly stale.
func degradationSet() []degradation {
	out := []degradation{{
		label: "absent",
		apply: func(a contract.Attribute) contract.Attribute {
			return contract.Absent(a.Source, a.SourceVersion, a.ObservedAt)
		},
	}}
	for _, reason := range contract.AllUnknownReasons() {
		r := reason
		out = append(out, degradation{
			label:   "unknown/" + string(r),
			unknown: true,
			apply: func(a contract.Attribute) contract.Attribute {
				return contract.Unknown(r, a.Source, a.SourceVersion, a.ObservedAt)
			},
		})
	}
	return out
}

// degradeAttribute returns a copy of the set with one path degraded.
//
// A path the fixture does not carry is INSERTED in its degraded state rather
// than skipped. The "missing" case is the one the whole tri-state design exists
// to catch, and a degradation loop that only touched attributes the fixture
// already supplied would never generate it.
func degradeAttribute(in contract.AttributeSet, path string, deg degradation) contract.AttributeSet {
	out := make(contract.AttributeSet, len(in)+1)
	for k, v := range in {
		out[k] = v
	}
	existing, ok := in[path]
	if !ok {
		existing = contract.Attribute{Source: contract.NamespaceOf(path).DefaultProvenance(), SourceVersion: 1, ObservedAt: time.Unix(0, 0).UTC()}
	}
	out[path] = deg.apply(existing)
	return out
}

// gateDeterminism requires that two evaluations of one input agree.
func gateDeterminism(ctx context.Context, rt *pdp.Runtime, fixtures []Fixture) (int, error) {
	checks := 0
	for _, f := range fixtures {
		first, err := rt.Eval(ctx, f.Attributes)
		if err != nil {
			return checks, fmt.Errorf("fixture %q did not evaluate: %w", f.Name, err)
		}
		second, err := rt.Eval(ctx, f.Attributes)
		if err != nil {
			return checks, fmt.Errorf("fixture %q did not evaluate on replay: %w", f.Name, err)
		}
		for id, a := range first.Outcomes {
			checks++
			b, ok := second.Outcomes[id]
			if !ok {
				return checks, fmt.Errorf("fixture %q: policy %q is present on the first evaluation and absent on the second", f.Name, id)
			}
			if a.Verdict != b.Verdict {
				return checks, fmt.Errorf("fixture %q: policy %q returned %s then %s on identical input", f.Name, id, a.Verdict, b.Verdict)
			}
		}
	}
	if checks == 0 {
		return 0, fmt.Errorf("no evaluation was replayed, so determinism was not observed")
	}
	return checks, nil
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
