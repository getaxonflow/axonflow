package conformance

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// corpusFamily is one way an attribute can fail to be a resolved value.
type corpusFamily struct {
	Name string
	// Perturb returns the attribute to substitute, or nil to REMOVE the
	// attribute entirely.
	Perturb func(path string, schema pdp.AttributeSchema, healthy contract.Attribute) *contract.Attribute
	// WantReason is the unknown reason this family must produce when it
	// produces an unknown at all.
	WantReason contract.UnknownReason
	// AbsenceIsDeterminate is true only for the known-absent family, where a
	// NO_MATCH is the correct answer for an attribute the schema declares
	// optional.
	AbsenceIsDeterminate bool
}

// corpusFamilies are the five ways ADR-065 requires the compiler's tri-state
// corpus to be able to break an attribute, plus the freshness family the ADR
// adds when it says an attribute outside its bound is unknown.
func corpusFamilies() []corpusFamily {
	return []corpusFamily{
		{
			Name:       "missing",
			Perturb:    func(string, pdp.AttributeSchema, contract.Attribute) *contract.Attribute { return nil },
			WantReason: contract.ReasonNotSupplied,
		},
		{
			Name: "known-absent",
			Perturb: func(path string, _ pdp.AttributeSchema, _ contract.Attribute) *contract.Attribute {
				return AbsentAttr(path)
			},
			WantReason:           contract.ReasonRequiredAbsent,
			AbsenceIsDeterminate: true,
		},
		{
			Name: "stale",
			Perturb: func(path string, _ pdp.AttributeSchema, healthy contract.Attribute) *contract.Attribute {
				if healthy.State != contract.StateKnown {
					return UnknownAttr(path, contract.ReasonStale)
				}
				return StaleAttr(path, healthy.Value, 300)
			},
			WantReason: contract.ReasonStale,
		},
		{
			Name: "malformed",
			Perturb: func(path string, schema pdp.AttributeSchema, _ contract.Attribute) *contract.Attribute {
				// A value of the wrong declared type. The compiler checks the
				// type BEFORE comparing, so this becomes a tagged unknown
				// rather than a built-in error that aborts the evaluation.
				var wrong any = "not-a-number"
				if schema.Type == pdp.TypeString {
					wrong = 42
				}
				return KnownAttr(path, wrong)
			},
			WantReason: contract.ReasonSchemaMismatch,
		},
		{
			Name: "resolver-failed",
			Perturb: func(path string, _ pdp.AttributeSchema, _ contract.Attribute) *contract.Attribute {
				return UnknownAttr(path, contract.ReasonResolutionFailed)
			},
			WantReason: contract.ReasonResolutionFailed,
		},
		{
			Name: "closure-truncated",
			Perturb: func(path string, _ pdp.AttributeSchema, _ contract.Attribute) *contract.Attribute {
				return UnknownAttr(path, contract.ReasonClosureTruncated)
			},
			WantReason: contract.ReasonClosureTruncated,
		},
		{
			Name: "closure-unavailable",
			Perturb: func(path string, _ pdp.AttributeSchema, _ contract.Attribute) *contract.Attribute {
				return UnknownAttr(path, contract.ReasonClosureUnavailable)
			},
			WantReason: contract.ReasonClosureUnavailable,
		},
	}
}

// corpusBaseline is one starting world in which a NAMED set of policies match.
//
// One baseline is not enough, and that is the defect this shape exists to
// close. The corpus only learns anything from a policy that MATCHED on healthy
// data, because the property it checks is that such a policy cannot become a
// clean non-match; a single baseline makes three policies match and every check
// against the other twenty is skipped, which reads as 98 green subtests over
// almost nothing. The baselines below are chosen so that every attribute any
// policy reads is read by a policy that matches in at least one of them.
type corpusBaseline struct {
	Name     string
	Scenario Scenario
}

func corpusBaselines() []corpusBaseline {
	known := func(path string, v any) *contract.Attribute { return KnownAttr(path, v) }
	return []corpusBaseline{
		{"a contractor refunding above the approval threshold", Scenario{
			Principal: "bob", Action: "T1", Resource: "SUP-43",
			Args: map[string]any{"amount_cents": 3000000},
			Overrides: map[string]*contract.Attribute{
				PathStateVelocity: known(PathStateVelocity, 9),
				PathStateAnomaly:  known(PathStateAnomaly, 1000),
				PathEnvNewDevice:  known(PathEnvNewDevice, true),
				PathResourceRisk:  known(PathResourceRisk, "high"),
			}}},
		{"a legal export of a page under the restricted space", Scenario{
			Principal: "dana", Action: "T6", Resource: "P-900",
			Args: map[string]any{"page_id": "P-900"}}},
		{"a personal-data read", Scenario{
			Principal: "dana", Action: "T4", Args: map[string]any{"contact_id": "c1"}}},
		{"a transition on a restricted project", Scenario{
			Principal: "alice", Action: "T5", Resource: "LEG-7",
			Args: map[string]any{"ticket_id": "LEG-7", "to_status": "done"}}},
		{"a transition on a quarantined project", Scenario{
			Principal: "alice", Action: "T5", Resource: "QRT-1",
			Args: map[string]any{"ticket_id": "QRT-1", "to_status": "done"}}},
		{"an autonomous workload refund", Scenario{
			Principal: "agent-A", Action: "T1", Args: map[string]any{"amount_cents": 3000000}}},
		{"a request from an agent whose attestation reports it untrusted", Scenario{
			Principal: "alice", Action: "T1", Resource: "SUP-42",
			Args:      map[string]any{"amount_cents": 30000},
			Overrides: map[string]*contract.Attribute{PathAgentTrust: known(PathAgentTrust, "untrusted")}}},
		{"a request over the gating risk threshold", Scenario{
			Principal: "alice", Action: "T1", Resource: "SUP-42",
			Args: map[string]any{"amount_cents": 30000}, RiskScore: 95}},
		{"an export by a principal outside legal", Scenario{
			Principal: "alice", Action: "T2", Args: map[string]any{"segment": "all"}}},
	}
}

// baselineAttributes flattens a baseline scenario into the single attribute set
// the runtime evaluates: the shared surface merged with the acting hop's
// identity attributes.
func baselineAttributes(t *testing.T, b corpusBaseline) contract.AttributeSet {
	t.Helper()
	w := defaultWorld(t)
	req, err := w.Request(b.Scenario)
	if err != nil {
		t.Fatalf("building the baseline %q: %v", b.Name, err)
	}
	out := contract.AttributeSet{}
	for k, v := range req.Attributes {
		out[k] = v
	}
	for k, v := range req.Context.ActorChain[0].Attributes {
		out[k] = v
	}
	return out
}

func corpusRuntimes(t *testing.T) map[pdp.Root]*pdp.Runtime {
	t.Helper()
	w := defaultWorld(t)
	out := map[pdp.Root]*pdp.Runtime{}
	for _, b := range w.Bundles {
		rt, err := pdp.NewRuntime(context.Background(), b, pdp.DefaultLimits())
		if err != nil {
			t.Fatalf("preparing the %s runtime: %v", b.Root, err)
		}
		out[b.Root] = rt
	}
	return out
}

func evalAll(t *testing.T, rts map[pdp.Root]*pdp.Runtime, attrs contract.AttributeSet) map[string]pdp.PolicyOutcome {
	t.Helper()
	out := map[string]pdp.PolicyOutcome{}
	roots := make([]pdp.Root, 0, len(rts))
	for r := range rts {
		roots = append(roots, r)
	}
	sort.Slice(roots, func(i, j int) bool { return roots[i] < roots[j] })
	for _, r := range roots {
		res, err := rts[r].Eval(context.Background(), attrs)
		if err != nil {
			// This is the whole point of the corpus. A bare Rego undefined, a
			// built-in error, or a policy missing from the sealed result
			// object surfaces here as an error rather than as a policy that
			// quietly did not apply.
			t.Fatalf("evaluating the %s root: %v", r, err)
		}
		for id, oc := range res.Outcomes {
			out[id] = oc
		}
	}
	return out
}

// TestTriStateCorpusIsComplete proves the corpus itself covers everything it
// claims to. A corpus that skips a namespace, a reason code or an attribute is
// not evidence about the ones it skipped.
func TestTriStateCorpusIsComplete(t *testing.T) {
	w := defaultWorld(t)
	paths := referencedPaths(w)
	if len(paths) == 0 {
		t.Fatal("no attribute is referenced by any policy, so the corpus would be vacuous")
	}

	namespaces := map[contract.Namespace]struct{}{}
	for _, p := range paths {
		namespaces[contract.NamespaceOf(p)] = struct{}{}
	}
	for _, ns := range contract.AllNamespaces() {
		if _, ok := namespaces[ns]; !ok {
			t.Errorf("namespace %q is not referenced by any fixture policy, so the corpus generates no entry for it", ns)
		}
	}

	// Every DECLARED attribute must also be referenced. An attribute in the
	// schema that no policy reads generates no corpus entries at all, so it
	// carries no tri-state evidence while looking, from the schema, like part
	// of the covered surface.
	referenced := map[string]struct{}{}
	for _, p := range paths {
		referenced[p] = struct{}{}
	}
	var unread []string
	for path := range mergedSchema(w) {
		if _, ok := referenced[path]; !ok {
			unread = append(unread, path)
		}
	}
	sort.Strings(unread)
	if len(unread) > 0 {
		t.Errorf("%d declared attributes are read by no policy, so the corpus generates no entry for them: %s",
			len(unread), strings.Join(unread, ", "))
	}

	// Every declared unknown reason must be produced by at least one corpus
	// family, so a reason added to the contract without a way to generate it
	// fails here rather than going untested.
	produced := map[contract.UnknownReason]struct{}{}
	for _, f := range corpusFamilies() {
		produced[f.WantReason] = struct{}{}
	}
	// malformed_value is the helper's fallback for an attribute carrying a
	// STATE this build does not recognise, which a request that passed
	// validation cannot do, because AttrState is a closed set the validator
	// enforces. No corpus family produces it and none can: it exists so that a
	// future Policy Information Point version speaking to an older evaluator
	// resolves to unknown rather than to anything else, and that is a property
	// of the helper rather than of a request.
	produced[contract.ReasonMalformedValue] = struct{}{}
	for _, r := range contract.AllUnknownReasons() {
		if _, ok := produced[r]; !ok {
			t.Errorf("unknown reason %q is declared but no corpus family produces it", r)
		}
	}
}

// TestTriStateCorpus is ADR-065 acceptance gate 4.
//
// For every attribute any policy references, and for every way that attribute
// can fail to be a resolved value, the corpus asserts that a policy which
// matched on healthy data does NOT become a clean non-match. It may stay
// matched, because another disjunct decided it; it may become unknown, which is
// the honest answer. What it may never do is disappear, because a constraint
// that disappears is a constraint that was silently skipped.
func TestTriStateCorpus(t *testing.T) {
	w := defaultWorld(t)
	rts := corpusRuntimes(t)
	schema := mergedSchema(w)
	paths := referencedPaths(w)

	// checksPerPath counts the per-policy comparisons that were actually
	// PERFORMED, not the subtests that were generated. The floor below is
	// derived from that measurement rather than from the generated count,
	// because the generated count is identically the product of two lengths and
	// therefore survives the deletion of every assertion it claims to guard.
	checksPerPath := map[string]int{}
	// The stale family is the one family whose perturbation is applied by the
	// EVALUATOR rather than by the fixture: it hands over a resolved value with
	// an expired freshness bound and the evaluator downgrades it. If the bound
	// stopped being applied, the value would stay resolved, every policy would
	// simply keep matching, and the family would report green having exercised
	// nothing. Counting the unknowns it actually produced is what makes that
	// visible here rather than only in the freshness unit test.
	staleUnknowns := 0

	for _, b := range corpusBaselines() {
		healthy := baselineAttributes(t, b)
		baseline := evalAll(t, rts, healthy)
		for _, path := range paths {
			refs := policiesReferencing(w, path)
			if len(refs) == 0 {
				t.Errorf("attribute %q is in the referenced set but no policy reads it", path)
				continue
			}
			// Only a policy that MATCHED here can teach this baseline
			// anything, so skip the pairing rather than the whole entry.
			var matched []string
			for _, id := range refs {
				if baseline[id].Verdict == pdp.VerdictMatch {
					matched = append(matched, id)
				}
			}
			if len(matched) == 0 {
				continue
			}
			for _, fam := range corpusFamilies() {
				t.Run(b.Name+"/"+path+"/"+fam.Name, func(t *testing.T) {
					perturbed := contract.AttributeSet{}
					for k, v := range healthy {
						perturbed[k] = v
					}
					replacement := fam.Perturb(path, schema[path], healthy[path])
					if replacement == nil {
						delete(perturbed, path)
					} else {
						perturbed[path] = *replacement
					}
					// Freshness is applied by the evaluator, not by the
					// fixture, so the stale family really exercises the
					// evaluator's bound rather than pre-cooking the answer.
					got := evalAll(t, rts, perturbed.AtFreshness(Now))

					for _, id := range matched {
						after := got[id]
						checksPerPath[path]++
						switch after.Verdict {
						case pdp.VerdictMatch:
							// Another term of the condition decided it. Sound.
						case pdp.VerdictUnknown:
							if fam.Name == "stale" && reasonPresent(after, contract.ReasonStale) {
								staleUnknowns++
							}
							if !causedBy(after, path) {
								t.Errorf("policy %s became unknown but does not name %q as a cause: %v", id, path, after.Causes)
							}
							if !reasonPresent(after, fam.WantReason) && fam.Name != "known-absent" {
								t.Errorf("policy %s is unknown for %q but reports %v, expected %q",
									id, path, reasonsOf(after), fam.WantReason)
							}
						case pdp.VerdictNoMatch:
							if !fam.AbsenceIsDeterminate {
								t.Errorf("policy %s matched on resolved data and became a clean non-match when %q was %s; "+
									"an attribute that could not be established is not evidence that a policy does not apply",
									id, path, fam.Name)
								break
							}
							if !schema[path].Optional {
								t.Errorf("policy %s became a clean non-match on the ABSENCE of %q, which the schema declares required; "+
									"known absence may produce a non-match only where the schema marks the attribute optional",
									id, path)
							}
						default:
							t.Errorf("policy %s returned verdict %q", id, after.Verdict)
						}
					}
				})
			}
		}
	}

	// Every referenced attribute must have been checked against a policy that
	// really matched. An attribute with zero performed checks is an attribute
	// the gate says nothing about, and saying nothing about it while reporting
	// green is the failure mode this corpus was written to prevent.
	var uncovered []string
	total := 0
	for _, path := range paths {
		total += checksPerPath[path]
		if checksPerPath[path] == 0 {
			uncovered = append(uncovered, path)
		}
	}
	sort.Strings(uncovered)
	if len(uncovered) > 0 {
		t.Fatalf("%d of %d referenced attributes carry no tri-state evidence at all: %s",
			len(uncovered), len(paths), strings.Join(uncovered, ", "))
	}
	// The floor is one performed check per attribute per family, derived from
	// the two measured populations rather than chosen.
	if want := len(paths) * len(corpusFamilies()); total < want {
		t.Fatalf("the corpus performed %d per-policy checks over %d attributes and %d families, fewer than the %d floor",
			total, len(paths), len(corpusFamilies()), want)
	}
	if staleUnknowns == 0 {
		t.Fatal("the stale family produced no unknown at all, so the freshness bound was never exercised; " +
			"a value handed over past its bound stayed resolved and every policy simply kept matching")
	}
	t.Logf("tri-state corpus performed %d per-policy checks across %d attributes, %d families and %d baselines, "+
		"of which %d were staleness downgrades applied by the evaluator",
		total, len(paths), len(corpusFamilies()), len(corpusBaselines()), staleUnknowns)
}

// TestTriStateCorpusNeverWidensTheDecision is the decision-level companion. It
// is coarser than the per-policy check above and it catches a different thing:
// a perturbation that leaves every policy verdict defensible but still produces
// a more permissive OUTCOME, which would mean the combining rule rather than the
// compiler had lost the unknown.
func TestTriStateCorpusNeverWidensTheDecision(t *testing.T) {
	w := defaultWorld(t)
	base := Scenario{Principal: "bob", Action: "T1", Resource: "SUP-43",
		Args: map[string]any{"amount_cents": 3000000},
		Overrides: map[string]*contract.Attribute{
			PathStateVelocity: KnownAttr(PathStateVelocity, 2),
			PathStateAnomaly:  KnownAttr(PathStateAnomaly, 10000000),
			PathEnvNewDevice:  KnownAttr(PathEnvNewDevice, false),
			PathResourceRisk:  KnownAttr(PathResourceRisk, "low"),
		}}
	healthy := decide(t, w, base)
	schema := mergedSchema(w)

	// The healthy value of EVERY referenced attribute is read from the built
	// request rather than from the override map. Reading it from the overrides
	// gives the zero Attribute for the paths the scenario did not override, and
	// the stale family then takes its "already unknown" branch and injects a
	// ready-made unknown instead of ageing a real value: the freshness bound
	// would never be exercised for those paths while the subtest still reported
	// green.
	baseReq, err := w.Request(base)
	if err != nil {
		t.Fatalf("building the base request: %v", err)
	}
	healthyAttrs := contract.AttributeSet{}
	for k, v := range baseReq.Attributes {
		healthyAttrs[k] = v
	}
	for k, v := range baseReq.Context.ActorChain[0].Attributes {
		healthyAttrs[k] = v
	}
	staleExercised := 0

	for _, path := range referencedPaths(w) {
		for _, fam := range corpusFamilies() {
			t.Run(path+"/"+fam.Name, func(t *testing.T) {
				s := base
				s.Overrides = map[string]*contract.Attribute{}
				for k, v := range base.Overrides {
					s.Overrides[k] = v
				}
				healthyAttr := healthyAttrs[path]
				if fam.Name == "stale" && healthyAttr.State == contract.StateKnown {
					staleExercised++
				}
				s.Overrides[path] = fam.Perturb(path, schema[path], healthyAttr)
				d := decide(t, w, s)
				if permissiveness(d) > permissiveness(healthy) {
					t.Fatalf("breaking %q as %s widened the outcome from %s to %s",
						path, fam.Name, healthy.State, d.State)
				}
				// And it must never fail through the evaluator itself: an
				// evaluation error means a bare undefined or a built-in error
				// reached the Go boundary, which is a compiler defect rather
				// than a policy answer.
				if d.Reason == contract.ReasonEvaluationError {
					t.Fatalf("breaking %q as %s produced an evaluation error rather than a tagged unknown: %s",
						path, fam.Name, d.Trace.Remediation)
				}
			})
		}
	}
	// The stale family must have aged a REAL value for most referenced
	// attributes, or the freshness bound is not what this run exercised.
	if want := len(referencedPaths(w)) - 2; staleExercised < want {
		t.Fatalf("the stale family aged a resolved value for only %d attributes, expected at least %d; "+
			"the rest took the pre-cooked branch and did not exercise the freshness bound",
			staleExercised, want)
	}
}

func referencedPaths(w *World) []string {
	set := map[string]struct{}{}
	for _, d := range []*pdp.Document{w.System, w.Org} {
		for _, p := range d.ReferencedPaths() {
			set[p] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func policiesReferencing(w *World, path string) []string {
	var out []string
	for _, d := range []*pdp.Document{w.System, w.Org} {
		for _, p := range d.Policies {
			for _, ref := range p.ReferencedPaths() {
				if ref == path {
					out = append(out, p.ID)
					break
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

func mergedSchema(w *World) map[string]pdp.AttributeSchema {
	out := map[string]pdp.AttributeSchema{}
	for _, d := range []*pdp.Document{w.System, w.Org} {
		for k, v := range d.AttributeIndex() {
			out[k] = v
		}
	}
	return out
}

func causedBy(oc pdp.PolicyOutcome, path string) bool {
	for _, c := range oc.Causes {
		if c.Path == path {
			return true
		}
	}
	return false
}

func reasonPresent(oc pdp.PolicyOutcome, want contract.UnknownReason) bool {
	for _, c := range oc.Causes {
		if c.Reason == want {
			return true
		}
	}
	return false
}

func reasonsOf(oc pdp.PolicyOutcome) string {
	var parts []string
	for _, c := range oc.Causes {
		parts = append(parts, fmt.Sprintf("%s=%s", c.Path, c.Reason))
	}
	return strings.Join(parts, ",")
}
