// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package metricdomain

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// newVec builds a real CounterVec on a private registry, so these tests never
// touch prometheus.DefaultRegisterer and cannot be affected by, or affect,
// anything else in the process.
func newVec(name string, labels ...string) *prometheus.CounterVec {
	return prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: name, Help: "test"}, labels,
	)
}

// TestAnUnboundedLabelIsCaught is the whole point of this package, expressed as
// the experiment #3720 asks for: take a metric whose label value comes from
// caller-supplied data, drive it with several distinct caller values, and
// require the check to fail.
//
// It also runs the POSITIVE CONTROL in the same function - the identical metric
// with the value put through a bounding step first - because a checker that
// reported everything would pass the first half and prove nothing.
func TestAnUnboundedLabelIsCaught(t *testing.T) {
	// The caller-supplied values. These are what a header, a client id or a
	// parsed enum's fall-through render looks like.
	callerValues := []string{
		"CapabilityStatus(9999)",
		"CapabilityStatus(10000)",
		"mcp-proxy/0.3.1",
		"acct_9f2c1ab4",
	}

	// --- THE DEFECT: the value reaches the label unbounded. ---
	unbounded := newVec("axonflow_test_unbounded_total", "outcome", "status")
	for _, v := range callerValues {
		unbounded.WithLabelValues("allow", v).Inc()
	}
	domains := map[string]Domain{
		"outcome": Closed("the handler's own verdict constant", "allow", "deny"),
		"status": Closed("SHOULD be the declared status vocabulary",
			"supported", "no_record", "declared_none"),
	}
	problems := Check("axonflow_test_unbounded_total", unbounded, domains)
	if len(problems) == 0 {
		t.Fatal("an unbounded label emitted four distinct caller-supplied values and Check reported " +
			"nothing. This is the exact class #3720 exists for, and a checker blind to it is the " +
			"list-vs-list test again with more code")
	}
	got := strings.Join(problems, "\n")
	for _, v := range callerValues {
		if !strings.Contains(got, v) {
			t.Errorf("Check did not name the escaping value %q. A report that says a label is wrong "+
				"without saying WHICH value escaped cannot be acted on.\ngot:\n%s", v, got)
		}
	}
	if strings.Contains(got, `label "outcome"`) {
		t.Errorf("the bounded label was reported as well as the unbounded one:\n%s", got)
	}

	// --- THE POSITIVE CONTROL: same metric, value put through a bounding step. ---
	bound := newVec("axonflow_test_bounded_total", "outcome", "status")
	boundingStep := func(v string) string {
		for _, declared := range []string{"supported", "no_record", "declared_none"} {
			if v == declared {
				return v
			}
		}
		return "undeclared"
	}
	for _, v := range callerValues {
		bound.WithLabelValues("allow", boundingStep(v)).Inc()
	}
	domains["status"] = Closed("bounded by boundingStep, whose fall-through is a named constant",
		"supported", "no_record", "declared_none", "undeclared")
	if problems := Check("axonflow_test_bounded_total", bound, domains); len(problems) != 0 {
		t.Errorf("the SAME four caller values, put through a bounding step, were reported as "+
			"defective: %v. Without this half, the failure above would be evidence about a checker "+
			"that always complains.", problems)
	}
}

// TestAnUndeclaredLabelIsReported covers the other direction: a label added to
// a metric that no domain mentions.
//
// A domain map is a claim about EVERY label, and a new label position is a new
// cardinality decision. Deriving the checked set from what was actually emitted
// - rather than iterating the declared map - is what makes that so.
func TestAnUndeclaredLabelIsReported(t *testing.T) {
	v := newVec("axonflow_test_new_label_total", "outcome", "tenant")
	v.WithLabelValues("allow", "acme").Inc()

	problems := Check("axonflow_test_new_label_total", v, map[string]Domain{
		"outcome": Closed("verdict constant", "allow", "deny"),
	})
	if len(problems) != 1 || !strings.Contains(problems[0], `label "tenant"`) {
		t.Fatalf("an undeclared label was reported as %v; a checker that only walks the DECLARED map "+
			"cannot see a label somebody added, which is how a per-tenant label reaches production", problems)
	}
}

// TestShapedDomainsAdmitAndBound covers the fourth bounding idiom - a shape
// allowlist plus a per-process series cap - which is the only one that admits a
// value nobody enumerated. Getting this wrong in either direction is fatal: too
// strict and the client-version family is reported as broken, too loose and the
// cap means nothing.
func TestShapedDomainsAdmitAndBound(t *testing.T) {
	shape := regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

	// A well-formed slug nobody enumerated IS admitted - the forward-compat
	// case the family's own doc requires.
	v := newVec("axonflow_test_shaped_total", "client")
	v.WithLabelValues("some-new-sdk").Inc()
	v.WithLabelValues("overflow").Inc()
	dom := map[string]Domain{
		"client": Shaped("shape allowlist plus a 1024-series cap", shape, 1024, "overflow"),
	}
	if problems := Check("axonflow_test_shaped_total", v, dom); len(problems) != 0 {
		t.Errorf("a shape-valid slug and the overflow token were reported as defective: %v", problems)
	}

	// A value that does NOT match the shape is refused - a header smuggling a
	// label separator is the case that matters.
	bad := newVec("axonflow_test_shaped_bad_total", "client")
	bad.WithLabelValues(`mcp-proxy/0.3.0",deployment_mode="community`).Inc()
	problems := Check("axonflow_test_shaped_bad_total", bad, dom)
	if len(problems) != 1 || !strings.Contains(problems[0], "deployment_mode") {
		t.Fatalf("a shape-violating value was reported as %v", problems)
	}

	// THE CAP IS A SEPARATE BOUND FROM THE SHAPE. Every value below matches
	// the shape, so only the cap can refuse them - which is the half a
	// shape-only check would miss.
	many := newVec("axonflow_test_capped_total", "client")
	for i := 0; i < 12; i++ {
		many.WithLabelValues(fmt.Sprintf("client-%d", i)).Inc()
	}
	capped := map[string]Domain{
		"client": Shaped("shape plus a cap of 10", shape, 10, "overflow"),
	}
	problems = Check("axonflow_test_capped_total", many, capped)
	if len(problems) != 1 || !strings.Contains(problems[0], "above its declared cap") {
		t.Fatalf("12 shape-valid values against a cap of 10 were reported as %v; the cap is the only "+
			"bound on a shaped domain and a check that skipped it would admit unbounded cardinality "+
			"from values that all look well-formed", problems)
	}
}

// TestZeroSeriesIsReported is the anti-vacuity floor.
//
// A Reset() followed by a driver that silently did nothing produces a collector
// with no children, and every domain then passes against nothing. That is
// indistinguishable from a correct metric unless something says so.
func TestZeroSeriesIsReported(t *testing.T) {
	v := newVec("axonflow_test_empty_total", "outcome")
	problems := Check("axonflow_test_empty_total", v, map[string]Domain{
		"outcome": Closed("verdict", "allow"),
	})
	if len(problems) != 1 || !strings.Contains(problems[0], "no series were collected") {
		t.Fatalf("an empty collector was reported as %v; a domain checked against nothing is a green "+
			"result that asserted nothing", problems)
	}
}

// TestTheVerdictDoesNotDependOnLabelOrder pins the property a Prometheus
// exposition makes easy to get wrong: label pairs come back sorted by NAME, and
// the order of series within a family is not the caller's to choose.
//
// The first version of a check like this is nearly always a joined string
// compared against an expected rendering, which passes on the machine it was
// written on and fails when a label is renamed to something that sorts
// differently ([[reference_a_prometheus_exposition_sorts_labels_alphabetically]]).
func TestTheVerdictDoesNotDependOnLabelOrder(t *testing.T) {
	dom := map[string]Domain{
		"aaa_first": Closed("sorts first", "x"),
		"zzz_last":  Closed("sorts last", "y"),
	}

	// Same two labels, declared to the vec in opposite orders. The exposition
	// sorts them either way, so the verdict must be identical.
	forward := newVec("axonflow_test_order_a_total", "aaa_first", "zzz_last")
	forward.WithLabelValues("x", "y").Inc()
	reverse := newVec("axonflow_test_order_b_total", "zzz_last", "aaa_first")
	reverse.WithLabelValues("y", "x").Inc()

	if p := Check("axonflow_test_order_a_total", forward, dom); len(p) != 0 {
		t.Errorf("declaration order aaa,zzz was reported as defective: %v", p)
	}
	if p := Check("axonflow_test_order_b_total", reverse, dom); len(p) != 0 {
		t.Errorf("declaration order zzz,aaa was reported as defective: %v. The judgement is keyed by "+
			"label NAME precisely so that it cannot depend on this.", p)
	}

	// And the escaping value is found whichever position it sits in.
	bad := newVec("axonflow_test_order_c_total", "zzz_last", "aaa_first")
	bad.WithLabelValues("y", "ESCAPED").Inc()
	p := Check("axonflow_test_order_c_total", bad, dom)
	if len(p) != 1 || !strings.Contains(p[0], "ESCAPED") {
		t.Fatalf("an escaping value in the second-declared position was reported as %v", p)
	}
}

// TestAMissingReasonIsReported pins the one field that is easy to leave empty
// and impossible to notice: Why.
//
// A domain is a claim about where a value comes from. A list of strings with no
// reason attached is a list the next reader has to re-derive from the call
// sites, which is the work the declaration exists to save - and the failure
// message would then say a value escaped without saying what was supposed to
// bound it.
func TestAMissingReasonIsReported(t *testing.T) {
	v := newVec("axonflow_test_reason_total", "outcome")
	v.WithLabelValues("nope").Inc()
	problems := Check("axonflow_test_reason_total", v, map[string]Domain{
		"outcome": Closed("the handler's verdict constant, never caller input", "allow"),
	})
	if len(problems) != 1 {
		t.Fatalf("want one problem, got %v", problems)
	}
	if !strings.Contains(problems[0], "the handler's verdict constant") {
		t.Errorf("the failure did not carry the domain's reason:\n%s", problems[0])
	}
	if !strings.Contains(problems[0], "one of [allow]") {
		t.Errorf("the failure did not describe the domain:\n%s", problems[0])
	}
}

// TestAnEmptyWhyIsReported is the half the old name promised and did not
// deliver.
//
// The function used to be called TestEveryDomainCarriesAReason and asserted
// only that a POPULATED reason is interpolated into the failure message. It did
// not check that any domain HAS one, and nothing else did either: two mutants
// blanking a Why survived every lane. A name that overclaims its assertion, in
// the package arguing that names must match claims.
func TestAnEmptyWhyIsReported(t *testing.T) {
	v := newVec("axonflow_test_no_why_total", "outcome")
	v.WithLabelValues("allow").Inc()
	problems := Check("axonflow_test_no_why_total", v, map[string]Domain{
		"outcome": Closed("", "allow"), // admits the value; carries no reason
	})
	if len(problems) != 1 || !strings.Contains(problems[0], "carries no Why") {
		t.Fatalf("a domain with an empty Why was reported as %v. The value is admitted, so nothing "+
			"else can see the omission - which is why Check has to.", problems)
	}
	// Whitespace is not a reason either.
	v2 := newVec("axonflow_test_blank_why_total", "outcome")
	v2.WithLabelValues("allow").Inc()
	if p := Check("axonflow_test_blank_why_total", v2, map[string]Domain{
		"outcome": Closed("   ", "allow"),
	}); len(p) != 1 {
		t.Errorf("a whitespace-only Why was reported as %v", p)
	}
}

// TestAnAdmissionSetWithNoShapeIsExpressible covers the third bounding idiom -
// identity.BoundedOrgLabel, which admits the first N organization ids VERBATIM,
// whatever they look like, and collapses the rest to an overflow token.
//
// The package doc claimed all four idioms were expressible and this one was
// not: with Shape nil, admits() fell through to `return false` and rejected
// every real value. Nothing failed because no guarded domain used it - a claim
// nobody had exercised, which is the shape this package exists to remove.
func TestAnAdmissionSetWithNoShapeIsExpressible(t *testing.T) {
	dom := map[string]Domain{
		"org": Shaped("identity.BoundedOrgLabel: first 100 org ids verbatim, the rest collapsed",
			nil, 3, "__over_cap__", "__none__"),
	}

	v := newVec("axonflow_test_admission_total", "org")
	for _, org := range []string{"acme", "globex", "__over_cap__"} {
		v.WithLabelValues(org).Inc()
	}
	if problems := Check("axonflow_test_admission_total", v, dom); len(problems) != 0 {
		t.Errorf("arbitrary org ids under an admission-set domain were reported as defective: %v. "+
			"That idiom admits values nobody enumerated - the cap is the bound, not a shape.", problems)
	}

	// THE CAP IS STILL THE BOUND. Without this the arm above would admit
	// everything unconditionally, which is worse than rejecting everything.
	over := newVec("axonflow_test_admission_over_total", "org")
	for _, org := range []string{"a", "b", "c", "d"} {
		over.WithLabelValues(org).Inc()
	}
	problems := Check("axonflow_test_admission_over_total", over, dom)
	if len(problems) != 1 || !strings.Contains(problems[0], "above its declared cap") {
		t.Fatalf("4 distinct values against a cap of 3 were reported as %v; with no shape to refuse "+
			"anything, the cap is the ONLY bound this domain has", problems)
	}
}
