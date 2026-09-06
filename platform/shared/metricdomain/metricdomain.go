// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package metricdomain states, and checks, what values a Prometheus label is
// allowed to take.
//
// # WHY THIS EXISTS (#3720)
//
// A label whose value comes from caller-supplied data mints one time series per
// distinct value, and eventually takes down the scrape. Every metric in this
// tree already CLAIMS to be bounded, in prose, at its declaration:
//
//	"It is a CLOSED, low-cardinality enum by construction (never a raw
//	 hostname/email/version)"          - decision_handler.go, decideRequests
//	"All labels are bounded: obligation type (fixed enum), action (log|block)"
//	                                   - decision_handler.go, decideObligationFallbacks
//	"The `policy` label is BOUNDED to a low-cardinality set by boundedBlockPolicy"
//	                                   - decision_handler.go, decideBlocks
//
// # WHAT WAS AND WAS NOT ALREADY CHECKED (corrected after R3 measured it)
//
// gateway-adapters/telemetry_test.go's TestNoLabelCarriesRequestContent - the
// test whose NAME claims this property - compares a list of expected label
// NAMES against the actual ones. It reads l.GetName() and never l.GetValue(),
// and its doc states the premise it cannot verify: "both label values come from
// the constants above and there is no path by which a request can introduce a
// tenth". That test is blind to the class by construction.
//
// It would be FALSE to say nothing checked it. Substituting a request header
// for the constant at that metric's call site IS killed - by sibling tests in
// the same file, which collect the vec and key on the emitted (surface,
// outcome) TUPLE, reading GetValue().
//
// The handshake family in platform/agent is checked differently, and the
// difference is the point. Three tests there
// (TestEveryOutcomeTheResolverProducesIsADeclaredLabel and two siblings) drive
// the real resolver and assert its answer is a declared member - one of them
// BIDIRECTIONALLY, which is stronger than anything here on that label. But none
// of the three COLLECTS THE VEC: they read the resolver's return value, or
// recompute contract.FamilyOf inside the test. Writing the raw capability type
// into the family label therefore passes all three and fails only the check
// here, because only this one reads what was actually emitted.
//
// What did not exist is a SHAPE: something that (1) forces every label of every
// guarded metric to have a declared, auditable domain, so a new label is a
// decision rather than a diff, (2) reads the value AS EMITTED rather than
// re-deriving it in the test - the pre-existing family test recomputes
// contract.FamilyOf inside itself, which tests a lookalike - and (3) can
// express the four different ways this tree bounds a label, so it does not
// report correct code. That is what this package is.
//
// # WHAT A DOMAIN IS
//
// The tree bounds labels in four different ways, and a declaration has to be
// able to express each or it will report a correct call site as a defect:
//
//   - a CLOSED enum, mapped through a helper whose fall-through is a named
//     constant (classifyDecisionOrigin -> OriginUnknown; capabilityRefusalStatusLabel
//     -> "undeclared"; metricPathLabel -> "invalid"; planeLabel -> "unattributed")
//   - a closed enum with no helper, where the values are compile-time literals
//   - an admission SET with a cap and an overflow bucket (identity.BoundedOrgLabel:
//     first 100 org ids admitted verbatim, everything after -> "__over_cap__")
//   - a SHAPE allowlist plus a per-process series cap (client_version_telemetry:
//     a regexp gate on the value, then at most 1024 distinct label tuples,
//     the 1025th counted as "overflow" instead)
//
// Closed and Shaped below are those four: the first two are Closed, the last
// two are Shaped with a Cap.
//
// # THIS IS A TESTING HELPER
//
// It is an ordinary package rather than a _test.go file so several packages can
// share one vocabulary - net/http/httptest's arrangement, and for the same
// reason. Nothing outside a test imports it, so it is linked into test binaries
// only.
package metricdomain

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// Domain is the permitted value set for ONE label of one metric.
//
// Why is REQUIRED - Check reports a domain without one - and is not decoration:
// a domain is a claim about where the value comes from, and a bare list of
// strings is a claim nobody can audit against the code. It is the prose that
// used to sit at the declaration, moved somewhere that fails when it stops
// being true.
//
// An earlier draft of this comment said "required by Declare below". There is
// no Declare function in this package and never was, and nothing validated Why
// at all: two mutants blanking a Why survived every lane. A comment asserting
// an enforcement that does not exist is worse than no comment, because the next
// reader stops at it.
type Domain struct {
	// Values is the closed set. Empty means the domain is Shaped instead.
	Values []string
	// Shape admits any value matching it. Nil for a closed domain.
	Shape *regexp.Regexp
	// Overflow are the bounded tokens a bounding step substitutes for a value
	// it refuses - "unknown", "__over_cap__", "undeclared". Always admitted.
	Overflow []string
	// Cap is the maximum number of DISTINCT values, for a Shaped domain whose
	// bound is an admission set rather than an enumeration. Zero means the
	// Values/Shape check is the whole bound.
	Cap int
	// Why says where the value comes from and what bounds it.
	Why string
}

// Closed declares a label whose value is one of a fixed set.
func Closed(why string, values ...string) Domain {
	return Domain{Values: values, Why: why}
}

// Shaped declares a label that admits any value matching shape, at most cap
// distinct ones, plus the named overflow tokens.
//
// This is the ONLY kind that admits a value nobody enumerated, and it is the
// kind the client-version family needs: its own doc says "validation is a shape
// allowlist, not a client-id allowlist: a well-formed but unrecognized slug (a
// forward-compat new client) is admitted, bounded by the per-process series
// cap". A checker that could not express that would have to report that family
// as unbounded, and a checker that reports correct code gets deleted.
func Shaped(why string, shape *regexp.Regexp, cap int, overflow ...string) Domain {
	return Domain{Shape: shape, Cap: cap, Overflow: overflow, Why: why}
}

// admits reports whether v is inside the domain.
func (d Domain) admits(v string) bool {
	for _, o := range d.Overflow {
		if v == o {
			return true
		}
	}
	for _, allowed := range d.Values {
		if v == allowed {
			return true
		}
	}
	if d.Shape != nil {
		return d.Shape.MatchString(v)
	}
	// IDIOM 3: an admission SET with a cap and an overflow bucket, and no shape
	// at all - identity.BoundedOrgLabel admits the first 100 organization ids
	// VERBATIM, whatever they look like, and collapses the rest.
	//
	// The package doc claimed all four idioms were expressible and this arm did
	// not exist, so `Shaped(why, nil, 100, "__over_cap__")` rejected every real
	// value. No guarded domain used it, which is the only reason nothing failed
	// - a claim nobody had exercised. The Cap is the whole bound here, and Check
	// enforces it below.
	if d.Cap > 0 && len(d.Values) == 0 {
		return true
	}
	return false
}

// Check collects c's OWN children and reports every way the emitted labels
// escape byLabel.
//
// # IT COLLECTS THE VEC, NOT THE REGISTRY
//
// Every metric in this tree is on prometheus.DefaultRegisterer, and a CounterVec
// retains every child for the process lifetime, so a whole-registry Gather()
// would be reading whatever earlier tests in the package left behind. The
// caller is expected to Reset() the vec first, which makes the result an
// assertion about the inputs THIS test drove.
//
// # IT IS ORDER-INDEPENDENT, DELIBERATELY
//
// A Prometheus exposition sorts label pairs alphabetically by name, and the
// order of series within a family is not something a caller controls. So every
// judgement here is set membership keyed by label NAME - never a positional
// index, never a joined string compared against an expected rendering.
func Check(metric string, c prometheus.Collector, byLabel map[string]Domain) []string {
	ch := make(chan prometheus.Metric, 4096)
	go func() {
		c.Collect(ch)
		close(ch)
	}()

	var problems []string
	seriesCount := 0
	// distinct[label] is the set of values seen, for the Cap check.
	distinct := map[string]map[string]bool{}
	// reported suppresses one line per series for a label that is wrong on
	// every one of them.
	reported := map[string]bool{}

	for m := range ch {
		var d dto.Metric
		if err := m.Write(&d); err != nil {
			problems = append(problems, fmt.Sprintf("%s: writing a collected metric failed: %v", metric, err))
			continue
		}
		seriesCount++
		for _, lp := range d.GetLabel() {
			name, value := lp.GetName(), lp.GetValue()
			dom, declared := byLabel[name]
			if !declared {
				key := "undeclared/" + name
				if !reported[key] {
					reported[key] = true
					problems = append(problems, fmt.Sprintf(
						"%s: label %q has no declared domain (seen with value %q). Every label is a "+
							"cardinality decision; one nobody declared is one nobody bounded.",
						metric, name, value))
				}
				continue
			}
			if distinct[name] == nil {
				distinct[name] = map[string]bool{}
			}
			distinct[name][value] = true
			if dom.admits(value) {
				continue
			}
			key := "escaped/" + name + "/" + value
			if reported[key] {
				continue
			}
			reported[key] = true
			problems = append(problems, fmt.Sprintf(
				"%s: label %q emitted %q, which its domain does not admit.\n    domain: %s\n    why:    %s",
				metric, name, value, dom.describe(), dom.Why))
		}
	}

	for name, dom := range byLabel {
		if strings.TrimSpace(dom.Why) == "" {
			problems = append(problems, fmt.Sprintf(
				"%s: the domain for label %q carries no Why. A domain is a claim about where the "+
					"value comes from and what collapses an out-of-domain one; without that, the list "+
					"of permitted strings is something the next reader has to re-derive from the call "+
					"sites, which is the work the declaration exists to save.", metric, name))
		}
		if dom.Cap > 0 && len(distinct[name]) > dom.Cap {
			problems = append(problems, fmt.Sprintf(
				"%s: label %q emitted %d distinct values, above its declared cap of %d",
				metric, name, len(distinct[name]), dom.Cap))
		}
	}

	// ANTI-VACUITY. A collector with no children admits every claim above, and
	// that is exactly what a caller gets from a Reset() followed by a driver
	// that silently did nothing - a green result that asserted nothing.
	if seriesCount == 0 {
		problems = append(problems, fmt.Sprintf(
			"%s: no series were collected, so every domain above was checked against nothing. "+
				"The driver did not reach the write site.", metric))
	}
	sort.Strings(problems)
	return problems
}

func (d Domain) describe() string {
	var parts []string
	if len(d.Values) > 0 {
		v := append([]string(nil), d.Values...)
		sort.Strings(v)
		parts = append(parts, "one of ["+strings.Join(v, " ")+"]")
	}
	if d.Shape != nil {
		parts = append(parts, "matching /"+d.Shape.String()+"/")
	}
	if len(d.Overflow) > 0 {
		o := append([]string(nil), d.Overflow...)
		sort.Strings(o)
		parts = append(parts, "or the overflow token(s) ["+strings.Join(o, " ")+"]")
	}
	if d.Cap > 0 {
		parts = append(parts, fmt.Sprintf("at most %d distinct", d.Cap))
	}
	if len(parts) == 0 {
		return "(empty: admits nothing)"
	}
	return strings.Join(parts, ", ")
}
