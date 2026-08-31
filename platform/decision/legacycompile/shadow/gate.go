package shadow

import (
	"fmt"
	"sort"
	"strings"

	"axonflow/platform/decision/legacycompile"
)

// GateOptions configure the shadow gate.
type GateOptions struct {
	// AllowUnexercisedRows permits a plane to have compiled rows the corpus
	// never reached. It defaults to false, and turning it on is how a team
	// says out loud that it is accepting an unmeasured population - which is
	// a decision, not a default.
	AllowUnexercisedRows bool
	// RequirePlanes are the planes that must have been exercised at all. A
	// plane that compiled policy and ran zero cases fails the gate.
	RequirePlanes []legacycompile.Plane
}

// GateResult is the gate's finding, whether or not it passed.
type GateResult struct {
	Passed bool
	// Failures are the reasons, one per line, in a stable order.
	Failures []string
	// Summary is the per-plane counter block an operator reads.
	Summary string
}

// Gate is ADR-065 acceptance gate 18, executable.
//
// Gate 18 reads "shadow migration has no unexplained fail-open difference for
// the agreed window". Two halves of that sentence are load bearing and both
// are enforced here:
//
//	UNEXPLAINED == 0        the numerator
//	over a non-vacuous run  the denominator
//
// The denominator is the half a gate usually forgets. Zero unexplained
// differences out of zero comparisons is the vacuity-at-zero class: it passes
// forever, it passes hardest when the corpus is broken, and it passes silently.
// So this gate fails on an empty corpus, on a plane with compiled policy and
// no cases, and - unless explicitly allowed - on any compiled row the corpus
// never reached.
//
// A note on direction. Gate 18 names fail-OPEN differences specifically, and
// this gate deliberately fails on EVERY unexplained difference, not only the
// fail-open ones. An unexplained difference in the safe direction is still a
// difference nobody can account for, and "we did not understand it but it
// looked strict" is not a migration record. The direction is recorded on each
// record so the fail-open subset can be counted separately, and it is: the
// summary reports it.
func Gate(run *Run, opts GateOptions) GateResult {
	res := GateResult{Passed: true}
	if run == nil {
		return GateResult{Passed: false, Failures: []string{"the shadow run is nil: nothing was compared"}}
	}

	// --- the denominator ---
	//
	// The corpus builder emits a baseline case per plane unconditionally, so
	// len(Records) is never zero from the real entry point and the check below
	// alone would be unreachable in production. The ENFORCED-ROW total is the
	// check that actually bites: a report with nothing behind it produces one
	// synthetic baseline comparison per plane, every one of them a match, and
	// a green gate over no policy at all.
	compiledRows := 0
	for _, cov := range run.Coverage {
		compiledRows += len(cov.CompiledRows)
	}
	if compiledRows == 0 {
		res.Passed = false
		res.Failures = append(res.Failures,
			"zero enforced policy rows: no plane has a single row the legacy engine enforces, so every comparison in this run "+
				"is between two empty policy sets. That is the vacuity-at-zero failure in the shape the pipeline can actually produce.")
	}
	for _, claim := range run.UnreachedClaims {
		res.Passed = false
		res.Failures = append(res.Failures, "corpus defect: "+claim)
	}
	if len(run.Records) == 0 {
		res.Passed = false
		res.Failures = append(res.Failures,
			"zero comparisons: an empty corpus reports zero unexplained differences and proves nothing. "+
				"This is the vacuity-at-zero failure the gate exists to refuse.")
	}
	for _, plane := range opts.RequirePlanes {
		if run.Coverage[plane].Cases == 0 {
			res.Passed = false
			res.Failures = append(res.Failures, fmt.Sprintf(
				"plane %q is required but the corpus ran zero cases against it", plane))
		}
	}
	var planes []legacycompile.Plane
	for p := range run.Coverage {
		planes = append(planes, p)
	}
	sort.Slice(planes, func(i, j int) bool { return planes[i] < planes[j] })
	for _, p := range planes {
		cov := run.Coverage[p]
		if len(cov.CompiledRows) > 0 && cov.Cases == 0 {
			res.Passed = false
			res.Failures = append(res.Failures, fmt.Sprintf(
				"plane %q compiled %d policy row(s) and ran zero cases; a plane with policy and no comparisons is unmeasured, not clean",
				p, len(cov.CompiledRows)))
		}
		if len(cov.UnexercisedRows) > 0 && !opts.AllowUnexercisedRows {
			res.Passed = false
			res.Failures = append(res.Failures, fmt.Sprintf(
				"plane %q has %d compiled row(s) the corpus never reached: %s. "+
					"Coverage is per-plane AND per-policy-row; an unreached row's behaviour is unknown, not equal.",
				p, len(cov.UnexercisedRows), strings.Join(cov.UnexercisedRows, ", ")))
		}
	}

	// --- the numerator ---
	for _, rec := range run.Unexplained() {
		res.Passed = false
		res.Failures = append(res.Failures, fmt.Sprintf(
			"UNEXPLAINED difference on plane %q, case %q (%s): %s",
			rec.Plane, rec.CaseID, rec.FailOpen, rec.Detail))
	}

	res.Summary = summarize(run)
	return res
}

func summarize(run *Run) string {
	var b strings.Builder
	if run.Provenance != "" {
		fmt.Fprintf(&b, "%s\n", run.Provenance)
	}
	total := run.CountsByClass()
	fmt.Fprintf(&b, "shadow diff summary: %d comparison(s) - match=%d expected_change=%d UNEXPLAINED=%d\n",
		len(run.Records), total[ClassMatch], total[ClassExpectedChange], total[ClassUnexplained])

	failOpen := map[FailOpenDirection]int{}
	unexplainedFailOpen := 0
	for _, rec := range run.Records {
		failOpen[rec.FailOpen]++
		if rec.Class == ClassUnexplained && rec.FailOpen == FailOpenNewPermitted {
			unexplainedFailOpen++
		}
	}
	fmt.Fprintf(&b, "executability: agree=%d legacy_permitted_new_denied=%d new_permitted_legacy_denied=%d (unexplained fail-open: %d)\n",
		failOpen[FailOpenNone], failOpen[FailOpenLegacyPermitted], failOpen[FailOpenNewPermitted], unexplainedFailOpen)

	byPlane := run.CountsByPlaneAndClass()
	var planes []legacycompile.Plane
	for p := range run.Coverage {
		planes = append(planes, p)
	}
	sort.Slice(planes, func(i, j int) bool { return planes[i] < planes[j] })
	for _, p := range planes {
		c := byPlane[p]
		cov := run.Coverage[p]
		fmt.Fprintf(&b, "  %-22s cases=%-4d rows %d/%d exercised  match=%d expected=%d UNEXPLAINED=%d\n",
			p, cov.Cases, len(cov.ExercisedRows), len(cov.CompiledRows),
			c[ClassMatch], c[ClassExpectedChange], c[ClassUnexplained])
		if len(cov.UnexercisedRows) > 0 {
			fmt.Fprintf(&b, "  %-22s unexercised rows: %s\n", "", strings.Join(cov.UnexercisedRows, ", "))
		}
		if len(cov.UnmeasurableRows) > 0 {
			fmt.Fprintf(&b, "  %-22s UNMEASURABLE rows (outside the fraction above): %s\n", "", strings.Join(cov.UnmeasurableRows, ", "))
		}
	}
	if len(run.ModelLimitations) > 0 {
		b.WriteString("legacy-model limitations (not reproduced, therefore not diffed):\n")
		for _, l := range run.ModelLimitations {
			fmt.Fprintf(&b, "  - %s\n", l)
		}
	}
	for _, l := range run.CompiledLimitations {
		fmt.Fprintf(&b, "compiler limitation %s (%s): %s\n", l.Issue, l.Scope, l.Detail)
	}
	return b.String()
}
