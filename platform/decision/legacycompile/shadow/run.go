package shadow

import (
	"context"
	"fmt"
	"sort"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
)

// Run is the result of one shadow evaluation pass.
type Run struct {
	Records []DiffRecord `json:"records"`
	// Coverage is per-plane, and inside a plane it is per-policy-row. An
	// unexercised row is REPORTED, never silently absent: a diff harness whose
	// corpus never reached half the policy set is not a clean run, it is an
	// unmeasured one.
	Coverage map[legacycompile.Plane]PlaneCoverage `json:"coverage"`
	// ModelLimitations names what the legacy side did not reproduce.
	ModelLimitations []string `json:"model_limitations"`
	// CompiledLimitations are the compiler's population-wide gaps.
	CompiledLimitations []legacycompile.Limitation `json:"compiled_limitations"`
	// UnreachedClaims names every case that declared it would exercise a row
	// and did not. A corpus whose cases quietly miss their target reports
	// clean coverage of whatever it happened to touch.
	UnreachedClaims []string `json:"unreached_claims,omitempty"`
	// Provenance says WHAT WAS COMPARED, in one line, at the top of the
	// summary.
	//
	// Without it an operator reading UNEXPLAINED=0 has no way to tell a
	// six-row fixture corpus from a captured production policy set, and no way
	// to tell generated cases from replayed traffic. The PR that introduced
	// this harness made exactly that mistake in its own body, presenting the
	// fixture gate's numbers immediately after a 112-row capture's, and a
	// reader cannot be expected to be more careful than the artifact.
	Provenance string `json:"provenance"`
}

// PlaneCoverage records what a run reached on one plane.
type PlaneCoverage struct {
	// Cases is the number of replay cases evaluated on this plane.
	Cases int `json:"cases"`
	// CompiledRows is every source row that produced at least one policy on
	// this plane.
	CompiledRows []string `json:"compiled_rows"`
	// ExercisedRows is the subset a case actually reached, meaning the row
	// appeared in at least one side's determining set.
	ExercisedRows []string `json:"exercised_rows"`
	// UnexercisedRows is the difference. It is the field that stops a green
	// gate from meaning "we compared nothing".
	UnexercisedRows []string `json:"unexercised_rows"`
	// UnmeasurableRows are rows that exist on this plane and contribute
	// NOTHING the harness can compare: a dynamic row whose only action is
	// modify_risk, or one whose action type the orchestrator's switch has no
	// arm for. They are outside the exercised/compiled fraction entirely, and
	// leaving them merely absent made "rows N/N exercised" read as "we
	// measured this plane's policy set" when two of three captured rows were
	// not in the fraction at all.
	UnmeasurableRows []string `json:"unmeasurable_rows,omitempty"`
}

// CountsByClass returns the diff record count per classification.
func (r Run) CountsByClass() map[Classification]int {
	out := map[Classification]int{
		ClassMatch: 0, ClassExpectedChange: 0, ClassUnexplained: 0,
	}
	for _, rec := range r.Records {
		out[rec.Class]++
	}
	return out
}

// CountsByPlaneAndClass returns per-plane counters, which is what an operator
// reads to decide whether ONE plane can leave shadow mode while another
// cannot.
func (r Run) CountsByPlaneAndClass() map[legacycompile.Plane]map[Classification]int {
	out := map[legacycompile.Plane]map[Classification]int{}
	for _, rec := range r.Records {
		if out[rec.Plane] == nil {
			out[rec.Plane] = map[Classification]int{
				ClassMatch: 0, ClassExpectedChange: 0, ClassUnexplained: 0,
			}
		}
		out[rec.Plane][rec.Class]++
	}
	return out
}

// Unexplained returns every unexplained difference.
func (r Run) Unexplained() []DiffRecord {
	var out []DiffRecord
	for _, rec := range r.Records {
		if rec.Class == ClassUnexplained {
			out = append(out, rec)
		}
	}
	return out
}

// NewDecider is the ADR-065 side of the harness: something that decides a
// normalized request. In the harness it is a real pdp.Engine over the compiled
// bundles.
type NewDecider interface {
	Decide(ctx context.Context, req *contract.Request) (*contract.Decision, error)
}

// Execute dual-evaluates every case and classifies every difference.
func Execute(ctx context.Context, cases []Case, legacy LegacyEvaluator, nw NewDecider, rep *legacycompile.Report, bundleDigest string) (*Run, error) {
	if legacy == nil || nw == nil || rep == nil {
		return nil, fmt.Errorf("shadow: a run needs a legacy evaluator, a decider and a compilation report; a missing side would compare a verdict against nothing and report agreement")
	}
	run := &Run{
		Coverage:            map[legacycompile.Plane]PlaneCoverage{},
		ModelLimitations:    ModelLimitations(),
		CompiledLimitations: rep.KnownLimitations,
	}
	exercised := map[legacycompile.Plane]map[string]bool{}

	for _, c := range cases {
		if _, err := legacycompile.SpecFor(c.Plane); err != nil {
			return nil, fmt.Errorf("shadow: case %q: %w", c.ID, err)
		}
		lv, err := legacy.Evaluate(ctx, c)
		if err != nil {
			return nil, fmt.Errorf("shadow: case %q legacy side: %w", c.ID, err)
		}
		req, err := c.Request(rep, bundleDigest)
		if err != nil {
			return nil, err
		}
		dec, err := nw.Decide(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("shadow: case %q ADR-065 side: %w", c.ID, err)
		}
		nv, err := FromDecision(dec)
		if err != nil {
			return nil, fmt.Errorf("shadow: case %q: %w", c.ID, err)
		}

		rec := Classify(ClassifyInput{Case: c, Legacy: lv, New: nv, Decision: dec, Report: rep})
		run.Records = append(run.Records, rec)

		if exercised[c.Plane] == nil {
			exercised[c.Plane] = map[string]bool{}
		}
		for _, id := range SourceDetermining(lv) {
			exercised[c.Plane][id] = true
		}
		for _, id := range SourceDetermining(nv) {
			exercised[c.Plane][id] = true
		}
		// A case that CLAIMED a row and did not reach it is a corpus defect,
		// and it is the one shape the coverage numbers cannot show on their
		// own: the row just appears unexercised, with nothing pointing at the
		// case that was meant to reach it.
		//
		// Checked against THIS case's own determining sets, not the plane's
		// cumulative set. Reading the cumulative set let a case that reached
		// nothing pass because an earlier case on the same plane had reached
		// the row - which is order-dependent and silent.
		reachedHere := map[string]bool{}
		for _, id := range SourceDetermining(lv) {
			reachedHere[id] = true
		}
		for _, id := range SourceDetermining(nv) {
			reachedHere[id] = true
		}
		for _, want := range c.ExercisesRows {
			if !reachedHere[want] {
				run.UnreachedClaims = append(run.UnreachedClaims, fmt.Sprintf(
					"case %q claims to exercise row %q on plane %q and neither engine named it",
					c.ID, want, c.Plane))
			}
		}
		cov := run.Coverage[c.Plane]
		cov.Cases++
		run.Coverage[c.Plane] = cov
	}

	// Coverage is computed over every plane the report compiled for, not only
	// the planes the corpus happened to visit. A plane with compiled rows and
	// zero cases has to appear with zero coverage, because that is exactly the
	// state a reader would otherwise mistake for "nothing to compare".
	for _, plane := range legacycompile.AllPlanes() {
		rows := rep.RowsFor(plane)
		if len(rows) == 0 && run.Coverage[plane].Cases == 0 {
			continue
		}
		cov := run.Coverage[plane]
		seen := map[string]bool{}
		for _, r := range rows {
			// Keyed on (table, policy_id): the two legacy tables have
			// independent id spaces and a shared id would otherwise collapse
			// two rows into one coverage entry, so exercising either would
			// report both as covered.
			k := RowKeyFor(r.Table, r.PolicyID)
			if seen[k] {
				continue
			}
			seen[k] = true
			cov.CompiledRows = append(cov.CompiledRows, k)
		}
		sort.Strings(cov.CompiledRows)
		for id := range exercised[plane] {
			if seen[id] {
				cov.ExercisedRows = append(cov.ExercisedRows, id)
			}
		}
		sort.Strings(cov.ExercisedRows)
		hit := map[string]bool{}
		for _, id := range cov.ExercisedRows {
			hit[id] = true
		}
		for _, id := range cov.CompiledRows {
			if !hit[id] {
				cov.UnexercisedRows = append(cov.UnexercisedRows, id)
			}
		}
		for _, rec := range rep.Records {
			if rec.ContributesTo(plane) {
				continue
			}
			// "Unmeasurable" means the row is APPLICABLE here and still
			// contributes nothing the harness can compare. A row the plane's
			// phase excludes, one the legacy reader drops, and one the
			// readers' own WHERE clause excludes are all applicable-elsewhere
			// or enforced-nowhere; counting them here would bury the rows that
			// genuinely enforce something under a list of rows that do not
			// belong on the plane at all.
			applicable := false
			for _, pr := range rec.Planes {
				if pr.Plane != plane {
					continue
				}
				excluded := false
				for _, rs := range pr.Reasons {
					switch rs.Code {
					case legacycompile.ReasonPhaseNotEvaluatedHere,
						legacycompile.ReasonLegacyScanDrop,
						legacycompile.ReasonExcludedByLegacyPredicate:
						excluded = true
					}
				}
				if !excluded {
					applicable = true
				}
			}
			if applicable {
				cov.UnmeasurableRows = append(cov.UnmeasurableRows, RowKeyFor(rec.Source.Table, rec.Source.PolicyID))
			}
		}
		sort.Strings(cov.UnmeasurableRows)
		run.Coverage[plane] = cov
	}
	return run, nil
}
