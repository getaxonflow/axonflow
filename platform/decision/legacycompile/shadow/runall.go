package shadow

import (
	"context"
	"fmt"
	"sort"

	"axonflow/platform/decision/legacycompile"
)

// noRowsOrgScope is the synthetic scope used when a report has no rows at all.
// It is a real identifier rather than the empty string so the request still
// validates and the gate fails for the reason that matters - zero compiled
// policy rows - instead of failing to build a request.
const noRowsOrgScope = "no-rows-captured"

// RunAll dual-evaluates EVERY enforcement plane and merges the results.
//
// The gate's coverage requirement is per-plane and per-policy-row, so a run
// that visits one plane and reports clean is not a migration measurement - it
// is a measurement of one plane with the rest silently absent. RunAll is the
// entry point CI uses, and it exists so that "we ran the diffs" cannot quietly
// mean "we ran some of them".
//
// Each plane gets its OWN compiled documents, bundles and engine, because the
// planes disagree about the policy set by construction: the proxy tier engine
// reads a different column, a response-phase plane resolves a different action
// column, and a plane with no posture lever resolves a different action again.
// One shared engine would erase exactly the differences the migration is
// looking for.
func RunAll(ctx context.Context, rep *legacycompile.Report, rows map[string]RowFacts, compileOpts legacycompile.Options, opts ...WorldOption) (*Run, error) {
	if rep == nil {
		return nil, fmt.Errorf("shadow: RunAll needs a compilation report")
	}
	merged := &Run{
		Coverage:            map[legacycompile.Plane]PlaneCoverage{},
		ModelLimitations:    ModelLimitations(),
		CompiledLimitations: rep.KnownLimitations,
	}
	// The model is given the SAME content target the compiler used. Both sides
	// have to name the same field for a static redaction or the correspondence
	// compares a configured value against a default.
	contentTarget := compileOpts.ContentTarget
	if contentTarget == "" {
		contentTarget = legacycompile.DefaultContentTarget
	}
	legacy := &ModelEvaluator{Report: rep, Rows: rows, ContentTarget: contentTarget}

	merged.Provenance = fmt.Sprintf(
		"corpus: cases GENERATED from the compiled policy set (not replayed traffic), over %d captured row(s) "+
			"across %d org scope(s); %d of them the legacy engine enforces somewhere",
		rep.InputRows, len(rep.OrgScopes()), enforcedRowCount(rep))

	orgs := rep.OrgScopes()
	if len(orgs) == 0 {
		// No rows at all. One synthetic scope so every plane still produces a
		// coverage entry and the gate's zero-policy-rows arm is what fires,
		// rather than the run being empty for a second reason.
		orgs = []string{noRowsOrgScope}
	}
	for _, plane := range legacycompile.AllPlanes() {
		var planeRecords []DiffRecord
		var planeClaims []string
		// One pass per PHASE on a plane that evaluates more than one, because
		// that is how production runs it: the mcp plane's input pass and
		// output pass each resolve their own action column against their own
		// policy set. A single pass over both phases evaluated two passes as
		// one comparison, and a phase='both' row then contributed both
		// phases' actions to a single verdict. Single-phase planes keep the
		// empty phase, which means "the whole plane" everywhere.
		phases := []legacycompile.Phase{""}
		if spec := legacycompile.MustSpecFor(plane); len(spec.Phases) > 1 {
			phases = spec.Phases
		}
		for _, orgScope := range orgs {
			for _, phase := range phases {
				world, err := NewWorld(ctx, rep, plane, orgScope,
					append([]WorldOption{WithRealm(compileOpts.Realm), WithPhase(phase)}, opts...)...)
				if err != nil {
					return nil, err
				}
				cases := BuildCorpusForPhase(rep, plane, phase, orgScope, rows, compileOpts)
				run, err := Execute(ctx, cases, legacy, world.Engine, rep, world.BundleDigest)
				if err != nil {
					return nil, err
				}
				planeRecords = append(planeRecords, run.Records...)
				planeClaims = append(planeClaims, run.UnreachedClaims...)
				cov := merged.Coverage[plane]
				pc := run.Coverage[plane]
				cov.Cases += pc.Cases
				cov.CompiledRows = mergeSorted(cov.CompiledRows, pc.CompiledRows)
				cov.ExercisedRows = mergeSorted(cov.ExercisedRows, pc.ExercisedRows)
				// Merged, not recomputed. Every field Execute populates has to
				// be carried here or the gate reads a half-filled coverage
				// entry - which is exactly how UnreachedClaims came to be dead
				// in the only entry point CI uses.
				cov.UnmeasurableRows = mergeSorted(cov.UnmeasurableRows, pc.UnmeasurableRows)
				merged.Coverage[plane] = cov
			}
		}
		// Unexercised is recomputed after every org has contributed, because a
		// row is unexercised only if NO org's corpus reached it.
		cov := merged.Coverage[plane]
		hit := map[string]bool{}
		for _, id := range cov.ExercisedRows {
			hit[id] = true
		}
		cov.UnexercisedRows = nil
		for _, id := range cov.CompiledRows {
			if !hit[id] {
				cov.UnexercisedRows = append(cov.UnexercisedRows, id)
			}
		}
		merged.Coverage[plane] = cov
		merged.Records = append(merged.Records, planeRecords...)
		merged.UnreachedClaims = append(merged.UnreachedClaims, planeClaims...)
	}

	// A plane with compiled rows that no pass produced coverage for would be
	// invisible, so it is materialised here rather than left out. This cannot
	// happen while RunAll iterates AllPlanes, and it is asserted anyway,
	// because the failure mode of a coverage map is silence.
	for _, plane := range legacycompile.AllPlanes() {
		if _, ok := merged.Coverage[plane]; ok {
			continue
		}
		rowsFor := rep.RowsFor(plane)
		if len(rowsFor) == 0 {
			continue
		}
		return nil, fmt.Errorf(
			"shadow: plane %q compiled %d policy row(s) and produced no coverage entry; a plane missing from the coverage map is a plane nobody measured",
			plane, len(rowsFor))
	}
	return merged, nil
}

// enforcedRowCount is how many captured rows the legacy engine enforces on at
// least one plane - the population the diff can say anything about.
func enforcedRowCount(rep *legacycompile.Report) int {
	n := 0
	for _, rec := range rep.Records {
		for _, p := range legacycompile.AllPlanes() {
			if rec.ContributesTo(p) {
				n++
				break
			}
		}
	}
	return n
}

// mergeSorted unions two sorted string slices, duplicate-free.
func mergeSorted(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range append(append([]string(nil), a...), b...) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
