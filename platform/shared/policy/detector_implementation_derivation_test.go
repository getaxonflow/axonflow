// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policy

import (
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// RE-DERIVING THE IMPLEMENTATION CLASS AGAINST THE RUNNING BINARY (#3884)
//
// `detectors_census.tsv` classifies twenty of its 101 rows as algorithmic. The
// census derives that from `ValidatorForPolicyID` and `GetValidatorForCategory`
// through a helper - `censusResolveValidator` - that REPRODUCES
// `PolicyLoader.getValidatorForPolicy` rather than calling it.
//
// AN EARLIER VERSION OF THIS COMMENT SAID THAT WAS BECAUSE THE LOADER'S METHOD
// IS UNEXPORTED AND TAKES A RECEIVER. That is not a barrier: both files are
// `package policy`, and `TestTheLoaderAndTheEvaluatorResolveTheSameValidator`
// below calls `loader.getValidatorForPolicy` on a zero-value receiver. There is no reason for the third copy
// beyond nobody having removed it, and #3963 is collapsing all three onto one
// exported composition - which is the right fix and is not this lane's.
//
// A reproduction that agrees with the real thing is indistinguishable from a
// correct one right up until the day the real thing changes, and this
// particular reproduction is four lines that decide whether twenty checksums
// are armed. So this file re-derives the same twenty rows three different ways,
// none of which is a copy of a resolution rule:
//
//  1. THE EVALUATOR'S OWN RESOLUTION. `PatternEvaluator.getValidator` is the
//     function the shared engine calls on the request path. This file calls it,
//     with a receiver, and reads back the function value it returns.
//
//  2. THE LOADER'S OWN RESOLUTION. `PolicyLoader.getValidatorForPolicy` is what
//     pre-sets `CompiledPolicy.Validator` for a database-loaded row. This file
//     calls it too, and requires the two to resolve to the SAME function for
//     every one of the 101 rows. If they ever diverge, a row is gated on one
//     path and bare on the other, which is the shape of the whole
//     `proxy_tier` finding one level down.
//
//  3. BEHAVIOUR, not resolution. A resolved function value is still only a
//     claim that something was consulted. So every algorithmic row is DRIVEN
//     through `PatternEvaluator.Evaluate` with a probe the pattern matches and
//     the validator rejects, and the row is class (b) exactly when the match
//     disappears. The evaluator with validators DISABLED is run over the same
//     probe in the same test as a built-in control: if it does not return a
//     match there, the probe never matched the pattern and the disappearance
//     proved nothing.
//
// The implementation SITE is re-derived as well, through `runtime.FuncForPC` on
// the function value the evaluator returned, and compared to the census's
// `impl_site`. Nobody transcribes it on either side.

// derivationProbes are inputs used to separate a gated detector from a bare
// one.
//
// The probe's job is to be matched by the pattern and REJECTED by whatever
// validator resolves. The pattern is supplied by this test rather than read
// from the corpus, deliberately: a shipped pattern might match none of these
// strings, and then a row would look ungated for a reason that has nothing to
// do with its implementation. Supplying a maximal pattern makes the validator
// the only thing that can decide the outcome, which is the question being
// asked.
//
// More than one probe because a validator that ACCEPTS the first one would
// otherwise make its row look like class (a). The test requires that at least
// one probe separates and names the row when none does, rather than quietly
// choosing a different answer.
var derivationProbes = []string{
	"zzzz",
	"not-a-value",
	"0000000000000000",
	"---",
}

// derivationPattern matches any non-empty input, so the pattern never decides
// the outcome.
const derivationPattern = `.+`

// resolvedValidatorSite renders the defining file and symbol of a resolved
// validator, in the `path::Symbol` form the census uses.
//
// It is derived from the function VALUE, so it cannot name a symbol that has
// moved or does not exist. The file is trimmed to a repository-relative path
// because the absolute one carries the runner's checkout directory.
func resolvedValidatorSite(t *testing.T, v ValidatorFunc) string {
	t.Helper()
	if v == nil {
		return ""
	}
	fn := runtime.FuncForPC(reflect.ValueOf(v).Pointer())
	if fn == nil {
		t.Fatalf("a resolved validator has no runtime function entry; the derivation below cannot name its implementation")
	}
	file, _ := fn.FileLine(fn.Entry())
	name := fn.Name()
	if i := strings.LastIndex(name, "."); i >= 0 {
		name = name[i+1:]
	}
	if i := strings.Index(file, "/platform/"); i >= 0 {
		file = file[i+1:]
	}
	return file + "::" + name
}

// TestTheLoaderAndTheEvaluatorResolveTheSameValidator holds the two resolution
// paths equal over the whole shipped corpus.
//
// They are two different functions in two different files, and the comment on
// each says it shares a single source of truth with the other. This asserts it
// instead.
//
// # IT BECOMES A TAUTOLOGY WHEN #3965 LANDS, AND THAT IS SAID HERE SO IT IS
// # RETIRED RATHER THAN LEFT LOOKING LIKE COVERAGE
//
// #3965 extracts the composition into one exported `ValidatorFor` and collapses
// the loader, the evaluator's fallback and the census's reproduction onto it.
// After that, these two do not "agree" - they call one function, and comparing
// their return values is `f(x) == f(x)`. A test that cannot fail is worse than
// no test, because it reads as coverage. On that day this becomes a CENSUS -
// every resolution site calls the shared function rather than reimplementing
// it, which is a question about the tree rather than about two return values -
// or it is deleted with its reason. It must not be left as it is. The failure it guards against is not hypothetical: the shape it has
// - one path consulting an implementation and another not - is exactly the
// `proxy_tier` plane difference (#3963), which went unnoticed for as long as it
// did because nothing compared two paths that were each individually correct.
func TestTheLoaderAndTheEvaluatorResolveTheSameValidator(t *testing.T) {
	census := loadDetectorCensus(t)
	evaluator := NewPatternEvaluator(true)
	var loader PolicyLoader

	compared := 0
	for _, row := range census {
		cp := &CompiledPolicy{PolicyID: row.PolicyID, Category: PolicyCategory(row.Category), Enabled: true}
		fromEvaluator := evaluator.getValidator(cp)
		fromLoader := loader.getValidatorForPolicy(row.PolicyID, PolicyCategory(row.Category))
		compared++
		if (fromEvaluator == nil) != (fromLoader == nil) {
			t.Errorf("%s: the evaluator resolves %v and the loader resolves %v; a row gated on one path and bare on the other is a control that depends on which handler asked",
				row.PolicyID, fromEvaluator != nil, fromLoader != nil)
			continue
		}
		if fromEvaluator == nil {
			continue
		}
		if a, b := resolvedValidatorSite(t, fromEvaluator), resolvedValidatorSite(t, fromLoader); a != b {
			t.Errorf("%s: the evaluator resolves %s and the loader resolves %s", row.PolicyID, a, b)
		}
	}
	// Anti-vacuity. Every assertion above is inside the loop.
	if compared < 50 {
		t.Fatalf("compared %d row(s); the census cannot have shrunk this far and every check in this test is inside the loop", compared)
	}
	t.Logf("compared the loader's and the evaluator's resolution over %d census rows", compared)
}

// TestEveryAlgorithmicDetectorIsGatedByItsImplementation is the evidence every
// algorithmic detector record in `platform/decision/registry` names.
//
// It answers, per row and by driving the code rather than by reading it: does
// the shared engine's evaluator consult an implementation for this detector,
// does that implementation refuse a match the pattern accepted, and is the
// implementation the one the census says it is.
func TestEveryAlgorithmicDetectorIsGatedByItsImplementation(t *testing.T) {
	census := loadDetectorCensus(t)

	gated := NewPatternEvaluator(true)
	// THE CONTROL, CONSTRUCTED IN THE SAME TEST AND RUN OVER THE SAME PROBES.
	//
	// "The match disappeared" is only evidence that a validator rejected it if
	// the match was there to begin with. An evaluator with validators disabled
	// runs the identical pattern over the identical probe and must return a
	// match; when it does not, the probe never matched.
	//
	// IT CANNOT FAIL TODAY AND THAT IS SAID RATHER THAN IMPLIED. The pattern is
	// this test's own `.+` and every probe is a non-empty literal, so
	// `FindStringIndex` cannot return nil - the hazard the control defends
	// against was removed two paragraphs earlier by supplying the pattern
	// instead of reading it from the corpus. It is kept because the day
	// somebody makes the pattern per-row - which is the obvious next
	// improvement - it becomes the only thing standing between a probe that
	// does not match and a row reported as gated. A control that cannot fail
	// under today's inputs and can under tomorrow's is worth its four lines;
	// one whose impossibility is undocumented is not.
	bare := NewPatternEvaluator(false)

	var algorithmic, patternRows, notADetector int
	var noSeparatingProbe []string

	for _, row := range census {
		cp := &CompiledPolicy{
			PolicyID:   row.PolicyID,
			Name:       row.Name,
			Category:   PolicyCategory(row.Category),
			PatternStr: derivationPattern,
			Pattern:    regexp.MustCompile(derivationPattern),
			Enabled:    true,
		}

		separated := ""
		for _, probe := range derivationProbes {
			if bare.Evaluate(probe, cp) == nil {
				t.Fatalf("%s: the control evaluator returned no match for probe %q against pattern %q; "+
					"the probe never matched, so nothing below could have been evidence",
					row.PolicyID, probe, derivationPattern)
			}
			if gated.Evaluate(probe, cp) == nil {
				separated = probe
				break
			}
		}

		switch row.Class {
		case classAlgorithmic:
			algorithmic++
			if separated == "" {
				noSeparatingProbe = append(noSeparatingProbe, row.PolicyID)
				continue
			}
			site := resolvedValidatorSite(t, gated.getValidator(cp))
			if site != row.ImplSite {
				t.Errorf("%s: the evaluator resolves %s and the census records impl_site %s",
					row.PolicyID, site, row.ImplSite)
			}
		case classPattern:
			patternRows++
			// THE DIRECT PROPERTY, NOT ONLY THE ABSENCE OF A REJECTION.
			//
			// Gating is observable through rejection alone, so a validator
			// that ACCEPTS every probe reads as class (a). R3 planted exactly
			// that - a real gate resolved for a pattern row, returning true
			// for all four probes - and this arm passed while claiming to have
			// re-derived 81 pattern rows. What "pattern" MEANS is that the
			// evaluator resolves no implementation for the row, so that is
			// what is asserted; the probe check stays beside it because the
			// two fail differently.
			if v := gated.getValidator(cp); v != nil {
				t.Errorf("%s: the census classes this row as a pattern detector and the running evaluator resolves %s for "+
					"it. A pattern row that is silently implementation-gated matches less than the census says it does, and "+
					"a probe-only check cannot see it when the implementation accepts every probe",
					row.PolicyID, resolvedValidatorSite(t, v))
			}
			if separated != "" {
				t.Errorf("%s: the census classes this row as a pattern detector, and the running evaluator "+
					"rejected probe %q for it - so an implementation gates it and the class is wrong",
					row.PolicyID, separated)
			}
		case classNotADetector:
			// A third class the census's own vocabulary declares
			// (`detector_census_test.go`), with zero rows today. It inspects
			// no content, so neither the probe nor the resolution question
			// applies - and reporting it as "unexpected", which an earlier
			// version did, would misattribute the first one that appears.
			notADetector++
		default:
			t.Errorf("%s: class %q is outside the census vocabulary (%s, %s, %s)",
				row.PolicyID, row.Class, classPattern, classAlgorithmic, classNotADetector)
		}
	}

	if len(noSeparatingProbe) > 0 {
		sort.Strings(noSeparatingProbe)
		t.Errorf("%d row(s) the census classes as algorithmic could not be separated by any probe: %v\n"+
			"Either their implementation accepts every probe in derivationProbes - in which case this "+
			"instrument cannot see the gate and needs a probe that it rejects - or the row is not gated "+
			"at all and the census is wrong. Both are findings; neither is a reason to widen the class.",
			len(noSeparatingProbe), noSeparatingProbe)
	}

	// Anti-vacuity in both directions. A census with no algorithmic rows would
	// pass every assertion above having derived nothing, and one with no
	// pattern rows would mean the negative half was never exercised.
	if algorithmic == 0 || patternRows == 0 {
		t.Fatalf("derived %d algorithmic and %d pattern row(s); a corpus missing either class exercises only half of this test",
			algorithmic, patternRows)
	}
	if t.Failed() {
		// A LOG LINE ASSERTING THE PROPERTY THE TEST JUST REFUTED IS WORSE
		// THAN NO LOG LINE. The unconditional version printed "every
		// algorithmic row was separated" in the same output as the failures
		// saying they were not.
		return
	}
	t.Logf("re-derived %d algorithmic, %d pattern and %d not-a-detector row(s) against the running binary; every algorithmic "+
		"row was separated by a probe and its implementation site matched the census, and no pattern row resolves an "+
		"implementation at all", algorithmic, patternRows, notADetector)
}
