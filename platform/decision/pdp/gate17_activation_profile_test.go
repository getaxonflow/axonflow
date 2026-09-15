// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package pdp

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
)

// WHICH HALF OF ACTIVATION IS SUPERLINEAR (#3693).
//
// Gate 17 measured bundle ACTIVATION - NewRuntime - at 5.3 ms / 238 ms / 12.3 s
// for 10 / 100 / 500 policies: five times the policies for roughly fifty times
// the time. #3693's first acceptance criterion is that the superlinear term is
// NAMED WITH A PROFILE rather than guessed, and NewRuntime does exactly two
// things that could be it: LintBundleModule, then rego.PrepareForEval.
//
// This test measures the two halves SEPARATELY over the same bundles the gate
// 17 harness builds, so the answer is attributable rather than inferred from
// the total. It is a measurement, not a budget: it prints a table and asserts
// only that the instrument reached its subject. The budgets live in
// gate17_budgets_test.go and the shape ratio there already refuses the curve
// getting worse.
//
// SAMPLE COUNTS ARE PINNED, NOT TIME-BUDGETED. One activation at 500 policies
// is over ten seconds, so a time-budgeted loop would take a different number of
// samples on every machine and the figures could not be compared across runs.
// Each cell below is a fixed number of iterations, stated in the output beside
// the machine, because a benchmark figure without its sample count and its
// machine is not a measurement.

// activationProfileIterations is fixed per policy count: enough samples to see
// past scheduler noise at the small sizes, few enough that 500 policies does
// not dominate the suite.
var activationProfileIterations = map[int]int{10: 20, 100: 5, 500: 2}

// profileHalf is one measured half of activation at one policy count.
type profileHalf struct {
	policies int
	lint     time.Duration
	prepare  time.Duration
	samples  int
}

// measureActivationHalves runs LintBundleModule and rego.PrepareForEval
// separately over the same module NewRuntime would compile, with the same
// options NewRuntime passes, so the two figures sum to activation rather than
// describing something adjacent to it.
func measureActivationHalves(t *testing.T, n int) profileHalf {
	t.Helper()
	bundle, err := BuildBundle(benchDocument(n))
	if err != nil {
		t.Fatalf("BuildBundle(%d): %v", n, err)
	}
	iterations := activationProfileIterations[n]
	if iterations <= 0 {
		t.Fatalf("no pinned iteration count for %d policies", n)
	}
	pkg := BundlePackage(bundle.Root)
	ctx := context.Background()

	// Warm once so the first sample is not paying one-time initialisation.
	if err := LintBundleModule(bundle.Module, pkg); err != nil {
		t.Fatalf("lint(%d): %v", n, err)
	}

	var lintTotal time.Duration
	for i := 0; i < iterations; i++ {
		start := time.Now()
		if err := LintBundleModule(bundle.Module, pkg); err != nil {
			t.Fatalf("lint(%d): %v", n, err)
		}
		lintTotal += time.Since(start)
	}

	prepare := func() {
		modules := map[string]string{
			"axonflow/decision/tri/tristate.rego": HelperSource,
			"axonflow/decision/bundle.rego":       bundle.Module,
		}
		opts := []func(*rego.Rego){
			rego.Query(fmt.Sprintf("data.%s.result", pkg)),
			rego.Capabilities(RestrictedCapabilities()),
			rego.SetRegoVersion(ast.RegoV1),
			rego.Strict(true),
			rego.StrictBuiltinErrors(true),
		}
		for name, src := range modules {
			opts = append(opts, rego.Module(name, src))
		}
		if _, err := rego.New(opts...).PrepareForEval(ctx); err != nil {
			t.Fatalf("PrepareForEval(%d): %v", n, err)
		}
	}
	prepare()

	var prepareTotal time.Duration
	for i := 0; i < iterations; i++ {
		start := time.Now()
		prepare()
		prepareTotal += time.Since(start)
	}

	return profileHalf{
		policies: n,
		lint:     lintTotal / time.Duration(iterations),
		prepare:  prepareTotal / time.Duration(iterations),
		samples:  iterations,
	}
}

func TestGate17ActivationProfileNamesTheSuperlinearTerm(t *testing.T) {
	if testing.Short() {
		t.Skip("the 500-policy half of this profile takes tens of seconds")
	}
	sizes := []int{10, 100, 500}
	out := make([]profileHalf, 0, len(sizes))
	for _, n := range sizes {
		out = append(out, measureActivationHalves(t, n))
	}

	t.Logf("machine: %s; %s; each cell is the mean of a PINNED iteration count",
		machineDescription(), runtime.Version()+" "+runtime.GOOS+"/"+runtime.GOARCH)
	t.Logf("%-9s | %-10s | %-12s | %-10s | %s", "policies", "lint", "PrepareForEval", "total", "samples")
	for _, h := range out {
		t.Logf("%-9d | %-10s | %-12s | %-10s | %d",
			h.policies, h.lint.Round(time.Microsecond), h.prepare.Round(time.Microsecond),
			(h.lint + h.prepare).Round(time.Microsecond), h.samples)
	}

	// THE INSTRUMENT MUST REACH ITS SUBJECT. A fixture that stopped scaling
	// with n reports a flat line at every size and nothing else in the output
	// says so - the same control gate 17's own benchmarks carry.
	small, large := out[0], out[len(out)-1]
	if large.lint+large.prepare <= small.lint+small.prepare {
		t.Fatalf("activation at %d policies (%s) is not slower than at %d (%s); the fixture has stopped scaling and these figures describe nothing",
			large.policies, large.lint+large.prepare, small.policies, small.lint+small.prepare)
	}

	// THE FINDING, stated as a ratio so it does not depend on the machine.
	lintRatio := ratio(out[len(out)-1].lint, out[0].lint)
	prepareRatio := ratio(out[len(out)-1].prepare, out[0].prepare)
	t.Logf("500-vs-10 growth: lint %.1fx, PrepareForEval %.1fx (policy count grew 50x)", lintRatio, prepareRatio)

	// Which half dominates is the question #3693 asks. Report it rather than
	// assert a threshold: a threshold here would be a budget, and the budgets
	// live in gate17_budgets_test.go with their own enforcement homes.
	dominant := "PrepareForEval"
	if large.lint > large.prepare {
		dominant = "lint"
	}
	t.Logf("at %d policies the dominant half is %s (lint %s, PrepareForEval %s)",
		large.policies, dominant, large.lint.Round(time.Millisecond), large.prepare.Round(time.Millisecond))
}

func ratio(a, b time.Duration) float64 {
	if b <= 0 {
		return 0
	}
	return float64(a) / float64(b)
}

func machineDescription() string {
	if v := os.Getenv("AXONFLOW_BENCH_MACHINE"); v != "" {
		return v
	}
	return "unnamed (set AXONFLOW_BENCH_MACHINE to record it)"
}
