// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policy

import (
	"regexp"
	"strings"
	"testing"
)

// The request path is latency-sensitive in a way the response path is not, and
// #3968 asked for the cost of scanning every occurrence there to be MEASURED
// rather than argued. These benchmarks drive Evaluate on the shapes that
// decide the answer:
//
//	no occurrence      the common request; both scans read the whole input
//	one valid, early   the shape where stopping at the first hit was cheapest
//	refused then valid the #3968 input; the old scan returned early and WRONG
//
// The input is padded to a realistic prompt length so the "reads past the
// first hit" cost is visible if it exists.

func benchCardPolicy() *CompiledPolicy {
	const pat = `\b\d{16}\b`
	return &CompiledPolicy{
		PolicyID: "sys_pii_credit_card", Name: "Credit Card Detection",
		Category: CategoryPIIGlobal, Pattern: regexp.MustCompile(pat), PatternStr: pat,
		Severity: SeverityCritical, Phase: PhaseBoth, Enabled: true,
	}
}

func benchPad() string { return strings.Repeat("the customer asked about their order status ", 40) }

func BenchmarkEvaluate_NoOccurrence(b *testing.B) {
	e, p, in := NewPatternEvaluator(true), benchCardPolicy(), benchPad()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = e.Evaluate(in, p)
	}
}

func BenchmarkEvaluate_OneValidEarly(b *testing.B) {
	e, p, in := NewPatternEvaluator(true), benchCardPolicy(), "charge 4111111111111111 "+benchPad()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = e.Evaluate(in, p)
	}
}

func BenchmarkEvaluate_RefusedThenValid(b *testing.B) {
	e, p := NewPatternEvaluator(true), benchCardPolicy()
	in := "charge 4111111111111112 " + benchPad() + " then charge 4111111111111111 please"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = e.Evaluate(in, p)
	}
}
