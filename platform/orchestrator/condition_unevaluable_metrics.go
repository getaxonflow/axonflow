// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	sharedpolicy "axonflow/platform/shared/policy"
)

// planeUnevaluableRecorder adapts promPolicyConditionUnevaluableTotal
// (run.go) to sharedpolicy.UnevaluableRecorder, binding a fixed "plane"
// label per call site. This is the only place platform/shared/policy's
// evaluator touches Prometheus, and it touches it indirectly: the shared
// package only ever sees the UnevaluableRecorder interface, never this type
// or the prometheus import it carries. See condition_evaluator.go's
// "Unevaluable conditions" doc section and unevaluable_recorder.go for why
// that boundary matters (the evaluator is a pure function, deliberately
// dependency-free).
type planeUnevaluableRecorder struct {
	plane string
}

// RecordUnevaluable implements sharedpolicy.UnevaluableRecorder.
func (r planeUnevaluableRecorder) RecordUnevaluable(reason string) {
	promPolicyConditionUnevaluableTotal.WithLabelValues(reason, r.plane).Inc()
}

// One recorder per call site named in condition_evaluator.go's convergence
// record (1a-1e) — the same package-level ConditionEvaluator values
// (dbConditionEvaluator, mcpConditionEvaluator, policyTestEvaluator) this
// file's siblings already declare. Package-level, not per-request, for the
// same reason those evaluators are: no per-call state, constructed once.
//
// #3319: memoryUnevaluableRecorder (plane: "memory") was deleted here — its
// only caller, the retired in-memory DynamicPolicyEngine (dynamic_policy_engine.go),
// no longer exists. There is one engine now ("database").
var (
	dbUnevaluableRecorder         sharedpolicy.UnevaluableRecorder = planeUnevaluableRecorder{plane: "database"}
	mcpUnevaluableRecorder        sharedpolicy.UnevaluableRecorder = planeUnevaluableRecorder{plane: "mcp"}
	policyTestUnevaluableRecorder sharedpolicy.UnevaluableRecorder = planeUnevaluableRecorder{plane: "policy_test"}
)
