// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policy

// UnevaluableRecorder is notified when a policy condition cannot be
// evaluated for a structural reason — an unrecognized operator, an operand
// that doesn't coerce, corrupt stored JSON, or a field the caller could not
// resolve — so that a policy which silently fails to enforce is visible
// rather than indistinguishable from a legitimate no-match (epic #3293).
//
// This package (platform/shared/policy) has zero Prometheus dependencies and
// stays that way: ConditionEvaluator is a pure function. Any real metrics
// sink lives one layer up (the orchestrator, alongside its other Prometheus
// counters) and is injected here only through this interface. A nil
// UnevaluableRecorder is always a safe no-op — every call in this package
// goes through recordUnevaluable, which nil-checks before calling out.
type UnevaluableRecorder interface {
	// RecordUnevaluable is invoked once per unevaluable occurrence with one
	// of the Reason* constants below. reason is always a closed constant —
	// never a policy ID, tenant ID, field name, or operator value — so a
	// Prometheus counter keyed on it stays low-cardinality by construction.
	RecordUnevaluable(reason string)
}

// The closed set of reasons a condition can be unevaluable. These are the
// only values RecordUnevaluable is ever called with from this package -
// callers outside this package (the orchestrator's field-unresolved
// short-circuits) reuse the same constants rather than inventing their own,
// so the label stays a single closed set end to end.
const (
	// ReasonUnknownOperator: cond.Operator is not one of the ten operators
	// Match implements.
	ReasonUnknownOperator = "unknown_operator"
	// ReasonEmptyConditions: a stored policy carried an EXPLICITLY-EMPTY
	// conditions array (`[]`) and was skipped at the cache-conversion layer
	// (cachedPolicyToDynamicPolicy, #3384). This is NOT the vacuous-match
	// shape: JSON `null` / an absent conditions key is the platform-seeded
	// "applies to everything" intent and passes through unrecorded (see
	// condition_evaluator.go's "Withdrawn" section). A stored `[]` can only
	// be residue of the pre-9.19 update-API gap — every released create
	// rejected len==0 conditions — so it is excluded from evaluation
	// entirely rather than allowed to arm as match-everything on the MCP
	// plane the old #3061 guard used to protect.
	ReasonEmptyConditions = "empty_conditions"
	// ReasonNonNumericOperand: greater_than/less_than could not coerce the
	// field value and/or the threshold to a number.
	ReasonNonNumericOperand = "non_numeric_operand"
	// ReasonNonStringPattern: a regex condition's Value was not a Go string,
	// so no compile was even attempted.
	ReasonNonStringPattern = "non_string_pattern"
	// ReasonConditionsUnmarshalFailed: a stored policy's conditions JSON
	// failed to unmarshal. Recorded by the orchestrator at the point it
	// discards that error (cachedPolicyToDynamicPolicy in
	// db_dynamic_policies.go) — this package never sees the raw JSON.
	ReasonConditionsUnmarshalFailed = "conditions_unmarshal_failed"
	// ReasonFieldUnresolved: a caller's own pre-Match short-circuit could not
	// resolve cond.Field to any value at all. Recorded by the caller (the
	// MCP handler and the policy-test evaluator), never by this package —
	// see condition_evaluator.go's "Field resolution is NOT part of this
	// evaluator" doc for why that short-circuit stays outside Match.
	ReasonFieldUnresolved = "field_unresolved"
)

// recordUnevaluable is the nil-safe call-through every emit point in this
// package uses, so Match/MatchAll never need their own nil check.
func recordUnevaluable(r UnevaluableRecorder, reason string) {
	if r == nil {
		return
	}
	r.RecordUnevaluable(reason)
}
