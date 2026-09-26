// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"fmt"

	"axonflow/platform/shared/anchoredenforcer"
)

// #4249 row 5665091860: a multi-agent conditional step's branch steps are
// presented to the anchored engine by their own type, before each runs, on
// every path that presents steps: the executors whose step gate has a checker
// (mapStepGate.conditionalGate, installed by the declarative engine on every
// route since #4382). Everywhere else a conditional
// carrying branch steps is refused, as in v11.0.0.
//
// The gate rides on the CONTEXT of one execution. One WorkflowEngine and one
// ConditionalProcessor are shared by every concurrent execution and by the
// paths that present no step, so nothing is installed on the processor; and the
// execution record is marshalled, so it carries nothing either. A processor
// reached with no gate on its context refuses a conditional with branch steps.

// conditionalGate is what an executor that presents steps carries on the
// context for the branch steps of the conditionals it runs
// (mapStepGate.conditionalGate).
type conditionalGate struct {
	// check decides one branch step over the input it will run with. It never
	// errs: a failed check is a block.
	check func(ctx context.Context, step WorkflowStep, input map[string]interface{}, execution *WorkflowExecution) *PolicyCheckResult
	// audit writes the branch step's step_gate row, stepGateEntry's entry with
	// the branch path as its StepID and Metadata["branch_path"].
	audit func(ctx context.Context, step WorkflowStep, pr *PolicyCheckResult, branchPath string)
}

type conditionalGateKey struct{}

type conditionalPathKey struct{}

type branchPositionKey struct{}

// withBranchPosition marks the context of a branch step's check. The MAP seam
// reads it to withhold a challenge rather than answer it as a hold; it never
// changes what the engine is asked or what it decides.
func withBranchPosition(ctx context.Context) context.Context {
	return context.WithValue(ctx, branchPositionKey{}, true)
}

func atBranchPosition(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	at, _ := ctx.Value(branchPositionKey{}).(bool)
	return at
}

// branchApprovalRequiredReason is the approval_required sentence for the one
// position on the map plane that cannot hold; the sentence is owned by
// anchoredenforcer.
func branchApprovalRequiredReason() string {
	return anchoredenforcer.ApprovalRequiredAtPositionReason(mapSeamScope, "a branch step of a conditional")
}

func withConditionalGate(ctx context.Context, gate *conditionalGate) context.Context {
	return context.WithValue(ctx, conditionalGateKey{}, gate)
}

func conditionalGateFrom(ctx context.Context) *conditionalGate {
	if ctx == nil {
		return nil
	}
	gate, _ := ctx.Value(conditionalGateKey{}).(*conditionalGate)
	return gate
}

// withConditionalPath sets the position of the conditional about to run: its
// top-level index, then ".<if_true|if_false>.<branch index>" per level. The path
// is read only for the audit row of a branch decision, never for the decision.
func withConditionalPath(ctx context.Context, path string) context.Context {
	return context.WithValue(ctx, conditionalPathKey{}, path)
}

func conditionalPathFrom(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	path, _ := ctx.Value(conditionalPathKey{}).(string)
	return path
}

// errConditionalPathMissing refuses a gated conditional reached with no path:
// its branch decisions could not be told apart in the audit trail.
var errConditionalPathMissing = fmt.Errorf("a conditional step was reached with a policy gate but no position, so its branch decisions could not be recorded apart; refusing its branch steps rather than executing them")

// gateBranchStep presents one branch step through the context's gate and
// records the decision. It returns nil only when the step may run.
//
//   - a nil result is a block;
//   - "block" is a block;
//   - "require_approval" is refused as approval_required: an in-memory MAP
//     execution has no hold a branch step could wait in. The MAP seam already
//     withholds a challenge at a branch position; this arm is the defence for a
//     checker that does not;
//   - "allow", "warn" and "log" let the step run, as they do at top level;
//   - any other action is a block.
func gateBranchStep(ctx context.Context, gate *conditionalGate, step WorkflowStep, input map[string]interface{}, execution *WorkflowExecution, branchPath string) error {
	pr := gate.check(withBranchPosition(ctx), step, input, execution)
	if pr == nil {
		pr = &PolicyCheckResult{Action: "block", Reason: "the policy check returned no decision for the branch step, so it is refused"}
	}
	switch pr.Action {
	case "allow":
		gate.audit(ctx, step, pr, branchPath)
		return nil
	case "warn", "log":
		return nil
	case "require_approval":
		withheld := *pr
		withheld.Action = "block"
		withheld.Allowed = false
		withheld.hold = nil
		withheld.Reason = branchApprovalRequiredReason()
		gate.audit(ctx, step, &withheld, branchPath)
		// #4382: a refusal the execute routes answer as 403, never 500.
		return &mapStepRefusal{code: mapApprovalRequiresDurableRecord, policy: withheld.PolicyName, reason: withheld.Reason,
			message: fmt.Sprintf("branch step %s (%s) refused: %s", step.Name, branchPath, withheld.Reason)}
	case "block":
		gate.audit(ctx, step, pr, branchPath)
		return &mapStepRefusal{code: mapStepExecutionBlocked, policy: pr.PolicyName, reason: pr.Reason,
			message: fmt.Sprintf("branch step %s (%s) blocked by policy %s: %s", step.Name, branchPath, pr.PolicyName, pr.Reason)}
	default:
		blocked := *pr
		blocked.Action = "block"
		blocked.Allowed = false
		blocked.hold = nil
		blocked.Reason = fmt.Sprintf("the policy check answered %q for the branch step, which is not a decision this plane runs a step on", pr.Action)
		gate.audit(ctx, step, &blocked, branchPath)
		return &mapStepRefusal{code: mapStepExecutionBlocked, policy: blocked.PolicyName, reason: blocked.Reason,
			message: fmt.Sprintf("branch step %s (%s) refused: %s", step.Name, branchPath, blocked.Reason)}
	}
}
