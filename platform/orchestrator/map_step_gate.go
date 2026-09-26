// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
)

// THE MULTI-AGENT PLANE DECIDES EVERY STEP ON EVERY DEPLOYMENT (#4382).
//
// mapStepGate is the one per-step decision of the multi-agent plane: the
// checker decides the step before it runs, and the decision is recorded as a
// step_gate row. One executor calls it: the declarative WorkflowEngine, which
// runs every multi-agent execution the routes start (POST /api/v1/workflows/execute,
// and POST /api/v1/plan/execute outside confirm and step mode) in every one of
// its modes.
//
// Before #4382 the routes dispatched to the gated engine only when
// AXONFLOW_HITL_ENABLED was "true", and no shipped deployment sets it. So on a
// customer's stack every step ran with no decision, and a typed block on the
// action the step presents did not stop it.
//
// A CHALLENGE IS WITHHELD, NEVER HELD, on every posture
// (approval_requires_durable_record). The engine keeps no durable record of an
// approval (the in-memory pause that wrote none is retired, #4249 row
// 5774060413). The holds that can be decided and resumed are
// confirm and step mode's, through the workflow control plane, and the reason
// names them.

// mapApprovalRequiresDurableRecord is the code and reason of a challenge
// withheld because the executor keeps no durable approval record.
const mapApprovalRequiresDurableRecord = "approval_requires_durable_record"

// mapStepExecutionBlocked is the code of a step a policy blocked.
const mapStepExecutionBlocked = "execution_blocked"

// mapStepRouteRefused is the code of a step whose LLM call the organization's
// route rows refused, or whose route could not be established (#4249 row
// 5701303521, llm_call_route_effects.go). Its policy is the route's reason
// (no_compliant_provider, segment_not_established, segment_resolution_failed,
// decision_enforcement_unavailable).
const mapStepRouteRefused = "route_refused"

// mapStepRefusal is a step the gate refused before it ran. The execute
// handlers answer it as a governance refusal (403 with its code), never as a
// server error.
type mapStepRefusal struct {
	code   string // mapStepExecutionBlocked, mapApprovalRequiresDurableRecord or mapStepRouteRefused
	policy string // the policy, or the cause, that refused the step
	reason string
	// message, when set, is the error text: a conditional's branch step names
	// itself and its position (map_conditional_gate.go).
	message string
	// cause is the refusal this one carries, when another layer made it (a
	// route refusal's llmCallRouteRefusal), so errors.As still finds it.
	cause error
}

// Unwrap is the refusal this one carries, or nil.
func (r *mapStepRefusal) Unwrap() error { return r.cause }

func (r *mapStepRefusal) Error() string {
	if r.message != "" {
		return r.message
	}
	if r.code == mapApprovalRequiresDurableRecord {
		return "execution blocked: " + mapApprovalRequiresDurableRecord
	}
	return "execution blocked by policy: " + r.policy
}

// detail is the refusal as the execution's Error and the 403 body carry it.
func (r *mapStepRefusal) detail() string {
	return fmt.Sprintf("Blocked by policy %s: %s", r.policy, r.reason)
}

// mapStepGate decides a multi-agent step. A nil checker decides nothing; the
// execute handlers refuse to run on an engine whose gate has none
// (WorkflowEngine.PresentsSteps).
type mapStepGate struct {
	checker HITLPolicyChecker
	audit   hitlAuditLogger
}

func (g *mapStepGate) presentsSteps() bool {
	return g != nil && g.checker != nil
}

// decide decides step before it runs. It answers nil when the step runs, and
// a *mapStepRefusal when it must not. The engine cannot pause, so every
// challenge is withheld (#4382); the in-memory pause that could hold an untyped
// one is retired (#4249 row 5774060413).
//
// A conditional is never presented here: its branch steps are, inside its
// processor, through the gate conditionalGate installs on the context.
func (g *mapStepGate) decide(ctx context.Context, execution *WorkflowExecution, workflowName string, step WorkflowStep, content StepContent, user UserContext) error {
	if !g.presentsSteps() || step.Type == mapStepTypeConditional {
		return nil
	}
	policyResult, err := g.checker.CheckPolicy(ctx, step, content, execution)
	if err != nil {
		// DESIGN DECISION (#2698), unchanged: a checker error proceeds, and the
		// errored verdict is recorded. The plane's own checker never returns an
		// error (MAPHITLPolicyChecker.CheckPolicy), so no production step reaches
		// this arm.
		log.Printf("[HITL] WARNING: Policy check error for step %s: %v - proceeding with execution (fail-open)", step.Name, err)
		g.auditStepGateError(ctx, execution, workflowName, step, err, user)
		return nil
	}
	if policyResult == nil {
		return nil
	}
	switch policyResult.Action {
	case "block":
		// Audit the terminal block BEFORE refusing: this verdict withholds the
		// step and must leave a trail (#2693).
		g.auditStepGate(ctx, execution, workflowName, step, policyResult, user)
		return &mapStepRefusal{code: mapStepExecutionBlocked, policy: policyResult.PolicyName, reason: policyResult.Reason}

	case "require_approval":
		withheld := *policyResult
		withheld.Action = "block"
		withheld.Reason = withheldApprovalReason(policyResult.hold)
		g.auditStepGate(ctx, execution, workflowName, step, &withheld, user)
		return &mapStepRefusal{code: mapApprovalRequiresDurableRecord, policy: withheld.PolicyName, reason: withheld.Reason}

	case "allow":
		// One row per decision, an allow included (PRD v11 §5.7): the step runs
		// once its decision is recorded.
		g.auditStepGate(ctx, execution, workflowName, step, policyResult, user)

	// warn and log run the step with no step_gate row. MAPHITLPolicyChecker,
	// the plane's only production checker, never answers either
	// (mapStepFromDecision answers allow, require_approval or block), so no
	// production step reaches these arms; they serve other checkers.
	case "warn":
		log.Printf("[HITL] Warning for step %s: Policy %s triggered - %s",
			step.Name, policyResult.PolicyName, policyResult.Reason)

	case "log":
		log.Printf("[HITL] Audit: Step %s triggered policy %s",
			step.Name, policyResult.PolicyName)
	}
	return nil
}

// withheldApprovalReason is the reason a challenge is withheld with.
func withheldApprovalReason(hold *stepGateHold) string {
	decision := "a policy"
	if hold != nil && hold.decisionID != "" {
		decision = "decision " + hold.decisionID
	}
	return mapApprovalRequiresDurableRecord + ": " + decision +
		" requires an approval, and this execution path keeps no durable approval record to decide it from;" +
		" run the plan in confirm or step mode, whose holds are durable"
}

// auditStepGate records a step's gate decision to the canonical audit_logs
// feed (#2693). A nil logger is a no-op.
func (g *mapStepGate) auditStepGate(ctx context.Context, execution *WorkflowExecution, workflowName string, step WorkflowStep, pr *PolicyCheckResult, user UserContext) {
	if g.audit == nil || pr == nil {
		return
	}
	g.audit.LogWorkflowOperation(ctx, stepGateEntry(executionIDOf(execution), workflowName, step, pr, user, ""))
}

// auditStepGateError records the fail-open-on-error verdict (#2698). A nil
// logger is a no-op.
func (g *mapStepGate) auditStepGateError(ctx context.Context, execution *WorkflowExecution, workflowName string, step WorkflowStep, checkErr error, user UserContext) {
	if g.audit == nil || checkErr == nil {
		return
	}
	g.audit.LogWorkflowOperation(ctx, stepGateErrorEntry(executionIDOf(execution), workflowName, step, checkErr, user))
}

// conditionalGate is the gate the branch steps of this execution's
// conditionals are decided through (#4249 row 5665091860). The check never
// fails open: a check error, or no result, is a block whose reason carries the
// error.
func (g *mapStepGate) conditionalGate(engine *WorkflowEngine, execution *WorkflowExecution, workflowName string, user UserContext) *conditionalGate {
	return &conditionalGate{
		check: func(ctx context.Context, step WorkflowStep, input map[string]interface{}, exec *WorkflowExecution) *PolicyCheckResult {
			// The branch step presents its content as a top-level step does:
			// the input it will run with and the processor that runs it.
			pr, err := g.checker.CheckPolicy(ctx, step, stepContentFor(engine, step, input), exec)
			if err != nil {
				return &PolicyCheckResult{Action: "block", Reason: fmt.Sprintf("policy check error, so the branch step is refused: %v", err)}
			}
			return pr
		},
		audit: func(ctx context.Context, step WorkflowStep, pr *PolicyCheckResult, branchPath string) {
			if g.audit == nil || pr == nil {
				return
			}
			g.audit.LogWorkflowOperation(ctx, stepGateEntry(executionIDOf(execution), workflowName, step, pr, user, branchPath))
		},
	}
}

// stepContentFor is what step presents to the policy checker (#4249, #4360):
// the input the executor passes it, and the processor that will run it. It is
// the one builder the engine's step gate and its conditional gate call, so a
// branch step presents what a top-level step does.
func stepContentFor(engine *WorkflowEngine, step WorkflowStep, input map[string]interface{}) StepContent {
	content := StepContent{Input: input}
	if engine != nil {
		content.Processor = engine.stepProcessors[step.Type]
	}
	return content
}

func executionIDOf(execution *WorkflowExecution) string {
	if execution == nil {
		return ""
	}
	return execution.ID
}

// multiAgentStepRefusalBody is the 403 a refused step is answered with: the
// flat error envelope with the refusal's code and policy (the spec's
// MultiAgentStepRefusal).
type multiAgentStepRefusalBody struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
	Code    string `json:"code"`
	Policy  string `json:"policy"`
	Reason  string `json:"reason"`
}

// sendStepRefusal answers an execution whose step the multi-agent plane
// refused before it ran (#4382): a governance refusal, 403 with its code
// (execution_blocked, or approval_requires_durable_record), never a server
// error.
func sendStepRefusal(w http.ResponseWriter, refusal *mapStepRefusal) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	if err := json.NewEncoder(w).Encode(multiAgentStepRefusalBody{
		Success: false,
		Error:   refusal.Error(),
		Code:    refusal.code,
		Policy:  refusal.policy,
		Reason:  refusal.reason,
	}); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

// wireMultiAgentEngines wires the multi-agent plane's executors at boot, on
// every deployment and every posture (#4382).
//
// The declarative engine runs every multi-agent execution the routes start, so
// the plane's checker is wired onto it unconditionally: the anchored enforcer
// it decides through is wired on every posture (wireOrchestratorEnforcer).
// Before v11.1.0 the routes dispatched to a decided engine only under
// AXONFLOW_HITL_ENABLED=true, which no shipped deployment sets; the variable is
// still read, and ignored, for one release.
//
// The in-memory HITL engine (#1082) that ran no route's execution since #4382
// is retired (#4249 row 5774060413): only the step gate is wired.
func wireMultiAgentEngines(engine *WorkflowEngine, audit *AuditLogger) {
	// A nil *AuditLogger must never become a non-nil interface.
	var stepAudit hitlAuditLogger
	if audit != nil {
		stepAudit = audit
	}
	engine.SetStepGate(&MAPHITLPolicyChecker{}, stepAudit)
	log.Println("Multi-agent step gate wired: every workflow and plan step is decided before it runs")

	hitlEnabled = os.Getenv("AXONFLOW_HITL_ENABLED") == "true"
	if hitlEnabled {
		log.Println("AXONFLOW_HITL_ENABLED is ignored since v11.1.0: every multi-agent execution is decided")
	}
}
