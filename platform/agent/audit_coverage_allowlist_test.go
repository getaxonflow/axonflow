// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// auditCoverageAllowlist is the checked-in, reviewable registry of Policy
// Enforcement Points that legitimately do NOT write a canonical audit row in
// their own body. The audit-coverage gate (TestEveryPolicyEnforcementPointAudits,
// #2687) passes only when every PEP is either covered or listed here.
//
// Keys are "<repo-relative-path>::<funcKey>" where funcKey is "Recv.Name" for
// methods and "Name" for free functions, so an entry can disambiguate
// same-named methods on different receivers. Each value MUST be a one-line
// reason in one of exactly two classes:
//
//   - BY-DESIGN: the function is a pure engine internal / adapter / detector /
//     dry-run simulation whose verdict is audited by its CALLER (state which
//     caller + writer) or whose execution writes no decision at all (a policy
//     *simulation*). These are correct and permanent.
//
//   - DEFERRED(#NNNN): a real coverage gap consciously parked to a follow-up,
//     citing the tracking issue (the 9.1.0 catch-all is #2684). "Pre-existing"
//     is not a reason on its own — the entry must say what the gap is and why
//     it is safe to defer.
//
// The reason string is printed in the test log for every allowlisted PEP, so
// this map doubles as the living audit-coverage ledger. Removing a fix and
// thereby re-opening a hole that is NOT listed here fails the gate.
//
// Triage evidence for every entry below was captured on #2687 (2026-06-12).
func auditCoverageAllowlist() map[string]string {
	return map[string]string{
		// ---- BY-DESIGN: MCP plane helpers (caller writes the canonical row) ----
		// evaluateInputPolicies is the request-phase DETECTOR pass: it returns the
		// shared engine's evaluation, whose detector facts the anchored engine
		// decides from, and decides nothing itself. Its callers (the MCP request
		// pass's entry points and handleDecide) audit the anchored verdict.
		"platform/agent/mcp_handler.go::evaluateInputPolicies": "by-design: detector pass only, no verdict; the MCP request pass's entry points and handleDecide audit the anchored verdict (#2641/#2679, #3564).",
		// proxyDetectorPass is /api/request's DETECTOR pass (#4253): it returns the
		// shared engine's evaluation, whose detector facts the anchored engine
		// decides from, and decides nothing itself. clientRequestHandler audits the
		// anchored verdict; the policy-test preview is a dry run and records nothing.
		"platform/agent/run.go::proxyDetectorPass": "by-design: detector pass only, no verdict; clientRequestHandler audits the anchored verdict and the policy-test preview records nothing (#4253).",
		// evaluateOutputPolicies returns an output outcome; callers run
		// mcpOutputDecisionVerdict → writeMCPDecisionAudit / recordDecideDecision
		// (mcp_handler.go ~1589, ~1956, ~2808). Closed by #2641.
		"platform/agent/mcp_handler.go::evaluateOutputPolicies": "by-design: returns output outcome; caller handlers audit via mcpOutputDecisionVerdict→writeMCPDecisionAudit/recordDecideDecision (#2641).",

		// ---- BY-DESIGN: Cowork / Claude Code OTEL ingest plane (caller audits) ----
		// coworkRedactDefault is the redact-at-collector helper: it wraps the SAME
		// engine response-plane redactor (evaluateOutputPolicies) and returns a
		// coworkRedactResult (masked/withheld/allowed + verdict). It writes no row
		// itself; its only caller, processCoworkRecord, records the canonical
		// audit_logs row via writeCoworkAuditLog AND signs it via recordSignedDecision
		// on every terminal verdict (allowed/redacted/blocked/error) — the same
		// split as the MCP evaluateOutputPolicies helper above. (#2760 / WS-6.)
		"platform/agent/cowork_otel_ingest.go::coworkRedactDefault": "by-design: redact-at-collector helper wrapping evaluateOutputPolicies; caller processCoworkRecord audits via writeCoworkAuditLog + recordSignedDecision on every verdict (#2760).",

		// ---- BY-DESIGN: orchestrator response plane (handler audits) ----
		// responseDetectorPass runs the response-phase evaluation for its detector
		// facts only and returns them; decideResponse, which calls it, returns the
		// anchored decision up, and run.go's llmProxyHandler audits the response
		// verdict via LogBlockedResponse / LogSuccessfulRequest (#2626). No verdict
		// is terminal inside either helper.
		"platform/orchestrator/response_enforcing_seam.go::responseDetectorPass": "by-design: detector pass returning facts to decideResponse; llmProxyHandler audits the response verdict via LogBlockedResponse/LogSuccessfulRequest (#2626).",
		"platform/orchestrator/response_enforcing_seam.go::decideResponse":       "by-design: returns the anchored response decision to ProcessResponse; llmProxyHandler audits via LogBlockedResponse/LogSuccessfulRequest (#2626).",
		// ProcessResponse is the public entrypoint that calls decideResponse (one
		// hop); same response plane, same llmProxyHandler audit (#2626).
		"platform/orchestrator/response_processor.go::ResponseProcessor.ProcessResponse": "by-design: response-plane entrypoint delegating to decideResponse; llmProxyHandler audits via LogBlockedResponse/LogSuccessfulRequest (#2626).",

		// ---- BY-DESIGN: WCP step-gate (adapter returns up; Service audits) ----
		// The adapter evaluates and returns a StepGateEvaluation; Service.StepGate
		// records the gate decision. (Service.StepGate itself is NOT allowlisted —
		// the gate now SEES its audit via the writer-side one-hop:
		// s.logAudit→LogWorkflowOperation, scoped to the workflow_control package.)
		"platform/orchestrator/wcp_policy_adapter.go::WCPPolicyAdapter.EvaluateStepGate": "by-design: adapter returns StepGateEvaluation; Service.StepGate records the gate decision via logAudit→LogWorkflowOperation.",

		// ---- BY-DESIGN: dry-run / simulation endpoints (no enforcement) ----
		"platform/orchestrator/policy_simulation_handler.go::PolicySimulationHandler.SimulatePolicies": "by-design: dry-run policy simulation (DryRun:true, test-* request id); evaluates with no enforcement and owes no audit row.",
		"platform/orchestrator/run.go::testPolicyHandler":                                              "by-design: policy test/introspection endpoint (test-* request id); returns raw evaluation, no enforcement, no audit owed.",
		"platform/agent/run.go::policyTestHandler":                                                     "by-design: admin policy test/introspection endpoint; returns a StaticPolicyResult, no enforcement, no audit owed.",

		// ---- BY-DESIGN: MAP/HITL adapter (engine records the verdict) ----
		// MAPHITLPolicyChecker.CheckPolicy is the adapter that evaluates the
		// per-step policy and RETURNS its verdict up to HITLWorkflowEngine.
		// ExecuteWithHITL, which records the block / require_approval gate decision
		// via auditStepGate→LogWorkflowOperation (hitl_execution.go, #2693 merged).
		// ExecuteWithHITL is therefore covered (the gate sees it via the writer-side
		// one-hop) and is NOT allowlisted; the adapter delegates, so it is.
		"platform/orchestrator/map_hitl_adapter.go::MAPHITLPolicyChecker.CheckPolicy": "by-design: adapter returns its per-step verdict to HITLWorkflowEngine.ExecuteWithHITL, which records it via auditStepGate→LogWorkflowOperation (#2693 merged).",
	}
}
