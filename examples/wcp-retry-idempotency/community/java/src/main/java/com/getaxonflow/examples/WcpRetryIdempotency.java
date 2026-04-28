// Copyright 2026 AxonFlow
// SPDX-License-Identifier: Apache-2.0
//
// WCP retry_context + idempotency_key E2E example (Issue #1673 Phase 1 + 2).
//
// Exercises the new Java SDK surface end-to-end against a running v7.3.0
// enterprise stack. Every assertion fails the process with System.exit(1).
//
// Run from this directory:
//   mvn install -DskipTests=true       # from the SDK root, first time only
//   source /tmp/axonflow-e2e-env.sh
//   export AXONFLOW_BASE_URL=http://localhost:8080
//   mvn -q compile exec:java
package com.getaxonflow.examples;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.exceptions.IdempotencyKeyMismatchException;
import com.getaxonflow.sdk.types.workflow.WorkflowTypes;

import java.util.HashMap;
import java.util.Map;

public class WcpRetryIdempotency {

    public static void main(String[] args) {
        String endpoint = envOrDefault("AXONFLOW_BASE_URL", "http://localhost:8080");
        String clientId = envOrDefault("AXONFLOW_CLIENT_ID", "demo");
        String clientSecret = envOrDefault("AXONFLOW_CLIENT_SECRET", "demo-secret");

        AxonFlow client = AxonFlow.create(
                AxonFlowConfig.builder()
                        .endpoint(endpoint)
                        .clientId(clientId)
                        .clientSecret(clientSecret)
                        .build());

        banner("Act 1 — retry_context (Java SDK)");
        act1(client);

        banner("Act 2 — idempotency_key (Java SDK)");
        act2(client);

        banner("All assertions passed ✔");
    }

    private static void act1(AxonFlow client) {
        WorkflowTypes.CreateWorkflowResponse wf = client.createWorkflow(
                WorkflowTypes.CreateWorkflowRequest.builder()
                        .workflowName("java-sdk-retry-context")
                        .build());
        System.out.println("workflow: " + wf.getWorkflowId());

        // 1) First gate — first-call invariants
        WorkflowTypes.StepGateResponse first = client.stepGate(
                wf.getWorkflowId(),
                "step-1",
                WorkflowTypes.StepGateRequest.builder()
                        .stepName("first-step")
                        .stepType(WorkflowTypes.StepType.TOOL_CALL)
                        .build());
        WorkflowTypes.RetryContext rc = first.getRetryContext();
        assertTrue("retry_context not null", rc != null);
        assertEqInt("first gate_count", 1, rc.getGateCount());
        assertEqInt("first completion_count", 0, rc.getCompletionCount());
        assertEqStr("first prior_completion_status",
                WorkflowTypes.PriorCompletionStatus.NONE.name(),
                rc.getPriorCompletionStatus().name());
        assertTrue("first !prior_output_available", !rc.isPriorOutputAvailable());
        assertEqStr("first last_decision (first-call invariant)",
                first.getDecision().name(), rc.getLastDecision().name());
        assertTrue("first FirstAttemptAt == LastAttemptAt",
                rc.getFirstAttemptAt().equals(rc.getLastAttemptAt()));
        System.out.println("  first gate invariants ✔");

        // 2) Complete, then re-gate
        Map<String, Object> output = new HashMap<>();
        output.put("transfer_id", "TXN-java-1");
        output.put("amount", 500);
        client.markStepCompleted(
                wf.getWorkflowId(),
                "step-1",
                WorkflowTypes.MarkStepCompletedRequest.builder().output(output).build());
        WorkflowTypes.StepGateResponse reGate = client.stepGate(
                wf.getWorkflowId(),
                "step-1",
                WorkflowTypes.StepGateRequest.builder()
                        .stepType(WorkflowTypes.StepType.TOOL_CALL)
                        .build());
        assertEqInt("re-gate post-complete gate_count", 2,
                reGate.getRetryContext().getGateCount());
        assertEqInt("re-gate post-complete completion_count", 1,
                reGate.getRetryContext().getCompletionCount());
        assertEqStr("re-gate post-complete prior_completion_status",
                WorkflowTypes.PriorCompletionStatus.COMPLETED.name(),
                reGate.getRetryContext().getPriorCompletionStatus().name());
        assertTrue("re-gate post-complete prior_output_available",
                reGate.getRetryContext().isPriorOutputAvailable());
        assertTrue("re-gate post-complete prior_output omitted by default",
                reGate.getRetryContext().getPriorOutput() == null);
        assertTrue("re-gate post-complete cached==true", reGate.isCached());
        System.out.println("  re-gate post-complete ✔");

        // 3) Gate on step-2 without completion (agent-crash simulation)
        client.stepGate(
                wf.getWorkflowId(),
                "step-2",
                WorkflowTypes.StepGateRequest.builder()
                        .stepName("second-step")
                        .stepType(WorkflowTypes.StepType.TOOL_CALL)
                        .build());
        WorkflowTypes.StepGateResponse reGate2 = client.stepGate(
                wf.getWorkflowId(),
                "step-2",
                WorkflowTypes.StepGateRequest.builder()
                        .stepType(WorkflowTypes.StepType.TOOL_CALL)
                        .build());
        assertEqStr("gated_not_completed status",
                WorkflowTypes.PriorCompletionStatus.GATED_NOT_COMPLETED.name(),
                reGate2.getRetryContext().getPriorCompletionStatus().name());
        assertEqInt("gated_not_completed completion_count", 0,
                reGate2.getRetryContext().getCompletionCount());
        System.out.println("  gated_not_completed ✔");

        // 4) include_prior_output=true recovers the payload
        WorkflowTypes.StepGateResponse withPrior = client.stepGate(
                wf.getWorkflowId(),
                "step-1",
                WorkflowTypes.StepGateRequest.builder()
                        .stepType(WorkflowTypes.StepType.TOOL_CALL)
                        .build(),
                WorkflowTypes.StepGateOptions.includePriorOutput());
        assertTrue("prior_output populated",
                withPrior.getRetryContext().getPriorOutput() != null);
        assertEqStr("prior_output[transfer_id]", "TXN-java-1",
                String.valueOf(withPrior.getRetryContext().getPriorOutput().get("transfer_id")));
        System.out.println("  prior_output recovery ✔");
    }

    private static void act2(AxonFlow client) {
        WorkflowTypes.CreateWorkflowResponse wf = client.createWorkflow(
                WorkflowTypes.CreateWorkflowRequest.builder()
                        .workflowName("java-sdk-idempotency-key")
                        .build());
        System.out.println("workflow: " + wf.getWorkflowId());

        String originalKey = "payment:wire:java-sdk-invoice-1";

        // 5) Gate with key — retry_context.idempotency_key echoes
        WorkflowTypes.StepGateResponse first = client.stepGate(
                wf.getWorkflowId(),
                "step-1",
                WorkflowTypes.StepGateRequest.builder()
                        .stepName("wire")
                        .stepType(WorkflowTypes.StepType.TOOL_CALL)
                        .idempotencyKey(originalKey)
                        .build());
        assertEqStr("retry_context.idempotency_key echo",
                originalKey, first.getRetryContext().getIdempotencyKey());
        System.out.println("  key round-trip ✔");

        // 6) Re-gate with different key → IdempotencyKeyMismatchException
        try {
            client.stepGate(
                    wf.getWorkflowId(),
                    "step-1",
                    WorkflowTypes.StepGateRequest.builder()
                            .stepType(WorkflowTypes.StepType.TOOL_CALL)
                            .idempotencyKey("payment:wire:different-2")
                            .build());
            fail("expected IdempotencyKeyMismatchException on gate with different key");
        } catch (IdempotencyKeyMismatchException e) {
            assertEqStr("mismatch expected_key", originalKey, e.getExpectedIdempotencyKey());
            assertEqStr("mismatch received_key", "payment:wire:different-2",
                    e.getReceivedIdempotencyKey());
            assertTrue("mismatch workflow_id populated",
                    e.getWorkflowId() != null && e.getWorkflowId().startsWith("wf_"));
            assertEqStr("mismatch step_id", "step-1", e.getStepId());
        }
        System.out.println("  typed 409 error ✔");

        // 7) Complete with matching key
        Map<String, Object> output = new HashMap<>();
        output.put("transfer_id", "TXN-K1");
        client.markStepCompleted(
                wf.getWorkflowId(),
                "step-1",
                WorkflowTypes.MarkStepCompletedRequest.builder()
                        .output(output)
                        .idempotencyKey(originalKey)
                        .build());
        System.out.println("  complete with matching key ✔");
    }

    // --- helpers ---

    private static String envOrDefault(String name, String fallback) {
        String v = System.getenv(name);
        return v == null || v.isEmpty() ? fallback : v;
    }

    private static String mustEnv(String name) {
        String v = System.getenv(name);
        if (v == null || v.isEmpty()) {
            fail("missing env: " + name);
        }
        return v;
    }

    private static void assertTrue(String label, boolean cond) {
        if (!cond) fail("assertion failed: " + label);
    }

    private static void assertEqStr(String label, String want, String got) {
        if (want == null ? got != null : !want.equals(got)) {
            fail(label + ": want \"" + want + "\", got \"" + got + "\"");
        }
    }

    private static void assertEqInt(String label, int want, int got) {
        if (want != got) fail(label + ": want " + want + ", got " + got);
    }

    private static void fail(String msg) {
        System.err.println("FAIL: " + msg);
        System.exit(1);
    }

    private static void banner(String s) {
        System.out.println();
        System.out.println("━━━ " + s + " ━━━");
    }
}
