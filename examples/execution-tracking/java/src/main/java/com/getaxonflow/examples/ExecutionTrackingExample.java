/*
 * AxonFlow Unified Execution Tracking Example - Java
 *
 * This example demonstrates unified execution tracking for both MAP plans
 * and WCP workflows using the AxonFlow Java SDK.
 *
 * Issue #1075 - EPIC #1074: Unified Workflow Infrastructure
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 */

package com.getaxonflow.examples;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.execution.ExecutionTypes.*;
import com.getaxonflow.sdk.types.workflow.WorkflowTypes.*;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

public class ExecutionTrackingExample {

    private static final List<String> failures = new ArrayList<>();

    private static void assertCheck(boolean condition, String message) {
        if (condition) {
            System.out.println("   ✓ PASS: " + message);
        } else {
            System.out.println("   ❌ FAIL: " + message);
            failures.add(message);
        }
    }

    public static void main(String[] args) {
        System.out.println("AxonFlow Unified Execution Tracking Example - Java");
        System.out.println("=".repeat(55));
        System.out.println();

        // Initialize client
        // WCP endpoints are on the orchestrator (port 8081)
        String endpoint = System.getenv().getOrDefault("AXONFLOW_ENDPOINT", "http://localhost:8081");
        String clientId = System.getenv().getOrDefault("AXONFLOW_CLIENT_ID", "demo");
        String clientSecret = System.getenv().getOrDefault("AXONFLOW_CLIENT_SECRET", "demo");

        AxonFlowConfig config = AxonFlowConfig.builder()
            .endpoint(endpoint)
            .clientId(clientId)
            .clientSecret(clientSecret)
            .build();

        AxonFlow client = AxonFlow.create(config);

        try {
            // Step 1: Create a WCP workflow to demonstrate unified tracking
            System.out.println("Creating WCP workflow...");
            CreateWorkflowRequest createRequest = CreateWorkflowRequest.builder()
                .workflowName("unified-tracking-demo")
                .source(WorkflowSource.EXTERNAL)
                .build();

            CreateWorkflowResponse workflow = client.createWorkflow(createRequest);
            System.out.println("Workflow ID: " + workflow.getWorkflowId());
            assertCheck(workflow != null, "createWorkflow returned response");
            assertCheck(workflow.getWorkflowId() != null && !workflow.getWorkflowId().isEmpty(), "Workflow has ID");
            System.out.println();

            // Step 2: Complete some steps
            System.out.println("Completing workflow steps...");

            for (int i = 1; i <= 3; i++) {
                String stepId = "step-" + i;

                // Check gate
                try {
                    StepGateRequest gateRequest = StepGateRequest.builder()
                        .stepName("Step " + i)
                        .stepType(StepType.LLM_CALL)
                        .build();

                    StepGateResponse gate = client.stepGate(workflow.getWorkflowId(), stepId, gateRequest);
                    System.out.println("  Step " + i + ": " + gate.getDecision().getValue());

                    // Mark completed if allowed
                    if (gate.isAllowed()) {
                        MarkStepCompletedRequest completeRequest = MarkStepCompletedRequest.builder()
                            .output(java.util.Map.of("result", "completed step " + i))
                            .build();
                        client.markStepCompleted(workflow.getWorkflowId(), stepId, completeRequest);
                    }
                } catch (Exception e) {
                    System.out.println("  Step " + i + " error: " + e.getMessage());
                }
            }

            // Complete workflow
            try {
                client.completeWorkflow(workflow.getWorkflowId());
            } catch (Exception e) {
                System.out.println("Error completing workflow: " + e.getMessage());
            }

            System.out.println();

            // Step 3: Get workflow status using existing API
            System.out.println("Getting workflow status...");
            try {
                WorkflowStatusResponse status = client.getWorkflow(workflow.getWorkflowId());
                System.out.println("  Workflow: " + status.getWorkflowName());
                System.out.println("  Status: " + status.getStatus().getValue());
                System.out.println("  Steps: " + (status.getSteps() != null ? status.getSteps().size() : 0));
                assertCheck(status != null, "getWorkflow returned status");
                assertCheck(status.getWorkflowName() != null, "Workflow status has name");
                assertCheck(status.getStatus() != null, "Workflow status has status value");
            } catch (Exception e) {
                System.out.println("Error getting status: " + e.getMessage());
                assertCheck(false, "getWorkflow failed: " + e.getMessage());
            }
            System.out.println();

            // Step 4: Demonstrate unified execution status types
            System.out.println("Unified Execution Status Types (SDK v2.5.0):");
            System.out.println("  ExecutionType constants:");
            System.out.println("    - MAP: " + ExecutionType.MAP_PLAN.getValue());
            System.out.println("    - WCP: " + ExecutionType.WCP_WORKFLOW.getValue());
            assertCheck("map_plan".equals(ExecutionType.MAP_PLAN.getValue()), "ExecutionType.MAP_PLAN has correct value");
            assertCheck("wcp_workflow".equals(ExecutionType.WCP_WORKFLOW.getValue()), "ExecutionType.WCP_WORKFLOW has correct value");
            System.out.println();
            System.out.println("  ExecutionStatusValue constants:");
            System.out.println("    - Pending: " + ExecutionStatusValue.PENDING.getValue());
            System.out.println("    - Running: " + ExecutionStatusValue.RUNNING.getValue());
            System.out.println("    - Completed: " + ExecutionStatusValue.COMPLETED.getValue());
            System.out.println("    - Failed: " + ExecutionStatusValue.FAILED.getValue());
            // v4.3.0: "expired" is now a valid execution status
            System.out.println("    - Expired: " + ExecutionStatusValue.EXPIRED.getValue());
            System.out.println();
            System.out.println("  StepStatusValue helpers:");
            System.out.println("    - IsTerminal(completed): " + StepStatusValue.COMPLETED.isTerminal());
            System.out.println("    - IsTerminal(running): " + StepStatusValue.RUNNING.isTerminal());
            System.out.println("    - IsBlocking(blocked): " + StepStatusValue.BLOCKED.isBlocking());
            assertCheck(StepStatusValue.COMPLETED.isTerminal(), "COMPLETED is terminal status");
            assertCheck(!StepStatusValue.RUNNING.isTerminal(), "RUNNING is not terminal status");
            assertCheck(StepStatusValue.BLOCKED.isBlocking(), "BLOCKED is blocking status");
            System.out.println();

            // Step 5: Try unified execution API (may fail if backend not wired)
            System.out.println("Testing unified execution API...");
            try {
                ExecutionStatus execStatus = client.getExecutionStatus(workflow.getWorkflowId());
                System.out.println("  Execution ID: " + execStatus.getExecutionId());
                System.out.println("  Execution Type: " + execStatus.getExecutionType().getValue());
                System.out.println("  Status: " + execStatus.getStatus().getValue());
                System.out.printf("  Progress: %.1f%%%n", execStatus.getProgressPercent());
            } catch (Exception e) {
                System.out.println("  Note: Unified API returned error: " + e.getMessage());
                System.out.println("  (This is expected if backend unified handler not yet wired)");
            }
            System.out.println();

            // Step 6: List executions
            System.out.println("Listing unified executions...");
            try {
                UnifiedListExecutionsRequest listRequest = UnifiedListExecutionsRequest.builder()
                    .executionType(ExecutionType.WCP_WORKFLOW)
                    .limit(5)
                    .build();
                UnifiedListExecutionsResponse listResult = client.listUnifiedExecutions(listRequest);
                System.out.println("  Found " + listResult.getTotal() + " WCP executions");
                if (listResult.getExecutions() != null) {
                    for (ExecutionStatus exec : listResult.getExecutions()) {
                        System.out.printf("    - %s: %s (%s)%n",
                            exec.getExecutionId(),
                            exec.getName(),
                            exec.getStatus().getValue());
                    }
                }
            } catch (Exception e) {
                System.out.println("  Note: List API returned error: " + e.getMessage());
                System.out.println("  (This is expected if backend unified handler not yet wired)");
            }
            System.out.println();

            // Step 7: List WCP workflows (native API)
            System.out.println("Listing WCP workflows...");
            try {
                ListWorkflowsResponse workflowsResp = client.listWorkflows(
                    ListWorkflowsOptions.builder().limit(10).build()
                );
                System.out.println("  Found " + workflowsResp.getTotal() + " workflows");
                if (workflowsResp.getWorkflows() != null) {
                    for (WorkflowStatusResponse wf : workflowsResp.getWorkflows()) {
                        System.out.printf("    - %s: %s (%s)%n",
                            wf.getWorkflowId(),
                            wf.getWorkflowName(),
                            wf.getStatus().getValue());
                    }
                }
            } catch (Exception e) {
                System.out.println("  Note: ListWorkflows API returned error: " + e.getMessage());
            }
            System.out.println();

            // Step 8: Live SSE Streaming
            System.out.println("Testing streamExecutionStatus (Live SSE)...");
            try {
                CreateWorkflowRequest sseRequest = CreateWorkflowRequest.builder()
                    .workflowName("sse-streaming-demo")
                    .source(WorkflowSource.EXTERNAL)
                    .build();
                CreateWorkflowResponse sseWf = client.createWorkflow(sseRequest);
                System.out.println("  Created workflow: " + sseWf.getWorkflowId());

                final String sseWfId = sseWf.getWorkflowId();
                AtomicInteger eventCount = new AtomicInteger(0);

                // Execute steps in background to generate SSE events
                Thread stepThread = new Thread(() -> {
                    try {
                        Thread.sleep(500);
                        for (int i = 1; i <= 2; i++) {
                            String stepId = "step-" + i;
                            client.stepGate(sseWfId, stepId, StepGateRequest.builder()
                                .stepName("SSE Step " + i)
                                .stepType(StepType.LLM_CALL)
                                .build());
                            client.markStepCompleted(sseWfId, stepId, MarkStepCompletedRequest.builder()
                                .output(java.util.Map.of("result", "sse-step-" + i + "-done"))
                                .build());
                        }
                        client.completeWorkflow(sseWfId);
                    } catch (Exception e) {
                        System.out.println("  Background step error: " + e.getMessage());
                    }
                });
                stepThread.setDaemon(true);
                stepThread.start();

                try {
                    client.streamExecutionStatus(sseWfId, status -> {
                        int n = eventCount.incrementAndGet();
                        System.out.printf("  SSE event %d: status=%s, progress=%.0f%%%n",
                            n, status.getStatus().getValue(), status.getProgressPercent());
                    });
                } catch (Exception e) {
                    System.out.println("  Note: SSE stream error: " + e.getMessage());
                }
                stepThread.join(5000);
                assertCheck(eventCount.get() > 0, "Received " + eventCount.get() + " SSE events");
            } catch (Exception e) {
                System.out.println("  Note: SSE streaming returned error: " + e.getMessage());
                System.out.println("  (SSE streaming may not be supported in this mode)");
            }
            System.out.println();

            // Step 9: Test cancelExecution (create workflow, then cancel)
            System.out.println("Testing cancelExecution...");
            try {
                CreateWorkflowRequest cancelRequest = CreateWorkflowRequest.builder()
                    .workflowName("cancel-test-demo")
                    .source(WorkflowSource.EXTERNAL)
                    .build();
                CreateWorkflowResponse cancelTest = client.createWorkflow(cancelRequest);
                System.out.println("  Created workflow: " + cancelTest.getWorkflowId());
                try {
                    client.cancelExecution(cancelTest.getWorkflowId(), "testing unified cancel");
                    System.out.println("  Cancelled workflow: " + cancelTest.getWorkflowId());
                    // Verify status
                    WorkflowStatusResponse cancelStatus = client.getWorkflow(cancelTest.getWorkflowId());
                    String statusVal = cancelStatus.getStatus().getValue();
                    assertCheck(
                        "aborted".equals(statusVal) || "cancelled".equals(statusVal),
                        "Workflow is aborted/cancelled after cancelExecution (got " + statusVal + ")"
                    );
                } catch (Exception e) {
                    System.out.println("  Note: cancelExecution returned error: " + e.getMessage());
                    System.out.println("  (Cancel propagation requires unified handler wiring)");
                }
            } catch (Exception e) {
                System.out.println("  Error creating cancel test workflow: " + e.getMessage());
            }
            System.out.println();

            // Step 10: Demonstrate resumeWorkflow (by aborting then resuming)
            System.out.println("Testing resumeWorkflow...");
            try {
                CreateWorkflowRequest resumeRequest = CreateWorkflowRequest.builder()
                    .workflowName("resume-test-demo")
                    .source(WorkflowSource.EXTERNAL)
                    .build();
                CreateWorkflowResponse resumeTest = client.createWorkflow(resumeRequest);

                // Abort the workflow first
                client.abortWorkflow(resumeTest.getWorkflowId());
                System.out.println("  Aborted workflow: " + resumeTest.getWorkflowId());

                // Try to resume it
                try {
                    client.resumeWorkflow(resumeTest.getWorkflowId());
                    System.out.println("  Resumed workflow: " + resumeTest.getWorkflowId());
                } catch (Exception e) {
                    System.out.println("  Note: resumeWorkflow returned error: " + e.getMessage());
                    System.out.println("  (Resume may not be supported for all abort reasons)");
                }
            } catch (Exception e) {
                System.out.println("  Error creating resume test workflow: " + e.getMessage());
            }
            System.out.println();

            System.out.println("=".repeat(55));
            System.out.println("Unified Execution Tracking Example Complete!");
            System.out.println();
            System.out.println("SDK methods demonstrated:");
            System.out.println("  WCP Workflow:");
            System.out.println("    - createWorkflow()");
            System.out.println("    - stepGate()");
            System.out.println("    - markStepCompleted()");
            System.out.println("    - completeWorkflow()");
            System.out.println("    - getWorkflow()");
            System.out.println("    - listWorkflows()");
            System.out.println("    - abortWorkflow()");
            System.out.println("    - resumeWorkflow()");
            System.out.println("  Unified Execution:");
            System.out.println("    - getExecutionStatus()");
            System.out.println("    - listUnifiedExecutions()");
            System.out.println("    - cancelExecution()");
            System.out.println("  SSE Streaming:");
            System.out.println("    - streamExecutionStatus()");
            System.out.println("  Helper Types:");
            System.out.println("    - ExecutionType (map_plan, wcp_workflow)");
            System.out.println("    - ExecutionStatusValue with isTerminal()");
            System.out.println("    - StepStatusValue with isTerminal(), isBlocking()");

            // Final assertion summary
            System.out.println();
            System.out.println("=".repeat(55));
            System.out.println("Assertion Summary");
            System.out.println("=".repeat(55));
            if (failures.isEmpty()) {
                System.out.println("All assertions passed!");
            } else {
                System.out.println("Failures (" + failures.size() + "):");
                for (String f : failures) {
                    System.out.println("  - " + f);
                }
                System.exit(1);
            }

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
