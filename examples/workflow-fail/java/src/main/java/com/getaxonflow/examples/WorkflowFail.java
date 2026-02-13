/*
 * Copyright 2026 AxonFlow
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.getaxonflow.examples;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.workflow.WorkflowTypes.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Workflow Fail - Java Example
 *
 * Demonstrates and VALIDATES the FailWorkflow SDK method:
 * 1. Create a workflow and complete one step
 * 2. Call failWorkflow() with a reason
 * 3. Verify workflow status is "failed"
 * 4. Call failWorkflow() without a reason (optional)
 * 5. Verify a failed workflow cannot be resumed
 * 6. Verify getWorkflow reflects failure correctly
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 */
public class WorkflowFail {

    private static final List<String> failures = new ArrayList<>();

    private static void assertCheck(boolean condition, String message) {
        if (condition) {
            System.out.println("   PASS: " + message);
        } else {
            System.out.println("   FAIL: " + message);
            failures.add(message);
        }
    }

    public static void main(String[] args) {
        System.out.println("Workflow Fail - Java (FailWorkflow Validation)");
        System.out.println("=".repeat(55));
        System.out.println();

        // Initialize AxonFlow client
        String endpoint = getEnv("AXONFLOW_ENDPOINT", getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080"));
        AxonFlow client = AxonFlow.create(AxonFlowConfig.builder()
            .endpoint(endpoint)
            .clientId(getEnv("AXONFLOW_CLIENT_ID", "workflow-fail-java"))
            .clientSecret(getEnv("AXONFLOW_CLIENT_SECRET", ""))
            .build());

        String workflowId = null;
        String noReasonWfId = null;

        try {
            // ========================================
            // Test 1: Create Workflow
            // ========================================
            System.out.println("Test 1: Create Workflow");
            System.out.println("   Creating 'fail-workflow-test' workflow...");

            CreateWorkflowResponse workflow = client.createWorkflow(
                CreateWorkflowRequest.builder()
                    .workflowName("fail-workflow-test")
                    .source(WorkflowSource.EXTERNAL)
                    .totalSteps(3)
                    .metadata(Map.of("test", "workflow-fail-java"))
                    .build()
            );

            workflowId = workflow.getWorkflowId();
            assertCheck(workflowId != null, "Workflow created with ID");
            assertCheck(workflowId.startsWith("wf_"), "Workflow ID has 'wf_' prefix");
            System.out.println("   Workflow ID: " + workflowId);
            System.out.println();

            // ========================================
            // Test 2: Step Gate + Complete Step
            // ========================================
            System.out.println("Test 2: Step Gate + Complete Step");
            System.out.println("   Checking gate for step-1...");

            StepGateResponse gate = client.stepGate(
                workflowId,
                "step-1",
                StepGateRequest.builder()
                    .stepName("Data Processing")
                    .stepType(StepType.LLM_CALL)
                    .model("gpt-4")
                    .provider("openai")
                    .stepInput(Map.of("prompt", "Process incoming data batch"))
                    .build()
            );

            assertCheck(gate.getDecision() != null, "Step gate returns decision");
            System.out.println("   Decision: " + gate.getDecision());

            if (gate.isAllowed()) {
                client.markStepCompleted(
                    workflowId,
                    "step-1",
                    MarkStepCompletedRequest.builder()
                        .output(Map.of("records_processed", 150))
                        .build()
                );
                assertCheck(true, "Step 1 completed successfully");
            }
            System.out.println();

            // ========================================
            // Test 3: FailWorkflow with Reason
            // ========================================
            System.out.println("Test 3: FailWorkflow with Reason");
            System.out.println("   Failing workflow with reason...");

            client.failWorkflow(workflowId, "LLM provider timeout after 30s");
            assertCheck(true, "failWorkflow() with reason succeeded");
            System.out.println("   Reason: LLM provider timeout after 30s");
            System.out.println();

            // ========================================
            // Test 4: Verify Workflow Status is Failed
            // ========================================
            System.out.println("Test 4: Verify Workflow Status is Failed");

            WorkflowStatusResponse status = client.getWorkflow(workflowId);
            assertCheck("fail-workflow-test".equals(status.getWorkflowName()), "Workflow name matches");
            String statusValue = status.getStatus() != null ? status.getStatus().getValue() : "null";
            assertCheck("failed".equals(statusValue), "Workflow status is 'failed' (got: " + statusValue + ")");
            System.out.println("   Status: " + statusValue);
            System.out.println("   Workflow: " + status.getWorkflowName());
            System.out.println();

            // ========================================
            // Test 5: FailWorkflow without Reason
            // ========================================
            System.out.println("Test 5: FailWorkflow without Reason");
            System.out.println("   Creating second workflow...");

            CreateWorkflowResponse noReasonWf = client.createWorkflow(
                CreateWorkflowRequest.builder()
                    .workflowName("fail-no-reason-test")
                    .source(WorkflowSource.EXTERNAL)
                    .totalSteps(2)
                    .metadata(Map.of("test", "fail-no-reason"))
                    .build()
            );

            noReasonWfId = noReasonWf.getWorkflowId();
            System.out.println("   Workflow ID: " + noReasonWfId);

            client.failWorkflow(noReasonWfId);
            assertCheck(true, "failWorkflow() without reason succeeded");

            WorkflowStatusResponse noReasonStatus = client.getWorkflow(noReasonWfId);
            String nrStatusValue = noReasonStatus.getStatus() != null ? noReasonStatus.getStatus().getValue() : "null";
            assertCheck("failed".equals(nrStatusValue), "Workflow status is 'failed' (got: " + nrStatusValue + ")");
            System.out.println("   Status: " + nrStatusValue);
            System.out.println();

            // ========================================
            // Test 6: Verify Failed Workflow Cannot Be Resumed
            // ========================================
            System.out.println("Test 6: Verify Failed Workflow Cannot Be Resumed");

            // Try step gate on failed workflow - should throw
            try {
                client.stepGate(
                    workflowId,
                    "step-2",
                    StepGateRequest.builder()
                        .stepName("Should Not Execute")
                        .stepType(StepType.TOOL_CALL)
                        .stepInput(Map.of("tool", "noop"))
                        .build()
                );
                assertCheck(false, "StepGate on failed workflow should have thrown");
            } catch (Exception resumeErr) {
                assertCheck(true, "StepGate on failed workflow throws error");
                System.out.println("   Expected error: " + resumeErr.getMessage());
            }

            // Try to complete the failed workflow - should throw
            try {
                client.completeWorkflow(workflowId);
                assertCheck(false, "CompleteWorkflow on failed workflow should have thrown");
            } catch (Exception completeErr) {
                assertCheck(true, "CompleteWorkflow on failed workflow throws error");
                System.out.println("   Expected error: " + completeErr.getMessage());
            }
            System.out.println();

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
            failures.add("Exception: " + e.getMessage());
        } finally {
            // Cleanup
            System.out.println("Cleanup");
            System.out.println("-------");
            for (String wfId : new String[]{workflowId, noReasonWfId}) {
                if (wfId != null) {
                    try {
                        client.abortWorkflow(wfId, "test cleanup");
                        System.out.println("   Cleaned up workflow: " + wfId);
                    } catch (Exception cleanupErr) {
                        System.out.println("   Warning: Could not abort " + wfId + " (may already be terminal)");
                    }
                }
            }
            System.out.println();
            client.close();
        }

        // ========================================
        // Summary
        // ========================================
        System.out.println("=".repeat(55));
        if (failures.isEmpty()) {
            System.out.println("ALL TESTS PASSED");
            System.out.println();
            System.out.println("FailWorkflow operations validated:");
            System.out.println("  - createWorkflow()");
            System.out.println("  - stepGate() + markStepCompleted()");
            System.out.println("  - failWorkflow() with reason");
            System.out.println("  - failWorkflow() without reason");
            System.out.println("  - getWorkflow() verifies 'failed' status");
            System.out.println("  - Failed workflow cannot be resumed");
        } else {
            System.out.println(failures.size() + " TEST(S) FAILED:");
            for (String failure : failures) {
                System.out.println("  - " + failure);
            }
            System.exit(1);
        }
    }

    private static String getEnv(String key, String defaultValue) {
        String value = System.getenv(key);
        return (value != null && !value.isEmpty()) ? value : defaultValue;
    }
}
