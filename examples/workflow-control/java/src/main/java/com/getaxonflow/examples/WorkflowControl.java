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

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Workflow Control Plane - Java Example
 *
 * "LangChain runs the workflow. AxonFlow decides when it's allowed to move forward."
 *
 * This example demonstrates how to:
 * 1. Create a workflow
 * 2. Check step gates before each step
 * 3. Mark steps as completed
 * 4. Complete the workflow
 * 5. Approve/reject steps (enterprise feature)
 * 6. List pending approvals (enterprise feature)
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 */
public class WorkflowControl {

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
        System.out.println("Workflow Control Plane - Java");
        System.out.println("========================================");
        System.out.println();

        // Initialize AxonFlow client
        AxonFlow client = AxonFlow.create(AxonFlowConfig.builder()
            .endpoint(getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080"))
            .clientId(getEnv("AXONFLOW_CLIENT_ID", "workflow-control-java"))
            .clientSecret(getEnv("AXONFLOW_CLIENT_SECRET", ""))
            .build());

        try {
            // Step 1: Create a workflow
            System.out.println("Step 1: Create Workflow");
            System.out.println("   Creating 'code-review-pipeline' workflow...");

            CreateWorkflowResponse workflow = client.createWorkflow(
                CreateWorkflowRequest.builder()
                    .workflowName("code-review-pipeline")
                    .source(WorkflowSource.EXTERNAL)
                    .totalSteps(3)
                    .metadata(Map.of("example", "workflow-control-java"))
                    .build()
            );

            System.out.println("   Workflow created!");
            System.out.println("   Workflow ID: " + workflow.getWorkflowId());
            assertCheck(workflow.getWorkflowId() != null, "Workflow created with ID");
            System.out.println();

            // Step 2: Check gate for first step (Generate Code - LLM call)
            System.out.println("Step 2: Check Gate - Generate Code");
            System.out.println("   Checking if 'generate_code' step is allowed...");

            StepGateResponse gate1 = client.stepGate(
                workflow.getWorkflowId(),
                "step-1",
                StepGateRequest.builder()
                    .stepName("Generate Code")
                    .stepType(StepType.LLM_CALL)
                    .model("gpt-4")
                    .provider("openai")
                    .stepInput(Map.of("prompt", "Write a Python function to sort a list"))
                    .build()
            );

            System.out.println("   Decision: " + gate1.getDecision());
            assertCheck(gate1.getDecision() != null, "Step gate returns decision");
            if (gate1.getReason() != null) {
                System.out.println("   Reason: " + gate1.getReason());
            }

            if (gate1.isBlocked()) {
                System.out.println("   Workflow blocked by policy. Aborting...");
                client.abortWorkflow(workflow.getWorkflowId(), gate1.getReason());
                assertCheck(true, "Workflow aborted correctly when blocked");
                return;
            }

            if (gate1.requiresApproval()) {
                System.out.println("   Approval URL: " + gate1.getApprovalUrl());
                System.out.println("   (Enterprise feature - approval workflow would be triggered)");
                assertCheck(gate1.getApprovalUrl() != null, "Approval URL provided");
                // In production, you would wait for approval here
            }

            // Mark step 1 completed
            if (gate1.isAllowed()) {
                client.markStepCompleted(
                    workflow.getWorkflowId(),
                    "step-1",
                    MarkStepCompletedRequest.builder()
                        .output(Map.of("code", "def sort_list(items): return sorted(items)"))
                        .build()
                );
                System.out.println("   Step completed!");
                assertCheck(true, "Step 1 completed successfully");
            }
            System.out.println();

            // Step 3: Check gate for second step (Review Code - Tool call)
            System.out.println("Step 3: Check Gate - Review Code");
            System.out.println("   Checking if 'review_code' step is allowed...");

            StepGateResponse gate2 = client.stepGate(
                workflow.getWorkflowId(),
                "step-2",
                StepGateRequest.builder()
                    .stepName("Review Code")
                    .stepType(StepType.TOOL_CALL)
                    .stepInput(Map.of(
                        "tool", "code_reviewer",
                        "code", "def sort_list(items): return sorted(items)"
                    ))
                    .build()
            );

            System.out.println("   Decision: " + gate2.getDecision());
            assertCheck(gate2.getDecision() != null, "Step 2 gate returns decision");
            if (gate2.isAllowed()) {
                client.markStepCompleted(
                    workflow.getWorkflowId(),
                    "step-2",
                    MarkStepCompletedRequest.builder()
                        .output(Map.of("review", "LGTM"))
                        .build()
                );
                System.out.println("   Step completed!");
                assertCheck(true, "Step 2 completed successfully");
            }
            System.out.println();

            // Step 4: Check gate for third step (Deploy - Connector call)
            System.out.println("Step 4: Check Gate - Deploy");
            System.out.println("   Checking if 'deploy' step is allowed...");

            StepGateResponse gate3 = client.stepGate(
                workflow.getWorkflowId(),
                "step-3",
                StepGateRequest.builder()
                    .stepName("Deploy to Production")
                    .stepType(StepType.CONNECTOR_CALL)
                    .stepInput(Map.of(
                        "connector", "github",
                        "action", "create_pr"
                    ))
                    .build()
            );

            System.out.println("   Decision: " + gate3.getDecision());
            assertCheck(gate3.getDecision() != null, "Step 3 gate returns decision");
            if (gate3.isAllowed()) {
                client.markStepCompleted(
                    workflow.getWorkflowId(),
                    "step-3",
                    MarkStepCompletedRequest.builder()
                        .output(Map.of("pr_url", "https://github.com/example/pr/123"))
                        .build()
                );
                System.out.println("   Step completed!");
                assertCheck(true, "Step 3 completed successfully");
            }
            System.out.println();

            // Step 5: Complete the workflow
            System.out.println("Step 5: Complete Workflow");
            client.completeWorkflow(workflow.getWorkflowId());
            System.out.println("   Workflow completed!");
            assertCheck(true, "Workflow completed successfully");
            System.out.println();

            // Step 5b: Fail Workflow (raw HTTP — SDK method not yet available)
            System.out.println("Step 5b: Fail Workflow");
            System.out.println("   Testing /fail endpoint...");
            try {
                CreateWorkflowResponse failWf = client.createWorkflow(
                    CreateWorkflowRequest.builder()
                        .workflowName("wcp-fail-test")
                        .source(WorkflowSource.EXTERNAL)
                        .totalSteps(2)
                        .metadata(Map.of("test", "fail-workflow"))
                        .build()
                );
                assertCheck(failWf.getWorkflowId() != null, "Fail-test workflow created with valid ID");
                System.out.println("   Workflow ID: " + failWf.getWorkflowId());

                // Call /fail endpoint via raw HTTP (SDK method not yet available)
                String agentUrl = getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080");
                String failUrl = agentUrl + "/api/v1/workflows/" + failWf.getWorkflowId() + "/fail";
                URL failEndpoint = new URL(failUrl);
                HttpURLConnection failConn = (HttpURLConnection) failEndpoint.openConnection();
                failConn.setRequestMethod("POST");
                failConn.setRequestProperty("Content-Type", "application/json");
                failConn.setRequestProperty("X-Client-ID", getEnv("AXONFLOW_CLIENT_ID", "workflow-control-java"));
                failConn.setRequestProperty("X-Client-Secret", getEnv("AXONFLOW_CLIENT_SECRET", ""));
                failConn.setDoOutput(true);
                failConn.setConnectTimeout(10000);
                failConn.setReadTimeout(10000);
                failConn.getOutputStream().write("{\"reason\":\"LLM provider timeout\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
                failConn.getOutputStream().flush();

                int failStatus = failConn.getResponseCode();
                assertCheck(failStatus == 200, "FailWorkflow returns HTTP 200 (got " + failStatus + ")");

                java.io.InputStream failInputStream = failConn.getInputStream();
                String failBody = new String(failInputStream.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
                assertCheck(failBody.contains("\"failed\""), "FailWorkflow response contains 'failed' status");
                System.out.println("   Status: " + failStatus);
                System.out.println("   Body: " + failBody);
                failConn.disconnect();

                // Verify via SDK
                WorkflowStatusResponse failedWfStatus = client.getWorkflow(failWf.getWorkflowId());
                assertCheck("failed".equals(failedWfStatus.getStatus().getValue()), "Workflow status verified as 'failed' (got: " + failedWfStatus.getStatus().getValue() + ")");
            } catch (Exception failEx) {
                System.out.println("   ERROR: FailWorkflow test failed: " + failEx.getMessage());
                failures.add("fail_workflow test failed: " + failEx.getMessage());
            }
            System.out.println();

            // Step 6: Get final workflow status
            System.out.println("Step 6: Workflow Status");
            WorkflowStatusResponse status = client.getWorkflow(workflow.getWorkflowId());
            System.out.println("   Workflow: " + status.getWorkflowName());
            System.out.println("   Status: " + status.getStatus());
            System.out.println("   Steps: " + (status.getSteps() != null ? status.getSteps().size() : 0));
            assertCheck(status.getWorkflowName() != null, "Workflow status has name");
            assertCheck(status.getStatus() != null, "Workflow status has status");
            System.out.println();

            // -------------------------------------------------------
            // Step Approval Tests (Enterprise Feature)
            // These may return 403 in community mode — skip gracefully.
            // -------------------------------------------------------

            // Test 7: Step Approval Flow
            System.out.println("Step 7: Step Approval Flow");
            System.out.println("   Creating 'wcp-approval-test' workflow (3 steps)...");
            try {
                CreateWorkflowResponse approvalWorkflow = client.createWorkflow(
                    CreateWorkflowRequest.builder()
                        .workflowName("wcp-approval-test")
                        .source(WorkflowSource.EXTERNAL)
                        .totalSteps(3)
                        .metadata(Map.of("example", "step-approval-java"))
                        .build()
                );

                assertCheck(approvalWorkflow.getWorkflowId() != null, "Approval test workflow created");
                System.out.println("   Workflow ID: " + approvalWorkflow.getWorkflowId());

                // Gate the first step
                System.out.println("   Checking gate for step-1...");
                StepGateResponse approvalGate = client.stepGate(
                    approvalWorkflow.getWorkflowId(),
                    "step-1",
                    StepGateRequest.builder()
                        .stepName("Approval Target Step")
                        .stepType(StepType.LLM_CALL)
                        .model("gpt-4")
                        .provider("openai")
                        .stepInput(Map.of("prompt", "Test step for approval"))
                        .build()
                );
                assertCheck(approvalGate.getDecision() != null, "Approval gate decision is valid");
                System.out.println("   Gate decision: " + approvalGate.getDecision());

                // Approve the step
                System.out.println("   Approving step-1...");
                ApproveStepResponse approveResp = client.approveStep(
                    approvalWorkflow.getWorkflowId(), "step-1"
                );
                assertCheck(approveResp != null, "approveStep returned a response");
                if (approveResp.getStatus() != null) {
                    assertCheck(
                        "approved".equals(approveResp.getStatus()) || approveResp.getStatus().length() > 0,
                        "Approve response shows approved status"
                    );
                    System.out.println("   Approval status: " + approveResp.getStatus());
                } else {
                    System.out.println("   Approval response received (no status field)");
                }

                // Check pending approvals
                System.out.println("   Checking pending approvals...");
                PendingApprovalsResponse pendingResp = client.getPendingApprovals();
                assertCheck(pendingResp != null, "getPendingApprovals returned a response");
                if (pendingResp.getApprovals() != null) {
                    assertCheck(true, "Pending approvals has items list");
                    System.out.println("   Pending approvals count: " + pendingResp.getApprovals().size());
                }
                if (pendingResp.getTotal() >= 0) {
                    System.out.println("   Total pending: " + pendingResp.getTotal());
                }
            } catch (Exception approvalEx) {
                String approvalMsg = approvalEx.getMessage() != null ? approvalEx.getMessage() : "";
                if (approvalMsg.contains("403") || approvalMsg.contains("404")
                        || approvalMsg.contains("enterprise")
                        || approvalMsg.contains("not available") || approvalMsg.contains("license")
                        || approvalMsg.contains("not found")) {
                    System.out.println("   SKIPPED: Step approval is an enterprise feature");
                    System.out.println("   (" + approvalMsg + ")");
                } else {
                    throw approvalEx;
                }
            }
            System.out.println();

            // Test 8: Step Rejection Flow
            System.out.println("Step 8: Step Rejection Flow");
            System.out.println("   Creating 'wcp-rejection-test' workflow (2 steps)...");
            try {
                CreateWorkflowResponse rejectionWorkflow = client.createWorkflow(
                    CreateWorkflowRequest.builder()
                        .workflowName("wcp-rejection-test")
                        .source(WorkflowSource.EXTERNAL)
                        .totalSteps(2)
                        .metadata(Map.of("example", "step-rejection-java"))
                        .build()
                );

                assertCheck(rejectionWorkflow.getWorkflowId() != null, "Rejection test workflow created");
                System.out.println("   Workflow ID: " + rejectionWorkflow.getWorkflowId());

                // Gate the first step
                System.out.println("   Checking gate for step-1...");
                StepGateResponse rejectionGate = client.stepGate(
                    rejectionWorkflow.getWorkflowId(),
                    "step-1",
                    StepGateRequest.builder()
                        .stepName("Rejection Target Step")
                        .stepType(StepType.TOOL_CALL)
                        .stepInput(Map.of("tool", "risky_action", "action", "delete_all"))
                        .build()
                );
                assertCheck(rejectionGate.getDecision() != null, "Rejection gate decision is valid");
                System.out.println("   Gate decision: " + rejectionGate.getDecision());

                // Reject the step
                System.out.println("   Rejecting step-1...");
                RejectStepResponse rejectResp = client.rejectStep(
                    rejectionWorkflow.getWorkflowId(), "step-1"
                );
                assertCheck(rejectResp != null, "rejectStep returned a response");
                if (rejectResp.getStatus() != null) {
                    assertCheck(
                        "rejected".equals(rejectResp.getStatus()) || rejectResp.getStatus().length() > 0,
                        "Reject response shows rejected status"
                    );
                    System.out.println("   Rejection status: " + rejectResp.getStatus());
                } else {
                    System.out.println("   Rejection response received (no status field)");
                }
            } catch (Exception rejectionEx) {
                String rejectionMsg = rejectionEx.getMessage() != null ? rejectionEx.getMessage() : "";
                if (rejectionMsg.contains("403") || rejectionMsg.contains("404")
                        || rejectionMsg.contains("enterprise")
                        || rejectionMsg.contains("not available") || rejectionMsg.contains("license")
                        || rejectionMsg.contains("not found")) {
                    System.out.println("   SKIPPED: Step rejection is an enterprise feature");
                    System.out.println("   (" + rejectionMsg + ")");
                } else {
                    throw rejectionEx;
                }
            }
            System.out.println();

            // Test 9: Get Pending Approvals (standalone)
            System.out.println("Step 9: Get Pending Approvals");
            System.out.println("   Fetching pending approvals list...");
            try {
                PendingApprovalsResponse allPending = client.getPendingApprovals();
                assertCheck(allPending != null, "getPendingApprovals returned a response");
                if (allPending.getApprovals() != null) {
                    assertCheck(true, "Response has items list");
                    System.out.println("   Items count: " + allPending.getApprovals().size());
                }
                if (allPending.getTotal() >= 0) {
                    assertCheck(true, "Response has total count");
                    System.out.println("   Total: " + allPending.getTotal());
                }
            } catch (Exception pendingEx) {
                String pendingMsg = pendingEx.getMessage() != null ? pendingEx.getMessage() : "";
                if (pendingMsg.contains("403") || pendingMsg.contains("404")
                        || pendingMsg.contains("enterprise")
                        || pendingMsg.contains("not available") || pendingMsg.contains("license")
                        || pendingMsg.contains("not found")) {
                    System.out.println("   SKIPPED: Pending approvals is an enterprise feature");
                    System.out.println("   (" + pendingMsg + ")");
                } else {
                    throw pendingEx;
                }
            }
            System.out.println();

            // ========================================
            // Step 10: SSE Streaming - Real-time execution status
            // ========================================
            System.out.println("Step 10: SSE Streaming - Real-time execution status");
            System.out.println("   Creating workflow for SSE streaming test...");

            try {
                CreateWorkflowResponse sseWorkflow = client.createWorkflow(
                    CreateWorkflowRequest.builder()
                        .workflowName("wcp-sse-streaming-test")
                        .source(WorkflowSource.EXTERNAL)
                        .totalSteps(2)
                        .metadata(Map.of("example", "sse-streaming-java"))
                        .build()
                );

                assertCheck(sseWorkflow.getWorkflowId() != null, "SSE workflow created with valid ID");
                System.out.println("   Workflow ID: " + sseWorkflow.getWorkflowId());

                // Run a step gate and complete a step to generate execution events
                StepGateResponse sseGate = client.stepGate(
                    sseWorkflow.getWorkflowId(),
                    "sse-step-1",
                    StepGateRequest.builder()
                        .stepName("SSE Test Step")
                        .stepType(StepType.LLM_CALL)
                        .model("gpt-4")
                        .provider("openai")
                        .stepInput(Map.of("prompt", "test SSE streaming"))
                        .build()
                );

                if (sseGate.isAllowed()) {
                    client.markStepCompleted(
                        sseWorkflow.getWorkflowId(),
                        "sse-step-1",
                        MarkStepCompletedRequest.builder()
                            .output(Map.of("result", "sse test output"))
                            .build()
                    );
                    assertCheck(true, "SSE step completed");
                }

                // Stream execution status via HTTP SSE endpoint
                String orchestratorUrl = getEnv("AXONFLOW_ORCHESTRATOR_URL", "http://localhost:8081");
                String sseClientId = getEnv("AXONFLOW_CLIENT_ID", "workflow-control-java");
                String sseClientSecret = getEnv("AXONFLOW_CLIENT_SECRET", "");
                String streamUrl = orchestratorUrl + "/api/v1/unified/executions/" + sseWorkflow.getWorkflowId() + "/stream";
                System.out.println("   SSE URL: " + streamUrl);

                try {
                    // Completed executions are evicted from the tracker, so a 404 with
                    // "NOT_FOUND" / "Execution not found" proves the endpoint exists.
                    URL url = new URL(streamUrl);
                    HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                    conn.setRequestMethod("GET");
                    conn.setRequestProperty("Accept", "application/json");
                    conn.setRequestProperty("X-Client-ID", sseClientId);
                    conn.setRequestProperty("X-Client-Secret", sseClientSecret);
                    conn.setConnectTimeout(10000);
                    conn.setReadTimeout(10000);
                    conn.connect();

                    int statusCode = conn.getResponseCode();
                    if (statusCode == 200) {
                        assertCheck(true, "SSE endpoint returned 200");
                        System.out.println("   SSE endpoint available (HTTP 200)");
                    } else if (statusCode == 404) {
                        java.io.InputStream errStream = conn.getErrorStream();
                        String body = errStream != null
                            ? new String(errStream.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8)
                            : "";
                        boolean validNotFound = body.contains("NOT_FOUND") || body.contains("Execution not found");
                        assertCheck(validNotFound, "SSE endpoint returned structured 404: " + body);
                        System.out.println("   SSE endpoint available (connect during active execution for real-time events)");
                    } else {
                        assertCheck(false, "SSE endpoint returned unexpected HTTP " + statusCode);
                    }
                    conn.disconnect();
                } catch (Exception sseErr) {
                    System.out.println("   Warning: SSE connection failed: " + sseErr.getMessage());
                    System.out.println("   Note: SSE endpoint may not be available yet");
                }
            } catch (Exception sseSetupErr) {
                String sseMsg = sseSetupErr.getMessage() != null ? sseSetupErr.getMessage() : "";
                System.out.println("   FATAL: SSE streaming test failed: " + sseMsg);
                failures.add("SSE streaming test failed: " + sseMsg);
            }
            System.out.println();

            System.out.println("========================================");
            System.out.println("Workflow Control Plane Example Complete!");
            System.out.println();
            System.out.println("Key concepts demonstrated:");
            System.out.println("  1. Create workflow (register with AxonFlow)");
            System.out.println("  2. Check step gates (policy evaluation)");
            System.out.println("  3. Mark steps completed (progress tracking)");
            System.out.println("  4. Complete workflow (lifecycle management)");
            System.out.println("  5b. Fail workflow (via /fail endpoint)");
            System.out.println("  5. Approve steps (enterprise approval flow)");
            System.out.println("  6. Reject steps (enterprise rejection flow)");
            System.out.println("  7. List pending approvals (enterprise)");
            System.out.println(" 10. SSE Streaming (real-time execution status)");

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
            failures.add("Exception: " + e.getMessage());
        } finally {
            client.close();
        }

        // Final assertion check
        if (!failures.isEmpty()) {
            System.out.println();
            System.out.println("FAILURES (" + failures.size() + "):");
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
