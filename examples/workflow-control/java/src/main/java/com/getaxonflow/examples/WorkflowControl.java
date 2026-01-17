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
 */
public class WorkflowControl {

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
            if (gate1.getReason() != null) {
                System.out.println("   Reason: " + gate1.getReason());
            }

            if (gate1.isBlocked()) {
                System.out.println("   Workflow blocked by policy. Aborting...");
                client.abortWorkflow(workflow.getWorkflowId(), gate1.getReason());
                return;
            }

            if (gate1.requiresApproval()) {
                System.out.println("   Approval URL: " + gate1.getApprovalUrl());
                System.out.println("   (Enterprise feature - approval workflow would be triggered)");
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
            if (gate2.isAllowed()) {
                client.markStepCompleted(
                    workflow.getWorkflowId(),
                    "step-2",
                    MarkStepCompletedRequest.builder()
                        .output(Map.of("review", "LGTM"))
                        .build()
                );
                System.out.println("   Step completed!");
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
            if (gate3.isAllowed()) {
                client.markStepCompleted(
                    workflow.getWorkflowId(),
                    "step-3",
                    MarkStepCompletedRequest.builder()
                        .output(Map.of("pr_url", "https://github.com/example/pr/123"))
                        .build()
                );
                System.out.println("   Step completed!");
            }
            System.out.println();

            // Step 5: Complete the workflow
            System.out.println("Step 5: Complete Workflow");
            client.completeWorkflow(workflow.getWorkflowId());
            System.out.println("   Workflow completed!");
            System.out.println();

            // Step 6: Get final workflow status
            System.out.println("Step 6: Workflow Status");
            WorkflowStatusResponse status = client.getWorkflow(workflow.getWorkflowId());
            System.out.println("   Workflow: " + status.getWorkflowName());
            System.out.println("   Status: " + status.getStatus());
            System.out.println("   Steps: " + (status.getSteps() != null ? status.getSteps().size() : 0));
            System.out.println();

            System.out.println("========================================");
            System.out.println("Workflow Control Plane Example Complete!");
            System.out.println();
            System.out.println("Key concepts demonstrated:");
            System.out.println("  1. Create workflow (register with AxonFlow)");
            System.out.println("  2. Check step gates (policy evaluation)");
            System.out.println("  3. Mark steps completed (progress tracking)");
            System.out.println("  4. Complete workflow (lifecycle management)");

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        } finally {
            client.close();
        }
    }

    private static String getEnv(String key, String defaultValue) {
        String value = System.getenv(key);
        return (value != null && !value.isEmpty()) ? value : defaultValue;
    }
}
