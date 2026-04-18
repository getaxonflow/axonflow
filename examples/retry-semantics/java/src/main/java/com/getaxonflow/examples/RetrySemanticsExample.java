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
 * Execution Boundary Semantics - Java SDK (#1414)
 *
 * Demonstrates and validates idempotent retry behavior for WCP step gates:
 * 1. Default retry behavior is idempotent (same step returns cached decision)
 * 2. Explicit retry_policy="reevaluate" forces fresh policy evaluation
 * 3. Response includes cached (boolean) and decisionSource ("fresh"/"cached")
 * 4. Different steps are evaluated independently
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 *
 * Run with: mvn compile exec:java
 * Prerequisites: docker compose up -d
 */
public class RetrySemanticsExample {

    private static int passCount = 0;
    private static int failCount = 0;

    private static String getEnv(String key, String defaultValue) {
        String value = System.getenv(key);
        return (value != null && !value.isEmpty()) ? value : defaultValue;
    }

    private static void assertCheck(boolean condition, String message) {
        if (condition) {
            System.out.println("   PASS: " + message);
            passCount++;
        } else {
            System.out.println("   FAIL: " + message);
            failCount++;
        }
    }

    public static void main(String[] args) {
        System.out.println("Execution Boundary Semantics - Java (#1414)");
        System.out.println("=".repeat(50));
        System.out.println();
        System.out.println("This test verifies idempotent retry behavior for WCP step gates.");
        System.out.println();

        AxonFlow client = AxonFlow.create(AxonFlowConfig.builder()
                .endpoint(getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080"))
                .clientId(getEnv("AXONFLOW_CLIENT_ID", "demo-org"))
                .clientSecret(getEnv("AXONFLOW_CLIENT_SECRET", ""))
                .build());

        // Test 1: Create workflow
        System.out.println("Test 1: Create Workflow");
        System.out.println("-".repeat(30));

        CreateWorkflowResponse wf = client.createWorkflow(CreateWorkflowRequest.builder()
                .workflowName("retry-semantics-test")
                .source(WorkflowSource.EXTERNAL)
                .build());
        assertCheck(wf.getWorkflowId() != null && !wf.getWorkflowId().isEmpty(),
                "Workflow created: " + wf.getWorkflowId());
        System.out.println();

        // Test 2: First step gate (fresh)
        System.out.println("Test 2: First Step Gate (fresh evaluation)");
        System.out.println("-".repeat(30));

        StepGateResponse resp1 = client.stepGate(wf.getWorkflowId(), "step-analyze",
                StepGateRequest.builder()
                        .stepName("Analyze Data")
                        .stepType(StepType.TOOL_CALL)
                        .stepInput(Map.of("tool", "data_analyzer"))
                        .build());
        assertCheck(resp1.getDecision() == GateDecision.ALLOW,
                "Decision is allow (got " + resp1.getDecision() + ")");
        assertCheck(!resp1.isCached(),
                "First call is NOT cached (cached=" + resp1.isCached() + ")");
        assertCheck("fresh".equals(resp1.getDecisionSource()),
                "Decision source is fresh (got " + resp1.getDecisionSource() + ")");
        System.out.println();

        // Test 3: Same step gate (default idempotent - cached)
        System.out.println("Test 3: Same Step Gate Again (default idempotent)");
        System.out.println("-".repeat(30));

        StepGateResponse resp2 = client.stepGate(wf.getWorkflowId(), "step-analyze",
                StepGateRequest.builder()
                        .stepName("Analyze Data")
                        .stepType(StepType.TOOL_CALL)
                        .build());
        assertCheck(resp2.getDecision() == GateDecision.ALLOW,
                "Same decision allow (got " + resp2.getDecision() + ")");
        assertCheck(resp2.isCached(),
                "Second call IS cached (cached=" + resp2.isCached() + ")");
        assertCheck("cached".equals(resp2.getDecisionSource()),
                "Decision source is cached (got " + resp2.getDecisionSource() + ")");
        System.out.println();

        // Test 4: Same step with retry_policy=reevaluate (fresh)
        System.out.println("Test 4: Same Step with retry_policy=reevaluate");
        System.out.println("-".repeat(30));

        StepGateResponse resp3 = client.stepGate(wf.getWorkflowId(), "step-analyze",
                StepGateRequest.builder()
                        .stepName("Analyze Data")
                        .stepType(StepType.TOOL_CALL)
                        .retryPolicy("reevaluate")
                        .build());
        assertCheck(resp3.getDecision() == GateDecision.ALLOW,
                "Decision is allow (got " + resp3.getDecision() + ")");
        assertCheck(!resp3.isCached(),
                "Reevaluate is NOT cached (cached=" + resp3.isCached() + ")");
        assertCheck("fresh".equals(resp3.getDecisionSource()),
                "Decision source is fresh (got " + resp3.getDecisionSource() + ")");
        System.out.println();

        // Test 5: Different step (independent)
        System.out.println("Test 5: Different Step (independent evaluation)");
        System.out.println("-".repeat(30));

        StepGateResponse resp4 = client.stepGate(wf.getWorkflowId(), "step-summarize",
                StepGateRequest.builder()
                        .stepName("Summarize Results")
                        .stepType(StepType.LLM_CALL)
                        .model("gpt-4")
                        .provider("openai")
                        .build());
        assertCheck(!resp4.isCached(),
                "New step is NOT cached (cached=" + resp4.isCached() + ")");
        assertCheck("fresh".equals(resp4.getDecisionSource()),
                "Decision source is fresh (got " + resp4.getDecisionSource() + ")");
        System.out.println();

        // Test 6: Complete workflow
        System.out.println("Test 6: Complete Workflow");
        System.out.println("-".repeat(30));

        client.completeWorkflow(wf.getWorkflowId());
        assertCheck(true, "Workflow completed");
        System.out.println();

        // Summary
        System.out.println("=".repeat(50));
        System.out.printf("Results: %d passed, %d failed%n", passCount, failCount);
        if (failCount > 0) {
            System.out.println("FAILED");
            System.exit(1);
        }
        System.out.println("ALL PASSED");
    }
}
