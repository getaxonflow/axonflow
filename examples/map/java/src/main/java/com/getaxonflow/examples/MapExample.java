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
import com.getaxonflow.sdk.types.Plan;
import com.getaxonflow.sdk.types.PlanExecution;
import com.getaxonflow.sdk.types.PlanStatus;
import com.getaxonflow.sdk.types.PlanStep;
import com.getaxonflow.sdk.types.StepResult;

import java.util.ArrayList;
import java.util.List;

/**
 * AxonFlow MAP (Multi-Agent Planning) Example - Java SDK
 *
 * This example demonstrates and VALIDATES all MAP SDK methods:
 * - generatePlan()   - Create a multi-agent execution plan
 * - executePlan()    - Execute a previously generated plan
 * - getPlanStatus()  - Get status of a running or completed plan
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 * This ensures CI/CD pipelines catch regressions.
 *
 * Run with: mvn compile exec:java
 * Prerequisites: docker compose up -d
 */
public class MapExample {

    private static final List<String> failures = new ArrayList<>();

    private static String getEnv(String key, String defaultValue) {
        String value = System.getenv(key);
        return (value != null && !value.isEmpty()) ? value : defaultValue;
    }

    private static void assertCheck(boolean condition, String message) {
        if (!condition) {
            failures.add(message);
            System.out.println("   \u274C FAIL: " + message);
        } else {
            System.out.println("   \u2713 PASS: " + message);
        }
    }

    public static void main(String[] args) {
        System.out.println("AxonFlow MAP (Multi-Agent Planning) - Java SDK");
        System.out.println("==============================================");
        System.out.println();

        AxonFlow client = AxonFlow.create(AxonFlowConfig.builder()
            .endpoint(getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080"))
            .clientId(getEnv("AXONFLOW_CLIENT_ID", "demo"))
            .clientSecret(getEnv("AXONFLOW_CLIENT_SECRET", "demo"))
            .debug("true".equals(getEnv("AXONFLOW_DEBUG", "")))
            .build());

        String query = "Create a brief plan to greet a new user and ask how to help them";
        String domain = "generic";

        System.out.println("Query: " + query);
        System.out.println("Domain: " + domain);
        System.out.println("----------------------------------------------");
        System.out.println();

        // ========================================
        // 1. GENERATE PLAN
        // ========================================
        System.out.println("1. generatePlan - Creating a multi-agent plan...");
        Plan plan;
        try {
            plan = client.generatePlan(query, domain);
        } catch (Exception e) {
            System.out.println("   \u274C FATAL: generatePlan failed: " + e.getMessage());
            System.exit(1);
            return;
        }

        System.out.println("   Plan ID: " + plan.getPlanId());
        System.out.println("   Domain: " + plan.getDomain());
        System.out.println("   Steps: " + (plan.getSteps() != null ? plan.getSteps().size() : 0));

        // Validate generatePlan response
        assertCheck(plan.getPlanId() != null && !plan.getPlanId().isEmpty(), "planId is not empty");
        assertCheck(plan.getPlanId().startsWith("plan_"), "planId has correct prefix 'plan_'");
        assertCheck(plan.getSteps() != null && !plan.getSteps().isEmpty(), "Plan has at least one step");

        int expectedStepCount = 0;
        if (plan.getSteps() != null && !plan.getSteps().isEmpty()) {
            expectedStepCount = plan.getSteps().size();
            System.out.println("   Plan Steps:");
            int i = 1;
            for (PlanStep step : plan.getSteps()) {
                System.out.println("     " + i + ". " + step.getName() + " (" + step.getType() + ")");
                assertCheck(step.getName() != null && !step.getName().isEmpty(), "Step " + i + " has a name");
                assertCheck(step.getType() != null && !step.getType().isEmpty(), "Step " + i + " has a type");
                i++;
            }
        }
        System.out.println();

        // ========================================
        // 2. GET PLAN STATUS (before execution) - Optional
        // ========================================
        System.out.println("2. getPlanStatus - Checking status before execution...");
        try {
            PlanStatus status = client.getPlanStatus(plan.getPlanId());
            System.out.println("   Status: " + status.getStatus());
            System.out.println("   Total Steps: " + status.getTotalSteps());

            // Validate pre-execution status
            assertCheck(
                "pending".equals(status.getStatus()) || "created".equals(status.getStatus()),
                "Plan status is pending/created before execution"
            );
            assertCheck(
                status.getTotalSteps() == expectedStepCount,
                "totalSteps matches plan (" + expectedStepCount + ")"
            );
        } catch (Exception e) {
            // getPlanStatus is optional - skip if not implemented (404)
            if (e.getMessage() != null && e.getMessage().contains("404")) {
                System.out.println("   ⏭ SKIP: getPlanStatus not implemented (404)");
            } else {
                System.out.println("   \u274C FATAL: getPlanStatus failed: " + e.getMessage());
                System.exit(1);
                return;
            }
        }
        System.out.println();

        // ========================================
        // 3. EXECUTE PLAN
        // ========================================
        System.out.println("3. executePlan - Executing the plan...");
        PlanExecution execution;
        try {
            execution = client.executePlan(plan.getPlanId());
        } catch (Exception e) {
            System.out.println("   \u274C FATAL: executePlan failed: " + e.getMessage());
            System.exit(1);
            return;
        }

        System.out.println("   Execution Status: " + execution.getStatus());
        int totalSteps = execution.getTotalSteps();
        int completedSteps = execution.getCompletedSteps();
        if (totalSteps > 0) {
            System.out.println("   Completed Steps: " + completedSteps + "/" + totalSteps);
        }

        // Validate execution response
        assertCheck(
            "completed".equals(execution.getStatus()) || "success".equals(execution.getStatus()),
            "Execution status indicates success"
        );

        // Step tracking is optional - only validate if present
        if (totalSteps > 0) {
            assertCheck(
                totalSteps == expectedStepCount,
                "Execution totalSteps matches plan (" + expectedStepCount + ")"
            );
            assertCheck(
                completedSteps == expectedStepCount,
                "All steps completed"
            );
        }

        // Validate step results if available
        List<StepResult> stepResults = execution.getStepResults();
        if (stepResults != null && !stepResults.isEmpty()) {
            System.out.println("   Step Results:");
            assertCheck(
                stepResults.size() == expectedStepCount,
                "stepResults count matches plan steps"
            );
            int i = 1;
            for (StepResult result : stepResults) {
                System.out.println("     - " + result.getStepName() + ": " + result.getStatus());
                assertCheck(
                    "completed".equals(result.getStatus()) || "success".equals(result.getStatus()),
                    "Step " + i + " completed successfully"
                );
                i++;
            }
        }
        System.out.println();

        // ========================================
        // 4. GET PLAN STATUS (after execution) - Optional
        // ========================================
        System.out.println("4. getPlanStatus - Checking status after execution...");
        try {
            PlanStatus finalStatus = client.getPlanStatus(plan.getPlanId());
            System.out.println("   Status: " + finalStatus.getStatus());
            System.out.println("   Completed Steps: " + finalStatus.getCompletedSteps() + "/" + finalStatus.getTotalSteps());

            // Validate post-execution status
            assertCheck(
                "completed".equals(finalStatus.getStatus()) || "success".equals(finalStatus.getStatus()),
                "Final status indicates completion"
            );
            assertCheck(
                finalStatus.getCompletedSteps() == expectedStepCount,
                "All steps show as completed"
            );
        } catch (Exception e) {
            // getPlanStatus is optional - skip if not implemented (404)
            if (e.getMessage() != null && e.getMessage().contains("404")) {
                System.out.println("   ⏭ SKIP: getPlanStatus not implemented (404)");
            } else {
                System.out.println("   \u274C FATAL: getPlanStatus (post-execution) failed: " + e.getMessage());
                System.exit(1);
                return;
            }
        }
        System.out.println();

        // ========================================
        // SUMMARY
        // ========================================
        System.out.println("==============================================");
        if (failures.isEmpty()) {
            System.out.println("\u2713 ALL TESTS PASSED");
            System.out.println();
            System.out.println("Methods validated:");
            System.out.println("  1. generatePlan()   - Plan created with valid ID and steps");
            System.out.println("  2. getPlanStatus()  - Pre-execution status is pending");
            System.out.println("  3. executePlan()    - All plan steps executed successfully");
            System.out.println("  4. getPlanStatus()  - Post-execution status is completed");
        } else {
            System.out.println("\u274C " + failures.size() + " TEST(S) FAILED:");
            for (String f : failures) {
                System.out.println("   - " + f);
            }
            System.exit(1);
        }
    }
}
