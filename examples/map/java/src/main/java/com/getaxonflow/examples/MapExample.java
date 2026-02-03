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
import com.getaxonflow.sdk.types.PlanRequest;
import com.getaxonflow.sdk.types.PlanResponse;
import com.getaxonflow.sdk.types.PlanStep;

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
            .clientId(getEnv("AXONFLOW_CLIENT_ID", "demo-org"))
            .clientSecret(getEnv("AXONFLOW_CLIENT_SECRET", "demo"))
            .debug("true".equals(getEnv("AXONFLOW_DEBUG", "")))
            .build());

        // User token for MAP operations (JWT for local testing with docker-compose)
        String userToken = getEnv("AXONFLOW_USER_TOKEN", "map-example-user");

        String objective = "Create a brief plan to greet a new user and ask how to help them";
        String domain = "generic";

        System.out.println("Objective: " + objective);
        System.out.println("Domain: " + domain);
        if (userToken.length() > 30) {
            System.out.println("User Token: " + userToken.substring(0, 20) + "..." + userToken.substring(userToken.length() - 10));
        }
        System.out.println("----------------------------------------------");
        System.out.println();

        // ========================================
        // 1. GENERATE PLAN
        // ========================================
        System.out.println("1. generatePlan - Creating a multi-agent plan...");
        PlanResponse plan;
        try {
            plan = client.generatePlan(PlanRequest.builder()
                .objective(objective)
                .domain(domain)
                .userToken(userToken)
                .build());
        } catch (Exception e) {
            System.out.println("   \u274C FATAL: generatePlan failed: " + e.getMessage());
            System.exit(1);
            return;
        }

        System.out.println("   Plan ID: " + plan.getPlanId());
        System.out.println("   Domain: " + plan.getDomain());
        System.out.println("   Steps: " + plan.getStepCount());

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
                String stepName = step.getName() != null ? step.getName() : step.getDescription();
                String stepType = step.getType() != null ? step.getType() : "action";
                System.out.println("     " + i + ". " + stepName + " (" + stepType + ")");
                assertCheck(stepName != null && !stepName.isEmpty(), "Step " + i + " has a name/description");
                i++;
            }
        }
        System.out.println();

        // ========================================
        // 2. GET PLAN STATUS (before execution) - Optional
        // ========================================
        System.out.println("2. getPlanStatus - Checking status before execution...");
        try {
            PlanResponse status = client.getPlanStatus(plan.getPlanId());
            System.out.println("   Status: " + status.getStatus());
            System.out.println("   Total Steps: " + status.getStepCount());

            // Validate pre-execution status
            assertCheck(
                status.getStatus() == null || "pending".equals(status.getStatus()) || "created".equals(status.getStatus()),
                "Plan status is pending/created before execution (or null)"
            );
        } catch (Exception e) {
            // getPlanStatus is optional - skip if not implemented (404)
            if (e.getMessage() != null && e.getMessage().contains("404")) {
                System.out.println("   \u23ED SKIP: getPlanStatus not implemented (404)");
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
        PlanResponse execution;
        try {
            execution = client.executePlan(plan.getPlanId());
        } catch (Exception e) {
            System.out.println("   \u274C FATAL: executePlan failed: " + e.getMessage());
            System.exit(1);
            return;
        }

        System.out.println("   Execution Status: " + execution.getStatus());
        if (execution.getResult() != null) {
            System.out.println("   Result: " + truncate(execution.getResult(), 100));
        }

        // Validate execution response
        assertCheck(
            "completed".equals(execution.getStatus()) || "success".equals(execution.getStatus()),
            "Execution status indicates success"
        );
        System.out.println();

        // ========================================
        // 4. GET PLAN STATUS (after execution) - Optional
        // ========================================
        System.out.println("4. getPlanStatus - Checking status after execution...");
        try {
            PlanResponse finalStatus = client.getPlanStatus(plan.getPlanId());
            System.out.println("   Status: " + finalStatus.getStatus());

            // Validate post-execution status
            assertCheck(
                "completed".equals(finalStatus.getStatus()) || "success".equals(finalStatus.getStatus()),
                "Final status indicates completion"
            );
        } catch (Exception e) {
            // getPlanStatus is optional - skip if not implemented (404)
            if (e.getMessage() != null && e.getMessage().contains("404")) {
                System.out.println("   \u23ED SKIP: getPlanStatus not implemented (404)");
            } else {
                System.out.println("   \u274C FATAL: getPlanStatus (post-execution) failed: " + e.getMessage());
                System.exit(1);
                return;
            }
        }
        System.out.println();

        // ========================================
        // 5. PII IN PLAN QUERY - Policy enforcement on plan generation
        // ========================================
        System.out.println("5. PII in Plan Query - Testing policy enforcement on plan with SSN...");
        String piiObjective = "Create a plan to process refund for customer with SSN 123-45-6789";
        String gatewayPiiAction = getEnv("GATEWAY_PII_ACTION", getEnv("PII_ACTION", "redact"));
        System.out.println("   GATEWAY_PII_ACTION=" + gatewayPiiAction);

        PlanResponse piiPlan = null;
        Exception piiErr = null;
        try {
            piiPlan = client.generatePlan(PlanRequest.builder()
                .objective(piiObjective)
                .domain(domain)
                .userToken(userToken)
                .build());
        } catch (Exception e) {
            piiErr = e;
        }

        if ("block".equals(gatewayPiiAction)) {
            if (piiErr != null) {
                assertCheck(true, "PII plan blocked as expected (GATEWAY_PII_ACTION=block)");
                System.out.println("   Block reason: " + piiErr.getMessage());
            } else {
                assertCheck(false, "PII plan should have been blocked (GATEWAY_PII_ACTION=block)");
            }
        } else if ("log".equals(gatewayPiiAction)) {
            if (piiErr != null) {
                System.out.println("   Warning: PII plan failed: " + piiErr.getMessage());
            } else {
                assertCheck(piiPlan.getPlanId() != null && !piiPlan.getPlanId().isEmpty(),
                    "PII plan approved with log-only mode");
                System.out.println("   Plan ID: " + piiPlan.getPlanId() + " (PII logged but not redacted)");
            }
        } else {
            // Default "redact" mode
            if (piiErr != null) {
                System.out.println("   Warning: PII plan failed: " + piiErr.getMessage());
            } else {
                assertCheck(piiPlan.getPlanId() != null && !piiPlan.getPlanId().isEmpty(),
                    "PII plan generated (redaction may apply downstream)");
                System.out.println("   Plan ID: " + piiPlan.getPlanId());
                System.out.println("   Note: PII redaction is applied downstream by the Orchestrator");
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
            System.out.println("  2. getPlanStatus()  - Pre-execution status checked");
            System.out.println("  3. executePlan()    - Plan executed successfully");
            System.out.println("  4. getPlanStatus()  - Post-execution status is completed");
        } else {
            System.out.println("\u274C " + failures.size() + " TEST(S) FAILED:");
            for (String f : failures) {
                System.out.println("   - " + f);
            }
            System.exit(1);
        }
    }

    private static String truncate(String str, int maxLen) {
        if (str == null) return null;
        if (str.length() <= maxLen) {
            return str;
        }
        return str.substring(0, maxLen) + "...";
    }
}
