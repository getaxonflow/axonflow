/*
 * AxonFlow MAP Confirm Mode Example - Java SDK (Enterprise Only)
 *
 * Demonstrates the confirm execution mode where every step
 * requires explicit approval before execution.
 *
 * REQUIRES: Enterprise license
 *
 * Flow:
 *  1. Generate plan with executionMode=CONFIRM
 *  2. Execute plan -> returns "awaiting_approval"
 *  3. Resume plan (approve step) -> executes step, pauses at next
 *  4. Repeat until all steps complete
 *
 * Run with: mvn compile exec:java
 * Prerequisites: docker compose up -d (enterprise mode)
 */
package com.getaxonflow.examples;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.ExecutionMode;
import com.getaxonflow.sdk.types.GeneratePlanOptions;
import com.getaxonflow.sdk.types.PlanRequest;
import com.getaxonflow.sdk.types.PlanResponse;
import com.getaxonflow.sdk.types.ResumePlanResponse;

import java.util.ArrayList;
import java.util.List;

public class MapConfirmModeExample {

    private static final List<String> failures = new ArrayList<>();
    private static int testsRun = 0;

    private static String getEnv(String key, String defaultValue) {
        String value = System.getenv(key);
        return (value != null && !value.isEmpty()) ? value : defaultValue;
    }

    private static void assertCheck(boolean condition, String message) {
        testsRun++;
        if (!condition) {
            failures.add(message);
            System.out.println("   FAIL: " + message);
        } else {
            System.out.println("   PASS: " + message);
        }
    }

    public static void main(String[] args) {
        System.out.println("AxonFlow MAP Confirm Mode - Java SDK (Enterprise)");
        System.out.println("==================================================");
        System.out.println();

        AxonFlow client = AxonFlow.create(AxonFlowConfig.builder()
            .endpoint(getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080"))
            .clientId(getEnv("AXONFLOW_CLIENT_ID", "demo-org"))
            .clientSecret(getEnv("AXONFLOW_CLIENT_SECRET", "demo"))
            .debug("true".equals(getEnv("AXONFLOW_DEBUG", "")))
            .build());

        String userToken = getEnv("AXONFLOW_USER_TOKEN", "map-confirm-user");
        String domain = "travel";

        // ========================================
        // 1. GENERATE PLAN WITH CONFIRM MODE
        // ========================================
        System.out.println("1. generatePlan - Confirm mode...");
        PlanResponse plan;
        try {
            plan = client.generatePlan(
                PlanRequest.builder()
                    .objective("Search flights, analyze options, and book the best one")
                    .domain(domain)
                    .userToken(userToken)
                    .build(),
                GeneratePlanOptions.builder()
                    .executionMode(ExecutionMode.CONFIRM)
                    .build()
            );
        } catch (Exception e) {
            String errMsg = e.getMessage() != null ? e.getMessage().toLowerCase() : "";
            if (errMsg.contains("enterprise") || errMsg.contains("403") || errMsg.contains("license")) {
                System.out.println("   SKIP: Confirm mode requires enterprise license: " + e.getMessage());
                System.out.println();
                System.out.println("==================================================");
                System.out.println("Skipped - enterprise license required");
                return;
            }
            System.out.println("   FATAL: generatePlan failed: " + e.getMessage());
            System.exit(1);
            return;
        }

        System.out.println("   Plan ID: " + plan.getPlanId());
        System.out.println("   Steps: " + plan.getStepCount());

        assertCheck(plan.getPlanId() != null && !plan.getPlanId().isEmpty(), "Confirm mode plan generated");
        assertCheck(plan.getSteps() != null && !plan.getSteps().isEmpty(), "Plan has steps");
        System.out.println();

        // ========================================
        // 2. EXECUTE PLAN (should return awaiting_approval)
        // ========================================
        System.out.println("2. executePlan - Should return awaiting_approval...");
        PlanResponse execution;
        try {
            execution = client.executePlan(plan.getPlanId(), userToken);
        } catch (Exception e) {
            System.out.println("   FATAL: executePlan failed: " + e.getMessage());
            System.exit(1);
            return;
        }

        assertCheck("awaiting_approval".equals(execution.getStatus()),
            "Status is awaiting_approval (" + execution.getStatus() + ")");
        System.out.println();

        // ========================================
        // 3-N. RESUME LOOP (approve each step)
        // ========================================
        int totalSteps = plan.getSteps() != null ? plan.getSteps().size() : 3;
        for (int step = 1; step <= totalSteps; step++) {
            System.out.println((step + 2) + ". resumePlan - Approve step " + step + "...");

            ResumePlanResponse resumeResp;
            try {
                resumeResp = client.resumePlan(plan.getPlanId(), true);
            } catch (Exception e) {
                System.out.println("   FATAL: resumePlan failed: " + e.getMessage());
                System.exit(1);
                return;
            }

            System.out.println("   Status: " + resumeResp.getStatus());

            if ("completed".equals(resumeResp.getStatus())) {
                assertCheck(true, "Plan completed after step " + step);
                System.out.println();
                break;
            } else if ("awaiting_approval".equals(resumeResp.getStatus())) {
                assertCheck(true, "Step " + step + " approved, paused at next step");
            } else {
                assertCheck(false, "Unexpected status after resume: " + resumeResp.getStatus());
            }
            System.out.println();
        }

        // ========================================
        // FINAL STATUS CHECK
        // ========================================
        System.out.println("Final Status Check...");
        try {
            PlanResponse finalStatus = client.getPlanStatus(plan.getPlanId());
            assertCheck(
                "completed".equals(finalStatus.getStatus()) || "success".equals(finalStatus.getStatus()),
                "Final status is completed (" + finalStatus.getStatus() + ")"
            );
        } catch (Exception e) {
            if (e.getMessage() != null && e.getMessage().contains("404")) {
                System.out.println("   SKIP: getPlanStatus not implemented (404)");
            } else {
                System.out.println("   FATAL: getPlanStatus failed: " + e.getMessage());
                System.exit(1);
                return;
            }
        }
        System.out.println();

        // ========================================
        // SUMMARY
        // ========================================
        System.out.println("==================================================");
        System.out.println("Tests Run: " + testsRun);
        if (failures.isEmpty()) {
            System.out.println("ALL TESTS PASSED");
            System.out.println();
            System.out.println("Confirm mode flow:");
            System.out.println("  1. generatePlan (confirm)");
            System.out.println("  2. executePlan -> awaiting_approval");
            System.out.println("  3. resumePlan (approve) x N steps");
            System.out.println("  4. getPlanStatus -> completed");
        } else {
            System.out.println(failures.size() + " TEST(S) FAILED:");
            for (String f : failures) {
                System.out.println("   - " + f);
            }
            System.exit(1);
        }
    }
}
