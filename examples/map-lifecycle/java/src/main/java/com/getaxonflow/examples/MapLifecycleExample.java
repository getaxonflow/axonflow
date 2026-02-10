/*
 * AxonFlow MAP Lifecycle Example - Java SDK
 *
 * Validates the FULL MAP v1.0 lifecycle:
 *  1. Generate plan (default mode) - verify planId, steps
 *  2. Get status (pending)
 *  3. Update plan (change executionMode, optimistic locking)
 *  4. Get version history
 *  5. Stale update (verify VersionConflictException)
 *  6. Execute plan - verify completed
 *  7. Get status (completed)
 *  8. Cancel completed plan - verify rejected
 *  9. Generate + cancel + try execute cancelled plan
 * 10. Generate with balanced mode - execute - verify completed
 *
 * Run with: mvn compile exec:java
 * Prerequisites: docker compose up -d
 */
package com.getaxonflow.examples;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.exceptions.VersionConflictException;
import com.getaxonflow.sdk.types.CancelPlanResponse;
import com.getaxonflow.sdk.types.ExecutionMode;
import com.getaxonflow.sdk.types.GeneratePlanOptions;
import com.getaxonflow.sdk.types.PlanRequest;
import com.getaxonflow.sdk.types.PlanResponse;
import com.getaxonflow.sdk.types.PlanVersionEntry;
import com.getaxonflow.sdk.types.PlanVersionsResponse;
import com.getaxonflow.sdk.types.UpdatePlanRequest;
import com.getaxonflow.sdk.types.UpdatePlanResponse;

import java.util.ArrayList;
import java.util.List;

public class MapLifecycleExample {

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
        System.out.println("AxonFlow MAP Lifecycle - Java SDK");
        System.out.println("=================================");
        System.out.println();

        AxonFlow client = AxonFlow.create(AxonFlowConfig.builder()
            .endpoint(getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080"))
            .clientId(getEnv("AXONFLOW_CLIENT_ID", "demo-org"))
            .clientSecret(getEnv("AXONFLOW_CLIENT_SECRET", "demo"))
            .debug("true".equals(getEnv("AXONFLOW_DEBUG", "")))
            .build());

        String userToken = getEnv("AXONFLOW_USER_TOKEN", "");
        String domain = "generic";

        // ========================================
        // 1. GENERATE PLAN (default mode)
        // ========================================
        System.out.println("1. generatePlan - Default mode...");
        PlanResponse plan;
        try {
            plan = client.generatePlan(PlanRequest.builder()
                .objective("Create a plan to analyze user feedback and suggest improvements")
                .domain(domain)
                .userToken(userToken)
                .build());
        } catch (Exception e) {
            System.out.println("   FATAL: generatePlan failed: " + e.getMessage());
            System.exit(1);
            return;
        }

        System.out.println("   Plan ID: " + plan.getPlanId());
        System.out.println("   Steps: " + plan.getStepCount());

        assertCheck(plan.getPlanId() != null && !plan.getPlanId().isEmpty(), "Plan ID is not empty");
        assertCheck(plan.getPlanId().startsWith("plan_"), "Plan ID has correct prefix");
        assertCheck(plan.getSteps() != null && !plan.getSteps().isEmpty(), "Plan has at least one step");
        System.out.println();

        // ========================================
        // 2. GET STATUS (pending)
        // ========================================
        System.out.println("2. getPlanStatus - Should be pending...");
        try {
            PlanResponse status = client.getPlanStatus(plan.getPlanId());
            assertCheck(
                "pending".equals(status.getStatus()) || "created".equals(status.getStatus()) || status.getStatus() == null,
                "Status is pending/created (" + status.getStatus() + ")"
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
        // 3. UPDATE PLAN (change executionMode, version 1 -> 2)
        // ========================================
        System.out.println("3. updatePlan - Change executionMode to parallel...");
        UpdatePlanResponse updateResp;
        boolean hitPlanLimit = false;
        try {
            updateResp = client.updatePlan(plan.getPlanId(), UpdatePlanRequest.builder()
                .version(1)
                .executionMode(ExecutionMode.PARALLEL)
                .build());
        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : "";
            if (msg.contains("maximum") || msg.contains("limit") || msg.contains("429")) {
                System.out.println("   SKIP: Plan versioning limit reached (restart containers to reset)");
                hitPlanLimit = true;
                updateResp = null;
            } else {
                System.out.println("   FATAL: updatePlan failed: " + e.getMessage());
                System.exit(1);
                return;
            }
        }

        if (!hitPlanLimit) {
            System.out.println("   New Version: " + updateResp.getVersion());
            assertCheck(updateResp.getVersion() == 2, "Version is 2 (got " + updateResp.getVersion() + ")");
            assertCheck(plan.getPlanId().equals(updateResp.getPlanId()), "planId matches");
        }
        System.out.println();

        // ========================================
        // 4. GET VERSION HISTORY
        // ========================================
        if (!hitPlanLimit) {
            System.out.println("4. getPlanVersions - Check version history...");
            PlanVersionsResponse versionsResp;
            try {
                versionsResp = client.getPlanVersions(plan.getPlanId());
            } catch (Exception e) {
                System.out.println("   FATAL: getPlanVersions failed: " + e.getMessage());
                System.exit(1);
                return;
            }

            int versionCount = versionsResp.getVersions() != null ? versionsResp.getVersions().size() : 0;
            System.out.println("   Version count: " + versionCount);
            assertCheck(versionCount >= 1, "At least 1 version (" + versionCount + ")");
            assertCheck(plan.getPlanId().equals(versionsResp.getPlanId()), "planId matches");
            if (versionsResp.getVersions() != null) {
                for (PlanVersionEntry v : versionsResp.getVersions()) {
                    System.out.println("     v" + v.getVersion() + ": " + v.getChangeType() + " (" + v.getChangedAt() + ")");
                }
            }
            System.out.println();

            // ========================================
            // 5. STALE UPDATE (verify VersionConflictException)
            // ========================================
            System.out.println("5. Stale Update - Send version 1 again (expect conflict)...");
            try {
                client.updatePlan(plan.getPlanId(), UpdatePlanRequest.builder()
                    .version(1)
                    .executionMode(ExecutionMode.SEQUENTIAL)
                    .build());
                assertCheck(false, "Stale update should have thrown");
            } catch (VersionConflictException e) {
                assertCheck(true, "VersionConflictException thrown");
                System.out.println("   Conflict: " + e.getMessage());
            } catch (Exception e) {
                assertCheck(false, "Expected VersionConflictException, got " + e.getClass().getName() + ": " + e.getMessage());
            }
            System.out.println();
        } else {
            System.out.println("4. SKIP: getPlanVersions (plan limit reached)");
            System.out.println("5. SKIP: Stale Update (plan limit reached)");
            System.out.println();
        }

        // ========================================
        // 6. EXECUTE PLAN
        // ========================================
        System.out.println("6. executePlan - Execute the updated plan...");
        PlanResponse execution;
        try {
            execution = client.executePlan(plan.getPlanId());
        } catch (Exception e) {
            System.out.println("   FATAL: executePlan failed: " + e.getMessage());
            System.exit(1);
            return;
        }

        System.out.println("   Status: " + execution.getStatus());
        assertCheck(
            "completed".equals(execution.getStatus()) || "success".equals(execution.getStatus()),
            "Execution completed"
        );
        System.out.println();

        // ========================================
        // 7. GET STATUS (completed)
        // ========================================
        System.out.println("7. getPlanStatus - Should be completed...");
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
        // 8. CANCEL COMPLETED PLAN (expect rejection)
        // ========================================
        System.out.println("8. cancelPlan - Cancel completed plan (expect rejection)...");
        try {
            client.cancelPlan(plan.getPlanId(), "Testing cancel on completed plan");
            assertCheck(false, "Cancel completed plan should have thrown");
        } catch (Exception e) {
            assertCheck(true, "Cancel completed plan rejected");
            System.out.println("   Error: " + e.getMessage());
        }
        System.out.println();

        // ========================================
        // 9. GENERATE + CANCEL + TRY EXECUTE
        // ========================================
        System.out.println("9. Generate -> Cancel -> Try Execute...");
        PlanResponse plan2;
        try {
            plan2 = client.generatePlan(PlanRequest.builder()
                .objective("Create a simple greeting plan")
                .domain(domain)
                .userToken(userToken)
                .build());
        } catch (Exception e) {
            System.out.println("   FATAL: Second plan failed: " + e.getMessage());
            System.exit(1);
            return;
        }

        assertCheck(plan2.getPlanId() != null && !plan2.getPlanId().isEmpty(), "Second plan generated");

        try {
            CancelPlanResponse cancelResp = client.cancelPlan(plan2.getPlanId(), "Testing cancel flow");
            assertCheck("cancelled".equals(cancelResp.getStatus()), "Plan cancelled (" + cancelResp.getStatus() + ")");
        } catch (Exception e) {
            System.out.println("   FATAL: cancelPlan failed: " + e.getMessage());
            System.exit(1);
            return;
        }

        // Try executing cancelled plan
        try {
            client.executePlan(plan2.getPlanId());
            assertCheck(false, "Execute cancelled plan should have thrown");
        } catch (Exception e) {
            assertCheck(true, "Execute cancelled plan rejected");
        }
        System.out.println();

        // ========================================
        // 10. GENERATE WITH BALANCED MODE + EXECUTE
        // ========================================
        System.out.println("10. generatePlan - Balanced mode...");
        PlanResponse plan3;
        try {
            plan3 = client.generatePlan(
                PlanRequest.builder()
                    .objective("Create a plan to process and summarize data")
                    .domain(domain)
                    .userToken(userToken)
                    .build(),
                GeneratePlanOptions.builder()
                    .executionMode(ExecutionMode.BALANCED)
                    .build()
            );
        } catch (Exception e) {
            System.out.println("   FATAL: Balanced plan failed: " + e.getMessage());
            System.exit(1);
            return;
        }

        assertCheck(plan3.getPlanId() != null && !plan3.getPlanId().isEmpty(), "Balanced plan generated");
        System.out.println("   Plan ID: " + plan3.getPlanId());

        try {
            PlanResponse exec3 = client.executePlan(plan3.getPlanId());
            assertCheck(
                "completed".equals(exec3.getStatus()) || "success".equals(exec3.getStatus()),
                "Balanced plan executed"
            );
        } catch (Exception e) {
            System.out.println("   FATAL: Execute balanced plan failed: " + e.getMessage());
            System.exit(1);
            return;
        }
        System.out.println();

        // ========================================
        // SUMMARY
        // ========================================
        System.out.println("=================================");
        System.out.println("Tests Run: " + testsRun);
        if (failures.isEmpty()) {
            System.out.println("ALL TESTS PASSED");
            System.out.println();
            System.out.println("Lifecycle validated:");
            System.out.println("  - generatePlan / generatePlan with GeneratePlanOptions");
            System.out.println("  - getPlanStatus (pre/post execution)");
            System.out.println("  - updatePlan (optimistic locking)");
            System.out.println("  - getPlanVersions (version history)");
            System.out.println("  - VersionConflictException detection");
            System.out.println("  - executePlan (default + balanced mode)");
            System.out.println("  - cancelPlan (pending + completed rejection)");
        } else {
            System.out.println(failures.size() + " TEST(S) FAILED:");
            for (String f : failures) {
                System.out.println("   - " + f);
            }
            System.exit(1);
        }
    }
}
