/*
 * Example 6: Multi-Step Approval Workflow - Java
 *
 * Demonstrates a multi-level approval chain: Manager → Director → Finance
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 */
package com.getaxonflow.examples;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.ClientRequest;
import com.getaxonflow.sdk.types.ClientResponse;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class Main {

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
        String agentUrl = Optional.ofNullable(System.getenv("AXONFLOW_AGENT_URL"))
                .orElse("http://localhost:8080");
        String clientId = System.getenv("AXONFLOW_CLIENT_ID");
        String clientSecret = System.getenv("AXONFLOW_CLIENT_SECRET");

        if (clientId == null || clientId.isEmpty() || clientSecret == null || clientSecret.isEmpty()) {
            System.err.println("❌ AXONFLOW_CLIENT_ID and AXONFLOW_CLIENT_SECRET must be set");
            System.exit(1);
        }

        AxonFlow client = AxonFlow.create(AxonFlowConfig.builder()
                .endpoint(agentUrl)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .build());

        System.out.println("✅ Connected to AxonFlow");
        System.out.println("🔐 Starting multi-step approval workflow for capital expenditure...");
        System.out.println();

        // Purchase request details
        double amount = 15000.00;
        String item = "10 Dell PowerEdge R750 servers for production deployment";
        int approvalsObtained = 0;

        try {
            // Step 1: Manager Approval
            System.out.printf("📤 Step 1: Requesting Manager approval for $%.2f purchase...%n", amount);
            String managerQuery = String.format(
                    "As a manager, would you approve a purchase request for $%.2f to buy: %s? " +
                    "Consider budget, necessity, and timing. Respond with APPROVED or REJECTED and brief reasoning.",
                    amount, item
            );

            ClientResponse managerResp = client.proxyLLMCall(
                    ClientRequest.builder()
                            .userToken("user-123")
                            .query(managerQuery)
                            .clientId(clientId)
                            .model("gpt-3.5-turbo")
                            .llmProvider("openai")
                            .context(Map.of("workflow", "approval-manager"))
                            .build()
            );

            String managerResult = "";
            if (managerResp.isBlocked()) {
                System.out.println("❌ Manager step was blocked: " + managerResp.getBlockReason());
                managerResult = "BLOCKED";
            } else {
                System.out.println("📥 Manager Response: " + managerResp.getData());
                managerResult = String.valueOf(managerResp.getData());
            }

            // Manager assertions
            System.out.println();
            System.out.println("=== Manager Step Assertions ===");
            assertCheck(managerResp != null, "Manager response is not null");
            assertCheck(!managerResult.isEmpty(), "Manager response is not empty");

            if (!managerResult.contains("APPROVED") && !managerResult.equals("BLOCKED")) {
                System.out.println("❌ Purchase rejected at manager level");
                System.out.println("Workflow terminated");

                System.out.println();
                System.out.println("=== Early Exit Assertions ===");
                assertCheck(managerResult.contains("REJECTED") || managerResult.contains("APPROVED"),
                        "Manager gave clear APPROVED or REJECTED response");

                if (!failures.isEmpty()) {
                    System.err.println();
                    System.err.println("❌ " + failures.size() + " assertion(s) failed:");
                    for (String failure : failures) {
                        System.err.println("   - " + failure);
                    }
                    System.exit(1);
                }
                return;
            }

            if (managerResult.contains("APPROVED")) {
                approvalsObtained++;
                System.out.println("✅ Manager approval granted");
            }
            System.out.println();

            // Step 2: Director Approval (for amounts > $10K)
            if (amount > 10000) {
                System.out.println("📤 Step 2: Escalating to Director for amounts > $10,000...");
                String directorQuery = String.format(
                        "As a Director, review this approved purchase: $%.2f for %s. " +
                        "Manager approved with reasoning: '%s'. " +
                        "Consider strategic alignment and ROI. Respond with APPROVED or REJECTED and reasoning.",
                        amount, item, managerResult.substring(0, Math.min(100, managerResult.length()))
                );

                ClientResponse directorResp = client.proxyLLMCall(
                        ClientRequest.builder()
                                .userToken("user-123")
                                .query(directorQuery)
                                .clientId(clientId)
                                .model("gpt-3.5-turbo")
                                .llmProvider("openai")
                                .context(Map.of("workflow", "approval-director"))
                                .build()
                );

                String directorResult = "";
                if (directorResp.isBlocked()) {
                    System.out.println("❌ Director step was blocked: " + directorResp.getBlockReason());
                    directorResult = "BLOCKED";
                } else {
                    System.out.println("📥 Director Response: " + directorResp.getData());
                    directorResult = String.valueOf(directorResp.getData());
                }

                // Director assertions
                System.out.println();
                System.out.println("=== Director Step Assertions ===");
                assertCheck(directorResp != null, "Director response is not null");
                assertCheck(!directorResult.isEmpty(), "Director response is not empty");

                if (!directorResult.contains("APPROVED") && !directorResult.equals("BLOCKED")) {
                    System.out.println("❌ Purchase rejected at director level");
                    System.out.println("Workflow terminated");

                    System.out.println();
                    System.out.println("=== Early Exit Assertions ===");
                    assertCheck(approvalsObtained >= 1, "At least manager approval was obtained");

                    if (!failures.isEmpty()) {
                        System.err.println();
                        System.err.println("❌ " + failures.size() + " assertion(s) failed:");
                        for (String failure : failures) {
                            System.err.println("   - " + failure);
                        }
                        System.exit(1);
                    }
                    return;
                }

                if (directorResult.contains("APPROVED")) {
                    approvalsObtained++;
                    System.out.println("✅ Director approval granted");
                }
                System.out.println();
            } else {
                System.out.println("ℹ️  Step 2: Director approval skipped (amount < $10,000)");
                System.out.println();
            }

            // Step 3: Finance Approval (for amounts > $5K)
            if (amount > 5000) {
                System.out.println("📤 Step 3: Final Finance team compliance check...");
                String financeQuery = String.format(
                        "As Finance team, perform final compliance check on approved purchase: $%.2f for %s. " +
                        "Verify budget availability and compliance with procurement policies. Respond with APPROVED or REJECTED and reasoning.",
                        amount, item
                );

                ClientResponse financeResp = client.proxyLLMCall(
                        ClientRequest.builder()
                                .userToken("user-123")
                                .query(financeQuery)
                                .clientId(clientId)
                                .model("gpt-3.5-turbo")
                                .llmProvider("openai")
                                .context(Map.of("workflow", "approval-finance"))
                                .build()
                );

                String financeResult = "";
                if (financeResp.isBlocked()) {
                    System.out.println("❌ Finance step was blocked: " + financeResp.getBlockReason());
                    financeResult = "BLOCKED";
                } else {
                    System.out.println("📥 Finance Response: " + financeResp.getData());
                    financeResult = String.valueOf(financeResp.getData());
                }

                // Finance assertions
                System.out.println();
                System.out.println("=== Finance Step Assertions ===");
                assertCheck(financeResp != null, "Finance response is not null");
                assertCheck(!financeResult.isEmpty(), "Finance response is not empty");

                if (!financeResult.contains("APPROVED") && !financeResult.equals("BLOCKED")) {
                    System.out.println("❌ Purchase rejected at finance level");
                    System.out.println("Workflow terminated");

                    System.out.println();
                    System.out.println("=== Early Exit Assertions ===");
                    assertCheck(approvalsObtained >= 2, "At least manager and director approvals were obtained");

                    if (!failures.isEmpty()) {
                        System.err.println();
                        System.err.println("❌ " + failures.size() + " assertion(s) failed:");
                        for (String failure : failures) {
                            System.err.println("   - " + failure);
                        }
                        System.exit(1);
                    }
                    return;
                }

                if (financeResult.contains("APPROVED")) {
                    approvalsObtained++;
                    System.out.println("✅ Finance approval granted");
                }
                System.out.println();
            }

            // All approvals obtained
            System.out.println("============================================================");
            System.out.println("🎉 Purchase Request FULLY APPROVED");
            System.out.println("============================================================");
            System.out.printf("Amount: $%.2f%n", amount);
            System.out.println("Item: " + item);
            System.out.println("Approvals: Manager ✅ Director ✅ Finance ✅");
            System.out.println();

            // Final assertions
            System.out.println("=== Final Assertions ===");
            assertCheck(approvalsObtained >= 2, "At least 2 approvals obtained");
            assertCheck(amount > 10000, "Amount triggered director approval requirement");
            assertCheck(amount > 5000, "Amount triggered finance approval requirement");

            System.out.println();
            System.out.println("✅ Workflow completed - Purchase can proceed");
            System.out.println("💡 Multi-step approval: Manager → Director → Finance");
        } catch (Exception e) {
            System.err.println("❌ Approval workflow failed: " + e.getMessage());
            failures.add("Approval workflow execution failed: " + e.getMessage());
        }

        // Exit with failure if any assertions failed
        if (!failures.isEmpty()) {
            System.err.println();
            System.err.println("❌ " + failures.size() + " assertion(s) failed:");
            for (String failure : failures) {
                System.err.println("   - " + failure);
            }
            System.exit(1);
        }
    }
}
