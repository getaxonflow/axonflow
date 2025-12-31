/*
 * Example 6: Multi-Step Approval Workflow - Java
 *
 * Demonstrates a multi-level approval chain: Manager → Director → Finance
 */
package com.getaxonflow.examples;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.ExecuteQueryRequest;
import com.getaxonflow.sdk.types.ExecuteResponse;

import java.util.Map;
import java.util.Optional;

public class Main {

    public static void main(String[] args) {
        String agentUrl = Optional.ofNullable(System.getenv("AXONFLOW_AGENT_URL"))
                .orElse("http://localhost:8080");
        String licenseKey = System.getenv("AXONFLOW_LICENSE_KEY");

        if (licenseKey == null || licenseKey.isEmpty()) {
            System.err.println("❌ AXONFLOW_LICENSE_KEY must be set");
            System.exit(1);
        }

        AxonFlowConfig config = AxonFlowConfig.builder()
                .agentUrl(agentUrl)
                .licenseKey(licenseKey)
                .build();

        AxonFlow client = new AxonFlow(config);

        System.out.println("✅ Connected to AxonFlow");
        System.out.println("🔐 Starting multi-step approval workflow for capital expenditure...");
        System.out.println();

        // Purchase request details
        double amount = 15000.00;
        String item = "10 Dell PowerEdge R750 servers for production deployment";

        try {
            // Step 1: Manager Approval
            System.out.printf("📤 Step 1: Requesting Manager approval for $%.2f purchase...%n", amount);
            String managerQuery = String.format(
                    "As a manager, would you approve a purchase request for $%.2f to buy: %s? " +
                    "Consider budget, necessity, and timing. Respond with APPROVED or REJECTED and brief reasoning.",
                    amount, item
            );

            ExecuteResponse managerResp = client.executeQuery(
                    ExecuteQueryRequest.builder()
                            .userToken("user-123")
                            .query(managerQuery)
                            .requestType("chat")
                            .context(Map.of("model", "gpt-4"))
                            .build()
            );

            System.out.println("📥 Manager Response: " + managerResp.getData());

            String managerResult = String.valueOf(managerResp.getData());
            if (!managerResult.contains("APPROVED")) {
                System.out.println("❌ Purchase rejected at manager level");
                System.out.println("Workflow terminated");
                return;
            }

            System.out.println("✅ Manager approval granted");
            System.out.println();

            // Step 2: Director Approval (for amounts > $10K)
            if (amount > 10000) {
                System.out.println("📤 Step 2: Escalating to Director for amounts > $10,000...");
                String directorQuery = String.format(
                        "As a Director, review this approved purchase: $%.2f for %s. " +
                        "Manager approved with reasoning: '%s'. " +
                        "Consider strategic alignment and ROI. Respond with APPROVED or REJECTED and reasoning.",
                        amount, item, managerResp.getData()
                );

                ExecuteResponse directorResp = client.executeQuery(
                        ExecuteQueryRequest.builder()
                                .userToken("user-123")
                                .query(directorQuery)
                                .requestType("chat")
                                .context(Map.of("model", "gpt-4"))
                                .build()
                );

                System.out.println("📥 Director Response: " + directorResp.getData());

                String directorResult = String.valueOf(directorResp.getData());
                if (!directorResult.contains("APPROVED")) {
                    System.out.println("❌ Purchase rejected at director level");
                    System.out.println("Workflow terminated");
                    return;
                }

                System.out.println("✅ Director approval granted");
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

                ExecuteResponse financeResp = client.executeQuery(
                        ExecuteQueryRequest.builder()
                                .userToken("user-123")
                                .query(financeQuery)
                                .requestType("chat")
                                .context(Map.of("model", "gpt-4"))
                                .build()
                );

                System.out.println("📥 Finance Response: " + financeResp.getData());

                String financeResult = String.valueOf(financeResp.getData());
                if (!financeResult.contains("APPROVED")) {
                    System.out.println("❌ Purchase rejected at finance level");
                    System.out.println("Workflow terminated");
                    return;
                }

                System.out.println("✅ Finance approval granted");
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
            System.out.println("✅ Workflow completed - Purchase can proceed");
            System.out.println("💡 Multi-step approval: Manager → Director → Finance");
        } catch (Exception e) {
            System.err.println("❌ Approval workflow failed: " + e.getMessage());
            System.exit(1);
        }
    }
}
