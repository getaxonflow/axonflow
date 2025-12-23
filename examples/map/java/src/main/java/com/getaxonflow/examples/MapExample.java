package com.getaxonflow.examples;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.PlanRequest;
import com.getaxonflow.sdk.PlanResponse;
import com.getaxonflow.sdk.PlanStep;

/**
 * AxonFlow MAP (Multi-Agent Planning) Example - Java SDK
 */
public class MapExample {
    public static void main(String[] args) {
        System.out.println("AxonFlow MAP Example - Java");
        System.out.println("==================================================");
        System.out.println();

        // Initialize client - uses environment variables or defaults for self-hosted
        String agentUrl = System.getenv("AXONFLOW_AGENT_URL");
        if (agentUrl == null || agentUrl.isEmpty()) {
            agentUrl = "http://localhost:8080";
        }
        String clientId = System.getenv("AXONFLOW_CLIENT_ID");
        if (clientId == null || clientId.isEmpty()) {
            clientId = "demo";
        }
        String clientSecret = System.getenv("AXONFLOW_CLIENT_SECRET");
        if (clientSecret == null || clientSecret.isEmpty()) {
            clientSecret = "demo";
        }

        AxonFlowConfig config = AxonFlowConfig.builder()
            .agentUrl(agentUrl)
            .clientId(clientId)
            .clientSecret(clientSecret)
            .debug(true)
            .build();

        try (AxonFlow client = new AxonFlow(config)) {
            // Simple query for testing
            String query = "Create a brief plan to greet a new user and ask how to help them";
            String domain = "generic";

            System.out.println("Query: " + query);
            System.out.println("Domain: " + domain);
            System.out.println("--------------------------------------------------");
            System.out.println();

            // Generate a plan
            PlanRequest request = PlanRequest.builder()
                .objective(query)
                .domain(domain)
                .build();

            PlanResponse plan = client.generatePlan(request);

            System.out.println("✅ Plan Generated Successfully");
            System.out.println("Plan ID: " + plan.getPlanId());
            System.out.println("Steps: " + (plan.getSteps() != null ? plan.getSteps().size() : 0));

            if (plan.getSteps() != null) {
                int i = 1;
                for (PlanStep step : plan.getSteps()) {
                    System.out.println("  " + i + ". " + step.getName() + " (" + step.getType() + ")");
                    i++;
                }
            }

            if (plan.getResult() != null && !plan.getResult().isEmpty()) {
                System.out.println();
                System.out.println("Result Preview:");
                String preview = plan.getResult();
                if (preview.length() > 500) {
                    preview = preview.substring(0, 500) + "...";
                }
                System.out.println(preview);
            }

            System.out.println();
            System.out.println("==================================================");
            System.out.println("✅ Java MAP Test: PASS");

        } catch (Exception e) {
            System.err.println("❌ Error: " + e.getMessage());
            e.printStackTrace();
            System.out.println();
            System.out.println("==================================================");
            System.out.println("❌ Java MAP Test: FAIL");
            System.exit(1);
        }
    }
}
