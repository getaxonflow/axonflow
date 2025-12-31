/*
 * Example 2: Parallel Execution Workflow - Java
 *
 * Demonstrates how AxonFlow MAP (Multi-Agent Plan) automatically parallelizes independent tasks.
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

        // Complex query that benefits from parallelization
        String query = "Plan a 3-day trip to Paris including: (1) round-trip flights from New York, " +
                "(2) hotel recommendations in the city center, and (3) top 5 tourist attractions to visit";

        System.out.println("📤 Planning trip to Paris...");
        System.out.println("🔄 MAP will detect independent tasks and execute them in parallel");

        long startTime = System.currentTimeMillis();

        try {
            // Send query to AxonFlow (uses MAP for parallelization)
            ExecuteResponse response = client.executeQuery(
                    ExecuteQueryRequest.builder()
                            .userToken("user-123")
                            .query(query)
                            .requestType("multi-agent-plan")  // Use MAP for parallel execution
                            .context(Map.of("model", "gpt-4"))
                            .build()
            );

            double duration = (System.currentTimeMillis() - startTime) / 1000.0;

            System.out.printf("⏱️  Parallel execution completed in %.1fs%n", duration);
            System.out.println("📥 Trip Plan:");
            System.out.println(response.getResult());
            System.out.println();
            System.out.println("✅ Workflow completed successfully");
            System.out.println("💡 Tip: MAP automatically parallelized the flight, hotel, and attractions search");
        } catch (Exception e) {
            System.err.println("❌ Query failed: " + e.getMessage());
            System.exit(1);
        }
    }
}
