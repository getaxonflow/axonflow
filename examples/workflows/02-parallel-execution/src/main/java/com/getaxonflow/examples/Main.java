/*
 * Example 2: Parallel Execution Workflow - Java
 *
 * Demonstrates how AxonFlow MAP (Multi-Agent Plan) automatically parallelizes independent tasks.
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

        // Complex query that benefits from parallelization
        String query = "Plan a 3-day trip to Paris including: (1) round-trip flights from New York, " +
                "(2) hotel recommendations in the city center, and (3) top 5 tourist attractions to visit";

        System.out.println("📤 Planning trip to Paris...");
        System.out.println("🔄 MAP will detect independent tasks and execute them in parallel");

        long startTime = System.currentTimeMillis();

        try {
            // Send query to AxonFlow (uses MAP for parallelization)
            ClientResponse response = client.proxyLLMCall(
                    ClientRequest.builder()
                            .userToken("user-123")
                            .query(query)
                            .clientId(clientId)
                            .model("gpt-3.5-turbo")
                            .llmProvider("openai")
                            .context(Map.of("workflow", "parallel-execution"))
                            .build()
            );

            double duration = (System.currentTimeMillis() - startTime) / 1000.0;

            System.out.printf("⏱️  Parallel execution completed in %.1fs%n", duration);

            // Check if blocked
            if (response.isBlocked()) {
                System.out.println("📥 Response: BLOCKED - " + response.getBlockReason());
            } else {
                System.out.println("📥 Trip Plan:");
                System.out.println(response.getData());
            }
            System.out.println();

            // Assertions
            System.out.println("=== Assertions ===");
            assertCheck(response != null, "Response is not null");
            assertCheck(response.isSuccess() || response.isBlocked(), "Response has valid status");

            if (!response.isBlocked()) {
                assertCheck(response.getData() != null, "Response data is not null");
                String resultStr = String.valueOf(response.getData());
                assertCheck(!resultStr.isEmpty(), "Response result is not empty");
                assertCheck(resultStr.length() > 50, "Response has substantial content (length > 50)");
            }
            assertCheck(duration > 0, "Execution time was recorded");

            System.out.println();
            System.out.println("✅ Workflow completed successfully");
            System.out.println("💡 Tip: MAP automatically parallelized the flight, hotel, and attractions search");
        } catch (Exception e) {
            System.err.println("❌ Query failed: " + e.getMessage());
            failures.add("Query execution failed: " + e.getMessage());
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
