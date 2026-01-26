/*
 * Example 3: Conditional Logic Workflow - Java
 *
 * Demonstrates if/else branching based on API responses.
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

        // Step 1: Search for flights
        String searchQuery = "Find round-trip flights from New York to Paris for next week";
        System.out.println("📤 Searching for flights to Paris...");

        int stepCount = 0;

        try {
            ClientResponse searchResponse = client.proxyLLMCall(
                    ClientRequest.builder()
                            .userToken("user-123")
                            .query(searchQuery)
                            .clientId(clientId)
                            .model("gpt-3.5-turbo")
                            .llmProvider("openai")
                            .context(Map.of("workflow", "conditional-logic"))
                            .build()
            );

            stepCount++;
            System.out.println("✅ Received search results");

            // Assertions for Step 1
            System.out.println();
            System.out.println("=== Step 1 Assertions ===");
            assertCheck(searchResponse != null, "Search response is not null");
            assertCheck(searchResponse.isSuccess() || searchResponse.isBlocked(), "Search response has valid status");

            if (searchResponse.isBlocked()) {
                System.out.println("❌ Search was blocked: " + searchResponse.getBlockReason());
                failures.add("Search request was blocked");
            } else {
                assertCheck(searchResponse.getData() != null, "Search response data is not null");

                String result = String.valueOf(searchResponse.getData()).toLowerCase();

                // Step 2: Conditional logic based on search results
                if (result.contains("no flights") || result.contains("not available")) {
                    // Fallback path - no flights available
                    System.out.println("⚠️  No flights found for selected dates");
                    System.out.println("💡 Trying alternative dates...");

                    String altQuery = "Find flights from New York to Paris for the following week instead";
                    ClientResponse altResponse = client.proxyLLMCall(
                            ClientRequest.builder()
                                    .userToken("user-123")
                                    .query(altQuery)
                                    .clientId(clientId)
                                    .model("gpt-3.5-turbo")
                                    .llmProvider("openai")
                                    .context(Map.of("workflow", "conditional-logic-fallback"))
                                    .build()
                    );

                    stepCount++;
                    System.out.println("📥 Alternative Options:");
                    System.out.println(altResponse.getData());

                    // Assertions for fallback path
                    System.out.println();
                    System.out.println("=== Fallback Path Assertions ===");
                    assertCheck(altResponse != null, "Alternative response is not null");
                    if (!altResponse.isBlocked()) {
                        assertCheck(altResponse.getData() != null, "Alternative response data is not null");
                    }
                    assertCheck(stepCount >= 2, "At least 2 steps executed (search + fallback)");

                    System.out.println();
                    System.out.println("✅ Workflow completed with fallback");
                } else {
                    // Success path - flights found
                    System.out.println("💡 Flights found! Analyzing best option...");
                    System.out.println(searchResponse.getData());

                    // Step 3: Proceed to booking recommendation
                    String bookQuery = "Based on the search results above, what would be the recommended booking?";
                    System.out.println("\n📤 Getting booking recommendation...");

                    ClientResponse bookResponse = client.proxyLLMCall(
                            ClientRequest.builder()
                                    .userToken("user-123")
                                    .query(bookQuery)
                                    .clientId(clientId)
                                    .model("gpt-3.5-turbo")
                                    .llmProvider("openai")
                                    .context(Map.of("workflow", "conditional-logic-booking"))
                                    .build()
                    );

                    stepCount++;
                    System.out.println("📥 Booking Recommendation:");
                    System.out.println(bookResponse.getData());

                    // Assertions for success path
                    System.out.println();
                    System.out.println("=== Success Path Assertions ===");
                    assertCheck(bookResponse != null, "Booking response is not null");
                    if (!bookResponse.isBlocked()) {
                        assertCheck(bookResponse.getData() != null, "Booking response data is not null");
                    }
                    assertCheck(stepCount >= 2, "At least 2 steps executed (search + booking)");

                    System.out.println();
                    System.out.println("✅ Workflow completed successfully");
                    System.out.println("💡 Tip: This example demonstrates if/else branching based on API responses");
                }
            }
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
