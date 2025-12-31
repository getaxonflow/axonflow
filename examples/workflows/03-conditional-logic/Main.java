/*
 * Example 3: Conditional Logic Workflow - Java
 *
 * Demonstrates if/else branching based on API responses.
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

        // Step 1: Search for flights
        String searchQuery = "Find round-trip flights from New York to Paris for next week";
        System.out.println("📤 Searching for flights to Paris...");

        try {
            ExecuteResponse searchResponse = client.executeQuery(
                    ExecuteQueryRequest.builder()
                            .userToken("user-123")
                            .query(searchQuery)
                            .requestType("chat")
                            .context(Map.of("model", "gpt-4"))
                            .build()
            );

            System.out.println("✅ Received search results");

            String result = String.valueOf(searchResponse.getData()).toLowerCase();

            // Step 2: Conditional logic based on search results
            if (result.contains("no flights") || result.contains("not available")) {
                // Fallback path - no flights available
                System.out.println("⚠️  No flights found for selected dates");
                System.out.println("💡 Trying alternative dates...");

                String altQuery = "Find flights from New York to Paris for the following week instead";
                ExecuteResponse altResponse = client.executeQuery(
                        ExecuteQueryRequest.builder()
                                .userToken("user-123")
                                .query(altQuery)
                                .requestType("chat")
                                .context(Map.of("model", "gpt-4"))
                                .build()
                );

                System.out.println("📥 Alternative Options:");
                System.out.println(altResponse.getData());
                System.out.println("✅ Workflow completed with fallback");
                return;
            }

            // Success path - flights found
            System.out.println("💡 Flights found! Analyzing best option...");
            System.out.println(searchResponse.getData());

            // Step 3: Proceed to booking recommendation
            String bookQuery = "Based on the search results above, what would be the recommended booking?";
            System.out.println("\n📤 Getting booking recommendation...");

            ExecuteResponse bookResponse = client.executeQuery(
                    ExecuteQueryRequest.builder()
                            .userToken("user-123")
                            .query(bookQuery)
                            .requestType("chat")
                            .context(Map.of("model", "gpt-4"))
                            .build()
            );

            System.out.println("📥 Booking Recommendation:");
            System.out.println(bookResponse.getData());
            System.out.println("\n✅ Workflow completed successfully");
            System.out.println("💡 Tip: This example demonstrates if/else branching based on API responses");
        } catch (Exception e) {
            System.err.println("❌ Query failed: " + e.getMessage());
            System.exit(1);
        }
    }
}
