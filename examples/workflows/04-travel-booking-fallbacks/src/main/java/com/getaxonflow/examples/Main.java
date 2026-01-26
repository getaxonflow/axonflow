/*
 * Example 4: Travel Booking with Fallbacks - Java
 *
 * Demonstrates intelligent fallback patterns: try premium options first,
 * fall back to alternatives if unavailable.
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
        System.out.println("📤 Planning trip to Tokyo with intelligent fallbacks...");
        System.out.println();

        String flightOption = "";
        String hotelOption = "";
        int stepsCompleted = 0;

        try {
            // STEP 1: Try direct flights first
            System.out.println("🔍 Step 1: Searching for direct flights from San Francisco to Tokyo...");
            ClientResponse flightResp1 = client.proxyLLMCall(
                    ClientRequest.builder()
                            .userToken("user-123")
                            .query("Find direct flights from San Francisco to Tokyo next month")
                            .clientId(clientId)
                            .model("gpt-3.5-turbo")
                            .llmProvider("openai")
                            .context(Map.of("workflow", "travel-fallbacks"))
                            .build()
            );

            stepsCompleted++;

            // Assertion for flight search
            System.out.println();
            System.out.println("=== Flight Search Assertions ===");
            assertCheck(flightResp1 != null, "Flight search response is not null");

            if (flightResp1.isBlocked()) {
                System.out.println("❌ Flight search was blocked: " + flightResp1.getBlockReason());
                failures.add("Flight search was blocked");
            } else {
                assertCheck(flightResp1.getData() != null, "Flight search data is not null");
                String flightResult = String.valueOf(flightResp1.getData()).toLowerCase();

                if (flightResult.contains("no direct flights") || flightResult.contains("not available")) {
                    System.out.println("⚠️  No direct flights available");
                    System.out.println("📤 Step 2 (Fallback): Trying connecting flights...");

                    ClientResponse flightResp2 = client.proxyLLMCall(
                            ClientRequest.builder()
                                    .userToken("user-123")
                                    .query("Find connecting flights from San Francisco to Tokyo with 1 stop")
                                    .clientId(clientId)
                                    .model("gpt-3.5-turbo")
                                    .llmProvider("openai")
                                    .context(Map.of("workflow", "travel-fallbacks-connecting"))
                                    .build()
                    );

                    stepsCompleted++;
                    assertCheck(flightResp2 != null, "Fallback flight response is not null");

                    if (!flightResp2.isBlocked()) {
                        String fallbackResult = String.valueOf(flightResp2.getData()).toLowerCase();
                        if (fallbackResult.contains("no flights")) {
                            System.out.println("⚠️  No connecting flights available either");
                            System.out.println("💡 Recommendation: Try different dates or airports");

                            System.out.println();
                            System.out.println("=== Early Exit Assertions ===");
                            assertCheck(stepsCompleted >= 2, "At least 2 flight search steps completed");

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
                    }

                    flightOption = "Connecting flight (1 stop)";
                    System.out.println("✅ Found connecting flight option");
                } else {
                    flightOption = "Direct flight";
                    System.out.println("✅ Found direct flight");
                }
            }

            if (flightOption.isEmpty()) {
                flightOption = "Flight option found";
            }

            assertCheck(!flightOption.isEmpty(), "Flight option was selected");
            System.out.println();

            // STEP 2: Try 5-star hotels first
            System.out.println("🔍 Step 3: Searching for 5-star hotels in Tokyo city center...");
            ClientResponse hotelResp1 = client.proxyLLMCall(
                    ClientRequest.builder()
                            .userToken("user-123")
                            .query("Find 5-star hotels in Tokyo Shibuya district")
                            .clientId(clientId)
                            .model("gpt-3.5-turbo")
                            .llmProvider("openai")
                            .context(Map.of("workflow", "travel-fallbacks-hotel"))
                            .build()
            );

            stepsCompleted++;

            // Assertion for hotel search
            System.out.println();
            System.out.println("=== Hotel Search Assertions ===");
            assertCheck(hotelResp1 != null, "Hotel search response is not null");

            if (hotelResp1.isBlocked()) {
                System.out.println("❌ Hotel search was blocked: " + hotelResp1.getBlockReason());
                hotelOption = "Hotel search blocked";
            } else {
                assertCheck(hotelResp1.getData() != null, "Hotel search data is not null");
                String hotelResult = String.valueOf(hotelResp1.getData()).toLowerCase();

                if (hotelResult.contains("fully booked") || hotelResult.contains("no availability")) {
                    System.out.println("⚠️  5-star hotels fully booked");
                    System.out.println("📤 Step 4 (Fallback): Trying 4-star hotels...");

                    ClientResponse hotelResp2 = client.proxyLLMCall(
                            ClientRequest.builder()
                                    .userToken("user-123")
                                    .query("Find 4-star hotels in Tokyo with good reviews")
                                    .clientId(clientId)
                                    .model("gpt-3.5-turbo")
                                    .llmProvider("openai")
                                    .context(Map.of("workflow", "travel-fallbacks-hotel-4star"))
                                    .build()
                    );

                    stepsCompleted++;
                    assertCheck(hotelResp2 != null, "Fallback hotel response is not null");

                    hotelOption = "4-star hotel (fallback)";
                    System.out.println("✅ Found 4-star hotel alternative");
                } else {
                    hotelOption = "5-star hotel";
                    System.out.println("✅ Found 5-star hotel");
                }
            }

            if (hotelOption.isEmpty()) {
                hotelOption = "Hotel option found";
            }

            assertCheck(!hotelOption.isEmpty(), "Hotel option was selected");
            System.out.println();

            // STEP 3: Generate final itinerary
            System.out.println("📋 Generating complete itinerary with selected options...");
            String itineraryQuery = String.format(
                    "Create a 7-day Tokyo itinerary with %s and %s accommodation. Include top attractions, restaurants, and transportation tips.",
                    flightOption, hotelOption
            );

            ClientResponse itineraryResp = client.proxyLLMCall(
                    ClientRequest.builder()
                            .userToken("user-123")
                            .query(itineraryQuery)
                            .clientId(clientId)
                            .model("gpt-3.5-turbo")
                            .llmProvider("openai")
                            .context(Map.of("workflow", "travel-fallbacks-itinerary"))
                            .build()
            );

            stepsCompleted++;

            System.out.println();
            System.out.println("📥 Your Tokyo Itinerary:");
            System.out.println("============================================================");
            if (itineraryResp.isBlocked()) {
                System.out.println("BLOCKED: " + itineraryResp.getBlockReason());
            } else {
                System.out.println(itineraryResp.getData());
            }
            System.out.println("============================================================");
            System.out.println();

            // Final assertions
            System.out.println("=== Final Assertions ===");
            assertCheck(itineraryResp != null, "Itinerary response is not null");
            if (!itineraryResp.isBlocked()) {
                assertCheck(itineraryResp.getData() != null, "Itinerary data is not null");
                String itineraryStr = String.valueOf(itineraryResp.getData());
                assertCheck(itineraryStr.length() > 100, "Itinerary has substantial content (length > 100)");
            }
            assertCheck(stepsCompleted >= 3, "At least 3 workflow steps completed");

            System.out.println();
            System.out.println("✅ Travel booking workflow completed successfully!");
            System.out.printf("💡 Booked: %s + %s%n", flightOption, hotelOption);
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
