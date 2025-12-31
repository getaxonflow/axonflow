/*
 * Example 4: Travel Booking with Fallbacks - Java
 *
 * Demonstrates intelligent fallback patterns: try premium options first,
 * fall back to alternatives if unavailable.
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
        System.out.println("📤 Planning trip to Tokyo with intelligent fallbacks...");
        System.out.println();

        String flightOption = "";
        String hotelOption = "";

        try {
            // STEP 1: Try direct flights first
            System.out.println("🔍 Step 1: Searching for direct flights from San Francisco to Tokyo...");
            ExecuteResponse flightResp1 = client.executeQuery(
                    ExecuteQueryRequest.builder()
                            .userToken("user-123")
                            .query("Find direct flights from San Francisco to Tokyo next month")
                            .requestType("chat")
                            .context(Map.of("model", "gpt-4"))
                            .build()
            );

            String flightResult = String.valueOf(flightResp1.getData()).toLowerCase();

            if (flightResult.contains("no direct flights") || flightResult.contains("not available")) {
                System.out.println("⚠️  No direct flights available");
                System.out.println("📤 Step 2 (Fallback): Trying connecting flights...");

                ExecuteResponse flightResp2 = client.executeQuery(
                        ExecuteQueryRequest.builder()
                                .userToken("user-123")
                                .query("Find connecting flights from San Francisco to Tokyo with 1 stop")
                                .requestType("chat")
                                .context(Map.of("model", "gpt-4"))
                                .build()
                );

                String fallbackResult = String.valueOf(flightResp2.getData()).toLowerCase();
                if (fallbackResult.contains("no flights")) {
                    System.out.println("⚠️  No connecting flights available either");
                    System.out.println("💡 Recommendation: Try different dates or airports");
                    return;
                }

                flightOption = "Connecting flight (1 stop)";
                System.out.println("✅ Found connecting flight option");
            } else {
                flightOption = "Direct flight";
                System.out.println("✅ Found direct flight");
            }

            System.out.println();

            // STEP 2: Try 5-star hotels first
            System.out.println("🔍 Step 3: Searching for 5-star hotels in Tokyo city center...");
            ExecuteResponse hotelResp1 = client.executeQuery(
                    ExecuteQueryRequest.builder()
                            .userToken("user-123")
                            .query("Find 5-star hotels in Tokyo Shibuya district")
                            .requestType("chat")
                            .context(Map.of("model", "gpt-4"))
                            .build()
            );

            String hotelResult = String.valueOf(hotelResp1.getData()).toLowerCase();

            if (hotelResult.contains("fully booked") || hotelResult.contains("no availability")) {
                System.out.println("⚠️  5-star hotels fully booked");
                System.out.println("📤 Step 4 (Fallback): Trying 4-star hotels...");

                ExecuteResponse hotelResp2 = client.executeQuery(
                        ExecuteQueryRequest.builder()
                                .userToken("user-123")
                                .query("Find 4-star hotels in Tokyo with good reviews")
                                .requestType("chat")
                                .context(Map.of("model", "gpt-4"))
                                .build()
                );

                String fallbackResult = String.valueOf(hotelResp2.getData()).toLowerCase();
                if (fallbackResult.contains("no availability")) {
                    System.out.println("⚠️  4-star hotels also unavailable");
                    System.out.println("💡 Recommendation: Try Airbnb or alternative districts");
                    return;
                }

                hotelOption = "4-star hotel (fallback)";
                System.out.println("✅ Found 4-star hotel alternative");
            } else {
                hotelOption = "5-star hotel";
                System.out.println("✅ Found 5-star hotel");
            }

            System.out.println();

            // STEP 3: Generate final itinerary
            System.out.println("📋 Generating complete itinerary with selected options...");
            String itineraryQuery = String.format(
                    "Create a 7-day Tokyo itinerary with %s and %s accommodation. Include top attractions, restaurants, and transportation tips.",
                    flightOption, hotelOption
            );

            ExecuteResponse itineraryResp = client.executeQuery(
                    ExecuteQueryRequest.builder()
                            .userToken("user-123")
                            .query(itineraryQuery)
                            .requestType("chat")
                            .context(Map.of("model", "gpt-4"))
                            .build()
            );

            System.out.println();
            System.out.println("📥 Your Tokyo Itinerary:");
            System.out.println("============================================================");
            System.out.println(itineraryResp.getData());
            System.out.println("============================================================");
            System.out.println();
            System.out.println("✅ Travel booking workflow completed successfully!");
            System.out.printf("💡 Booked: %s + %s%n", flightOption, hotelOption);
        } catch (Exception e) {
            System.err.println("❌ Query failed: " + e.getMessage());
            System.exit(1);
        }
    }
}
