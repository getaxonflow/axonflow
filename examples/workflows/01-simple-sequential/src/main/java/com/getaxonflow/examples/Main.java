/*
 * Example 1: Simple Sequential Workflow - Java
 *
 * This example shows the most basic AxonFlow workflow: send a query to an LLM and get a response.
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
        // Get AxonFlow configuration from environment
        String agentUrl = Optional.ofNullable(System.getenv("AXONFLOW_AGENT_URL"))
                .orElse("http://localhost:8080");
        String clientId = System.getenv("AXONFLOW_CLIENT_ID");
        String clientSecret = System.getenv("AXONFLOW_CLIENT_SECRET");

        if (clientId == null || clientId.isEmpty() || clientSecret == null || clientSecret.isEmpty()) {
            System.err.println("❌ AXONFLOW_CLIENT_ID and AXONFLOW_CLIENT_SECRET must be set");
            System.exit(1);
        }

        // Create AxonFlow client
        AxonFlow client = AxonFlow.create(AxonFlowConfig.builder()
                .endpoint(agentUrl)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .build());

        System.out.println("✅ Connected to AxonFlow");

        // Define a simple query
        String query = "What is the capital of France?";
        System.out.println("📤 Sending query: " + query);

        try {
            // Send query to AxonFlow
            ClientResponse response = client.proxyLLMCall(
                    ClientRequest.builder()
                            .userToken("user-123")
                            .query(query)
                            .clientId(clientId)
                            .model("gpt-3.5-turbo")
                            .llmProvider("openai")
                            .context(Map.of("workflow", "simple-sequential"))
                            .build()
            );

            // Check if blocked
            if (response.isBlocked()) {
                System.out.println("📥 Response: BLOCKED - " + response.getBlockReason());
            } else {
                // Print response
                System.out.println("📥 Response: " + response.getData());
            }

            // Assertions
            System.out.println();
            System.out.println("=== Assertions ===");
            assertCheck(response != null, "Response is not null");
            assertCheck(response.isSuccess() || response.isBlocked(), "Response has valid status");

            if (!response.isBlocked()) {
                assertCheck(response.getData() != null, "Response data is not null");
                String responseStr = String.valueOf(response.getData());
                assertCheck(!responseStr.isEmpty(), "Response data is not empty");
                assertCheck(responseStr.length() > 10, "Response has meaningful content (length > 10)");
            }

            System.out.println();
            System.out.println("✅ Workflow completed successfully");
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
