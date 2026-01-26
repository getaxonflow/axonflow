/**
 * LLM Provider Routing Example
 *
 * This example demonstrates how AxonFlow routes requests to LLM providers.
 * Provider selection is controlled SERVER-SIDE via environment variables,
 * not per-request. This ensures consistent routing policies across your org.
 *
 * Server-side configuration (environment variables):
 *   LLM_ROUTING_STRATEGY=weighted|round_robin|failover|cost_optimized*
 *   PROVIDER_WEIGHTS=openai:50,anthropic:30,ollama:20
 *   DEFAULT_LLM_PROVIDER=openai
 *
 * * cost_optimized is Enterprise only
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 */

package com.example.llmrouting;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.ClientRequest;
import com.getaxonflow.sdk.types.ClientResponse;
import com.getaxonflow.sdk.types.HealthStatus;
import com.getaxonflow.sdk.types.RequestType;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class ProviderRouting {

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
        // Initialize client
        String endpoint = Optional.ofNullable(System.getenv("AXONFLOW_ENDPOINT"))
                .orElse("http://localhost:8080");
        String clientId = System.getenv("AXONFLOW_CLIENT_ID");
        String clientSecret = System.getenv("AXONFLOW_CLIENT_SECRET");

        AxonFlow client = AxonFlow.create(AxonFlowConfig.builder()
                .endpoint(endpoint)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .build());

        // AXONFLOW_USER_TOKEN: Set to JWT for enterprise mode
        // In community mode, SDK defaults to "anonymous" if not set
        String userToken = System.getenv("AXONFLOW_USER_TOKEN");

        System.out.println("=== LLM Provider Routing Examples ===\n");
        System.out.println("Provider selection is server-side. Configure via environment variables:");
        System.out.println("  LLM_ROUTING_STRATEGY=weighted");
        System.out.println("  PROVIDER_WEIGHTS=openai:50,anthropic:30,ollama:20\n");

        // Example 1: Send a request (server decides which provider to use)
        System.out.println("1. Send request (server routes based on configured strategy):");
        boolean example1Success = false;
        try {
            ClientResponse response = client.proxyLLMCall(ClientRequest.builder()
                    .userToken(userToken)
                    .query("What is 2 + 2?")
                    .requestType(RequestType.CHAT)
                    .context(Map.of("provider", "openai"))
                    .build());
            printResponse(response);
            example1Success = response.isSuccess();
        } catch (Exception e) {
            System.out.println("   Error: " + e.getMessage() + "\n");
        }
        assertCheck(example1Success, "First request routed successfully");

        // Example 2: Multiple requests show distribution based on weights
        System.out.println("2. Multiple requests (observe provider distribution):");
        int successfulRequests = 0;
        for (int i = 1; i <= 3; i++) {
            try {
                ClientResponse response = client.proxyLLMCall(ClientRequest.builder()
                        .userToken(userToken)
                        .query("Question " + i + ": What is the capital of France?")
                        .requestType(RequestType.CHAT)
                        .context(Map.of("provider", "openai"))
                        .build());
                System.out.println("   Request " + i + ": Success (provider selected by server)");
                if (response.isSuccess()) {
                    successfulRequests++;
                }
            } catch (Exception e) {
                System.out.println("   Request " + i + " Error: " + e.getMessage());
            }
        }
        assertCheck(successfulRequests > 0, "Multiple requests processed (" + successfulRequests + "/3 successful)");
        System.out.println();

        // Example 3: Health check
        System.out.println("3. Check agent health:");
        boolean healthPassed = false;
        try {
            HealthStatus health = client.healthCheck();
            System.out.println("   Status: " + health.getStatus());
            healthPassed = health.isHealthy();
        } catch (Exception e) {
            System.out.println("   Error: " + e.getMessage());
        }
        assertCheck(healthPassed, "Agent health check passed");

        System.out.println("\n=== Examples Complete ===");
        System.out.println("\nTo change provider routing, update server environment variables:");
        System.out.println("  - LLM_ROUTING_STRATEGY: weighted, round_robin, failover");
        System.out.println("  - PROVIDER_WEIGHTS: distribution percentages");
        System.out.println("  - DEFAULT_LLM_PROVIDER: fallback for failover strategy");

        // Final assertion summary
        System.out.println();
        System.out.println("=".repeat(50));
        if (!failures.isEmpty()) {
            System.out.println("FAILED: " + failures.size() + " assertion(s) failed:");
            for (String failure : failures) {
                System.out.println("  - " + failure);
            }
            System.exit(1);
        } else {
            System.out.println("All assertions passed!");
        }
    }

    private static void printResponse(ClientResponse response) {
        Object data = response.getData();
        String dataStr = data != null ? data.toString() : "N/A";
        if (dataStr.length() > 100) {
            dataStr = dataStr.substring(0, 100);
        }
        System.out.println("   Response: " + dataStr + "...");
        System.out.println("   Success: " + response.isSuccess() + "\n");
    }
}
