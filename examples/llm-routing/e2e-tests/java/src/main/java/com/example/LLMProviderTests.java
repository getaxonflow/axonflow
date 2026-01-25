// Community LLM Provider E2E Tests using Java SDK
// Tests governed LLM access through AxonFlow Agent
package com.example;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.ClientRequest;
import com.getaxonflow.sdk.types.ClientResponse;
import com.getaxonflow.sdk.types.HealthStatus;
import com.getaxonflow.sdk.types.RequestType;

import java.util.HashMap;
import java.util.Map;

public class LLMProviderTests {

    public static void main(String[] args) {
        // Create client - SDK talks to Agent which routes to Orchestrator
        String agentUrl = System.getenv("AGENT_URL");
        if (agentUrl == null || agentUrl.isEmpty()) {
            agentUrl = "http://localhost:8080";
        }

        String clientId = System.getenv("AXONFLOW_CLIENT_ID");
        String clientSecret = System.getenv("AXONFLOW_CLIENT_SECRET");
        String userToken = System.getenv("AXONFLOW_USER_TOKEN");

        AxonFlowConfig.Builder configBuilder = AxonFlowConfig.builder()
                .endpoint(agentUrl);

        if (clientId != null && !clientId.isEmpty()) {
            configBuilder.clientId(clientId);
        }
        if (clientSecret != null && !clientSecret.isEmpty()) {
            configBuilder.clientSecret(clientSecret);
        }

        try (AxonFlow client = AxonFlow.create(configBuilder.build())) {

            System.out.println("=== Community LLM Provider Tests (Java SDK) ===");
            System.out.println("Agent URL: " + agentUrl);
            System.out.println();

            // Test 1: Health check
            System.out.println("Test 1: Agent health check");
            try {
                HealthStatus health = client.healthCheck();
                System.out.println("  Agent is healthy: " + health.getStatus());
            } catch (Exception e) {
                System.out.println("  Health check failed: " + e.getMessage());
            }
            System.out.println();

            // Test 2: Execute query with OpenAI preference
            System.out.println("Test 2: Per-request selection - OpenAI");
            testProvider(client, userToken, "openai");
            System.out.println();

            // Test 3: Execute query with Anthropic preference
            System.out.println("Test 3: Per-request selection - Anthropic");
            testProvider(client, userToken, "anthropic");
            System.out.println();

            // Test 4: Execute query with Gemini preference
            System.out.println("Test 4: Per-request selection - Gemini");
            testProvider(client, userToken, "gemini");
            System.out.println();

            // Test 5: Weighted routing (no provider preference)
            System.out.println("Test 5: Weighted routing distribution (5 queries)");
            for (int i = 0; i < 5; i++) {
                try {
                    ClientResponse resp = client.proxyLLMCall(ClientRequest.builder()
                            .userToken(userToken)
                            .query("Hello")
                            .requestType(RequestType.CHAT)
                            .build());
                    System.out.printf("  Query %d: Success%n", i + 1);
                } catch (Exception e) {
                    System.out.printf("  Query %d: Error - %s%n", i + 1, e.getMessage());
                }
            }
            System.out.println();

            System.out.println("=== Tests Complete ===");
        }
    }

    private static void testProvider(AxonFlow client, String userToken, String providerName) {
        try {
            Map<String, Object> context = new HashMap<>();
            context.put("provider", providerName);

            ClientResponse resp = client.proxyLLMCall(ClientRequest.builder()
                    .userToken(userToken)
                    .query("Say hello in 3 words")
                    .requestType(RequestType.CHAT)
                    .context(context)
                    .build());
            System.out.println("  Success: " + resp.isSuccess());
            if (resp.getData() != null) {
                System.out.println("  Response: " + truncate(String.valueOf(resp.getData()), 50));
            }
        } catch (Exception e) {
            System.out.println("  Error: " + e.getMessage());
        }
    }

    private static String truncate(String s, int maxLen) {
        if (s == null) {
            return "";
        }
        if (s.length() <= maxLen) {
            return s;
        }
        return s.substring(0, maxLen) + "...";
    }
}
