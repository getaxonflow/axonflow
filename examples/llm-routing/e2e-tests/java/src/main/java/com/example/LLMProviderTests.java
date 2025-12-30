// Community LLM Provider E2E Tests using Java SDK
package com.example;

import com.axonflow.sdk.AxonFlowClient;
import com.axonflow.sdk.AxonFlowConfig;
import com.axonflow.sdk.models.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class LLMProviderTests {

    public static void main(String[] args) {
        // Create client
        String endpoint = System.getenv("ORCHESTRATOR_URL");
        if (endpoint == null || endpoint.isEmpty()) {
            endpoint = "http://localhost:8081";
        }

        AxonFlowConfig config = AxonFlowConfig.builder()
                .endpoint(endpoint)
                .build();
        AxonFlowClient client = new AxonFlowClient(config);

        System.out.println("=== Community LLM Provider Tests (Java SDK) ===");
        System.out.println("Target: " + endpoint);
        System.out.println();

        // Test 1: List providers
        System.out.println("Test 1: List providers");
        try {
            List<Provider> providers = client.listProviders();
            for (Provider p : providers) {
                System.out.printf("  - %s (%s): %s%n", p.getName(), p.getType(), p.getHealth().getStatus());
            }
        } catch (Exception e) {
            System.out.println("  Failed: " + e.getMessage());
        }
        System.out.println();

        // Test 2: Per-request OpenAI
        System.out.println("Test 2: Per-request selection - OpenAI");
        testProvider(client, "openai");
        System.out.println();

        // Test 3: Per-request Anthropic
        System.out.println("Test 3: Per-request selection - Anthropic");
        testProvider(client, "anthropic");
        System.out.println();

        // Test 4: Per-request Gemini
        System.out.println("Test 4: Per-request selection - Gemini");
        testProvider(client, "gemini");
        System.out.println();

        // Test 5: Weighted routing distribution
        System.out.println("Test 5: Weighted routing distribution (5 requests)");
        Map<String, Integer> providersUsed = new HashMap<>();
        for (int i = 0; i < 5; i++) {
            try {
                ProcessRequest request = ProcessRequest.builder()
                        .query("Hello")
                        .requestType("chat")
                        .user(User.builder().email("test@example.com").role("user").build())
                        .build();
                ProcessResponse resp = client.process(request);
                String provider = resp.getProviderInfo().getProvider();
                providersUsed.merge(provider, 1, Integer::sum);
                System.out.printf("  Request %d: %s%n", i + 1, provider);
            } catch (Exception e) {
                System.out.printf("  Request %d: failed (%s)%n", i + 1, e.getMessage());
            }
        }
        System.out.println();

        System.out.println("=== Tests Complete ===");
    }

    private static void testProvider(AxonFlowClient client, String providerName) {
        try {
            Map<String, Object> context = new HashMap<>();
            context.put("provider", providerName);

            ProcessRequest request = ProcessRequest.builder()
                    .query("Say hello in 3 words")
                    .requestType("chat")
                    .context(context)
                    .user(User.builder().email("test@example.com").role("user").build())
                    .build();

            ProcessResponse resp = client.process(request);
            System.out.println("  Provider: " + resp.getProviderInfo().getProvider());
            String response = resp.getData().getData();
            System.out.println("  Response: " + truncate(response, 50));
        } catch (Exception e) {
            System.out.println("  Failed: " + e.getMessage());
        }
    }

    private static String truncate(String s, int maxLen) {
        if (s.length() <= maxLen) {
            return s;
        }
        return s.substring(0, maxLen) + "...";
    }
}
