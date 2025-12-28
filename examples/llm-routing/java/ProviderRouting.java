/**
 * LLM Provider Routing Example
 *
 * This example demonstrates how to:
 * 1. Use default routing (server-side configuration)
 * 2. Specify a preferred provider in requests
 * 3. Query provider status
 *
 * Server-side configuration (environment variables):
 *   LLM_ROUTING_STRATEGY=weighted|round_robin|failover
 *   PROVIDER_WEIGHTS=openai:50,anthropic:30,bedrock:20
 *   DEFAULT_LLM_PROVIDER=bedrock
 */

package com.example.llmrouting;

import com.getaxonflow.sdk.AxonFlowClient;
import com.getaxonflow.sdk.AxonFlowClientConfig;
import com.getaxonflow.sdk.ProxyRequest;
import com.getaxonflow.sdk.ProxyResponse;
import com.getaxonflow.sdk.HealthResponse;
import com.getaxonflow.sdk.RequestType;

import java.util.Map;
import java.util.Optional;

public class ProviderRouting {

    public static void main(String[] args) {
        // Initialize client
        String endpoint = Optional.ofNullable(System.getenv("AXONFLOW_ENDPOINT"))
                .orElse("http://localhost:8080");
        String licenseKey = System.getenv("AXONFLOW_LICENSE_KEY");
        String tenant = Optional.ofNullable(System.getenv("AXONFLOW_TENANT"))
                .orElse("demo");

        AxonFlowClientConfig config = AxonFlowClientConfig.builder()
                .endpoint(endpoint)
                .licenseKey(licenseKey)
                .tenant(tenant)
                .build();

        try (AxonFlowClient client = new AxonFlowClient(config)) {
            System.out.println("=== LLM Provider Routing Examples ===\n");

            // Example 1: Default routing (uses server-side strategy)
            System.out.println("1. Default routing (server decides provider):");
            ProxyResponse defaultResponse = client.proxy(ProxyRequest.builder()
                    .query("What is 2 + 2?")
                    .requestType(RequestType.CHAT)
                    .build());
            printResponse(defaultResponse, "provider");

            // Example 2: Request a specific provider
            System.out.println("2. Request specific provider (OpenAI):");
            ProxyResponse openaiResponse = client.proxy(ProxyRequest.builder()
                    .query("What is the capital of France?")
                    .requestType(RequestType.CHAT)
                    .context(Map.of("provider", "openai"))  // Request specific provider
                    .build());
            printResponse(openaiResponse, "provider");

            // Example 3: Request Anthropic
            System.out.println("3. Request specific provider (Anthropic):");
            ProxyResponse anthropicResponse = client.proxy(ProxyRequest.builder()
                    .query("Explain quantum computing in one sentence.")
                    .requestType(RequestType.CHAT)
                    .context(Map.of("provider", "anthropic"))
                    .build());
            printResponse(anthropicResponse, "provider");

            // Example 4: Request with model override
            System.out.println("4. Request with specific model:");
            ProxyResponse modelResponse = client.proxy(ProxyRequest.builder()
                    .query("What is machine learning?")
                    .requestType(RequestType.CHAT)
                    .context(Map.of(
                            "provider", "openai",
                            "model", "gpt-4o-mini"  // Specify exact model
                    ))
                    .build());
            printModelResponse(modelResponse);

            // Example 5: Health check to see available providers
            System.out.println("5. Check provider health status:");
            HealthResponse health = client.health();
            System.out.println("   Status: " + health.getStatus());
            if (health.getProviders() != null) {
                health.getProviders().forEach((name, status) -> {
                    boolean healthy = false;
                    if (status instanceof Map) {
                        @SuppressWarnings("unchecked")
                        Map<String, Object> statusMap = (Map<String, Object>) status;
                        Object healthyObj = statusMap.get("healthy");
                        healthy = Boolean.TRUE.equals(healthyObj);
                    }
                    String symbol = healthy ? "✓ healthy" : "✗ unhealthy";
                    System.out.println("   - " + name + ": " + symbol);
                });
            }

            System.out.println("\n=== Examples Complete ===");
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void printResponse(ProxyResponse response, String metadataKey) {
        String responseText = response.getResponse();
        if (responseText != null && responseText.length() > 50) {
            responseText = responseText.substring(0, 50);
        }
        System.out.println("   Response: " + (responseText != null ? responseText : "N/A") + "...");

        String metadataValue = "unknown";
        if (response.getMetadata() != null && response.getMetadata().containsKey(metadataKey)) {
            Object value = response.getMetadata().get(metadataKey);
            if (value != null) {
                metadataValue = value.toString();
            }
        }
        System.out.println("   Provider used: " + metadataValue + "\n");
    }

    private static void printModelResponse(ProxyResponse response) {
        String responseText = response.getResponse();
        if (responseText != null && responseText.length() > 50) {
            responseText = responseText.substring(0, 50);
        }
        System.out.println("   Response: " + (responseText != null ? responseText : "N/A") + "...");

        String model = "unknown";
        if (response.getMetadata() != null && response.getMetadata().containsKey("model")) {
            Object value = response.getMetadata().get("model");
            if (value != null) {
                model = value.toString();
            }
        }
        System.out.println("   Model used: " + model + "\n");
    }
}
