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

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.ClientRequest;
import com.getaxonflow.sdk.types.ClientResponse;
import com.getaxonflow.sdk.types.HealthStatus;
import com.getaxonflow.sdk.types.RequestType;

import java.util.Optional;

public class ProviderRouting {

    public static void main(String[] args) {
        // Initialize client
        String endpoint = Optional.ofNullable(System.getenv("AXONFLOW_ENDPOINT"))
                .orElse("http://localhost:8080");
        String licenseKey = System.getenv("AXONFLOW_LICENSE_KEY");

        AxonFlow client = AxonFlow.create(AxonFlowConfig.builder()
                .agentUrl(endpoint)
                .licenseKey(licenseKey)
                .build());

        System.out.println("=== LLM Provider Routing Examples ===\n");

        // Example 1: Default routing (uses server-side strategy)
        System.out.println("1. Default routing (server decides provider):");
        try {
            ClientResponse defaultResponse = client.executeQuery(ClientRequest.builder()
                    .userToken("demo-user")
                    .query("What is 2 + 2?")
                    .requestType(RequestType.CHAT)
                    .build());
            printResponse(defaultResponse);
        } catch (Exception e) {
            System.out.println("   Error: " + e.getMessage() + "\n");
        }

        // Example 2: Request specific provider (Ollama - local)
        System.out.println("2. Request specific provider (Ollama):");
        try {
            ClientResponse ollamaResponse = client.executeQuery(ClientRequest.builder()
                    .userToken("demo-user")
                    .query("What is the capital of France?")
                    .requestType(RequestType.CHAT)
                    .llmProvider("ollama")  // Request specific provider
                    .build());
            printResponse(ollamaResponse);
        } catch (Exception e) {
            System.out.println("   Error: " + e.getMessage() + "\n");
        }

        // Example 3: Request with model override
        System.out.println("3. Request with specific model:");
        try {
            ClientResponse modelResponse = client.executeQuery(ClientRequest.builder()
                    .userToken("demo-user")
                    .query("What is machine learning in one sentence?")
                    .requestType(RequestType.CHAT)
                    .llmProvider("ollama")
                    .model("tinyllama")  // Specify exact model
                    .build());
            printResponse(modelResponse);
        } catch (Exception e) {
            System.out.println("   Error: " + e.getMessage() + "\n");
        }

        // Example 4: Health check
        System.out.println("4. Check agent health:");
        try {
            HealthStatus health = client.healthCheck();
            System.out.println("   Status: " + health.getStatus());
            System.out.println("   Healthy: " + health.isHealthy() + "\n");
        } catch (Exception e) {
            System.out.println("   Error: " + e.getMessage() + "\n");
        }

        System.out.println("=== Examples Complete ===");
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
