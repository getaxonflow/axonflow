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
        System.out.println("Provider selection is server-side. Configure via environment variables:");
        System.out.println("  LLM_ROUTING_STRATEGY=weighted");
        System.out.println("  PROVIDER_WEIGHTS=openai:50,anthropic:30,ollama:20\n");

        // Example 1: Send a request (server decides which provider to use)
        System.out.println("1. Send request (server routes based on configured strategy):");
        try {
            ClientResponse response = client.executeQuery(ClientRequest.builder()
                    .userToken("demo-user")
                    .query("What is 2 + 2?")
                    .requestType(RequestType.CHAT)
                    .build());
            printResponse(response);
        } catch (Exception e) {
            System.out.println("   Error: " + e.getMessage() + "\n");
        }

        // Example 2: Multiple requests show distribution based on weights
        System.out.println("2. Multiple requests (observe provider distribution):");
        for (int i = 1; i <= 3; i++) {
            try {
                ClientResponse response = client.executeQuery(ClientRequest.builder()
                        .userToken("demo-user")
                        .query("Question " + i + ": What is the capital of France?")
                        .requestType(RequestType.CHAT)
                        .build());
                System.out.println("   Request " + i + ": Success (provider selected by server)");
            } catch (Exception e) {
                System.out.println("   Request " + i + " Error: " + e.getMessage());
            }
        }
        System.out.println();

        // Example 3: Health check
        System.out.println("3. Check agent health:");
        try {
            HealthStatus health = client.healthCheck();
            System.out.println("   Status: " + health.getStatus());
        } catch (Exception e) {
            System.out.println("   Error: " + e.getMessage());
        }

        System.out.println("\n=== Examples Complete ===");
        System.out.println("\nTo change provider routing, update server environment variables:");
        System.out.println("  - LLM_ROUTING_STRATEGY: weighted, round_robin, failover");
        System.out.println("  - PROVIDER_WEIGHTS: distribution percentages");
        System.out.println("  - DEFAULT_LLM_PROVIDER: fallback for failover strategy");
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
