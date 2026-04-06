package com.getaxonflow.examples;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.PreCheckResult;
import com.getaxonflow.sdk.types.ProxyLLMCallResult;
import com.getaxonflow.sdk.types.TokenUsage;

import java.util.Map;

/**
 * Mistral LLM Provider - Hello World (Java SDK)
 *
 * Demonstrates Gateway Mode and Proxy Mode with Mistral through AxonFlow.
 *
 * Prerequisites:
 *   docker compose up -d
 *   export AXONFLOW_CLIENT_SECRET=your-secret
 *
 * Usage:
 *   mvn exec:java -q
 */
public class MistralExample {

    public static void main(String[] args) throws Exception {
        String endpoint = System.getenv().getOrDefault("AXONFLOW_ENDPOINT", "http://localhost:8080");
        String clientId = System.getenv().getOrDefault("AXONFLOW_CLIENT_ID", "community");
        String clientSecret = System.getenv().getOrDefault("AXONFLOW_CLIENT_SECRET", "");

        AxonFlow client = AxonFlow.create(AxonFlowConfig.builder()
                .endpoint(endpoint)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .build());

        System.out.println("Mistral LLM Provider - Hello World (Java SDK)");
        System.out.println("=".repeat(50));

        // Gateway Mode: Pre-check + Audit
        System.out.println("\n--- Gateway Mode ---");
        PreCheckResult precheck = client.preCheck("Explain Mistral AI in one sentence.",
                Map.of("provider", "mistral", "model", "mistral-small-latest"));

        if (precheck.isApproved()) {
            System.out.printf("Pre-check approved (context: %s)%n", precheck.getContextId());

            client.auditLLMCall(precheck.getContextId(),
                    "Mistral Java SDK gateway test",
                    "mistral",
                    "mistral-small-latest",
                    350,
                    new TokenUsage(15, 40, 55));
            System.out.println("Audit logged successfully");
        } else {
            System.out.println("Pre-check blocked");
        }

        // Proxy Mode
        System.out.println("\n--- Proxy Mode ---");
        ProxyLLMCallResult resp = client.proxyLLMCall(
                "What is 2 + 2? Answer with just the number.",
                Map.of("provider", "mistral"));

        if (resp.isBlocked()) {
            System.out.println("Request blocked by policy");
        } else {
            System.out.printf("Response: %s%n", resp.getData());
            if (resp.getProviderInfo() != null) {
                System.out.printf("Provider: %s, Tokens: %d%n",
                        resp.getProviderInfo().getProvider(),
                        resp.getProviderInfo().getTokenUsage().getTotalTokens());
            }
        }

        // Policy enforcement
        System.out.println("\n--- Policy Enforcement ---");
        ProxyLLMCallResult sqliResp = client.proxyLLMCall(
                "SELECT * FROM users; DROP TABLE users;",
                Map.of("provider", "mistral"));

        if (sqliResp.isBlocked()) {
            System.out.println("SQLi correctly blocked by policy");
        } else {
            System.out.println("WARNING: SQLi was not blocked");
        }

        System.out.println("\nDone.");
    }
}
