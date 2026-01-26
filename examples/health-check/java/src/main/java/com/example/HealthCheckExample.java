/*
 * Health Check Example - Java
 *
 * Demonstrates how to check the health of AxonFlow Agent and Orchestrator services.
 * This is essential for monitoring and ensuring your governance infrastructure is running.
 *
 * Usage:
 *   mvn exec:java -Dexec.mainClass="com.example.HealthCheckExample"
 *
 * Environment:
 *   AXONFLOW_AGENT_URL     - Agent URL (default: http://localhost:8080)
 *   AXONFLOW_CLIENT_ID     - OAuth2 client ID (optional for community mode)
 *   AXONFLOW_CLIENT_SECRET - OAuth2 client secret (optional for community mode)
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 */

package com.example;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.HealthStatus;

import java.util.ArrayList;
import java.util.List;

public class HealthCheckExample {
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
        // Initialize client (credentials optional for community mode)
        String agentUrl = System.getenv("AXONFLOW_AGENT_URL");
        if (agentUrl == null || agentUrl.isEmpty()) {
            agentUrl = "http://localhost:8080";
        }
        String clientId = System.getenv("AXONFLOW_CLIENT_ID");
        String clientSecret = System.getenv("AXONFLOW_CLIENT_SECRET");

        AxonFlowConfig config = AxonFlowConfig.builder()
            .endpoint(agentUrl)
            .clientId(clientId)
                .clientSecret(clientSecret)
            .build();

        try (AxonFlow client = AxonFlow.create(config)) {
            System.out.println("=== AxonFlow Health Check Example ===");
            System.out.println();

            // 1. Check Agent health
            System.out.println("1. Checking Agent health...");
            HealthStatus agentHealth = null;
            try {
                agentHealth = client.healthCheck();
                System.out.println("   Agent Status: " + agentHealth.getStatus().toUpperCase());
                if (agentHealth.getVersion() != null) {
                    System.out.println("   Version: " + agentHealth.getVersion());
                }
                assertCheck(agentHealth != null, "Agent health check returned response");
                assertCheck(agentHealth.getStatus() != null, "Agent health has status");
            } catch (Exception e) {
                System.out.println("   Agent health check failed: " + e.getMessage());
                assertCheck(false, "Agent health check failed: " + e.getMessage());
            }

            // 2. Check Orchestrator health
            System.out.println();
            System.out.println("2. Checking Orchestrator health...");
            HealthStatus orchHealth = null;
            try {
                orchHealth = client.orchestratorHealthCheck();
                System.out.println("   Orchestrator Status: " + orchHealth.getStatus().toUpperCase());
                if (orchHealth.getVersion() != null) {
                    System.out.println("   Version: " + orchHealth.getVersion());
                }
                assertCheck(orchHealth != null, "Orchestrator health check returned response");
                assertCheck(orchHealth.getStatus() != null, "Orchestrator health has status");
            } catch (Exception e) {
                System.out.println("   Orchestrator health check failed: " + e.getMessage());
                assertCheck(false, "Orchestrator health check failed: " + e.getMessage());
            }

            // 3. Summary
            System.out.println();
            System.out.println("=== Health Check Summary ===");
            boolean agentHealthy = agentHealth != null && agentHealth.isHealthy();
            boolean orchHealthy = orchHealth != null && orchHealth.isHealthy();

            System.out.println("   Agent: " + (agentHealthy ? "HEALTHY" : "UNHEALTHY"));
            System.out.println("   Orchestrator: " + (orchHealthy ? "HEALTHY" : "UNHEALTHY"));

            assertCheck(agentHealthy, "Agent is healthy");
            assertCheck(orchHealthy, "Orchestrator is healthy");

            // Final assertion summary
            System.out.println();
            System.out.println("=".repeat(40));
            System.out.println("Assertion Summary");
            System.out.println("=".repeat(40));
            if (failures.isEmpty()) {
                System.out.println("All assertions passed!");
            } else {
                System.out.println("Failures (" + failures.size() + "):");
                for (String f : failures) {
                    System.out.println("  - " + f);
                }
                System.exit(1);
            }
        }
    }
}
