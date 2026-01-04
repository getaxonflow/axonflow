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
 *   AXONFLOW_AGENT_URL   - Agent URL (default: http://localhost:8080)
 *   AXONFLOW_LICENSE_KEY - Optional for community mode
 */

package com.example;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.HealthStatus;

public class HealthCheckExample {
    public static void main(String[] args) {
        // Initialize client (credentials optional for community mode)
        String agentUrl = System.getenv("AXONFLOW_AGENT_URL");
        if (agentUrl == null || agentUrl.isEmpty()) {
            agentUrl = "http://localhost:8080";
        }
        String licenseKey = System.getenv("AXONFLOW_LICENSE_KEY");

        AxonFlowConfig config = AxonFlowConfig.builder()
            .agentUrl(agentUrl)
            .licenseKey(licenseKey)
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
            } catch (Exception e) {
                System.out.println("   Agent health check failed: " + e.getMessage());
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
            } catch (Exception e) {
                System.out.println("   Orchestrator health check failed: " + e.getMessage());
            }

            // 3. Summary
            System.out.println();
            System.out.println("=== Health Check Summary ===");
            boolean agentHealthy = agentHealth != null && agentHealth.isHealthy();
            boolean orchHealthy = orchHealth != null && orchHealth.isHealthy();

            System.out.println("   Agent: " + (agentHealthy ? "HEALTHY" : "UNHEALTHY"));
            System.out.println("   Orchestrator: " + (orchHealthy ? "HEALTHY" : "UNHEALTHY"));

            // Exit with error if either service is unhealthy
            if (!agentHealthy || !orchHealthy) {
                System.exit(1);
            }
        }
    }
}
