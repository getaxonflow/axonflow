/*
 * Example 1: Simple Sequential Workflow - Java
 *
 * This example shows the most basic AxonFlow workflow: send a query to an LLM and get a response.
 */
package com.getaxonflow.examples;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.ExecuteQueryRequest;
import com.getaxonflow.sdk.types.ExecuteResponse;

import java.util.Map;
import java.util.Optional;

public class Main {

    public static void main(String[] args) {
        // Get AxonFlow configuration from environment
        String agentUrl = Optional.ofNullable(System.getenv("AXONFLOW_AGENT_URL"))
                .orElse("http://localhost:8080");
        String licenseKey = System.getenv("AXONFLOW_LICENSE_KEY");

        if (licenseKey == null || licenseKey.isEmpty()) {
            System.err.println("❌ AXONFLOW_LICENSE_KEY must be set");
            System.exit(1);
        }

        // Create AxonFlow client
        AxonFlowConfig config = AxonFlowConfig.builder()
                .agentUrl(agentUrl)
                .licenseKey(licenseKey)
                .build();

        AxonFlow client = new AxonFlow(config);

        System.out.println("✅ Connected to AxonFlow");

        // Define a simple query
        String query = "What is the capital of France?";
        System.out.println("📤 Sending query: " + query);

        try {
            // Send query to AxonFlow
            ExecuteResponse response = client.executeQuery(
                    ExecuteQueryRequest.builder()
                            .userToken("user-123")
                            .query(query)
                            .requestType("chat")
                            .context(Map.of("model", "gpt-4"))
                            .build()
            );

            // Print response
            System.out.println("📥 Response: " + response.getData());
            System.out.println("✅ Workflow completed successfully");
        } catch (Exception e) {
            System.err.println("❌ Query failed: " + e.getMessage());
            System.exit(1);
        }
    }
}
