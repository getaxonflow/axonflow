/*
 * Dynamic Policy Management Example - Java
 *
 * Demonstrates CRUD operations for dynamic policies (LLM-powered policies).
 * Dynamic policies use an LLM to evaluate complex, context-aware rules that
 * can't be expressed with simple regex patterns.
 *
 * SDK Methods demonstrated:
 *   - listDynamicPolicies()
 *   - createDynamicPolicy()
 *   - getDynamicPolicy()
 *   - updateDynamicPolicy()
 *   - deleteDynamicPolicy()
 *   - toggleDynamicPolicy()
 *   - getEffectiveDynamicPolicies()
 *
 * Usage:
 *   mvn exec:java -Dexec.mainClass="com.example.DynamicPolicyExample"
 *
 * Environment:
 *   AXONFLOW_ENDPOINT    - Agent URL (default: http://localhost:8080)
 *   AXONFLOW_LICENSE_KEY - Required for dynamic policies
 */

package com.example;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.policies.PolicyTypes.*;
import java.util.List;

public class DynamicPolicyExample {
    public static void main(String[] args) {
        // Initialize client
        String endpoint = System.getenv("AXONFLOW_ENDPOINT");
        if (endpoint == null || endpoint.isEmpty()) {
            endpoint = "http://localhost:8080";
        }
        String licenseKey = System.getenv("AXONFLOW_LICENSE_KEY");

        AxonFlowConfig config = AxonFlowConfig.builder()
            .endpoint(endpoint)
            .licenseKey(licenseKey)
            .build();

        DynamicPolicy createdPolicy = null;

        try (AxonFlow client = new AxonFlow(config)) {
            System.out.println("=== Dynamic Policy Management Example ===\n");

            // 1. List existing dynamic policies
            System.out.println("1. Listing existing dynamic policies...");
            try {
                List<DynamicPolicy> policies = client.listDynamicPolicies();
                System.out.println("   Found " + policies.size() + " dynamic policies");
                for (DynamicPolicy p : policies) {
                    System.out.println("   - " + p.getId() + ": " + p.getName() +
                        " (enabled: " + p.isEnabled() + ")");
                }
            } catch (Exception e) {
                System.out.println("   Failed to list policies: " + e.getMessage());
            }

            // 2. Create a new dynamic policy
            System.out.println("\n2. Creating a new dynamic policy...");
            try {
                CreateDynamicPolicyRequest request = CreateDynamicPolicyRequest.builder()
                    .name("financial-advice-guard")
                    .description("Block requests that ask for specific financial advice")
                    .prompt("Evaluate if this request is asking for specific financial advice like stock picks, investment amounts, or trading strategies. If so, block it.")
                    .action("block")
                    .enabled(true)
                    .tenantId("demo-tenant")
                    .build();

                createdPolicy = client.createDynamicPolicy(request);
                System.out.println("   Created policy: " + createdPolicy.getName() +
                    " (ID: " + createdPolicy.getId() + ")");
            } catch (Exception e) {
                System.out.println("   Failed to create policy: " + e.getMessage());
            }

            // 3. Get the policy by ID
            if (createdPolicy != null) {
                System.out.println("\n3. Getting policy by ID...");
                try {
                    DynamicPolicy policy = client.getDynamicPolicy(createdPolicy.getId());
                    System.out.println("   Policy: " + policy.getName());
                    System.out.println("   Description: " + policy.getDescription());
                    System.out.println("   Prompt: " + policy.getPrompt());
                    System.out.println("   Action: " + policy.getAction());
                } catch (Exception e) {
                    System.out.println("   Failed to get policy: " + e.getMessage());
                }
            }

            // 4. Update the policy
            if (createdPolicy != null) {
                System.out.println("\n4. Updating policy description...");
                try {
                    UpdateDynamicPolicyRequest update = UpdateDynamicPolicyRequest.builder()
                        .description("Block requests asking for specific financial or investment advice")
                        .build();
                    DynamicPolicy updated = client.updateDynamicPolicy(createdPolicy.getId(), update);
                    System.out.println("   Updated description: " + updated.getDescription());
                } catch (Exception e) {
                    System.out.println("   Failed to update policy: " + e.getMessage());
                }
            }

            // 5. Toggle policy (disable it)
            if (createdPolicy != null) {
                System.out.println("\n5. Toggling policy (disabling)...");
                try {
                    DynamicPolicy toggled = client.toggleDynamicPolicy(createdPolicy.getId());
                    System.out.println("   Policy enabled: " + toggled.isEnabled());
                } catch (Exception e) {
                    System.out.println("   Failed to toggle policy: " + e.getMessage());
                }
            }

            // 6. Get effective dynamic policies
            System.out.println("\n6. Getting effective dynamic policies...");
            try {
                List<DynamicPolicy> effective = client.getEffectiveDynamicPolicies();
                System.out.println("   Found " + effective.size() + " effective dynamic policies");
            } catch (Exception e) {
                System.out.println("   Failed to get effective policies: " + e.getMessage());
            }

            // 7. Delete the test policy (cleanup)
            if (createdPolicy != null) {
                System.out.println("\n7. Cleaning up - deleting test policy...");
                try {
                    client.deleteDynamicPolicy(createdPolicy.getId());
                    System.out.println("   Policy deleted successfully");
                } catch (Exception e) {
                    System.out.println("   Failed to delete policy: " + e.getMessage());
                }
            }

            System.out.println("\n=== Dynamic Policy Example Complete ===");
        }
    }
}
