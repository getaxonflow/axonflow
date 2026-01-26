/*
 * Dynamic Policy Management Example - Java
 *
 * Demonstrates CRUD operations for dynamic policies (LLM-powered policies).
 * Dynamic policies use conditions and actions to evaluate complex, context-aware
 * rules that can't be expressed with simple regex patterns.
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
 *   AXONFLOW_ENDPOINT      - Agent URL (default: http://localhost:8080)
 *   AXONFLOW_CLIENT_ID     - Client ID for authentication
 *   AXONFLOW_CLIENT_SECRET - Client secret (optional for community mode)
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 */

package com.example;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.policies.PolicyTypes.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class DynamicPolicyExample {
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
        // Initialize client
        String endpoint = System.getenv("AXONFLOW_ENDPOINT");
        if (endpoint == null || endpoint.isEmpty()) {
            endpoint = "http://localhost:8080";
        }
        String clientId = System.getenv("AXONFLOW_CLIENT_ID");
        if (clientId == null || clientId.isEmpty()) {
            clientId = "demo-tenant";
        }
        String clientSecret = System.getenv("AXONFLOW_CLIENT_SECRET");

        DynamicPolicy createdPolicy = null;
        AxonFlow client = AxonFlow.create(AxonFlowConfig.builder()
            .endpoint(endpoint)
            .clientId(clientId)
            .clientSecret(clientSecret)
            .build());

        try {
            System.out.println("=== Dynamic Policy Management Example ===\n");

            // 1. List existing dynamic policies
            System.out.println("1. Listing existing dynamic policies...");
            try {
                List<DynamicPolicy> policies = client.listDynamicPolicies();
                System.out.println("   Found " + policies.size() + " dynamic policies");
                for (DynamicPolicy p : policies) {
                    System.out.println("   - " + p.getId() + ": " + p.getName() +
                        " (type: " + p.getType() + ", enabled: " + p.isEnabled() + ")");
                }
                assertCheck(policies != null, "listDynamicPolicies returned list");
            } catch (Exception e) {
                System.out.println("   Failed to list policies: " + e.getMessage());
                assertCheck(false, "listDynamicPolicies failed: " + e.getMessage());
            }

            // 2. Create a new dynamic policy
            System.out.println("\n2. Creating a new dynamic policy...");
            try {
                CreateDynamicPolicyRequest request = CreateDynamicPolicyRequest.builder()
                    .name("high-risk-block")
                    .description("Block requests with high risk scores")
                    .type("risk")
                    .category("dynamic-risk")
                    .conditions(List.of(
                        new DynamicPolicyCondition("risk_score", "greater_than", 0.8)
                    ))
                    .actions(List.of(
                        new DynamicPolicyAction("block", Map.of("reason", "High risk detected"))
                    ))
                    .priority(100)
                    .enabled(true)
                    .build();

                createdPolicy = client.createDynamicPolicy(request);
                System.out.println("   Created policy: " + createdPolicy.getName() +
                    " (ID: " + createdPolicy.getId() + ")");
                assertCheck(createdPolicy != null, "createDynamicPolicy returned policy");
                assertCheck(createdPolicy.getId() != null, "Created policy has ID");
                assertCheck("high-risk-block".equals(createdPolicy.getName()), "Policy name matches");
            } catch (Exception e) {
                System.out.println("   Failed to create policy: " + e.getMessage());
                assertCheck(false, "createDynamicPolicy failed: " + e.getMessage());
            }

            // 3. Get the policy by ID
            if (createdPolicy != null) {
                System.out.println("\n3. Getting policy by ID...");
                try {
                    DynamicPolicy policy = client.getDynamicPolicy(createdPolicy.getId());
                    System.out.println("   Policy: " + policy.getName());
                    System.out.println("   Description: " + policy.getDescription());
                    System.out.println("   Type: " + policy.getType());
                    System.out.println("   Priority: " + policy.getPriority());
                    System.out.println("   Conditions: " + (policy.getConditions() != null ? policy.getConditions().size() : 0));
                    System.out.println("   Actions: " + (policy.getActions() != null ? policy.getActions().size() : 0));
                    assertCheck(policy != null, "getDynamicPolicy returned policy");
                    assertCheck(createdPolicy.getId().equals(policy.getId()), "Retrieved policy ID matches");
                    assertCheck(policy.getConditions() != null && policy.getConditions().size() == 1, "Policy has 1 condition");
                    assertCheck(policy.getActions() != null && policy.getActions().size() == 1, "Policy has 1 action");
                } catch (Exception e) {
                    System.out.println("   Failed to get policy: " + e.getMessage());
                    assertCheck(false, "getDynamicPolicy failed: " + e.getMessage());
                }
            }

            // 4. Update the policy
            if (createdPolicy != null) {
                System.out.println("\n4. Updating policy description...");
                try {
                    UpdateDynamicPolicyRequest update = UpdateDynamicPolicyRequest.builder()
                        .description("Block requests with risk scores above threshold (0.8)")
                        .build();
                    DynamicPolicy updated = client.updateDynamicPolicy(createdPolicy.getId(), update);
                    System.out.println("   Updated description: " + updated.getDescription());
                    assertCheck(updated != null, "updateDynamicPolicy returned updated policy");
                    assertCheck(updated.getDescription().contains("0.8"), "Description updated correctly");
                } catch (Exception e) {
                    System.out.println("   Failed to update policy: " + e.getMessage());
                    assertCheck(false, "updateDynamicPolicy failed: " + e.getMessage());
                }
            }

            // 5. Toggle policy (disable it)
            if (createdPolicy != null) {
                System.out.println("\n5. Toggling policy (disabling)...");
                try {
                    DynamicPolicy toggled = client.toggleDynamicPolicy(createdPolicy.getId(), false);
                    System.out.println("   Policy enabled: " + toggled.isEnabled());
                    assertCheck(toggled != null, "toggleDynamicPolicy returned policy");
                    assertCheck(!toggled.isEnabled(), "Policy is now disabled");
                } catch (Exception e) {
                    System.out.println("   Failed to toggle policy: " + e.getMessage());
                    assertCheck(false, "toggleDynamicPolicy failed: " + e.getMessage());
                }
            }

            // 6. Get effective dynamic policies
            System.out.println("\n6. Getting effective dynamic policies...");
            try {
                List<DynamicPolicy> effective = client.getEffectiveDynamicPolicies();
                System.out.println("   Found " + effective.size() + " effective dynamic policies");
                assertCheck(effective != null, "getEffectiveDynamicPolicies returned list");
            } catch (Exception e) {
                System.out.println("   Failed to get effective policies: " + e.getMessage());
                assertCheck(false, "getEffectiveDynamicPolicies failed: " + e.getMessage());
            }

            // 7. Delete the test policy (cleanup)
            if (createdPolicy != null) {
                System.out.println("\n7. Cleaning up - deleting test policy...");
                try {
                    client.deleteDynamicPolicy(createdPolicy.getId());
                    System.out.println("   Policy deleted successfully");
                    assertCheck(true, "deleteDynamicPolicy completed successfully");
                } catch (Exception e) {
                    System.out.println("   Failed to delete policy: " + e.getMessage());
                    assertCheck(false, "deleteDynamicPolicy failed: " + e.getMessage());
                }
            }

            System.out.println("\n=== Dynamic Policy Example Complete ===");

            // Final assertion summary
            System.out.println();
            System.out.println("=".repeat(45));
            System.out.println("Assertion Summary");
            System.out.println("=".repeat(45));
            if (failures.isEmpty()) {
                System.out.println("All assertions passed!");
            } else {
                System.out.println("Failures (" + failures.size() + "):");
                for (String f : failures) {
                    System.out.println("  - " + f);
                }
                System.exit(1);
            }
        } catch (Exception e) {
            System.err.println("Unexpected error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
