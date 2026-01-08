/**
 * Compliance Policy Examples - Java
 *
 * Demonstrates using allowed_providers in dynamic policies for:
 *   - GDPR: EU data sovereignty
 *   - HIPAA: Healthcare data protection
 *   - RBI: India financial data sovereignty
 *
 * SDK Methods demonstrated:
 *   - createDynamicPolicy() with actions containing allowed_providers config
 *   - listDynamicPolicies()
 *   - deleteDynamicPolicy()
 *
 * Usage:
 *   mvn exec:java -Dexec.mainClass="com.example.CompliancePolicyExample"
 *
 * Environment:
 *   AXONFLOW_ENDPOINT      - Agent URL (default: http://localhost:8080)
 *   AXONFLOW_CLIENT_ID     - Client ID for authentication
 *   AXONFLOW_CLIENT_SECRET - Client secret (required for dynamic policies)
 */

package com.example;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.policies.PolicyTypes.DynamicPolicy;
import com.getaxonflow.sdk.types.policies.PolicyTypes.CreateDynamicPolicyRequest;
import com.getaxonflow.sdk.types.policies.PolicyTypes.DynamicPolicyAction;
import com.getaxonflow.sdk.types.policies.PolicyTypes.DynamicPolicyCondition;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CompliancePolicyExample {

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

        AxonFlow client = AxonFlow.create(AxonFlowConfig.builder()
            .endpoint(endpoint)
            .clientId(clientId)
            .clientSecret(clientSecret)
            .build());

        System.out.println("=== Compliance Policy Examples ===\n");

        List<String> createdPolicies = new ArrayList<>();

        // 1. GDPR - EU Data Sovereignty
        System.out.println("1. Creating GDPR policy for EU data sovereignty...");
        try {
            List<DynamicPolicyCondition> gdprConditions = Arrays.asList(
                new DynamicPolicyCondition("user_region", "equals", "EU")
            );

            Map<String, Object> routeConfig = new HashMap<>();
            routeConfig.put("allowed_providers", Arrays.asList("ollama", "azure-eu"));

            List<DynamicPolicyAction> gdprActions = Arrays.asList(
                new DynamicPolicyAction("route", routeConfig)
            );

            CreateDynamicPolicyRequest gdprRequest = CreateDynamicPolicyRequest.builder()
                .name("gdpr-eu-data-sovereignty")
                .description("Route EU users to EU-hosted LLMs only (GDPR Article 44)")
                .type("content")
                .category("dynamic-compliance")
                .conditions(gdprConditions)
                .actions(gdprActions)
                .enabled(true)
                .build();

            DynamicPolicy gdprPolicy = client.createDynamicPolicy(gdprRequest);
            System.out.println("   Created: " + gdprPolicy.getName() + " (ID: " + gdprPolicy.getId() + ")");
            printAllowedProviders(gdprPolicy.getActions());
            createdPolicies.add(gdprPolicy.getId());
        } catch (Exception e) {
            System.out.println("   Failed to create GDPR policy: " + e.getMessage());
        }

        // 2. HIPAA - Healthcare Data Protection
        System.out.println("\n2. Creating HIPAA policy for PHI protection...");
        try {
            List<DynamicPolicyCondition> hipaaConditions = Arrays.asList(
                new DynamicPolicyCondition("request_type", "equals", "healthcare"),
                new DynamicPolicyCondition("contains_phi", "equals", true)
            );

            Map<String, Object> hipaaRouteConfig = new HashMap<>();
            hipaaRouteConfig.put("allowed_providers", Arrays.asList("ollama"));

            List<DynamicPolicyAction> hipaaActions = Arrays.asList(
                new DynamicPolicyAction("route", hipaaRouteConfig)
            );

            CreateDynamicPolicyRequest hipaaRequest = CreateDynamicPolicyRequest.builder()
                .name("hipaa-phi-protection")
                .description("Route PHI queries to local LLM only (HIPAA Safe Harbor)")
                .type("content")
                .category("dynamic-compliance")
                .conditions(hipaaConditions)
                .actions(hipaaActions)
                .enabled(true)
                .build();

            DynamicPolicy hipaaPolicy = client.createDynamicPolicy(hipaaRequest);
            System.out.println("   Created: " + hipaaPolicy.getName() + " (ID: " + hipaaPolicy.getId() + ")");
            printAllowedProviders(hipaaPolicy.getActions());
            createdPolicies.add(hipaaPolicy.getId());
        } catch (Exception e) {
            System.out.println("   Failed to create HIPAA policy: " + e.getMessage());
        }

        // 3. RBI - India Financial Data Sovereignty
        System.out.println("\n3. Creating RBI policy for financial data sovereignty...");
        try {
            List<DynamicPolicyCondition> rbiConditions = Arrays.asList(
                new DynamicPolicyCondition("request_type", "equals", "banking"),
                new DynamicPolicyCondition("user_region", "equals", "IN")
            );

            Map<String, Object> rbiRouteConfig = new HashMap<>();
            rbiRouteConfig.put("allowed_providers", Arrays.asList("azure-india", "ollama"));

            List<DynamicPolicyAction> rbiActions = Arrays.asList(
                new DynamicPolicyAction("route", rbiRouteConfig)
            );

            CreateDynamicPolicyRequest rbiRequest = CreateDynamicPolicyRequest.builder()
                .name("rbi-financial-data-sovereignty")
                .description("Route banking queries to India-hosted providers (RBI Data Localization)")
                .type("content")
                .category("dynamic-compliance")
                .conditions(rbiConditions)
                .actions(rbiActions)
                .enabled(true)
                .build();

            DynamicPolicy rbiPolicy = client.createDynamicPolicy(rbiRequest);
            System.out.println("   Created: " + rbiPolicy.getName() + " (ID: " + rbiPolicy.getId() + ")");
            printAllowedProviders(rbiPolicy.getActions());
            createdPolicies.add(rbiPolicy.getId());
        } catch (Exception e) {
            System.out.println("   Failed to create RBI policy: " + e.getMessage());
        }

        // 4. List all compliance policies
        System.out.println("\n4. Listing all compliance policies...");
        try {
            List<DynamicPolicy> policies = client.listDynamicPolicies(null);
            int complianceCount = 0;
            for (DynamicPolicy p : policies) {
                List<Object> providers = getAllowedProviders(p.getActions());
                if (providers != null && !providers.isEmpty()) {
                    complianceCount++;
                    System.out.println("   - " + p.getName() + ": providers=" + providers);
                }
            }
            System.out.println("   Found " + complianceCount + " policies with provider restrictions");
        } catch (Exception e) {
            System.out.println("   Failed to list policies: " + e.getMessage());
        }

        // 5. Cleanup
        System.out.println("\n5. Cleaning up test policies...");
        for (String policyId : createdPolicies) {
            try {
                client.deleteDynamicPolicy(policyId);
            } catch (Exception e) {
                System.out.println("   Failed to delete " + policyId + ": " + e.getMessage());
            }
        }
        System.out.println("   Deleted " + createdPolicies.size() + " test policies");

        System.out.println("\n=== Compliance Policy Examples Complete ===");
    }

    /**
     * Prints allowed_providers from action config.
     */
    private static void printAllowedProviders(List<DynamicPolicyAction> actions) {
        if (actions == null) return;
        for (DynamicPolicyAction action : actions) {
            if (action.getConfig() != null && action.getConfig().containsKey("allowed_providers")) {
                System.out.println("   Allowed providers: " + action.getConfig().get("allowed_providers"));
                return;
            }
        }
    }

    /**
     * Extracts allowed_providers from action config.
     */
    @SuppressWarnings("unchecked")
    private static List<Object> getAllowedProviders(List<DynamicPolicyAction> actions) {
        if (actions == null) return null;
        for (DynamicPolicyAction action : actions) {
            if (action.getConfig() != null && action.getConfig().containsKey("allowed_providers")) {
                Object providers = action.getConfig().get("allowed_providers");
                if (providers instanceof List) {
                    return (List<Object>) providers;
                }
            }
        }
        return null;
    }
}
