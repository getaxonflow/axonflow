package com.getaxonflow.examples.policies;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.policies.PolicyTypes.ListStaticPoliciesOptions;
import com.getaxonflow.sdk.types.policies.PolicyTypes.PolicyCategory;
import com.getaxonflow.sdk.types.policies.PolicyTypes.PolicyTier;
import com.getaxonflow.sdk.types.policies.PolicyTypes.StaticPolicy;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * AxonFlow Policy Management - List and Filter Policies
 *
 * This example demonstrates how to:
 * - List all static policies
 * - Filter policies by category, tier, and status
 * - Get effective policies with tier inheritance
 */
public class ListAndFilter {

    public static void main(String[] args) {
        String endpoint = System.getenv("AXONFLOW_ENDPOINT");
        if (endpoint == null || endpoint.isEmpty()) {
            endpoint = "http://localhost:8080";
        }

        AxonFlowConfig config = AxonFlowConfig.builder()
            .agentUrl(endpoint)
            .clientId("test-org-001")  // Used as tenant ID
            .build();

        AxonFlow axonflow = AxonFlow.create(config);

        System.out.println("AxonFlow Policy Management - List and Filter");
        System.out.println("============================================================");

        try {
            // 1. List all policies
            System.out.println("\n1. Listing all policies...");

            List<StaticPolicy> allPolicies = axonflow.listStaticPolicies();
            System.out.println("   Total: " + allPolicies.size() + " policies");

            // Group by category for summary
            Map<String, Integer> byCategory = new HashMap<>();
            for (StaticPolicy p : allPolicies) {
                String cat = p.getCategory().getValue();
                byCategory.put(cat, byCategory.getOrDefault(cat, 0) + 1);
            }
            System.out.println("\n   By category:");
            byCategory.forEach((cat, count) ->
                System.out.println("     " + cat + ": " + count));

            // 2. Filter by category - SQL Injection policies
            System.out.println("\n2. Filtering by category (security-sqli)...");

            ListStaticPoliciesOptions sqliOptions = ListStaticPoliciesOptions.builder()
                .category(PolicyCategory.SECURITY_SQLI)
                .build();
            List<StaticPolicy> sqliPolicies = axonflow.listStaticPolicies(sqliOptions);
            System.out.println("   Found: " + sqliPolicies.size() + " SQLi policies");

            // Show first 3
            int count = 0;
            for (StaticPolicy p : sqliPolicies) {
                if (count >= 3) {
                    System.out.println("     ... and " + (sqliPolicies.size() - 3) + " more");
                    break;
                }
                System.out.println("     - " + p.getName() + " (severity: " + p.getSeverity().getValue() + ")");
                count++;
            }

            // 3. Filter by tier - System policies
            System.out.println("\n3. Filtering by tier (system)...");

            ListStaticPoliciesOptions systemOptions = ListStaticPoliciesOptions.builder()
                .tier(PolicyTier.SYSTEM)
                .build();
            List<StaticPolicy> systemPolicies = axonflow.listStaticPolicies(systemOptions);
            System.out.println("   Found: " + systemPolicies.size() + " system policies");

            // 4. Filter by enabled status
            System.out.println("\n4. Filtering by enabled status...");

            ListStaticPoliciesOptions enabledOptions = ListStaticPoliciesOptions.builder()
                .enabled(true)
                .build();
            List<StaticPolicy> enabledPolicies = axonflow.listStaticPolicies(enabledOptions);

            ListStaticPoliciesOptions disabledOptions = ListStaticPoliciesOptions.builder()
                .enabled(false)
                .build();
            List<StaticPolicy> disabledPolicies = axonflow.listStaticPolicies(disabledOptions);

            System.out.println("   Enabled: " + enabledPolicies.size());
            System.out.println("   Disabled: " + disabledPolicies.size());

            // 5. Combine filters
            System.out.println("\n5. Combining filters (enabled PII policies)...");

            ListStaticPoliciesOptions piiEnabledOptions = ListStaticPoliciesOptions.builder()
                .category(PolicyCategory.PII_GLOBAL)
                .enabled(true)
                .build();
            List<StaticPolicy> piiEnabled = axonflow.listStaticPolicies(piiEnabledOptions);
            System.out.println("   Found: " + piiEnabled.size() + " enabled PII policies");

            count = 0;
            for (StaticPolicy p : piiEnabled) {
                if (count >= 5) break;
                String pattern = p.getPattern();
                if (pattern.length() > 40) {
                    pattern = pattern.substring(0, 40) + "...";
                }
                System.out.println("     - " + p.getName() + ": " + pattern);
                count++;
            }

            // 6. Get effective policies (includes tier inheritance)
            System.out.println("\n6. Getting effective policies...");

            List<StaticPolicy> effective = axonflow.getEffectiveStaticPolicies();
            System.out.println("   Effective total: " + effective.size() + " policies");

            // Group by tier
            Map<String, Integer> byTier = new HashMap<>();
            for (StaticPolicy p : effective) {
                String tier = p.getTier().getValue();
                byTier.put(tier, byTier.getOrDefault(tier, 0) + 1);
            }
            System.out.println("\n   By tier (effective):");
            byTier.forEach((tier, cnt) ->
                System.out.println("     " + tier + ": " + cnt));

            // 7. Pagination example
            System.out.println("\n7. Pagination example...");

            ListStaticPoliciesOptions page1Options = ListStaticPoliciesOptions.builder()
                .limit(5)
                .offset(0)
                .build();
            List<StaticPolicy> page1 = axonflow.listStaticPolicies(page1Options);

            ListStaticPoliciesOptions page2Options = ListStaticPoliciesOptions.builder()
                .limit(5)
                .offset(5)
                .build();
            List<StaticPolicy> page2 = axonflow.listStaticPolicies(page2Options);

            System.out.println("   Page 1: " + page1.size() + " policies");
            System.out.println("   Page 2: " + page2.size() + " policies");

            // 8. Sorting
            System.out.println("\n8. Sorting by severity (descending)...");

            ListStaticPoliciesOptions sortOptions = ListStaticPoliciesOptions.builder()
                .sortBy("severity")
                .sortOrder("desc")
                .limit(5)
                .build();
            List<StaticPolicy> bySeverity = axonflow.listStaticPolicies(sortOptions);

            System.out.println("   Top 5 by severity:");
            for (StaticPolicy p : bySeverity) {
                System.out.println("     [" + p.getSeverity().getValue() + "] " + p.getName());
            }

            System.out.println("\n============================================================");
            System.out.println("Example completed successfully!");

        } catch (Exception e) {
            System.err.println("\nError: " + e.getMessage());
            System.exit(1);
        }
    }
}
