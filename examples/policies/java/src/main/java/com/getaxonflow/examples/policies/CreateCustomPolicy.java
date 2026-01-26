package com.getaxonflow.examples.policies;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.policies.PolicyTypes.CreateStaticPolicyRequest;
import com.getaxonflow.sdk.types.policies.PolicyTypes.PolicyCategory;
import com.getaxonflow.sdk.types.policies.PolicyTypes.PolicySeverity;
import com.getaxonflow.sdk.types.policies.PolicyTypes.StaticPolicy;
import com.getaxonflow.sdk.types.policies.PolicyTypes.TestPatternResult;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * AxonFlow Policy Management - Create Custom Policy
 *
 * This example demonstrates how to create a custom static policy
 * using the AxonFlow Java SDK.
 *
 * Static policies are pattern-based rules that detect:
 * - PII (personally identifiable information)
 * - SQL injection attempts
 * - Sensitive data patterns
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 */
public class CreateCustomPolicy {

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
        // Initialize the client
        // For self-hosted Community, no auth needed when running locally
        String endpoint = System.getenv("AXONFLOW_ENDPOINT");
        if (endpoint == null || endpoint.isEmpty()) {
            endpoint = "http://localhost:8080";
        }

        AxonFlowConfig config = AxonFlowConfig.builder()
            .endpoint(endpoint)
            .clientId("test-org-001")  // Used as tenant ID
            .build();

        AxonFlow axonflow = AxonFlow.create(config);

        System.out.println("AxonFlow Policy Management - Create Custom Policy");
        System.out.println("============================================================");

        try {
            // Create a custom PII detection policy
            // This policy detects email addresses from a specific domain
            System.out.println("\n1. Creating custom email detection policy...");

            CreateStaticPolicyRequest request = CreateStaticPolicyRequest.builder()
                .name("Custom Email Pattern")
                .description("Detects email addresses in specific company format")
                .category(PolicyCategory.PII_GLOBAL)
                .pattern("[a-zA-Z0-9._%+-]+@company\\.com")
                .severity(PolicySeverity.MEDIUM)
                .enabled(true)
                .build();

            StaticPolicy policy = axonflow.createStaticPolicy(request);

            System.out.println("   Created policy: " + policy.getId());
            System.out.println("   Name: " + policy.getName());
            System.out.println("   Tier: " + policy.getTier());  // Will be 'tenant' for custom policies
            System.out.println("   Category: " + policy.getCategory());
            System.out.println("   Pattern: " + policy.getPattern());

            assertCheck(policy.getId() != null && !policy.getId().isEmpty(), "Policy created with ID");
            assertCheck("Custom Email Pattern".equals(policy.getName()), "Policy name matches");
            assertCheck(policy.getPattern() != null, "Policy has pattern");

            // Test the pattern before using in production
            System.out.println("\n2. Testing the pattern...");

            List<String> testInputs = Arrays.asList(
                "john@company.com",
                "jane@gmail.com",
                "test@company.com",
                "invalid-email"
            );

            TestPatternResult testResult = axonflow.testPattern(policy.getPattern(), testInputs);

            System.out.println("   Pattern valid: " + testResult.isValid());
            System.out.println("\n   Test results:");

            testResult.getMatches().forEach(match -> {
                String icon = match.isMatched() ? "\u2713" : "\u2717";
                String suffix = match.isMatched() ? "-> MATCH" : "";
                System.out.printf("   %s \"%s\" %s%n", icon, match.getInput(), suffix);
            });

            assertCheck(testResult.isValid(), "Pattern is valid regex");
            // Verify john@company.com matches and jane@gmail.com doesn't
            long matchCount = testResult.getMatches().stream().filter(m -> m.isMatched()).count();
            assertCheck(matchCount == 2, "Pattern matches exactly 2 company emails (john@company.com, test@company.com)");

            // Retrieve the created policy
            System.out.println("\n3. Retrieving created policy...");

            StaticPolicy retrieved = axonflow.getStaticPolicy(policy.getId());
            System.out.println("   Retrieved: " + retrieved.getName());
            System.out.println("   Version: " + (retrieved.getVersion() != null ? retrieved.getVersion() : 1));

            assertCheck(retrieved.getId().equals(policy.getId()), "Retrieved policy ID matches");
            assertCheck(retrieved.getName().equals(policy.getName()), "Retrieved policy name matches");

            // Clean up - delete the test policy
            System.out.println("\n4. Cleaning up (deleting test policy)...");
            axonflow.deleteStaticPolicy(policy.getId());
            System.out.println("   Deleted successfully");
            assertCheck(true, "Policy deleted successfully");

            System.out.println("\n============================================================");
            System.out.println("Example completed successfully!");

        } catch (Exception e) {
            System.err.println("\nError: " + e.getMessage());

            // Provide helpful error messages
            if (e.getMessage() != null && e.getMessage().contains("Connection refused")) {
                System.err.println("\nHint: Make sure AxonFlow is running:");
                System.err.println("  docker compose up -d");
            }
            failures.add("Exception: " + e.getMessage());
        }

        // Final assertion check
        if (!failures.isEmpty()) {
            System.out.println();
            System.out.println("FAILURES (" + failures.size() + "):");
            for (String failure : failures) {
                System.out.println("  - " + failure);
            }
            System.exit(1);
        }
    }
}
