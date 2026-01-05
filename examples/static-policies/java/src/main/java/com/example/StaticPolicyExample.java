/**
 * AxonFlow Static Policy Management - Java SDK (Comprehensive)
 *
 * This example demonstrates ALL static policy SDK methods:
 * - listStaticPolicies
 * - getStaticPolicy
 * - createStaticPolicy
 * - updateStaticPolicy
 * - deleteStaticPolicy
 * - toggleStaticPolicy
 * - testPattern
 * - getStaticPolicyVersions
 * - getEffectiveStaticPolicies
 *
 * Run with: mvn compile exec:java
 * Prerequisites: docker compose up -d
 */

package com.example;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.policies.PolicyTypes.*;

import java.util.Arrays;
import java.util.List;

public class StaticPolicyExample {

    private static String getEnv(String key, String defaultVal) {
        String val = System.getenv(key);
        return val != null && !val.isEmpty() ? val : defaultVal;
    }

    public static void main(String[] args) {
        System.out.println("AxonFlow Static Policy Management - Java SDK");
        System.out.println("=============================================");
        System.out.println();

        // Create AxonFlow client
        // Note: As of SDK v2.0.0 (ADR-026), all routes go through a single endpoint.
        // The Agent proxies orchestrator routes internally.
        AxonFlowConfig config = AxonFlowConfig.builder()
                .endpoint(getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080"))
                .clientId(getEnv("AXONFLOW_CLIENT_ID", "demo-client"))
                .clientSecret(getEnv("AXONFLOW_CLIENT_SECRET", "demo-secret"))
                .build();

        AxonFlow client = AxonFlow.create(config);

        // Unique name for our test policy
        String policyName = "demo-custom-policy-" + System.currentTimeMillis();
        String policyId = null;

        try {
            // ========================================
            // 1. LIST STATIC POLICIES
            // ========================================
            System.out.println("1. listStaticPolicies - Listing all static policies...");
            try {
                List<StaticPolicy> policies = client.listStaticPolicies(
                        ListStaticPoliciesOptions.builder().limit(10).build()
                );
                System.out.println("   Found " + policies.size() + " policies");
                for (int i = 0; i < Math.min(3, policies.size()); i++) {
                    StaticPolicy p = policies.get(i);
                    String status = p.isEnabled() ? "enabled" : "disabled";
                    System.out.println("   - " + p.getName() + ": " + p.getCategory() + " (" + status + ")");
                }
                if (policies.size() > 3) {
                    System.out.println("   ... and " + (policies.size() - 3) + " more");
                }
            } catch (Exception e) {
                System.out.println("   ERROR: " + e.getMessage());
            }
            System.out.println();

            // ========================================
            // 2. LIST BY CATEGORY
            // ========================================
            System.out.println("2. listStaticPolicies - Filtering by category...");
            try {
                List<StaticPolicy> sqliPolicies = client.listStaticPolicies(
                        PolicyCategory.SECURITY_SQLI
                );
                System.out.println("   Found " + sqliPolicies.size() + " SQL injection policies");
                for (int i = 0; i < Math.min(3, sqliPolicies.size()); i++) {
                    StaticPolicy p = sqliPolicies.get(i);
                    System.out.println("   - " + p.getName() + ": severity=" + p.getSeverity());
                }
            } catch (Exception e) {
                System.out.println("   ERROR: " + e.getMessage());
            }
            System.out.println();

            // ========================================
            // 3. CREATE STATIC POLICY
            // ========================================
            // Using CODE_SECRETS category - appropriate for custom tenant policies
            // that detect sensitive patterns in generated code.
            System.out.println("3. createStaticPolicy - Creating a custom policy...");
            try {
                CreateStaticPolicyRequest createReq = CreateStaticPolicyRequest.builder()
                        .name(policyName)
                        .description("Demo policy for SDK testing - detects test secrets in code")
                        .category(PolicyCategory.CODE_SECRETS)
                        .tier(PolicyTier.TENANT)
                        .pattern("(?i)test_secret_\\d+")
                        .severity(PolicySeverity.MEDIUM)
                        .enabled(true)
                        .action(PolicyAction.WARN)
                        .build();

                StaticPolicy created = client.createStaticPolicy(createReq);
                policyId = created.getId();
                System.out.println("   Created: " + created.getName());
                System.out.println("   ID: " + created.getId());
                System.out.println("   Category: " + created.getCategory());
                System.out.println("   Action: " + created.getAction());
            } catch (Exception e) {
                System.out.println("   ERROR: " + e.getMessage());
                return;
            }
            System.out.println();

            // ========================================
            // 4. GET STATIC POLICY
            // ========================================
            System.out.println("4. getStaticPolicy - Retrieving policy by ID...");
            try {
                StaticPolicy retrieved = client.getStaticPolicy(policyId);
                System.out.println("   Retrieved: " + retrieved.getName());
                System.out.println("   Pattern: " + retrieved.getPattern());
                System.out.println("   Enabled: " + retrieved.isEnabled());
                System.out.println("   Version: " + (retrieved.getVersion() != null ? retrieved.getVersion() : 1));
            } catch (Exception e) {
                System.out.println("   ERROR: " + e.getMessage());
            }
            System.out.println();

            // ========================================
            // 5. TEST PATTERN
            // ========================================
            System.out.println("5. testPattern - Testing regex pattern...");
            try {
                List<String> testInputs = Arrays.asList(
                        "test_secret_123",       // Should match
                        "test_secret_abc",       // Should NOT match (no digits)
                        "TEST_SECRET_999",       // Should match (case insensitive)
                        "normal text",           // Should NOT match
                        "my test_secret_42 data" // Should match
                );

                TestPatternResult result = client.testPattern("(?i)test_secret_\\d+", testInputs);
                System.out.println("   Pattern valid: " + result.isValid());
                System.out.println("   Match results:");
                for (TestPatternMatch match : result.getMatches()) {
                    String status = match.isMatched() ? "MATCH" : "NO MATCH";
                    System.out.println("     [" + status + "] " + match.getInput());
                }
            } catch (Exception e) {
                System.out.println("   ERROR: " + e.getMessage());
            }
            System.out.println();

            // ========================================
            // 6. UPDATE STATIC POLICY
            // ========================================
            System.out.println("6. updateStaticPolicy - Updating policy...");
            try {
                UpdateStaticPolicyRequest updateReq = UpdateStaticPolicyRequest.builder()
                        .description("Updated description - now with stricter severity")
                        .severity(PolicySeverity.HIGH)
                        .action(PolicyAction.BLOCK)
                        .build();

                StaticPolicy updated = client.updateStaticPolicy(policyId, updateReq);
                System.out.println("   Updated: " + updated.getName());
                System.out.println("   New severity: " + updated.getSeverity());
                System.out.println("   New action: " + updated.getAction());
                System.out.println("   New version: " + (updated.getVersion() != null ? updated.getVersion() : 2));
            } catch (Exception e) {
                System.out.println("   ERROR: " + e.getMessage());
            }
            System.out.println();

            // ========================================
            // 7. GET POLICY VERSIONS
            // ========================================
            System.out.println("7. getStaticPolicyVersions - Getting version history...");
            try {
                List<PolicyVersion> versions = client.getStaticPolicyVersions(policyId);
                System.out.println("   Found " + versions.size() + " versions");
                for (PolicyVersion v : versions) {
                    System.out.println("   - v" + v.getVersion() + ": " + v.getChangeType() + " at " + v.getChangedAt());
                }
            } catch (Exception e) {
                System.out.println("   Note: Version history may require Enterprise: " + e.getMessage());
            }
            System.out.println();

            // ========================================
            // 8. TOGGLE STATIC POLICY
            // ========================================
            System.out.println("8. toggleStaticPolicy - Disabling policy...");
            try {
                StaticPolicy toggled = client.toggleStaticPolicy(policyId, false);
                System.out.println("   Policy: " + toggled.getName());
                System.out.println("   Enabled: " + toggled.isEnabled());
                System.out.println();

                System.out.println("   Enabling policy again...");
                toggled = client.toggleStaticPolicy(policyId, true);
                System.out.println("   Enabled: " + toggled.isEnabled());
            } catch (Exception e) {
                System.out.println("   ERROR: " + e.getMessage());
            }
            System.out.println();

            // ========================================
            // 9. GET EFFECTIVE POLICIES
            // ========================================
            System.out.println("9. getEffectiveStaticPolicies - Getting effective policies...");
            try {
                List<StaticPolicy> effective = client.getEffectiveStaticPolicies();
                System.out.println("   Found " + effective.size() + " effective policies");

                String finalPolicyId = policyId;
                StaticPolicy ourPolicy = effective.stream()
                        .filter(p -> p.getId().equals(finalPolicyId))
                        .findFirst()
                        .orElse(null);

                if (ourPolicy != null) {
                    System.out.println("   Our policy is effective: " + ourPolicy.getName());
                } else {
                    System.out.println("   Our policy is not in the effective list (may be disabled)");
                }
            } catch (Exception e) {
                System.out.println("   ERROR: " + e.getMessage());
            }
            System.out.println();

            // ========================================
            // 10. DELETE STATIC POLICY
            // ========================================
            System.out.println("10. deleteStaticPolicy - Cleaning up...");
            try {
                client.deleteStaticPolicy(policyId);
                System.out.println("   Deleted policy: " + policyName);
                policyId = null; // Mark as deleted
            } catch (Exception e) {
                System.out.println("   WARNING: Failed to delete policy: " + e.getMessage());
            }
            System.out.println();

            System.out.println("=============================================");
            System.out.println("All 10 Static Policy SDK methods tested!");
            System.out.println();
            System.out.println("Methods demonstrated:");
            System.out.println("  1. listStaticPolicies()           - List with filtering");
            System.out.println("  2. listStaticPolicies(category)   - Filter by category");
            System.out.println("  3. createStaticPolicy()           - Create new policy");
            System.out.println("  4. getStaticPolicy()              - Get by ID");
            System.out.println("  5. testPattern()                  - Test regex pattern");
            System.out.println("  6. updateStaticPolicy()           - Update policy");
            System.out.println("  7. getStaticPolicyVersions()      - Version history");
            System.out.println("  8. toggleStaticPolicy()           - Enable/disable");
            System.out.println("  9. getEffectiveStaticPolicies()   - Effective policies");
            System.out.println(" 10. deleteStaticPolicy()           - Delete policy");

        } finally {
            // Cleanup if policy wasn't deleted
            if (policyId != null) {
                try {
                    client.deleteStaticPolicy(policyId);
                    System.out.println("\nCleanup: Deleted policy " + policyName);
                } catch (Exception ignored) {
                }
            }
            client.close();
        }
    }
}
