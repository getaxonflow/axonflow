package com.axonflow.examples.hitl;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.policies.PolicyTypes.*;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * AxonFlow HITL - Create Policy with require_approval Action
 *
 * This example demonstrates how to create a policy that triggers
 * Human-in-the-Loop (HITL) approval using the {@code require_approval} action.
 *
 * The {@code require_approval} action:
 * <ul>
 *   <li>Enterprise: Pauses execution and creates an approval request in the HITL queue</li>
 *   <li>Community: Auto-approves immediately (upgrade path to Enterprise)</li>
 * </ul>
 *
 * Use cases:
 * <ul>
 *   <li>High-value transaction oversight (EU AI Act Article 14, SEBI AI/ML)</li>
 *   <li>Admin access detection</li>
 *   <li>Sensitive data access control</li>
 * </ul>
 */
public class RequireApprovalPolicy {

    public static void main(String[] args) {
        // Initialize the client
        String agentUrl = System.getenv("AXONFLOW_AGENT_URL");
        if (agentUrl == null || agentUrl.isEmpty()) {
            agentUrl = "http://localhost:8080";
        }
        String clientId = System.getenv("AXONFLOW_CLIENT_ID");
        if (clientId == null || clientId.isEmpty()) {
            clientId = "demo-tenant";
        }

        AxonFlowConfig config = AxonFlowConfig.builder()
                .agentUrl(agentUrl)
                .clientId(clientId)
                .build();

        try (AxonFlow client = AxonFlow.create(config)) {
            System.out.println("AxonFlow HITL - require_approval Policy Example");
            System.out.println("=".repeat(60));

            // 1. Create a policy with require_approval action
            System.out.println("\n1. Creating HITL oversight policy...");

            StaticPolicy policy = client.createStaticPolicy(CreateStaticPolicyRequest.builder()
                    .name("High-Value Transaction Oversight")
                    .description("Require human approval for high-value financial decisions")
                    .category(PolicyCategory.SECURITY_ADMIN)
                    // Pattern matches amounts over 1 million (₹, $, €)
                    .pattern("(amount|value|total|transaction).*[₹$€]\\s*[1-9][0-9]{6,}")
                    .severity(PolicySeverity.HIGH)
                    .enabled(true)
                    .action(PolicyAction.REQUIRE_APPROVAL) // Triggers HITL queue
                    .build());

            System.out.println("   Created policy: " + policy.getId());
            System.out.println("   Name: " + policy.getName());
            System.out.println("   Action: " + policy.getAction());
            System.out.println("   Tier: " + policy.getTier());

            // 2. Test the pattern with sample inputs
            System.out.println("\n2. Testing pattern with sample inputs...");

            List<String> testInputs = Arrays.asList(
                    "Transfer amount $5,000,000 to account",  // Should match (5M)
                    "Transaction value ₹10,00,00,000",        // Should match (10Cr)
                    "Total: €2500000",                        // Should match (2.5M)
                    "Payment of $500 completed",               // Should NOT match
                    "Amount: $999999"                          // Should NOT match (under 1M)
            );

            TestPatternResult testResult = client.testPattern(policy.getPattern(), testInputs);

            System.out.println("\n   Test results:");
            for (TestPatternMatch match : testResult.getMatches()) {
                String icon = match.isMatched() ? "✓ HITL" : "✗ PASS";
                String input = match.getInput();
                if (input.length() > 40) {
                    input = input.substring(0, 40) + "...";
                }
                System.out.println("   " + icon + ": \"" + input + "\"");
            }

            // 3. Create additional HITL policies
            System.out.println("\n3. Creating admin access oversight policy...");

            StaticPolicy adminPolicy = client.createStaticPolicy(CreateStaticPolicyRequest.builder()
                    .name("Admin Access Detection")
                    .description("Route admin operations through human review")
                    .category(PolicyCategory.SECURITY_ADMIN)
                    .pattern("(admin|root|superuser|sudo|DELETE\\s+FROM|DROP\\s+TABLE)")
                    .severity(PolicySeverity.CRITICAL)
                    .enabled(true)
                    .action(PolicyAction.REQUIRE_APPROVAL)
                    .build());

            System.out.println("   Created: " + adminPolicy.getName());
            System.out.println("   Action: " + adminPolicy.getAction());

            // 4. List all policies with require_approval action
            // Note: Filter by tenant tier to get our custom policies (system policies are on earlier pages)
            System.out.println("\n4. Listing all HITL policies...");

            ListStaticPoliciesOptions options = ListStaticPoliciesOptions.builder()
                    .tier(PolicyTier.TENANT)
                    .build();
            List<StaticPolicy> allPolicies = client.listStaticPolicies(options);
            List<StaticPolicy> hitlPolicies = allPolicies.stream()
                    .filter(p -> PolicyAction.REQUIRE_APPROVAL.equals(p.getAction()))
                    .collect(Collectors.toList());

            System.out.println("   HITL policies:");
            for (StaticPolicy p : hitlPolicies) {
                System.out.println("   - " + p.getName() + " (" + p.getSeverity() + ")");
            }
            System.out.println("   Found " + hitlPolicies.size() + " HITL policies");

            // 5. Clean up test policies
            System.out.println("\n5. Cleaning up test policies...");
            client.deleteStaticPolicy(policy.getId());
            client.deleteStaticPolicy(adminPolicy.getId());
            System.out.println("   Deleted test policies");

            System.out.println("\n" + "=".repeat(60));
            System.out.println("Example completed successfully!");
            System.out.println("\nNote: In Community Edition, require_approval auto-approves.");
            System.out.println("Upgrade to Enterprise for full HITL queue functionality.");

        } catch (Exception e) {
            System.err.println("\nError: " + e.getMessage());

            if (e.getMessage() != null && e.getMessage().contains("Connection refused")) {
                System.err.println("\nHint: Make sure AxonFlow is running:");
                System.err.println("  docker compose up -d");
            }

            System.exit(1);
        }
    }
}
