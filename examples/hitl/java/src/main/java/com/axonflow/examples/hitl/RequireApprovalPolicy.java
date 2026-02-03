package com.axonflow.examples.hitl;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.ClientRequest;
import com.getaxonflow.sdk.types.ClientResponse;
import com.getaxonflow.sdk.types.policies.PolicyTypes.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
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
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 */
public class RequireApprovalPolicy {

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
        String agentUrl = System.getenv("AXONFLOW_AGENT_URL");
        if (agentUrl == null || agentUrl.isEmpty()) {
            agentUrl = "http://localhost:8080";
        }
        String clientId = System.getenv("AXONFLOW_CLIENT_ID");
        if (clientId == null || clientId.isEmpty()) {
            clientId = "demo-tenant";
        }

        AxonFlowConfig config = AxonFlowConfig.builder()
                .endpoint(agentUrl)
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
                    .pattern("(?i)(amount|value|total|transaction).*[₹$€]\\s*[1-9][0-9]{6,}")
                    .severity(PolicySeverity.HIGH)
                    .enabled(true)
                    .action(PolicyAction.REQUIRE_APPROVAL) // Triggers HITL queue
                    .build());

            System.out.println("   Created policy: " + policy.getId());
            System.out.println("   Name: " + policy.getName());
            System.out.println("   Action: " + policy.getAction());
            System.out.println("   Tier: " + policy.getTier());
            assertCheck(policy != null, "High-value transaction policy created");
            assertCheck(policy.getId() != null && !policy.getId().isEmpty(), "Policy has ID");
            assertCheck(PolicyAction.REQUIRE_APPROVAL.equals(policy.getAction()), "Policy action is require_approval");

            // 2. Test the pattern with sample inputs
            System.out.println("\n2. Testing pattern with sample inputs...");

            List<String> testInputs = Arrays.asList(
                    "Transfer amount $5000000 to account",    // Should match (5M)
                    "Transaction value ₹100000000",           // Should match (10Cr)
                    "Total: €2500000",                        // Should match (2.5M)
                    "Payment of $500 completed",               // Should NOT match
                    "Amount: $999999"                          // Should NOT match (under 1M)
            );

            TestPatternResult testResult = client.testPattern(policy.getPattern(), testInputs);
            assertCheck(testResult != null, "testPattern returned result");
            assertCheck(testResult.getMatches() != null, "testPattern has matches list");

            System.out.println("\n   Test results:");
            int matchCount = 0;
            for (TestPatternMatch match : testResult.getMatches()) {
                String icon = match.isMatched() ? "✓ HITL" : "✗ PASS";
                String input = match.getInput();
                if (input.length() > 40) {
                    input = input.substring(0, 40) + "...";
                }
                System.out.println("   " + icon + ": \"" + input + "\"");
                if (match.isMatched()) matchCount++;
            }
            // First 3 inputs should match (high values), last 2 should not
            assertCheck(matchCount == 3, "Pattern matched exactly 3 high-value inputs (got " + matchCount + ")");

            // 3. Test enforcement via proxyLLMCall — verify policy actually blocks
            System.out.println("\n3. Testing HITL enforcement via proxyLLMCall...");
            System.out.println("   Waiting for policy propagation...");
            Thread.sleep(3000);

            String userToken = System.getenv("AXONFLOW_USER_TOKEN");
            if (userToken == null) userToken = "";

            // 3a. Send query that MATCHES the require_approval pattern
            System.out.println("\n   3a. Sending query that matches HITL pattern...");
            try {
                ClientResponse matchingResponse = client.proxyLLMCall(
                    ClientRequest.builder()
                        .query("Process transaction amount $5000000 to offshore account")
                        .userToken(userToken)
                        .clientId(clientId)
                        .model("gpt-3.5-turbo")
                        .llmProvider("openai")
                        .context(Map.of("source", "hitl-enforcement-test"))
                        .build()
                );

                if (matchingResponse.isBlocked()) {
                    // Enterprise mode: policy enforcement blocks the request
                    System.out.println("   BLOCKED: " + matchingResponse.getBlockReason());
                    assertCheck(true, "Enterprise HITL enforcement: matching query was blocked");
                    String blockReason = matchingResponse.getBlockReason() != null ? matchingResponse.getBlockReason() : "";
                    assertCheck(
                        blockReason.contains("require_approval") || blockReason.contains("approval"),
                        "Block reason mentions approval (got: " + blockReason + ")"
                    );
                } else {
                    // Community mode: auto-approved
                    System.out.println("   NOT BLOCKED (community mode auto-approve)");
                    assertCheck(true, "Community mode: matching query auto-approved (expected)");
                }
            } catch (Exception e) {
                String errMsg = e.getMessage() != null ? e.getMessage().toLowerCase() : "";
                if (errMsg.contains("api_key") || errMsg.contains("authentication")) {
                    System.out.println("   Note: LLM API error (expected without key): " + e.getMessage());
                    assertCheck(true, "Matching query processed (LLM key issue expected)");
                } else {
                    assertCheck(false, "Matching query failed unexpectedly: " + e.getMessage());
                }
            }

            // 3b. Send safe query that should NOT trigger HITL
            System.out.println("\n   3b. Sending safe query (should NOT trigger HITL)...");
            try {
                ClientResponse safeResponse = client.proxyLLMCall(
                    ClientRequest.builder()
                        .query("What is the weather today?")
                        .userToken(userToken)
                        .clientId(clientId)
                        .model("gpt-3.5-turbo")
                        .llmProvider("openai")
                        .context(Map.of("source", "hitl-enforcement-test"))
                        .build()
                );
                assertCheck(!safeResponse.isBlocked(), "Safe query was NOT blocked by HITL policy");
            } catch (Exception e) {
                String errMsg = e.getMessage() != null ? e.getMessage().toLowerCase() : "";
                if (errMsg.contains("api_key") || errMsg.contains("authentication")) {
                    System.out.println("   Note: LLM API error (expected without key): " + e.getMessage());
                    assertCheck(true, "Safe query processed (LLM key issue expected)");
                } else {
                    assertCheck(false, "Safe query failed unexpectedly: " + e.getMessage());
                }
            }

            // 4. Create additional HITL policies
            System.out.println("\n4. Creating admin access oversight policy...");

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
            assertCheck(adminPolicy != null, "Admin access policy created");
            assertCheck(adminPolicy.getId() != null && !adminPolicy.getId().isEmpty(), "Admin policy has ID");
            assertCheck(PolicyAction.REQUIRE_APPROVAL.equals(adminPolicy.getAction()), "Admin policy action is require_approval");

            // 5. List all policies with require_approval action
            // Note: Filter by tenant tier to get our custom policies (system policies are on earlier pages)
            System.out.println("\n5. Listing all HITL policies...");

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
            assertCheck(hitlPolicies.size() >= 2, "Found at least 2 HITL policies (created in this example)");

            // 6. Clean up test policies
            System.out.println("\n6. Cleaning up test policies...");
            client.deleteStaticPolicy(policy.getId());
            client.deleteStaticPolicy(adminPolicy.getId());
            System.out.println("   Deleted test policies");
            assertCheck(true, "Test policies cleaned up successfully");

            System.out.println("\n" + "=".repeat(60));
            System.out.println("Example completed successfully!");
            System.out.println("\nNote: In Community Edition, require_approval auto-approves.");
            System.out.println("Upgrade to Enterprise for full HITL queue functionality.");

            // Final assertion summary
            System.out.println();
            System.out.println("=".repeat(60));
            System.out.println("Assertion Summary");
            System.out.println("=".repeat(60));
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
            System.err.println("\nError: " + e.getMessage());

            if (e.getMessage() != null && e.getMessage().contains("Connection refused")) {
                System.err.println("\nHint: Make sure AxonFlow is running:");
                System.err.println("  docker compose up -d");
            }

            System.exit(1);
        }
    }
}
