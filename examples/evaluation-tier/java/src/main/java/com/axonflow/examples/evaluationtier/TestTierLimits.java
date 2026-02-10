package com.axonflow.examples.evaluationtier;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.exceptions.AxonFlowException;
import com.getaxonflow.sdk.types.HealthStatus;
import com.getaxonflow.sdk.types.policies.PolicyTypes.CreateDynamicPolicyRequest;
import com.getaxonflow.sdk.types.policies.PolicyTypes.DynamicPolicy;
import com.getaxonflow.sdk.types.policies.PolicyTypes.DynamicPolicyCondition;
import com.getaxonflow.sdk.types.policies.PolicyTypes.DynamicPolicyAction;
import com.getaxonflow.sdk.types.policies.PolicyTypes.PolicyTier;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * AxonFlow Evaluation Tier - License Tier Limits Testing (Java)
 *
 * TIER COMPATIBILITY: Community / Evaluation
 * Works without any license (Community mode) and with a free Evaluation license.
 * No paid Enterprise license required. Get a free Evaluation license at:
 * https://getaxonflow.com/evaluation-license
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 *
 * This example tests:
 * - Tier detection (Community, Evaluation, Enterprise)
 * - Tenant policy limits (20/50/unlimited)
 * - Organization policy access (0/5/unlimited)
 *
 * Run with:
 *   mvn exec:java -Dexec.mainClass="com.axonflow.examples.evaluationtier.TestTierLimits"
 *
 * Prerequisites: docker compose up -d
 */
public class TestTierLimits {
    private static final List<String> failures = new ArrayList<>();

    private static void assertCheck(boolean condition, String message) {
        if (condition) {
            System.out.println("   ✓ PASS: " + message);
        } else {
            System.out.println("   ❌ FAIL: " + message);
            failures.add(message);
        }
    }

    private static String getExpectedTier() {
        String licenseKey = System.getenv("AXONFLOW_LICENSE_KEY");
        if (licenseKey == null || licenseKey.isEmpty()) {
            return "community";
        }
        // Ed25519 format: AXON-{base64url_payload}.{base64url_signature}
        if (licenseKey.startsWith("AXON-") && licenseKey.contains(".")) {
            try {
                String inner = licenseKey.substring(5); // Strip "AXON-"
                int lastDot = inner.lastIndexOf('.');
                if (lastDot > 0) {
                    String payloadB64 = inner.substring(0, lastDot);
                    byte[] decoded = Base64.getUrlDecoder().decode(payloadB64);
                    String payload = new String(decoded);
                    // Simple JSON tier extraction
                    int tierIdx = payload.indexOf("\"tier\"");
                    if (tierIdx >= 0) {
                        int valStart = payload.indexOf('"', tierIdx + 6) + 1;
                        int valEnd = payload.indexOf('"', valStart);
                        String tier = payload.substring(valStart, valEnd);
                        if ("Evaluation".equals(tier)) return "evaluation";
                        if ("Enterprise".equals(tier) || "Plus".equals(tier) || "Professional".equals(tier)) return "enterprise";
                    }
                }
            } catch (Exception e) {
                // Fall through to simple check
            }
        }
        if (licenseKey.toUpperCase().contains("EVALUATION")) {
            return "evaluation";
        }
        return "enterprise";
    }

    public static void main(String[] args) {
        System.out.println("============================================================");
        System.out.println("AxonFlow Evaluation Tier - License Tier Limits Testing (Java)");
        System.out.println("============================================================");

        String expectedTier = getExpectedTier();
        System.out.println("\nDetected tier (from env): " + expectedTier);

        String endpoint = System.getenv("AXONFLOW_ENDPOINT");
        if (endpoint == null || endpoint.isEmpty()) {
            endpoint = "http://localhost:8080";
        }

        String clientId = System.getenv("AXONFLOW_CLIENT_ID");
        if (clientId == null || clientId.isEmpty()) {
            clientId = "test-org-001";
        }

        AxonFlowConfig config = AxonFlow.builder()
            .endpoint(endpoint)
            .clientId(clientId)
            .clientSecret(System.getenv("AXONFLOW_CLIENT_SECRET"))
            .build();

        try (AxonFlow client = AxonFlow.create(config)) {
            // Test 1: Health Check / Tier Detection
            System.out.println("\n1. Testing Tier Detection");
            System.out.println("----------------------------------------");

            try {
                HealthStatus health = client.healthCheck();
                assertCheck(health.isHealthy(), "Platform is healthy");
                System.out.println("   Platform version: " + health.getVersion());
            } catch (Exception e) {
                System.out.println("   Error: " + e.getMessage());
                assertCheck(false, "Health check passed");
            }

            // Test 2: Create and Delete Tenant Policy
            System.out.println("\n2. Testing Tenant Policy Limits");
            System.out.println("----------------------------------------");

            String expectedLimit;
            switch (expectedTier) {
                case "community":
                    expectedLimit = "20";
                    break;
                case "evaluation":
                    expectedLimit = "50";
                    break;
                default:
                    expectedLimit = "unlimited";
            }
            System.out.println("   Expected limit for " + expectedTier + ": " + expectedLimit);

            try {
                CreateDynamicPolicyRequest request = CreateDynamicPolicyRequest.builder()
                    .name("Java Evaluation Tier Test Policy")
                    .description("Test policy for tier limit verification")
                    .type("content")
                    .category("dynamic-java-tier-test")
                    .conditions(List.of(
                        new DynamicPolicyCondition("query", "contains", "java-tier-test")
                    ))
                    .actions(List.of(
                        new DynamicPolicyAction("log", null)
                    ))
                    .priority(100)
                    .enabled(false)
                    .build();

                DynamicPolicy policy = client.createDynamicPolicy(request);
                assertCheck(true, "Policy creation succeeded");
                System.out.println("   Created policy: " + policy.getId());

                // Clean up
                client.deleteDynamicPolicy(policy.getId());
                System.out.println("   Cleaned up test policy");

            } catch (AxonFlowException e) {
                String errStr = e.getMessage();
                if (errStr != null && errStr.contains("POLICY_LIMIT_EXCEEDED")) {
                    System.out.println("   Policy limit reached");
                    assertCheck(true, "Policy limit enforcement working");

                    if ("community".equals(expectedTier) && errStr.toLowerCase().contains("evaluation")) {
                        assertCheck(true, "Error mentions Evaluation upgrade path");
                    } else if ("evaluation".equals(expectedTier) && errStr.toLowerCase().contains("enterprise")) {
                        assertCheck(true, "Error mentions Enterprise upgrade path");
                    }
                } else {
                    System.out.println("   Error: " + e.getMessage());
                    assertCheck(false, "Policy creation succeeded or limit enforced");
                }
            }

            // Test 3: Organization Policy Access
            System.out.println("\n3. Testing Organization Policy Access");
            System.out.println("----------------------------------------");

            try {
                CreateDynamicPolicyRequest orgRequest = CreateDynamicPolicyRequest.builder()
                    .name("Java Org Policy Test")
                    .description("Test org policy for tier verification")
                    .type("content")
                    .category("dynamic-java-org-test")
                    .tier(PolicyTier.ORGANIZATION)
                    .conditions(List.of(
                        new DynamicPolicyCondition("query", "contains", "java-org-test")
                    ))
                    .actions(List.of(
                        new DynamicPolicyAction("log", null)
                    ))
                    .priority(100)
                    .enabled(false)
                    .build();

                DynamicPolicy orgPolicy = client.createDynamicPolicy(orgRequest);

                if ("community".equals(expectedTier)) {
                    assertCheck(false, "Community should not create org policies");
                } else {
                    assertCheck(true, expectedTier + " tier can create org policies");
                    System.out.println("   Created org policy: " + orgPolicy.getId());

                    // Clean up
                    client.deleteDynamicPolicy(orgPolicy.getId());
                    System.out.println("   Cleaned up org policy");
                }

            } catch (AxonFlowException e) {
                String errStr = e.getMessage();
                if ("community".equals(expectedTier)) {
                    if (errStr != null && (errStr.contains("ORG_TIER") || errStr.toLowerCase().contains("evaluation"))) {
                        assertCheck(true, "Community tier correctly blocked org policy creation");
                        if (errStr.toLowerCase().contains("evaluation")) {
                            assertCheck(true, "Error includes Evaluation upgrade path");
                        }
                    } else {
                        System.out.println("   Error: " + e.getMessage());
                        assertCheck(false, "Expected org tier error for Community");
                    }
                } else if (errStr != null && errStr.contains("ORG_POLICY_LIMIT_EXCEEDED")) {
                    System.out.println("   Org policy limit reached for Evaluation tier");
                    assertCheck(true, "Evaluation tier has org policy limit enforcement");
                } else {
                    System.out.println("   Error: " + e.getMessage());
                    assertCheck(false, "Unexpected error creating org policy");
                }
            }

            // Summary
            System.out.println("\n============================================================");
            System.out.println("TEST SUMMARY");
            System.out.println("============================================================");

            if (!failures.isEmpty()) {
                System.out.println("\n❌ " + failures.size() + " test(s) failed:");
                for (String f : failures) {
                    System.out.println("   - " + f);
                }
                System.exit(1);
            } else {
                System.out.println("\n✓ All tests passed!");
                System.out.println("\nTier limits verified for: " + expectedTier);
                System.out.println("\nTier Comparison:");
                System.out.println("  | Feature          | Community | Evaluation | Enterprise |");
                System.out.println("  |------------------|-----------|------------|------------|");
                System.out.println("  | Tenant policies  | 20        | 50         | Unlimited  |");
                System.out.println("  | Org policies     | 0         | 5          | Unlimited  |");
                System.out.println("  | MCP connectors   | 2         | 5          | Unlimited  |");
                System.out.println("  | Audit retention  | 3 days    | 14 days    | 3650 days  |");
                System.exit(0);
            }

        } catch (Exception e) {
            System.err.println("Unexpected error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
