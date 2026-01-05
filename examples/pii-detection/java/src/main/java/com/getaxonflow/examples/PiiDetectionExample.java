/*
 * AxonFlow PII Detection - Java
 *
 * Demonstrates AxonFlow's built-in PII detection:
 * - US Social Security Numbers (SSN)
 * - Credit Card numbers
 * - India PAN (Permanent Account Number)
 * - India Aadhaar numbers
 * - Email addresses
 * - Phone numbers
 *
 * Default Behavior (Issue #891):
 *   PII detection defaults to "redact" mode - requests are APPROVED but flagged
 *   with isRequiresRedaction()=true for downstream redaction by the Orchestrator.
 *   Set PII_ACTION=block to restore blocking behavior.
 */
package com.getaxonflow.examples;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.PolicyApprovalRequest;
import com.getaxonflow.sdk.types.PolicyApprovalResult;
import com.getaxonflow.sdk.exceptions.AxonFlowException;

import java.util.Arrays;
import java.util.List;

public class PiiDetectionExample {

    private static final String CLIENT_ID = "pii-detection-demo";

    public static void main(String[] args) {
        System.out.println("AxonFlow PII Detection - Java");
        System.out.println("========================================");
        System.out.println();
        System.out.println("Default Mode: redact (PII flagged for redaction, not blocked)");
        System.out.println();

        // Initialize AxonFlow client
        AxonFlow client = AxonFlow.create(AxonFlowConfig.builder()
            .endpoint(getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080"))
            .licenseKey(getEnv("AXONFLOW_LICENSE_KEY", ""))
            .build());

        // PII test cases
        // expectRedact: true = critical PII (isRequiresRedaction()=true)
        // expectRedact: false = non-critical or no PII (logged but not flagged)
        List<TestCase> testCases = Arrays.asList(
            new TestCase("Safe Query (No PII)",
                "What is the capital of France?", false),
            new TestCase("US Social Security Number (Critical PII)",
                "Process refund for customer with SSN 123-45-6789", true),
            new TestCase("Credit Card Number (Critical PII)",
                "Charge card 4111-1111-1111-1111 for $99.99", true),
            new TestCase("India PAN (Critical PII)",
                "Verify PAN number ABCDE1234F for tax filing", true),
            new TestCase("India Aadhaar (Critical PII)",
                "Link Aadhaar 2345 6789 0123 to account", true),
            new TestCase("Email Address (Non-Critical PII)",
                "Send invoice to john.doe@gmail.com", false), // Medium severity - logged but not flagged
            new TestCase("Phone Number (Non-Critical PII)",
                "Call customer at +1-555-123-4567", false) // Medium severity - logged but not flagged
        );

        int passed = 0;
        int failed = 0;

        for (TestCase test : testCases) {
            System.out.printf("Test: %s%n", test.name);
            System.out.printf("  Query: %s%n", truncate(test.query, 60));

            try {
                PolicyApprovalResult result = client.getPolicyApprovedContext(
                    PolicyApprovalRequest.builder()
                        .query(test.query)
                        .clientId(CLIENT_ID)
                        .userToken("pii-detection-user")
                        .build()
                );

                // Check if request was approved
                if (result.isApproved()) {
                    if (result.isRequiresRedaction()) {
                        System.out.println("  Result: APPROVED (requires redaction)");
                    } else {
                        System.out.println("  Result: APPROVED");
                    }
                    System.out.printf("  Context ID: %s%n", result.getContextId());
                } else {
                    // Request was blocked (only if PII_ACTION=block)
                    System.out.println("  Result: BLOCKED");
                    System.out.printf("  Reason: %s%n", result.getBlockReason());
                }

                if (result.getPolicies() != null && !result.getPolicies().isEmpty()) {
                    System.out.printf("  Policies: %s%n",
                        String.join(", ", result.getPolicies()));
                }

                // Get actual redaction status (blocked also counts as "requires handling")
                boolean actualRequiresRedaction = result.isRequiresRedaction() || !result.isApproved();

                // Verify expected behavior
                if (test.expectRedact && actualRequiresRedaction) {
                    System.out.println("  Test: PASS (PII detected, flagged for redaction)");
                    passed++;
                } else if (!test.expectRedact && !actualRequiresRedaction && result.isApproved()) {
                    System.out.println("  Test: PASS (no critical PII detected)");
                    passed++;
                } else {
                    String expected = test.expectRedact ? "isRequiresRedaction()=true" : "no critical PII";
                    System.out.printf("  Test: FAIL (expected %s)%n", expected);
                    failed++;
                }

            } catch (AxonFlowException e) {
                System.out.println("  Result: ERROR");
                System.out.printf("  Error: %s%n", e.getMessage());
                failed++;
            }

            System.out.println();
        }

        System.out.println("========================================");
        System.out.printf("Results: %d passed, %d failed%n", passed, failed);
        System.out.println();

        if (failed > 0) {
            System.out.println("Some tests failed. Check your AxonFlow policy configuration.");
            System.exit(1);
        }

        System.out.println("All PII detection tests passed!");
        System.out.println();
        System.out.println("Configuration:");
        System.out.println("  - Default: PII_ACTION=redact (PII flagged for redaction, not blocked)");
        System.out.println("  - To block PII: PII_ACTION=block docker compose up -d");
        System.out.println();
        System.out.println("Next steps:");
        System.out.println("  - Custom Policies: ../policies/java/");
        System.out.println("  - Code Governance: ../code-governance/java/");
    }

    private static String getEnv(String key, String defaultValue) {
        String value = System.getenv(key);
        return (value != null && !value.isEmpty()) ? value : defaultValue;
    }

    private static String truncate(String str, int maxLen) {
        if (str.length() <= maxLen) {
            return str;
        }
        return str.substring(0, maxLen) + "...";
    }

    private static class TestCase {
        final String name;
        final String query;
        final boolean expectRedact;

        TestCase(String name, String query, boolean expectRedact) {
            this.name = name;
            this.query = query;
            this.expectRedact = expectRedact;
        }
    }
}
