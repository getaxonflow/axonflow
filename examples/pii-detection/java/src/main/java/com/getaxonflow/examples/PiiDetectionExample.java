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
 */
package com.getaxonflow.examples;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.PolicyApprovalRequest;
import com.getaxonflow.sdk.types.PolicyApprovalResult;
import com.getaxonflow.sdk.exceptions.AxonFlowException;
import com.getaxonflow.sdk.exceptions.PolicyViolationException;

import java.util.Arrays;
import java.util.List;

public class PiiDetectionExample {

    private static final String CLIENT_ID = "pii-detection-demo";

    public static void main(String[] args) {
        System.out.println("AxonFlow PII Detection - Java");
        System.out.println("========================================");
        System.out.println();

        // Initialize AxonFlow client
        AxonFlow client = AxonFlow.create(AxonFlowConfig.builder()
            .agentUrl(getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080"))
            .licenseKey(getEnv("AXONFLOW_LICENSE_KEY", ""))
            .build());

        // PII test cases
        List<TestCase> testCases = Arrays.asList(
            new TestCase("Safe Query (No PII)",
                "What is the capital of France?", false, ""),
            new TestCase("US Social Security Number",
                "Process refund for customer with SSN 123-45-6789", true, "ssn"),
            new TestCase("Credit Card Number",
                "Charge card 4111-1111-1111-1111 for $99.99", true, "credit_card"),
            new TestCase("India PAN",
                "Verify PAN number ABCDE1234F for tax filing", true, "pan"),
            new TestCase("India Aadhaar",
                "Link Aadhaar 2345 6789 0123 to account", true, "aadhaar"),
            new TestCase("Email Address",
                "Send invoice to john.doe@example.com", true, "email"),
            new TestCase("Phone Number",
                "Call customer at +1-555-123-4567", true, "phone")
        );

        int passed = 0;
        int failed = 0;

        for (TestCase test : testCases) {
            System.out.printf("Test: %s%n", test.name);
            System.out.printf("  Query: %s%n", truncate(test.query, 60));

            boolean wasBlocked = false;
            String blockReason = "";

            try {
                PolicyApprovalResult result = client.getPolicyApprovedContext(
                    PolicyApprovalRequest.builder()
                        .query(test.query)
                        .clientId(CLIENT_ID)
                        .userToken("pii-detection-user")
                        .build()
                );

                // If we get here, request was approved
                System.out.println("  Result: APPROVED");
                System.out.printf("  Context ID: %s%n", result.getContextId());

                if (result.getPolicies() != null && !result.getPolicies().isEmpty()) {
                    System.out.printf("  Policies: %s%n",
                        String.join(", ", result.getPolicies()));
                }

            } catch (PolicyViolationException e) {
                wasBlocked = true;
                blockReason = e.getMessage();
                System.out.println("  Result: BLOCKED");
                System.out.printf("  Policy: %s%n", e.getPolicyName());
                System.out.printf("  Reason: %s%n", blockReason);

            } catch (AxonFlowException e) {
                System.out.println("  Result: ERROR");
                System.out.printf("  Error: %s%n", e.getMessage());
                failed++;
                System.out.println();
                continue;
            }

            // Verify expected behavior
            if (wasBlocked == test.shouldBlock) {
                System.out.println("  Test: PASS");
                passed++;
            } else {
                String expected = test.shouldBlock ? "blocked" : "approved";
                System.out.printf("  Test: FAIL (expected %s)%n", expected);
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
        final boolean shouldBlock;
        final String piiType;

        TestCase(String name, String query, boolean shouldBlock, String piiType) {
            this.name = name;
            this.query = query;
            this.shouldBlock = shouldBlock;
            this.piiType = piiType;
        }
    }
}
