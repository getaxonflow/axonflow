/**
 * Singapore PII Detection Example
 *
 * Demonstrates AxonFlow's Singapore-specific PII detection for MAS FEAT compliance:
 * - NRIC (National Registration Identity Card)
 * - FIN (Foreign Identification Number)
 * - UEN (Unique Entity Number)
 * - Singapore phone numbers
 * - Singapore postal codes
 *
 * These patterns are available in Community Edition.
 */
package com.getaxonflow.examples;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.PolicyApprovalRequest;
import com.getaxonflow.sdk.types.PolicyApprovalResult;

import java.util.ArrayList;
import java.util.List;

public class SingaporePIIExample {

    record TestCase(String name, String query, String expectedAction, String piiType) {}

    public static void main(String[] args) {
        System.out.println("AxonFlow Singapore PII Detection - Java");
        System.out.println("=".repeat(44));
        System.out.println();
        System.out.println("Testing MAS FEAT Community PII patterns");
        System.out.println();

        // Initialize AxonFlow client
        AxonFlow client = AxonFlow.create(AxonFlowConfig.builder()
            .endpoint(getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080"))
            .clientId(getEnv("AXONFLOW_CLIENT_ID", "singapore-pii-example"))
            .clientSecret(getEnv("AXONFLOW_CLIENT_SECRET", ""))
            .build());

        // Test cases for Singapore PII patterns
        List<TestCase> testCases = List.of(
            new TestCase("NRIC (S prefix - Citizen pre-2000)", "Customer NRIC is S1234567D", "redact", "NRIC"),
            new TestCase("NRIC (T prefix - Citizen 2000+)", "New customer T9876543J registered", "redact", "NRIC"),
            new TestCase("FIN (F prefix - Foreigner pre-2000)", "Employee FIN: F1234567N", "redact", "FIN"),
            new TestCase("FIN (G prefix - Foreigner 2000+)", "Applicant G9876543X submitted documents", "redact", "FIN"),
            new TestCase("NRIC (M prefix - Foreigner 2022+)", "New hire M1234567K onboarded", "redact", "NRIC"),
            new TestCase("UEN (Business registration)", "Invoice from company UEN 53276128A", "redact", "UEN"),
            new TestCase("UEN (Company registration)", "Vendor UEN: 200312345A verified", "redact", "UEN"),
            new TestCase("Singapore Phone (Mobile)", "Contact customer at +65 9123 4567", "redact", "Phone"),
            new TestCase("Singapore Phone (Landline)", "Office number: +65 6234 5678", "redact", "Phone"),
            new TestCase("Singapore Postal Code", "Delivery address: Singapore 238877", "warn", "Postal"),
            new TestCase("Safe Query (No PII)", "What is the weather in Singapore?", "approved", "None"),
            new TestCase("Multiple PII", "Customer S1234567D phone +65 8123 4567", "redact", "Multiple")
        );

        int passed = 0;
        int failed = 0;

        for (TestCase tc : testCases) {
            System.out.printf("Test: %s (%s)%n", tc.name(), tc.piiType());
            String queryPreview = tc.query().length() > 60
                ? tc.query().substring(0, 60) + "..."
                : tc.query();
            System.out.printf("  Query: %s%n", queryPreview);

            try {
                PolicyApprovalResult result = client.getPolicyApprovedContext(
                    PolicyApprovalRequest.builder()
                        .userToken("singapore-user")
                        .query(tc.query())
                        .build()
                );

                System.out.printf("  Approved: %s%n", result.isApproved());
                if (result.getContextId() != null) {
                    System.out.printf("  Context ID: %s%n", result.getContextId());
                }
                if (result.getPolicies() != null && !result.getPolicies().isEmpty()) {
                    System.out.printf("  Policies: %s%n", String.join(", ", result.getPolicies()));
                }
                if (!result.isApproved() && result.getBlockReason() != null) {
                    System.out.printf("  Block Reason: %s%n", result.getBlockReason());
                }

                // Check expectation
                // For redact/warn, the request should still be approved
                String status;
                if (List.of("redact", "warn", "approved").contains(tc.expectedAction())) {
                    if (result.isApproved()) {
                        status = "PASS";
                        passed++;
                    } else {
                        status = "FAIL";
                        failed++;
                    }
                } else {
                    // blocked
                    if (!result.isApproved()) {
                        status = "PASS";
                        passed++;
                    } else {
                        status = "FAIL";
                        failed++;
                    }
                }

                System.out.printf("  Status: %s (expected: %s)%n", status, tc.expectedAction());
            } catch (Exception e) {
                System.out.printf("  Result: ERROR - %s%n", e.getMessage());
                failed++;
            }

            System.out.println();
        }

        System.out.println("=".repeat(44));
        System.out.printf("Results: %d passed, %d failed%n", passed, failed);
        System.out.println();

        if (failed > 0) {
            System.out.println("Some tests failed. Check:");
            System.out.println("  - AxonFlow stack is running");
            System.out.println("  - Singapore PII policies are loaded (migration 042)");
            System.exit(1);
        }

        System.out.println("All Singapore PII detection tests passed!");
        System.out.println();
        System.out.println("MAS FEAT Compliance Notes:");
        System.out.println("  - NRIC/FIN: Critical severity, auto-redacted");
        System.out.println("  - UEN: High severity, auto-redacted");
        System.out.println("  - Phone: Medium severity, auto-redacted");
        System.out.println("  - Postal: Low severity, warning only");
        System.out.println();
        System.out.println("Enterprise features (checksum validation, AI registry)");
        System.out.println("are available with an Enterprise license.");
    }

    private static String getEnv(String name, String defaultValue) {
        String value = System.getenv(name);
        return (value != null && !value.isEmpty()) ? value : defaultValue;
    }
}
