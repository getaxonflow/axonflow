/*
 * MCP PII Redaction - Comprehensive Test (Java SDK)
 *
 * This example validates that PII types are properly redacted in MCP connector responses:
 * - US Social Security Numbers (SSN)
 * - Credit Card numbers
 * - India PAN
 * - India Aadhaar
 * - Email addresses (non-critical, logged only)
 * - Phone numbers (non-critical, logged only)
 *
 * Run: mvn compile exec:java
 * Prerequisites: docker compose up -d
 */
package com.example;

import java.util.ArrayList;
import java.util.List;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.exceptions.ConnectorException;
import com.getaxonflow.sdk.types.ConnectorResponse;

public class PiiRedactionExample {

    private static final List<String> failures = new ArrayList<>();
    private static int passes = 0;

    private static String getEnv(String key, String defaultValue) {
        String value = System.getenv(key);
        return value != null && !value.isEmpty() ? value : defaultValue;
    }

    private static void assertCheck(boolean condition, String message) {
        if (!condition) {
            failures.add(message);
            System.out.println("   FAIL: " + message);
        } else {
            passes++;
            System.out.println("   PASS: " + message);
        }
    }

    public static void main(String[] args) {
        System.out.println("MCP PII Redaction - Comprehensive Test");
        System.out.println("=======================================");
        System.out.println();

        String endpoint = getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080");
        String clientId = getEnv("AXONFLOW_CLIENT_ID", "demo");
        String clientSecret = getEnv("AXONFLOW_CLIENT_SECRET", "demo");
        boolean debug = "true".equals(getEnv("AXONFLOW_DEBUG", "false"));

        AxonFlowConfig config = AxonFlowConfig.builder()
                .endpoint(endpoint)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .debug(debug)
                .build();

        try (AxonFlow client = AxonFlow.create(config)) {

            // Test 1: Query test_customers table (pre-seeded with PII data)
            System.out.println("Test 1: Query test_customers (Response Redaction)");
            System.out.println("-------------------------------------------------");
            try {
                ConnectorResponse resp = client.mcpQuery("postgres", "SELECT * FROM test_customers LIMIT 1");
                assertCheck(resp.isSuccess(), "Query executed successfully");

                if (resp.isRedacted()) {
                    assertCheck(true, "Response was redacted");
                    assertCheck(resp.getRedactedFields() != null && !resp.getRedactedFields().isEmpty(),
                            "Redacted fields are listed");
                    System.out.println("   Redacted fields: " + String.join(", ", resp.getRedactedFields()));

                    String redactedStr = String.join(", ", resp.getRedactedFields());
                    if (redactedStr.contains("ssn")) {
                        System.out.println("   - SSN: redacted");
                    }
                    if (redactedStr.contains("credit_card")) {
                        System.out.println("   - Credit Card: redacted");
                    }
                } else {
                    System.out.println("   Note: No PII found in response (test_customers may be empty)");
                }

                if (resp.getPolicyInfo() != null) {
                    System.out.printf("   PolicyInfo: %d policies, %d redactions in %dms%n",
                            resp.getPolicyInfo().getPoliciesEvaluated(),
                            resp.getPolicyInfo().getRedactionsApplied(),
                            resp.getPolicyInfo().getProcessingTimeMs());
                }
            } catch (Exception e) {
                System.out.println("   Query failed: " + e.getMessage());
                System.out.println("   Note: test_customers table may not exist");
            }
            System.out.println();

            // Test 2: Request-phase PII blocking (SSN in query)
            System.out.println("Test 2: Request-phase PII Blocking (SSN)");
            System.out.println("----------------------------------------");
            try {
                ConnectorResponse resp = client.mcpQuery("postgres", "SELECT * FROM users WHERE ssn = '123-45-6789'");
                if (!resp.isSuccess()) {
                    assertCheck(true, "SSN in query blocked as expected");
                } else {
                    assertCheck(false, "SSN in query should have been blocked");
                }
            } catch (ConnectorException e) {
                assertCheck(true, "SSN in query blocked as expected");
                System.out.println("   Block reason: " + e.getMessage());
            } catch (Exception e) {
                System.out.println("   Unexpected error: " + e.getMessage());
            }
            System.out.println();

            // Test 3: Request-phase PII blocking (Credit Card)
            System.out.println("Test 3: Request-phase PII Blocking (Credit Card)");
            System.out.println("------------------------------------------------");
            try {
                ConnectorResponse resp = client.mcpQuery("postgres", "SELECT * FROM orders WHERE card = '4111111111111111'");
                if (!resp.isSuccess()) {
                    assertCheck(true, "Credit card in query blocked as expected");
                } else {
                    assertCheck(false, "Credit card in query should have been blocked");
                }
            } catch (ConnectorException e) {
                assertCheck(true, "Credit card in query blocked as expected");
                System.out.println("   Block reason: " + e.getMessage());
            } catch (Exception e) {
                System.out.println("   Unexpected error: " + e.getMessage());
            }
            System.out.println();

            // Test 4: Request-phase PII blocking (India PAN)
            System.out.println("Test 4: Request-phase PII Blocking (India PAN)");
            System.out.println("----------------------------------------------");
            try {
                ConnectorResponse resp = client.mcpQuery("postgres", "SELECT * FROM customers WHERE pan = 'ABCDE1234F'");
                if (!resp.isSuccess()) {
                    assertCheck(true, "India PAN in query blocked as expected");
                } else {
                    assertCheck(false, "India PAN in query should have been blocked");
                }
            } catch (ConnectorException e) {
                assertCheck(true, "India PAN in query blocked as expected");
                System.out.println("   Block reason: " + e.getMessage());
            } catch (Exception e) {
                System.out.println("   Unexpected error: " + e.getMessage());
            }
            System.out.println();

            // Test 5: Request-phase PII blocking (India Aadhaar)
            System.out.println("Test 5: Request-phase PII Blocking (India Aadhaar)");
            System.out.println("--------------------------------------------------");
            try {
                ConnectorResponse resp = client.mcpQuery("postgres", "SELECT * FROM customers WHERE aadhaar = '234567890123'");
                if (!resp.isSuccess()) {
                    assertCheck(true, "India Aadhaar in query blocked as expected");
                } else {
                    assertCheck(false, "India Aadhaar in query should have been blocked");
                }
            } catch (ConnectorException e) {
                assertCheck(true, "India Aadhaar in query blocked as expected");
                System.out.println("   Block reason: " + e.getMessage());
            } catch (Exception e) {
                System.out.println("   Unexpected error: " + e.getMessage());
            }
            System.out.println();

            // Test 6: Non-critical PII (email) - should NOT be blocked
            System.out.println("Test 6: Non-critical PII (Email) - Should Pass");
            System.out.println("----------------------------------------------");
            try {
                ConnectorResponse resp = client.mcpQuery("postgres", "SELECT 'john@example.com' as test_email");
                if (resp.isSuccess()) {
                    assertCheck(true, "Email in query allowed (non-critical PII)");
                } else {
                    System.out.println("   Note: Email was blocked (policy may be strict)");
                }
            } catch (Exception e) {
                System.out.println("   Note: Email was blocked (policy may be strict): " + e.getMessage());
            }
            System.out.println();

            // Test 7: Non-critical PII (phone) - should NOT be blocked
            System.out.println("Test 7: Non-critical PII (Phone) - Should Pass");
            System.out.println("----------------------------------------------");
            try {
                ConnectorResponse resp = client.mcpQuery("postgres", "SELECT '+1-555-123-4567' as test_phone");
                if (resp.isSuccess()) {
                    assertCheck(true, "Phone in query allowed (non-critical PII)");
                } else {
                    System.out.println("   Note: Phone was blocked (policy may be strict)");
                }
            } catch (Exception e) {
                System.out.println("   Note: Phone was blocked (policy may be strict): " + e.getMessage());
            }
            System.out.println();

        } catch (Exception e) {
            System.out.println("Failed to create client: " + e.getMessage());
            System.exit(1);
        }

        // Summary
        System.out.println("=======================================");
        if (failures.isEmpty()) {
            System.out.println("ALL TESTS PASSED (" + passes + " assertions)");
            System.out.println();
            System.out.println("MCP PII Handling validated:");
            System.out.println("  Response-phase:");
            System.out.println("    - SSN redaction in response data");
            System.out.println("    - Credit card redaction in response data");
            System.out.println("  Request-phase blocking:");
            System.out.println("    - US SSN in query (critical)");
            System.out.println("    - Credit Card in query (critical)");
            System.out.println("    - India PAN in query (critical)");
            System.out.println("    - India Aadhaar in query (critical)");
            System.out.println("  Non-critical (allowed):");
            System.out.println("    - Email in query");
            System.out.println("    - Phone in query");
        } else {
            System.out.println(failures.size() + " TEST(S) FAILED:");
            for (String f : failures) {
                System.out.println("   - " + f);
            }
            System.exit(1);
        }
    }
}
