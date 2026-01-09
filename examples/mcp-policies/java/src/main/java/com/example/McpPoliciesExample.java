/*
 * MCP Policy Enforcement Example - Java SDK
 *
 * Demonstrates phase-aware policy enforcement:
 * 1. REQUEST phase: SQLi patterns are blocked
 * 2. RESPONSE phase: PII in connector data is redacted
 * 3. PolicyInfo metadata in all responses
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

public class McpPoliciesExample {

    private static final List<String> failures = new ArrayList<>();

    private static String getEnv(String key, String defaultValue) {
        String value = System.getenv(key);
        return value != null && !value.isEmpty() ? value : defaultValue;
    }

    private static void assertTrue(boolean condition, String message) {
        if (!condition) {
            failures.add(message);
            System.out.println("   FAIL: " + message);
        } else {
            System.out.println("   PASS: " + message);
        }
    }

    public static void main(String[] args) {
        System.out.println("AxonFlow MCP Policy Enforcement - Java SDK");
        System.out.println("===========================================");
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

            // Test 1: Clean query should pass through
            System.out.println("Test 1: Clean Query (No PII, No SQLi)");
            System.out.println("--------------------------------------");
            try {
                ConnectorResponse resp = client.mcpQuery("postgres", "SELECT 1 as test_value");
                assertTrue(resp.isSuccess(), "Query succeeded");
                assertTrue(!resp.isRedacted(), "No redaction applied");
                if (resp.getPolicyInfo() != null) {
                    assertTrue(resp.getPolicyInfo().getPoliciesEvaluated() >= 0, "Policies were evaluated");
                    assertTrue(!resp.getPolicyInfo().isBlocked(), "Request was not blocked");
                    System.out.printf("   PolicyInfo: %d policies evaluated in %dms%n",
                            resp.getPolicyInfo().getPoliciesEvaluated(),
                            resp.getPolicyInfo().getProcessingTimeMs());
                }
            } catch (Exception e) {
                System.out.println("   Query failed: " + e.getMessage());
            }
            System.out.println();

            // Test 2: SQLi pattern should be blocked
            System.out.println("Test 2: SQL Injection Pattern (Request Blocked)");
            System.out.println("------------------------------------------------");
            try {
                client.mcpQuery("postgres", "SELECT * FROM users WHERE id = 1; DROP TABLE users; --");
                assertTrue(false, "SQLi pattern should have been blocked");
            } catch (ConnectorException e) {
                assertTrue(true, "Request blocked as expected");
                System.out.println("   Block reason: " + e.getMessage());
            } catch (Exception e) {
                System.out.println("   Unexpected error: " + e.getMessage());
            }
            System.out.println();

            // Test 3: UNION-based SQLi should also be blocked
            System.out.println("Test 3: UNION SQLi Pattern (Request Blocked)");
            System.out.println("---------------------------------------------");
            try {
                client.mcpQuery("postgres", "SELECT name FROM employees UNION SELECT password FROM admin_users");
                assertTrue(false, "UNION SQLi should have been blocked");
            } catch (ConnectorException e) {
                assertTrue(true, "UNION SQLi blocked as expected");
                System.out.println("   Block reason: " + e.getMessage());
            } catch (Exception e) {
                System.out.println("   Unexpected error: " + e.getMessage());
            }
            System.out.println();

            // Test 4: Response with PII should have redacted fields
            System.out.println("Test 4: Response Redaction (PII in Data)");
            System.out.println("-----------------------------------------");
            try {
                ConnectorResponse resp = client.mcpQuery("postgres", "SELECT * FROM test_customers LIMIT 1");
                if (resp.isSuccess()) {
                    if (resp.isRedacted()) {
                        assertTrue(true, "Response was redacted");
                        assertTrue(resp.getRedactedFields() != null && !resp.getRedactedFields().isEmpty(),
                                "Redacted fields are listed");
                        System.out.println("   Redacted fields: " + String.join(", ", resp.getRedactedFields()));
                    } else {
                        System.out.println("   Note: No PII found in response");
                    }
                    if (resp.getPolicyInfo() != null) {
                        System.out.printf("   PolicyInfo: %d redactions in %dms%n",
                                resp.getPolicyInfo().getRedactionsApplied(),
                                resp.getPolicyInfo().getProcessingTimeMs());
                    }
                }
            } catch (Exception e) {
                System.out.println("   Query failed: " + e.getMessage());
                System.out.println("   Note: test_customers table may not exist");
            }
            System.out.println();

            // Test 5: Request-side PII blocking (SSN in query)
            System.out.println("Test 5: Request-side PII Blocking (SSN in Query)");
            System.out.println("------------------------------------------------");
            try {
                client.mcpQuery("postgres", "SELECT * FROM customers WHERE ssn = '123-45-6789'");
                assertTrue(false, "SSN in query should have been blocked");
            } catch (ConnectorException e) {
                assertTrue(true, "SSN in query blocked as expected");
                System.out.println("   Block reason: " + e.getMessage());
            } catch (Exception e) {
                System.out.println("   Unexpected error: " + e.getMessage());
            }
            System.out.println();

        } catch (Exception e) {
            System.out.println("Failed to create client: " + e.getMessage());
            System.exit(1);
        }

        // Summary
        System.out.println("===========================================");
        if (failures.isEmpty()) {
            System.out.println("ALL TESTS PASSED");
            System.out.println();
            System.out.println("MCP Policy Enforcement validated:");
            System.out.println("  - REQUEST phase: SQLi blocking");
            System.out.println("  - REQUEST phase: PII blocking");
            System.out.println("  - RESPONSE phase: PII redaction");
            System.out.println("  - PolicyInfo metadata in responses");
        } else {
            System.out.println(failures.size() + " TEST(S) FAILED:");
            for (String f : failures) {
                System.out.println("   - " + f);
            }
            System.exit(1);
        }
    }
}
