package com.getaxonflow.examples;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.MCPCheckInputResponse;
import com.getaxonflow.sdk.types.MCPCheckOutputResponse;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * MCP Policy Check Endpoints Example - Java SDK
 *
 * Demonstrates standalone policy-check endpoints:
 * 1. check-input: Validate MCP requests against policies without executing
 * 2. check-output: Validate MCP response data against policies
 *
 * Run with: mvn exec:java
 * Prerequisites: docker compose up -d
 */
public class McpCheckEndpointsExample {

    private static final List<String> failures = new ArrayList<>();

    private static void assertCheck(boolean condition, String message) {
        if (!condition) {
            failures.add(message);
            System.out.println("   FAIL: " + message);
        } else {
            System.out.println("   PASS: " + message);
        }
    }

    private static String env(String key, String defaultValue) {
        String value = System.getenv(key);
        return (value != null && !value.isEmpty()) ? value : defaultValue;
    }

    public static void main(String[] args) {
        System.out.println("MCP Policy Check Endpoints - Java SDK");
        System.out.println("======================================");
        System.out.println();

        AxonFlowConfig config = new AxonFlowConfig.Builder()
                .endpoint(env("AXONFLOW_ENDPOINT", "http://localhost:8080"))
                .clientId(env("AXONFLOW_CLIENT_ID", "demo"))
                .clientSecret(env("AXONFLOW_CLIENT_SECRET", ""))
                .build();

        AxonFlow client = new AxonFlow(config);

        // ---------------------------------------------------------------
        // CHECK-INPUT TESTS
        // ---------------------------------------------------------------

        // Test 1: Clean SQL query passes
        System.out.println("Test 1: Check-Input — Clean SQL Query");
        System.out.println("--------------------------------------");
        MCPCheckInputResponse inputResp = client.mcpCheckInput(
                "postgres",
                "SELECT name, department FROM employees WHERE id = 42");
        assertCheck(inputResp.isAllowed(), "allowed = true");
        assertCheck(inputResp.getPoliciesEvaluated() > 0,
                "policies_evaluated = " + inputResp.getPoliciesEvaluated());
        System.out.println();

        // Test 2: SQL injection blocked
        System.out.println("Test 2: Check-Input — SQL Injection Blocked");
        System.out.println("--------------------------------------------");
        inputResp = client.mcpCheckInput(
                "postgres",
                "SELECT * FROM users UNION SELECT username, password FROM admin_users--");
        assertCheck(!inputResp.isAllowed(), "allowed = false");
        assertCheck(inputResp.getBlockReason() != null && !inputResp.getBlockReason().isEmpty(),
                "block_reason: " + inputResp.getBlockReason());
        System.out.println();

        // Test 3: Dangerous query blocked
        System.out.println("Test 3: Check-Input — Dangerous Query (DROP TABLE)");
        System.out.println("---------------------------------------------------");
        inputResp = client.mcpCheckInput(
                "postgres",
                "SELECT * FROM users; DROP TABLE users--");
        assertCheck(!inputResp.isAllowed(), "allowed = false");
        System.out.println();

        // ---------------------------------------------------------------
        // CHECK-OUTPUT TESTS
        // ---------------------------------------------------------------

        // Test 4: Clean response data passes
        System.out.println("Test 4: Check-Output — Clean Response Data");
        System.out.println("-------------------------------------------");
        List<Map<String, Object>> cleanData = new ArrayList<>();
        Map<String, Object> row1 = new HashMap<>();
        row1.put("id", 1);
        row1.put("name", "Alice Johnson");
        row1.put("department", "Engineering");
        cleanData.add(row1);
        Map<String, Object> row2 = new HashMap<>();
        row2.put("id", 2);
        row2.put("name", "Bob Smith");
        row2.put("department", "Marketing");
        cleanData.add(row2);

        MCPCheckOutputResponse outputResp = client.mcpCheckOutput("postgres", cleanData);
        assertCheck(outputResp.isAllowed(), "allowed = true");
        assertCheck(outputResp.getPoliciesEvaluated() > 0,
                "policies_evaluated = " + outputResp.getPoliciesEvaluated());
        System.out.println();

        // Test 5: PII in response — redacted
        System.out.println("Test 5: Check-Output — PII Redaction (SSN)");
        System.out.println("-------------------------------------------");
        List<Map<String, Object>> piiData = new ArrayList<>();
        Map<String, Object> piiRow1 = new HashMap<>();
        piiRow1.put("id", 1);
        piiRow1.put("name", "Alice");
        piiRow1.put("ssn", "123-45-6789");
        piiData.add(piiRow1);
        Map<String, Object> piiRow2 = new HashMap<>();
        piiRow2.put("id", 2);
        piiRow2.put("name", "Bob");
        piiRow2.put("ssn", "987-65-4321");
        piiData.add(piiRow2);

        outputResp = client.mcpCheckOutput("postgres", piiData);
        assertCheck(outputResp.isAllowed(), "allowed = true (redacted, not blocked)");
        if (outputResp.getRedactedData() != null) {
            String redacted = outputResp.getRedactedData().toString();
            assertCheck(!redacted.contains("123-45-6789"), "SSN was redacted from response");
        }
        System.out.println();

        // Test 6: Execute-style response
        System.out.println("Test 6: Check-Output — Execute Response (Message)");
        System.out.println("--------------------------------------------------");
        Map<String, Object> options = new HashMap<>();
        options.put("message", "3 rows updated");
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("query", "UPDATE users SET status = 'active' WHERE region = 'us'");
        options.put("metadata", metadata);

        outputResp = client.mcpCheckOutput("postgres", null, options);
        assertCheck(outputResp.isAllowed(), "allowed = true");
        System.out.println();

        // ---------------------------------------------------------------
        // Summary
        // ---------------------------------------------------------------
        System.out.println("======================================");
        if (!failures.isEmpty()) {
            System.out.println("FAILED: " + failures.size() + " assertion(s) failed:");
            for (String f : failures) {
                System.out.println("  - " + f);
            }
            System.exit(1);
        }
        System.out.println("ALL TESTS PASSED");
    }
}
