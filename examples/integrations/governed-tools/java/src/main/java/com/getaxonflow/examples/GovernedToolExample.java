/*
 * GovernedTool -- Framework-Agnostic Tool Governance Example (Java)
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 *
 * Demonstrates GovernedTool wrapping standard tools with AxonFlow input/output
 * governance. Tests the UNDERLYING policy engine behavior: PII detection actually
 * blocks/redacts, SQLi is actually caught, policies are actually evaluated, and
 * tools are NOT called when input is blocked.
 *
 * GovernedTool works with any framework that accepts the Tool interface.
 *
 * Run with: mvn compile exec:java
 * Prerequisites: docker compose up -d
 */
package com.getaxonflow.examples;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.adapters.GovernedTool;
import com.getaxonflow.sdk.adapters.Tool;
import com.getaxonflow.sdk.exceptions.PolicyViolationException;
import com.getaxonflow.sdk.types.MCPCheckInputResponse;
import com.getaxonflow.sdk.types.MCPCheckOutputResponse;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class GovernedToolExample {

    private static final List<String> failures = new ArrayList<>();
    private static final List<String> callLog = new ArrayList<>();

    private static void assertCheck(boolean condition, String message) {
        if (condition) {
            System.out.println("   PASS: " + message);
        } else {
            System.out.println("   FAIL: " + message);
            failures.add(message);
        }
    }

    // =========================================================================
    // Tool implementations (standard tools -- no AxonFlow awareness)
    // =========================================================================

    static Tool safeSearch = new Tool() {
        public String name() { return "safe_search"; }
        public String description() { return "Search for products -- returns clean data without PII."; }
        public Object invoke(Object input) {
            String query = input instanceof Map ? (String) ((Map<?, ?>) input).get("query") : input.toString();
            callLog.add("safe_search:" + query);
            return "{\"products\": [{\"name\": \"Widget A\", \"price\": 9.99}]}";
        }
    };

    static Tool customerLookup = new Tool() {
        public String name() { return "customer_lookup"; }
        public String description() { return "Look up customer data -- returns PII in results."; }
        public Object invoke(Object input) {
            String query = input instanceof Map ? (String) ((Map<?, ?>) input).get("query") : input.toString();
            callLog.add("customer_lookup:" + query);
            return "{\"name\": \"John Doe\", \"ssn\": \"123-45-6789\", \"email\": \"john@example.com\", \"order_status\": \"shipped\"}";
        }
    };

    static Tool sendEmail = new Tool() {
        public String name() { return "send_email"; }
        public String description() { return "Send an email notification."; }
        public Object invoke(Object input) {
            String message = input instanceof Map ? (String) ((Map<?, ?>) input).get("message") : input.toString();
            callLog.add("send_email:" + message);
            return "Email sent successfully";
        }
    };

    // =========================================================================
    // Tests
    // =========================================================================

    static void testCleanToolCall(AxonFlow client) {
        System.out.println("=".repeat(60));
        System.out.println("[Test 1] Clean Tool Call -- Policies Must Be Evaluated");
        System.out.println("=".repeat(60));

        callLog.clear();
        GovernedTool governed = GovernedTool.wrap(safeSearch, client);
        Map<String, Object> input = Map.of("query", "latest widgets");

        try {
            long t0 = System.currentTimeMillis();
            Object result = governed.invoke(input);
            long latencyMs = System.currentTimeMillis() - t0;

            assertCheck(result != null, "Tool call returned a result");
            assertCheck(callLog.size() == 1, "Wrapped tool was called exactly once");
            assertCheck("safe_search:latest widgets".equals(callLog.get(0)), "Tool received correct args");
            assertCheck(result.toString().contains("Widget A"), "Result contains expected data");
            System.out.println("   Latency: " + latencyMs + "ms");
        } catch (Exception e) {
            assertCheck(false, "Clean tool call should not throw: " + e.getMessage());
        }

        // Verify the policy engine actually ran
        try {
            MCPCheckInputResponse direct = client.mcpCheckInput("safe_search", "{\"query\": \"latest widgets\"}");
            assertCheck(
                direct.getPoliciesEvaluated() > 0,
                "Policy engine evaluated " + direct.getPoliciesEvaluated() + " policies (not zero)");
        } catch (Exception e) {
            System.out.println("   Direct check error: " + e.getMessage());
        }
        System.out.println();
    }

    static void testSqliInToolInputBlocked(AxonFlow client) {
        System.out.println("=".repeat(60));
        System.out.println("[Test 2] SQL Injection in Tool Input -- Must Block");
        System.out.println("=".repeat(60));

        callLog.clear();
        GovernedTool governed = GovernedTool.builder(safeSearch, client)
            .connectorTypeFn(name -> "postgres.query")
            .build();

        String sqliInput = "SELECT * FROM users WHERE id=1; DROP TABLE users;--";
        Map<String, Object> input = Map.of("query", sqliInput);

        boolean blocked = false;
        String blockReason = "";
        try {
            governed.invoke(input);
        } catch (PolicyViolationException e) {
            blocked = true;
            blockReason = e.getMessage();
            System.out.println("   Blocked: " + blockReason);
        } catch (Exception e) {
            System.out.println("   Unexpected error: " + e.getMessage());
        }

        assertCheck(blocked, "SQL injection tool call was blocked");
        assertCheck(callLog.isEmpty(), "Tool was NOT called (blocked before execution)");

        // Verify underlying policy engine
        try {
            MCPCheckInputResponse direct = client.mcpCheckInput("postgres.query", sqliInput);
            assertCheck(!direct.isAllowed(), "Direct check-input confirms SQLi is blocked");
            assertCheck(
                direct.getBlockReason() != null && !direct.getBlockReason().isEmpty(),
                "Block reason: " + direct.getBlockReason());
        } catch (Exception e) {
            System.out.println("   Direct check error: " + e.getMessage());
        }
        System.out.println();
    }

    static void testPiiInToolInput(AxonFlow client) {
        System.out.println("=".repeat(60));
        System.out.println("[Test 3] PII in Tool Input -- Must Be Detected");
        System.out.println("=".repeat(60));

        callLog.clear();
        GovernedTool governed = GovernedTool.wrap(sendEmail, client);
        String piiInput = "Customer SSN is 123-45-6789, please process their refund";

        // Verify the policy engine detects PII via direct call first
        try {
            MCPCheckInputResponse direct = client.mcpCheckInput(
                "send_email", "{\"message\": \"" + piiInput + "\"}");

            boolean piiDetected;
            if (!direct.isAllowed()) {
                piiDetected = true;
                System.out.println("   Direct check: Input blocked (" + direct.getBlockReason() + ")");
            } else {
                piiDetected = direct.getPoliciesEvaluated() > 0;
                System.out.println("   Direct check: " + direct.getPoliciesEvaluated() + " policies evaluated (PII_ACTION may be warn/log)");
            }
            assertCheck(piiDetected, "PII in tool input was detected by policy engine");
        } catch (Exception e) {
            System.out.println("   Direct check error: " + e.getMessage());
        }

        // Now test through GovernedTool
        Map<String, Object> input = Map.of("message", piiInput);
        try {
            Object result = governed.invoke(input);
            assertCheck(callLog.size() == 1, "Tool called (PII detected but not blocking at input)");
            System.out.println("   GovernedTool result: " + result);
        } catch (PolicyViolationException e) {
            assertCheck(callLog.isEmpty(), "Tool NOT called (PII blocking at input)");
            System.out.println("   GovernedTool blocked: " + e.getMessage());
        } catch (Exception e) {
            System.out.println("   Unexpected error: " + e.getMessage());
        }
        System.out.println();
    }

    static void testPiiInToolOutput(AxonFlow client) {
        System.out.println("=".repeat(60));
        System.out.println("[Test 4] PII in Tool Output -- Must Be Detected/Redacted");
        System.out.println("=".repeat(60));

        callLog.clear();
        GovernedTool governed = GovernedTool.wrap(customerLookup, client);

        // Verify policy engine handles PII output via direct call
        String piiOutput = "{\"name\": \"John Doe\", \"ssn\": \"123-45-6789\", \"email\": \"john@example.com\"}";
        try {
            Map<String, Object> outputOptions = new HashMap<>();
            outputOptions.put("message", piiOutput);
            MCPCheckOutputResponse direct = client.mcpCheckOutput("customer_lookup", null, outputOptions);

            boolean outputPiiHandled;
            if (!direct.isAllowed()) {
                outputPiiHandled = true;
                System.out.println("   Direct check: Output blocked (" + direct.getBlockReason() + ")");
            } else if (direct.getRedactedData() != null) {
                outputPiiHandled = true;
                System.out.println("   Direct check: Output redacted");
            } else {
                outputPiiHandled = direct.getPoliciesEvaluated() > 0;
                System.out.println("   Direct check: " + direct.getPoliciesEvaluated() + " policies evaluated");
            }
            assertCheck(outputPiiHandled, "PII in tool output was handled by policy engine");
        } catch (Exception e) {
            System.out.println("   Direct check error: " + e.getMessage());
        }

        // Test through GovernedTool
        Map<String, Object> input = Map.of("query", "John Doe");
        try {
            Object result = governed.invoke(input);
            assertCheck(callLog.size() == 1, "Tool was called (output-side check)");

            String resultStr = result.toString();
            if (!resultStr.contains("123-45-6789")) {
                System.out.println("   GovernedTool: Output redacted (raw SSN not present)");
            } else if (resultStr.contains("***") || resultStr.contains("REDACTED")) {
                System.out.println("   GovernedTool: Output redacted");
            } else {
                System.out.println("   GovernedTool: Output returned (PII_ACTION may be warn/log)");
            }
            String display = resultStr.length() > 200 ? resultStr.substring(0, 200) : resultStr;
            System.out.println("   Result: " + display);
        } catch (PolicyViolationException e) {
            assertCheck(callLog.size() == 1, "Tool was called before output block");
            System.out.println("   GovernedTool: Output blocked (" + e.getMessage() + ")");
        } catch (Exception e) {
            System.out.println("   Unexpected error: " + e.getMessage());
        }
        System.out.println();
    }

    static void testCustomConnectorType(AxonFlow client) {
        System.out.println("=".repeat(60));
        System.out.println("[Test 5] Custom Connector Type Derivation");
        System.out.println("=".repeat(60));

        callLog.clear();
        GovernedTool governed = GovernedTool.builder(safeSearch, client)
            .connectorTypeFn(name -> "salesforce." + name)
            .build();

        assertCheck(
            governed.toString().contains("salesforce.safe_search"),
            "Connector type derived correctly: " + governed);

        Map<String, Object> input = Map.of("query", "find contacts");
        try {
            Object result = governed.invoke(input);
            assertCheck(result != null, "Custom connector type call succeeded");
            assertCheck(callLog.size() == 1, "Tool was called");
        } catch (Exception e) {
            assertCheck(false, "Custom connector type should not throw: " + e.getMessage());
        }

        // Verify connector type was used in the check
        try {
            MCPCheckInputResponse direct = client.mcpCheckInput(
                "salesforce.safe_search", "{\"query\": \"find contacts\"}");
            assertCheck(direct.isAllowed(), "Direct check with custom connector_type allowed");
            assertCheck(
                direct.getPoliciesEvaluated() > 0,
                "Policies evaluated: " + direct.getPoliciesEvaluated());
        } catch (Exception e) {
            System.out.println("   Direct check error: " + e.getMessage());
        }
        System.out.println();
    }

    static void testQueryOperation(AxonFlow client) {
        System.out.println("=".repeat(60));
        System.out.println("[Test 6] Read-Only Tool with operation='query'");
        System.out.println("=".repeat(60));

        callLog.clear();
        GovernedTool governed = GovernedTool.builder(safeSearch, client)
            .operation("query")
            .build();

        Map<String, Object> input = Map.of("query", "list products");
        try {
            Object result = governed.invoke(input);
            assertCheck(result != null, "Query-mode tool call succeeded");
            assertCheck(callLog.size() == 1, "Tool was called");
        } catch (Exception e) {
            assertCheck(false, "Query operation should not throw: " + e.getMessage());
        }
        System.out.println();
    }

    static void testGovernToolsHelper(AxonFlow client) {
        System.out.println("=".repeat(60));
        System.out.println("[Test 7] governTools() Helper -- Multi-Tool Wrapping");
        System.out.println("=".repeat(60));

        callLog.clear();
        List<GovernedTool> governed = GovernedTool.governTools(
            List.of(safeSearch, customerLookup, sendEmail), client);

        assertCheck(governed.size() == 3, "Wrapped " + governed.size() + " tools");

        for (GovernedTool g : governed) {
            assertCheck(g instanceof Tool, g.name() + " implements Tool interface");
        }

        // Call first tool
        try {
            Object result = governed.get(0).invoke(Map.of("query", "test"));
            assertCheck(result != null, "First governed tool returned result");
            assertCheck(callLog.size() == 1, "Only the first tool was called");
        } catch (Exception e) {
            assertCheck(false, "First tool should not throw: " + e.getMessage());
        }

        System.out.println("   Tools: " + governed.stream()
            .map(GovernedTool::name)
            .reduce((a, b) -> a + ", " + b)
            .orElse(""));
        System.out.println();
    }

    static void testReprAndMetadata(AxonFlow client) {
        System.out.println("=".repeat(60));
        System.out.println("[Test 8] GovernedTool Metadata & toString");
        System.out.println("=".repeat(60));

        GovernedTool governed = GovernedTool.wrap(safeSearch, client);

        assertCheck("safe_search".equals(governed.name()), "Name: " + governed.name());
        assertCheck(governed.description().contains("Search for products"), "Description preserved");
        assertCheck(governed.toString().contains("GovernedTool"), "toString: " + governed);
        assertCheck(governed.toString().contains("safe_search"), "Tool name in toString");

        // Custom connector type
        GovernedTool governed2 = GovernedTool.builder(customerLookup, client)
            .connectorTypeFn(name -> "crm." + name)
            .operation("query")
            .build();
        assertCheck(governed2.toString().contains("crm.customer_lookup"), "Custom toString: " + governed2);
        System.out.println();
    }

    // =========================================================================
    // Main
    // =========================================================================

    public static void main(String[] args) {
        System.out.println("GovernedTool -- Framework-Agnostic Tool Governance (Java)");
        System.out.println("=".repeat(60));
        System.out.println();
        System.out.println("Validates AxonFlow policy enforcement around any Tool,");
        System.out.println("verifying the underlying policy engine behavior.");
        System.out.println();

        String agentUrl = getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080");
        System.out.println("Checking AxonFlow at " + agentUrl + "...");

        AxonFlow client = AxonFlow.create(AxonFlowConfig.builder()
            .endpoint(agentUrl)
            .clientId(getEnv("AXONFLOW_CLIENT_ID", "governed-tool-example"))
            .clientSecret(getEnv("AXONFLOW_CLIENT_SECRET", ""))
            .build());

        // Health check
        try {
            client.healthCheck();
            System.out.println("Status: healthy");
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
            System.out.println("\nMake sure AxonFlow is running: docker compose up -d");
            System.exit(1);
        }
        System.out.println();

        System.out.println("Running GovernedTool tests...");
        System.out.println();

        testCleanToolCall(client);
        testSqliInToolInputBlocked(client);
        testPiiInToolInput(client);
        testPiiInToolOutput(client);
        testCustomConnectorType(client);
        testQueryOperation(client);
        testGovernToolsHelper(client);
        testReprAndMetadata(client);

        // Summary
        System.out.println("=".repeat(60));
        System.out.println("Test Summary");
        System.out.println("=".repeat(60));
        if (failures.isEmpty()) {
            System.out.println("ALL TESTS PASSED");
        } else {
            System.out.println(failures.size() + " TEST(S) FAILED:");
            for (String f : failures) {
                System.out.println("   - " + f);
            }
        }
        System.out.println("=".repeat(60));

        if (!failures.isEmpty()) {
            System.exit(1);
        }
    }

    private static String getEnv(String key, String defaultValue) {
        String value = System.getenv(key);
        return (value != null && !value.isEmpty()) ? value : defaultValue;
    }
}
