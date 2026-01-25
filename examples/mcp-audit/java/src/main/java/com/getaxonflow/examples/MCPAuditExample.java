/*
 * MCP Audit Logging Example - Java SDK
 *
 * This example demonstrates how MCP query operations are automatically
 * audited by AxonFlow. Every MCP query/execute operation is logged to
 * the mcp_query_audits table with policy evaluation results.
 *
 * What gets audited:
 *   - Request phase: SQLi detection, PII blocking
 *   - Response phase: PII redaction
 *   - Exfiltration checks: Row/volume limits
 *   - Final result: success/failure, duration
 *
 * Usage:
 *   docker compose up -d  # Start AxonFlow
 *   cd examples/mcp-audit/java
 *   mvn exec:java -q
 */

package com.getaxonflow.examples;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.ConnectorResponse;
import com.getaxonflow.sdk.types.ConnectorPolicyInfo;

public class MCPAuditExample {
    public static void main(String[] args) {
        // Get configuration from environment
        String agentUrl = System.getenv("AGENT_URL");
        if (agentUrl == null || agentUrl.isEmpty()) {
            agentUrl = "http://localhost:8080";
        }

        String clientId = System.getenv("CLIENT_ID");
        if (clientId == null || clientId.isEmpty()) {
            clientId = "demo-client";
        }

        String clientSecret = System.getenv("CLIENT_SECRET");
        if (clientSecret == null || clientSecret.isEmpty()) {
            clientSecret = "demo-secret";
        }

        System.out.println("==============================================");
        System.out.println("MCP Audit Logging Example - Java SDK");
        System.out.println("==============================================");
        System.out.println("Agent URL: " + agentUrl);
        System.out.println("Client ID: " + clientId);
        System.out.println();

        // Create AxonFlow client
        AxonFlowConfig config = AxonFlowConfig.builder()
            .endpoint(agentUrl)
            .clientId(clientId)
            .clientSecret(clientSecret)
            .build();

        try (AxonFlow client = AxonFlow.create(config)) {
            // Test 1: Simple query (creates audit entry)
            System.out.println("Test 1: Execute simple MCP query...");
            System.out.println("----------------------------------------------");

            try {
                ConnectorResponse result = client.mcpQuery("postgres", "SELECT 1 as test_value, 'hello' as test_message");
                System.out.println("SUCCESS: Query executed");
                System.out.println("  Success: " + result.isSuccess());
                System.out.println("  Processing time: " + result.getProcessingTime());
                ConnectorPolicyInfo policyInfo = result.getPolicyInfo();
                if (policyInfo != null) {
                    System.out.println("  Policies evaluated: " + policyInfo.getPoliciesEvaluated());
                    System.out.println("  Blocked: " + policyInfo.isBlocked());
                    System.out.println("  Redactions applied: " + policyInfo.getRedactionsApplied());
                }
            } catch (Exception e) {
                System.out.println("Query error (expected if postgres not configured): " + e.getMessage());
            }
            System.out.println();

            // Test 2: Query that may trigger PII detection
            System.out.println("Test 2: Execute query with potential PII fields...");
            System.out.println("----------------------------------------------");

            try {
                ConnectorResponse result = client.mcpQuery("postgres", "SELECT email, phone, name FROM users LIMIT 5");
                System.out.println("SUCCESS: Query executed");
                System.out.println("  Success: " + result.isSuccess());
                System.out.println("  Redacted: " + result.isRedacted());
                if (!result.getRedactedFields().isEmpty()) {
                    System.out.println("  PII REDACTED! Fields: " + result.getRedactedFields());
                }
                ConnectorPolicyInfo policyInfo = result.getPolicyInfo();
                if (policyInfo != null) {
                    System.out.println("  Policies evaluated: " + policyInfo.getPoliciesEvaluated());
                    if (policyInfo.getRedactionsApplied() > 0) {
                        System.out.println("  Redactions applied: " + policyInfo.getRedactionsApplied());
                    }
                }
            } catch (Exception e) {
                System.out.println("Query error: " + e.getMessage());
            }
            System.out.println();

            // Test 3: Query with SQLi pattern (should be blocked)
            System.out.println("Test 3: Execute query with SQLi pattern (should be blocked)...");
            System.out.println("----------------------------------------------");

            try {
                client.mcpQuery("postgres", "SELECT * FROM users; DROP TABLE users;--");
                System.out.println("Note: SQLi detection may not be enabled");
            } catch (Exception e) {
                System.out.println("Query blocked as expected: " + e.getMessage());
                System.out.println("SUCCESS: SQLi attempt was blocked and audit logged");
            }
            System.out.println();

            // Test 4: Execute (INSERT) operation
            System.out.println("Test 4: Execute INSERT operation...");
            System.out.println("----------------------------------------------");

            try {
                ConnectorResponse result = client.mcpExecute("postgres", "INSERT INTO audit_test (name) VALUES ('test')");
                System.out.println("SUCCESS: Execute completed");
                System.out.println("  Success: " + result.isSuccess());
                System.out.println("  Processing time: " + result.getProcessingTime());
            } catch (Exception e) {
                System.out.println("Execute error (expected if table doesn't exist): " + e.getMessage());
            }
            System.out.println();

            System.out.println("==============================================");
            System.out.println("MCP Audit Logging Tests Complete!");
            System.out.println("==============================================");
            System.out.println();
            System.out.println("All MCP operations above have been logged to the");
            System.out.println("mcp_query_audits table. Each entry includes:");
            System.out.println("  - audit_id: Unique identifier");
            System.out.println("  - tenant_id, client_id, user_id: Who made the request");
            System.out.println("  - connector_name, operation: What was requested");
            System.out.println("  - request_blocked, request_block_reason: If request was blocked");
            System.out.println("  - response_redacted, response_redacted_fields: If PII was redacted");
            System.out.println("  - exfil_exceeded, exfil_limit_type: If exfiltration limit hit");
            System.out.println("  - success, error_message: Final result");
            System.out.println("  - duration_ms: How long it took");
        }
    }
}
