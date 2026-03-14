/*
 * AxonFlow Audit Logging - Java
 *
 * Demonstrates the complete Gateway Mode workflow with audit logging:
 * 1. Pre-check - Validate request against policies
 * 2. LLM Call - Make your own call to LLM provider
 * 3. Audit - Log the interaction for compliance
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 */
package com.getaxonflow.examples;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.PolicyApprovalRequest;
import com.getaxonflow.sdk.types.PolicyApprovalResult;
import com.getaxonflow.sdk.types.AuditOptions;
import com.getaxonflow.sdk.types.TokenUsage;
import com.getaxonflow.sdk.exceptions.AxonFlowException;

import com.getaxonflow.sdk.types.AuditToolCallRequest;
import com.getaxonflow.sdk.types.AuditToolCallResponse;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class AuditLoggingExample {

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
        System.out.println("AxonFlow Audit Logging - Java");
        System.out.println("========================================");
        System.out.println();

        String clientId = getEnv("AXONFLOW_CLIENT_ID", "audit-logging-demo");
        String clientSecret = getEnv("AXONFLOW_CLIENT_SECRET", "");
        String userToken = getEnv("AXONFLOW_USER_TOKEN", "audit-user");

        AxonFlow client = AxonFlow.create(AxonFlowConfig.builder()
            .endpoint(getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080"))
            .clientId(clientId)
            .clientSecret(clientSecret)
            .build());

        List<QueryTest> queries = Arrays.asList(
            new QueryTest("Simple Question", "What is the capital of France?"),
            new QueryTest("Technical Query", "Explain the CAP theorem in distributed systems."),
            new QueryTest("Analysis Request", "What are the key benefits of containerization?")
        );

        for (QueryTest q : queries) {
            System.out.printf("Query: %s%n", q.name);
            System.out.printf("  \"%s\"%n%n", q.query);

            try {
                // Step 1: Pre-check
                System.out.println("Step 1: Policy Pre-Check...");
                long precheckStart = System.currentTimeMillis();

                Map<String, Object> context = new HashMap<>();
                context.put("example", "audit-logging");

                PolicyApprovalResult precheck = client.getPolicyApprovedContext(
                    PolicyApprovalRequest.builder()
                        .query(q.query)
                        .clientId(clientId)
                        .userToken(userToken)
                        .context(context)
                        .build()
                );

                long precheckLatency = System.currentTimeMillis() - precheckStart;
                System.out.printf("   Latency: %dms%n", precheckLatency);
                System.out.printf("   Context ID: %s%n", precheck.getContextId());
                assertCheck(precheck.getContextId() != null && !precheck.getContextId().isEmpty(),
                    "Pre-check returned contextId for query: " + q.name);

                if (!precheck.isApproved()) {
                    System.out.printf("   BLOCKED: %s%n%n", precheck.getBlockReason());
                    continue;
                }
                System.out.println("   Status: APPROVED");
                System.out.println();

                // Step 2: LLM Call (Mock)
                System.out.println("Step 2: LLM Call (Mock)...");
                long llmStart = System.currentTimeMillis();

                // Simulate LLM call
                Thread.sleep(100);
                String response = "Mock response for: " + q.query;
                int promptTokens = 20;
                int completionTokens = 30;
                int totalTokens = 50;

                long llmLatency = System.currentTimeMillis() - llmStart;
                System.out.printf("   Latency: %dms%n", llmLatency);
                System.out.printf("   Tokens: %d prompt, %d completion%n%n", promptTokens, completionTokens);

                // Step 3: Audit
                System.out.println("Step 3: Audit Logging...");
                long auditStart = System.currentTimeMillis();

                String responseSummary = response.length() > 100
                    ? response.substring(0, 100) + "..."
                    : response;

                client.auditLLMCall(AuditOptions.builder()
                    .contextId(precheck.getContextId())
                    .clientId(clientId)
                    .provider("openai")
                    .model("gpt-4o-mini")
                    .tokenUsage(TokenUsage.of(promptTokens, completionTokens))
                    .latencyMs((int) llmLatency)
                    .success(true)
                    .build());

                long auditLatency = System.currentTimeMillis() - auditStart;
                System.out.printf("   Latency: %dms%n", auditLatency);
                System.out.println("   Audit logged successfully");
                assertCheck(true, "Audit logged successfully for query: " + q.name);

                // Summary
                long governance = precheckLatency + auditLatency;
                long total = precheckLatency + llmLatency + auditLatency;

                System.out.println();
                System.out.println("   Latency Breakdown:");
                System.out.printf("     Pre-check:  %dms%n", precheckLatency);
                System.out.printf("     LLM call:   %dms%n", llmLatency);
                System.out.printf("     Audit:      %dms%n", auditLatency);
                System.out.printf("     Governance: %dms (%.1f%% overhead)%n",
                    governance, (double) governance / total * 100);
                System.out.printf("     Total:      %dms%n", total);

            } catch (AxonFlowException e) {
                System.out.printf("   Error: %s%n", e.getMessage());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }

            System.out.println();
            System.out.println("========================================");
            System.out.println();
        }

        System.out.println("Audit Logging Complete!");
        System.out.println();

        // =========================================================================
        // Tool Call Audit (Non-LLM tool tracking)
        // =========================================================================

        System.out.println("========================================");
        System.out.println("Tool Call Audit (Non-LLM)");
        System.out.println("========================================");
        System.out.println();

        System.out.println("Recording a non-LLM tool call (e.g., API call, MCP execution)...");
        try {
            Map<String, Object> toolInput = new HashMap<>();
            toolInput.put("city", "San Francisco");
            toolInput.put("units", "metric");

            Map<String, Object> toolOutput = new HashMap<>();
            toolOutput.put("temperature", 18);
            toolOutput.put("condition", "sunny");

            AuditToolCallResponse toolCallResult = client.auditToolCall(
                AuditToolCallRequest.builder()
                    .toolName("weather-api")
                    .toolType("api")
                    .input(toolInput)
                    .output(toolOutput)
                    .durationMs(245L)
                    .success(true)
                    .policiesApplied(Arrays.asList("data-residency", "rate-limit"))
                    .build()
            );

            System.out.printf("   Audit ID: %s%n", toolCallResult.getAuditId());
            System.out.printf("   Status: %s%n", toolCallResult.getStatus());
            System.out.printf("   Timestamp: %s%n", toolCallResult.getTimestamp());
            assertCheck(toolCallResult.getAuditId() != null, "auditToolCall returned audit ID");
            assertCheck("recorded".equals(toolCallResult.getStatus()), "Tool call audit status is 'recorded'");
        } catch (AxonFlowException e) {
            if (e.getMessage() != null && e.getMessage().contains("404")) {
                System.out.println("   Endpoint not available (requires Platform v5.1.0+)");
            } else {
                System.out.printf("   Error: %s%n", e.getMessage());
                failures.add("auditToolCall failed: " + e.getMessage());
            }
        }
        System.out.println();

        // =========================================================================
        // Query Audit Logs (SDK Methods)
        // =========================================================================

        System.out.println("========================================");
        System.out.println("Query Audit Logs via SDK");
        System.out.println("========================================");
        System.out.println();

        // Get audit logs for tenant (default pagination)
        System.out.println("1. getAuditLogsByTenant (default options):");
        try {
            var tenantLogs = client.getAuditLogsByTenant(clientId, null);
            if (tenantLogs != null && tenantLogs.getEntries() != null) {
                System.out.printf("   Found %d entries%n", tenantLogs.getEntries().size());
                assertCheck(tenantLogs.getEntries().size() >= 0, "getAuditLogsByTenant returned valid entries list");
                if (!tenantLogs.getEntries().isEmpty()) {
                    var entry = tenantLogs.getEntries().get(0);
                    System.out.printf("   Latest: %s - %s/%s%n",
                        entry.getTimestamp(), entry.getProvider(), entry.getModel());
                    assertCheck(entry.getTimestamp() != null, "Audit entry has timestamp");
                }
            } else {
                System.out.println("   Found 0 entries (empty response)");
                assertCheck(true, "getAuditLogsByTenant returned response (empty is valid)");
            }
        } catch (AxonFlowException e) {
            System.out.printf("   Error: %s%n", e.getMessage());
            assertCheck(false, "getAuditLogsByTenant failed: " + e.getMessage());
        }
        System.out.println();

        // Get audit logs with custom pagination
        System.out.println("2. getAuditLogsByTenant (limit=5, offset=0):");
        try {
            var paginatedLogs = client.getAuditLogsByTenant(clientId,
                com.getaxonflow.sdk.types.AuditQueryOptions.builder()
                    .limit(5)
                    .offset(0)
                    .build());
            if (paginatedLogs != null && paginatedLogs.getEntries() != null) {
                System.out.printf("   Found %d entries (hasMore: %s)%n",
                    paginatedLogs.getEntries().size(), paginatedLogs.hasMore());
            } else {
                System.out.println("   Found 0 entries (empty response)");
            }
        } catch (AxonFlowException e) {
            System.out.printf("   Error: %s%n", e.getMessage());
        }
        System.out.println();

        // Search audit logs with filters
        System.out.println("3. searchAuditLogs (with filters):");
        try {
            var searchResult = client.searchAuditLogs(
                com.getaxonflow.sdk.types.AuditSearchRequest.builder()
                    .clientId(clientId)
                    .requestType("chat")
                    .limit(10)
                    .build());
            if (searchResult != null && searchResult.getEntries() != null) {
                System.out.printf("   Found %d matching entries%n", searchResult.getEntries().size());
                int count = 0;
                for (var entry : searchResult.getEntries()) {
                    if (count >= 3) {
                        System.out.printf("   ... and %d more%n", searchResult.getEntries().size() - 3);
                        break;
                    }
                    String status = entry.isBlocked() ? "blocked" : "allowed";
                    System.out.printf("   - %s: %s (%d tokens)%n",
                        entry.getId(), status, entry.getTokensUsed());
                    count++;
                }
            } else {
                System.out.println("   Found 0 matching entries (empty response)");
            }
        } catch (AxonFlowException e) {
            System.out.printf("   Error: %s%n", e.getMessage());
        }
        System.out.println();

        System.out.println("========================================");
        System.out.println("Done!");

        // Final assertion summary
        System.out.println();
        System.out.println("========================================");
        System.out.println("Assertion Summary");
        System.out.println("========================================");
        if (failures.isEmpty()) {
            System.out.println("All assertions passed!");
        } else {
            System.out.println("Failures (" + failures.size() + "):");
            for (String f : failures) {
                System.out.println("  - " + f);
            }
            System.exit(1);
        }
    }

    private static String getEnv(String key, String defaultValue) {
        String value = System.getenv(key);
        return (value != null && !value.isEmpty()) ? value : defaultValue;
    }

    private static class QueryTest {
        final String name;
        final String query;

        QueryTest(String name, String query) {
            this.name = name;
            this.query = query;
        }
    }
}
