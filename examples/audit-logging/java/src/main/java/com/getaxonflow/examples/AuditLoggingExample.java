/*
 * AxonFlow Audit Logging - Java
 *
 * Demonstrates the complete Gateway Mode workflow with audit logging:
 * 1. Pre-check - Validate request against policies
 * 2. LLM Call - Make your own call to LLM provider
 * 3. Audit - Log the interaction for compliance
 */
package com.getaxonflow.examples;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.PolicyApprovalRequest;
import com.getaxonflow.sdk.types.PolicyApprovalResult;
import com.getaxonflow.sdk.types.AuditOptions;
import com.getaxonflow.sdk.types.TokenUsage;
import com.getaxonflow.sdk.exceptions.AxonFlowException;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class AuditLoggingExample {

    private static final String CLIENT_ID = "audit-logging-demo";

    public static void main(String[] args) {
        System.out.println("AxonFlow Audit Logging - Java");
        System.out.println("========================================");
        System.out.println();

        AxonFlow client = AxonFlow.create(AxonFlowConfig.builder()
            .agentUrl(getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080"))
            .licenseKey(getEnv("AXONFLOW_LICENSE_KEY", ""))
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
                        .clientId(CLIENT_ID)
                        .userToken("audit-user")
                        .context(context)
                        .build()
                );

                long precheckLatency = System.currentTimeMillis() - precheckStart;
                System.out.printf("   Latency: %dms%n", precheckLatency);
                System.out.printf("   Context ID: %s%n", precheck.getContextId());

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
                    .clientId(CLIENT_ID)
                    .provider("openai")
                    .model("gpt-3.5-turbo")
                    .tokenUsage(TokenUsage.of(promptTokens, completionTokens))
                    .latencyMs((int) llmLatency)
                    .success(true)
                    .build());

                long auditLatency = System.currentTimeMillis() - auditStart;
                System.out.printf("   Latency: %dms%n", auditLatency);
                System.out.println("   Audit logged successfully");

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
        System.out.println("Query audit logs via Orchestrator API:");
        System.out.println("  curl http://localhost:8081/api/v1/audit/tenant/audit-logging-demo");
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
