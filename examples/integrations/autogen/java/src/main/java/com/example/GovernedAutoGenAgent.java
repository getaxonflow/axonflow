package com.example;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.*;
import com.getaxonflow.sdk.exceptions.AxonFlowException;
import com.getaxonflow.sdk.exceptions.PolicyViolationException;

import java.util.*;

/**
 * AutoGen + AxonFlow Integration Example (Java SDK)
 *
 * This example demonstrates how to add AxonFlow governance to AutoGen-style
 * multi-agent workflows using the Java SDK's Gateway Mode.
 *
 * Gateway Mode provides:
 * - Policy evaluation before LLM calls
 * - PII detection and blocking
 * - SQL injection prevention
 * - Audit logging after LLM responses
 *
 * Requirements:
 * - AxonFlow running locally (docker compose up)
 * - Java 17+
 * - Maven
 *
 * Usage:
 *     mvn compile exec:java
 */
public class GovernedAutoGenAgent {

    private static final String CLIENT_ID = "autogen-java-example";

    public static void main(String[] args) {
        // First check if AxonFlow is running
        if (!testHealthCheck()) {
            System.out.println("\nAxonFlow is not running. Start it with:");
            System.out.println("  cd /path/to/axonflow && docker compose up -d");
            System.exit(1);
        }

        System.out.println();
        testGatewayMode();
    }

    /**
     * Quick health check to verify AxonFlow is running.
     */
    private static boolean testHealthCheck() {
        String agentUrl = getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080");
        System.out.println("Checking AxonFlow at " + agentUrl + "...");

        AxonFlowConfig config = AxonFlowConfig.builder()
                .agentUrl(agentUrl)
                .build();

        try (AxonFlow client = AxonFlow.create(config)) {
            HealthStatus status = client.healthCheck();
            boolean healthy = status.isHealthy();
            System.out.println("Status: " + (healthy ? "healthy" : "unhealthy"));
            return healthy;
        } catch (Exception e) {
            System.out.println("Health check failed: " + e.getMessage());
            return false;
        }
    }

    /**
     * Test Gateway Mode integration with AxonFlow.
     *
     * Gateway Mode is ideal for AutoGen because:
     * - You maintain control over LLM provider selection
     * - Policy checks happen before your LLM call
     * - Audit logging happens after you receive the response
     * - Works seamlessly with AutoGen's agent orchestration
     */
    private static void testGatewayMode() {
        String agentUrl = getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080");

        System.out.println("=".repeat(60));
        System.out.println("AutoGen + AxonFlow Gateway Mode Example (Java SDK)");
        System.out.println("=".repeat(60));

        AxonFlowConfig config = AxonFlowConfig.builder()
                .agentUrl(agentUrl)
                .build();

        try (AxonFlow client = AxonFlow.create(config)) {
            String userToken = "autogen-java-user-123";

            // Test 1: Safe query (should be approved)
            System.out.println("\n[Test 1] Safe query - Research request");
            System.out.println("-".repeat(40));

            String safeQuery = "What are the best practices for secure API design?";
            System.out.println("Query: " + safeQuery);

            Map<String, Object> context = new HashMap<>();
            context.put("agent_name", "security_researcher");
            context.put("framework", "autogen");
            context.put("conversation_id", "conv-java-001");

            try {
                PolicyApprovalResult approved = client.getPolicyApprovedContext(
                        PolicyApprovalRequest.builder()
                                .query(safeQuery)
                                .userToken(userToken)
                                .clientId(CLIENT_ID)
                                .context(context)
                                .build()
                );

                System.out.println("Approved: " + approved.isApproved());
                if (approved.isApproved()) {
                    System.out.println("Context ID: " + approved.getContextId());

                    // In a real AutoGen integration, you would:
                    // 1. Call your LLM provider here
                    // 2. Get the response
                    // 3. Log it with auditLLMCall

                    String simulatedResponse = "Best practices for secure API design include: " +
                            "1) Use HTTPS, 2) Implement rate limiting, 3) Validate all inputs...";

                    // Audit the LLM call
                    client.auditLLMCall(
                            AuditOptions.builder()
                                    .contextId(approved.getContextId())
                                    .clientId(CLIENT_ID)
                                    .responseSummary(simulatedResponse.substring(0, Math.min(100, simulatedResponse.length())))
                                    .provider("openai")
                                    .model("gpt-4")
                                    .tokenUsage(TokenUsage.of(50, 100))
                                    .latencyMs(150)
                                    .build()
                    );

                    System.out.println("Response: " + simulatedResponse.substring(0, Math.min(80, simulatedResponse.length())) + "...");
                    System.out.println("Audit logged successfully!");
                    System.out.println("\u2713 Safe query processed successfully!");
                }
            } catch (PolicyViolationException e) {
                System.out.println("Blocked: true");
                System.out.println("Policy: " + e.getPolicyName());
                System.out.println("Reason: " + e.getMessage());
            } catch (Exception e) {
                System.out.println("Error: " + e.getMessage());
            }

            // Test 2: Query with PII (should detect SSN)
            System.out.println("\n[Test 2] Query with PII - SSN Detection");
            System.out.println("-".repeat(40));

            String piiQuery = "Process payment for customer with SSN 123-45-6789";
            System.out.println("Query: " + piiQuery);

            context.put("agent_name", "payment_processor");

            try {
                PolicyApprovalResult approved = client.getPolicyApprovedContext(
                        PolicyApprovalRequest.builder()
                                .query(piiQuery)
                                .userToken(userToken)
                                .clientId(CLIENT_ID)
                                .context(context)
                                .build()
                );

                if (!approved.isApproved()) {
                    System.out.println("Blocked: true");
                    System.out.println("\u2713 PII correctly detected!");
                } else {
                    System.out.println("Approved: true (PII detection may be in warn mode)");
                }
            } catch (PolicyViolationException e) {
                System.out.println("Blocked: true");
                System.out.println("Block reason: " + e.getMessage());
                System.out.println("\u2713 PII correctly detected and blocked!");
            } catch (Exception e) {
                String errorMsg = e.getMessage();
                if (errorMsg != null && (errorMsg.contains("Social Security") || errorMsg.toUpperCase().contains("PII"))) {
                    System.out.println("Blocked: true");
                    System.out.println("Block reason: " + errorMsg);
                    System.out.println("\u2713 PII correctly detected and blocked!");
                } else {
                    System.out.println("Error: " + e.getMessage());
                }
            }

            // Test 3: SQL injection (should be blocked)
            System.out.println("\n[Test 3] SQL Injection - Should be blocked");
            System.out.println("-".repeat(40));

            String sqliQuery = "SELECT * FROM users WHERE id=1; DROP TABLE users;--";
            System.out.println("Query: " + sqliQuery);

            context.put("agent_name", "data_analyst");

            try {
                PolicyApprovalResult approved = client.getPolicyApprovedContext(
                        PolicyApprovalRequest.builder()
                                .query(sqliQuery)
                                .userToken(userToken)
                                .clientId(CLIENT_ID)
                                .context(context)
                                .build()
                );

                if (!approved.isApproved()) {
                    System.out.println("Blocked: true");
                    System.out.println("\u2713 SQL injection correctly blocked!");
                } else {
                    System.out.println("Unexpected: Query was approved");
                }
            } catch (PolicyViolationException e) {
                System.out.println("Blocked: true");
                System.out.println("Block reason: " + e.getMessage());
                System.out.println("\u2713 SQL injection correctly blocked!");
            } catch (Exception e) {
                String errorMsg = e.getMessage();
                if (errorMsg != null && errorMsg.toLowerCase().contains("sql injection")) {
                    System.out.println("Blocked: true");
                    System.out.println("Block reason: " + errorMsg);
                    System.out.println("\u2713 SQL injection correctly blocked!");
                } else {
                    System.out.println("Error: " + e.getMessage());
                }
            }

            // Test 4: Multi-agent conversation simulation
            System.out.println("\n[Test 4] Multi-Agent Conversation (AutoGen Style)");
            System.out.println("-".repeat(40));

            List<Map<String, String>> agents = Arrays.asList(
                    Map.of("name", "planner", "role", "Plans the research approach"),
                    Map.of("name", "researcher", "role", "Gathers information"),
                    Map.of("name", "critic", "role", "Reviews and validates findings")
            );

            String conversationId = "autogen-group-chat-001";

            for (Map<String, String> agent : agents) {
                String agentName = agent.get("name");
                String query = "Analyze from " + agentName + "'s perspective: AI safety best practices";

                context.put("agent_name", agentName);
                context.put("agent_role", agent.get("role"));
                context.put("conversation_id", conversationId);
                context.put("multi_agent", "true");

                try {
                    PolicyApprovalResult approved = client.getPolicyApprovedContext(
                            PolicyApprovalRequest.builder()
                                    .query(query)
                                    .userToken(userToken)
                                    .clientId(CLIENT_ID)
                                    .context(context)
                                    .build()
                    );

                    if (approved.isApproved()) {
                        // Simulate LLM response and audit
                        String response = "Analysis from " + agentName + ": ...";
                        client.auditLLMCall(
                                AuditOptions.builder()
                                        .contextId(approved.getContextId())
                                        .clientId(CLIENT_ID)
                                        .responseSummary(response)
                                        .provider("openai")
                                        .model("gpt-4")
                                        .tokenUsage(TokenUsage.of(30, 60))
                                        .latencyMs(100)
                                        .build()
                        );
                        System.out.println("Agent '" + agentName + "': \u2713 Processed and audited");
                    } else {
                        System.out.println("Agent '" + agentName + "': \u2717 Blocked");
                    }
                } catch (PolicyViolationException e) {
                    System.out.println("Agent '" + agentName + "': \u2717 Blocked - " + e.getMessage());
                } catch (Exception e) {
                    System.out.println("Agent '" + agentName + "': Error - " + e.getMessage());
                }
            }

            System.out.println("\n" + "=".repeat(60));
            System.out.println("All tests completed!");
            System.out.println("=".repeat(60));
        }
    }

    private static String getEnv(String key, String defaultValue) {
        String value = System.getenv(key);
        return (value != null && !value.isEmpty()) ? value : defaultValue;
    }
}
