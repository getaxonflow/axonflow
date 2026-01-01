package com.example;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.*;
import com.getaxonflow.sdk.exceptions.PolicyViolationException;

import java.util.*;
import java.util.function.Function;

/**
 * Semantic Kernel + AxonFlow Integration Example (Java SDK)
 *
 * This example demonstrates how to add AxonFlow governance to Semantic Kernel-style
 * AI agent workflows. Semantic Kernel provides an SDK for building AI agents with
 * plugins, planners, and memory.
 *
 * Features demonstrated:
 * - Governed Kernel: AxonFlow policy enforcement for AI operations
 * - Plugin Governance: Each plugin call goes through policy checks
 * - Planner Integration: Plans are validated before execution
 * - Memory Governance: Sensitive data is protected
 *
 * Requirements:
 * - AxonFlow running locally (docker compose up)
 * - Java 17+
 * - Maven
 *
 * Usage:
 *     mvn compile exec:java
 */
public class GovernedSemanticKernel {

    private static final String CLIENT_ID = "semantic-kernel-example";

    public static void main(String[] args) {
        // First check if AxonFlow is running
        if (!testHealthCheck()) {
            System.out.println("\nAxonFlow is not running. Start it with:");
            System.out.println("  cd /path/to/axonflow && docker compose up -d");
            System.exit(1);
        }

        System.out.println();
        runKernelDemo();
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

    // =========================================================================
    // Semantic Kernel-style Components with Governance
    // =========================================================================

    /**
     * GovernedKernel wraps Semantic Kernel operations with AxonFlow governance.
     * All AI calls go through policy evaluation before execution.
     */
    static class GovernedKernel {
        private final AxonFlow axonflow;
        private final String userToken;
        private final Map<String, PluginFunction> plugins = new HashMap<>();

        public GovernedKernel(AxonFlow axonflow, String userToken) {
            this.axonflow = axonflow;
            this.userToken = userToken;
        }

        /**
         * Register a plugin function with the kernel.
         */
        public void registerPlugin(String name, String description, PluginFunction function) {
            plugins.put(name, function);
            System.out.println("   Registered plugin: " + name);
        }

        /**
         * Invoke a plugin with governance.
         */
        public PluginResult invokePlugin(String pluginName, String input) {
            System.out.println("\n[Kernel] Invoking plugin: " + pluginName);
            System.out.println("   Input: " + truncate(input, 50));

            // Get policy approval before plugin execution
            try {
                PolicyApprovalResult approved = axonflow.getPolicyApprovedContext(
                        PolicyApprovalRequest.builder()
                                .query(input)
                                .userToken(userToken)
                                .clientId(CLIENT_ID)
                                .context(Map.of(
                                        "plugin", pluginName,
                                        "framework", "semantic-kernel",
                                        "operation", "plugin_invoke"
                                ))
                                .build()
                );

                if (!approved.isApproved()) {
                    System.out.println("   BLOCKED: " + approved.getBlockReason());
                    return new PluginResult(false, null, approved.getBlockReason());
                }

                // Execute the plugin
                PluginFunction plugin = plugins.get(pluginName);
                if (plugin == null) {
                    return new PluginResult(false, null, "Plugin not found: " + pluginName);
                }

                String result = plugin.execute(input);

                // Audit the execution
                axonflow.auditLLMCall(
                        AuditOptions.builder()
                                .contextId(approved.getContextId())
                                .clientId(CLIENT_ID)
                                .responseSummary(truncate(result, 100))
                                .provider("semantic-kernel")
                                .model(pluginName)
                                .tokenUsage(TokenUsage.of(50, 100))
                                .latencyMs(50)
                                .build()
                );

                System.out.println("   ✓ Plugin executed and audited");
                return new PluginResult(true, result, null);

            } catch (PolicyViolationException e) {
                System.out.println("   BLOCKED: " + e.getMessage());
                return new PluginResult(false, null, e.getMessage());
            } catch (Exception e) {
                String errorMsg = e.getMessage();
                if (errorMsg != null && (errorMsg.contains("Social Security") ||
                        errorMsg.toLowerCase().contains("sql injection"))) {
                    System.out.println("   BLOCKED: " + errorMsg);
                    return new PluginResult(false, null, errorMsg);
                }
                System.out.println("   Error: " + e.getMessage());
                return new PluginResult(false, null, e.getMessage());
            }
        }

        /**
         * Execute a governed prompt.
         */
        public PluginResult invokePrompt(String prompt) {
            return invokePlugin("prompt", prompt);
        }
    }

    /**
     * Interface for plugin functions.
     */
    interface PluginFunction {
        String execute(String input);
    }

    /**
     * Result of a plugin invocation.
     */
    static class PluginResult {
        final boolean success;
        final String result;
        final String blockReason;

        PluginResult(boolean success, String result, String blockReason) {
            this.success = success;
            this.result = result;
            this.blockReason = blockReason;
        }
    }

    // =========================================================================
    // Demo: Governed Semantic Kernel Operations
    // =========================================================================

    private static void runKernelDemo() {
        String agentUrl = getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080");

        System.out.println("=".repeat(60));
        System.out.println("Semantic Kernel + AxonFlow Integration (Java SDK)");
        System.out.println("=".repeat(60));

        AxonFlowConfig config = AxonFlowConfig.builder()
                .agentUrl(agentUrl)
                .build();

        try (AxonFlow axonflow = AxonFlow.create(config)) {
            // Create governed kernel
            System.out.println("\n[Setup] Creating Governed Kernel...");
            GovernedKernel kernel = new GovernedKernel(axonflow, "sk-user-123");

            // Register plugins
            kernel.registerPlugin("summarize", "Summarizes text content", input ->
                    "Summary: " + truncate(input, 50) + "...");

            kernel.registerPlugin("translate", "Translates text to another language", input ->
                    "Translated: " + input);

            kernel.registerPlugin("search", "Searches for information", input ->
                    "Search results for: " + truncate(input, 30) + "...");

            kernel.registerPlugin("prompt", "Executes a prompt", input ->
                    "Response to: " + truncate(input, 30) + "...");

            // Test 1: Safe plugin call
            System.out.println("\n" + "=".repeat(60));
            System.out.println("[Test 1] Safe Plugin Call - Summarize");
            System.out.println("-".repeat(40));

            PluginResult result1 = kernel.invokePlugin("summarize",
                    "The quick brown fox jumps over the lazy dog. This is a classic pangram used for testing.");

            if (result1.success) {
                System.out.println("   Result: " + result1.result);
                System.out.println("   ✓ Safe plugin call succeeded!");
            }

            // Test 2: Safe prompt
            System.out.println("\n" + "=".repeat(60));
            System.out.println("[Test 2] Safe Prompt - Research Query");
            System.out.println("-".repeat(40));

            PluginResult result2 = kernel.invokePrompt(
                    "What are the key principles of responsible AI development?");

            if (result2.success) {
                System.out.println("   Result: " + result2.result);
                System.out.println("   ✓ Safe prompt succeeded!");
            }

            // Test 3: PII Detection
            System.out.println("\n" + "=".repeat(60));
            System.out.println("[Test 3] PII Detection - Should be blocked");
            System.out.println("-".repeat(40));

            PluginResult result3 = kernel.invokePlugin("search",
                    "Find customer record for SSN 123-45-6789");

            if (!result3.success && result3.blockReason != null) {
                System.out.println("   ✓ PII correctly detected and blocked!");
            }

            // Test 4: SQL Injection
            System.out.println("\n" + "=".repeat(60));
            System.out.println("[Test 4] SQL Injection - Should be blocked");
            System.out.println("-".repeat(40));

            PluginResult result4 = kernel.invokePlugin("search",
                    "SELECT * FROM users; DROP TABLE customers;--");

            if (!result4.success && result4.blockReason != null) {
                System.out.println("   ✓ SQL injection correctly blocked!");
            }

            // Test 5: Multi-plugin workflow
            System.out.println("\n" + "=".repeat(60));
            System.out.println("[Test 5] Multi-Plugin Workflow");
            System.out.println("-".repeat(40));

            String[] workflow = {"search", "summarize", "translate"};
            String workflowInput = "Find information about renewable energy trends";

            System.out.println("   Workflow: search → summarize → translate");
            System.out.println("   Input: " + workflowInput);

            String currentInput = workflowInput;
            boolean workflowSuccess = true;

            for (String pluginName : workflow) {
                PluginResult stepResult = kernel.invokePlugin(pluginName, currentInput);
                if (!stepResult.success) {
                    System.out.println("   ✗ Workflow blocked at: " + pluginName);
                    workflowSuccess = false;
                    break;
                }
                currentInput = stepResult.result;
            }

            if (workflowSuccess) {
                System.out.println("\n   Final result: " + truncate(currentInput, 50));
                System.out.println("   ✓ Multi-plugin workflow completed!");
            }

            System.out.println("\n" + "=".repeat(60));
            System.out.println("All tests completed!");
            System.out.println("=".repeat(60));
        }
    }

    // =========================================================================
    // Utility Methods
    // =========================================================================

    private static String getEnv(String key, String defaultValue) {
        String value = System.getenv(key);
        return (value != null && !value.isEmpty()) ? value : defaultValue;
    }

    private static String truncate(String text, int maxLength) {
        if (text == null) return "";
        if (text.length() <= maxLength) return text;
        return text.substring(0, maxLength) + "...";
    }
}
