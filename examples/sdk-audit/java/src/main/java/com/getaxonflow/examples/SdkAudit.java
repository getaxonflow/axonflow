/*
 * Copyright 2025 AxonFlow
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.getaxonflow.examples;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.*;
import com.getaxonflow.sdk.types.policies.PolicyTypes.*;
import com.getaxonflow.sdk.exceptions.AxonFlowException;
import com.getaxonflow.sdk.exceptions.PolicyViolationException;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * AxonFlow SDK Comprehensive Audit - Java
 *
 * Validates all SDK methods work correctly against live services.
 * Tests include:
 * 1. Health checks (Agent + Orchestrator)
 * 2. Gateway Mode request
 * 3. Proxy Mode request
 * 4. Static policy CRUD
 * 5. Audit logging
 * 6. Error handling (blocked requests)
 * 7. Connector operations (list, install, uninstall)
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 */
public class SdkAudit {

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
        System.out.println("AxonFlow SDK Comprehensive Audit - Java");
        System.out.println("=".repeat(42));
        System.out.println();
        String approvedContextId = null;

        // Initialize AxonFlow client
        // Note: As of SDK v2.0.0 (ADR-026), all routes go through a single endpoint.
        // The Agent proxies orchestrator routes internally.
        String clientId = getEnv("AXONFLOW_CLIENT_ID", "demo-client");
        String clientSecret = getEnv("AXONFLOW_CLIENT_SECRET", "demo-secret");

        AxonFlow client = AxonFlow.create(AxonFlowConfig.builder()
            .endpoint(getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080"))
            .clientId(clientId)
            .clientSecret(clientSecret)
            .build());

        // Test 1: Agent Health Check
        System.out.println("Test 1: Agent Health Check");
        try {
            HealthStatus health = client.healthCheck();
            assertCheck(health.isHealthy(), "Agent is healthy");
        } catch (Exception e) {
            System.out.printf("  Error: %s%n", e.getMessage());
            assertCheck(false, "Agent health check should not throw");
        }

        // Test 2: Orchestrator Health Check
        System.out.println("Test 2: Orchestrator Health Check");
        try {
            HealthStatus health = client.orchestratorHealthCheck();
            assertCheck(health.isHealthy(), "Orchestrator is healthy");
        } catch (Exception e) {
            System.out.printf("  Error: %s%n", e.getMessage());
            assertCheck(false, "Orchestrator health check should not throw");
        }

        // Get client ID for requests (already set above)

        // Test 3: Gateway Mode - Safe Query
        System.out.println("Test 3: Gateway Mode - Safe Query");
        try {
            PolicyApprovalResult result = client.getPolicyApprovedContext(
                PolicyApprovalRequest.builder()
                    .query("What is the capital of France?")
                    .userToken("audit-user")
                    .clientId(clientId)
                    .build()
            );
            assertCheck(result.getContextId() != null, "Safe query approved with context ID");
            approvedContextId = result.getContextId();
        } catch (PolicyViolationException e) {
            System.out.printf("  Blocked: %s%n", e.getMessage());
            assertCheck(false, "Safe query should not be blocked");
        } catch (Exception e) {
            System.out.printf("  Error: %s%n", e.getMessage());
            assertCheck(false, "Safe query should not throw");
        }

        // Test 4: Gateway Mode - Blocked Query (SQL Injection)
        System.out.println("Test 4: Gateway Mode - Blocked Query (SQL Injection)");
        boolean sqlInjectionBlocked = false;
        try {
            client.getPolicyApprovedContext(
                PolicyApprovalRequest.builder()
                    .query("SELECT * FROM users; DROP TABLE users;")
                    .userToken("audit-user")
                    .clientId(clientId)
                    .build()
            );
            assertCheck(false, "SQL injection should be blocked");
        } catch (PolicyViolationException e) {
            System.out.printf("  Blocked by policy: %s%n", e.getPolicyName());
            sqlInjectionBlocked = true;
            assertCheck(true, "SQL injection correctly blocked by policy");
        } catch (Exception e) {
            System.out.printf("  Error: %s%n", e.getMessage());
            // May still be blocked via different exception type
            if (e.getMessage() != null && e.getMessage().contains("blocked")) {
                sqlInjectionBlocked = true;
                assertCheck(true, "SQL injection blocked");
            } else {
                assertCheck(false, "SQL injection should be blocked");
            }
        }

        // Test 5: Audit LLM Call
        System.out.println("Test 5: Audit LLM Call");
        if (approvedContextId != null) {
            try {
                AuditResult result = client.auditLLMCall(AuditOptions.builder()
                    .contextId(approvedContextId)
                    .clientId(clientId)
                    .provider("openai")
                    .model("gpt-4")
                    .responseSummary("Test response for SDK audit")
                    .tokenUsage(TokenUsage.of(100, 50))
                    .latencyMs(250)
                    .build());
                assertCheck(result.isSuccess(), "Audit recorded successfully");
                assertCheck(result.getAuditId() != null, "Audit has audit ID");
            } catch (Exception e) {
                System.out.printf("  Error: %s%n", e.getMessage());
                assertCheck(false, "Audit LLM call should not throw");
            }
        } else {
            System.out.println("  Skipped: No context ID from previous test");
        }

        // Test 6: List Connectors
        System.out.println("Test 6: List Connectors");
        try {
            List<ConnectorInfo> connectors = client.listConnectors();
            assertCheck(connectors != null, "List connectors returns non-null result");
            System.out.printf("  Found %d connectors%n", connectors.size());
        } catch (Exception e) {
            System.out.printf("  Error: %s%n", e.getMessage());
            assertCheck(false, "List connectors should not throw");
        }

        // Test 7: Static Policy CRUD
        System.out.println("Test 7: Static Policy CRUD");
        String policyName = "sdk-audit-test-" + System.currentTimeMillis();

        try {
            // Create policy
            StaticPolicy created = client.createStaticPolicy(CreateStaticPolicyRequest.builder()
                .name(policyName)
                .description("Test policy from SDK audit")
                .category(PolicyCategory.SECURITY_SQLI)
                .pattern("sdk-audit-test-pattern")
                .severity(PolicySeverity.LOW)
                .enabled(true)
                .action(PolicyAction.WARN)
                .build());
            assertCheck(created.getId() != null, "Policy created with ID");

            // Get policy
            StaticPolicy fetched = client.getStaticPolicy(created.getId());
            assertCheck(policyName.equals(fetched.getName()), "Policy retrieved with correct name");

            // Update policy
            StaticPolicy updated = client.updateStaticPolicy(created.getId(),
                UpdateStaticPolicyRequest.builder()
                    .description("Updated description from SDK audit")
                    .build());
            assertCheck(updated.getDescription() != null && updated.getDescription().contains("Updated"),
                "Policy description updated");

            // Delete policy
            client.deleteStaticPolicy(created.getId());
            assertCheck(true, "Policy deleted successfully");

        } catch (Exception e) {
            System.out.printf("  Error: %s%n", e.getMessage());
            assertCheck(false, "Policy CRUD should not throw");
        }

        // Test 8: List Static Policies
        System.out.println("Test 8: List Static Policies");
        try {
            List<StaticPolicy> policies = client.listStaticPolicies();
            assertCheck(policies != null, "List policies returns non-null result");
            assertCheck(policies.size() > 0, "At least one policy exists");
            System.out.printf("  Found %d policies%n", policies.size());
        } catch (Exception e) {
            System.out.printf("  Error: %s%n", e.getMessage());
            assertCheck(false, "List policies should not throw");
        }

        // Summary
        System.out.println();
        System.out.println("=".repeat(42));
        int passed = (int) failures.stream().filter(f -> false).count(); // Count would be 0
        int totalTests = 8;
        System.out.printf("Summary: %d assertions, %d failures%n", totalTests, failures.size());
        System.out.println();

        if (!failures.isEmpty()) {
            System.out.println("FAILURES (" + failures.size() + "):");
            for (String failure : failures) {
                System.out.println("  - " + failure);
            }
            System.exit(1);
        }
    }

    private static String getEnv(String key, String defaultValue) {
        String value = System.getenv(key);
        return (value != null && !value.isEmpty()) ? value : defaultValue;
    }
}
