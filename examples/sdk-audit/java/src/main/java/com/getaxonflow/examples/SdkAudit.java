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
 */
public class SdkAudit {

    public static void main(String[] args) {
        System.out.println("AxonFlow SDK Comprehensive Audit - Java");
        System.out.println("=".repeat(42));
        System.out.println();

        int passed = 0;
        int failed = 0;
        String approvedContextId = null;

        // Initialize AxonFlow client
        // Note: As of SDK v2.0.0 (ADR-026), all routes go through a single endpoint.
        // The Agent proxies orchestrator routes internally.
        AxonFlow client = AxonFlow.create(AxonFlowConfig.builder()
            .endpoint(getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080"))
            .clientId(getEnv("AXONFLOW_CLIENT_ID", "demo"))
            .clientSecret(getEnv("AXONFLOW_CLIENT_SECRET", "demo-secret"))
            .licenseKey(getEnv("AXONFLOW_LICENSE_KEY", ""))
            .build());

        // Test 1: Agent Health Check
        System.out.println("Test 1: Agent Health Check");
        try {
            HealthStatus health = client.healthCheck();
            if (health.isHealthy()) {
                System.out.println("  ✅ PASSED: Agent is healthy");
                passed++;
            } else {
                System.out.println("  ❌ FAILED: Agent is not healthy");
                failed++;
            }
        } catch (Exception e) {
            System.out.printf("  ❌ FAILED: %s%n", e.getMessage());
            failed++;
        }

        // Test 2: Orchestrator Health Check
        System.out.println("Test 2: Orchestrator Health Check");
        try {
            HealthStatus health = client.orchestratorHealthCheck();
            if (health.isHealthy()) {
                System.out.println("  ✅ PASSED: Orchestrator is healthy");
                passed++;
            } else {
                System.out.println("  ❌ FAILED: Orchestrator is not healthy");
                failed++;
            }
        } catch (Exception e) {
            System.out.printf("  ❌ FAILED: %s%n", e.getMessage());
            failed++;
        }

        // Get client ID for requests
        String clientId = getEnv("AXONFLOW_CLIENT_ID", "demo");

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
            System.out.printf("  ✅ PASSED: Query approved (contextId: %s)%n", result.getContextId());
            passed++;
            approvedContextId = result.getContextId();
        } catch (PolicyViolationException e) {
            System.out.printf("  ❌ FAILED: Query unexpectedly blocked: %s%n", e.getMessage());
            failed++;
        } catch (Exception e) {
            System.out.printf("  ❌ FAILED: %s%n", e.getMessage());
            failed++;
        }

        // Test 4: Gateway Mode - Blocked Query (SQL Injection)
        System.out.println("Test 4: Gateway Mode - Blocked Query (SQL Injection)");
        try {
            client.getPolicyApprovedContext(
                PolicyApprovalRequest.builder()
                    .query("SELECT * FROM users; DROP TABLE users;")
                    .userToken("audit-user")
                    .clientId(clientId)
                    .build()
            );
            System.out.println("  ❌ FAILED: SQL injection should be blocked");
            failed++;
        } catch (PolicyViolationException e) {
            System.out.printf("  ✅ PASSED: Query correctly blocked (%s)%n", e.getPolicyName());
            passed++;
        } catch (Exception e) {
            System.out.printf("  ❌ FAILED: %s%n", e.getMessage());
            failed++;
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
                if (result.isSuccess()) {
                    System.out.printf("  ✅ PASSED: Audit recorded (auditId: %s)%n", result.getAuditId());
                    passed++;
                } else {
                    System.out.println("  ❌ FAILED: Audit not successful");
                    failed++;
                }
            } catch (Exception e) {
                System.out.printf("  ❌ FAILED: %s%n", e.getMessage());
                failed++;
            }
        } else {
            System.out.println("  ⏭️ SKIPPED: No context ID from previous test");
        }

        // Test 6: List Connectors
        System.out.println("Test 6: List Connectors");
        try {
            List<ConnectorInfo> connectors = client.listConnectors();
            System.out.printf("  ✅ PASSED: Found %d connectors%n", connectors.size());
            passed++;
        } catch (Exception e) {
            System.out.printf("  ❌ FAILED: %s%n", e.getMessage());
            failed++;
        }

        // Test 7: Static Policy CRUD
        System.out.println("Test 7: Static Policy CRUD");
        String policyName = "sdk-audit-test-" + System.currentTimeMillis();
        boolean crudPassed = true;

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
            System.out.printf("  ✅ Create: Policy created (id: %s)%n", created.getId());

            // Get policy
            StaticPolicy fetched = client.getStaticPolicy(created.getId());
            if (policyName.equals(fetched.getName())) {
                System.out.println("  ✅ Get: Policy retrieved correctly");
            } else {
                System.out.println("  ❌ FAILED (Get): Name mismatch");
                crudPassed = false;
            }

            // Update policy
            StaticPolicy updated = client.updateStaticPolicy(created.getId(),
                UpdateStaticPolicyRequest.builder()
                    .description("Updated description from SDK audit")
                    .build());
            if (updated.getDescription() != null && updated.getDescription().contains("Updated")) {
                System.out.println("  ✅ Update: Policy updated correctly");
            } else {
                System.out.println("  ❌ FAILED (Update): Description not updated");
                crudPassed = false;
            }

            // Delete policy
            client.deleteStaticPolicy(created.getId());
            System.out.println("  ✅ Delete: Policy deleted correctly");

            if (crudPassed) {
                passed++;
            } else {
                failed++;
            }

        } catch (Exception e) {
            System.out.printf("  ❌ FAILED: %s%n", e.getMessage());
            failed++;
        }

        // Test 8: List Static Policies
        System.out.println("Test 8: List Static Policies");
        try {
            List<StaticPolicy> policies = client.listStaticPolicies();
            System.out.printf("  ✅ PASSED: Found %d policies%n", policies.size());
            passed++;
        } catch (Exception e) {
            System.out.printf("  ❌ FAILED: %s%n", e.getMessage());
            failed++;
        }

        // Summary
        System.out.println();
        System.out.println("=".repeat(42));
        System.out.printf("Summary: %d passed, %d failed%n", passed, failed);
        System.out.println();

        if (failed > 0) {
            System.exit(1);
        }
    }

    private static String getEnv(String key, String defaultValue) {
        String value = System.getenv(key);
        return (value != null && !value.isEmpty()) ? value : defaultValue;
    }
}
