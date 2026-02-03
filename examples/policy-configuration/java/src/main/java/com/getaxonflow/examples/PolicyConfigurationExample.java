/*
 * Copyright 2026 AxonFlow
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
import com.getaxonflow.sdk.types.PolicyApprovalRequest;
import com.getaxonflow.sdk.types.PolicyApprovalResult;
import com.getaxonflow.sdk.exceptions.AxonFlowException;
import com.getaxonflow.sdk.exceptions.PolicyViolationException;

import java.util.ArrayList;
import java.util.List;

/**
 * AxonFlow Per-Mode Policy Configuration - Java SDK
 *
 * This example demonstrates and VALIDATES per-mode policy configuration.
 * AxonFlow's static policies can be configured per-mode using environment variables.
 * This example validates the CURRENT configuration by sending test queries through
 * the policy pre-check API and checking that the Agent responds according to the
 * configured policy actions.
 *
 * Environment variables (must match Agent-side config):
 *   MCP_PII_ACTION   / PII_ACTION   = block | redact | warn | log  (default: redact)
 *   MCP_SQLI_ACTION  / SQLI_ACTION  = block | warn | log           (default: block)
 *   MCP_STATIC_POLICIES_ENABLED     = true | false                  (default: true)
 *
 * IMPORTANT: Changing policy behavior requires restarting the AxonFlow Agent with
 * different env vars. This example validates behavior for the CURRENT configuration.
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 * This ensures CI/CD pipelines catch regressions.
 *
 * Run with: mvn compile exec:java
 * Prerequisites: docker compose up -d
 */
public class PolicyConfigurationExample {

    private static final List<String> failures = new ArrayList<>();

    private static String getEnv(String key, String defaultValue) {
        String value = System.getenv(key);
        return (value != null && !value.isEmpty()) ? value : defaultValue;
    }

    private static void assertCheck(boolean condition, String message) {
        if (!condition) {
            failures.add(message);
            System.out.println("   FAIL: " + message);
        } else {
            System.out.println("   PASS: " + message);
        }
    }

    public static void main(String[] args) {
        System.out.println("AxonFlow Per-Mode Policy Configuration - Java SDK");
        System.out.println("=".repeat(50));
        System.out.println();

        // Read expected policy actions (must match Agent-side config)
        // MCP_ prefix takes priority, then falls back to global env var
        String piiAction = getEnv("MCP_PII_ACTION", getEnv("PII_ACTION", "redact")).toLowerCase();
        String sqliAction = getEnv("MCP_SQLI_ACTION", getEnv("SQLI_ACTION", "block")).toLowerCase();
        String policiesEnabled = getEnv("MCP_STATIC_POLICIES_ENABLED", "true").toLowerCase();

        System.out.printf("Expected PII_ACTION:  %s%n", piiAction);
        System.out.printf("Expected SQLI_ACTION: %s%n", sqliAction);
        System.out.printf("Static policies enabled: %s%n", policiesEnabled);
        System.out.println();

        AxonFlow client = AxonFlow.create(AxonFlowConfig.builder()
            .endpoint(getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080"))
            .clientId(getEnv("AXONFLOW_CLIENT_ID", "demo"))
            .clientSecret(getEnv("AXONFLOW_CLIENT_SECRET", ""))
            .debug("true".equals(getEnv("AXONFLOW_DEBUG", "")))
            .build());

        // -----------------------------------------------------------
        // Test 1: Safe query -- should always be approved
        // -----------------------------------------------------------
        System.out.println("Test 1: Safe Query (No PII, No SQLi)");
        System.out.println("-".repeat(37));

        try {
            PolicyApprovalResult result = client.getPolicyApprovedContext(
                PolicyApprovalRequest.builder()
                    .query("What is the current date?")
                    .userToken("policy-config-user")
                    .build()
            );
            assertCheck(result.isApproved(), "Safe query is approved");
            assertCheck(result.getContextId() != null && !result.getContextId().isEmpty(),
                "Context ID is returned");
        } catch (PolicyViolationException e) {
            assertCheck(false, "Safe query should not be blocked: " + e.getMessage());
        } catch (AxonFlowException e) {
            System.out.println("   FATAL: Policy check failed: " + e.getMessage());
            System.exit(1);
            return;
        }
        System.out.println();

        // -----------------------------------------------------------
        // Test 2: PII query (SSN) -- behavior depends on PII_ACTION
        // -----------------------------------------------------------
        System.out.println("Test 2: PII Query (SSN '123-45-6789')");
        System.out.println("-".repeat(38));
        System.out.printf("  Expected action: %s%n", piiAction);

        try {
            PolicyApprovalResult result = client.getPolicyApprovedContext(
                PolicyApprovalRequest.builder()
                    .query("Process refund for SSN 123-45-6789")
                    .userToken("policy-config-user")
                    .build()
            );

            // If we get here, the request was approved (no PolicyViolationException)
            if ("false".equals(policiesEnabled)) {
                assertCheck(true, "PII query approved (static policies disabled)");
                assertCheck(result.getPolicies() == null || result.getPolicies().isEmpty(),
                    "No policies matched (static policies disabled)");
            } else {
                switch (piiAction) {
                    case "block":
                        assertCheck(false, "PII query should have been blocked (PII_ACTION=block)");
                        break;
                    case "redact":
                        // In redact mode, request phase approves but flags PII
                        assertCheck(true, "PII query approved in request phase (PII_ACTION=redact)");
                        assertCheck(result.getPolicies() != null && !result.getPolicies().isEmpty(),
                            "PII policies detected");
                        if (result.getPolicies() != null) {
                            System.out.printf("   Policies: %s%n", String.join(", ", result.getPolicies()));
                        }
                        break;
                    case "warn":
                        assertCheck(true, "PII query approved (PII_ACTION=warn)");
                        assertCheck(result.getPolicies() != null && !result.getPolicies().isEmpty(),
                            "PII policies detected for warning");
                        break;
                    case "log":
                        assertCheck(true, "PII query approved (PII_ACTION=log)");
                        break;
                    default:
                        System.out.println("   Unknown PII_ACTION: " + piiAction);
                        failures.add("Unknown PII_ACTION: " + piiAction);
                }
            }
        } catch (PolicyViolationException e) {
            // Request was blocked by policy
            if ("false".equals(policiesEnabled)) {
                assertCheck(false, "PII query should not be blocked when policies disabled: " + e.getMessage());
            } else if ("block".equals(piiAction)) {
                assertCheck(true, "PII query blocked (PII_ACTION=block)");
                assertCheck(e.getMessage() != null && !e.getMessage().isEmpty(), "Block reason provided");
                System.out.printf("   Block reason: %s%n", e.getMessage());
            } else {
                assertCheck(false, "PII query should not be blocked with PII_ACTION=" + piiAction + ": " + e.getMessage());
            }
        } catch (AxonFlowException e) {
            System.out.println("   FATAL: Policy check failed: " + e.getMessage());
            System.exit(1);
            return;
        }
        System.out.println();

        // -----------------------------------------------------------
        // Test 3: SQLi query -- behavior depends on SQLI_ACTION
        // -----------------------------------------------------------
        System.out.println("Test 3: SQL Injection (UNION SELECT)");
        System.out.println("-".repeat(37));
        System.out.printf("  Expected action: %s%n", sqliAction);

        try {
            PolicyApprovalResult result = client.getPolicyApprovedContext(
                PolicyApprovalRequest.builder()
                    .query("SELECT name FROM employees UNION SELECT password FROM admin")
                    .userToken("policy-config-user")
                    .build()
            );

            // If we get here, the request was approved
            if ("false".equals(policiesEnabled)) {
                assertCheck(true, "SQLi query approved (static policies disabled)");
            } else {
                switch (sqliAction) {
                    case "block":
                        assertCheck(false, "SQLi query should have been blocked (SQLI_ACTION=block)");
                        break;
                    case "warn":
                        assertCheck(true, "SQLi query approved with warning (SQLI_ACTION=warn)");
                        break;
                    case "log":
                        assertCheck(true, "SQLi query approved (SQLI_ACTION=log)");
                        break;
                    default:
                        System.out.println("   Unknown SQLI_ACTION: " + sqliAction);
                        failures.add("Unknown SQLI_ACTION: " + sqliAction);
                }
            }
        } catch (PolicyViolationException e) {
            if ("false".equals(policiesEnabled)) {
                assertCheck(false, "SQLi query should not be blocked when policies disabled: " + e.getMessage());
            } else if ("block".equals(sqliAction)) {
                assertCheck(true, "SQLi query blocked (SQLI_ACTION=block)");
                assertCheck(e.getMessage() != null && !e.getMessage().isEmpty(), "Block reason provided");
                System.out.printf("   Block reason: %s%n", e.getMessage());
            } else {
                assertCheck(false, "SQLi query should not be blocked with SQLI_ACTION=" + sqliAction + ": " + e.getMessage());
            }
        } catch (AxonFlowException e) {
            System.out.println("   FATAL: Policy check failed: " + e.getMessage());
            System.exit(1);
            return;
        }
        System.out.println();

        // -----------------------------------------------------------
        // Test 4: Credit card PII -- validates PII detection breadth
        // -----------------------------------------------------------
        System.out.println("Test 4: Credit Card PII");
        System.out.println("-".repeat(23));

        try {
            PolicyApprovalResult result = client.getPolicyApprovedContext(
                PolicyApprovalRequest.builder()
                    .query("Charge card 4111-1111-1111-1111 for $50")
                    .userToken("policy-config-user")
                    .build()
            );

            // If we get here, the request was approved
            if ("false".equals(policiesEnabled)) {
                assertCheck(true, "Credit card query approved (static policies disabled)");
            } else {
                switch (piiAction) {
                    case "block":
                        assertCheck(false, "Credit card should have been blocked (PII_ACTION=block)");
                        break;
                    case "redact":
                        assertCheck(true, "Credit card approved for redaction (PII_ACTION=redact)");
                        assertCheck(result.getPolicies() != null && !result.getPolicies().isEmpty(),
                            "Credit card PII detected");
                        break;
                    case "warn":
                    case "log":
                        assertCheck(true, "Credit card approved (PII_ACTION=" + piiAction + ")");
                        break;
                }
            }
        } catch (PolicyViolationException e) {
            if ("false".equals(policiesEnabled)) {
                assertCheck(false, "Credit card should not be blocked when policies disabled: " + e.getMessage());
            } else if ("block".equals(piiAction)) {
                assertCheck(true, "Credit card blocked (PII_ACTION=block)");
            } else {
                assertCheck(false, "Credit card should not be blocked with PII_ACTION=" + piiAction + ": " + e.getMessage());
            }
        } catch (AxonFlowException e) {
            System.out.println("   FATAL: Policy check failed: " + e.getMessage());
            System.exit(1);
            return;
        }
        System.out.println();

        // -----------------------------------------------------------
        // Summary
        // -----------------------------------------------------------
        System.out.println("=".repeat(50));
        if (failures.isEmpty()) {
            System.out.println("ALL TESTS PASSED");
            System.out.println();
            System.out.printf("Policy configuration validated:%n");
            System.out.printf("  PII_ACTION=%s, SQLI_ACTION=%s, enabled=%s%n",
                piiAction, sqliAction, policiesEnabled);
        } else {
            System.out.println(failures.size() + " TEST(S) FAILED:");
            for (String f : failures) {
                System.out.println("   - " + f);
            }
            System.exit(1);
        }
    }
}
