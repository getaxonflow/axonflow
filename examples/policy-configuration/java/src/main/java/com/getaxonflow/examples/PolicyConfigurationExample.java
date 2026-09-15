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
 * This example demonstrates and VALIDATES policy behavior by sending test queries
 * through the policy pre-check API and checking that the Agent responds according
 * to the shipped policy actions.
 *
 * v11: the stored policy action decides. Environment variables no longer set
 * detection actions (PII_ACTION, SQLI_ACTION and their MCP_/GATEWAY_ variants are
 * ignored, with a boot WARN). The shipped request-phase actions exercised here:
 *   sys_pii_ssn, sys_pii_credit_card = warn (approved, policy id in getPolicies())
 *   sys_sqli_*                       = warn (approved, policy id in getPolicies())
 *
 * To change an outcome, record an organization override (customer portal API,
 * Enterprise: PUT /api/v1/detection-posture/{pii|sqli} with {"action":"block"})
 * or change the policy's action. This example validates the shipped actions with
 * no override recorded.
 *
 * Still read from the environment (a non-action knob, must match Agent config):
 *   MCP_STATIC_POLICIES_ENABLED = true | false (default: true)
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

    private static boolean hasPolicyPrefix(List<String> policies, String prefix) {
        return policies != null && policies.stream().anyMatch(p -> p.startsWith(prefix));
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

        // Detection actions come from the stored policy rows (no org override
        // recorded), not from the environment.
        String policiesEnabled = getEnv("MCP_STATIC_POLICIES_ENABLED", "true").toLowerCase();

        System.out.println("Expected actions: shipped stored actions (PII warn at request phase, SQLi warn)");
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
        // Test 2: PII query (SSN) -- sys_pii_ssn stores warn for the request phase
        // -----------------------------------------------------------
        System.out.println("Test 2: PII Query (SSN '123-45-6789')");
        System.out.println("-".repeat(38));
        System.out.println("  Expected action: warn (stored)");

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
                // warn approves the request and reports the matched policy
                assertCheck(result.isApproved(), "PII query approved with a warning (stored action: warn)");
                assertCheck(hasPolicyPrefix(result.getPolicies(), "sys_pii_"),
                    "PII policy detected (sys_pii_* in policies)");
                if (result.getPolicies() != null) {
                    System.out.printf("   Policies: %s%n", String.join(", ", result.getPolicies()));
                }
            }
        } catch (PolicyViolationException e) {
            // Request was blocked by policy - not the shipped outcome
            if ("false".equals(policiesEnabled)) {
                assertCheck(false, "PII query should not be blocked when policies disabled: " + e.getMessage());
            } else {
                assertCheck(false, "PII query should be approved with a warning (stored action: warn), but was blocked"
                    + " (an org pii=block override or an edited policy action is in force): " + e.getMessage());
            }
        } catch (AxonFlowException e) {
            System.out.println("   FATAL: Policy check failed: " + e.getMessage());
            System.exit(1);
            return;
        }
        System.out.println();

        // -----------------------------------------------------------
        // Test 3: SQLi query -- every sys_sqli_* policy stores warn
        // -----------------------------------------------------------
        System.out.println("Test 3: SQL Injection (UNION SELECT)");
        System.out.println("-".repeat(37));
        System.out.println("  Expected action: warn (stored)");

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
                // SQL injection warns by default; it is not blocked
                assertCheck(result.isApproved(), "SQLi query approved with a warning (stored action: warn)");
                assertCheck(hasPolicyPrefix(result.getPolicies(), "sys_sqli_"),
                    "SQLi policy detected (sys_sqli_* in policies)");
                if (result.getPolicies() != null) {
                    System.out.printf("   Policies: %s%n", String.join(", ", result.getPolicies()));
                }
            }
        } catch (PolicyViolationException e) {
            if ("false".equals(policiesEnabled)) {
                assertCheck(false, "SQLi query should not be blocked when policies disabled: " + e.getMessage());
            } else {
                assertCheck(false, "SQLi query should be approved with a warning (stored action: warn), but was blocked"
                    + " (an org sqli=block override or an edited policy action is in force): " + e.getMessage());
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
                // sys_pii_credit_card stores warn for the request phase
                assertCheck(result.isApproved(), "Credit card approved with a warning (stored action: warn)");
                assertCheck(hasPolicyPrefix(result.getPolicies(), "sys_pii_"),
                    "Credit card PII detected (sys_pii_* in policies)");
            }
        } catch (PolicyViolationException e) {
            if ("false".equals(policiesEnabled)) {
                assertCheck(false, "Credit card should not be blocked when policies disabled: " + e.getMessage());
            } else {
                assertCheck(false, "Credit card should be approved with a warning (stored action: warn), but was blocked"
                    + " (an org pii=block override or an edited policy action is in force): " + e.getMessage());
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
            System.out.printf("  shipped stored actions (PII warn, SQLi warn), enabled=%s%n",
                policiesEnabled);
        } else {
            System.out.println(failures.size() + " TEST(S) FAILED:");
            for (String f : failures) {
                System.out.println("   - " + f);
            }
            System.exit(1);
        }
    }
}
