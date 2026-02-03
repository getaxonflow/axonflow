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
import com.getaxonflow.sdk.exceptions.PolicyViolationException;
import com.getaxonflow.sdk.types.PolicyApprovalRequest;
import com.getaxonflow.sdk.types.PolicyApprovalResult;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * AxonFlow PII Detection - Java SDK
 *
 * This example demonstrates and VALIDATES AxonFlow's PII detection:
 * - US Social Security Numbers (SSN)
 * - Credit Card numbers
 * - India PAN (Permanent Account Number)
 * - India Aadhaar numbers
 * - Email addresses
 * - Phone numbers
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 * This ensures CI/CD pipelines catch regressions.
 *
 * Default Behavior (Issue #891):
 *   PII detection defaults to "redact" mode - requests are APPROVED but flagged
 *   with isRequiresRedaction()=true for downstream redaction by the Orchestrator.
 *   Set PII_ACTION=block to restore blocking behavior.
 *
 * Policy Configuration (env vars):
 *   PII_ACTION         - Controls PII detection behavior: "redact" (default), "block", or "log"
 *   GATEWAY_PII_ACTION - Same as PII_ACTION but applies only in gateway mode
 *
 *   When PII_ACTION=block: requests with critical PII are blocked (isApproved()=false)
 *   When PII_ACTION=log:   PII is detected and logged but passes through unmodified
 *   When PII_ACTION=redact: (default) PII is flagged for downstream redaction
 *
 * Run with: mvn compile exec:java
 * Prerequisites: docker compose up -d
 */
public class PiiDetectionExample {

    private static final List<String> failures = new ArrayList<>();

    private static String getEnv(String key, String defaultValue) {
        String value = System.getenv(key);
        return (value != null && !value.isEmpty()) ? value : defaultValue;
    }

    private static void assertCheck(boolean condition, String message) {
        if (!condition) {
            failures.add(message);
            System.out.println("   \u274C FAIL: " + message);
        } else {
            System.out.println("   \u2713 PASS: " + message);
        }
    }

    public static void main(String[] args) {
        System.out.println("AxonFlow PII Detection - Java SDK");
        System.out.println("==================================");
        System.out.println();
        System.out.println("Default Mode: redact (PII flagged for redaction, not blocked)");
        System.out.println();

        AxonFlow client = AxonFlow.create(AxonFlowConfig.builder()
            .endpoint(getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080"))
            .clientId(getEnv("AXONFLOW_CLIENT_ID", "demo"))
            .clientSecret(getEnv("AXONFLOW_CLIENT_SECRET", "demo"))
            .debug("true".equals(getEnv("AXONFLOW_DEBUG", "")))
            .build());

        // PII test cases
        // expectRedact: true = critical PII (isRequiresRedaction()=true)
        // expectRedact: false = non-critical or no PII (logged but not flagged)
        List<TestCase> testCases = Arrays.asList(
            new TestCase("Safe Query (No PII)",
                "What is the capital of France?", false),
            new TestCase("US Social Security Number (Critical PII)",
                "Process refund for customer with SSN 123-45-6789", true),
            new TestCase("Credit Card Number (Critical PII)",
                "Charge card 4111-1111-1111-1111 for $99.99", true),
            new TestCase("India PAN (Critical PII)",
                "Verify PAN number ABCPD1234E for tax filing", true),
            new TestCase("India Aadhaar (Critical PII)",
                "Link Aadhaar 2345 6789 0123 to account", true),
            new TestCase("Email Address (Non-Critical PII)",
                "Send invoice to john.doe@gmail.com", false), // Medium severity - logged but not flagged
            new TestCase("Phone Number (Non-Critical PII)",
                "Call customer at +1-555-123-4567", false) // Medium severity - logged but not flagged
        );

        int testNum = 1;
        for (TestCase test : testCases) {
            System.out.printf("Test %d: %s%n", testNum++, test.name);
            System.out.printf("  Query: %s%n", truncate(test.query, 60));

            PolicyApprovalResult result = null;
            boolean wasBlocked = false;
            String blockReason = null;

            try {
                result = client.getPolicyApprovedContext(
                    PolicyApprovalRequest.builder()
                        .query(test.query)
                        .userToken("pii-detection-user")
                        .build()
                );
            } catch (PolicyViolationException e) {
                // Request was blocked by policy - this is expected for critical PII
                wasBlocked = true;
                blockReason = e.getBlockReason();
            } catch (Exception e) {
                System.out.println("   \u274C FATAL: getPolicyApprovedContext failed: " + e.getMessage());
                System.exit(1);
                return;
            }

            if (wasBlocked) {
                // Request was blocked by policy
                System.out.println("   Status: BLOCKED");
                System.out.printf("   Reason: %s%n", blockReason);

                // Verify expected behavior for blocked requests
                if (test.expectRedact) {
                    assertCheck(true, "Critical PII detected and flagged for redaction");
                } else {
                    assertCheck(false, "No critical PII detected, request approved");
                }
            } else {
                // Validate context ID (UUID format)
                assertCheck(
                    result.getContextId() != null && !result.getContextId().isEmpty(),
                    "contextId is not empty"
                );

                // Check if request was approved
                if (result.isApproved()) {
                    if (result.isRequiresRedaction()) {
                        System.out.println("   Status: APPROVED (requires redaction)");
                    } else {
                        System.out.println("   Status: APPROVED");
                    }
                } else {
                    // Request was blocked (only if PII_ACTION=block)
                    System.out.println("   Status: BLOCKED");
                    System.out.printf("   Reason: %s%n", result.getBlockReason());
                }

                // Get actual redaction status (blocked also counts as "requires handling")
                boolean actualRequiresRedaction = result.isRequiresRedaction() || !result.isApproved();

                // Verify expected behavior
                if (test.expectRedact) {
                    assertCheck(actualRequiresRedaction, "Critical PII detected and flagged for redaction");
                } else {
                    assertCheck(
                        !actualRequiresRedaction && result.isApproved(),
                        "No critical PII detected, request approved"
                    );
                }
            }

            System.out.println();
        }

        // ========================================
        // Policy Configuration Tests (PII_ACTION)
        // ========================================
        String piiAction = getEnv("PII_ACTION", "redact");
        System.out.printf("Policy Config: PII_ACTION=%s%n", piiAction);
        System.out.println();

        if ("block".equals(piiAction)) {
            System.out.println("Test (config): PII_ACTION=block - SSN should be BLOCKED");
            PolicyApprovalResult configResult = null;
            boolean configBlocked = false;
            try {
                configResult = client.getPolicyApprovedContext(
                    PolicyApprovalRequest.builder()
                        .query("Customer SSN is 999-88-7777")
                        .userToken("pii-config-test-user")
                        .build()
                );
            } catch (PolicyViolationException e) {
                configBlocked = true;
            } catch (Exception e) {
                System.out.println("   \u274C FATAL: getPolicyApprovedContext failed: " + e.getMessage());
                System.exit(1);
                return;
            }
            boolean wasBlocked2 = configBlocked || (configResult != null && !configResult.isApproved());
            assertCheck(wasBlocked2, "PII_ACTION=block: SSN query is blocked (not approved)");
            System.out.println();
        } else if ("log".equals(piiAction)) {
            System.out.println("Test (config): PII_ACTION=log - SSN should pass through unmodified");
            try {
                PolicyApprovalResult configResult = client.getPolicyApprovedContext(
                    PolicyApprovalRequest.builder()
                        .query("Customer SSN is 999-88-7777")
                        .userToken("pii-config-test-user")
                        .build()
                );
                assertCheck(configResult.isApproved(), "PII_ACTION=log: SSN query is approved (pass-through)");
                assertCheck(!configResult.isRequiresRedaction(), "PII_ACTION=log: no redaction required (log only)");
            } catch (PolicyViolationException e) {
                assertCheck(false, "PII_ACTION=log: SSN query should NOT be blocked");
            } catch (Exception e) {
                System.out.println("   \u274C FATAL: getPolicyApprovedContext failed: " + e.getMessage());
                System.exit(1);
                return;
            }
            System.out.println();
        }

        System.out.println("==================================");
        if (failures.isEmpty()) {
            System.out.println("\u2713 ALL TESTS PASSED");
            System.out.println();
            System.out.println("PII types validated:");
            System.out.println("  - Safe query (no PII)");
            System.out.println("  - US SSN (critical)");
            System.out.println("  - Credit card (critical)");
            System.out.println("  - India PAN (critical)");
            System.out.println("  - India Aadhaar (critical)");
            System.out.println("  - Email (non-critical)");
            System.out.println("  - Phone (non-critical)");
        } else {
            System.out.println("\u274C " + failures.size() + " TEST(S) FAILED:");
            for (String f : failures) {
                System.out.println("   - " + f);
            }
            System.exit(1);
        }
    }

    private static String truncate(String str, int maxLen) {
        if (str.length() <= maxLen) {
            return str;
        }
        return str.substring(0, maxLen) + "...";
    }

    private static class TestCase {
        final String name;
        final String query;
        final boolean expectRedact;

        TestCase(String name, String query, boolean expectRedact) {
            this.name = name;
            this.query = query;
            this.expectRedact = expectRedact;
        }
    }
}
