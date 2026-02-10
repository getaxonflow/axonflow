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
import com.getaxonflow.sdk.types.PolicyApprovalRequest;
import com.getaxonflow.sdk.types.PolicyApprovalResult;
import com.getaxonflow.sdk.exceptions.AxonFlowException;
import com.getaxonflow.sdk.exceptions.PolicyViolationException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * AxonFlow Hello World - Java
 *
 * The simplest possible AxonFlow integration:
 * 1. Connect to AxonFlow
 * 2. Check if queries pass policy evaluation
 * 3. Print the results
 *
 * This example demonstrates the core AxonFlow workflow without any LLM calls.
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 */
public class HelloWorld {

    private static final String CLIENT_ID = "hello-world-app";
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
        System.out.println("AxonFlow Hello World - Java");
        System.out.println("========================================");
        System.out.println();

        // Initialize AxonFlow client
        String clientId = getEnv("AXONFLOW_CLIENT_ID", "");
        String clientSecret = getEnv("AXONFLOW_CLIENT_SECRET", "");

        AxonFlow client = AxonFlow.create(AxonFlowConfig.builder()
            .endpoint(getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080"))
            .clientId(clientId)
            .clientSecret(clientSecret)
            .build());

        // Test queries with expected results
        List<TestCase> testCases = Arrays.asList(
            new TestCase("Safe Query", "What is the weather today?", "approved"),
            new TestCase("SQL Injection", "SELECT * FROM users; DROP TABLE users;", "blocked"),
            new TestCase("PII (SSN)", "Process payment for SSN 123-45-6789", "approved") // v3.0.0: PII defaults to redact
        );

        for (TestCase test : testCases) {
            System.out.printf("Test: %s%n", test.name);
            System.out.printf("  Query: %s%n", truncate(test.query, 50));
            System.out.println();

            try {
                // Check policy approval using Gateway Mode pre-check
                PolicyApprovalResult result = client.getPolicyApprovedContext(
                    PolicyApprovalRequest.builder()
                        .query(test.query)
                        .clientId(CLIENT_ID)
                        .userToken(getEnv("AXONFLOW_USER_TOKEN", "hello-world-user"))
                        .build()
                );

                // If we get here, the request was approved
                System.out.println("  Result: APPROVED");
                System.out.printf("  Context ID: %s%n", result.getContextId());

                if (result.getPolicies() != null && !result.getPolicies().isEmpty()) {
                    System.out.printf("  Policies: %s%n", String.join(", ", result.getPolicies()));
                }

                // Validate result
                assertCheck(result.getContextId() != null && !result.getContextId().isEmpty(),
                    test.name + " - contextId is not empty");
                assertCheck("approved".equals(test.expected),
                    test.name + " - expected " + test.expected + ", got approved");

            } catch (PolicyViolationException e) {
                // Request was blocked by policy
                System.out.println("  Result: BLOCKED");
                System.out.printf("  Policy: %s%n", e.getPolicyName());
                System.out.printf("  Reason: %s%n", e.getMessage());

                // Validate result
                assertCheck("blocked".equals(test.expected),
                    test.name + " - expected " + test.expected + ", got blocked");

            } catch (AxonFlowException e) {
                System.out.println("  Result: ERROR");
                System.out.printf("  Error: %s%n", e.getMessage());
                failures.add(test.name + " - unexpected error: " + e.getMessage());
            }

            System.out.println();
        }

        System.out.println("========================================");
        if (failures.isEmpty()) {
            System.out.println("✓ ALL TESTS PASSED");
            System.out.println();
            System.out.println("Next steps:");
            System.out.println("  - Gateway Mode: examples/integrations/gateway-mode/java/");
            System.out.println("  - Proxy Mode: examples/integrations/proxy-mode/java/");
        } else {
            System.out.println("❌ " + failures.size() + " TEST(S) FAILED:");
            for (String f : failures) {
                System.out.println("   - " + f);
            }
            System.exit(1);
        }
    }

    private static String getEnv(String key, String defaultValue) {
        String value = System.getenv(key);
        return (value != null && !value.isEmpty()) ? value : defaultValue;
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
        final String expected;

        TestCase(String name, String query, String expected) {
            this.name = name;
            this.query = query;
            this.expected = expected;
        }
    }
}
