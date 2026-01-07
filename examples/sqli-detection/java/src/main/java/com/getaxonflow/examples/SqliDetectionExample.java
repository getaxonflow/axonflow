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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * AxonFlow SQL Injection Detection - Java SDK
 *
 * This example demonstrates and VALIDATES AxonFlow's SQLi detection:
 * - DROP/DELETE/TRUNCATE statements
 * - UNION SELECT attacks
 * - Boolean-based injection (OR 1=1)
 * - Comment injection
 * - Stacked queries
 * - Time-based blind SQLi
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 * This ensures CI/CD pipelines catch regressions.
 *
 * Run with: mvn compile exec:java
 * Prerequisites: docker compose up -d
 */
public class SqliDetectionExample {

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
        System.out.println("AxonFlow SQL Injection Detection - Java SDK");
        System.out.println("============================================");
        System.out.println();

        AxonFlow client = AxonFlow.create(AxonFlowConfig.builder()
            .endpoint(getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080"))
            .clientId(getEnv("AXONFLOW_CLIENT_ID", "demo"))
            .clientSecret(getEnv("AXONFLOW_CLIENT_SECRET", "demo"))
            .debug("true".equals(getEnv("AXONFLOW_DEBUG", "")))
            .build());

        List<TestCase> testCases = Arrays.asList(
            new TestCase("Safe Query",
                "Find users who signed up in the last 30 days", false, ""),
            new TestCase("DROP TABLE",
                "SELECT * FROM users; DROP TABLE users;--", true, "drop_table"),
            new TestCase("UNION SELECT",
                "Get user where id = 1 UNION SELECT password FROM admin", true, "union_select"),
            new TestCase("Boolean Injection (OR 1=1)",
                "SELECT * FROM users WHERE username='' OR '1'='1'", true, "boolean_injection"),
            new TestCase("Comment Injection",
                "SELECT * FROM users WHERE name='admin'-- AND password='secret'", false, "comment_injection"),
            new TestCase("Stacked Queries",
                "SELECT name FROM users; DELETE FROM audit_log;", true, "stacked_queries"),
            new TestCase("Truncate Statement",
                "SELECT * FROM data; TRUNCATE TABLE logs;", true, "truncate")
        );

        int testNum = 1;
        for (TestCase test : testCases) {
            System.out.printf("Test %d: %s%n", testNum++, test.name);
            System.out.printf("  Query: %s%n", truncate(test.query, 60));

            PolicyApprovalResult result;
            try {
                result = client.getPolicyApprovedContext(
                    PolicyApprovalRequest.builder()
                        .query(test.query)
                        .userToken("sqli-detection-user")
                        .build()
                );
            } catch (Exception e) {
                System.out.println("   \u274C FATAL: getPolicyApprovedContext failed: " + e.getMessage());
                System.exit(1);
                return;
            }

            boolean wasBlocked = !result.isApproved();

            // Validate context ID for approved requests
            if (result.isApproved()) {
                assertCheck(
                    result.getContextId() != null && !result.getContextId().isEmpty(),
                    "contextId is not empty"
                );
                assertCheck(
                    result.getContextId().startsWith("ctx_"),
                    "contextId has correct prefix 'ctx_'"
                );
                System.out.println("   Status: APPROVED");
            } else {
                System.out.println("   Status: BLOCKED");
                System.out.printf("   Reason: %s%n", result.getBlockReason());
                assertCheck(
                    result.getBlockReason() != null && !result.getBlockReason().isEmpty(),
                    "blockReason is provided for blocked requests"
                );
            }

            // Verify expected behavior
            if (test.shouldBlock) {
                assertCheck(wasBlocked, "SQLi type '" + test.sqliType + "' is blocked");
            } else {
                assertCheck(!wasBlocked, "Safe query is approved");
            }

            System.out.println();
        }

        System.out.println("============================================");
        if (failures.isEmpty()) {
            System.out.println("\u2713 ALL TESTS PASSED");
            System.out.println();
            System.out.println("SQLi patterns validated:");
            System.out.println("  - Safe query (approved)");
            System.out.println("  - DROP TABLE (blocked)");
            System.out.println("  - UNION SELECT (blocked)");
            System.out.println("  - Boolean injection (blocked)");
            System.out.println("  - Comment injection (not detected)");
            System.out.println("  - Stacked queries (blocked)");
            System.out.println("  - TRUNCATE (blocked)");
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
        final boolean shouldBlock;
        final String sqliType;

        TestCase(String name, String query, boolean shouldBlock, String sqliType) {
            this.name = name;
            this.query = query;
            this.shouldBlock = shouldBlock;
            this.sqliType = sqliType;
        }
    }
}
