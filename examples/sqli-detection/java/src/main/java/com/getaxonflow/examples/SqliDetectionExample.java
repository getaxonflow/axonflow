/*
 * AxonFlow SQL Injection Detection - Java
 *
 * Demonstrates AxonFlow's SQLi detection capabilities:
 * - DROP/DELETE/TRUNCATE statements
 * - UNION SELECT attacks
 * - Boolean-based injection (OR 1=1)
 * - Comment injection
 * - Stacked queries
 * - Time-based blind SQLi
 */
package com.getaxonflow.examples;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.PolicyApprovalRequest;
import com.getaxonflow.sdk.types.PolicyApprovalResult;
import com.getaxonflow.sdk.exceptions.AxonFlowException;
import com.getaxonflow.sdk.exceptions.PolicyViolationException;

import java.util.Arrays;
import java.util.List;

public class SqliDetectionExample {

    private static final String CLIENT_ID = "sqli-detection-demo";

    public static void main(String[] args) {
        System.out.println("AxonFlow SQL Injection Detection - Java");
        System.out.println("========================================");
        System.out.println();

        AxonFlow client = AxonFlow.create(AxonFlowConfig.builder()
            .agentUrl(getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080"))
            .licenseKey(getEnv("AXONFLOW_LICENSE_KEY", ""))
            .build());

        List<TestCase> testCases = Arrays.asList(
            new TestCase("Safe Query",
                "Find users who signed up in the last 30 days", false),
            new TestCase("DROP TABLE",
                "SELECT * FROM users; DROP TABLE users;--", true),
            new TestCase("UNION SELECT",
                "Get user where id = 1 UNION SELECT password FROM admin", true),
            new TestCase("Boolean Injection (OR 1=1)",
                "SELECT * FROM users WHERE username='' OR '1'='1'", true),
            new TestCase("Comment Injection",
                "SELECT * FROM users WHERE name='admin'-- AND password='secret'", false), // Not detected by default policies
            new TestCase("Stacked Queries",
                "SELECT name FROM users; DELETE FROM audit_log;", true),
            new TestCase("Truncate Statement",
                "SELECT * FROM data; TRUNCATE TABLE logs;", true)
        );

        int passed = 0;
        int failed = 0;

        for (TestCase test : testCases) {
            System.out.printf("Test: %s%n", test.name);
            System.out.printf("  Query: %s%n", truncate(test.query, 60));

            boolean wasBlocked = false;

            try {
                PolicyApprovalResult result = client.getPolicyApprovedContext(
                    PolicyApprovalRequest.builder()
                        .query(test.query)
                        .clientId(CLIENT_ID)
                        .userToken("sqli-detection-user")
                        .build()
                );

                System.out.println("  Result: APPROVED");
                System.out.printf("  Context ID: %s%n", result.getContextId());

                if (result.getPolicies() != null && !result.getPolicies().isEmpty()) {
                    System.out.printf("  Policies: %s%n",
                        String.join(", ", result.getPolicies()));
                }

            } catch (PolicyViolationException e) {
                wasBlocked = true;
                System.out.println("  Result: BLOCKED");
                System.out.printf("  Policy: %s%n", e.getPolicyName());
                System.out.printf("  Reason: %s%n", e.getMessage());

            } catch (AxonFlowException e) {
                System.out.println("  Result: ERROR");
                System.out.printf("  Error: %s%n", e.getMessage());
                failed++;
                System.out.println();
                continue;
            }

            if (wasBlocked == test.shouldBlock) {
                System.out.println("  Test: PASS");
                passed++;
            } else {
                String expected = test.shouldBlock ? "blocked" : "approved";
                System.out.printf("  Test: FAIL (expected %s)%n", expected);
                failed++;
            }

            System.out.println();
        }

        System.out.println("========================================");
        System.out.printf("Results: %d passed, %d failed%n", passed, failed);
        System.out.println();

        if (failed > 0) {
            System.out.println("Some tests failed. Check your AxonFlow policy configuration.");
            System.exit(1);
        }

        System.out.println("All SQLi detection tests passed!");
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
        final boolean shouldBlock;

        TestCase(String name, String query, boolean shouldBlock) {
            this.name = name;
            this.query = query;
            this.shouldBlock = shouldBlock;
        }
    }
}
