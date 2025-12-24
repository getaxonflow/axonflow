package com.getaxonflow.examples.policies;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.policies.PolicyTypes.TestPatternResult;

import java.util.Arrays;
import java.util.List;

/**
 * AxonFlow Policy Management - Test Pattern
 *
 * This example demonstrates how to test regex patterns
 * before creating policies. This helps ensure your patterns
 * work correctly and catch the right inputs.
 */
public class TestPattern {

    public static void main(String[] args) {
        String endpoint = System.getenv("AXONFLOW_ENDPOINT");
        if (endpoint == null || endpoint.isEmpty()) {
            endpoint = "http://localhost:8080";
        }

        AxonFlowConfig config = AxonFlowConfig.builder()
            .agentUrl(endpoint)
            .clientId("test-org-001")  // Used as tenant ID
            .build();

        AxonFlow axonflow = AxonFlow.create(config);

        System.out.println("AxonFlow Policy Management - Pattern Testing");
        System.out.println("============================================================");

        try {
            // 1. Test a credit card pattern
            System.out.println("\n1. Testing credit card pattern...");

            String ccPattern = "\\b(?:\\d{4}[- ]?){3}\\d{4}\\b";
            List<String> ccTestInputs = Arrays.asList(
                "4111-1111-1111-1111",           // Valid Visa format with dashes
                "4111111111111111",               // Valid Visa format no dashes
                "4111 1111 1111 1111",            // Valid with spaces
                "not-a-card",                     // Invalid
                "411111111111111",                // Too short (15 digits)
                "41111111111111111",              // Too long (17 digits)
                "My card is 5500-0000-0000-0004"  // Embedded in text
            );

            TestPatternResult ccResult = axonflow.testPattern(ccPattern, ccTestInputs);

            System.out.println("   Pattern: " + ccPattern);
            System.out.println("   Valid regex: " + ccResult.isValid());
            System.out.println("\n   Results:");

            ccResult.getMatches().forEach(match -> {
                String icon = match.isMatched() ? "\u2713 MATCH" : "\u2717 no match";
                System.out.printf("   %s  \"%s\"%n", icon, match.getInput());
                if (match.isMatched() && match.getMatchedText() != null) {
                    System.out.printf("            Matched: \"%s\"%n", match.getMatchedText());
                }
            });

            // 2. Test a US SSN pattern
            System.out.println("\n2. Testing US SSN pattern...");

            String ssnPattern = "\\b\\d{3}-\\d{2}-\\d{4}\\b";
            List<String> ssnTestInputs = Arrays.asList(
                "123-45-6789",      // Valid SSN format
                "000-00-0000",      // Valid format (but invalid SSN)
                "SSN: 987-65-4321", // Embedded in text
                "123456789",        // No dashes
                "12-345-6789"       // Wrong grouping
            );

            TestPatternResult ssnResult = axonflow.testPattern(ssnPattern, ssnTestInputs);

            System.out.println("   Pattern: " + ssnPattern);
            System.out.println("\n   Results:");

            ssnResult.getMatches().forEach(match -> {
                String icon = match.isMatched() ? "\u2713 MATCH" : "\u2717 no match";
                System.out.printf("   %s  \"%s\"%n", icon, match.getInput());
            });

            // 3. Test an email pattern
            System.out.println("\n3. Testing email pattern...");

            String emailPattern = "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}";
            List<String> emailTestInputs = Arrays.asList(
                "user@example.com",
                "first.last@company.org",
                "test+filter@gmail.com",
                "invalid-email",
                "@missing-local.com",
                "no-domain@"
            );

            TestPatternResult emailResult = axonflow.testPattern(emailPattern, emailTestInputs);

            System.out.println("   Pattern: " + emailPattern);
            System.out.println("\n   Results:");

            emailResult.getMatches().forEach(match -> {
                String icon = match.isMatched() ? "\u2713 MATCH" : "\u2717 no match";
                System.out.printf("   %s  \"%s\"%n", icon, match.getInput());
            });

            // 4. Test SQL injection pattern
            System.out.println("\n4. Testing SQL injection pattern...");

            String sqliPattern = "(?i)\\b(union\\s+select|select\\s+.*\\s+from|insert\\s+into|delete\\s+from|drop\\s+table)\\b";
            List<String> sqliTestInputs = Arrays.asList(
                "SELECT * FROM users",
                "UNION SELECT password FROM admin",
                "DROP TABLE customers",
                "Normal user query",
                "My name is Robert",
                "INSERT INTO logs VALUES"
            );

            TestPatternResult sqliResult = axonflow.testPattern(sqliPattern, sqliTestInputs);

            String displayPattern = sqliPattern.length() > 50
                ? sqliPattern.substring(0, 50) + "..."
                : sqliPattern;
            System.out.println("   Pattern: " + displayPattern);
            System.out.println("\n   Results:");

            sqliResult.getMatches().forEach(match -> {
                String icon = match.isMatched() ? "\u2713 BLOCKED" : "\u2717 allowed";
                System.out.printf("   %s  \"%s\"%n", icon, match.getInput());
            });

            // 5. Test an invalid pattern
            System.out.println("\n5. Testing invalid pattern (error handling)...");

            try {
                String invalidPattern = "([unclosed";
                TestPatternResult invalidResult = axonflow.testPattern(invalidPattern, Arrays.asList("test"));

                if (!invalidResult.isValid()) {
                    System.out.println("   Pattern: " + invalidPattern);
                    System.out.println("   Valid: false");
                    System.out.println("   Error: " + invalidResult.getError());
                }
            } catch (Exception e) {
                System.out.println("   Server rejected invalid pattern (expected)");
            }

            // Summary
            System.out.println("\n============================================================");
            System.out.println("Pattern Testing Summary");
            System.out.println("============================================================");
            System.out.println();
            System.out.println("Best Practices:");
            System.out.println("  1. Always test patterns before creating policies");
            System.out.println("  2. Include edge cases in your test inputs");
            System.out.println("  3. Test with real-world examples from your domain");
            System.out.println("  4. Consider case sensitivity (use (?i) for case-insensitive)");
            System.out.println("  5. Use word boundaries (\\b) to avoid partial matches");
            System.out.println();

        } catch (Exception e) {
            System.err.println("\nError: " + e.getMessage());
            System.exit(1);
        }
    }
}
