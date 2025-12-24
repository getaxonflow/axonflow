// Package main demonstrates how to test regex patterns
// before creating policies using the AxonFlow Go SDK.
//
// This helps ensure your patterns work correctly and catch the right inputs.
package main

import (
	"fmt"
	"os"

	axonflow "github.com/getaxonflow/axonflow-sdk-go"
)

func main() {
	endpoint := os.Getenv("AXONFLOW_ENDPOINT")
	if endpoint == "" {
		endpoint = "http://localhost:8080"
	}

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		AgentURL: endpoint,
		ClientID: "test-org-001", // Used as tenant ID
	})

	fmt.Println("AxonFlow Policy Management - Pattern Testing")
	fmt.Println("============================================================")

	// 1. Test a credit card pattern
	fmt.Println("\n1. Testing credit card pattern...")

	ccPattern := `\b(?:\d{4}[- ]?){3}\d{4}\b`
	ccTestInputs := []string{
		"4111-1111-1111-1111",          // Valid Visa format with dashes
		"4111111111111111",              // Valid Visa format no dashes
		"4111 1111 1111 1111",           // Valid with spaces
		"not-a-card",                    // Invalid
		"411111111111111",               // Too short (15 digits)
		"41111111111111111",             // Too long (17 digits)
		"My card is 5500-0000-0000-0004", // Embedded in text
	}

	ccResult, err := client.TestPattern(ccPattern, ccTestInputs)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("   Pattern: %s\n", ccPattern)
	fmt.Printf("   Valid regex: %v\n", ccResult.Valid)
	fmt.Println("\n   Results:")

	for _, match := range ccResult.Matches {
		icon := "\u2717 no match"
		if match.Matched {
			icon = "\u2713 MATCH"
		}
		fmt.Printf("   %s  \"%s\"\n", icon, match.Input)
		if match.Matched && match.MatchedText != "" {
			fmt.Printf("            Matched: \"%s\"\n", match.MatchedText)
		}
	}

	// 2. Test a US SSN pattern
	fmt.Println("\n2. Testing US SSN pattern...")

	ssnPattern := `\b\d{3}-\d{2}-\d{4}\b`
	ssnTestInputs := []string{
		"123-45-6789",      // Valid SSN format
		"000-00-0000",      // Valid format (but invalid SSN)
		"SSN: 987-65-4321", // Embedded in text
		"123456789",        // No dashes
		"12-345-6789",      // Wrong grouping
	}

	ssnResult, err := client.TestPattern(ssnPattern, ssnTestInputs)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("   Pattern: %s\n", ssnPattern)
	fmt.Println("\n   Results:")

	for _, match := range ssnResult.Matches {
		icon := "\u2717 no match"
		if match.Matched {
			icon = "\u2713 MATCH"
		}
		fmt.Printf("   %s  \"%s\"\n", icon, match.Input)
	}

	// 3. Test an email pattern
	fmt.Println("\n3. Testing email pattern...")

	emailPattern := `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`
	emailTestInputs := []string{
		"user@example.com",
		"first.last@company.org",
		"test+filter@gmail.com",
		"invalid-email",
		"@missing-local.com",
		"no-domain@",
	}

	emailResult, err := client.TestPattern(emailPattern, emailTestInputs)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("   Pattern: %s\n", emailPattern)
	fmt.Println("\n   Results:")

	for _, match := range emailResult.Matches {
		icon := "\u2717 no match"
		if match.Matched {
			icon = "\u2713 MATCH"
		}
		fmt.Printf("   %s  \"%s\"\n", icon, match.Input)
	}

	// 4. Test SQL injection pattern
	fmt.Println("\n4. Testing SQL injection pattern...")

	sqliPattern := `(?i)\b(union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|drop\s+table)\b`
	sqliTestInputs := []string{
		"SELECT * FROM users",
		"UNION SELECT password FROM admin",
		"DROP TABLE customers",
		"Normal user query",
		"My name is Robert",
		"INSERT INTO logs VALUES",
	}

	sqliResult, err := client.TestPattern(sqliPattern, sqliTestInputs)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if len(sqliPattern) > 50 {
		fmt.Printf("   Pattern: %s...\n", sqliPattern[:50])
	} else {
		fmt.Printf("   Pattern: %s\n", sqliPattern)
	}
	fmt.Println("\n   Results:")

	for _, match := range sqliResult.Matches {
		icon := "\u2717 allowed"
		if match.Matched {
			icon = "\u2713 BLOCKED"
		}
		fmt.Printf("   %s  \"%s\"\n", icon, match.Input)
	}

	// 5. Test an invalid pattern
	fmt.Println("\n5. Testing invalid pattern (error handling)...")

	invalidPattern := "([unclosed"
	invalidResult, err := client.TestPattern(invalidPattern, []string{"test"})

	if err != nil {
		fmt.Println("   Server rejected invalid pattern (expected)")
	} else if !invalidResult.Valid {
		fmt.Printf("   Pattern: %s\n", invalidPattern)
		fmt.Println("   Valid: false")
		fmt.Printf("   Error: %s\n", invalidResult.Error)
	}

	// Summary
	fmt.Println("\n============================================================")
	fmt.Println("Pattern Testing Summary")
	fmt.Println("============================================================")
	fmt.Println(`
Best Practices:
  1. Always test patterns before creating policies
  2. Include edge cases in your test inputs
  3. Test with real-world examples from your domain
  4. Consider case sensitivity (use (?i) for case-insensitive)
  5. Use word boundaries (\b) to avoid partial matches
`)
}
