// AxonFlow Static Policy Management - Go SDK (Comprehensive)
//
// This example demonstrates and VALIDATES static policy SDK methods:
// - ListStaticPolicies
// - GetStaticPolicy
// - CreateStaticPolicy
// - UpdateStaticPolicy
// - DeleteStaticPolicy
// - ToggleStaticPolicy
// - TestPattern
// - GetStaticPolicyVersions
// - GetEffectiveStaticPolicies
//
// Issue #1082: Examples should test actual behavior, not just API availability
//
// Run with: go run main.go
// Prerequisites: docker compose up -d

package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v2"
)

var (
	passCount int
	failCount int
)

func assert(condition bool, message string) {
	if condition {
		fmt.Printf("   PASS: %s\n", message)
		passCount++
	} else {
		fmt.Printf("   FAIL: %s\n", message)
		failCount++
	}
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func main() {
	fmt.Println("AxonFlow Static Policy Management - Go SDK")
	fmt.Println("===========================================")
	fmt.Println()

	// Create AxonFlow client
	// Note: As of SDK v2.0.0 (ADR-026), all routes go through a single endpoint.
	// The Agent proxies orchestrator routes internally.
	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
		ClientID:     getEnv("AXONFLOW_CLIENT_ID", "demo-client"),
		ClientSecret: getEnv("AXONFLOW_CLIENT_SECRET", ""), // Empty for community mode
	})

	// Unique name for our test policy
	policyName := fmt.Sprintf("demo-custom-policy-%d", time.Now().Unix())
	var policyID string

	defer func() {
		// Cleanup if policy wasn't deleted
		if policyID != "" {
			_ = client.DeleteStaticPolicy(policyID)
			fmt.Printf("\nCleanup: Deleted policy %s\n", policyName)
		}
	}()

	// ========================================
	// 1. LIST STATIC POLICIES
	// ========================================
	fmt.Println("1. ListStaticPolicies - Listing all static policies...")
	policies, err := client.ListStaticPolicies(&axonflow.ListStaticPoliciesOptions{
		Limit: 10,
	})
	if err != nil {
		fmt.Printf("   ERROR: %v\n", err)
		failCount++
	} else {
		assert(len(policies) > 0, "Policies list is not empty")
		fmt.Printf("   Found %d policies\n", len(policies))
		for i, p := range policies {
			if i >= 3 {
				fmt.Printf("   ... and %d more\n", len(policies)-3)
				break
			}
			status := "enabled"
			if !p.Enabled {
				status = "disabled"
			}
			fmt.Printf("   - %s: %s (%s)\n", p.Name, p.Category, status)
		}
	}
	fmt.Println()

	// ========================================
	// 2. LIST BY CATEGORY
	// ========================================
	fmt.Println("2. ListStaticPolicies - Filtering by category...")
	sqliPolicies, err := client.ListStaticPolicies(&axonflow.ListStaticPoliciesOptions{
		Category: axonflow.CategorySecuritySQLI,
		Limit:    5,
	})
	if err != nil {
		fmt.Printf("   ERROR: %v\n", err)
	} else {
		fmt.Printf("   Found %d SQL injection policies\n", len(sqliPolicies))
		for i, p := range sqliPolicies {
			if i >= 3 {
				break
			}
			fmt.Printf("   - %s: severity=%s\n", p.Name, p.Severity)
		}
	}
	fmt.Println()

	// ========================================
	// 3. CREATE STATIC POLICY
	// ========================================
	fmt.Println("3. CreateStaticPolicy - Creating a custom policy...")
	// Using CategoryCodeSecrets - appropriate for custom tenant policies
	// that detect sensitive patterns in generated code.
	created, err := client.CreateStaticPolicy(&axonflow.CreateStaticPolicyRequest{
		Name:        policyName,
		Description: "Demo policy for SDK testing - detects test secrets in code",
		Category:    axonflow.CategoryCodeSecrets,
		Tier:        axonflow.TierTenant,
		Pattern:     `(?i)test_secret_\d+`,
		Severity:    axonflow.SeverityMedium,
		Enabled:     true,
		Action:      axonflow.ActionWarn,
	})
	if err != nil {
		fmt.Printf("   ERROR: %v\n", err)
		failCount++
		return
	}
	policyID = created.ID
	assert(created.ID != "", "Created policy has ID")
	assert(created.Name == policyName, "Created policy name matches")
	assert(string(created.Category) == string(axonflow.CategoryCodeSecrets), "Created policy category matches")
	assert(created.Enabled, "Created policy is enabled")
	fmt.Printf("   Created: %s (ID: %s)\n", created.Name, created.ID)
	fmt.Println()

	// ========================================
	// 4. GET STATIC POLICY
	// ========================================
	fmt.Println("4. GetStaticPolicy - Retrieving policy by ID...")
	retrieved, err := client.GetStaticPolicy(policyID)
	if err != nil {
		fmt.Printf("   ERROR: %v\n", err)
		failCount++
	} else {
		assert(retrieved.ID == policyID, "Retrieved policy ID matches")
		assert(retrieved.Name == policyName, "Retrieved policy name matches")
		assert(strings.Contains(retrieved.Pattern, "test_secret"), "Retrieved policy pattern matches")
		fmt.Printf("   Retrieved: %s (ID: %s)\n", retrieved.Name, retrieved.ID)
	}
	fmt.Println()

	// ========================================
	// 5. TEST PATTERN
	// ========================================
	fmt.Println("5. TestPattern - Testing regex pattern...")
	testInputs := []string{
		"test_secret_123",        // Should match
		"test_secret_abc",        // Should NOT match (no digits)
		"TEST_SECRET_999",        // Should match (case insensitive)
		"normal text",            // Should NOT match
		"my test_secret_42 data", // Should match
	}
	result, err := client.TestPattern(`(?i)test_secret_\d+`, testInputs)
	if err != nil {
		fmt.Printf("   ERROR: %v\n", err)
		failCount++
	} else {
		assert(result.Valid, "Pattern is valid")
		// Verify expected matches
		matchCount := 0
		for _, match := range result.Matches {
			if match.Matched {
				matchCount++
			}
		}
		assert(matchCount == 3, fmt.Sprintf("Expected 3 matches, got %d", matchCount))
		fmt.Printf("   Pattern valid: %v, Matches: %d/5\n", result.Valid, matchCount)
	}
	fmt.Println()

	// ========================================
	// 6. UPDATE STATIC POLICY
	// ========================================
	fmt.Println("6. UpdateStaticPolicy - Updating policy...")
	newDesc := "Updated description - now with stricter severity"
	newSeverity := axonflow.SeverityHigh
	newAction := axonflow.ActionBlock
	updated, err := client.UpdateStaticPolicy(policyID, &axonflow.UpdateStaticPolicyRequest{
		Description: &newDesc,
		Severity:    &newSeverity,
		Action:      &newAction,
	})
	if err != nil {
		fmt.Printf("   ERROR: %v\n", err)
		failCount++
	} else {
		assert(updated.Description == newDesc, "Description was updated")
		assert(string(updated.Severity) == string(newSeverity), "Severity was updated to high")
		assert(string(updated.Action) == string(newAction), "Action was updated to block")
		fmt.Printf("   Updated: %s (severity: %s, action: %s)\n", updated.Name, updated.Severity, updated.Action)
	}
	fmt.Println()

	// ========================================
	// 7. GET POLICY VERSIONS
	// ========================================
	fmt.Println("7. GetStaticPolicyVersions - Getting version history...")
	versions, err := client.GetStaticPolicyVersions(policyID)
	if err != nil {
		fmt.Printf("   Note: Version history may require Enterprise: %v\n", err)
	} else {
		fmt.Printf("   Found %d versions\n", len(versions))
		for _, v := range versions {
			fmt.Printf("   - v%d: %s at %s\n", v.Version, v.ChangeType, v.ChangedAt.Format(time.RFC3339))
		}
	}
	fmt.Println()

	// ========================================
	// 8. TOGGLE STATIC POLICY
	// ========================================
	fmt.Println("8. ToggleStaticPolicy - Disabling policy...")
	toggled, err := client.ToggleStaticPolicy(policyID, false)
	if err != nil {
		fmt.Printf("   ERROR: %v\n", err)
		failCount++
	} else {
		assert(!toggled.Enabled, "Policy was disabled")
		fmt.Printf("   Policy: %s, Enabled: %v\n", toggled.Name, toggled.Enabled)
	}

	fmt.Println("   Enabling policy again...")
	toggled, err = client.ToggleStaticPolicy(policyID, true)
	if err != nil {
		fmt.Printf("   ERROR: %v\n", err)
		failCount++
	} else {
		assert(toggled.Enabled, "Policy was re-enabled")
		fmt.Printf("   Policy: %s, Enabled: %v\n", toggled.Name, toggled.Enabled)
	}
	fmt.Println()

	// ========================================
	// 9. GET EFFECTIVE POLICIES
	// ========================================
	fmt.Println("9. GetEffectiveStaticPolicies - Getting effective policies...")
	effective, err := client.GetEffectiveStaticPolicies(&axonflow.EffectivePoliciesOptions{
		IncludeDisabled: false,
	})
	if err != nil {
		fmt.Printf("   ERROR: %v\n", err)
	} else {
		fmt.Printf("   Found %d effective policies\n", len(effective))
		// Check if our policy is in the effective list
		found := false
		for _, p := range effective {
			if p.ID == policyID {
				fmt.Printf("   Our policy is effective: %s\n", p.Name)
				found = true
				break
			}
		}
		if !found {
			fmt.Println("   Our policy is not in the effective list (may be disabled)")
		}
	}
	fmt.Println()

	// ========================================
	// 10. DELETE STATIC POLICY
	// ========================================
	fmt.Println("10. DeleteStaticPolicy - Cleaning up...")
	err = client.DeleteStaticPolicy(policyID)
	if err != nil {
		fmt.Printf("   WARNING: Failed to delete policy: %v\n", err)
		failCount++
	} else {
		assert(true, "Policy deleted successfully")
		fmt.Printf("   Deleted policy: %s\n", policyName)
		policyID = "" // Mark as deleted
	}
	fmt.Println()

	// ========================================
	// SUMMARY
	// ========================================
	fmt.Println("===========================================")
	fmt.Printf("Results: %d PASS, %d FAIL\n", passCount, failCount)
	fmt.Println()
	if failCount > 0 {
		fmt.Println("SOME TESTS FAILED")
		os.Exit(1)
	} else {
		fmt.Println("ALL TESTS PASSED - Static Policy CRUD verified!")
	}
}
