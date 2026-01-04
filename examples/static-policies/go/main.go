// AxonFlow Static Policy Management - Go SDK (Comprehensive)
//
// This example demonstrates ALL static policy SDK methods:
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
// Run with: go run main.go
// Prerequisites: docker compose up -d

package main

import (
	"fmt"
	"os"
	"time"

	axonflow "github.com/getaxonflow/axonflow-sdk-go"
)

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
	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		AgentURL:        getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
		OrchestratorURL: getEnv("AXONFLOW_ORCHESTRATOR_URL", "http://localhost:8081"),
		ClientID:        getEnv("AXONFLOW_CLIENT_ID", "demo-client"),
		ClientSecret:    getEnv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
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
	} else {
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
		return
	}
	policyID = created.ID
	fmt.Printf("   Created: %s\n", created.Name)
	fmt.Printf("   ID: %s\n", created.ID)
	fmt.Printf("   Category: %s\n", created.Category)
	fmt.Printf("   Action: %s\n", created.Action)
	fmt.Println()

	// ========================================
	// 4. GET STATIC POLICY
	// ========================================
	fmt.Println("4. GetStaticPolicy - Retrieving policy by ID...")
	retrieved, err := client.GetStaticPolicy(policyID)
	if err != nil {
		fmt.Printf("   ERROR: %v\n", err)
	} else {
		fmt.Printf("   Retrieved: %s\n", retrieved.Name)
		fmt.Printf("   Pattern: %s\n", retrieved.Pattern)
		fmt.Printf("   Enabled: %v\n", retrieved.Enabled)
		version := 1
		if retrieved.Version > 0 {
			version = retrieved.Version
		}
		fmt.Printf("   Version: %d\n", version)
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
	} else {
		fmt.Printf("   Pattern valid: %v\n", result.Valid)
		fmt.Println("   Match results:")
		for _, match := range result.Matches {
			status := "NO MATCH"
			if match.Matched {
				status = "MATCH"
			}
			fmt.Printf("     [%s] %s\n", status, match.Input)
		}
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
	} else {
		fmt.Printf("   Updated: %s\n", updated.Name)
		fmt.Printf("   New severity: %s\n", updated.Severity)
		fmt.Printf("   New action: %s\n", updated.Action)
		version := 2
		if updated.Version > 0 {
			version = updated.Version
		}
		fmt.Printf("   New version: %d\n", version)
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
	} else {
		fmt.Printf("   Policy: %s\n", toggled.Name)
		fmt.Printf("   Enabled: %v\n", toggled.Enabled)
	}
	fmt.Println()

	fmt.Println("   Enabling policy again...")
	toggled, err = client.ToggleStaticPolicy(policyID, true)
	if err != nil {
		fmt.Printf("   ERROR: %v\n", err)
	} else {
		fmt.Printf("   Enabled: %v\n", toggled.Enabled)
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
	} else {
		fmt.Printf("   Deleted policy: %s\n", policyName)
		policyID = "" // Mark as deleted
	}
	fmt.Println()

	fmt.Println("===========================================")
	fmt.Println("All 10 Static Policy SDK methods tested!")
	fmt.Println()
	fmt.Println("Methods demonstrated:")
	fmt.Println("  1. ListStaticPolicies()           - List with filtering")
	fmt.Println("  2. ListStaticPolicies(category)   - Filter by category")
	fmt.Println("  3. CreateStaticPolicy()           - Create new policy")
	fmt.Println("  4. GetStaticPolicy()              - Get by ID")
	fmt.Println("  5. TestPattern()                  - Test regex pattern")
	fmt.Println("  6. UpdateStaticPolicy()           - Update policy")
	fmt.Println("  7. GetStaticPolicyVersions()      - Version history")
	fmt.Println("  8. ToggleStaticPolicy()           - Enable/disable")
	fmt.Println("  9. GetEffectiveStaticPolicies()   - Effective policies")
	fmt.Println(" 10. DeleteStaticPolicy()           - Delete policy")
}
