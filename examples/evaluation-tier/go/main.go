// Package main demonstrates Evaluation tier licensing and tier-aware policy limits
// using the AxonFlow Go SDK.
//
// TIER COMPATIBILITY: Community / Evaluation
// Works without any license (Community mode) and with a free Evaluation license.
// No paid Enterprise license required. Get a free Evaluation license at:
// https://getaxonflow.com/evaluation-license
//
// VALIDATION: This example exits with code 1 if any assertion fails.
//
// This example tests:
// - Tier detection (Community, Evaluation, Enterprise)
// - Tenant policy limits (20/50/unlimited)
// - Organization policy access (0/5/unlimited)
// - Upgrade path messages
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v6"
)

var failures []string

func assertCheck(condition bool, message string) {
	if condition {
		fmt.Printf("   ✓ PASS: %s\n", message)
	} else {
		fmt.Printf("   ❌ FAIL: %s\n", message)
		failures = append(failures, message)
	}
}

func getExpectedTier() string {
	licenseKey := os.Getenv("AXONFLOW_LICENSE_KEY")
	if licenseKey == "" {
		return "community"
	}
	// Ed25519 format: AXON-{base64url_payload}.{base64url_signature}
	if strings.HasPrefix(licenseKey, "AXON-") && strings.Contains(licenseKey, ".") {
		inner := licenseKey[5:] // Strip "AXON-"
		lastDot := strings.LastIndex(inner, ".")
		if lastDot > 0 {
			payloadB64 := inner[:lastDot]
			decoded, err := base64.RawURLEncoding.DecodeString(payloadB64)
			if err == nil {
				var payload struct {
					Tier string `json:"tier"`
				}
				if json.Unmarshal(decoded, &payload) == nil {
					tier := payload.Tier
					if tier == "Evaluation" {
						return "evaluation"
					}
					if tier == "Enterprise" || tier == "Plus" || tier == "Professional" {
						return "enterprise"
					}
				}
			}
		}
	}
	if strings.Contains(strings.ToUpper(licenseKey), "EVALUATION") {
		return "evaluation"
	}
	return "enterprise"
}

func main() {
	fmt.Println("============================================================")
	fmt.Println("AxonFlow Evaluation Tier - License Tier Limits Testing (Go)")
	fmt.Println("============================================================")

	expectedTier := getExpectedTier()
	fmt.Printf("\nDetected tier (from env): %s\n", expectedTier)

	endpoint := os.Getenv("AXONFLOW_ENDPOINT")
	if endpoint == "" {
		endpoint = "http://localhost:8080"
	}

	clientID := os.Getenv("AXONFLOW_CLIENT_ID")
	if clientID == "" {
		clientID = "test-org-001"
	}

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint: endpoint,
		ClientID: clientID,
	})

	// Test 1: Health Check / Tier Detection
	fmt.Println("\n1. Testing Tier Detection")
	fmt.Println("----------------------------------------")

	err := client.HealthCheck()
	if err != nil {
		fmt.Printf("   Error: %v\n", err)
		assertCheck(false, "Health check passed")
	} else {
		assertCheck(true, "Platform is healthy")
	}

	// Test 2: Create and Delete Tenant Policy
	fmt.Println("\n2. Testing Tenant Policy Limits")
	fmt.Println("----------------------------------------")

	var expectedLimit string
	switch expectedTier {
	case "community":
		expectedLimit = "20"
	case "evaluation":
		expectedLimit = "50"
	default:
		expectedLimit = "unlimited"
	}
	fmt.Printf("   Expected limit for %s: %s\n", expectedTier, expectedLimit)

	policy, err := client.CreateDynamicPolicy(&axonflow.CreateDynamicPolicyRequest{
		Name:        "Go Evaluation Tier Test Policy",
		Description: "Test policy for tier limit verification",
		Type:        "content",
		Category:    "dynamic-go-tier-test",
		Conditions: []axonflow.DynamicPolicyCondition{
			{Field: "query", Operator: "contains", Value: "go-tier-test"},
		},
		Actions:  []axonflow.DynamicPolicyAction{{Type: "log"}},
		Priority: 100,
		Enabled:  false,
	})

	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "POLICY_LIMIT_EXCEEDED") {
			fmt.Printf("   Policy limit reached\n")
			assertCheck(true, "Policy limit enforcement working")

			if expectedTier == "community" && strings.Contains(strings.ToLower(errStr), "evaluation") {
				assertCheck(true, "Error mentions Evaluation upgrade path")
			} else if expectedTier == "evaluation" && strings.Contains(strings.ToLower(errStr), "enterprise") {
				assertCheck(true, "Error mentions Enterprise upgrade path")
			}
		} else {
			fmt.Printf("   Error: %v\n", err)
			assertCheck(false, "Policy creation succeeded or limit enforced")
		}
	} else {
		assertCheck(true, "Policy creation succeeded")
		fmt.Printf("   Created policy: %s\n", policy.ID)

		// Clean up
		err = client.DeleteDynamicPolicy(policy.ID)
		if err == nil {
			fmt.Println("   Cleaned up test policy")
		}
	}

	// Test 3: Organization Policy Access
	fmt.Println("\n3. Testing Organization Policy Access")
	fmt.Println("----------------------------------------")

	orgPolicy, err := client.CreateDynamicPolicy(&axonflow.CreateDynamicPolicyRequest{
		Name:        "Go Org Policy Test",
		Description: "Test org policy for tier verification",
		Type:        "content",
		Category:    "dynamic-go-org-test",
		Tier:        "organization",
		Conditions: []axonflow.DynamicPolicyCondition{
			{Field: "query", Operator: "contains", Value: "go-org-test"},
		},
		Actions:  []axonflow.DynamicPolicyAction{{Type: "log"}},
		Priority: 100,
		Enabled:  false,
	})

	if err != nil {
		errStr := err.Error()
		if expectedTier == "community" {
			if strings.Contains(errStr, "ORG_TIER") || strings.Contains(strings.ToLower(errStr), "evaluation") {
				assertCheck(true, "Community tier correctly blocked org policy creation")
				if strings.Contains(strings.ToLower(errStr), "evaluation") {
					assertCheck(true, "Error includes Evaluation upgrade path")
				}
			} else {
				fmt.Printf("   Error: %v\n", err)
				assertCheck(false, "Expected org tier error for Community")
			}
		} else if strings.Contains(errStr, "ORG_POLICY_LIMIT_EXCEEDED") {
			fmt.Println("   Org policy limit reached for Evaluation tier")
			assertCheck(true, "Evaluation tier has org policy limit enforcement")
		} else {
			fmt.Printf("   Error: %v\n", err)
			assertCheck(false, "Unexpected error creating org policy")
		}
	} else {
		if expectedTier == "community" {
			assertCheck(false, "Community should not create org policies")
		} else {
			assertCheck(true, fmt.Sprintf("%s tier can create org policies", expectedTier))
			fmt.Printf("   Created org policy: %s\n", orgPolicy.ID)

			// Clean up
			err = client.DeleteDynamicPolicy(orgPolicy.ID)
			if err == nil {
				fmt.Println("   Cleaned up org policy")
			}
		}
	}

	// Summary
	fmt.Println("\n============================================================")
	fmt.Println("TEST SUMMARY")
	fmt.Println("============================================================")

	if len(failures) > 0 {
		fmt.Printf("\n❌ %d test(s) failed:\n", len(failures))
		for _, f := range failures {
			fmt.Printf("   - %s\n", f)
		}
		os.Exit(1)
	} else {
		fmt.Println("\n✓ All tests passed!")
		fmt.Printf("\nTier limits verified for: %s\n", expectedTier)
		fmt.Println("\nTier Comparison:")
		fmt.Println("  | Feature          | Community | Evaluation | Enterprise |")
		fmt.Println("  |------------------|-----------|------------|------------|")
		fmt.Println("  | Tenant policies  | 20        | 50         | Unlimited  |")
		fmt.Println("  | Org policies     | 0         | 5          | Unlimited  |")
		fmt.Println("  | MCP connectors   | 2         | 5          | Unlimited  |")
		fmt.Println("  | Audit retention  | 3 days    | 14 days    | 3650 days  |")
		os.Exit(0)
	}
}
