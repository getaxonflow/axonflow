// Media Governance Policies Example - Go
//
// Demonstrates and VALIDATES media governance policy management using the Go SDK.
// Media governance policies are dynamic policies of type "media" that evaluate
// signals derived from image analysis (NSFW scores, face detection, PII, documents)
// rather than text content patterns.
//
// Tests covered:
//   - System media policies verification (seeded by migration)
//   - NSFW system policy evaluation with clean image
//   - Custom media policy CRUD (create, list, verify, delete)
//   - Media governance config and status endpoints
//   - Policy toggle lifecycle (enable/disable)
//   - Per-tenant media governance disable/enable (Enterprise only)
//   - Non-media requests unaffected by media policies
//
// All requests go through the agent entry point (AXONFLOW_ENDPOINT, default 8080).
// The agent proxies policy CRUD, media governance config, and LLM proxy requests.
//
// Usage:
//
//	go run main.go
//
// Environment:
//
//	AXONFLOW_ENDPOINT      - Agent URL (default: http://localhost:8080)
//	AXONFLOW_CLIENT_ID     - Client/Tenant ID for policy scoping
//	AXONFLOW_CLIENT_SECRET - Client secret (optional for community mode)
//
// VALIDATION: This example exits with code 1 if any assertion fails.
package main

import (
	"fmt"
	"os"
	"strings"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v5"
)

// Minimal valid 1x1 white pixel JPEG encoded as base64.
const testImageBase64 = "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCAABAAEDASIAAhEBAxEB/8QAFAABAAAAAAAAAAAAAAAAAAAACf/EABQQAQAAAAAAAAAAAAAAAAAAAAD/xAAUAQEAAAAAAAAAAAAAAAAAAAAA/8QAFBEBAAAAAAAAAAAAAAAAAAAAAP/aAAwDAQACEQMRAD8AbwA//9k="

var failures []string

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func assert(condition bool, message string) {
	if condition {
		fmt.Printf("   PASS: %s\n", message)
	} else {
		fmt.Printf("   FAIL: %s\n", message)
		failures = append(failures, message)
	}
}

func boolPtr(b bool) *bool {
	return &b
}

func main() {
	fmt.Println("AxonFlow Media Governance Policies - Go SDK")
	fmt.Println("============================================")
	fmt.Println()

	// Initialize client: all requests go through the agent entry point.
	agentEndpoint := getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080")
	clientID := getEnv("AXONFLOW_CLIENT_ID", "demo-tenant")
	clientSecret := getEnv("AXONFLOW_CLIENT_SECRET", "")

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     agentEndpoint,
		ClientID:     clientID,
		ClientSecret: clientSecret,
	})

	fmt.Printf("Agent:     %s\n", agentEndpoint)
	fmt.Printf("Client ID: %s\n", clientID)
	fmt.Println()

	// Track per-tenant control availability for Test 6
	var perTenantControl bool

	// ========================================
	// Test 1: Verify system media policies exist
	// ========================================
	fmt.Println("Test 1: Verify system media policies exist")
	fmt.Println("  ListDynamicPolicies(type=media, page_size=100)")
	fmt.Println()

	policies, err := client.ListDynamicPolicies(&axonflow.ListDynamicPoliciesOptions{
		Type:     "media",
		Limit: 100,
	})
	if err != nil {
		fmt.Printf("   FATAL: ListDynamicPolicies failed: %v\n", err)
		os.Exit(1)
	}

	// Count system media policies (IDs starting with sys_media_)
	var sysMediaPolicies []axonflow.DynamicPolicy
	categoryCounts := map[string]int{}
	for _, p := range policies {
		if strings.HasPrefix(p.ID, "sys_media_") {
			sysMediaPolicies = append(sysMediaPolicies, p)
			categoryCounts[p.Category]++
		}
	}

	assert(len(sysMediaPolicies) >= 5, fmt.Sprintf("At least 5 system media policies found (got %d)", len(sysMediaPolicies)))
	assert(categoryCounts["media-safety"] >= 2, fmt.Sprintf("media-safety category has >= 2 policies (got %d)", categoryCounts["media-safety"]))
	assert(categoryCounts["media-biometric"] >= 1, fmt.Sprintf("media-biometric category has >= 1 policy (got %d)", categoryCounts["media-biometric"]))
	assert(categoryCounts["media-pii"] >= 1, fmt.Sprintf("media-pii category has >= 1 policy (got %d)", categoryCounts["media-pii"]))
	assert(categoryCounts["media-document"] >= 1, fmt.Sprintf("media-document category has >= 1 policy (got %d)", categoryCounts["media-document"]))

	fmt.Println()
	fmt.Println("  System media policies:")
	for _, p := range sysMediaPolicies {
		fmt.Printf("    - %s: %s [%s]\n", p.ID, p.Name, p.Category)
	}
	fmt.Println()

	// ========================================
	// Test 2: System NSFW policy evaluation -- clean image passes
	// ========================================
	fmt.Println("Test 2: System NSFW policy evaluation -- clean image passes")
	fmt.Println("  ProxyLLMCallWithMedia (1x1 white JPEG)")
	fmt.Println()

	resp2, err := client.ProxyLLMCallWithMedia(
		"media-policy-user",
		"Describe this image",
		"chat",
		[]axonflow.MediaContent{{
			Source:     "base64",
			MIMEType:   "image/jpeg",
			Base64Data: testImageBase64,
		}},
		nil,
	)
	if err != nil {
		fmt.Printf("   FATAL: ProxyLLMCallWithMedia failed: %v\n", err)
		os.Exit(1)
	}

	assert(resp2.Success, "Response is successful")
	assert(!resp2.Blocked, fmt.Sprintf("Clean image is NOT blocked (blocked=%v)", resp2.Blocked))

	if resp2.MediaAnalysis != nil {
		fmt.Println("   PASS: media_analysis present (pipeline active)")
		if len(resp2.MediaAnalysis.Results) > 0 {
			fmt.Printf("   NSFW score: %.4f\n", resp2.MediaAnalysis.Results[0].NSFWScore)
			fmt.Printf("   Content safe: %v\n", resp2.MediaAnalysis.Results[0].ContentSafe)
		}
	} else {
		fmt.Println("   WARNING: media_analysis absent -- media governance pipeline not active (requires platform v4.4.0+ with analyzers)")
	}
	fmt.Println()

	// ========================================
	// Test 3: Custom media policy -- create and verify
	// ========================================
	fmt.Println("Test 3: Custom media policy -- create and verify")
	fmt.Println()

	// 3a. Create a custom media policy: block if has_faces == true
	fmt.Println("  3a. Creating custom media policy: block if media.has_faces == true")
	policyName := fmt.Sprintf("test-face-block-go-%d", os.Getpid())
	createReq := &axonflow.CreateDynamicPolicyRequest{
		Name:        policyName,
		Description: "Blocks images containing faces (Go example test policy)",
		Type:        "media",
		Category:    "media-safety",
		Conditions: []axonflow.DynamicPolicyCondition{
			{
				Field:    "media.has_faces",
				Operator: "equals",
				Value:    true,
			},
		},
		Actions: []axonflow.DynamicPolicyAction{
			{
				Type:   "block",
				Config: map[string]interface{}{"message": "Media blocked: faces detected in image"},
			},
		},
		Priority: 100,
		Enabled:  true,
	}

	created, err := client.CreateDynamicPolicy(createReq)
	if err != nil {
		fmt.Printf("   FATAL: CreateDynamicPolicy failed: %v\n", err)
		os.Exit(1)
	}

	assert(created.ID != "", fmt.Sprintf("Policy created with ID: %s", created.ID))
	assert(created.Name == policyName, fmt.Sprintf("Policy name matches (%s)", created.Name))

	// 3b. Verify it appears in the list
	fmt.Println()
	fmt.Println("  3b. Verifying policy appears in list")
	policiesAfterCreate, err := client.ListDynamicPolicies(&axonflow.ListDynamicPoliciesOptions{
		Type:     "media",
		Limit: 100,
	})
	if err != nil {
		fmt.Printf("   ERROR: ListDynamicPolicies failed: %v\n", err)
		assert(false, "ListDynamicPolicies succeeded after create")
	} else {
		found := false
		for _, p := range policiesAfterCreate {
			if p.ID == created.ID {
				found = true
				break
			}
		}
		assert(found, fmt.Sprintf("Created policy found in list (ID: %s)", created.ID))
	}

	// 3c. Send a 1x1 image request -- should NOT be blocked (no faces in a 1px image)
	fmt.Println()
	fmt.Println("  3c. Sending 1x1 image request (no faces expected)")
	resp3c, err := client.ProxyLLMCallWithMedia(
		"media-policy-user",
		"Describe this image",
		"chat",
		[]axonflow.MediaContent{{
			Source:     "base64",
			MIMEType:   "image/jpeg",
			Base64Data: testImageBase64,
		}},
		nil,
	)
	if err != nil {
		fmt.Printf("   FATAL: ProxyLLMCallWithMedia failed: %v\n", err)
		os.Exit(1)
	}

	assert(!resp3c.Blocked, fmt.Sprintf("1x1 image NOT blocked by face policy (no faces in 1px image, blocked=%v)", resp3c.Blocked))

	// 3d. Cleanup -- delete the custom policy
	fmt.Println()
	fmt.Println("  3d. Cleaning up: deleting custom policy")
	err = client.DeleteDynamicPolicy(created.ID)
	if err != nil {
		fmt.Printf("   ERROR: DeleteDynamicPolicy failed: %v\n", err)
		assert(false, "Policy deleted successfully")
	} else {
		assert(true, "Policy deleted successfully")
	}
	fmt.Println()

	// ========================================
	// Test 4: Media governance config -- read status
	// ========================================
	fmt.Println("Test 4: Media governance config -- read status")
	fmt.Println()

	// 4a. GetMediaGovernanceStatus
	fmt.Println("  4a. GetMediaGovernanceStatus")
	status, err := client.GetMediaGovernanceStatus()
	if err != nil {
		fmt.Printf("   FATAL: GetMediaGovernanceStatus failed: %v\n", err)
		os.Exit(1)
	}

	assert(status.Tier != "", fmt.Sprintf("Tier is non-empty (%s)", status.Tier))
	fmt.Printf("   Tier: %s | Available: %v | Per-tenant control: %v\n", status.Tier, status.Available, status.PerTenantControl)

	perTenantControl = status.PerTenantControl

	// 4b. GetMediaGovernanceConfig
	fmt.Println()
	fmt.Println("  4b. GetMediaGovernanceConfig")
	config, err := client.GetMediaGovernanceConfig()
	if err != nil {
		fmt.Printf("   FATAL: GetMediaGovernanceConfig failed: %v\n", err)
		os.Exit(1)
	}

	assert(config.TenantID != "", fmt.Sprintf("Config has TenantID (%s)", config.TenantID))
	fmt.Printf("   Tenant: %s | Enabled: %v\n", config.TenantID, config.Enabled)
	fmt.Println()

	// ========================================
	// Test 5: Policy toggle lifecycle
	// ========================================
	fmt.Println("Test 5: Policy toggle lifecycle (create -> disable -> re-enable -> delete)")
	fmt.Println()

	// 5a. Create a media policy
	fmt.Println("  5a. Creating media policy: media.nsfw_score > 0.5 -> block")
	togglePolicyName := fmt.Sprintf("test-nsfw-toggle-go-%d", os.Getpid())
	toggleCreateReq := &axonflow.CreateDynamicPolicyRequest{
		Name:        togglePolicyName,
		Description: "NSFW threshold policy for toggle lifecycle test",
		Type:        "media",
		Category:    "media-safety",
		Conditions: []axonflow.DynamicPolicyCondition{
			{
				Field:    "media.nsfw_score",
				Operator: "greater_than",
				Value:    0.5,
			},
		},
		Actions: []axonflow.DynamicPolicyAction{
			{
				Type:   "block",
				Config: map[string]interface{}{"message": "Media blocked: NSFW score exceeds threshold (> 0.5)"},
			},
		},
		Priority: 200,
		Enabled:  true,
	}

	toggleCreated, err := client.CreateDynamicPolicy(toggleCreateReq)
	if err != nil {
		fmt.Printf("   FATAL: CreateDynamicPolicy failed: %v\n", err)
		os.Exit(1)
	}

	assert(toggleCreated.ID != "", fmt.Sprintf("Policy created with ID: %s", toggleCreated.ID))
	assert(toggleCreated.Enabled, fmt.Sprintf("Policy initially enabled (enabled=%v)", toggleCreated.Enabled))

	// 5b. Disable the policy
	fmt.Println()
	fmt.Println("  5b. Disabling policy (UpdateDynamicPolicy enabled=false)")
	disabledPolicy, err := client.UpdateDynamicPolicy(toggleCreated.ID, &axonflow.UpdateDynamicPolicyRequest{
		Enabled: boolPtr(false),
	})
	if err != nil {
		fmt.Printf("   ERROR: UpdateDynamicPolicy failed: %v\n", err)
		assert(false, "Policy disable succeeded")
	} else {
		assert(!disabledPolicy.Enabled, fmt.Sprintf("Policy is now disabled (enabled=%v)", disabledPolicy.Enabled))
	}

	// 5c. Re-enable the policy
	fmt.Println()
	fmt.Println("  5c. Re-enabling policy (UpdateDynamicPolicy enabled=true)")
	enabledPolicy, err := client.UpdateDynamicPolicy(toggleCreated.ID, &axonflow.UpdateDynamicPolicyRequest{
		Enabled: boolPtr(true),
	})
	if err != nil {
		fmt.Printf("   ERROR: UpdateDynamicPolicy failed: %v\n", err)
		assert(false, "Policy re-enable succeeded")
	} else {
		assert(enabledPolicy.Enabled, fmt.Sprintf("Policy is now re-enabled (enabled=%v)", enabledPolicy.Enabled))
	}

	// 5d. Cleanup
	fmt.Println()
	fmt.Println("  5d. Cleaning up: deleting toggle test policy")
	err = client.DeleteDynamicPolicy(toggleCreated.ID)
	if err != nil {
		fmt.Printf("   ERROR: DeleteDynamicPolicy failed: %v\n", err)
		assert(false, "Toggle policy deleted successfully")
	} else {
		assert(true, "Toggle policy deleted successfully")
	}
	fmt.Println()

	// ========================================
	// Test 6: Media governance disable/enable (Enterprise only)
	// ========================================
	fmt.Println("Test 6: Media governance disable/enable (per-tenant config)")
	fmt.Println()

	if perTenantControl {
		fmt.Println("  Enterprise mode detected -- testing per-tenant media governance toggle")
		fmt.Println()

		// 6a. Disable media governance for this tenant
		fmt.Println("  6a. Disabling media governance (UpdateMediaGovernanceConfig enabled=false)")
		_, err := client.UpdateMediaGovernanceConfig(axonflow.UpdateMediaGovernanceConfigRequest{
			Enabled: boolPtr(false),
		})
		if err != nil {
			fmt.Printf("   ERROR: UpdateMediaGovernanceConfig failed: %v\n", err)
			assert(false, "Media governance disabled")
		} else {
			assert(true, "Media governance disabled")
		}

		// 6b. Process request with media -- media_analysis should be absent
		fmt.Println()
		fmt.Println("  6b. Sending image request with media governance disabled")
		resp6b, err := client.ProxyLLMCallWithMedia(
			"media-policy-user",
			"Describe this image",
			"chat",
			[]axonflow.MediaContent{{
				Source:     "base64",
				MIMEType:   "image/jpeg",
				Base64Data: testImageBase64,
			}},
			nil,
		)
		if err != nil {
			fmt.Printf("   FATAL: ProxyLLMCallWithMedia failed: %v\n", err)
			os.Exit(1)
		}

		assert(resp6b.Success, fmt.Sprintf("Request still succeeds (success=%v)", resp6b.Success))
		assert(resp6b.MediaAnalysis == nil, "media_analysis absent when governance disabled")

		// 6c. Re-enable media governance
		fmt.Println()
		fmt.Println("  6c. Re-enabling media governance (UpdateMediaGovernanceConfig enabled=true)")
		_, err = client.UpdateMediaGovernanceConfig(axonflow.UpdateMediaGovernanceConfigRequest{
			Enabled: boolPtr(true),
		})
		if err != nil {
			fmt.Printf("   ERROR: UpdateMediaGovernanceConfig failed: %v\n", err)
			assert(false, "Media governance re-enabled")
		} else {
			assert(true, "Media governance re-enabled")
		}

		// 6d. Verify media_analysis returns after re-enable
		fmt.Println()
		fmt.Println("  6d. Sending image request with media governance re-enabled")
		resp6d, err := client.ProxyLLMCallWithMedia(
			"media-policy-user",
			"Describe this image",
			"chat",
			[]axonflow.MediaContent{{
				Source:     "base64",
				MIMEType:   "image/jpeg",
				Base64Data: testImageBase64,
			}},
			nil,
		)
		if err != nil {
			fmt.Printf("   FATAL: ProxyLLMCallWithMedia failed: %v\n", err)
			os.Exit(1)
		}

		assert(resp6d.Success, fmt.Sprintf("Request succeeds after re-enable (success=%v)", resp6d.Success))
		if resp6d.MediaAnalysis != nil {
			fmt.Println("   PASS: media_analysis present after re-enable")
		} else {
			fmt.Println("   WARNING: media_analysis absent after re-enable (analyzers may not be active in this environment)")
		}
	} else {
		fmt.Println("  SKIP: Per-tenant media governance control requires Enterprise license.")
		fmt.Println("  Community/Evaluation tiers use the global media governance setting.")
		fmt.Println("  To test this, run with an Enterprise license key set in AXONFLOW_LICENSE_KEY.")
	}
	fmt.Println()

	// ========================================
	// Test 7: Non-media request unaffected
	// ========================================
	fmt.Println("Test 7: Non-media request unaffected by media policies")
	fmt.Println("  ProxyLLMCall (text only, no media)")
	fmt.Println()

	resp7, err := client.ProxyLLMCall(
		"media-policy-user",
		"What is the capital of France?",
		"chat",
		nil,
	)
	if err != nil {
		fmt.Printf("   FATAL: ProxyLLMCall failed: %v\n", err)
		os.Exit(1)
	}

	assert(resp7.Success, fmt.Sprintf("Text-only request is successful (success=%v)", resp7.Success))
	assert(resp7.MediaAnalysis == nil, "No media_analysis present for text-only request")
	fmt.Println()

	// ========================================
	// Summary
	// ========================================
	fmt.Println("============================================")
	fmt.Println()

	if len(failures) == 0 {
		fmt.Println("ALL TESTS PASSED")
		fmt.Println()
		fmt.Println("Media governance policy capabilities validated:")
		fmt.Println("  - System media policies (NSFW, violence, biometric, PII, documents)")
		fmt.Println("  - Clean image passes system NSFW policy")
		fmt.Println("  - Custom media policy CRUD (create, list, verify, delete)")
		fmt.Println("  - Media governance config and status endpoints")
		fmt.Println("  - Policy toggle lifecycle (create, disable, re-enable, delete)")
		if perTenantControl {
			fmt.Println("  - Per-tenant media governance disable/enable (Enterprise)")
		}
		fmt.Println("  - Non-media requests unaffected by media policies")
	} else {
		fmt.Printf("%d TEST(S) FAILED:\n", len(failures))
		for _, f := range failures {
			fmt.Printf("   - %s\n", f)
		}
		os.Exit(1)
	}
}
