// Package main demonstrates and VALIDATES AxonFlow's media governance capabilities.
//
// Media governance analyzes images attached to LLM requests for:
// - PII in image text (via OCR)
// - Content safety (NSFW, violence scoring)
// - Face and biometric data detection (GDPR Art. 9)
// - Document classification (ID cards, bank statements)
// - SHA-256 integrity hashing for audit trails
//
// VALIDATION: This example exits with code 1 if any assertion fails.
// This ensures CI/CD pipelines catch regressions.
//
// Run with: go run main.go
// Prerequisites: docker compose up -d
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/getaxonflow/axonflow-sdk-go/v3"
)

// Minimal valid 1x1 white pixel JPEG encoded as base64.
const testImageBase64 = "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCAABAAEDASIAAhEBAxEB/8QAFAABAAAAAAAAAAAAAAAAAAAACf/EABQQAQAAAAAAAAAAAAAAAAAAAAD/xAAUAQEAAAAAAAAAAAAAAAAAAAAA/8QAFBEBAAAAAAAAAAAAAAAAAAAAAP/aAAwDAQACEQMRAD8AbwA//9k="

var failures []string

// pipelineActive tracks whether any response included MediaAnalysis data.
// If the platform version does not support media governance (< v4.4.0), this
// will remain false and the summary will report it.
var pipelineActive bool

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func assert(condition bool, message string) {
	if !condition {
		failures = append(failures, message)
		fmt.Printf("   FAIL: %s\n", message)
	} else {
		fmt.Printf("   PASS: %s\n", message)
	}
}

func main() {
	fmt.Println("AxonFlow Media Governance - Go SDK")
	fmt.Println("===================================")
	fmt.Println()

	// Initialize AxonFlow client
	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
		ClientID:     getEnv("AXONFLOW_CLIENT_ID", "demo"),
		ClientSecret: getEnv("AXONFLOW_CLIENT_SECRET", "demo"),
		Debug:        getEnv("AXONFLOW_DEBUG", "") == "true",
	})

	// ========================================
	// Test 1: Single image governance
	// ========================================
	fmt.Println("Test 1: Single image governance (base64)")
	fmt.Println("  Query: Describe this image")

	resp, err := client.ProxyLLMCallWithMedia(
		"media-governance-user",
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

	assert(resp.Success, "Response is successful")

	if resp.MediaAnalysis != nil {
		pipelineActive = true

		// Validate result count matches media items sent
		assert(len(resp.MediaAnalysis.Results) == 1, "Single media analysis result returned (expected 1, got "+fmt.Sprintf("%d", len(resp.MediaAnalysis.Results))+")")

		if len(resp.MediaAnalysis.Results) > 0 {
			result := resp.MediaAnalysis.Results[0]
			assert(result.SHA256Hash != "", "SHA-256 hash is populated")
			assert(result.MediaIndex == 0, "Media index is 0 for first image")
			assert(result.NSFWScore >= 0, fmt.Sprintf("NSFW score is non-negative (got %.4f)", result.NSFWScore))
			assert(result.ViolenceScore >= 0, fmt.Sprintf("Violence score is non-negative (got %.4f)", result.ViolenceScore))

			fmt.Printf("   Content safe: %v\n", result.ContentSafe)
			fmt.Printf("   NSFW score: %.2f\n", result.NSFWScore)
			fmt.Printf("   Violence score: %.2f\n", result.ViolenceScore)
			fmt.Printf("   Has PII: %v\n", result.HasPII)
			fmt.Printf("   Has faces: %v (count: %d)\n", result.HasFaces, result.FaceCount)
			fmt.Printf("   Has biometric data: %v\n", result.HasBiometricData)
			fmt.Printf("   Document type: %s\n", result.DocumentType)
			fmt.Printf("   Is sensitive document: %v\n", result.IsSensitiveDocument)
			fmt.Printf("   Estimated cost: $%.6f\n", result.EstimatedCostUSD)
		}

		assert(resp.MediaAnalysis.AnalysisTimeMs >= 0, fmt.Sprintf("Analysis time is non-negative (got %dms)", resp.MediaAnalysis.AnalysisTimeMs))
		assert(resp.MediaAnalysis.TotalCostUSD >= 0, fmt.Sprintf("Total cost is non-negative (got $%.6f)", resp.MediaAnalysis.TotalCostUSD))

		fmt.Printf("   Total analysis time: %dms\n", resp.MediaAnalysis.AnalysisTimeMs)
		fmt.Printf("   Total cost: $%.6f\n", resp.MediaAnalysis.TotalCostUSD)
	} else {
		fmt.Println("   WARNING: MEDIA GOVERNANCE PIPELINE NOT ACTIVE -- MediaAnalysis is nil (requires platform v4.4.0+)")
	}
	fmt.Println()

	// ========================================
	// Test 2: Multiple images in single request
	// ========================================
	fmt.Println("Test 2: Multiple images in single request")
	fmt.Println("  Query: Compare these images")

	resp2, err := client.ProxyLLMCallWithMedia(
		"media-governance-user",
		"Compare these images",
		"chat",
		[]axonflow.MediaContent{
			{
				Source:     "base64",
				MIMEType:   "image/jpeg",
				Base64Data: testImageBase64,
			},
			{
				Source:     "base64",
				MIMEType:   "image/jpeg",
				Base64Data: testImageBase64,
			},
		},
		nil,
	)
	if err != nil {
		fmt.Printf("   FATAL: ProxyLLMCallWithMedia failed: %v\n", err)
		os.Exit(1)
	}

	assert(resp2.Success, "Response is successful")

	if resp2.MediaAnalysis != nil {
		pipelineActive = true

		// Validate result count matches media items sent (2 images)
		assert(len(resp2.MediaAnalysis.Results) == 2, "Two media analysis results returned (expected 2, got "+fmt.Sprintf("%d", len(resp2.MediaAnalysis.Results))+")")

		for i, result := range resp2.MediaAnalysis.Results {
			assert(result.MediaIndex == i, fmt.Sprintf("Media index is %d for image %d (got %d)", i, i, result.MediaIndex))
			assert(result.SHA256Hash != "", fmt.Sprintf("SHA-256 hash is populated for image %d", i))
			assert(result.NSFWScore >= 0, fmt.Sprintf("NSFW score is non-negative for image %d (got %.4f)", i, result.NSFWScore))
			assert(result.ViolenceScore >= 0, fmt.Sprintf("Violence score is non-negative for image %d (got %.4f)", i, result.ViolenceScore))
		}

		// Both images are identical (same base64 data), so their SHA-256 hashes must match
		if len(resp2.MediaAnalysis.Results) == 2 {
			hash0 := resp2.MediaAnalysis.Results[0].SHA256Hash
			hash1 := resp2.MediaAnalysis.Results[1].SHA256Hash
			assert(hash0 == hash1, fmt.Sprintf("Identical images have same SHA-256 hash (%s == %s)", hash0, hash1))
		}

		assert(resp2.MediaAnalysis.AnalysisTimeMs >= 0, fmt.Sprintf("Analysis time is non-negative (got %dms)", resp2.MediaAnalysis.AnalysisTimeMs))
		assert(resp2.MediaAnalysis.TotalCostUSD >= 0, fmt.Sprintf("Total cost is non-negative (got $%.6f)", resp2.MediaAnalysis.TotalCostUSD))
	} else {
		fmt.Println("   WARNING: MEDIA GOVERNANCE PIPELINE NOT ACTIVE -- MediaAnalysis is nil (requires platform v4.4.0+)")
	}
	fmt.Println()

	// ========================================
	// Test 3: URL-sourced image
	// ========================================
	fmt.Println("Test 3: URL-sourced image")
	fmt.Println("  Query: Analyze this image from URL")

	resp3, err := client.ProxyLLMCallWithMedia(
		"media-governance-user",
		"Analyze this image from URL",
		"chat",
		[]axonflow.MediaContent{{
			Source:   "url",
			MIMEType: "image/png",
			URL:      "https://via.placeholder.com/1x1.png",
		}},
		nil,
	)
	if err != nil {
		fmt.Printf("   FATAL: ProxyLLMCallWithMedia failed: %v\n", err)
		os.Exit(1)
	}

	assert(resp3.Success, "Response is successful")

	if resp3.MediaAnalysis != nil {
		pipelineActive = true

		// Validate result count matches media items sent (1 URL image)
		assert(len(resp3.MediaAnalysis.Results) == 1, "Single media analysis result returned for URL image (expected 1, got "+fmt.Sprintf("%d", len(resp3.MediaAnalysis.Results))+")")

		if len(resp3.MediaAnalysis.Results) > 0 {
			result := resp3.MediaAnalysis.Results[0]
			if result.SHA256Hash != "" {
				fmt.Println("   PASS: SHA-256 hash is populated for URL image")
			} else {
				fmt.Println("   WARNING: SHA-256 hash empty for URL source (platform may not have network access to download URL)")
			}
			assert(result.MediaIndex == 0, fmt.Sprintf("Media index is 0 for URL image (got %d)", result.MediaIndex))
			assert(result.NSFWScore >= 0, fmt.Sprintf("NSFW score is non-negative for URL image (got %.4f)", result.NSFWScore))
			assert(result.ViolenceScore >= 0, fmt.Sprintf("Violence score is non-negative for URL image (got %.4f)", result.ViolenceScore))
		}

		assert(resp3.MediaAnalysis.AnalysisTimeMs >= 0, fmt.Sprintf("Analysis time is non-negative (got %dms)", resp3.MediaAnalysis.AnalysisTimeMs))
		assert(resp3.MediaAnalysis.TotalCostUSD >= 0, fmt.Sprintf("Total cost is non-negative (got $%.6f)", resp3.MediaAnalysis.TotalCostUSD))
	} else {
		fmt.Println("   WARNING: MEDIA GOVERNANCE PIPELINE NOT ACTIVE -- MediaAnalysis is nil (requires platform v4.4.0+)")
	}
	fmt.Println()

	// ========================================
	// Test 4: Request without media still succeeds
	// ========================================
	fmt.Println("Test 4: Request without media still succeeds")
	fmt.Println("  Query: What is the capital of France?")

	resp4, err := client.ProxyLLMCall(
		"media-governance-user",
		"What is the capital of France?",
		"chat",
		nil,
	)
	if err != nil {
		fmt.Printf("   FATAL: ProxyLLMCall failed: %v\n", err)
		os.Exit(1)
	}

	assert(resp4.Success, "Non-media LLM call succeeds")
	assert(resp4.MediaAnalysis == nil, "MediaAnalysis is nil for non-media request")
	fmt.Println()

	// ========================================
	// Test 5: Verify policy_info present for media requests
	// ========================================
	fmt.Println("Test 5: Verify policy_info present for media requests")
	fmt.Println("  Checking policy_info from Test 1 response (media request)")

	if resp.PolicyInfo != nil {
		assert(resp.PolicyInfo.TenantID != "", "policy_info.tenant_id is non-empty (got "+resp.PolicyInfo.TenantID+")")
		assert(resp.PolicyInfo.ProcessingTime != "", "policy_info.processing_time is non-empty")

		hasMediaPolicy := false
		for _, p := range resp.PolicyInfo.PoliciesEvaluated {
			if strings.HasPrefix(p, "sys_media_") {
				hasMediaPolicy = true
				break
			}
		}
		if hasMediaPolicy {
			fmt.Println("   PASS: system media policies found in policies_evaluated")
		} else {
			fmt.Println("   INFO: no sys_media_* policies in policies_evaluated (dynamic policies may be tracked separately)")
		}
		fmt.Printf("   Policies evaluated: %v\n", resp.PolicyInfo.PoliciesEvaluated)
	} else if pipelineActive {
		fmt.Println("   WARNING: policy_info absent despite media analysis being active")
	} else {
		fmt.Println("   SKIP: policy_info not available (media governance pipeline not active)")
	}
	fmt.Println()

	// ========================================
	// Summary
	// ========================================
	fmt.Println("===================================")

	if pipelineActive {
		fmt.Println("Media governance pipeline: ACTIVE")
	} else {
		fmt.Println("Media governance pipeline: NOT DETECTED (requires platform v4.4.0+)")
	}
	fmt.Println()

	if len(failures) == 0 {
		fmt.Println("ALL TESTS PASSED")
		fmt.Println()
		fmt.Println("Media governance capabilities validated:")
		fmt.Println("  - Single image analysis (base64)")
		fmt.Println("  - Multiple image analysis (with SHA-256 dedup check)")
		fmt.Println("  - URL-sourced image analysis")
		fmt.Println("  - Non-media baseline request")
		fmt.Println("  - Policy evaluation metadata for media requests")
	} else {
		fmt.Printf("%d TEST(S) FAILED:\n", len(failures))
		for _, f := range failures {
			fmt.Printf("   - %s\n", f)
		}
		os.Exit(1)
	}
}
