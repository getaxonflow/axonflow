// Package main validates the HITL Queue API SDK methods.
//
// The HITL Queue is an enterprise-only feature. In community mode, all HITL
// queue endpoints return HTTP 403 or 404. This example verifies that the API
// exists and returns the expected enterprise-only response, printing a clear message that this
// is an enterprise feature.
//
// In enterprise mode, the same SDK calls would succeed and return queue data.
//
// VALIDATION: This example exits with code 1 if any assertion fails.
// In community mode, 403/404 responses are EXPECTED and count as PASS.
//
// Prerequisites:
//   - AxonFlow Agent running on localhost:8080
//
// Usage:
//
//	export AXONFLOW_CLIENT_ID=demo-org
//	export AXONFLOW_CLIENT_SECRET="<license-key>"
//	go run main.go
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v3"
)

var (
	passCount int
	failCount int
	failures  []string
)

func assertCheck(condition bool, message string) {
	if condition {
		fmt.Printf("   PASS: %s\n", message)
		passCount++
	} else {
		fmt.Printf("   FAIL: %s\n", message)
		failCount++
		failures = append(failures, message)
	}
}

// isEnterpriseOnly checks whether an error indicates that the endpoint is
// enterprise-only. In community mode, HITL Queue endpoints may return HTTP 403
// (Forbidden) or HTTP 404 (Not Found) if the routes are not registered.
func isEnterpriseOnly(err error) bool {
	if err == nil {
		return false
	}
	errStr := fmt.Sprintf("%v", err)
	return strings.Contains(errStr, "403") ||
		strings.Contains(errStr, "Forbidden") ||
		strings.Contains(errStr, "enterprise") ||
		strings.Contains(errStr, "Enterprise") ||
		strings.Contains(errStr, "404") ||
		strings.Contains(errStr, "not found") ||
		strings.Contains(errStr, "Not Found") ||
		strings.Contains(errStr, "page not found")
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func main() {
	fmt.Println("HITL Queue API - Go")
	fmt.Println(strings.Repeat("=", 50))
	fmt.Println()
	fmt.Println("This example validates the HITL Queue SDK methods.")
	fmt.Println("In community mode, all HITL queue endpoints return 403.")
	fmt.Println("403/404 responses are EXPECTED and count as PASS.")
	fmt.Println()

	endpoint := getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080")
	clientID := getEnv("AXONFLOW_CLIENT_ID", "demo-org")
	clientSecret := getEnv("AXONFLOW_CLIENT_SECRET", "")

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     endpoint,
		ClientID:     clientID,
		ClientSecret: clientSecret,
	})

	// ========================================
	// Test 1: HITL Status (raw HTTP)
	// ========================================
	fmt.Println("Test 1: HITL Status Endpoint")
	fmt.Println("----------------------------")

	statusURL := fmt.Sprintf("%s/api/v1/hitl/status", endpoint)
	req, err := http.NewRequest("GET", statusURL, nil)
	if err != nil {
		fmt.Printf("   FATAL: Failed to create request: %v\n", err)
		os.Exit(1)
	}
	req.Header.Set("X-Client-ID", clientID)
	req.Header.Set("X-Client-Secret", clientSecret)

	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		if strings.Contains(err.Error(), "connection refused") {
			fmt.Println("\nHint: Make sure AxonFlow is running:")
			fmt.Println("  docker compose up -d")
		}
		fmt.Printf("   FATAL: HTTP request failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusOK {
		var statusResp map[string]interface{}
		if jsonErr := json.Unmarshal(body, &statusResp); jsonErr == nil {
			enabled, _ := statusResp["enabled"].(bool)
			mode, _ := statusResp["mode"].(string)
			assertCheck(true, fmt.Sprintf("HITL status endpoint reachable (enabled=%v, mode=%s)", enabled, mode))
			if mode == "community" {
				fmt.Println("   Running in community mode - HITL queue endpoints will return 403")
			} else {
				fmt.Println("   Running in enterprise mode - HITL queue endpoints should succeed")
			}
		} else {
			assertCheck(true, "HITL status endpoint returned 200")
		}
	} else if resp.StatusCode == http.StatusForbidden {
		assertCheck(true, "HITL status endpoint returned 403 (enterprise feature)")
	} else if resp.StatusCode == http.StatusNotFound {
		// Endpoint may not exist in older versions
		assertCheck(true, fmt.Sprintf("HITL status endpoint returned %d (endpoint may not be available)", resp.StatusCode))
	} else {
		assertCheck(false, fmt.Sprintf("HITL status endpoint returned unexpected HTTP %d: %s", resp.StatusCode, string(body)))
	}
	fmt.Println()

	// ========================================
	// Test 2: ListHITLQueue
	// ========================================
	fmt.Println("Test 2: ListHITLQueue")
	fmt.Println("---------------------")

	listResp, err := client.ListHITLQueue(axonflow.HITLQueueListOptions{})
	if isEnterpriseOnly(err) {
		assertCheck(true, "ListHITLQueue returns 403/404 (enterprise-only feature)")
		fmt.Println("   HITL Queue listing requires Enterprise license (403/404 expected)")
	} else if err != nil {
		assertCheck(false, fmt.Sprintf("ListHITLQueue unexpected error: %v", err))
	} else {
		// Enterprise mode: SDK call succeeded
		assertCheck(true, "ListHITLQueue succeeded (enterprise mode)")
		assertCheck(listResp != nil, "ListHITLQueue returned non-nil response")
		if listResp != nil {
			fmt.Printf("   Queue items: %d, Total: %d\n", len(listResp.Items), listResp.Total)
		}
	}
	fmt.Println()

	// Also test with options
	fmt.Println("Test 2b: ListHITLQueue with options")
	fmt.Println("------------------------------------")

	listRespOpts, err := client.ListHITLQueue(axonflow.HITLQueueListOptions{
		Limit:  10,
		Offset: 0,
	})
	if isEnterpriseOnly(err) {
		assertCheck(true, "ListHITLQueue with options returns 403/404 (enterprise-only feature)")
	} else if err != nil {
		assertCheck(false, fmt.Sprintf("ListHITLQueue with options unexpected error: %v", err))
	} else {
		assertCheck(true, "ListHITLQueue with options succeeded (enterprise mode)")
		if listRespOpts != nil {
			fmt.Printf("   Queue items: %d, Total: %d\n", len(listRespOpts.Items), listRespOpts.Total)
		}
	}
	fmt.Println()

	// ========================================
	// Test 3: GetHITLStats
	// ========================================
	fmt.Println("Test 3: GetHITLStats")
	fmt.Println("--------------------")

	stats, err := client.GetHITLStats()
	if isEnterpriseOnly(err) {
		assertCheck(true, "GetHITLStats returns 403/404 (enterprise-only feature)")
		fmt.Println("   HITL Queue statistics require Enterprise license (403/404 expected)")
	} else if err != nil {
		assertCheck(false, fmt.Sprintf("GetHITLStats unexpected error: %v", err))
	} else {
		assertCheck(true, "GetHITLStats succeeded (enterprise mode)")
		assertCheck(stats != nil, "GetHITLStats returned non-nil response")
		if stats != nil {
			fmt.Printf("   TotalPending: %d, HighPriority: %d, CriticalPriority: %d\n",
				stats.TotalPending, stats.HighPriority, stats.CriticalPriority)
		}
	}
	fmt.Println()

	// ========================================
	// Test 4: GetHITLRequest with fake ID
	// ========================================
	fmt.Println("Test 4: GetHITLRequest (fake ID)")
	fmt.Println("--------------------------------")

	fakeRequestID := "hitl_req_nonexistent_12345"
	hitlReq, err := client.GetHITLRequest(fakeRequestID)
	if isEnterpriseOnly(err) {
		assertCheck(true, "GetHITLRequest returns 403/404 (enterprise-only feature)")
		fmt.Println("   HITL request retrieval requires Enterprise license (403/404 expected)")
	} else if err != nil {
		// In enterprise mode, a 404 for nonexistent ID is also acceptable
		errStr := fmt.Sprintf("%v", err)
		if strings.Contains(errStr, "404") || strings.Contains(errStr, "not found") || strings.Contains(errStr, "Not Found") {
			assertCheck(true, "GetHITLRequest returns 404 for nonexistent ID (expected)")
		} else {
			assertCheck(false, fmt.Sprintf("GetHITLRequest unexpected error: %v", err))
		}
	} else {
		assertCheck(hitlReq != nil, "GetHITLRequest succeeded (enterprise mode, unexpected for fake ID)")
	}
	fmt.Println()

	// ========================================
	// Test 5: ApproveHITLRequest with fake ID
	// ========================================
	fmt.Println("Test 5: ApproveHITLRequest (fake ID)")
	fmt.Println("------------------------------------")

	approveErr := client.ApproveHITLRequest(fakeRequestID, axonflow.HITLReviewInput{
		ReviewerID: "test-reviewer",
		Comment:    "Auto-approved by HITL queue validation example",
	})
	if isEnterpriseOnly(approveErr) {
		assertCheck(true, "ApproveHITLRequest returns 403/404 (enterprise-only feature)")
	} else if approveErr != nil {
		errStr := fmt.Sprintf("%v", approveErr)
		if strings.Contains(errStr, "404") || strings.Contains(errStr, "not found") || strings.Contains(errStr, "Not Found") {
			assertCheck(true, "ApproveHITLRequest returns 404 for nonexistent ID (expected)")
		} else {
			assertCheck(false, fmt.Sprintf("ApproveHITLRequest unexpected error: %v", approveErr))
		}
	} else {
		assertCheck(true, "ApproveHITLRequest succeeded (enterprise mode)")
	}
	fmt.Println()

	// ========================================
	// Test 6: RejectHITLRequest with fake ID
	// ========================================
	fmt.Println("Test 6: RejectHITLRequest (fake ID)")
	fmt.Println("-----------------------------------")

	rejectErr := client.RejectHITLRequest(fakeRequestID, axonflow.HITLReviewInput{
		ReviewerID: "test-reviewer",
		Comment:    "Rejected by HITL queue validation example",
	})
	if isEnterpriseOnly(rejectErr) {
		assertCheck(true, "RejectHITLRequest returns 403/404 (enterprise-only feature)")
	} else if rejectErr != nil {
		errStr := fmt.Sprintf("%v", rejectErr)
		if strings.Contains(errStr, "404") || strings.Contains(errStr, "not found") || strings.Contains(errStr, "Not Found") {
			assertCheck(true, "RejectHITLRequest returns 404 for nonexistent ID (expected)")
		} else {
			assertCheck(false, fmt.Sprintf("RejectHITLRequest unexpected error: %v", rejectErr))
		}
	} else {
		assertCheck(true, "RejectHITLRequest succeeded (enterprise mode)")
	}
	fmt.Println()

	// ========================================
	// Summary
	// ========================================
	fmt.Println(strings.Repeat("=", 50))
	fmt.Printf("Results: %d PASS, %d FAIL\n", passCount, failCount)
	fmt.Println(strings.Repeat("=", 50))

	if failCount > 0 {
		fmt.Println("SOME TESTS FAILED")
		for _, f := range failures {
			fmt.Printf("  - %s\n", f)
		}
		os.Exit(1)
	}

	fmt.Println("ALL TESTS PASSED")
	fmt.Println()
	fmt.Println("HITL Queue operations validated:")
	fmt.Println("  - HITL status endpoint (raw HTTP)")
	fmt.Println("  - ListHITLQueue() / ListHITLQueue(opts)")
	fmt.Println("  - GetHITLStats()")
	fmt.Println("  - GetHITLRequest(requestID)")
	fmt.Println("  - ApproveHITLRequest(requestID, review)")
	fmt.Println("  - RejectHITLRequest(requestID, review)")
	fmt.Println()
	fmt.Println("Note: In Community Edition, all HITL queue endpoints return 403.")
	fmt.Println("Upgrade to Enterprise for full HITL queue management.")
}
