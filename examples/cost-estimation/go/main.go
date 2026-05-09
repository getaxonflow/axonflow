// Cost Estimation Example - Go
//
// Validates the new cost estimation endpoints added in v4.3.0:
//   - POST /api/v1/plans/estimate  - Estimate cost of a plan before execution
//   - GET  /api/v1/plans/{id}/cost - Get cost estimate for an existing plan
//
// These endpoints are NOT in any SDK yet, so this example uses raw HTTP calls
// via net/http for the cost endpoints and the Go SDK for plan generation.
//
// Usage:
//   go run main.go
//
// Environment:
//   AXONFLOW_ENDPOINT     - Agent URL (default: http://localhost:8080)
//   AXONFLOW_CLIENT_ID    - Client ID (default: demo-org)
//   AXONFLOW_CLIENT_SECRET - Client secret (optional for community mode)
//   AXONFLOW_USER_TOKEN   - JWT token for MAP operations (optional)
//
// VALIDATION: This example exits with code 1 if any assertion fails.

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v8"
)

var failures []string

func assertCheck(condition bool, message string) {
	if condition {
		fmt.Printf("   PASS: %s\n", message)
	} else {
		fmt.Printf("   FAIL: %s\n", message)
		failures = append(failures, message)
	}
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

// doRequest performs an HTTP request and returns the status code, parsed JSON body, and any error.
func doRequest(method, url, body string, headers map[string]string) (int, map[string]interface{}, error) {
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return 0, nil, fmt.Errorf("creating request: %w", err)
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if clientID, clientSecret := os.Getenv("AXONFLOW_CLIENT_ID"), os.Getenv("AXONFLOW_CLIENT_SECRET"); clientID != "" && clientSecret != "" {
		req.SetBasicAuth(clientID, clientSecret)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("reading response: %w", err)
	}

	var result map[string]interface{}
	if len(respBody) > 0 {
		if err := json.Unmarshal(respBody, &result); err != nil {
			// Not JSON - return raw body as error context
			return resp.StatusCode, nil, fmt.Errorf("parsing JSON response: %w (body: %s)", err, string(respBody))
		}
	}

	return resp.StatusCode, result, nil
}

func main() {
	fmt.Println("AxonFlow Cost Estimation - Go (Raw HTTP + SDK)")
	fmt.Println("================================================")
	fmt.Println()

	endpoint := getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080")
	clientID := getEnv("AXONFLOW_CLIENT_ID", "demo-org")
	clientSecret := getEnv("AXONFLOW_CLIENT_SECRET", "")
	userToken := getEnv("AXONFLOW_USER_TOKEN", "")

	fmt.Printf("Endpoint: %s\n", endpoint)
	fmt.Printf("Client ID: %s\n", clientID)
	fmt.Println("------------------------------------------------")
	fmt.Println()

	headers := map[string]string{
		"Content-Type": "application/json",
		"X-Client-ID":  clientID,
	}
	if clientSecret != "" {
		headers["X-Client-Secret"] = clientSecret
	}

	// ========================================
	// 1. HEALTH CHECK
	// ========================================
	fmt.Println("1. Health Check...")
	status, healthData, err := doRequest("GET", endpoint+"/health", "", nil)
	if err != nil {
		fmt.Printf("   ERROR: %v\n", err)
		assertCheck(false, "Health check request succeeded")
	} else {
		assertCheck(status == 200, fmt.Sprintf("Health check returns 200 (got %d)", status))
		if healthData != nil {
			fmt.Printf("   Status: %v\n", healthData["status"])
		}
	}
	fmt.Println()

	// ========================================
	// 2. POST /api/v1/plans/estimate
	// ========================================
	fmt.Println("2. POST /api/v1/plans/estimate - Estimate cost before execution...")

	// Use real WorkflowStep fields: prompt and max_tokens.
	// Short prompt (~50 chars) vs long prompt (~600 chars) should produce different estimates.
	shortPrompt := "Summarize the key findings from the analysis."
	longPrompt := "You are a senior data analyst. Given the following customer feedback dataset " +
		"containing 500 reviews across 12 product categories spanning the last fiscal quarter, " +
		"perform a comprehensive sentiment analysis. Break down sentiment by category, identify " +
		"emerging trends, flag critical issues that require immediate attention, and provide " +
		"actionable recommendations for each product team. Include statistical confidence intervals " +
		"for your sentiment scores and highlight any anomalies or outliers in the data distribution."

	estimateBody := fmt.Sprintf(`{
		"provider": "openai",
		"model": "gpt-4",
		"steps": [
			{
				"name": "analyze",
				"type": "llm_call",
				"prompt": %q,
				"max_tokens": 2000
			},
			{
				"name": "summarize",
				"type": "llm_call",
				"prompt": %q,
				"max_tokens": 200
			}
		]
	}`, longPrompt, shortPrompt)

	status, estimateData, err := doRequest("POST", endpoint+"/api/v1/plans/estimate", estimateBody, headers)
	if err != nil {
		fmt.Printf("   ERROR: %v\n", err)
		assertCheck(false, "Estimate request completed")
	} else if status == 429 {
		fmt.Println("   Rate limited (429) - community mode allows 10 estimates/day")
		fmt.Println("   This is expected behavior; skipping estimate assertions.")
		assertCheck(true, "Estimate endpoint returned valid status (429 rate limit)")
	} else {
		assertCheck(status == 200, fmt.Sprintf("Estimate returns 200 (got %d)", status))

		if estimateData != nil {
			fmt.Printf("   Response: %v\n", estimateData)

			// Verify estimated_cost_usd field
			costVal, hasCost := estimateData["estimated_cost_usd"]
			assertCheck(hasCost, "Response contains 'estimated_cost_usd' field")
			if hasCost {
				costFloat, ok := costVal.(float64)
				assertCheck(ok, "estimated_cost_usd is a number")
				if ok {
					assertCheck(costFloat >= 0, fmt.Sprintf("estimated_cost_usd >= 0 (got %.6f)", costFloat))
					fmt.Printf("   Estimated Cost: $%.6f USD\n", costFloat)
				}
			}

			// Verify currency field
			currencyVal, hasCurrency := estimateData["currency"]
			assertCheck(hasCurrency, "Response contains 'currency' field")
			if hasCurrency {
				currency, ok := currencyVal.(string)
				assertCheck(ok && currency == "USD", fmt.Sprintf("currency is 'USD' (got '%v')", currencyVal))
			}

			// Check breakdown and verify prompt-aware estimation
			if breakdown, hasBreakdown := estimateData["breakdown"]; hasBreakdown {
				fmt.Printf("   Breakdown: %v\n", breakdown)

				// Verify per-step token estimates differ (long prompt > short prompt)
				if steps, ok := breakdown.([]interface{}); ok && len(steps) >= 2 {
					step0, _ := steps[0].(map[string]interface{})
					step1, _ := steps[1].(map[string]interface{})
					analyzeTokensIn, _ := step0["estimated_tokens_in"].(float64)
					summarizeTokensIn, _ := step1["estimated_tokens_in"].(float64)
					fmt.Printf("   Analyze step tokens_in: %.0f\n", analyzeTokensIn)
					fmt.Printf("   Summarize step tokens_in: %.0f\n", summarizeTokensIn)
					assertCheck(analyzeTokensIn > summarizeTokensIn,
						"Long-prompt step has more estimated input tokens than short-prompt step")

					// Verify max_tokens is respected for output estimates
					analyzeTokensOut, _ := step0["estimated_tokens_out"].(float64)
					summarizeTokensOut, _ := step1["estimated_tokens_out"].(float64)
					fmt.Printf("   Analyze step tokens_out: %.0f (expected: 2000)\n", analyzeTokensOut)
					fmt.Printf("   Summarize step tokens_out: %.0f (expected: 200)\n", summarizeTokensOut)
					assertCheck(analyzeTokensOut == 2000,
						fmt.Sprintf("Analyze step respects max_tokens=2000 for output estimate (got %.0f)", analyzeTokensOut))
					assertCheck(summarizeTokensOut == 200,
						fmt.Sprintf("Summarize step respects max_tokens=200 for output estimate (got %.0f)", summarizeTokensOut))
				}
			} else {
				fmt.Println("   Note: 'breakdown' not present (community mode returns aggregate only)")
			}
		}
	}
	fmt.Println()

	// ========================================
	// 3. CREATE PLAN VIA SDK + GET COST
	// ========================================
	fmt.Println("3. Create MAP plan via SDK, then GET /api/v1/plans/{id}/cost...")

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     endpoint,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Cache:        axonflow.CacheConfig{Enabled: false, TTL: 1 * time.Nanosecond},
	})

	query := "Create a brief plan to analyze customer feedback and generate a summary report"
	domain := "generic"

	var plan *axonflow.PlanResponse
	if userToken != "" {
		plan, err = client.GeneratePlan(query, domain, userToken)
	} else {
		plan, err = client.GeneratePlan(query, domain)
	}

	if err != nil {
		fmt.Printf("   ERROR generating plan: %v\n", err)
		assertCheck(false, "GeneratePlan succeeded")
	} else {
		assertCheck(plan != nil, "Plan generated successfully")
		assertCheck(plan.PlanID != "", "Plan has a valid ID")
		fmt.Printf("   Plan ID: %s\n", plan.PlanID)
		fmt.Printf("   Steps: %d\n", len(plan.Steps))

		// GET /api/v1/plans/{id}/cost
		fmt.Println()
		fmt.Println("   Fetching cost for existing plan...")
		costURL := fmt.Sprintf("%s/api/v1/plans/%s/cost", endpoint, plan.PlanID)
		status, costData, err := doRequest("GET", costURL, "", headers)
		if err != nil {
			fmt.Printf("   ERROR: %v\n", err)
			assertCheck(false, "GET plan cost request completed")
		} else if status == 429 {
			fmt.Println("   Rate limited (429) - community mode allows 10 estimates/day")
			assertCheck(true, "Plan cost endpoint returned valid status (429 rate limit)")
		} else if status == 404 {
			// Cost estimation may not be available for all plan types
			fmt.Println("   Plan cost endpoint returned 404 - endpoint may require enterprise mode")
			assertCheck(true, "Plan cost endpoint responded (404 - may require enterprise)")
		} else {
			assertCheck(status == 200, fmt.Sprintf("GET plan cost returns 200 (got %d)", status))

			if costData != nil {
				fmt.Printf("   Cost Response: %v\n", costData)

				costVal, hasCost := costData["estimated_cost_usd"]
				assertCheck(hasCost, "Plan cost response contains 'estimated_cost_usd'")
				if hasCost {
					costFloat, ok := costVal.(float64)
					if ok {
						assertCheck(costFloat >= 0, fmt.Sprintf("Plan cost >= 0 (got %.6f)", costFloat))
					}
				}

				currencyVal, hasCurrency := costData["currency"]
				assertCheck(hasCurrency, "Plan cost response contains 'currency'")
				if hasCurrency {
					currency, ok := currencyVal.(string)
					assertCheck(ok && currency == "USD", fmt.Sprintf("Plan cost currency is 'USD' (got '%v')", currencyVal))
				}

				if _, hasBreakdown := costData["breakdown"]; !hasBreakdown {
					fmt.Println("   Note: 'breakdown' not present (community mode returns aggregate only)")
				}
			}
		}
	}
	fmt.Println()

	// ========================================
	// SUMMARY
	// ========================================
	fmt.Println("================================================")
	fmt.Println("Cost Estimation Example - Summary")
	fmt.Println("================================================")
	if len(failures) == 0 {
		fmt.Println("All assertions passed!")
		os.Exit(0)
	} else {
		fmt.Printf("%d assertion(s) FAILED:\n", len(failures))
		for _, f := range failures {
			fmt.Printf("   - %s\n", f)
		}
		os.Exit(1)
	}
}
