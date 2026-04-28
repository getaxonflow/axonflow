// Data Pipeline Workflow Example
//
// VALIDATION: This example exits with code 1 if any assertion fails.
//
// Demonstrates a 5-stage ETL pipeline: Extract, Transform, Enrich, Aggregate, Report.
package main

import (
	"fmt"
	"os"
	"time"

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

func main() {
	fmt.Println("Data Pipeline Workflow - Go")
	fmt.Println("============================")
	fmt.Println()

	// Create AxonFlow client (no auth required for community mode)
	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint: getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
	})

	// Test 1: Health check
	fmt.Println("Test 1: Health Check")
	fmt.Println("--------------------")
	err := client.HealthCheck()
	assertCheck(err == nil, "Agent is healthy")
	if err != nil {
		fmt.Printf("   Error: %v\n", err)
	}
	fmt.Println()

	fmt.Println("Starting 5-stage data pipeline for customer analytics...")
	fmt.Println()

	startTime := time.Now()
	stagesCompleted := 0

	// Stage 1: Extract
	fmt.Println("Test 2: Stage 1/5 - Extract")
	fmt.Println("---------------------------")
	extractQuery := "Extract customer purchase data from the last 30 days. " +
		"Include customer ID, purchase amount, product categories, and timestamps. " +
		"Simulate 500 customer transactions."
	fmt.Printf("   Query: %s\n", truncate(extractQuery, 70))

	extractResp, err := client.ProxyLLMCall(getEnv("AXONFLOW_USER_TOKEN", "user-123"), extractQuery, "chat", map[string]interface{}{"provider": "openai"})
	assertCheck(err == nil, "Stage 1 (Extract) does not return error")
	if err == nil {
		assertCheck(extractResp.Success, "Stage 1 (Extract) is successful")
		stagesCompleted++
		fmt.Println("   Status: Data extracted")
	}
	fmt.Println()

	// Stage 2: Transform (Clean & Normalize)
	fmt.Println("Test 3: Stage 2/5 - Transform")
	fmt.Println("-----------------------------")
	transformQuery := "From the extracted data above, perform the following transformations:\n" +
		"1. Remove duplicate transactions\n" +
		"2. Standardize date formats to ISO 8601\n" +
		"3. Normalize product category names\n" +
		"4. Validate all amounts are positive numbers\n" +
		"5. Flag any anomalies (unusually high amounts)"
	fmt.Printf("   Query: %s\n", truncate(transformQuery, 70))

	transformResp, err := client.ProxyLLMCall(getEnv("AXONFLOW_USER_TOKEN", "user-123"), transformQuery, "chat", map[string]interface{}{"provider": "openai"})
	assertCheck(err == nil, "Stage 2 (Transform) does not return error")
	if err == nil {
		assertCheck(transformResp.Success, "Stage 2 (Transform) is successful")
		stagesCompleted++
		fmt.Println("   Status: Data cleaned and normalized")
	}
	fmt.Println()

	// Stage 3: Enrich
	fmt.Println("Test 4: Stage 3/5 - Enrich")
	fmt.Println("--------------------------")
	enrichQuery := "Based on the cleaned transaction data:\n" +
		"1. Calculate customer lifetime value (CLV)\n" +
		"2. Segment customers into: VIP (CLV > $5000), Regular ($1000-$5000), New (< $1000)\n" +
		"3. Identify top-spending product categories per segment\n" +
		"4. Calculate average order value per segment"
	fmt.Printf("   Query: %s\n", truncate(enrichQuery, 70))

	enrichResp, err := client.ProxyLLMCall(getEnv("AXONFLOW_USER_TOKEN", "user-123"), enrichQuery, "chat", map[string]interface{}{"provider": "openai"})
	assertCheck(err == nil, "Stage 3 (Enrich) does not return error")
	if err == nil {
		assertCheck(enrichResp.Success, "Stage 3 (Enrich) is successful")
		stagesCompleted++
		fmt.Println("   Status: Data enriched with segments and metrics")
	}
	fmt.Println()

	// Stage 4: Aggregate
	fmt.Println("Test 5: Stage 4/5 - Aggregate")
	fmt.Println("-----------------------------")
	aggregateQuery := "Generate aggregated insights:\n" +
		"1. Total revenue by customer segment\n" +
		"2. Growth trends (week-over-week)\n" +
		"3. Top 5 products by revenue\n" +
		"4. Customer churn risk indicators\n" +
		"5. Recommended actions for each segment"
	fmt.Printf("   Query: %s\n", truncate(aggregateQuery, 70))

	aggregateResp, err := client.ProxyLLMCall(getEnv("AXONFLOW_USER_TOKEN", "user-123"), aggregateQuery, "chat", map[string]interface{}{"provider": "openai"})
	assertCheck(err == nil, "Stage 4 (Aggregate) does not return error")
	if err == nil {
		assertCheck(aggregateResp.Success, "Stage 4 (Aggregate) is successful")
		stagesCompleted++
		fmt.Println("   Status: Insights aggregated")
	}
	fmt.Println()

	// Stage 5: Report
	fmt.Println("Test 6: Stage 5/5 - Report")
	fmt.Println("--------------------------")
	reportQuery := "Create an executive summary report with:\n" +
		"1. Key metrics (total revenue, customer count, avg order value)\n" +
		"2. Segment analysis\n" +
		"3. Top actionable recommendations\n" +
		"4. Risk alerts (if any)\n" +
		"Format as a concise business report."
	fmt.Printf("   Query: %s\n", truncate(reportQuery, 70))

	reportResp, err := client.ProxyLLMCall(getEnv("AXONFLOW_USER_TOKEN", "user-123"), reportQuery, "chat", map[string]interface{}{"provider": "openai"})
	assertCheck(err == nil, "Stage 5 (Report) does not return error")
	if err == nil {
		assertCheck(reportResp.Success, "Stage 5 (Report) is successful")
		assertCheck(reportResp.Data != nil, "Report has data")
		stagesCompleted++
		fmt.Printf("   Response: %v\n", truncate(fmt.Sprintf("%v", reportResp.Data), 100))
	}
	fmt.Println()

	duration := time.Since(startTime)

	// Verify all stages completed
	assertCheck(stagesCompleted == 5, fmt.Sprintf("All 5 stages completed (got %d)", stagesCompleted))

	// Summary
	fmt.Println("============================")
	fmt.Printf("Pipeline completed in %.1f seconds\n", duration.Seconds())
	if len(failures) == 0 {
		fmt.Println("✓ ALL TESTS PASSED")
		fmt.Println("Tip: Data pipeline: Extract -> Clean -> Enrich -> Aggregate -> Report")
		os.Exit(0)
	} else {
		fmt.Printf("❌ %d TEST(S) FAILED:\n", len(failures))
		for _, f := range failures {
			fmt.Printf("   - %s\n", f)
		}
		os.Exit(1)
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func truncate(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}
