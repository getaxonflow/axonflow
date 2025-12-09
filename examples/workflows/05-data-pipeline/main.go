package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/getaxonflow/axonflow-sdk-go"
)

func main() {
	// Get AxonFlow agent URL from environment
	agentURL := os.Getenv("AXONFLOW_AGENT_URL")
	if agentURL == "" {
		agentURL = "http://localhost:8080"
	}

	licenseKey := os.Getenv("AXONFLOW_LICENSE_KEY")
	if licenseKey == "" {
		log.Fatal("❌ AXONFLOW_LICENSE_KEY must be set in .env file")
	}

	// Create AxonFlow client
	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		AgentURL:   agentURL,
		LicenseKey: licenseKey,
	})

	fmt.Println("✅ Connected to AxonFlow")
	fmt.Println("🔄 Starting 5-stage data pipeline for customer analytics...")
	fmt.Println()

	startTime := time.Now()

	// Stage 1: Extract
	fmt.Println("📥 Stage 1/5: Extracting customer transaction data...")
	extractQuery := "Extract customer purchase data from the last 30 days. " +
		"Include customer ID, purchase amount, product categories, and timestamps. " +
		"Simulate 500 customer transactions."

	_, err := client.ExecuteQuery("user-123", extractQuery, "chat", map[string]interface{}{"model": "gpt-4"})
	if err != nil {
		log.Fatalf("❌ Stage 1 failed: %v", err)
	}
	fmt.Println("✅ Stage 1 complete: Data extracted")
	fmt.Println()

	// Stage 2: Transform (Clean & Normalize)
	fmt.Println("🧹 Stage 2/5: Cleaning and normalizing data...")
	transformQuery := "From the extracted data above, perform the following transformations:\n" +
		"1. Remove duplicate transactions\n" +
		"2. Standardize date formats to ISO 8601\n" +
		"3. Normalize product category names\n" +
		"4. Validate all amounts are positive numbers\n" +
		"5. Flag any anomalies (unusually high amounts)"

	_, err = client.ExecuteQuery("user-123", transformQuery, "chat", map[string]interface{}{"model": "gpt-4"})
	if err != nil {
		log.Fatalf("❌ Stage 2 failed: %v", err)
	}
	fmt.Println("✅ Stage 2 complete: Data cleaned and normalized")
	fmt.Println()

	// Stage 3: Enrich
	fmt.Println("💎 Stage 3/5: Enriching with customer segments and lifetime value...")
	enrichQuery := "Based on the cleaned transaction data:\n" +
		"1. Calculate customer lifetime value (CLV)\n" +
		"2. Segment customers into: VIP (CLV > $5000), Regular ($1000-$5000), New (< $1000)\n" +
		"3. Identify top-spending product categories per segment\n" +
		"4. Calculate average order value per segment"

	_, err = client.ExecuteQuery("user-123", enrichQuery, "chat", map[string]interface{}{"model": "gpt-4"})
	if err != nil {
		log.Fatalf("❌ Stage 3 failed: %v", err)
	}
	fmt.Println("✅ Stage 3 complete: Data enriched with segments and metrics")
	fmt.Println()

	// Stage 4: Aggregate
	fmt.Println("📊 Stage 4/5: Aggregating insights and trends...")
	aggregateQuery := "Generate aggregated insights:\n" +
		"1. Total revenue by customer segment\n" +
		"2. Growth trends (week-over-week)\n" +
		"3. Top 5 products by revenue\n" +
		"4. Customer churn risk indicators\n" +
		"5. Recommended actions for each segment"

	_, err = client.ExecuteQuery("user-123", aggregateQuery, "chat", map[string]interface{}{"model": "gpt-4"})
	if err != nil {
		log.Fatalf("❌ Stage 4 failed: %v", err)
	}
	fmt.Println("✅ Stage 4 complete: Insights aggregated")
	fmt.Println()

	// Stage 5: Report
	fmt.Println("📈 Stage 5/5: Generating executive summary report...")
	reportQuery := "Create an executive summary report with:\n" +
		"1. Key metrics (total revenue, customer count, avg order value)\n" +
		"2. Segment analysis\n" +
		"3. Top actionable recommendations\n" +
		"4. Risk alerts (if any)\n" +
		"Format as a concise business report."

	reportResp, err := client.ExecuteQuery("user-123", reportQuery, "chat", map[string]interface{}{"model": "gpt-4"})
	if err != nil {
		log.Fatalf("❌ Stage 5 failed: %v", err)
	}

	duration := time.Since(startTime)

	// Display final report
	fmt.Println()
	fmt.Println("=" + "=")
	fmt.Println("📊 CUSTOMER ANALYTICS REPORT")
	fmt.Println("=" + "=")
	fmt.Println(reportResp.Data)
	fmt.Println()
	fmt.Println("=" + "=")
	fmt.Println()
	fmt.Printf("⏱️  Pipeline completed in %.1f seconds\n", duration.Seconds())
	fmt.Println("✅ All 5 stages executed successfully")
	fmt.Println("💡 Data pipeline: Extract → Clean → Enrich → Aggregate → Report")
}
