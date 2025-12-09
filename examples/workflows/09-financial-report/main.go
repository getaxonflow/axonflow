package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/getaxonflow/axonflow-sdk-go"
)

func main() {
	agentURL := os.Getenv("AXONFLOW_AGENT_URL")
	if agentURL == "" {
		agentURL = "http://localhost:8080"
	}

	licenseKey := os.Getenv("AXONFLOW_LICENSE_KEY")
	if licenseKey == "" {
		log.Fatal("❌ AXONFLOW_LICENSE_KEY must be set in .env file")
	}

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		AgentURL:   agentURL,
		LicenseKey: licenseKey,
	})

	fmt.Println("✅ Connected to AxonFlow")
	fmt.Println("📊 Starting Q4 2024 financial report generation workflow...")
	fmt.Println()

	startTime := time.Now()

	// Step 1: Collect Revenue Data
	fmt.Println("💰 Step 1: Collecting revenue data from multiple sources...")
	revenueQuery := "Generate Q4 2024 revenue data summary:\n" +
		"- Product sales: $1.8M (breakdown by category: SaaS $1.2M, Services $400K, Hardware $200K)\n" +
		"- Customer count: 450 customers (300 SaaS, 100 services, 50 hardware)\n" +
		"- Average revenue per customer: Calculate ARPC\n" +
		"- Top 5 customers by revenue\n" +
		"- Revenue by month: Oct, Nov, Dec"

	revenueResp, err := client.ExecuteQuery("user-123", revenueQuery, "chat", map[string]interface{}{"model": "gpt-4"})
	if err != nil {
		log.Fatalf("❌ Revenue collection failed: %v", err)
	}
	fmt.Println("✅ Revenue data collected")
	fmt.Println()

	// Step 2: Collect Expense Data
	fmt.Println("💸 Step 2: Collecting expense data...")
	expenseQuery := "Generate Q4 2024 expense breakdown:\n" +
		"- Personnel: $800K (salaries, benefits)\n" +
		"- Infrastructure: $300K (AWS, servers, tools)\n" +
		"- Marketing: $200K (ads, events, content)\n" +
		"- Operations: $150K (rent, utilities, misc)\n" +
		"- R&D: $250K (development, testing)\n" +
		"Total expenses and percentage breakdown"

	expenseResp, err := client.ExecuteQuery("user-123", expenseQuery, "chat", map[string]interface{}{"model": "gpt-4"})
	if err != nil {
		log.Fatalf("❌ Expense collection failed: %v", err)
	}
	fmt.Println("✅ Expense data collected")
	fmt.Println()

	// Step 3: Calculate Key Metrics
	fmt.Println("📈 Step 3: Calculating key financial metrics...")
	metricsQuery := "Based on Q4 2024 data (Revenue: $1.8M, Expenses: $1.7M):\n" +
		"Calculate:\n" +
		"1. Gross Profit and Profit Margin %\n" +
		"2. Burn Rate (monthly)\n" +
		"3. Runway (months remaining with current cash $3M)\n" +
		"4. Customer Acquisition Cost (CAC) - $200K marketing / new customers\n" +
		"5. Customer Lifetime Value (LTV) estimate\n" +
		"6. LTV:CAC Ratio"

	metricsResp, err := client.ExecuteQuery("user-123", metricsQuery, "chat", map[string]interface{}{"model": "gpt-4"})
	if err != nil {
		log.Fatalf("❌ Metrics calculation failed: %v", err)
	}
	fmt.Println("✅ Key metrics calculated")
	fmt.Println()

	// Step 4: Trend Analysis
	fmt.Println("📊 Step 4: Analyzing trends and growth...")
	trendsQuery := "Compare Q4 2024 ($1.8M revenue) with:\n" +
		"- Q3 2024: $1.6M revenue\n" +
		"- Q4 2023: $1.4M revenue\n" +
		"Calculate:\n" +
		"1. Quarter-over-Quarter (QoQ) growth %\n" +
		"2. Year-over-Year (YoY) growth %\n" +
		"3. Revenue growth trajectory\n" +
		"4. Identify growth drivers\n" +
		"5. Risk factors or concerns"

	trendsResp, err := client.ExecuteQuery("user-123", trendsQuery, "chat", map[string]interface{}{"model": "gpt-4"})
	if err != nil {
		log.Fatalf("❌ Trend analysis failed: %v", err)
	}
	fmt.Println("✅ Trends analyzed")
	fmt.Println()

	// Step 5: Generate Executive Summary
	fmt.Println("📋 Step 5: Generating executive summary report...")
	reportQuery := "Create executive summary for Q4 2024 financial report:\n" +
		"- Key highlights (revenue, profit, growth)\n" +
		"- Financial health assessment\n" +
		"- Top 3 achievements\n" +
		"- Top 3 concerns\n" +
		"- Strategic recommendations for Q1 2025\n" +
		"Format as professional executive summary (2-3 paragraphs max)"

	reportResp, err := client.ExecuteQuery("user-123", reportQuery, "chat", map[string]interface{}{"model": "gpt-4"})
	if err != nil {
		log.Fatalf("❌ Report generation failed: %v", err)
	}

	duration := time.Since(startTime)

	// Display Final Report
	fmt.Println()
	fmt.Println("=" + "=")
	fmt.Println("💼 Q4 2024 FINANCIAL REPORT")
	fmt.Println("=" + "=")
	fmt.Println()
	fmt.Println("📊 EXECUTIVE SUMMARY")
	fmt.Println(reportResp.Data)
	fmt.Println()
	fmt.Println("📈 KEY METRICS")
	fmt.Println(metricsResp.Data)
	fmt.Println()
	fmt.Println("📉 TREND ANALYSIS")
	fmt.Println(trendsResp.Data)
	fmt.Println()
	fmt.Println("=" + "=")
	fmt.Println()
	fmt.Printf("⏱️  Report generated in %.1f seconds\n", duration.Seconds())
	fmt.Println("✅ Financial reporting workflow completed")
	fmt.Println("💡 Workflow: Revenue → Expenses → Metrics → Trends → Report")
}
