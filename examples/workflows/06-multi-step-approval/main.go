package main

import (
	"fmt"
	"log"
	"os"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v2"
)

func main() {
	agentURL := os.Getenv("AXONFLOW_AGENT_URL")
	if agentURL == "" {
		agentURL = "http://localhost:8080"
	}

	clientID := os.Getenv("AXONFLOW_CLIENT_ID")
	clientSecret := os.Getenv("AXONFLOW_CLIENT_SECRET")
	if clientID == "" || clientSecret == "" {
		log.Fatal("AXONFLOW_CLIENT_ID and AXONFLOW_CLIENT_SECRET must be set")
	}

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     agentURL,
		ClientID:     clientID,
		ClientSecret: clientSecret,
	})

	fmt.Println("✅ Connected to AxonFlow")
	fmt.Println("🔐 Starting multi-step approval workflow for capital expenditure...")
	fmt.Println()

	// Purchase request details
	amount := 15000.00
	item := "10 Dell PowerEdge R750 servers for production deployment"

	// Step 1: Manager Approval
	fmt.Printf("📤 Step 1: Requesting Manager approval for $%.2f purchase...\n", amount)
	managerQuery := fmt.Sprintf("As a manager, would you approve a purchase request for $%.2f to buy: %s? "+
		"Consider budget, necessity, and timing. Respond with APPROVED or REJECTED and brief reasoning.",
		amount, item)

	managerResp, err := client.ProxyLLMCall("user-123", managerQuery, "chat", map[string]interface{}{"provider": "openai"})
	if err != nil {
		log.Fatalf("❌ Manager approval failed: %v", err)
	}

	fmt.Println("📥 Manager Response:", managerResp.Data)

	if !contains(fmt.Sprintf("%v", managerResp.Data), "APPROVED") {
		fmt.Println("❌ Purchase rejected at manager level")
		fmt.Println("Workflow terminated")
		return
	}

	fmt.Println("✅ Manager approval granted")
	fmt.Println()

	// Step 2: Director Approval (for amounts > $10K)
	if amount > 10000 {
		fmt.Println("📤 Step 2: Escalating to Director for amounts > $10,000...")
		directorQuery := fmt.Sprintf("As a Director, review this approved purchase: $%.2f for %s. "+
			"Manager approved with reasoning: '%s'. "+
			"Consider strategic alignment and ROI. Respond with APPROVED or REJECTED and reasoning.",
			amount, item, managerResp.Data)

		directorResp, err := client.ProxyLLMCall("user-123", directorQuery, "chat", map[string]interface{}{"provider": "openai"})
		if err != nil {
			log.Fatalf("❌ Director approval failed: %v", err)
		}

		fmt.Println("📥 Director Response:", directorResp.Data)

		if !contains(fmt.Sprintf("%v", directorResp.Data), "APPROVED") {
			fmt.Println("❌ Purchase rejected at director level")
			fmt.Println("Workflow terminated")
			return
		}

		fmt.Println("✅ Director approval granted")
		fmt.Println()
	} else {
		fmt.Println("ℹ️  Step 2: Director approval skipped (amount < $10,000)")
		fmt.Println()
	}

	// Step 3: Finance Approval (for amounts > $5K)
	if amount > 5000 {
		fmt.Println("📤 Step 3: Final Finance team compliance check...")
		financeQuery := fmt.Sprintf("As Finance team, perform final compliance check on approved purchase: "+
			"$%.2f for %s. Verify budget availability and compliance with procurement policies. "+
			"Respond with APPROVED or REJECTED and reasoning.",
			amount, item)

		financeResp, err := client.ProxyLLMCall("user-123", financeQuery, "chat", map[string]interface{}{"provider": "openai"})
		if err != nil {
			log.Fatalf("❌ Finance approval failed: %v", err)
		}

		fmt.Println("📥 Finance Response:", financeResp.Data)

		if !contains(fmt.Sprintf("%v", financeResp.Data), "APPROVED") {
			fmt.Println("❌ Purchase rejected at finance level")
			fmt.Println("Workflow terminated")
			return
		}

		fmt.Println("✅ Finance approval granted")
		fmt.Println()
	}

	// All approvals obtained
	fmt.Println("=" + "=")
	fmt.Println("🎉 Purchase Request FULLY APPROVED")
	fmt.Println("=" + "=")
	fmt.Printf("Amount: $%.2f\n", amount)
	fmt.Printf("Item: %s\n", item)
	fmt.Println("Approvals: Manager ✅ Director ✅ Finance ✅")
	fmt.Println()
	fmt.Println("✅ Workflow completed - Purchase can proceed")
	fmt.Println("💡 Multi-step approval: Manager → Director → Finance")
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) &&
		(findSubstring(s, substr) >= 0))
}

func findSubstring(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
