// AxonFlow Webhook Management Example - Go SDK
//
// This example demonstrates webhook subscription CRUD operations:
// 1. Create a webhook subscription
// 2. Get a webhook subscription
// 3. List all webhook subscriptions
// 4. Update a webhook subscription
// 5. Delete a webhook subscription
//
// Run with: go run main.go
// Prerequisites: docker compose up -d
package main

import (
	"fmt"
	"os"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v9"
)

var failures []string
var testsRun int

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func assert(condition bool, message string) {
	testsRun++
	if !condition {
		failures = append(failures, message)
		fmt.Printf("   FAIL: %s\n", message)
	} else {
		fmt.Printf("   PASS: %s\n", message)
	}
}

func main() {
	fmt.Println("AxonFlow Webhook Management - Go SDK")
	fmt.Println("=====================================")
	fmt.Println()

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     getEnv("AXONFLOW_ENDPOINT", getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080")),
		ClientID:     getEnv("AXONFLOW_CLIENT_ID", "demo-org"),
		ClientSecret: getEnv("AXONFLOW_CLIENT_SECRET", "demo"),
		Debug:        getEnv("AXONFLOW_DEBUG", "") == "true",
	})

	// ========================================
	// 1. CREATE WEBHOOK SUBSCRIPTION
	// ========================================
	fmt.Println("1. CreateWebhook - Create a new subscription...")

	webhook, err := client.CreateWebhook(axonflow.CreateWebhookRequest{
		URL:    "https://example.com/webhooks/axonflow",
		Events: []string{"step.approval_required", "workflow.completed"},
		Active: true,
	})
	if err != nil {
		fmt.Printf("   FATAL: CreateWebhook failed: %v\n", err)
		os.Exit(1)
	}

	assert(webhook.ID != "", "Webhook created with valid ID")
	assert(webhook.URL == "https://example.com/webhooks/axonflow", "Webhook URL matches")
	assert(len(webhook.Events) == 2, fmt.Sprintf("Webhook has 2 events (got %d)", len(webhook.Events)))
	assert(webhook.Active, "Webhook is active")
	fmt.Printf("   Webhook ID: %s\n", webhook.ID)
	fmt.Println()

	webhookID := webhook.ID

	// ========================================
	// 2. GET WEBHOOK SUBSCRIPTION
	// ========================================
	fmt.Println("2. GetWebhook - Retrieve the subscription...")

	got, err := client.GetWebhook(webhookID)
	if err != nil {
		fmt.Printf("   FATAL: GetWebhook failed: %v\n", err)
		os.Exit(1)
	}

	assert(got.ID == webhookID, "Retrieved webhook has correct ID")
	assert(got.URL == "https://example.com/webhooks/axonflow", "Retrieved webhook URL matches")
	assert(got.Active, "Retrieved webhook is active")
	fmt.Println()

	// ========================================
	// 3. LIST WEBHOOK SUBSCRIPTIONS
	// ========================================
	fmt.Println("3. ListWebhooks - List all subscriptions...")

	// Create a second webhook for listing
	webhook2, err := client.CreateWebhook(axonflow.CreateWebhookRequest{
		URL:    "https://example.com/webhooks/backup",
		Events: []string{"step.approved", "step.rejected"},
		Active: true,
	})
	if err != nil {
		fmt.Printf("   FATAL: CreateWebhook (second) failed: %v\n", err)
		os.Exit(1)
	}

	listResp, err := client.ListWebhooks()
	if err != nil {
		fmt.Printf("   FATAL: ListWebhooks failed: %v\n", err)
		os.Exit(1)
	}

	assert(listResp.Total >= 2, fmt.Sprintf("At least 2 webhooks listed (got %d)", listResp.Total))
	assert(len(listResp.Webhooks) >= 2, fmt.Sprintf("At least 2 webhooks in response (got %d)", len(listResp.Webhooks)))
	fmt.Printf("   Total webhooks: %d\n", listResp.Total)
	for _, wh := range listResp.Webhooks {
		fmt.Printf("     - %s: %s (active: %v)\n", wh.ID, wh.URL, wh.Active)
	}
	fmt.Println()

	// ========================================
	// 4. UPDATE WEBHOOK SUBSCRIPTION
	// ========================================
	fmt.Println("4. UpdateWebhook - Update URL and deactivate...")

	active := false
	updated, err := client.UpdateWebhook(webhookID, axonflow.UpdateWebhookRequest{
		URL:    "https://example.com/webhooks/updated",
		Active: &active,
	})
	if err != nil {
		fmt.Printf("   FATAL: UpdateWebhook failed: %v\n", err)
		os.Exit(1)
	}

	assert(updated.ID == webhookID, "Updated webhook has correct ID")
	assert(updated.URL == "https://example.com/webhooks/updated", "Webhook URL was updated")
	assert(!updated.Active, "Webhook was deactivated")
	fmt.Println()

	// ========================================
	// 5. DELETE WEBHOOK SUBSCRIPTIONS
	// ========================================
	fmt.Println("5. DeleteWebhook - Delete both subscriptions...")

	err = client.DeleteWebhook(webhookID)
	assert(err == nil, "First webhook deleted successfully")

	err = client.DeleteWebhook(webhook2.ID)
	assert(err == nil, "Second webhook deleted successfully")

	// Verify deletion by trying to get
	_, err = client.GetWebhook(webhookID)
	assert(err != nil, "Deleted webhook returns error on get")
	fmt.Println()

	// ========================================
	// 6. ERROR HANDLING
	// ========================================
	fmt.Println("6. Error Handling - Invalid webhook ID...")

	_, err = client.GetWebhook("nonexistent-webhook-id")
	assert(err != nil, "Getting nonexistent webhook returns error")
	if err != nil {
		fmt.Printf("   Expected error: %v\n", err)
	}
	fmt.Println()

	// ========================================
	// SUMMARY
	// ========================================
	fmt.Println("=====================================")
	fmt.Printf("Tests Run: %d\n", testsRun)
	if len(failures) == 0 {
		fmt.Println("ALL TESTS PASSED")
		fmt.Println()
		fmt.Println("Coverage validated:")
		fmt.Println("  - CreateWebhook()  - Create subscription with URL + events")
		fmt.Println("  - GetWebhook()     - Retrieve subscription by ID")
		fmt.Println("  - ListWebhooks()   - List all subscriptions")
		fmt.Println("  - UpdateWebhook()  - Update URL and active status")
		fmt.Println("  - DeleteWebhook()  - Delete subscription")
		fmt.Println("  - Error handling   - Nonexistent webhook ID")
	} else {
		fmt.Printf("%d TEST(S) FAILED:\n", len(failures))
		for _, f := range failures {
			fmt.Printf("   - %s\n", f)
		}
		os.Exit(1)
	}
}
