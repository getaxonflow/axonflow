package main

import (
	"fmt"
	"log"
	"os"
	"strings"
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
	fmt.Println("🛒 Starting e-commerce order processing workflow...")
	fmt.Println()

	orderID := "ORD-2024-" + fmt.Sprintf("%d", time.Now().Unix())
	orderDetails := "Customer: John Doe, Items: MacBook Pro 16\" (1x $2,499), " +
		"AirPods Pro (1x $249), Shipping: Express, Total: $2,748 + $25 shipping"

	fmt.Printf("📦 Order ID: %s\n", orderID)
	fmt.Println(orderDetails)
	fmt.Println()

	// Step 1: Validate Order
	fmt.Println("✅ Step 1: Validating order details...")
	validateQuery := fmt.Sprintf("Validate this e-commerce order: %s. "+
		"Check: valid items, correct pricing, shipping address format. "+
		"Respond with VALID or INVALID and list any issues.", orderDetails)

	validateResp, err := client.ExecuteQuery("user-123", validateQuery, "chat", map[string]interface{}{"model": "gpt-4"})
	if err != nil {
		log.Fatalf("❌ Validation failed: %v", err)
	}

	if strings.Contains(strings.ToLower(fmt.Sprintf("%v", validateResp.Data)), "invalid") {
		fmt.Println("❌ Order validation failed:", validateResp.Data)
		return
	}
	fmt.Println("✅ Order validated successfully")
	fmt.Println()

	// Step 2: Inventory Check
	fmt.Println("📦 Step 2: Checking inventory availability...")
	inventoryQuery := "Check inventory for: MacBook Pro 16\" (need 1), AirPods Pro (need 1). " +
		"Respond with IN_STOCK or OUT_OF_STOCK for each item."

	inventoryResp, err := client.ExecuteQuery("user-123", inventoryQuery, "chat", map[string]interface{}{"model": "gpt-4"})
	if err != nil {
		log.Fatalf("❌ Inventory check failed: %v", err)
	}

	if strings.Contains(strings.ToLower(fmt.Sprintf("%v", inventoryResp.Data)), "out_of_stock") {
		fmt.Println("⚠️  Some items out of stock:", inventoryResp.Data)
		fmt.Println("💡 Sending back-order notification...")
		return
	}
	fmt.Println("✅ All items in stock")
	fmt.Println()

	// Step 3: Payment Processing
	fmt.Println("💳 Step 3: Processing payment ($2,773 total)...")
	paymentQuery := "Process payment: Amount $2,773, Card ending in 4242, CVV verified. " +
		"Perform fraud check: Order from regular customer, shipping matches billing. " +
		"Respond with APPROVED or DECLINED and fraud score (low/medium/high)."

	paymentResp, err := client.ExecuteQuery("user-123", paymentQuery, "chat", map[string]interface{}{"model": "gpt-4"})
	if err != nil {
		log.Fatalf("❌ Payment processing failed: %v", err)
	}

	if strings.Contains(strings.ToLower(fmt.Sprintf("%v", paymentResp.Data)), "declined") {
		fmt.Println("❌ Payment declined:", paymentResp.Data)
		return
	}
	fmt.Println("✅ Payment authorized:", paymentResp.Data)
	fmt.Println()

	// Step 4: Create Shipment
	fmt.Println("📮 Step 4: Creating shipment and generating tracking number...")
	shipmentQuery := "Create shipment for order: 2 items (MacBook Pro + AirPods), " +
		"Express shipping to California. " +
		"Generate tracking number and estimated delivery date."

	shipmentResp, err := client.ExecuteQuery("user-123", shipmentQuery, "chat", map[string]interface{}{"model": "gpt-4"})
	if err != nil {
		log.Fatalf("❌ Shipment creation failed: %v", err)
	}
	fmt.Println("✅ Shipment created:", shipmentResp.Data)
	fmt.Println()

	// Step 5: Send Confirmation
	fmt.Println("📧 Step 5: Sending order confirmation email...")
	confirmQuery := fmt.Sprintf("Generate order confirmation email for Order ID: %s. "+
		"Include: order summary, payment confirmation ($2,773), "+
		"tracking information, estimated delivery. Keep professional and friendly.", orderID)

	confirmResp, err := client.ExecuteQuery("user-123", confirmQuery, "chat", map[string]interface{}{"model": "gpt-4"})
	if err != nil {
		log.Fatalf("❌ Confirmation failed: %v", err)
	}

	fmt.Println()
	fmt.Println("=" + "=")
	fmt.Println("✉️  ORDER CONFIRMATION EMAIL")
	fmt.Println("=" + "=")
	fmt.Println(confirmResp.Data)
	fmt.Println("=" + "=")
	fmt.Println()
	fmt.Printf("🎉 Order %s completed successfully!\n", orderID)
	fmt.Println("✅ Workflow: Validate → Inventory → Payment → Shipment → Notification")
}
