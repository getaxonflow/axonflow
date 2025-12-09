# Example 8: E-Commerce Order Processing

This example demonstrates end-to-end e-commerce order processing with inventory checks, payment, and fulfillment.

## What You'll Learn

- How to orchestrate multi-system transactions
- How to handle payment processing workflows
- How to implement order state management

## Running

```bash
cp .env.example .env
# Add your API key to .env
go run main.go
```

## Expected Output

```
✅ Connected to AxonFlow
📤 Processing order #12345...
✅ Inventory check: Items available
📤 Processing payment...
✅ Payment authorized: $299.99
📤 Creating shipment...
✅ Shipment created: Tracking #ABC123
📤 Sending confirmation email...
✅ Order completed successfully!
```

## How It Works

1. **Validate Order:** Check items, quantities, pricing
2. **Inventory Check:** Verify stock availability
3. **Payment Processing:** Authorize and capture payment
4. **Fraud Check:** Risk assessment and verification
5. **Fulfillment:** Create shipment and generate tracking
6. **Notification:** Send order confirmation to customer

**Order States:**
```
Pending → Validated → Payment Authorized → Fraud Cleared → Shipped → Delivered
```

## Key Concepts

**Transaction Orchestration:**
- Multi-step transaction with rollback
- Idempotent operations (retry-safe)
- State persistence
- Error recovery

## Next Steps

- Try Example 9 for financial reporting
- Add refund/cancellation workflows
- Implement split payments
