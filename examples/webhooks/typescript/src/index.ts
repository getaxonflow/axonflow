/**
 * AxonFlow Webhook Management Example - TypeScript SDK
 *
 * Demonstrates webhook subscription CRUD operations:
 * 1. Create a webhook subscription
 * 2. Get a webhook subscription
 * 3. List all webhook subscriptions
 * 4. Update a webhook subscription
 * 5. Delete a webhook subscription
 *
 * Run with: npx ts-node src/index.ts
 * Prerequisites: docker compose up -d
 */

import { AxonFlow } from "@axonflow/sdk";

let failures: string[] = [];
let testsRun = 0;

function assert(condition: boolean, message: string): void {
  testsRun++;
  if (!condition) {
    failures.push(message);
    console.log(`   FAIL: ${message}`);
  } else {
    console.log(`   PASS: ${message}`);
  }
}

async function main(): Promise<number> {
  console.log("AxonFlow Webhook Management - TypeScript SDK");
  console.log("=".repeat(48));
  console.log();

  const client = new AxonFlow({
    endpoint: process.env.AXONFLOW_ORCHESTRATOR_URL || "http://localhost:8081",
    clientId: process.env.AXONFLOW_CLIENT_ID || "demo-org",
    clientSecret: process.env.AXONFLOW_CLIENT_SECRET || "demo",
  });

  // ========================================
  // 1. CREATE WEBHOOK SUBSCRIPTION
  // ========================================
  console.log("1. createWebhook - Create a new subscription...");

  const webhook = await client.createWebhook({
    url: "https://example.com/webhooks/axonflow",
    events: ["step.approval_required", "workflow.completed"],
    active: true,
  });

  assert(webhook.id !== "", "Webhook created with valid ID");
  assert(webhook.url === "https://example.com/webhooks/axonflow", "Webhook URL matches");
  assert(webhook.events.length === 2, `Webhook has 2 events (got ${webhook.events.length})`);
  assert(webhook.active === true, "Webhook is active");
  console.log(`   Webhook ID: ${webhook.id}`);
  console.log();

  const webhookId = webhook.id;

  // ========================================
  // 2. GET WEBHOOK SUBSCRIPTION
  // ========================================
  console.log("2. getWebhook - Retrieve the subscription...");

  const got = await client.getWebhook(webhookId);

  assert(got.id === webhookId, "Retrieved webhook has correct ID");
  assert(got.url === "https://example.com/webhooks/axonflow", "Retrieved webhook URL matches");
  assert(got.active === true, "Retrieved webhook is active");
  console.log();

  // ========================================
  // 3. LIST WEBHOOK SUBSCRIPTIONS
  // ========================================
  console.log("3. listWebhooks - List all subscriptions...");

  // Create a second webhook for listing
  const webhook2 = await client.createWebhook({
    url: "https://example.com/webhooks/backup",
    events: ["step.approved", "step.rejected"],
    active: true,
  });

  const listResp = await client.listWebhooks();

  assert(listResp.total >= 2, `At least 2 webhooks listed (got ${listResp.total})`);
  assert(listResp.webhooks.length >= 2, `At least 2 webhooks in response (got ${listResp.webhooks.length})`);
  console.log(`   Total webhooks: ${listResp.total}`);
  for (const wh of listResp.webhooks) {
    console.log(`     - ${wh.id}: ${wh.url} (active: ${wh.active})`);
  }
  console.log();

  // ========================================
  // 4. UPDATE WEBHOOK SUBSCRIPTION
  // ========================================
  console.log("4. updateWebhook - Update URL and deactivate...");

  const updated = await client.updateWebhook(webhookId, {
    url: "https://example.com/webhooks/updated",
    active: false,
  });

  assert(updated.id === webhookId, "Updated webhook has correct ID");
  assert(updated.url === "https://example.com/webhooks/updated", "Webhook URL was updated");
  assert(updated.active === false, "Webhook was deactivated");
  console.log();

  // ========================================
  // 5. DELETE WEBHOOK SUBSCRIPTIONS
  // ========================================
  console.log("5. deleteWebhook - Delete both subscriptions...");

  try {
    await client.deleteWebhook(webhookId);
    assert(true, "First webhook deleted successfully");
  } catch (e) {
    assert(false, `First webhook deletion failed: ${e}`);
  }

  try {
    await client.deleteWebhook(webhook2.id);
    assert(true, "Second webhook deleted successfully");
  } catch (e) {
    assert(false, `Second webhook deletion failed: ${e}`);
  }

  // Verify deletion
  try {
    await client.getWebhook(webhookId);
    assert(false, "Deleted webhook should not be retrievable");
  } catch {
    assert(true, "Deleted webhook returns error on get");
  }
  console.log();

  // ========================================
  // 6. ERROR HANDLING
  // ========================================
  console.log("6. Error Handling - Invalid webhook ID...");

  try {
    await client.getWebhook("nonexistent-webhook-id");
    assert(false, "Getting nonexistent webhook should fail");
  } catch (e) {
    assert(true, "Getting nonexistent webhook returns error");
    console.log(`   Expected error: ${e}`);
  }
  console.log();

  // ========================================
  // SUMMARY
  // ========================================
  console.log("=".repeat(48));
  console.log(`Tests Run: ${testsRun}`);
  if (failures.length === 0) {
    console.log("ALL TESTS PASSED");
    console.log();
    console.log("Coverage validated:");
    console.log("  - createWebhook()  - Create subscription with URL + events");
    console.log("  - getWebhook()     - Retrieve subscription by ID");
    console.log("  - listWebhooks()   - List all subscriptions");
    console.log("  - updateWebhook()  - Update URL and active status");
    console.log("  - deleteWebhook()  - Delete subscription");
    console.log("  - Error handling   - Nonexistent webhook ID");
    return 0;
  } else {
    console.log(`${failures.length} TEST(S) FAILED:`);
    for (const f of failures) {
      console.log(`   - ${f}`);
    }
    return 1;
  }
}

main().then((code) => process.exit(code));
