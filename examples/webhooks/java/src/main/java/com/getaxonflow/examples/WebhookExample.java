// AxonFlow Webhook Management Example - Java SDK
//
// Demonstrates webhook subscription CRUD operations:
// 1. Create a webhook subscription
// 2. Get a webhook subscription
// 3. List all webhook subscriptions
// 4. Update a webhook subscription
// 5. Delete a webhook subscription
//
// Run with: mvn exec:java
// Prerequisites: docker compose up -d
package com.getaxonflow.examples;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.webhook.WebhookTypes.CreateWebhookRequest;
import com.getaxonflow.sdk.types.webhook.WebhookTypes.UpdateWebhookRequest;
import com.getaxonflow.sdk.types.webhook.WebhookTypes.WebhookSubscription;
import com.getaxonflow.sdk.types.webhook.WebhookTypes.ListWebhooksResponse;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class WebhookExample {
    private static int testsRun = 0;
    private static final List<String> failures = new ArrayList<>();

    private static void assertCheck(boolean condition, String message) {
        testsRun++;
        if (!condition) {
            failures.add(message);
            System.out.println("   FAIL: " + message);
        } else {
            System.out.println("   PASS: " + message);
        }
    }

    private static String getEnv(String key, String defaultValue) {
        String value = System.getenv(key);
        return value != null && !value.isEmpty() ? value : defaultValue;
    }

    public static void main(String[] args) {
        System.out.println("AxonFlow Webhook Management - Java SDK");
        System.out.println("=".repeat(42));
        System.out.println();

        AxonFlow client = AxonFlow.create(AxonFlowConfig.builder()
                .endpoint(getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080"))
                .clientId(getEnv("AXONFLOW_CLIENT_ID", "demo-org"))
                .clientSecret(getEnv("AXONFLOW_CLIENT_SECRET", "demo"))
                .build());

        // ========================================
        // 1. CREATE WEBHOOK SUBSCRIPTION
        // ========================================
        System.out.println("1. createWebhook - Create a new subscription...");

        CreateWebhookRequest createReq = CreateWebhookRequest.builder()
                .url("https://example.com/webhooks/axonflow")
                .events(Arrays.asList("step.approval_required", "workflow.completed"))
                .active(true)
                .build();

        WebhookSubscription webhook = client.createWebhook(createReq);

        assertCheck(webhook.getId() != null && !webhook.getId().isEmpty(), "Webhook created with valid ID");
        assertCheck("https://example.com/webhooks/axonflow".equals(webhook.getUrl()), "Webhook URL matches");
        assertCheck(webhook.getEvents().size() == 2, "Webhook has 2 events (got " + webhook.getEvents().size() + ")");
        assertCheck(webhook.isActive(), "Webhook is active");
        System.out.println("   Webhook ID: " + webhook.getId());
        System.out.println();

        String webhookId = webhook.getId();

        // ========================================
        // 2. GET WEBHOOK SUBSCRIPTION
        // ========================================
        System.out.println("2. getWebhook - Retrieve the subscription...");

        WebhookSubscription got = client.getWebhook(webhookId);

        assertCheck(webhookId.equals(got.getId()), "Retrieved webhook has correct ID");
        assertCheck("https://example.com/webhooks/axonflow".equals(got.getUrl()), "Retrieved webhook URL matches");
        assertCheck(got.isActive(), "Retrieved webhook is active");
        System.out.println();

        // ========================================
        // 3. LIST WEBHOOK SUBSCRIPTIONS
        // ========================================
        System.out.println("3. listWebhooks - List all subscriptions...");

        // Create a second webhook for listing
        CreateWebhookRequest createReq2 = CreateWebhookRequest.builder()
                .url("https://example.com/webhooks/backup")
                .events(Arrays.asList("step.approved", "step.rejected"))
                .active(true)
                .build();

        WebhookSubscription webhook2 = client.createWebhook(createReq2);

        ListWebhooksResponse listResp = client.listWebhooks();

        assertCheck(listResp.getTotal() >= 2, "At least 2 webhooks listed (got " + listResp.getTotal() + ")");
        assertCheck(listResp.getWebhooks().size() >= 2, "At least 2 webhooks in response (got " + listResp.getWebhooks().size() + ")");
        System.out.println("   Total webhooks: " + listResp.getTotal());
        for (WebhookSubscription wh : listResp.getWebhooks()) {
            System.out.println("     - " + wh.getId() + ": " + wh.getUrl() + " (active: " + wh.isActive() + ")");
        }
        System.out.println();

        // ========================================
        // 4. UPDATE WEBHOOK SUBSCRIPTION
        // ========================================
        System.out.println("4. updateWebhook - Update URL and deactivate...");

        UpdateWebhookRequest updateReq = UpdateWebhookRequest.builder()
                .url("https://example.com/webhooks/updated")
                .active(false)
                .build();

        WebhookSubscription updated = client.updateWebhook(webhookId, updateReq);

        assertCheck(webhookId.equals(updated.getId()), "Updated webhook has correct ID");
        assertCheck("https://example.com/webhooks/updated".equals(updated.getUrl()), "Webhook URL was updated");
        assertCheck(!updated.isActive(), "Webhook was deactivated");
        System.out.println();

        // ========================================
        // 5. DELETE WEBHOOK SUBSCRIPTIONS
        // ========================================
        System.out.println("5. deleteWebhook - Delete both subscriptions...");

        try {
            client.deleteWebhook(webhookId);
            assertCheck(true, "First webhook deleted successfully");
        } catch (Exception e) {
            assertCheck(false, "First webhook deletion failed: " + e.getMessage());
        }

        try {
            client.deleteWebhook(webhook2.getId());
            assertCheck(true, "Second webhook deleted successfully");
        } catch (Exception e) {
            assertCheck(false, "Second webhook deletion failed: " + e.getMessage());
        }

        // Verify deletion
        try {
            client.getWebhook(webhookId);
            assertCheck(false, "Deleted webhook should not be retrievable");
        } catch (Exception e) {
            assertCheck(true, "Deleted webhook returns error on get");
        }
        System.out.println();

        // ========================================
        // 6. ERROR HANDLING
        // ========================================
        System.out.println("6. Error Handling - Invalid webhook ID...");

        try {
            client.getWebhook("nonexistent-webhook-id");
            assertCheck(false, "Getting nonexistent webhook should fail");
        } catch (Exception e) {
            assertCheck(true, "Getting nonexistent webhook returns error");
            System.out.println("   Expected error: " + e.getMessage());
        }
        System.out.println();

        // ========================================
        // SUMMARY
        // ========================================
        System.out.println("=".repeat(42));
        System.out.println("Tests Run: " + testsRun);
        if (failures.isEmpty()) {
            System.out.println("ALL TESTS PASSED");
            System.out.println();
            System.out.println("Coverage validated:");
            System.out.println("  - createWebhook()  - Create subscription with URL + events");
            System.out.println("  - getWebhook()     - Retrieve subscription by ID");
            System.out.println("  - listWebhooks()   - List all subscriptions");
            System.out.println("  - updateWebhook()  - Update URL and active status");
            System.out.println("  - deleteWebhook()  - Delete subscription");
            System.out.println("  - Error handling   - Nonexistent webhook ID");
        } else {
            System.out.println(failures.size() + " TEST(S) FAILED:");
            for (String f : failures) {
                System.out.println("   - " + f);
            }
            System.exit(1);
        }
    }
}
