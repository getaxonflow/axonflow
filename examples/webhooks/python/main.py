#!/usr/bin/env python3
"""
AxonFlow Webhook Management Example - Python SDK

Demonstrates webhook subscription CRUD operations:
 1. Create a webhook subscription
 2. Get a webhook subscription
 3. List all webhook subscriptions
 4. Update a webhook subscription
 5. Delete a webhook subscription

Run with: python main.py
Prerequisites: docker compose up -d
"""

import asyncio
import os
import sys

from axonflow import AxonFlow

failures: list[str] = []
tests_run = 0


def get_env(key: str, default: str) -> str:
    return os.getenv(key, default)


def assert_check(condition: bool, message: str) -> None:
    global tests_run
    tests_run += 1
    if not condition:
        failures.append(message)
        print(f"   FAIL: {message}")
    else:
        print(f"   PASS: {message}")


async def main() -> int:
    print("AxonFlow Webhook Management - Python SDK")
    print("=" * 45)
    print()

    endpoint = get_env("AXONFLOW_ENDPOINT", os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"))
    client_id = get_env("AXONFLOW_CLIENT_ID", "demo-org")
    client_secret = get_env("AXONFLOW_CLIENT_SECRET", "demo")

    async with AxonFlow(
        endpoint=endpoint,
        client_id=client_id,
        client_secret=client_secret,
        debug=get_env("AXONFLOW_DEBUG", "") == "true",
    ) as client:
        # ========================================
        # 1. CREATE WEBHOOK SUBSCRIPTION
        # ========================================
        print("1. create_webhook - Create a new subscription...")

        webhook = await client.create_webhook(
            url="https://example.com/webhooks/axonflow",
            events=["step.approval_required", "workflow.completed"],
            active=True,
        )

        assert_check(webhook.id != "", "Webhook created with valid ID")
        assert_check(
            webhook.url == "https://example.com/webhooks/axonflow",
            "Webhook URL matches",
        )
        assert_check(len(webhook.events) == 2, f"Webhook has 2 events (got {len(webhook.events)})")
        assert_check(webhook.active, "Webhook is active")
        print(f"   Webhook ID: {webhook.id}")
        print()

        webhook_id = webhook.id

        # ========================================
        # 2. GET WEBHOOK SUBSCRIPTION
        # ========================================
        print("2. get_webhook - Retrieve the subscription...")

        got = await client.get_webhook(webhook_id)

        assert_check(got.id == webhook_id, "Retrieved webhook has correct ID")
        assert_check(
            got.url == "https://example.com/webhooks/axonflow",
            "Retrieved webhook URL matches",
        )
        assert_check(got.active, "Retrieved webhook is active")
        print()

        # ========================================
        # 3. LIST WEBHOOK SUBSCRIPTIONS
        # ========================================
        print("3. list_webhooks - List all subscriptions...")

        # Create a second webhook for listing
        webhook2 = await client.create_webhook(
            url="https://example.com/webhooks/backup",
            events=["step.approved", "step.rejected"],
            active=True,
        )

        list_resp = await client.list_webhooks()

        assert_check(list_resp.total >= 2, f"At least 2 webhooks listed (got {list_resp.total})")
        assert_check(
            len(list_resp.webhooks) >= 2,
            f"At least 2 webhooks in response (got {len(list_resp.webhooks)})",
        )
        print(f"   Total webhooks: {list_resp.total}")
        for wh in list_resp.webhooks:
            print(f"     - {wh.id}: {wh.url} (active: {wh.active})")
        print()

        # ========================================
        # 4. UPDATE WEBHOOK SUBSCRIPTION
        # ========================================
        print("4. update_webhook - Update URL and deactivate...")

        updated = await client.update_webhook(
            webhook_id,
            url="https://example.com/webhooks/updated",
            active=False,
        )

        assert_check(updated.id == webhook_id, "Updated webhook has correct ID")
        assert_check(
            updated.url == "https://example.com/webhooks/updated",
            "Webhook URL was updated",
        )
        assert_check(not updated.active, "Webhook was deactivated")
        print()

        # ========================================
        # 5. DELETE WEBHOOK SUBSCRIPTIONS
        # ========================================
        print("5. delete_webhook - Delete both subscriptions...")

        try:
            await client.delete_webhook(webhook_id)
            assert_check(True, "First webhook deleted successfully")
        except Exception as e:
            assert_check(False, f"First webhook deletion failed: {e}")

        try:
            await client.delete_webhook(webhook2.id)
            assert_check(True, "Second webhook deleted successfully")
        except Exception as e:
            assert_check(False, f"Second webhook deletion failed: {e}")

        # Verify deletion
        try:
            await client.get_webhook(webhook_id)
            assert_check(False, "Deleted webhook should not be retrievable")
        except Exception:
            assert_check(True, "Deleted webhook returns error on get")
        print()

        # ========================================
        # 6. ERROR HANDLING
        # ========================================
        print("6. Error Handling - Invalid webhook ID...")

        try:
            await client.get_webhook("nonexistent-webhook-id")
            assert_check(False, "Getting nonexistent webhook should fail")
        except Exception as e:
            assert_check(True, "Getting nonexistent webhook returns error")
            print(f"   Expected error: {e}")
        print()

        # ========================================
        # SUMMARY
        # ========================================
        print("=" * 45)
        print(f"Tests Run: {tests_run}")
        if not failures:
            print("ALL TESTS PASSED")
            print()
            print("Coverage validated:")
            print("  - create_webhook()  - Create subscription with URL + events")
            print("  - get_webhook()     - Retrieve subscription by ID")
            print("  - list_webhooks()   - List all subscriptions")
            print("  - update_webhook()  - Update URL and active status")
            print("  - delete_webhook()  - Delete subscription")
            print("  - Error handling    - Nonexistent webhook ID")
            return 0
        else:
            print(f"{len(failures)} TEST(S) FAILED:")
            for f in failures:
                print(f"   - {f}")
            return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
