#!/usr/bin/env python3
"""
HITL Queue API Example - Python

Validates the HITL Queue SDK methods against a running AxonFlow instance.

The HITL Queue is an enterprise-only feature. In community mode, HITL
queue routes are not registered, so the server returns HTTP 404 (or 403).
This example verifies that the API exists and returns the expected
enterprise-only response, printing a clear message.

In enterprise mode, the same SDK calls would succeed and return queue data.

VALIDATION: This example exits with code 1 if any assertion fails.
In community mode, 403/404 responses are EXPECTED and count as PASS.

Run with: python main.py
Prerequisites: docker compose up -d
"""

import asyncio
import os
import sys

import requests as sync_requests
from dotenv import load_dotenv
from axonflow import AxonFlow, HITLQueueListOptions, HITLReviewInput

load_dotenv()

pass_count = 0
fail_count = 0
failures: list[str] = []


def assert_check(condition: bool, message: str) -> None:
    """Check a condition and record pass/failure."""
    global pass_count, fail_count
    if condition:
        print(f"   PASS: {message}")
        pass_count += 1
    else:
        print(f"   FAIL: {message}")
        fail_count += 1
        failures.append(message)


def is_enterprise_only(exc: Exception) -> bool:
    """Check whether an exception indicates an enterprise-only response (403 or 404).

    In community mode, HITL queue routes are not registered, so the server
    may return 404 (route not found) instead of 403 (forbidden).  Both are
    valid enterprise-only indicators.
    """
    err_str = str(exc)
    return any(marker in err_str for marker in ("403", "404", "Forbidden", "enterprise", "Enterprise", "Not Found"))


async def main() -> int:
    print("HITL Queue API - Python")
    print("=" * 50)
    print()
    print("This example validates the HITL Queue SDK methods.")
    print("In community mode, HITL queue endpoints return 403 or 404.")
    print("403/404 responses are EXPECTED and count as PASS.")
    print()

    endpoint = os.getenv("AXONFLOW_ENDPOINT", os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"))
    client_id = os.getenv("AXONFLOW_CLIENT_ID", "demo-org")
    client_secret = os.getenv("AXONFLOW_CLIENT_SECRET", "")

    async with AxonFlow(
        endpoint=endpoint,
        client_id=client_id,
        client_secret=client_secret,
    ) as client:

        # ========================================
        # Test 1: HITL Status (raw HTTP)
        # ========================================
        print("Test 1: HITL Status Endpoint")
        print("-" * 28)

        status_url = f"{endpoint}/api/v1/hitl/status"
        headers = {
            "X-Client-ID": client_id,
            "X-Client-Secret": client_secret,
        }

        try:
            resp = sync_requests.get(status_url, headers=headers, timeout=10)
            if resp.status_code == 200:
                status_data = resp.json()
                enabled = status_data.get("enabled", False)
                mode = status_data.get("mode", "unknown")
                assert_check(True, f"HITL status endpoint reachable (enabled={enabled}, mode={mode})")
                if mode == "community":
                    print("   Running in community mode - HITL queue endpoints will return 403")
                else:
                    print("   Running in enterprise mode - HITL queue endpoints should succeed")
            elif resp.status_code == 403:
                assert_check(True, "HITL status endpoint returned 403 (enterprise feature)")
            elif resp.status_code == 404:
                assert_check(True, f"HITL status endpoint returned {resp.status_code} (endpoint may not be available)")
            else:
                assert_check(False, f"HITL status endpoint returned unexpected HTTP {resp.status_code}: {resp.text}")
        except sync_requests.exceptions.ConnectionError:
            print("\nHint: Make sure AxonFlow is running:")
            print("  docker compose up -d")
            return 1
        except Exception as e:
            assert_check(False, f"HITL status request failed: {e}")
        print()

        # ========================================
        # Test 2: list_hitl_queue
        # ========================================
        print("Test 2: list_hitl_queue")
        print("-" * 22)

        try:
            list_resp = await client.list_hitl_queue()
            assert_check(True, "list_hitl_queue succeeded (enterprise mode)")
            assert_check(list_resp is not None, "list_hitl_queue returned non-None response")
            if list_resp is not None:
                print(f"   Queue items: {len(list_resp.items)}, Total: {list_resp.total}")
        except Exception as e:
            if is_enterprise_only(e):
                assert_check(True, "list_hitl_queue returns enterprise-only response (expected)")
                print("   HITL Queue listing requires Enterprise license")
            else:
                assert_check(False, f"list_hitl_queue unexpected error: {e}")
        print()

        # Test with options
        print("Test 2b: list_hitl_queue with options")
        print("-" * 37)

        try:
            list_resp_opts = await client.list_hitl_queue(
                HITLQueueListOptions(limit=10, offset=0)
            )
            assert_check(True, "list_hitl_queue with options succeeded (enterprise mode)")
            if list_resp_opts is not None:
                print(f"   Queue items: {len(list_resp_opts.items)}, Total: {list_resp_opts.total}")
        except Exception as e:
            if is_enterprise_only(e):
                assert_check(True, "list_hitl_queue with options returns enterprise-only response (expected)")
            else:
                assert_check(False, f"list_hitl_queue with options unexpected error: {e}")
        print()

        # ========================================
        # Test 3: get_hitl_stats
        # ========================================
        print("Test 3: get_hitl_stats")
        print("-" * 21)

        try:
            stats = await client.get_hitl_stats()
            assert_check(True, "get_hitl_stats succeeded (enterprise mode)")
            assert_check(stats is not None, "get_hitl_stats returned non-None response")
            if stats is not None:
                print(f"   Pending: {stats.pending}, Approved: {stats.approved}, Rejected: {stats.rejected}")
        except Exception as e:
            if is_enterprise_only(e):
                assert_check(True, "get_hitl_stats returns enterprise-only response (expected)")
                print("   HITL Queue statistics require Enterprise license")
            else:
                assert_check(False, f"get_hitl_stats unexpected error: {e}")
        print()

        # ========================================
        # Test 4: get_hitl_request (fake ID)
        # ========================================
        print("Test 4: get_hitl_request (fake ID)")
        print("-" * 34)

        fake_request_id = "hitl_req_nonexistent_12345"
        try:
            hitl_req = await client.get_hitl_request(fake_request_id)
            assert_check(hitl_req is not None, "get_hitl_request succeeded (enterprise mode, unexpected for fake ID)")
        except Exception as e:
            if is_enterprise_only(e):
                assert_check(True, "get_hitl_request returns enterprise-only response (expected)")
                print("   HITL request retrieval requires Enterprise license")
            elif "404" in str(e) or "not found" in str(e).lower():
                assert_check(True, "get_hitl_request returns 404 for nonexistent ID (expected)")
            else:
                assert_check(False, f"get_hitl_request unexpected error: {e}")
        print()

        # ========================================
        # Test 5: approve_hitl_request (fake ID)
        # ========================================
        print("Test 5: approve_hitl_request (fake ID)")
        print("-" * 38)

        try:
            await client.approve_hitl_request(
                fake_request_id,
                HITLReviewInput(
                    reviewer_id="test-reviewer",
                    reviewer_email="test-reviewer@example.com",
                    comment="Auto-approved by HITL queue validation example",
                ),
            )
            assert_check(True, "approve_hitl_request succeeded (enterprise mode)")
        except Exception as e:
            if is_enterprise_only(e):
                assert_check(True, "approve_hitl_request returns enterprise-only response (expected)")
            elif "404" in str(e) or "not found" in str(e).lower():
                assert_check(True, "approve_hitl_request returns 404 for nonexistent ID (expected)")
            else:
                assert_check(False, f"approve_hitl_request unexpected error: {e}")
        print()

        # ========================================
        # Test 6: reject_hitl_request (fake ID)
        # ========================================
        print("Test 6: reject_hitl_request (fake ID)")
        print("-" * 37)

        try:
            await client.reject_hitl_request(
                fake_request_id,
                HITLReviewInput(
                    reviewer_id="test-reviewer",
                    reviewer_email="test-reviewer@example.com",
                    comment="Rejected by HITL queue validation example",
                ),
            )
            assert_check(True, "reject_hitl_request succeeded (enterprise mode)")
        except Exception as e:
            if is_enterprise_only(e):
                assert_check(True, "reject_hitl_request returns enterprise-only response (expected)")
            elif "404" in str(e) or "not found" in str(e).lower():
                assert_check(True, "reject_hitl_request returns 404 for nonexistent ID (expected)")
            else:
                assert_check(False, f"reject_hitl_request unexpected error: {e}")
        print()

    # ========================================
    # Summary
    # ========================================
    print("=" * 50)
    print(f"Results: {pass_count} PASS, {fail_count} FAIL")
    print("=" * 50)

    if failures:
        print("SOME TESTS FAILED:")
        for f in failures:
            print(f"  - {f}")
        return 1

    print("ALL TESTS PASSED")
    print()
    print("HITL Queue operations validated:")
    print("  - HITL status endpoint (raw HTTP)")
    print("  - list_hitl_queue() / list_hitl_queue(options)")
    print("  - get_hitl_stats()")
    print("  - get_hitl_request(request_id)")
    print("  - approve_hitl_request(request_id, review)")
    print("  - reject_hitl_request(request_id, review)")
    print()
    print("Note: In Community Edition, HITL queue endpoints return 403 or 404.")
    print("Upgrade to Enterprise for full HITL queue management.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
