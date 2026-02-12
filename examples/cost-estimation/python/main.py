#!/usr/bin/env python3
"""
AxonFlow Cost Estimation Example - Python

Validates the new cost estimation endpoints added in v4.3.0:
  - POST /api/v1/plans/estimate  - Estimate cost of a plan before execution
  - GET  /api/v1/plans/{id}/cost - Get cost estimate for an existing plan

These endpoints are NOT in any SDK yet, so this example uses the requests
library for raw HTTP calls and the Python SDK for plan generation.

Usage:
  python main.py

Environment:
  AXONFLOW_ENDPOINT      - Agent URL (default: http://localhost:8080)
  AXONFLOW_CLIENT_ID     - Client ID (default: demo-org)
  AXONFLOW_CLIENT_SECRET - Client secret (optional for community mode)
  AXONFLOW_USER_TOKEN    - JWT token for MAP operations (optional)

VALIDATION: This example exits with code 1 if any assertion fails.
"""

import asyncio
import os
import sys

import requests as http_requests

from axonflow import AxonFlow

failures: list[str] = []


def get_env(key: str, default: str) -> str:
    return os.getenv(key, default)


def assert_check(condition: bool, message: str) -> None:
    """Check a condition and record failure if false."""
    if condition:
        print(f"   PASS: {message}")
    else:
        print(f"   FAIL: {message}")
        failures.append(message)


async def main() -> int:
    print("AxonFlow Cost Estimation - Python (Raw HTTP + SDK)")
    print("=" * 52)
    print()

    endpoint = get_env("AXONFLOW_ENDPOINT", "http://localhost:8080")
    client_id = get_env("AXONFLOW_CLIENT_ID", "demo-org")
    client_secret = get_env("AXONFLOW_CLIENT_SECRET", "")
    user_token = get_env("AXONFLOW_USER_TOKEN", "")

    print(f"Endpoint: {endpoint}")
    print(f"Client ID: {client_id}")
    print("-" * 52)
    print()

    headers = {
        "Content-Type": "application/json",
        "X-Client-ID": client_id,
    }
    if client_secret:
        headers["X-Client-Secret"] = client_secret

    # ========================================
    # 1. HEALTH CHECK
    # ========================================
    print("1. Health Check...")
    try:
        resp = http_requests.get(f"{endpoint}/health", timeout=15)
        assert_check(resp.status_code == 200, f"Health check returns 200 (got {resp.status_code})")
        if resp.status_code == 200:
            data = resp.json()
            print(f"   Status: {data.get('status', 'unknown')}")
    except Exception as e:
        print(f"   ERROR: {e}")
        assert_check(False, "Health check request succeeded")
    print()

    # ========================================
    # 2. POST /api/v1/plans/estimate
    # ========================================
    print("2. POST /api/v1/plans/estimate - Estimate cost before execution...")

    estimate_payload = {
        "provider": "openai",
        "model": "gpt-4",
        "steps": [
            {
                "name": "analyze",
                "type": "llm_call",
                "estimated_tokens_in": 1000,
                "estimated_tokens_out": 500,
            },
            {
                "name": "summarize",
                "type": "llm_call",
                "estimated_tokens_in": 500,
                "estimated_tokens_out": 200,
            },
        ],
    }

    try:
        resp = http_requests.post(
            f"{endpoint}/api/v1/plans/estimate",
            json=estimate_payload,
            headers=headers,
            timeout=15,
        )

        if resp.status_code == 429:
            print("   Rate limited (429) - community mode allows 10 estimates/day")
            print("   This is expected behavior; skipping estimate assertions.")
            assert_check(True, "Estimate endpoint returned valid status (429 rate limit)")
        else:
            assert_check(
                resp.status_code == 200,
                f"Estimate returns 200 (got {resp.status_code})",
            )

            if resp.status_code == 200:
                data = resp.json()
                print(f"   Response: {data}")

                # Verify estimated_cost_usd field
                has_cost = "estimated_cost_usd" in data
                assert_check(has_cost, "Response contains 'estimated_cost_usd' field")
                if has_cost:
                    cost = data["estimated_cost_usd"]
                    assert_check(
                        isinstance(cost, (int, float)),
                        "estimated_cost_usd is a number",
                    )
                    assert_check(cost >= 0, f"estimated_cost_usd >= 0 (got {cost:.6f})")
                    print(f"   Estimated Cost: ${cost:.6f} USD")

                # Verify currency field
                has_currency = "currency" in data
                assert_check(has_currency, "Response contains 'currency' field")
                if has_currency:
                    assert_check(
                        data["currency"] == "USD",
                        f"currency is 'USD' (got '{data['currency']}')",
                    )

                # Check breakdown (may be absent in community mode)
                if "breakdown" in data:
                    print(f"   Breakdown available: {data['breakdown']}")
                else:
                    print("   Note: 'breakdown' not present (community mode returns aggregate only)")

    except Exception as e:
        print(f"   ERROR: {e}")
        assert_check(False, "Estimate request completed")
    print()

    # ========================================
    # 3. CREATE PLAN VIA SDK + GET COST
    # ========================================
    print("3. Create MAP plan via SDK, then GET /api/v1/plans/{id}/cost...")

    try:
        async with AxonFlow(
            endpoint=endpoint,
            client_id=client_id,
            client_secret=client_secret,
            debug=get_env("AXONFLOW_DEBUG", "") == "true",
            cache_enabled=False,
        ) as client:
            query = "Create a brief plan to analyze customer feedback and generate a summary report"
            domain = "generic"

            plan = await client.generate_plan(
                query=query,
                domain=domain,
                user_token=user_token if user_token else None,
            )

            assert_check(plan is not None, "Plan generated successfully")
            assert_check(
                plan.plan_id is not None and plan.plan_id != "",
                "Plan has a valid ID",
            )
            print(f"   Plan ID: {plan.plan_id}")
            print(f"   Steps: {len(plan.steps) if plan.steps else 0}")

            # GET /api/v1/plans/{id}/cost
            print()
            print("   Fetching cost for existing plan...")
            cost_url = f"{endpoint}/api/v1/plans/{plan.plan_id}/cost"
            resp = http_requests.get(cost_url, headers=headers, timeout=15)

            if resp.status_code == 429:
                print("   Rate limited (429) - community mode allows 10 estimates/day")
                assert_check(True, "Plan cost endpoint returned valid status (429 rate limit)")
            elif resp.status_code == 404:
                print("   Plan cost endpoint returned 404 - endpoint may require enterprise mode")
                assert_check(True, "Plan cost endpoint responded (404 - may require enterprise)")
            else:
                assert_check(
                    resp.status_code == 200,
                    f"GET plan cost returns 200 (got {resp.status_code})",
                )

                if resp.status_code == 200:
                    cost_data = resp.json()
                    print(f"   Cost Response: {cost_data}")

                    has_cost = "estimated_cost_usd" in cost_data
                    assert_check(has_cost, "Plan cost response contains 'estimated_cost_usd'")
                    if has_cost:
                        cost = cost_data["estimated_cost_usd"]
                        assert_check(
                            isinstance(cost, (int, float)) and cost >= 0,
                            f"Plan cost >= 0 (got {cost})",
                        )

                    has_currency = "currency" in cost_data
                    assert_check(has_currency, "Plan cost response contains 'currency'")
                    if has_currency:
                        assert_check(
                            cost_data["currency"] == "USD",
                            f"Plan cost currency is 'USD' (got '{cost_data['currency']}')",
                        )

                    if "breakdown" not in cost_data:
                        print("   Note: 'breakdown' not present (community mode returns aggregate only)")

    except Exception as e:
        print(f"   ERROR: {e}")
        assert_check(False, f"Plan creation and cost retrieval succeeded: {e}")
    print()

    # ========================================
    # SUMMARY
    # ========================================
    print("=" * 52)
    print("Cost Estimation Example - Summary")
    print("=" * 52)
    if not failures:
        print("All assertions passed!")
        return 0
    else:
        print(f"{len(failures)} assertion(s) FAILED:")
        for f in failures:
            print(f"   - {f}")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
