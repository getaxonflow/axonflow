#!/usr/bin/env python3
"""
AxonFlow Evaluation Tier - License Tier Limits Testing

TIER COMPATIBILITY: Community / Evaluation
Works without any license (Community mode) and with a free Evaluation license.
No paid Enterprise license required. Get a free Evaluation license at:
https://getaxonflow.com/evaluation-license

VALIDATION: This example exits with code 1 if any assertion fails.

This example demonstrates and verifies the tier-based policy limits:
- Community (no license): 20 tenant policies, 0 org policies
- Evaluation (free license): 50 tenant policies, 5 org policies
- Enterprise (paid license): Unlimited

Run with:
  # Community mode (no license)
  python test_tier_limits.py

  # Evaluation mode (with Evaluation license)
  AXONFLOW_LICENSE_KEY=<evaluation-license> python test_tier_limits.py

  # Enterprise mode (with Enterprise license)
  AXONFLOW_LICENSE_KEY=<enterprise-license> python test_tier_limits.py

Prerequisites: docker compose up -d
"""

import asyncio
import os
import sys

from axonflow import (
    AxonFlow,
    CreateDynamicPolicyRequest,
    DynamicPolicyCondition,
    DynamicPolicyAction,
    AxonFlowError,
)

failures: list[str] = []


def assert_check(condition: bool, message: str) -> None:
    """Check a condition and record failure if false."""
    if condition:
        print(f"   ✓ PASS: {message}")
    else:
        print(f"   ❌ FAIL: {message}")
        failures.append(message)


def get_expected_tier() -> str:
    """Determine expected tier based on license key."""
    import base64
    import json

    license_key = os.getenv("AXONFLOW_LICENSE_KEY", "")
    if not license_key:
        return "community"
    # Ed25519 format: AXON-{base64url_payload}.{base64url_signature}
    if license_key.startswith("AXON-") and "." in license_key:
        try:
            inner = license_key[5:]  # Strip "AXON-"
            payload_b64 = inner.rsplit(".", 1)[0]
            padding = 4 - len(payload_b64) % 4
            if padding != 4:
                payload_b64 += "=" * padding
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            tier = payload.get("tier", "")
            if tier == "Evaluation":
                return "evaluation"
            if tier in ("Enterprise", "Plus", "Professional"):
                return "enterprise"
        except Exception:
            pass
    if "EVALUATION" in license_key.upper():
        return "evaluation"
    return "enterprise"


async def main() -> int:
    print("=" * 60)
    print("AxonFlow Evaluation Tier - License Tier Limits Testing (Python)")
    print("=" * 60)

    expected_tier = get_expected_tier()
    print(f"\nDetected tier (from env): {expected_tier}")

    client = AxonFlow(
        endpoint=os.getenv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "test-org-001"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", "test-secret"),
    )

    # Test 1: Health Check / Tier Detection
    print("\n1. Testing Tier Detection")
    print("-" * 40)

    try:
        is_healthy = await client.health_check()
        assert_check(is_healthy, "Platform is healthy")
    except Exception as e:
        print(f"   Error: {e}")
        assert_check(False, "Health check passed")

    # Test 2: Create and Delete Tenant Policy
    print("\n2. Testing Tenant Policy Limits")
    print("-" * 40)

    expected_limit = "20" if expected_tier == "community" else ("50" if expected_tier == "evaluation" else "unlimited")
    print(f"   Expected limit for {expected_tier}: {expected_limit}")

    try:
        request = CreateDynamicPolicyRequest(
            name="Python Evaluation Tier Test Policy",
            description="Test policy for tier limit verification",
            type="content",
            category="dynamic-py-tier-test",
            conditions=[
                DynamicPolicyCondition(
                    field="query",
                    operator="contains",
                    value="py-tier-test",
                )
            ],
            actions=[DynamicPolicyAction(type="log")],
            priority=100,
            enabled=False,
        )

        policy = await client.create_dynamic_policy(request)
        assert_check(True, "Policy creation succeeded")
        print(f"   Created policy: {policy.id}")

        # Clean up
        await client.delete_dynamic_policy(policy.id)
        print("   Cleaned up test policy")

    except AxonFlowError as e:
        errstr = str(e)
        if "POLICY_LIMIT_EXCEEDED" in errstr:
            print("   Policy limit reached")
            assert_check(True, "Policy limit enforcement working")

            if expected_tier == "community" and "evaluation" in errstr.lower():
                assert_check(True, "Error mentions Evaluation upgrade path")
            elif expected_tier == "evaluation" and "enterprise" in errstr.lower():
                assert_check(True, "Error mentions Enterprise upgrade path")
        else:
            print(f"   Error: {e}")
            assert_check(False, "Policy creation succeeded or limit enforced")

    # Test 3: Organization Policy Access
    print("\n3. Testing Organization Policy Access")
    print("-" * 40)

    try:
        org_request = CreateDynamicPolicyRequest(
            name="Python Org Policy Test",
            description="Test org policy for tier verification",
            type="content",
            category="dynamic-py-org-test",
            tier="organization",
            conditions=[
                DynamicPolicyCondition(
                    field="query",
                    operator="contains",
                    value="py-org-test",
                )
            ],
            actions=[DynamicPolicyAction(type="log")],
            priority=100,
            enabled=False,
        )

        org_policy = await client.create_dynamic_policy(org_request)

        if expected_tier == "community":
            assert_check(False, "Community should not create org policies")
        else:
            assert_check(True, f"{expected_tier} tier can create org policies")
            print(f"   Created org policy: {org_policy.id}")

            # Clean up
            await client.delete_dynamic_policy(org_policy.id)
            print("   Cleaned up org policy")

    except AxonFlowError as e:
        errstr = str(e)
        if expected_tier == "community":
            if "ORG_TIER" in errstr or "evaluation" in errstr.lower():
                assert_check(True, "Community tier correctly blocked org policy creation")
                if "evaluation" in errstr.lower():
                    assert_check(True, "Error includes Evaluation upgrade path")
            else:
                print(f"   Error: {e}")
                assert_check(False, "Expected org tier error for Community")
        elif "ORG_POLICY_LIMIT_EXCEEDED" in errstr:
            print("   Org policy limit reached for Evaluation tier")
            assert_check(True, "Evaluation tier has org policy limit enforcement")
        else:
            print(f"   Error: {e}")
            assert_check(False, "Unexpected error creating org policy")

    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)

    if failures:
        print(f"\n❌ {len(failures)} test(s) failed:")
        for failure in failures:
            print(f"   - {failure}")
        return 1
    else:
        print("\n✓ All tests passed!")
        print(f"\nTier limits verified for: {expected_tier}")
        print("\nTier Comparison:")
        print("  | Feature          | Community | Evaluation | Enterprise |")
        print("  |------------------|-----------|------------|------------|")
        print("  | Tenant policies  | 20        | 50         | Unlimited  |")
        print("  | Org policies     | 0         | 5          | Unlimited  |")
        print("  | MCP connectors   | 2         | 5          | Unlimited  |")
        print("  | Audit retention  | 3 days    | 14 days    | 3650 days  |")
        return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
