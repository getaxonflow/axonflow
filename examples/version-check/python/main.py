#!/usr/bin/env python3
"""
Version Discovery Example - Python SDK

Demonstrates SDK-platform version discovery:
1. health_check_detailed() returns platform version and capabilities
2. has_capability() checks for specific platform features
3. SDK version mismatch warnings

VALIDATION: This example exits with code 1 if any assertion fails.

Run with: python main.py
Prerequisites: docker compose up -d
"""

import os
import sys
from typing import List

from axonflow import AxonFlow

failures: List[str] = []


def assert_check(condition: bool, message: str) -> None:
    """Check a condition and record failure if false."""
    if condition:
        print(f"   PASS: {message}")
    else:
        print(f"   FAIL: {message}")
        failures.append(message)


def main() -> int:
    """Run version discovery tests."""
    print("Version Discovery — Python SDK")
    print("=" * 40)
    print()

    client = AxonFlow.sync(
        endpoint=os.getenv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "demo"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", ""),
        debug=os.getenv("AXONFLOW_DEBUG", "").lower() == "true",
    )

    # ---------------------------------------------------------------
    # Test 1: health_check_detailed returns version and capabilities
    # ---------------------------------------------------------------
    print("Test 1: health_check_detailed — Version and Capabilities")
    print("-" * 55)

    health = client.health_check_detailed()

    print(f"   Platform version: {health.version}")
    print(f"   Service: {health.service}")
    print(f"   Status: {health.status}")
    print(f"   Capabilities: {len(health.capabilities)}")

    assert_check(health.version != "", "version is non-empty")
    assert_check(health.status in ("healthy", "starting"), "status is healthy or starting")
    assert_check(len(health.capabilities) > 0, "capabilities list is non-empty")
    assert_check(health.sdk_compatibility is not None, "sdk_compatibility is present")

    if health.sdk_compatibility:
        print(f"   Min SDK: {health.sdk_compatibility.min_sdk_version}")
        print(f"   Recommended SDK: {health.sdk_compatibility.recommended_sdk_version}")
        assert_check(
            health.sdk_compatibility.min_sdk_version != "",
            "min_sdk_version is non-empty",
        )
        assert_check(
            health.sdk_compatibility.recommended_sdk_version != "",
            "recommended_sdk_version is non-empty",
        )
    print()

    # ---------------------------------------------------------------
    # Test 2: has_capability
    # ---------------------------------------------------------------
    print("Test 2: has_capability")
    print("-" * 25)

    assert_check(
        health.has_capability("health_check"),
        "has_capability('health_check') = True",
    )
    assert_check(
        health.has_capability("version_discovery"),
        "has_capability('version_discovery') = True",
    )
    assert_check(
        not health.has_capability("nonexistent_feature"),
        "has_capability('nonexistent_feature') = False",
    )
    print()

    # ---------------------------------------------------------------
    # Test 3: List all capabilities
    # ---------------------------------------------------------------
    print("Test 3: All Capabilities")
    print("-" * 25)
    for cap in health.capabilities:
        print(f"   - {cap.name} (since {cap.since}): {cap.description}")
    print()

    # ---------------------------------------------------------------
    # Test 4: SDK version info
    # ---------------------------------------------------------------
    print("Test 4: SDK Version")
    print("-" * 20)
    from axonflow import __version__

    print(f"   SDK version: {__version__}")
    assert_check(__version__ != "", "SDK version is non-empty")
    print()

    # ---------------------------------------------------------------
    # Summary
    # ---------------------------------------------------------------
    print("=" * 40)
    if failures:
        print(f"FAILED: {len(failures)} failures")
        for f in failures:
            print(f"  - {f}")
        return 1

    print("ALL PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
