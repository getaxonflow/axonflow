#!/usr/bin/env python3
"""Cloud Storage Connector Example - Python SDK

Tests S3 cloud storage connector operations via the AxonFlow Python SDK.
Uses MinIO as S3-compatible backend (started by docker compose).

VALIDATION: This example exits with code 1 if any assertion fails.

Usage:
    docker compose up -d
    cd examples/mcp-connectors/cloud-storage/python
    pip install -r requirements.txt
    python main.py
"""

import os
import sys
import time

from axonflow import AxonFlow, AxonFlowConfig

failures = []


def assert_check(condition: bool, message: str) -> None:
    if condition:
        print(f"   PASS: {message}")
    else:
        print(f"   FAIL: {message}")
        failures.append(message)


def data_to_rows(data):
    """Convert ConnectorResponse.data to a list of dicts."""
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    return []


def main() -> None:
    endpoint = os.environ.get("AXONFLOW_ENDPOINT", "http://localhost:8080")
    client_id = os.environ.get("AXONFLOW_CLIENT_ID", "test-client")
    client_secret = os.environ.get("AXONFLOW_CLIENT_SECRET", "test-secret")

    config = AxonFlowConfig.builder().endpoint(endpoint).client_id(client_id).client_secret(client_secret).build()
    client = AxonFlow.create(config)

    test_key = f"test-object-{int(time.time() * 1000)}.txt"
    test_content = f"Hello from AxonFlow Python SDK cloud storage example - {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}"
    bucket = "axonflow-test-bucket"

    print("==============================================")
    print("Cloud Storage Connector - Python SDK Example")
    print("==============================================")
    print(f"Endpoint: {endpoint}")
    print(f"Test key: {test_key}")
    print()

    # Test 1: Verify S3 connector is registered
    print("Test 1: Verify S3 connector is registered...")
    print("----------------------------------------------")

    try:
        connectors = client.list_connectors()
        types = [c.type for c in connectors]
        assert_check("s3" in types, "S3 connector is registered")
    except Exception as e:
        print(f"  Error: {e}")
        assert_check(False, "List connectors succeeded")
    print()

    # Test 2: Put object
    print("Test 2: Put object to S3 (MinIO)...")
    print("----------------------------------------------")

    try:
        put_resp = client.mcp_execute(
            connector="s3",
            action="put_object",
            params={"bucket": bucket, "key": test_key, "content": test_content, "content_type": "text/plain"},
        )
        assert_check(put_resp.success, "Put object succeeded")
    except Exception as e:
        print(f"  Error: {e}")
        assert_check(False, "Put object succeeded")
    print()

    # Test 3: Get object and verify content
    print("Test 3: Get object and verify content...")
    print("----------------------------------------------")

    try:
        get_resp = client.mcp_query(
            connector="s3",
            statement="get_object",
            params={"bucket": bucket, "key": test_key},
        )
        rows = data_to_rows(get_resp.data)
        assert_check(len(rows) > 0, "Get object returned data")

        if rows:
            content = rows[0].get("content", "")
            assert_check("Hello from AxonFlow Python SDK" in content, "Content matches uploaded data")

        assert_check(get_resp.policy_info is not None, "Policy info present in response")
    except Exception as e:
        print(f"  Error: {e}")
        assert_check(False, "Get object returned data")
    print()

    # Test 4: List objects and verify key
    print("Test 4: List objects and verify key exists...")
    print("----------------------------------------------")

    try:
        list_resp = client.mcp_query(
            connector="s3",
            statement="list_objects",
            params={"bucket": bucket, "prefix": "test-object-"},
        )
        rows = data_to_rows(list_resp.data)
        assert_check(len(rows) > 0, "List objects returned results")

        keys = [r.get("key", "") for r in rows]
        assert_check(test_key in keys, "Uploaded key found in listing")
    except Exception as e:
        print(f"  Error: {e}")
        assert_check(False, "List objects returned results")
    print()

    # Test 5: Head object metadata
    print("Test 5: Head object metadata...")
    print("----------------------------------------------")

    try:
        head_resp = client.mcp_query(
            connector="s3",
            statement="head_object",
            params={"bucket": bucket, "key": test_key},
        )
        rows = data_to_rows(head_resp.data)
        assert_check(len(rows) > 0, "Head object returned metadata")

        if rows:
            ct = rows[0].get("content_type", "")
            assert_check("text/plain" in ct, "Content-Type is text/plain")

            size = rows[0].get("content_length", rows[0].get("size", 0))
            assert_check(int(size) > 0, "Object has non-zero size")
    except Exception as e:
        print(f"  Error: {e}")
        assert_check(False, "Head object returned metadata")
    print()

    # Test 6: Delete object
    print("Test 6: Delete object...")
    print("----------------------------------------------")

    try:
        del_resp = client.mcp_execute(
            connector="s3",
            action="delete_object",
            params={"bucket": bucket, "key": test_key},
        )
        assert_check(del_resp.success, "Delete object succeeded")
    except Exception as e:
        print(f"  Error: {e}")
        assert_check(False, "Delete object succeeded")
    print()

    # Test 7: Verify deletion
    print("Test 7: Verify object was deleted...")
    print("----------------------------------------------")

    try:
        verify_resp = client.mcp_query(
            connector="s3",
            statement="list_objects",
            params={"bucket": bucket, "prefix": test_key},
        )
        rows = data_to_rows(verify_resp.data)
        keys = [r.get("key", "") for r in rows]
        assert_check(test_key not in keys, "Deleted object no longer in listing")
    except Exception as e:
        print(f"  Error: {e}")
        assert_check(False, "Deleted object no longer in listing")
    print()

    # Results
    print("==============================================")
    if failures:
        print(f"FAILED: {len(failures)} assertions failed")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)

    print("ALL ASSERTIONS PASSED - Cloud storage connector tests verified!")
    print("==============================================")


if __name__ == "__main__":
    main()
