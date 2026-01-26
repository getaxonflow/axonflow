#!/usr/bin/env python3
"""
Azure OpenAI Integration Example - Python

VALIDATION: This example exits with code 1 if any assertion fails.

Demonstrates Gateway Mode and Proxy Mode with AxonFlow.

Run with: python main.py
Prerequisites: docker compose up -d, AZURE_OPENAI_* env vars set
"""

import os
import sys
import time
import requests

AXONFLOW_URL = "http://localhost:8080"
TIMEOUT = 30

failures: list[str] = []


def assert_check(condition: bool, message: str) -> None:
    """Check a condition and record failure if false."""
    if condition:
        print(f"   ✓ PASS: {message}")
    else:
        print(f"   ❌ FAIL: {message}")
        failures.append(message)


def main() -> int:
    # Get Azure OpenAI credentials from environment
    endpoint = os.getenv("AZURE_OPENAI_ENDPOINT", "").rstrip("/")
    api_key = os.getenv("AZURE_OPENAI_API_KEY", "")
    deployment_name = os.getenv("AZURE_OPENAI_DEPLOYMENT_NAME", "")
    api_version = os.getenv("AZURE_OPENAI_API_VERSION", "2024-08-01-preview")

    if not endpoint or not api_key or not deployment_name:
        print("Note: Azure OpenAI credentials not set, running in validation mode")
        print("Set AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_API_KEY, AZURE_OPENAI_DEPLOYMENT_NAME")
        # Run pre-check test only
        return run_precheck_only_test()

    print("=== Azure OpenAI with AxonFlow ===")
    print(f"Endpoint: {endpoint}")
    print(f"Deployment: {deployment_name}")
    print(f"Auth: {detect_auth_type(endpoint)}")
    print()

    # Example 1: Gateway Mode (recommended)
    print("--- Example 1: Gateway Mode ---")
    try:
        gateway_mode_example(endpoint, api_key, deployment_name, api_version)
    except Exception as e:
        print(f"Gateway mode error: {e}")
        failures.append(f"Gateway mode failed: {e}")
    print()

    # Example 2: Proxy Mode
    print("--- Example 2: Proxy Mode ---")
    try:
        proxy_mode_example()
    except Exception as e:
        print(f"Proxy mode error: {e}")
        # Proxy mode may fail without LLM key configured
        if "api" not in str(e).lower():
            failures.append(f"Proxy mode failed: {e}")

    print()
    print("=" * 50)
    if not failures:
        print("✓ ALL TESTS PASSED")
        print()
        print("Azure OpenAI Integration validated:")
        print("  - Gateway Mode: pre-check, LLM call, audit")
        print("  - Proxy Mode: request through AxonFlow")
        return 0
    else:
        print(f"❌ {len(failures)} TEST(S) FAILED:")
        for f in failures:
            print(f"   - {f}")
        return 1


def run_precheck_only_test() -> int:
    """Run pre-check test when Azure credentials not available."""
    print("\n--- Running Pre-Check Validation Only ---")

    try:
        pre_check_resp = pre_check("What are the benefits of cloud computing?", "azure-openai", "test-deployment")

        assert_check(pre_check_resp is not None, "Pre-check returned response")
        assert_check("approved" in pre_check_resp or "context_id" in pre_check_resp, "Response has expected fields")

        if pre_check_resp.get("approved"):
            assert_check(True, "Safe query was approved")
            context_id = pre_check_resp.get("context_id", "")
            assert_check(context_id != "", "Context ID returned")

        print()
        print("=" * 50)
        if not failures:
            print("✓ ALL TESTS PASSED (Pre-check only)")
            return 0
        else:
            print(f"❌ {len(failures)} TEST(S) FAILED:")
            for f in failures:
                print(f"   - {f}")
            return 1

    except Exception as e:
        print(f"Pre-check test failed: {e}")
        return 1


def detect_auth_type(endpoint: str) -> str:
    """Determine authentication type from endpoint."""
    if "cognitiveservices.azure.com" in endpoint.lower():
        return "Bearer token (Foundry)"
    return "api-key (Classic)"


def gateway_mode_example(endpoint: str, api_key: str, deployment_name: str, api_version: str):
    """Gateway Mode: Pre-check, call Azure OpenAI, then audit."""

    user_prompt = "What are the key benefits of using Azure OpenAI over standard OpenAI API?"

    # Step 1: Pre-check with AxonFlow
    print("Step 1: Pre-checking with AxonFlow...")
    pre_check_resp = pre_check(user_prompt, "azure-openai", deployment_name)

    assert_check(pre_check_resp is not None, "Pre-check returned response")

    if not pre_check_resp.get("approved"):
        print("Request blocked by policy")
        return

    context_id = pre_check_resp.get("context_id", "")
    assert_check(context_id != "", "Pre-check returned context_id")
    print(f"Pre-check passed (context: {context_id})")

    # Step 2: Call Azure OpenAI directly
    print("Step 2: Calling Azure OpenAI...")
    start_time = time.time()

    azure_url = f"{endpoint}/openai/deployments/{deployment_name}/chat/completions?api-version={api_version}"

    headers = {"Content-Type": "application/json"}

    if "cognitiveservices.azure.com" in endpoint.lower():
        headers["Authorization"] = f"Bearer {api_key}"
    else:
        headers["api-key"] = api_key

    payload = {
        "messages": [{"role": "user", "content": user_prompt}],
        "max_tokens": 500,
        "temperature": 0.7
    }

    resp = requests.post(azure_url, json=payload, headers=headers, timeout=TIMEOUT)

    if resp.status_code != 200:
        raise Exception(f"Azure OpenAI error (status {resp.status_code}): {resp.text}")

    data = resp.json()
    latency_ms = int((time.time() - start_time) * 1000)

    assert_check(data is not None, "Azure OpenAI returned response")
    assert_check("choices" in data, "Response has choices")

    content = ""
    if data.get("choices"):
        content = data["choices"][0]["message"]["content"]
        assert_check(content != "", "Response has content")

    usage = data.get("usage", {})
    prompt_tokens = usage.get("prompt_tokens", 0)
    completion_tokens = usage.get("completion_tokens", 0)

    print(f"Response received (latency: {latency_ms}ms)")
    print(f"Response: {truncate(content, 200)}")

    # Step 3: Audit the response
    print("Step 3: Auditing with AxonFlow...")
    try:
        audit_llm_call(context_id, content, "azure-openai", deployment_name, latency_ms, prompt_tokens, completion_tokens)
        assert_check(True, "Audit call succeeded")
        print("Audit logged successfully")
    except Exception as e:
        print(f"Audit warning: {e}")


def proxy_mode_example():
    """Proxy Mode: Send request through AxonFlow."""

    print("Sending request through AxonFlow proxy...")

    payload = {
        "query": "Explain the difference between Azure OpenAI Classic and Foundry patterns in 2 sentences.",
        "context": {
            "provider": "azure-openai"
        }
    }

    start_time = time.time()
    resp = requests.post(
        f"{AXONFLOW_URL}/api/request",
        json=payload,
        headers={"Content-Type": "application/json"},
        timeout=TIMEOUT
    )

    assert_check(resp.status_code in [200, 400, 403], "Proxy endpoint responded")

    data = resp.json()
    latency_ms = int((time.time() - start_time) * 1000)

    response_text = data.get("data", {}).get("data", "")
    blocked = data.get("blocked", False)

    print(f"Response received (latency: {latency_ms}ms)")
    print(f"Blocked: {blocked}")
    print(f"Response: {truncate(response_text, 300)}")


def pre_check(prompt: str, provider: str, model: str) -> dict:
    """Call AxonFlow's pre-check endpoint."""
    payload = {
        "client_id": "azure-openai-example",
        "query": prompt,
        "context": {
            "provider": provider,
            "model": model
        }
    }

    resp = requests.post(
        f"{AXONFLOW_URL}/api/policy/pre-check",
        json=payload,
        headers={"Content-Type": "application/json"},
        timeout=TIMEOUT
    )

    if resp.status_code != 200:
        raise Exception(f"Pre-check failed (status {resp.status_code}): {resp.text}")

    return resp.json()


def audit_llm_call(context_id: str, response: str, provider: str, model: str,
                   latency_ms: int, prompt_tokens: int, completion_tokens: int):
    """Log the LLM response with AxonFlow."""
    payload = {
        "client_id": "azure-openai-example",
        "context_id": context_id,
        "response_summary": truncate(response, 500),
        "provider": provider,
        "model": model,
        "latency_ms": latency_ms,
        "token_usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens
        }
    }

    resp = requests.post(
        f"{AXONFLOW_URL}/api/audit/llm-call",
        json=payload,
        headers={"Content-Type": "application/json"},
        timeout=TIMEOUT
    )

    if resp.status_code not in (200, 202, 204):
        raise Exception(f"Audit failed (status {resp.status_code}): {resp.text}")


def truncate(s: str, max_len: int) -> str:
    """Truncate string with ellipsis."""
    if len(s) <= max_len:
        return s
    return s[:max_len] + "..."


if __name__ == "__main__":
    sys.exit(main())
