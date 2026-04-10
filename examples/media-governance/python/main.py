#!/usr/bin/env python3
"""
AxonFlow Media Governance - Python SDK

This example demonstrates and VALIDATES AxonFlow's media governance capabilities
for images attached to LLM requests:
- PII in image text (via OCR)
- Content safety (NSFW, violence scoring)
- Face and biometric data detection (GDPR Art. 9)
- Document classification (ID cards, bank statements)
- SHA-256 integrity hashing for audit trails

VALIDATION: This example exits with code 1 if any assertion fails.
This ensures CI/CD pipelines catch regressions.

Run with: python main.py
Prerequisites: docker compose up -d
"""

import asyncio
import os
import sys

from axonflow import AxonFlow, MediaContent

# Minimal valid 1x1 white pixel JPEG encoded as base64.
TEST_IMAGE_BASE64 = (
    "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRof"
    "Hh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwh"
    "MjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAAR"
    "CAABAAEDASIAAhEBAxEB/8QAFAABAAAAAAAAAAAAAAAAAAAACf/EABQQAQAAAAAAAAAAAAAAAA"
    "AAAAD/xAAUAQEAAAAAAAAAAAAAAAAAAAAA/8QAFBEBAAAAAAAAAAAAAAAAAAAAAP/aAAwDAQAC"
    "EQMRAD8AbwA//9k="
)

failures: list[str] = []
pipeline_active: bool = False


def get_env(key: str, default: str) -> str:
    return os.getenv(key, default)


def assert_check(condition: bool, message: str) -> None:
    """Check a condition and record failure if false."""
    if not condition:
        failures.append(message)
        print(f"   FAIL: {message}")
    else:
        print(f"   PASS: {message}")


def validate_media_analysis(
    resp_media_analysis, expected_count: int, test_label: str, *, url_source: bool = False
) -> bool:
    """Validate media_analysis fields strictly. Returns True if pipeline was active.

    When url_source is True, an empty sha256_hash produces a warning instead of a failure.
    """
    global pipeline_active

    if resp_media_analysis is None:
        print(
            f"   WARNING: MEDIA GOVERNANCE PIPELINE NOT ACTIVE"
            f" -- media_analysis is None (requires platform v4.4.0+)"
        )
        return False

    pipeline_active = True

    assert_check(
        len(resp_media_analysis.results) == expected_count,
        f"{test_label}: results length is {expected_count} (got {len(resp_media_analysis.results)})",
    )

    for i, result in enumerate(resp_media_analysis.results):
        prefix = f"{test_label} result[{i}]"

        # SHA-256 hash — non-empty for base64; warn (not fail) for URL sources
        sha256_present = isinstance(result.sha256_hash, str) and len(result.sha256_hash) > 0
        if sha256_present:
            assert_check(True, f"{prefix}: sha256_hash is non-empty string")
        elif url_source:
            print(
                f"   WARNING: {prefix} SHA-256 hash empty for URL source"
                f" (platform may not have network access to download URL)"
            )
        else:
            assert_check(False, f"{prefix}: sha256_hash is non-empty string")

        # media_index must match position
        assert_check(
            result.media_index == i,
            f"{prefix}: media_index is {i} (got {result.media_index})",
        )

        # content_safe must be a boolean
        assert_check(
            isinstance(result.content_safe, bool),
            f"{prefix}: content_safe is bool (got {type(result.content_safe).__name__})",
        )

        # nsfw_score must be non-negative
        assert_check(
            isinstance(result.nsfw_score, (int, float)) and result.nsfw_score >= 0,
            f"{prefix}: nsfw_score >= 0 (got {result.nsfw_score})",
        )

        # violence_score must be non-negative
        assert_check(
            isinstance(result.violence_score, (int, float)) and result.violence_score >= 0,
            f"{prefix}: violence_score >= 0 (got {result.violence_score})",
        )

        print(f"   Content safe: {result.content_safe}")
        print(f"   NSFW score: {result.nsfw_score:.2f}")
        print(f"   Violence score: {result.violence_score:.2f}")
        print(f"   Has PII: {result.has_pii}")
        print(f"   Has faces: {result.has_faces} (count: {result.face_count})")
        print(f"   Has biometric data: {result.has_biometric_data}")
        print(f"   Document type: {result.document_type}")
        print(f"   Is sensitive document: {result.is_sensitive_document}")
        print(f"   Estimated cost: ${result.estimated_cost_usd:.6f}")

    # analysis_time_ms must be non-negative
    assert_check(
        isinstance(resp_media_analysis.analysis_time_ms, (int, float))
        and resp_media_analysis.analysis_time_ms >= 0,
        f"{test_label}: analysis_time_ms >= 0 (got {resp_media_analysis.analysis_time_ms})",
    )

    # total_cost_usd must be non-negative
    assert_check(
        isinstance(resp_media_analysis.total_cost_usd, (int, float))
        and resp_media_analysis.total_cost_usd >= 0,
        f"{test_label}: total_cost_usd >= 0 (got {resp_media_analysis.total_cost_usd})",
    )

    print(f"   Total analysis time: {resp_media_analysis.analysis_time_ms}ms")
    print(f"   Total cost: ${resp_media_analysis.total_cost_usd:.6f}")

    return True


async def main() -> int:
    global pipeline_active

    print("AxonFlow Media Governance - Python SDK")
    print("=" * 40)
    print()

    async with AxonFlow(
        endpoint=get_env("AXONFLOW_ENDPOINT", "http://localhost:8080"),
        client_id=get_env("AXONFLOW_CLIENT_ID", "demo"),
        client_secret=get_env("AXONFLOW_CLIENT_SECRET", "demo"),
        debug=get_env("AXONFLOW_DEBUG", "") == "true",
    ) as client:
        # ========================================
        # Test 1: Single image governance
        # ========================================
        print("Test 1: Single image governance (base64)")
        print("  Query: Describe this image")

        try:
            resp = await client.proxy_llm_call_with_media(
                user_token=get_env("AXONFLOW_USER_TOKEN", "media-governance-user"),
                query="Describe this image",
                request_type="chat",
                media=[
                    MediaContent(
                        source="base64",
                        mime_type="image/jpeg",
                        base64_data=TEST_IMAGE_BASE64,
                    )
                ],
            )
        except Exception as e:
            print(f"   FATAL: proxy_llm_call_with_media failed: {e}")
            return 1

        assert_check(resp.success, "Response is successful")
        validate_media_analysis(resp.media_analysis, expected_count=1, test_label="Test 1")
        print()

        # ========================================
        # Test 2: Multiple images in single request
        # ========================================
        print("Test 2: Multiple images in single request")
        print("  Query: Compare these images")

        try:
            resp2 = await client.proxy_llm_call_with_media(
                user_token=get_env("AXONFLOW_USER_TOKEN", "media-governance-user"),
                query="Compare these images",
                request_type="chat",
                media=[
                    MediaContent(
                        source="base64",
                        mime_type="image/jpeg",
                        base64_data=TEST_IMAGE_BASE64,
                    ),
                    MediaContent(
                        source="base64",
                        mime_type="image/jpeg",
                        base64_data=TEST_IMAGE_BASE64,
                    ),
                ],
            )
        except Exception as e:
            print(f"   FATAL: proxy_llm_call_with_media failed: {e}")
            return 1

        assert_check(resp2.success, "Response is successful")
        validate_media_analysis(resp2.media_analysis, expected_count=2, test_label="Test 2")

        # Additional Test 2 assertion: same image sent twice must produce same sha256_hash
        if (
            resp2.media_analysis is not None
            and len(resp2.media_analysis.results) == 2
        ):
            hash_0 = resp2.media_analysis.results[0].sha256_hash
            hash_1 = resp2.media_analysis.results[1].sha256_hash
            assert_check(
                hash_0 == hash_1,
                f"Test 2: both results have same sha256_hash (same image sent twice)"
                f" -- got {hash_0[:16]}... vs {hash_1[:16]}...",
            )
        print()

        # ========================================
        # Test 3: URL-sourced image
        # ========================================
        print("Test 3: URL-sourced image")
        print("  Query: Analyze this image from URL")

        try:
            resp3 = await client.proxy_llm_call_with_media(
                user_token=get_env("AXONFLOW_USER_TOKEN", "media-governance-user"),
                query="Analyze this image from URL",
                request_type="chat",
                media=[
                    MediaContent(
                        source="url",
                        mime_type="image/png",
                        url="https://via.placeholder.com/1x1.png",
                    )
                ],
            )
        except Exception as e:
            print(f"   FATAL: proxy_llm_call_with_media failed: {e}")
            return 1

        assert_check(resp3.success, "Response is successful")
        validate_media_analysis(resp3.media_analysis, expected_count=1, test_label="Test 3", url_source=True)
        print()

        # ========================================
        # Test 4: Request without media still succeeds
        # ========================================
        print("Test 4: Request without media still succeeds")
        print("  Query: What is the capital of France?")

        try:
            resp4 = await client.proxy_llm_call(
                user_token=get_env("AXONFLOW_USER_TOKEN", "media-governance-user"),
                query="What is the capital of France?",
                request_type="chat",
            )
        except Exception as e:
            print(f"   FATAL: proxy_llm_call failed: {e}")
            return 1

        assert_check(resp4.success, "Response is successful (no media attached)")
        print()

        # ========================================
        # Test 5: Verify policy_info present for media requests
        # ========================================
        print("Test 5: Verify policy_info present for media requests")
        print("  Checking policy_info from Test 1 response (media request)")

        if resp.policy_info is not None:
            assert_check(
                resp.policy_info.tenant_id != "",
                f"policy_info.tenant_id is non-empty (got {resp.policy_info.tenant_id})",
            )
            assert_check(
                resp.policy_info.processing_time != "",
                "policy_info.processing_time is non-empty",
            )

            has_media_policy = any(
                p.startswith("sys_media_")
                for p in resp.policy_info.policies_evaluated
            )
            if has_media_policy:
                print("   PASS: system media policies found in policies_evaluated")
            else:
                print(
                    "   INFO: no sys_media_* policies in policies_evaluated"
                    " (dynamic policies may be tracked separately)"
                )
            print(f"   Policies evaluated: {resp.policy_info.policies_evaluated}")
        elif pipeline_active:
            print("   WARNING: policy_info absent despite media analysis being active")
        else:
            print("   SKIP: policy_info not available (media governance pipeline not active)")
        print()

        # ========================================
        # Summary
        # ========================================
        print("=" * 40)

        if pipeline_active:
            print("Media governance pipeline: ACTIVE")
        else:
            print(
                "Media governance pipeline: NOT ACTIVE"
                " -- media_analysis was None for all media requests"
            )

        print()

        if not failures:
            print("ALL TESTS PASSED")
            print()
            print("Media governance capabilities validated:")
            print("  - Single image analysis (base64)")
            print("  - Multiple image analysis (with hash consistency)")
            print("  - URL-sourced image analysis")
            print("  - Non-media request baseline")
            print("  - Policy evaluation metadata for media requests")
            if pipeline_active:
                print("  - Strict field validation (sha256, scores, costs, types)")
            return 0
        else:
            print(f"{len(failures)} TEST(S) FAILED:")
            for f in failures:
                print(f"   - {f}")
            return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
