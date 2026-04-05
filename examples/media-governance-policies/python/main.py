#!/usr/bin/env python3
"""
AxonFlow Media Governance Policies - Python SDK

Demonstrates and VALIDATES media governance policy management:
  - Listing system media policies (NSFW, violence, biometric, PII, documents)
  - System NSFW policy evaluation with a clean image
  - Custom media policy CRUD (create, verify, process, delete)
  - Media governance config and status endpoints
  - Policy toggle lifecycle (create, disable, re-enable, delete)
  - Per-tenant media governance disable/enable (Enterprise only)
  - Non-media requests unaffected by media policies

All requests go through the agent entry point (AXONFLOW_ENDPOINT, default port 8080).
The agent proxies policy CRUD, media governance config, and ProxyLLMCall requests.

VALIDATION: This example exits with code 1 if any assertion fails.
This ensures CI/CD pipelines catch regressions.

Run with: python main.py
Prerequisites: docker compose up -d
"""

import asyncio
import os
import sys

from axonflow import (
    AxonFlow,
    CreateDynamicPolicyRequest,
    DynamicPolicyAction,
    DynamicPolicyCondition,
    ListDynamicPoliciesOptions,
    MediaContent,
    UpdateDynamicPolicyRequest,
    UpdateMediaGovernanceConfigRequest,
)

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


async def main() -> int:
    global pipeline_active

    agent_endpoint = get_env("AXONFLOW_ENDPOINT", "http://localhost:8080")
    client_id = get_env("AXONFLOW_CLIENT_ID", "demo")
    client_secret = get_env("AXONFLOW_CLIENT_SECRET", "demo")
    tenant_id = get_env("AXONFLOW_TENANT", client_id)
    is_debug = get_env("AXONFLOW_DEBUG", "") == "true"

    print("AxonFlow Media Governance Policies - Python SDK")
    print("=" * 50)
    print()
    print(f"  Agent endpoint: {agent_endpoint}")
    print(f"  Tenant ID:      {tenant_id}")
    print()

    # Single client: all requests go through the agent entry point
    async with AxonFlow(
        endpoint=agent_endpoint,
        client_id=client_id,
        client_secret=client_secret,
        debug=is_debug,
    ) as client:
        # ========================================
        # Test 1: Verify system media policies exist
        # ========================================
        print("Test 1: Verify system media policies exist")
        print("  Listing dynamic policies with type=media")
        print()

        try:
            policies = await client.list_dynamic_policies(
                ListDynamicPoliciesOptions(type="media", limit=100)
            )
        except Exception as e:
            print(f"   FATAL: list_dynamic_policies failed: {e}")
            return 1

        sys_media_policies = [p for p in policies if p.id.startswith("sys_media_")]
        assert_check(
            len(sys_media_policies) >= 5,
            f"At least 5 system media policies found (got {len(sys_media_policies)})",
        )

        # Verify expected categories
        categories: dict[str, int] = {}
        for p in sys_media_policies:
            cat = p.category or "unknown"
            categories[cat] = categories.get(cat, 0) + 1

        assert_check(
            categories.get("media-safety", 0) >= 2,
            f"media-safety category has >= 2 policies (got {categories.get('media-safety', 0)})",
        )
        assert_check(
            categories.get("media-biometric", 0) >= 1,
            f"media-biometric category has >= 1 policy (got {categories.get('media-biometric', 0)})",
        )
        assert_check(
            categories.get("media-pii", 0) >= 1,
            f"media-pii category has >= 1 policy (got {categories.get('media-pii', 0)})",
        )
        assert_check(
            categories.get("media-document", 0) >= 1,
            f"media-document category has >= 1 policy (got {categories.get('media-document', 0)})",
        )

        print()
        print("  System media policies:")
        for p in sys_media_policies:
            print(f"    - {p.id}: {p.name} [{p.category}]")
        print()

        # ========================================
        # Test 2: System NSFW policy -- clean image passes
        # ========================================
        print("Test 2: System NSFW policy evaluation -- clean image passes")
        print("  Sending 1x1 white JPEG via proxy_llm_call_with_media")
        print()

        try:
            resp2 = await client.proxy_llm_call_with_media(
                user_token="media-policy-user",
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

        assert_check(resp2.success, "Response is successful")
        assert_check(
            not getattr(resp2, "blocked", False),
            "Clean image is NOT blocked",
        )

        if resp2.media_analysis is not None:
            pipeline_active = True
            print("   PASS: media_analysis present (pipeline active)")
            if resp2.media_analysis.results:
                r = resp2.media_analysis.results[0]
                print(f"   NSFW score: {r.nsfw_score}")
                print(f"   Content safe: {r.content_safe}")
        else:
            print(
                "   WARNING: media_analysis absent -- media governance pipeline"
                " not active (requires platform v4.4.0+ with analyzers)"
            )
        print()

        # ========================================
        # Test 3: Custom media policy -- create and verify
        # ========================================
        print("Test 3: Custom media policy -- create and verify")
        print()

        # 3a. Create a tenant-tier policy: block if media.has_faces == true
        print("  3a. Creating custom media policy: block if media.has_faces == true")
        created_policy = None
        try:
            created_policy = await client.create_dynamic_policy(
                CreateDynamicPolicyRequest(
                    name="test-face-block-python-example",
                    description="Blocks images containing faces (Python example test policy)",
                    type="media",
                    category="media-safety",
                    conditions=[
                        DynamicPolicyCondition(
                            field="media.has_faces",
                            operator="equals",
                            value=True,
                        )
                    ],
                    actions=[
                        DynamicPolicyAction(
                            type="block",
                            config={"message": "Media blocked: faces detected in image"},
                        )
                    ],
                    priority=100,
                    enabled=True,
                )
            )
            assert_check(
                created_policy.id != "",
                f"Policy created with ID: {created_policy.id}",
            )
        except Exception as e:
            print(f"   FAIL: Failed to create policy: {e}")
            failures.append(f"Failed to create policy: {e}")

        # 3b. Verify it appears in the list
        print()
        print("  3b. Verifying policy appears in list")
        if created_policy:
            try:
                updated_list = await client.list_dynamic_policies(
                    ListDynamicPoliciesOptions(type="media", limit=100)
                )
                found = any(p.id == created_policy.id for p in updated_list)
                assert_check(found, "Created policy found in list")
            except Exception as e:
                print(f"   FAIL: list_dynamic_policies failed: {e}")
                failures.append(f"list_dynamic_policies after create failed: {e}")
        else:
            print("   SKIP: No policy ID to verify")

        # 3c. Send 1x1 image -- should NOT be blocked (no faces in a 1px image)
        print()
        print("  3c. Sending 1x1 image request (no faces expected)")
        try:
            resp3c = await client.proxy_llm_call_with_media(
                user_token="media-policy-user",
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
            assert_check(resp3c.success, "1x1 image request succeeded")
            assert_check(
                not getattr(resp3c, "blocked", False),
                "1x1 image NOT blocked by face policy (no faces in 1px image)",
            )
        except Exception as e:
            print(f"   FAIL: proxy_llm_call_with_media failed: {e}")
            failures.append(f"Test 3c proxy_llm_call_with_media failed: {e}")

        # 3d. Cleanup -- delete the custom policy
        print()
        print("  3d. Cleaning up: deleting custom policy")
        if created_policy:
            try:
                await client.delete_dynamic_policy(created_policy.id)
                assert_check(True, "Policy deleted successfully")
            except Exception as e:
                print(f"   FAIL: Failed to delete policy: {e}")
                failures.append(f"Failed to delete policy: {e}")
        else:
            print("   SKIP: No policy to delete")
        print()

        # ========================================
        # Test 4: Media governance config -- read status
        # ========================================
        print("Test 4: Media governance config -- read status")
        print()

        per_tenant_control = False

        # 4a. get_media_governance_status()
        print("  4a. get_media_governance_status()")
        try:
            status = await client.get_media_governance_status()

            assert_check(
                status.available is not None,
                f"Response contains 'available' field (available={status.available})",
            )
            assert_check(
                isinstance(status.tier, str) and len(status.tier) > 0,
                f"Tier is non-empty (got: {status.tier})",
            )

            per_tenant_control = status.per_tenant_control is True
            print(
                f"   Tier: {status.tier} | Available: {status.available}"
                f" | Per-tenant control: {per_tenant_control}"
            )
        except Exception as e:
            print(f"   FAIL: get_media_governance_status failed: {e}")
            failures.append(f"get_media_governance_status failed: {e}")

        # 4b. get_media_governance_config()
        print()
        print("  4b. get_media_governance_config()")
        try:
            config = await client.get_media_governance_config()

            assert_check(
                config.tenant_id is not None,
                f"Response contains 'tenant_id' field (got: {config.tenant_id})",
            )
            assert_check(
                config.enabled is not None,
                f"Response contains 'enabled' field (got: {config.enabled})",
            )

            print(
                f"   Tenant: {config.tenant_id}"
                f" | Enabled: {config.enabled}"
            )
        except Exception as e:
            print(f"   FAIL: get_media_governance_config failed: {e}")
            failures.append(f"get_media_governance_config failed: {e}")
        print()

        # ========================================
        # Test 5: Policy toggle lifecycle
        # ========================================
        print("Test 5: Policy toggle lifecycle (create -> disable -> re-enable -> delete)")
        print()

        # 5a. Create a media policy
        print("  5a. Creating media policy: media.nsfw_score > 0.5 -> block")
        toggle_policy = None
        try:
            toggle_policy = await client.create_dynamic_policy(
                CreateDynamicPolicyRequest(
                    name="test-nsfw-toggle-python-example",
                    description="NSFW threshold policy for toggle lifecycle test",
                    type="media",
                    category="media-safety",
                    conditions=[
                        DynamicPolicyCondition(
                            field="media.nsfw_score",
                            operator="greater_than",
                            value=0.5,
                        )
                    ],
                    actions=[
                        DynamicPolicyAction(
                            type="block",
                            config={
                                "message": "Media blocked: NSFW score exceeds threshold (> 0.5)"
                            },
                        )
                    ],
                    priority=200,
                    enabled=True,
                )
            )
            assert_check(
                toggle_policy.id != "",
                f"Policy created with ID: {toggle_policy.id}",
            )
            assert_check(
                toggle_policy.enabled is True,
                f"Policy initially enabled (enabled={toggle_policy.enabled})",
            )
        except Exception as e:
            print(f"   FAIL: Failed to create toggle policy: {e}")
            failures.append(f"Failed to create toggle policy: {e}")

        # 5b. Disable the policy
        print()
        print("  5b. Disabling policy (update enabled=false)")
        if toggle_policy:
            try:
                disabled = await client.update_dynamic_policy(
                    toggle_policy.id,
                    UpdateDynamicPolicyRequest(enabled=False),
                )
                assert_check(
                    disabled.enabled is False,
                    f"Policy is now disabled (enabled={disabled.enabled})",
                )
            except Exception as e:
                print(f"   FAIL: Failed to disable policy: {e}")
                failures.append(f"Failed to disable policy: {e}")
        else:
            print("   SKIP: No policy ID for toggle test")

        # 5c. Re-enable the policy
        print()
        print("  5c. Re-enabling policy (update enabled=true)")
        if toggle_policy:
            try:
                reenabled = await client.update_dynamic_policy(
                    toggle_policy.id,
                    UpdateDynamicPolicyRequest(enabled=True),
                )
                assert_check(
                    reenabled.enabled is True,
                    f"Policy is now re-enabled (enabled={reenabled.enabled})",
                )
            except Exception as e:
                print(f"   FAIL: Failed to re-enable policy: {e}")
                failures.append(f"Failed to re-enable policy: {e}")
        else:
            print("   SKIP: No policy ID for toggle test")

        # 5d. Cleanup
        print()
        print("  5d. Cleaning up: deleting toggle test policy")
        if toggle_policy:
            try:
                await client.delete_dynamic_policy(toggle_policy.id)
                assert_check(True, "Toggle policy deleted successfully")
            except Exception as e:
                print(f"   FAIL: Failed to delete toggle policy: {e}")
                failures.append(f"Failed to delete toggle policy: {e}")
        else:
            print("   SKIP: No policy to delete")
        print()

        # ========================================
        # Test 6: Media governance disable/enable (Enterprise only)
        # ========================================
        print("Test 6: Media governance disable/enable (per-tenant config)")
        print()

        if per_tenant_control:
            print("  Enterprise mode detected -- testing per-tenant media governance toggle")
            print()

            # 6a. Disable media governance for this tenant
            print("  6a. Disabling media governance (update_media_governance_config enabled=false)")
            try:
                mg_disabled = await client.update_media_governance_config(
                    UpdateMediaGovernanceConfigRequest(enabled=False)
                )
                assert_check(
                    mg_disabled.enabled is False,
                    f"Media governance disabled (enabled={mg_disabled.enabled})",
                )
            except Exception as e:
                print(f"   FAIL: Failed to disable media governance: {e}")
                failures.append(f"Failed to disable media governance: {e}")

            # 6b. Send media request -- media_analysis should be absent
            print()
            print("  6b. Sending image request with media governance disabled")
            try:
                resp6b = await client.proxy_llm_call_with_media(
                    user_token="media-policy-user",
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
                assert_check(resp6b.success, "Request still succeeds with governance disabled")
                assert_check(
                    resp6b.media_analysis is None,
                    "media_analysis absent when governance disabled",
                )
            except Exception as e:
                print(f"   FAIL: proxy_llm_call_with_media failed: {e}")
                failures.append(f"Test 6b proxy_llm_call_with_media failed: {e}")

            # 6c. Re-enable media governance
            print()
            print("  6c. Re-enabling media governance (update_media_governance_config enabled=true)")
            try:
                mg_enabled = await client.update_media_governance_config(
                    UpdateMediaGovernanceConfigRequest(enabled=True)
                )
                assert_check(
                    mg_enabled.enabled is True,
                    f"Media governance re-enabled (enabled={mg_enabled.enabled})",
                )
            except Exception as e:
                print(f"   FAIL: Failed to re-enable media governance: {e}")
                failures.append(f"Failed to re-enable media governance: {e}")

            # 6d. Send media request -- check media_analysis returns
            print()
            print("  6d. Sending image request with media governance re-enabled")
            try:
                resp6d = await client.proxy_llm_call_with_media(
                    user_token="media-policy-user",
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
                assert_check(resp6d.success, "Request succeeds after re-enable")
                if resp6d.media_analysis is not None:
                    print("   PASS: media_analysis present after re-enable")
                else:
                    print(
                        "   WARNING: media_analysis absent after re-enable"
                        " (analyzers may not be active in this environment)"
                    )
            except Exception as e:
                print(f"   FAIL: proxy_llm_call_with_media failed: {e}")
                failures.append(f"Test 6d proxy_llm_call_with_media failed: {e}")
        else:
            print("  SKIP: Per-tenant media governance control requires Enterprise license.")
            print("  Community/Evaluation tiers use the global media governance setting.")
            print("  To test this, run with an Enterprise license key set in AXONFLOW_LICENSE_KEY.")
        print()

        # ========================================
        # Test 7: Non-media request unaffected
        # ========================================
        print("Test 7: Non-media request unaffected by media policies")
        print("  Sending text-only query via proxy_llm_call")
        print()

        try:
            resp7 = await client.proxy_llm_call(
                user_token="media-policy-user",
                query="What is the capital of France?",
                request_type="chat",
            )
        except Exception as e:
            print(f"   FATAL: proxy_llm_call failed: {e}")
            return 1

        assert_check(resp7.success, "Text-only request is successful")
        assert_check(
            resp7.media_analysis is None,
            "No media_analysis present for text-only request",
        )
        print()

        # ========================================
        # Summary
        # ========================================
        print("=" * 50)

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
            print("Media governance policy capabilities validated:")
            print("  - System media policies (NSFW, violence, biometric, PII, documents)")
            print("  - Clean image passes system policies")
            print("  - Custom media policy CRUD (create, verify, process, delete)")
            print("  - Media governance config and status endpoints")
            print("  - Policy toggle lifecycle (create, disable, re-enable, delete)")
            if per_tenant_control:
                print("  - Per-tenant media governance disable/enable (Enterprise)")
            print("  - Non-media requests unaffected by media policies")
            return 0
        else:
            print(f"{len(failures)} TEST(S) FAILED:")
            for f in failures:
                print(f"   - {f}")
            return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
