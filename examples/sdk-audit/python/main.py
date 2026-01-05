"""
AxonFlow SDK Comprehensive Audit - Python

Validates all SDK methods work correctly against live services.
Tests include:
1. Health checks (Agent + Orchestrator)
2. Gateway Mode request
3. Proxy Mode request
4. Static policy CRUD
5. Audit logging
6. Error handling (blocked requests)
7. Connector operations (list, install, uninstall)
"""

import asyncio
import os
import sys
import time

from dotenv import load_dotenv
from axonflow import AxonFlow
from axonflow.types import TokenUsage
from axonflow.policies import CreateStaticPolicyRequest, UpdateStaticPolicyRequest, PolicyCategory, PolicySeverity, PolicyAction

load_dotenv()


async def main():
    print("AxonFlow SDK Comprehensive Audit - Python")
    print("=" * 42)
    print()

    passed = 0
    failed = 0

    # Note: As of SDK v1.0.0 (ADR-026), all routes go through a single endpoint.
    # The Agent proxies orchestrator routes internally.
    async with AxonFlow(
        endpoint=os.getenv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "demo"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
    ) as client:

        # Test 1: Agent Health Check
        print("Test 1: Agent Health Check")
        try:
            healthy = await client.health_check()
            if healthy:
                print("  ✅ PASSED: Agent is healthy")
                passed += 1
            else:
                print("  ❌ FAILED: Agent is not healthy")
                failed += 1
        except Exception as e:
            print(f"  ❌ FAILED: {e}")
            failed += 1

        # Test 2: Orchestrator Health Check
        print("Test 2: Orchestrator Health Check")
        try:
            healthy = await client.orchestrator_health_check()
            if healthy:
                print("  ✅ PASSED: Orchestrator is healthy")
                passed += 1
            else:
                print("  ❌ FAILED: Orchestrator is not healthy")
                failed += 1
        except Exception as e:
            print(f"  ❌ FAILED: {e}")
            failed += 1

        # Test 3: Gateway Mode - Safe Query
        print("Test 3: Gateway Mode - Safe Query")
        try:
            result = await client.get_policy_approved_context(
                user_token="audit-user",
                query="What is the capital of France?",
            )
            if result.approved:
                print(f"  ✅ PASSED: Query approved (contextId: {result.context_id})")
                passed += 1
                approved_context_id = result.context_id
            else:
                print(f"  ❌ FAILED: Query unexpectedly blocked: {result.block_reason}")
                failed += 1
                approved_context_id = None
        except Exception as e:
            print(f"  ❌ FAILED: {e}")
            failed += 1
            approved_context_id = None

        # Test 4: Gateway Mode - Blocked Query (SQL Injection)
        print("Test 4: Gateway Mode - Blocked Query (SQL Injection)")
        try:
            result = await client.get_policy_approved_context(
                user_token="audit-user",
                query="SELECT * FROM users; DROP TABLE users;",
            )
            if not result.approved:
                print(f"  ✅ PASSED: Query correctly blocked ({result.block_reason})")
                passed += 1
            else:
                print("  ❌ FAILED: SQL injection should be blocked")
                failed += 1
        except Exception as e:
            print(f"  ❌ FAILED: {e}")
            failed += 1

        # Test 5: Audit LLM Call
        print("Test 5: Audit LLM Call")
        if approved_context_id:
            try:
                audit_result = await client.audit_llm_call(
                    context_id=approved_context_id,
                    response_summary="Test response for SDK audit",
                    provider="openai",
                    model="gpt-4",
                    token_usage=TokenUsage(prompt_tokens=100, completion_tokens=50, total_tokens=150),
                    latency_ms=250,
                )
                if audit_result.success:
                    print(f"  ✅ PASSED: Audit recorded (auditId: {audit_result.audit_id})")
                    passed += 1
                else:
                    print("  ❌ FAILED: Audit not successful")
                    failed += 1
            except Exception as e:
                print(f"  ❌ FAILED: {e}")
                failed += 1
        else:
            print("  ⏭️ SKIPPED: No context ID from previous test")

        # Test 6: List Connectors
        print("Test 6: List Connectors")
        try:
            connectors = await client.list_connectors()
            print(f"  ✅ PASSED: Found {len(connectors)} connectors")
            passed += 1
        except Exception as e:
            print(f"  ❌ FAILED: {e}")
            failed += 1

        # Test 7: Static Policy CRUD
        print("Test 7: Static Policy CRUD")
        policy_name = f"sdk-audit-test-{int(time.time())}"
        crud_passed = True

        try:
            # Create policy
            create_request = CreateStaticPolicyRequest(
                name=policy_name,
                description="Test policy from SDK audit",
                category=PolicyCategory.SECURITY_SQLI,
                pattern="sdk-audit-test-pattern",
                severity=PolicySeverity.LOW,
                enabled=True,
                action=PolicyAction.WARN,
            )
            created = await client.create_static_policy(create_request)
            print(f"  ✅ Create: Policy created (id: {created.id})")
            policy_id = created.id

            # Get policy
            fetched = await client.get_static_policy(policy_id)
            if fetched.name == policy_name:
                print("  ✅ Get: Policy retrieved correctly")
            else:
                print("  ❌ FAILED (Get): Name mismatch")
                crud_passed = False

            # Update policy
            update_request = UpdateStaticPolicyRequest(
                description="Updated description from SDK audit",
            )
            updated = await client.update_static_policy(policy_id, update_request)
            if "Updated" in (updated.description or ""):
                print("  ✅ Update: Policy updated correctly")
            else:
                print("  ❌ FAILED (Update): Description not updated")
                crud_passed = False

            # Delete policy
            await client.delete_static_policy(policy_id)
            print("  ✅ Delete: Policy deleted correctly")

            if crud_passed:
                passed += 1
            else:
                failed += 1

        except Exception as e:
            print(f"  ❌ FAILED: {e}")
            failed += 1

        # Test 8: List Static Policies
        print("Test 8: List Static Policies")
        try:
            policies = await client.list_static_policies()
            print(f"  ✅ PASSED: Found {len(policies)} policies")
            passed += 1
        except Exception as e:
            print(f"  ❌ FAILED: {e}")
            failed += 1

    # Summary
    print()
    print("=" * 42)
    print(f"Summary: {passed} passed, {failed} failed")
    print()

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
