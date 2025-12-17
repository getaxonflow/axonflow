"""
AxonFlow Policy Management - CRUD Operations

This example demonstrates how to manage policies via the AxonFlow API:
- List static policies (pattern-based, from Agent)
- List dynamic policies (condition-based, from Orchestrator)
- Create custom policies
- Update policies
- Delete policies

Static Policies: Pattern-matching rules (SQL injection, PII detection)
Dynamic Policies: Condition-based rules (RBAC, rate limiting, risk scoring)
"""

import asyncio
import os
from typing import Optional

import httpx
from dotenv import load_dotenv

load_dotenv()


class PolicyClient:
    """Client for AxonFlow Policy Management API."""

    def __init__(
        self,
        agent_url: str,
        orchestrator_url: str,
        client_secret: str,
        tenant_id: str,
    ):
        self.agent_url = agent_url.rstrip("/")
        self.orchestrator_url = orchestrator_url.rstrip("/")
        self.headers = {
            "Content-Type": "application/json",
            "X-Client-Secret": client_secret,
            "X-Tenant-ID": tenant_id,
        }
        self.client = httpx.AsyncClient(headers=self.headers, timeout=30.0)

    async def close(self):
        await self.client.aclose()

    # =========================================================================
    # Static Policies (Agent - Pattern-based)
    # =========================================================================

    async def list_static_policies(
        self,
        category: Optional[str] = None,
        page: int = 1,
        limit: int = 20,
    ) -> dict:
        """List static policies from Agent."""
        params = {"page": page, "limit": limit}
        if category:
            params["category"] = category

        resp = await self.client.get(
            f"{self.agent_url}/api/v1/static-policies",
            params=params,
        )
        resp.raise_for_status()
        return resp.json()

    async def get_static_policy(self, policy_id: str) -> dict:
        """Get a specific static policy."""
        resp = await self.client.get(
            f"{self.agent_url}/api/v1/static-policies/{policy_id}"
        )
        resp.raise_for_status()
        return resp.json()

    # =========================================================================
    # Dynamic Policies (Orchestrator - Condition-based)
    # =========================================================================

    async def list_dynamic_policies(self) -> dict:
        """List dynamic policies from Orchestrator."""
        resp = await self.client.get(
            f"{self.orchestrator_url}/api/v1/policies/dynamic"
        )
        resp.raise_for_status()
        return resp.json()

    async def list_tenant_policies(self) -> dict:
        """List tenant-specific policies."""
        resp = await self.client.get(
            f"{self.orchestrator_url}/api/v1/policies"
        )
        resp.raise_for_status()
        return resp.json()

    async def create_policy(self, policy: dict) -> dict:
        """Create a new dynamic policy."""
        resp = await self.client.post(
            f"{self.orchestrator_url}/api/v1/policies",
            json=policy,
        )
        resp.raise_for_status()
        return resp.json()

    async def get_policy(self, policy_id: str) -> dict:
        """Get a specific dynamic policy."""
        resp = await self.client.get(
            f"{self.orchestrator_url}/api/v1/policies/{policy_id}"
        )
        resp.raise_for_status()
        return resp.json()

    async def update_policy(self, policy_id: str, policy: dict) -> dict:
        """Update an existing dynamic policy."""
        resp = await self.client.put(
            f"{self.orchestrator_url}/api/v1/policies/{policy_id}",
            json=policy,
        )
        resp.raise_for_status()
        return resp.json()

    async def delete_policy(self, policy_id: str) -> None:
        """Delete a dynamic policy."""
        resp = await self.client.delete(
            f"{self.orchestrator_url}/api/v1/policies/{policy_id}"
        )
        resp.raise_for_status()


async def main():
    print("AxonFlow Policy Management - CRUD Operations")
    print("=" * 60)

    client = PolicyClient(
        agent_url=os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
        orchestrator_url=os.getenv("AXONFLOW_ORCHESTRATOR_URL", "http://localhost:8081"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
        tenant_id=os.getenv("AXONFLOW_TENANT_ID", "test-org-001"),
    )

    try:
        # =====================================================================
        # 1. List Static Policies (Agent)
        # =====================================================================
        print("\n" + "-" * 60)
        print("1. LIST STATIC POLICIES (Pattern-based)")
        print("-" * 60)

        static_policies = await client.list_static_policies(limit=5)
        policies = static_policies.get("policies", static_policies.get("data", []))

        print(f"\n  Found {len(policies)} static policies (showing first 5):")
        for p in policies[:5]:
            print(f"    - {p.get('name', p.get('id'))}: {p.get('description', '')[:50]}")

        # Show categories
        categories = set(p.get("category", "unknown") for p in policies)
        print(f"\n  Categories: {', '.join(categories)}")

        # =====================================================================
        # 2. List Dynamic Policies (Orchestrator)
        # =====================================================================
        print("\n" + "-" * 60)
        print("2. LIST DYNAMIC POLICIES (Condition-based)")
        print("-" * 60)

        try:
            dynamic_policies = await client.list_dynamic_policies()
            # API may return list directly or wrapped in dict
            if isinstance(dynamic_policies, list):
                dyn_list = dynamic_policies
            else:
                dyn_list = dynamic_policies.get("policies", dynamic_policies.get("data", []))

            print(f"\n  Found {len(dyn_list)} dynamic policies:")
            for p in dyn_list[:5]:
                print(f"    - {p.get('name', p.get('id'))}: {p.get('description', '')[:50]}")
        except httpx.HTTPStatusError as e:
            print(f"\n  Note: Dynamic policies endpoint returned {e.response.status_code}")
            print("  (This is normal if you haven't created any dynamic policies yet)")

        # =====================================================================
        # 3. Create a Custom Policy
        # =====================================================================
        print("\n" + "-" * 60)
        print("3. CREATE CUSTOM POLICY")
        print("-" * 60)

        new_policy = {
            "name": "demo-risk-threshold",
            "description": "Block queries with risk score above 0.8",
            "enabled": True,
            "conditions": {
                "risk_score": {"gt": 0.8},
            },
            "action": "block",
            "priority": 100,
            "metadata": {
                "created_by": "policy-crud-demo",
                "purpose": "demonstration",
            },
        }

        print(f"\n  Creating policy: {new_policy['name']}")

        try:
            created = await client.create_policy(new_policy)
            policy_id = created.get("id") or created.get("policy_id")
            print(f"  Created with ID: {policy_id}")

            # =====================================================================
            # 4. Retrieve the Created Policy
            # =====================================================================
            print("\n" + "-" * 60)
            print("4. RETRIEVE POLICY")
            print("-" * 60)

            if policy_id:
                retrieved = await client.get_policy(policy_id)
                print(f"\n  Retrieved policy:")
                print(f"    Name: {retrieved.get('name')}")
                print(f"    Description: {retrieved.get('description')}")
                print(f"    Enabled: {retrieved.get('enabled')}")
                print(f"    Action: {retrieved.get('action')}")

                # =====================================================================
                # 5. Update the Policy
                # =====================================================================
                print("\n" + "-" * 60)
                print("5. UPDATE POLICY")
                print("-" * 60)

                update_data = {
                    "name": "demo-risk-threshold",
                    "description": "Block queries with risk score above 0.9 (updated)",
                    "enabled": True,
                    "conditions": {
                        "risk_score": {"gt": 0.9},  # Changed threshold
                    },
                    "action": "block",
                    "priority": 100,
                }

                print(f"\n  Updating policy: lowering risk threshold to 0.9")

                updated = await client.update_policy(policy_id, update_data)
                print(f"  Updated successfully")
                print(f"  New description: {updated.get('description')}")

                # =====================================================================
                # 6. Delete the Policy
                # =====================================================================
                print("\n" + "-" * 60)
                print("6. DELETE POLICY")
                print("-" * 60)

                print(f"\n  Deleting policy: {policy_id}")

                await client.delete_policy(policy_id)
                print("  Deleted successfully")

        except httpx.HTTPStatusError as e:
            print(f"\n  Note: Policy operation returned {e.response.status_code}")
            print(f"  Response: {e.response.text[:200]}")
            print("  (Policy CRUD requires Orchestrator to be running)")

        # =====================================================================
        # Summary
        # =====================================================================
        print("\n" + "=" * 60)
        print("POLICY MANAGEMENT SUMMARY")
        print("=" * 60)
        print("""
  Policy Types:
    - Static (Agent): Pattern-matching (SQL injection, PII)
    - Dynamic (Orchestrator): Condition-based (RBAC, risk scoring)

  Endpoints:
    Static:  GET /api/v1/static-policies
    Dynamic: GET /api/v1/policies/dynamic
    CRUD:    /api/v1/policies (GET, POST, PUT, DELETE)

  Common Policy Actions:
    - block: Reject the request
    - allow: Allow the request
    - redact: Mask sensitive data
    - audit: Log but allow
    - escalate: Send to HITL queue
""")

    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
