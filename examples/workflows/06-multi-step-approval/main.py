#!/usr/bin/env python3
"""
Example 6: Multi-Step Approval Workflow - Python

Demonstrates a multi-level approval chain: Manager → Director → Finance
"""

import os
import sys

from axonflow import AxonFlow


def main():
    agent_url = os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080")
    license_key = os.getenv("AXONFLOW_LICENSE_KEY")

    if not license_key:
        print("❌ AXONFLOW_LICENSE_KEY must be set")
        sys.exit(1)

    client = AxonFlow(
        endpoint=agent_url,
        license_key=license_key,
    )

    print("✅ Connected to AxonFlow")
    print("🔐 Starting multi-step approval workflow for capital expenditure...\n")

    # Purchase request details
    amount = 15000.00
    item = "10 Dell PowerEdge R750 servers for production deployment"

    try:
        # Step 1: Manager Approval
        print(f"📤 Step 1: Requesting Manager approval for ${amount:.2f} purchase...")
        manager_query = (
            f"As a manager, would you approve a purchase request for ${amount:.2f} to buy: {item}? "
            "Consider budget, necessity, and timing. Respond with APPROVED or REJECTED and brief reasoning."
        )

        manager_resp = client.execute_query(
            user_token="user-123",
            query=manager_query,
            request_type="chat",
            context={"model": "gpt-4"},
        )

        print("📥 Manager Response:", manager_resp.data)

        manager_result = str(manager_resp.data)
        if "APPROVED" not in manager_result:
            print("❌ Purchase rejected at manager level")
            print("Workflow terminated")
            return

        print("✅ Manager approval granted\n")

        # Step 2: Director Approval (for amounts > $10K)
        if amount > 10000:
            print("📤 Step 2: Escalating to Director for amounts > $10,000...")
            director_query = (
                f"As a Director, review this approved purchase: ${amount:.2f} for {item}. "
                f"Manager approved with reasoning: '{manager_resp.data}'. "
                "Consider strategic alignment and ROI. Respond with APPROVED or REJECTED and reasoning."
            )

            director_resp = client.execute_query(
                user_token="user-123",
                query=director_query,
                request_type="chat",
                context={"model": "gpt-4"},
            )

            print("📥 Director Response:", director_resp.data)

            director_result = str(director_resp.data)
            if "APPROVED" not in director_result:
                print("❌ Purchase rejected at director level")
                print("Workflow terminated")
                return

            print("✅ Director approval granted\n")
        else:
            print("ℹ️  Step 2: Director approval skipped (amount < $10,000)\n")

        # Step 3: Finance Approval (for amounts > $5K)
        if amount > 5000:
            print("📤 Step 3: Final Finance team compliance check...")
            finance_query = (
                f"As Finance team, perform final compliance check on approved purchase: ${amount:.2f} for {item}. "
                "Verify budget availability and compliance with procurement policies. Respond with APPROVED or REJECTED and reasoning."
            )

            finance_resp = client.execute_query(
                user_token="user-123",
                query=finance_query,
                request_type="chat",
                context={"model": "gpt-4"},
            )

            print("📥 Finance Response:", finance_resp.data)

            finance_result = str(finance_resp.data)
            if "APPROVED" not in finance_result:
                print("❌ Purchase rejected at finance level")
                print("Workflow terminated")
                return

            print("✅ Finance approval granted\n")

        # All approvals obtained
        print("=" * 60)
        print("🎉 Purchase Request FULLY APPROVED")
        print("=" * 60)
        print(f"Amount: ${amount:.2f}")
        print(f"Item: {item}")
        print("Approvals: Manager ✅ Director ✅ Finance ✅\n")
        print("✅ Workflow completed - Purchase can proceed")
        print("💡 Multi-step approval: Manager → Director → Finance")
    except Exception as e:
        print(f"❌ Approval workflow failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
