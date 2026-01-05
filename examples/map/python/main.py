#!/usr/bin/env python3
"""
AxonFlow MAP (Multi-Agent Planning) Example - Python SDK

This example demonstrates ALL MAP SDK methods:
- generate_plan() - Create a multi-agent execution plan
- execute_plan()  - Execute a previously generated plan
- get_plan_status() - Get status of a running or completed plan

Run with: python main.py
Prerequisites: docker compose up -d
"""

import asyncio
import os
import time

from axonflow import AxonFlow


async def main():
    print("AxonFlow MAP (Multi-Agent Planning) - Python SDK")
    print("=" * 55)
    print()

    # Initialize client
    # Note: As of SDK v1.0.0 (ADR-026), all routes go through a single endpoint.
    # The Agent proxies orchestrator routes internally.
    endpoint = os.getenv("AXONFLOW_ENDPOINT", "http://localhost:8080")
    client_id = os.getenv("AXONFLOW_CLIENT_ID", "demo")
    client_secret = os.getenv("AXONFLOW_CLIENT_SECRET", "demo")

    async with AxonFlow(
        endpoint=endpoint,
        client_id=client_id,
        client_secret=client_secret,
        debug=True,
    ) as client:
        query = "Create a brief plan to greet a new user and ask how to help them"
        domain = "generic"

        print(f"Query: {query}")
        print(f"Domain: {domain}")
        print("-" * 55)
        print()

        try:
            # ========================================
            # 1. GENERATE PLAN
            # ========================================
            print("1. generate_plan - Creating a multi-agent plan...")
            plan = await client.generate_plan(query=query, domain=domain)

            print(f"   Plan ID: {plan.plan_id}")
            print(f"   Domain: {plan.domain}")
            print(f"   Steps: {len(plan.steps)}")
            print("   Plan Steps:")
            for i, step in enumerate(plan.steps, 1):
                step_type = getattr(step, 'type', 'action')
                print(f"     {i}. {step.name} ({step_type})")
            print()

            # ========================================
            # 2. GET PLAN STATUS (before execution)
            # ========================================
            print("2. get_plan_status - Checking plan status before execution...")
            try:
                status = await client.get_plan_status(plan.plan_id)
                print(f"   Status: {status.status}")
                print(f"   Completed Steps: {status.completed_steps}/{status.total_steps}")
            except Exception as e:
                print(f"   Note: get_plan_status may require plan execution first: {e}")
            print()

            # ========================================
            # 3. EXECUTE PLAN
            # ========================================
            print("3. execute_plan - Executing the plan...")
            try:
                execution = await client.execute_plan(plan.plan_id)
                print(f"   Execution Status: {execution.status}")
                print(f"   Completed Steps: {execution.completed_steps}/{execution.total_steps}")

                if hasattr(execution, 'results') and execution.results:
                    print("   Results:")
                    for result in execution.results[:3]:
                        step_name = getattr(result, 'step_name', 'step')
                        step_status = getattr(result, 'status', 'completed')
                        print(f"     - {step_name}: {step_status}")
            except Exception as e:
                print(f"   Note: execute_plan may require LLM provider: {e}")
            print()

            # ========================================
            # 4. GET PLAN STATUS (after execution)
            # ========================================
            print("4. get_plan_status - Checking status after execution...")
            try:
                # Brief wait for execution to complete
                await asyncio.sleep(1)

                final_status = await client.get_plan_status(plan.plan_id)
                print(f"   Status: {final_status.status}")
                print(f"   Completed Steps: {final_status.completed_steps}/{final_status.total_steps}")

                if hasattr(final_status, 'duration_ms') and final_status.duration_ms:
                    print(f"   Duration: {final_status.duration_ms}ms")

                if hasattr(final_status, 'error') and final_status.error:
                    print(f"   Error: {final_status.error}")
            except Exception as e:
                print(f"   Note: Status check may fail if plan was not executed: {e}")
            print()

            print("=" * 55)
            print("All 3 MAP SDK methods demonstrated!")
            print()
            print("Methods tested:")
            print("  1. generate_plan()    - Create execution plan")
            print("  2. get_plan_status()  - Check plan status (before)")
            print("  3. execute_plan()     - Execute the plan")
            print("  4. get_plan_status()  - Check plan status (after)")

        except Exception as e:
            print(f"Error: {e}")
            print()
            print("=" * 55)
            print("MAP Test: Some steps may have failed (check LLM provider)")
            raise


if __name__ == "__main__":
    asyncio.run(main())
