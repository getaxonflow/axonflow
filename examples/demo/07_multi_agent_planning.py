"""
Part 5: Multi-Agent Planning (MAP)

MAP lets you orchestrate complex AI workflows:
- Define workflows declaratively
- Break tasks into governed steps
- Execute with automatic policy enforcement

Each step in the workflow gets the same governance as individual calls.
"""

import asyncio
import os

from axonflow import AxonFlow


async def simple_plan_demo():
    """Generate and execute a simple multi-step plan."""
    print("Multi-Agent Planning Demo")
    print("=" * 60)
    print()
    print("A single request becomes a multi-step workflow,")
    print("with governance applied at every step.")
    print()

    agent_url = os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080")

    async with AxonFlow(
        agent_url=agent_url,
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "demo-client"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
    ) as client:

        # Step 1: Generate a plan from natural language
        print("-" * 60)
        print("Step 1: Plan Generation")
        print("-" * 60)

        # Using 'generic' domain works without external connectors
        task = "Analyze our support ticket trends and create recommendations for improving response times"

        print(f"Task: \"{task}\"")
        print()

        try:
            plan = await client.generate_plan(
                query=task,
                domain="generic",  # Works without external connectors
            )

            print(f"Plan ID: {plan.plan_id}")
            print(f"Domain: {plan.domain}")
            print(f"Steps: {len(plan.steps)}")
            print()

            if plan.steps:
                print("Generated Steps:")
                for i, step in enumerate(plan.steps, 1):
                    step_type = getattr(step, 'type', 'llm-call')
                    step_name = getattr(step, 'name', f'step_{i}')
                    print(f"  {i}. {step_name} ({step_type})")
            print()

            # Step 2: Execute the plan
            print("-" * 60)
            print("Step 2: Plan Execution")
            print("-" * 60)

            print("Executing plan...")
            result = await client.execute_plan(plan.plan_id)

            print(f"Status: {result.status}")

            if result.duration:
                print(f"Duration: {result.duration}")

            # Show step results if available
            if result.step_results:
                print()
                print("Step Results:")
                for step_id, step_result in result.step_results.items():
                    result_preview = str(step_result)[:80]
                    print(f"  {step_id}: {result_preview}...")

            # Show final result preview
            if result.result:
                print()
                print("Final Result:")
                result_str = str(result.result)
                print(f"  {result_str[:300]}{'...' if len(result_str) > 300 else ''}")

        except Exception as e:
            print(f"Error: {e}")
            print()
            print("Note: MAP requires an LLM provider (OpenAI/Anthropic) to be configured.")
            print("Set OPENAI_API_KEY or ANTHROPIC_API_KEY environment variable.")

        print()


async def workflow_example():
    """Show a predefined workflow pattern."""
    print("-" * 60)
    print("Workflow Pattern Example")
    print("-" * 60)
    print()

    print("MAP supports these step types:")
    print()
    print("  llm-call       - AI inference (policy enforced)")
    print("  api-call       - External API requests")
    print("  connector-call - MCP connector queries")
    print("  conditional    - If/else branching")
    print("  function-call  - Custom code execution")
    print()
    print("Example workflow for support analysis:")
    print()
    print("  1. gather-data (connector-call)")
    print("     └─ Query tickets from PostgreSQL")
    print()
    print("  2. analyze-trends (llm-call)")
    print("     └─ AI analyzes the ticket data")
    print()
    print("  3. generate-report (llm-call)")
    print("     └─ Create actionable recommendations")
    print()
    print("Each step is governed by AxonFlow policies.")
    print()


async def main():
    await simple_plan_demo()
    await workflow_example()

    print("=" * 60)
    print("MAP Summary")
    print("=" * 60)
    print()
    print("Multi-Agent Planning enables:")
    print("  - Complex workflows from natural language")
    print("  - Step-by-step execution with governance")
    print("  - Automatic audit trail for each step")
    print("  - Mix of LLM, API, and connector calls")
    print("  - Conditional logic and branching")
    print()


if __name__ == "__main__":
    asyncio.run(main())
