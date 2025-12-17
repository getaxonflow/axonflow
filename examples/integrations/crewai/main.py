"""
AxonFlow + CrewAI Integration

Add AI governance to multi-agent CrewAI workflows.
This example shows two approaches:

1. Task-level governance: Pre-check each task before execution
2. Agent-level governance: Wrap individual agent LLM calls

Both approaches provide complete audit trails for compliance.
"""

import asyncio
import os
import time

from dotenv import load_dotenv
from crewai import Agent, Task, Crew, Process
from langchain_openai import ChatOpenAI

from axonflow import AxonFlow
from axonflow.types import TokenUsage

load_dotenv()


async def main():
    print("AxonFlow + CrewAI Integration Example")
    print("=" * 60)
    print()

    # Initialize LLM
    llm = ChatOpenAI(
        model="gpt-3.5-turbo",
        temperature=0.7,
        openai_api_key=os.getenv("OPENAI_API_KEY"),
    )

    # Define CrewAI Agents
    researcher = Agent(
        role="Senior Research Analyst",
        goal="Research and analyze AI governance best practices",
        backstory="You are an expert researcher specializing in AI ethics and governance.",
        llm=llm,
        verbose=True,
    )

    writer = Agent(
        role="Technical Writer",
        goal="Write clear, concise documentation",
        backstory="You are a skilled technical writer who creates easy-to-understand documentation.",
        llm=llm,
        verbose=True,
    )

    # Define Tasks
    research_task = Task(
        description="Research the top 3 AI governance frameworks used by enterprises. Focus on practical implementation details.",
        expected_output="A list of 3 AI governance frameworks with key features and implementation considerations.",
        agent=researcher,
    )

    writing_task = Task(
        description="Based on the research, write a concise summary (under 200 words) of AI governance best practices.",
        expected_output="A 200-word summary of AI governance best practices.",
        agent=writer,
    )

    async with AxonFlow(
        agent_url=os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "demo"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
    ) as axonflow:

        # =====================================================================
        # APPROACH 1: Task-Level Governance
        # Pre-check each task before execution
        # =====================================================================
        print("\n" + "=" * 60)
        print("TASK-LEVEL GOVERNANCE")
        print("=" * 60)

        tasks_to_run = [
            ("research_task", research_task),
            ("writing_task", writing_task),
        ]

        approved_tasks = []

        for task_name, task in tasks_to_run:
            print(f"\n[Pre-Check] Task: {task_name}")

            ctx = await axonflow.get_policy_approved_context(
                user_token="crewai-demo",
                query=task.description,
                context={
                    "task_name": task_name,
                    "agent_role": task.agent.role,
                    "framework": "crewai",
                },
            )

            if ctx.approved:
                print(f"  Approved - Context ID: {ctx.context_id}")
                approved_tasks.append((task_name, task, ctx.context_id))
            else:
                print(f"  BLOCKED: {ctx.block_reason}")

        if not approved_tasks:
            print("\nNo tasks approved. Exiting.")
            return

        # Run approved tasks
        print(f"\n[Executing] Running {len(approved_tasks)} approved tasks...")

        crew = Crew(
            agents=[researcher, writer],
            tasks=[t[1] for t in approved_tasks],
            process=Process.sequential,
            verbose=True,
        )

        crew_start = time.time()
        result = crew.kickoff()
        crew_latency_ms = int((time.time() - crew_start) * 1000)

        # Audit all tasks
        print("\n[Audit] Logging task executions...")
        for task_name, task, context_id in approved_tasks:
            await axonflow.audit_llm_call(
                context_id=context_id,
                response_summary=f"Task '{task_name}' completed",
                provider="openai",
                model="gpt-3.5-turbo",
                token_usage=TokenUsage(
                    prompt_tokens=0,
                    completion_tokens=0,
                    total_tokens=0,
                ),
                latency_ms=crew_latency_ms // len(approved_tasks),
            )
            print(f"  Audited: {task_name}")

        # Results
        print("\n" + "=" * 60)
        print("CREW OUTPUT")
        print("=" * 60)
        print(result)
        print(f"\nTotal execution time: {crew_latency_ms}ms")


if __name__ == "__main__":
    asyncio.run(main())
