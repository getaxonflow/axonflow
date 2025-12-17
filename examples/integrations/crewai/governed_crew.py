"""
AxonFlow Governed Crew

A reusable wrapper class that adds governance to any CrewAI crew.
All agent interactions are automatically pre-checked and audited.
"""

import asyncio
import os
import time
from typing import List, Optional, Dict, Any

from dotenv import load_dotenv
from crewai import Agent, Task, Crew, Process
from langchain_openai import ChatOpenAI

from axonflow import AxonFlow
from axonflow.types import TokenUsage

load_dotenv()


class GovernedCrew:
    """
    A CrewAI Crew wrapper with AxonFlow governance.

    Usage:
        governed = GovernedCrew(
            agents=[agent1, agent2],
            tasks=[task1, task2],
            axonflow_config={...}
        )
        result = await governed.kickoff(user_token="user-123")
    """

    def __init__(
        self,
        agents: List[Agent],
        tasks: List[Task],
        axonflow_config: Optional[Dict[str, str]] = None,
        process: Process = Process.sequential,
    ):
        self.agents = agents
        self.tasks = tasks
        self.process = process
        self.config = axonflow_config or {
            "agent_url": os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
            "client_id": os.getenv("AXONFLOW_CLIENT_ID", "demo"),
            "client_secret": os.getenv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
        }
        self.governance_results: List[Dict[str, Any]] = []

    async def kickoff(
        self,
        user_token: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Execute the crew with governance.

        1. Pre-check all tasks against policies
        2. Execute approved tasks
        3. Audit all executions

        Returns the crew output or raises if blocked.
        """
        context = context or {}
        self.governance_results = []

        async with AxonFlow(
            agent_url=self.config["agent_url"],
            client_id=self.config["client_id"],
            client_secret=self.config["client_secret"],
        ) as axonflow:

            # Phase 1: Pre-check all tasks
            print("\n[Governance] Pre-checking tasks...")
            approved_tasks = []
            blocked_tasks = []

            for i, task in enumerate(self.tasks):
                task_context = {
                    **context,
                    "task_index": i,
                    "task_description": task.description[:100],
                    "agent_role": task.agent.role if task.agent else "unassigned",
                    "framework": "crewai",
                }

                pre_check_start = time.time()
                ctx = await axonflow.get_policy_approved_context(
                    user_token=user_token,
                    query=task.description,
                    context=task_context,
                )
                pre_check_ms = int((time.time() - pre_check_start) * 1000)

                result = {
                    "task_index": i,
                    "approved": ctx.approved,
                    "context_id": ctx.context_id,
                    "pre_check_ms": pre_check_ms,
                }

                if ctx.approved:
                    print(f"  Task {i}: APPROVED ({pre_check_ms}ms)")
                    approved_tasks.append((i, task, ctx.context_id))
                else:
                    print(f"  Task {i}: BLOCKED - {ctx.block_reason}")
                    result["block_reason"] = ctx.block_reason
                    blocked_tasks.append(i)

                self.governance_results.append(result)

            # Check if we should proceed
            if not approved_tasks:
                raise ValueError(f"All tasks blocked. Blocked: {blocked_tasks}")

            if blocked_tasks:
                print(f"\n  Warning: {len(blocked_tasks)} task(s) blocked, proceeding with {len(approved_tasks)}")

            # Phase 2: Execute approved tasks
            print("\n[Governance] Executing approved tasks...")

            crew = Crew(
                agents=self.agents,
                tasks=[t[1] for t in approved_tasks],
                process=self.process,
                verbose=True,
            )

            exec_start = time.time()
            result = crew.kickoff()
            exec_ms = int((time.time() - exec_start) * 1000)

            # Phase 3: Audit all tasks
            print("\n[Governance] Auditing task executions...")

            for task_index, task, context_id in approved_tasks:
                await axonflow.audit_llm_call(
                    context_id=context_id,
                    response_summary=f"Task {task_index} completed: {task.expected_output[:50]}...",
                    provider="openai",
                    model="gpt-3.5-turbo",
                    token_usage=TokenUsage(
                        prompt_tokens=0,
                        completion_tokens=0,
                        total_tokens=0,
                    ),
                    latency_ms=exec_ms // len(approved_tasks),
                )

                # Update governance results
                for gr in self.governance_results:
                    if gr["task_index"] == task_index:
                        gr["execution_ms"] = exec_ms // len(approved_tasks)
                        gr["audited"] = True

            print(f"  Total execution: {exec_ms}ms")

            return str(result)

    def get_governance_report(self) -> Dict[str, Any]:
        """Get a summary of governance decisions for this run."""
        approved = sum(1 for r in self.governance_results if r["approved"])
        blocked = sum(1 for r in self.governance_results if not r["approved"])
        total_pre_check_ms = sum(r["pre_check_ms"] for r in self.governance_results)

        return {
            "total_tasks": len(self.governance_results),
            "approved": approved,
            "blocked": blocked,
            "total_pre_check_ms": total_pre_check_ms,
            "details": self.governance_results,
        }


async def main():
    """Demo of GovernedCrew wrapper."""
    print("GovernedCrew Demo")
    print("=" * 60)

    llm = ChatOpenAI(
        model="gpt-3.5-turbo",
        temperature=0.7,
        openai_api_key=os.getenv("OPENAI_API_KEY"),
    )

    # Define agents
    analyst = Agent(
        role="Data Analyst",
        goal="Analyze data and provide insights",
        backstory="Expert data analyst with 10 years experience.",
        llm=llm,
        verbose=True,
    )

    presenter = Agent(
        role="Presentation Specialist",
        goal="Create clear, compelling presentations",
        backstory="Communications expert who makes complex topics simple.",
        llm=llm,
        verbose=True,
    )

    # Define tasks
    analysis_task = Task(
        description="Analyze the benefits and challenges of implementing AI governance in mid-size companies.",
        expected_output="A structured analysis with 3 benefits and 3 challenges.",
        agent=analyst,
    )

    presentation_task = Task(
        description="Create an executive summary (under 150 words) of the analysis for the board.",
        expected_output="A 150-word executive summary suitable for C-level executives.",
        agent=presenter,
    )

    # Create governed crew
    governed = GovernedCrew(
        agents=[analyst, presenter],
        tasks=[analysis_task, presentation_task],
    )

    # Execute with governance
    try:
        result = await governed.kickoff(
            user_token="exec-demo-user",
            context={"department": "strategy", "purpose": "board_presentation"},
        )

        print("\n" + "=" * 60)
        print("CREW OUTPUT")
        print("=" * 60)
        print(result)

        print("\n" + "=" * 60)
        print("GOVERNANCE REPORT")
        print("=" * 60)
        report = governed.get_governance_report()
        print(f"Tasks: {report['approved']} approved, {report['blocked']} blocked")
        print(f"Pre-check overhead: {report['total_pre_check_ms']}ms")

    except ValueError as e:
        print(f"\nCrew execution blocked: {e}")


if __name__ == "__main__":
    asyncio.run(main())
