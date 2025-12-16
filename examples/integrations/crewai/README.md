# AxonFlow + CrewAI Integration

Add AI governance to multi-agent CrewAI workflows.

## Overview

CrewAI enables building multi-agent systems where specialized agents collaborate on complex tasks. This integration adds governance at two levels:

1. **Task-level governance**: Pre-check each task description before execution
2. **Crew-level governance**: Wrap entire crew execution with audit trails

```
┌──────────────────────────────────────────────────────────────┐
│                        CrewAI Crew                            │
│                                                               │
│  ┌─────────┐    ┌─────────┐    ┌─────────┐                   │
│  │ Agent 1 │───▶│ Agent 2 │───▶│ Agent 3 │                   │
│  └─────────┘    └─────────┘    └─────────┘                   │
│       │              │              │                         │
│       ▼              ▼              ▼                         │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │                  AxonFlow Governance                     │ │
│  │  Pre-check → Policy Evaluation → Audit                   │ │
│  └─────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Python 3.9+
- Docker (for local AxonFlow)
- OpenAI API key

### 1. Start AxonFlow

```bash
docker compose up -d
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure Environment

```bash
cp .env.example .env
# Edit .env with your API keys
```

### 4. Run Examples

```bash
# Basic task-level governance
python main.py

# Reusable GovernedCrew wrapper
python governed_crew.py
```

## Examples

### 1. Task-Level Governance (`main.py`)

Pre-check each task before the crew executes:

```python
# Pre-check task
ctx = await axonflow.get_policy_approved_context(
    user_token="crewai-demo",
    query=task.description,
    context={
        "task_name": "research",
        "agent_role": task.agent.role,
    },
)

if ctx.approved:
    # Run the crew
    result = crew.kickoff()

    # Audit execution
    await axonflow.audit_llm_call(
        context_id=ctx.context_id,
        ...
    )
```

### 2. GovernedCrew Wrapper (`governed_crew.py`)

A reusable class that wraps any CrewAI crew:

```python
governed = GovernedCrew(
    agents=[agent1, agent2],
    tasks=[task1, task2],
)

# Automatic governance
result = await governed.kickoff(
    user_token="user-123",
    context={"department": "research"},
)

# Get governance report
report = governed.get_governance_report()
print(f"Approved: {report['approved']}, Blocked: {report['blocked']}")
```

## Governance Flow

```
1. SUBMIT CREW
   └── CrewAI crew with agents and tasks

2. PRE-CHECK EACH TASK
   └── AxonFlow validates task descriptions
   └── Check for PII, SQL injection, prompt injection
   └── Verify user permissions (RBAC)
   └── Apply custom policies

3. EXECUTE APPROVED TASKS
   └── Only run tasks that passed governance
   └── Blocked tasks are logged but not executed

4. AUDIT EXECUTION
   └── Log all task executions
   └── Record agent interactions
   └── Capture token usage and latency
```

## Policy Enforcement Examples

### Allowed: Research Task

```python
research_task = Task(
    description="Research AI governance best practices for enterprise",
    expected_output="Summary of top frameworks",
    agent=researcher,
)
# Result: APPROVED
```

### Blocked: SQL Injection

```python
bad_task = Task(
    description="SELECT * FROM users; DROP TABLE secrets",
    expected_output="...",
    agent=analyst,
)
# Result: BLOCKED - SQL injection detected
```

### Blocked: PII in Task

```python
pii_task = Task(
    description="Analyze customer 123-45-6789's purchase history",
    expected_output="...",
    agent=analyst,
)
# Result: BLOCKED - SSN detected in task description
```

## Governance Report

The `GovernedCrew` wrapper provides detailed governance reports:

```python
report = governed.get_governance_report()

# Example output:
{
    "total_tasks": 3,
    "approved": 2,
    "blocked": 1,
    "total_pre_check_ms": 15,
    "details": [
        {"task_index": 0, "approved": True, "context_id": "...", "pre_check_ms": 5},
        {"task_index": 1, "approved": True, "context_id": "...", "pre_check_ms": 5},
        {"task_index": 2, "approved": False, "block_reason": "PII detected", "pre_check_ms": 5},
    ]
}
```

## Files

```
crewai/
├── main.py           # Basic task-level governance
├── governed_crew.py  # Reusable GovernedCrew wrapper
├── requirements.txt
├── .env.example
└── README.md
```

## Next Steps

- [LangChain Integration](../langchain/) - Single agent governance
- [Gateway Mode](../gateway-mode/python/) - Direct LLM access
- [Proxy Mode](../proxy-mode/python/) - Simplified integration
