# MAP vs Workflow: Understanding the Difference

**Version:** 1.0
**Last Updated:** February 2026
**Status:** Reference Document
**Related:** See [SDK Getting Started](/docs/sdk/python-getting-started/) for MAP and WCP usage examples.

---

## Executive Summary

AxonFlow provides two distinct execution paradigms for AI orchestration:

1. **MAP (Multi-Agent Planning)** - LLM-powered dynamic plan generation from natural language
2. **Workflow Engine** - Declarative execution of predefined step sequences

This document clarifies the differences, connections, and when to use each.

---

## Quick Comparison

| Aspect | MAP | Workflow |
|--------|-----|----------|
| **Definition** | Natural language query | YAML/JSON schema |
| **Planning** | LLM generates execution plan dynamically | Developer pre-defines steps |
| **Flexibility** | Adapts to query context | Fixed structure |
| **Predictability** | Variable (LLM-dependent) | Deterministic |
| **Use Case** | Exploratory, complex reasoning | Repeatable, auditable processes |
| **Availability** | Community + Enterprise | Enterprise only |
| **API Endpoint** | `POST /api/v1/plan` | `POST /api/v1/workflows/execute` |

---

## Conceptual Model

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        USER REQUEST                                      │
│                "Plan a 3-day trip to Paris"                             │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┴───────────────┐
                    │                               │
                    ▼                               ▼
┌─────────────────────────────────┐  ┌─────────────────────────────────┐
│            MAP                   │  │          WORKFLOW               │
│     (Multi-Agent Planning)       │  │     (Workflow Engine)           │
├─────────────────────────────────┤  ├─────────────────────────────────┤
│                                  │  │                                  │
│  Input: Natural language query   │  │  Input: Predefined YAML/JSON    │
│                                  │  │                                  │
│  ┌─────────────────────────┐    │  │  ┌─────────────────────────┐    │
│  │ 1. Analyze Query (LLM)  │    │  │  │ 1. Parse Workflow Def   │    │
│  │    - Detect domain      │    │  │  │    - Validate schema    │    │
│  │    - Estimate complexity│    │  │  │    - Extract steps      │    │
│  └───────────┬─────────────┘    │  │  └───────────┬─────────────┘    │
│              │                   │  │              │                   │
│              ▼                   │  │              │                   │
│  ┌─────────────────────────┐    │  │              │                   │
│  │ 2. Generate Workflow    │────┼──┼──────────────┘                   │
│  │    (LLM creates steps)  │    │  │                                  │
│  └───────────┬─────────────┘    │  │                                  │
│              │                   │  │                                  │
│              └───────────────────┼──┼───────────────┐                  │
│                                  │  │               │                  │
│                                  │  │               ▼                  │
│                                  │  │  ┌─────────────────────────┐    │
│                                  │  │  │ 2. Execute Steps        │    │
│                                  │  │  │    - llm-call           │    │
│                                  │  │  │    - connector-call     │    │
│                                  │  │  │    - conditional        │    │
│                                  │  │  └───────────┬─────────────┘    │
│                                  │  │              │                   │
│                                  │  │              ▼                   │
│                                  │  │  ┌─────────────────────────┐    │
│                                  │  │  │ 3. Return Results       │    │
│                                  │  │  └─────────────────────────┘    │
│                                  │  │                                  │
└─────────────────────────────────┘  └─────────────────────────────────┘
        PLANNING LAYER                       EXECUTION LAYER
```

**Key Insight:** MAP is a **planning layer** that generates Workflow definitions. The Workflow Engine is the **execution layer** that runs those definitions.

---

## MAP (Multi-Agent Planning)

### What It Is

MAP is an LLM-powered system that:
1. Analyzes natural language queries
2. Decomposes them into subtasks
3. Generates a workflow definition dynamically
4. Executes the workflow
5. Synthesizes results

### How It Works

```
User Query: "Plan a 3-day trip to Paris with moderate budget"
                    │
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│                    PLANNING ENGINE                               │
│                                                                  │
│  1. Query Analysis (LLM Call)                                   │
│     {                                                            │
│       "domain": "travel",                                        │
│       "complexity": 3,                                           │
│       "requires_parallel": true,                                 │
│       "suggested_tasks": ["flights", "hotels", "activities"]     │
│     }                                                            │
│                                                                  │
│  2. Workflow Generation (LLM Call)                              │
│     Creates workflow definition with steps:                      │
│     - flight-search (connector-call)                            │
│     - hotel-search (connector-call)                             │
│     - activity-search (llm-call)                                │
│     - synthesize-itinerary (llm-call)                           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│                    WORKFLOW ENGINE                               │
│                                                                  │
│  Executes the generated workflow:                               │
│  - Parallel: flight-search, hotel-search, activity-search       │
│  - Sequential: synthesize-itinerary (needs all previous)        │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
                    │
                    ▼
              Final Response:
              "Day 1: Arrive at CDG, check into Hotel X..."
```

### API

```bash
POST /api/v1/plan
{
  "query": "Plan a 3-day trip to Paris with moderate budget",
  "domain": "travel",           // Optional hint
  "execution_mode": "auto"      // auto, parallel, sequential
}
```

### Availability

| Edition | MAP Support |
|---------|-------------|
| Community | Yes |
| Enterprise | Yes |

---

## Workflow Engine

### What It Is

The Workflow Engine executes predefined, structured workflows with explicit steps. The workflow definition is created by developers, not generated by an LLM.

### How It Works

```yaml
# Developer creates this definition
apiVersion: axonflow.io/v1
kind: Workflow
metadata:
  name: trip-planner-v1
spec:
  steps:
    - name: flight-search
      type: connector-call
      connector: amadeus
      operation: searchFlights

    - name: hotel-search
      type: connector-call
      connector: amadeus
      operation: searchHotels

    - name: synthesize
      type: llm-call
      provider: openai
      model: gpt-4
      prompt: "Create itinerary from: {{steps.flight-search.output.response}}"
```

### API

```bash
POST /api/v1/workflows/execute
{
  "apiVersion": "axonflow.io/v1",
  "kind": "Workflow",
  "metadata": { "name": "trip-planner-v1" },
  "spec": {
    "steps": [...]
  }
}
```

### Availability

| Edition | Workflow API |
|---------|--------------|
| Community | No |
| Enterprise | Yes |

---

## How They Connect

### MAP Generates Workflow Definitions

The key relationship: **MAP uses the Workflow Engine internally**.

```go
// In planning_engine.go
func (e *PlanningEngine) ExecutePlan(ctx context.Context, query string) (*WorkflowExecution, error) {
    // Generate workflow from natural language
    workflow, _ := e.GeneratePlan(ctx, query)

    // Execute using Workflow Engine
    return e.workflowEngine.ExecuteWorkflowWithParallelSupport(ctx, *workflow, input, user, true)
}
```

### Execution Flow

```
┌─────────────┐     generates      ┌─────────────────────┐
│     MAP     │ ─────────────────► │  Workflow Definition │
│  (Planning) │                    │      (YAML/JSON)     │
└─────────────┘                    └──────────┬──────────┘
                                              │
                                              │ executes
                                              ▼
                                   ┌─────────────────────┐
                                   │   Workflow Engine    │
                                   │    (Execution)       │
                                   └──────────┬──────────┘
                                              │
                                              ▼
                                   ┌─────────────────────┐
                                   │      Results         │
                                   └─────────────────────┘
```

---

## No Circular Dependencies

A common concern: "Can MAP and Workflow call each other recursively?"

**Answer: No. The architecture prevents this by design.**

### Registered Workflow Step Types

```go
engine.stepProcessors["llm-call"] = NewLLMCallProcessor(router)
engine.stepProcessors["connector-call"] = mcpProcessor
engine.stepProcessors["api-call"] = NewAPICallProcessor(amadeusClient)
engine.stepProcessors["conditional"] = NewConditionalProcessor()
engine.stepProcessors["function-call"] = NewFunctionCallProcessor()
```

### NOT Registered

- No `workflow` step type
- No `map` step type
- No `plan` step type

### Why This Matters

| Pattern | Possible? | Reason |
|---------|-----------|--------|
| MAP -> Workflow | Yes | MAP generates workflow definitions |
| Workflow -> LLM | Yes | `llm-call` step type exists |
| Workflow -> Connector | Yes | `connector-call` step type exists |
| Workflow -> Workflow | No | No `workflow` step type registered |
| Workflow -> MAP | No | No `map` step type registered |
| MAP -> MAP | No | MAP outputs a Workflow, not another MAP call |

**Result:** The system is inherently acyclic.

---

## When to Use Each

### Use MAP When

- User provides natural language queries
- Task complexity is unknown ahead of time
- You want LLM to determine the execution strategy
- Exploratory tasks requiring reasoning
- Rapid prototyping without defining workflow schemas

**Example:** Chat-based trip planning assistant

```
User: "I want to visit Japan for 2 weeks, interested in temples and food"
MAP: Analyzes -> generates workflow -> executes -> returns itinerary
```

### Use Workflow When

- Execution path is known and fixed
- Compliance/audit requirements demand predictability
- Same process runs repeatedly with different inputs
- Fine-grained control over each step is needed
- Performance optimization (no planning overhead)

**Example:** Automated compliance report generation

```yaml
# Same workflow runs daily
steps:
  - name: fetch-data
    type: connector-call
    connector: postgres
  - name: analyze-compliance
    type: llm-call
  - name: generate-report
    type: function-call
```

### Decision Matrix

| Scenario | Use MAP | Use Workflow |
|----------|---------|--------------|
| User chat interface | Yes | |
| Scheduled batch job | | Yes |
| Unknown query complexity | Yes | |
| Fixed compliance process | | Yes |
| Exploratory analysis | Yes | |
| Repeatable ETL pipeline | | Yes |
| Customer-facing AI assistant | Yes | |
| Internal audit workflow | | Yes |

---

## Performance Comparison

| Metric | MAP | Workflow |
|--------|-----|----------|
| Planning overhead | 3-5 seconds (LLM call) | 0 seconds |
| Step execution | Same | Same |
| Total time (3 steps) | ~20-25 seconds | ~15-20 seconds |
| LLM calls | N+2 (analysis + generation + steps) | N (steps only) |

**Recommendation:** For latency-sensitive, repeatable tasks, prefer Workflow.

---

## Code Examples

### MAP Example (Natural Language)

```bash
curl -X POST http://localhost:8081/api/v1/plan \
  -H "Authorization: Basic $(echo -n 'clientId:clientSecret' | base64)" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "Plan a weekend trip to Barcelona",
    "domain": "travel",
    "execution_mode": "parallel"
  }'
```

### Workflow Example (Predefined)

```bash
curl -X POST http://localhost:8081/api/v1/workflows/execute \
  -H "Authorization: Basic $(echo -n 'clientId:clientSecret' | base64)" \
  -H "Content-Type: application/json" \
  -d '{
    "apiVersion": "axonflow.io/v1",
    "kind": "Workflow",
    "metadata": { "name": "barcelona-trip" },
    "spec": {
      "steps": [
        {
          "name": "flights",
          "type": "connector-call",
          "connector": "amadeus",
          "operation": "searchFlights",
          "parameters": { "origin": "JFK", "destination": "BCN" }
        },
        {
          "name": "hotels",
          "type": "connector-call",
          "connector": "amadeus",
          "operation": "searchHotels",
          "parameters": { "cityCode": "BCN" }
        },
        {
          "name": "itinerary",
          "type": "llm-call",
          "provider": "openai",
          "model": "gpt-4",
          "prompt": "Create Barcelona weekend itinerary using flights: {{steps.flights.output.response}} and hotels: {{steps.hotels.output.response}}"
        }
      ]
    }
  }'
```

---

## MAP v1.0: WCP Integration

MAP v1.0 introduces **confirm** and **step** execution modes that bridge MAP and the Workflow Control Plane (WCP). This is a key architectural integration point:

### How Confirm/Step Modes Work

```
┌──────────┐     ┌──────────────┐     ┌──────────────┐     ┌───────────────┐
│ MAP Plan │────▶│ WCP Workflow  │────▶│  Approval    │────▶│ Step Executed  │
│ (confirm)│     │ (auto-created)│     │  Gate        │     │ (on approve)   │
└──────────┘     └──────────────┘     └──────────────┘     └───────────────┘
                                            │
                                            ▼ (repeat for each step)
```

| WCP Component | Usage in MAP |
|---|---|
| `CreateWorkflow()` | Track MAP plan as WCP workflow |
| `StepGate()` | Gate each MAP step |
| `GateDecisionRequireApproval` | Pause execution |
| `ApproveStep()` | Resume on client approval |

### When to Use Confirm/Step vs Workflow

| Need | Use |
|------|-----|
| Dynamic plan from natural language + human approval | MAP with confirm/step mode |
| Predefined process with approval gates | Workflow Engine with approval steps |
| Fully automated dynamic execution | MAP with auto/parallel/balanced mode |
| Fully automated fixed execution | Workflow Engine |

### Execution Mode Comparison

| Mode | Planning | Execution | Approval | Edition |
|------|----------|-----------|----------|---------|
| MAP auto | LLM-dynamic | Automatic | None | Community |
| MAP sequential | LLM-dynamic | Step-by-step | None | Community |
| MAP parallel | LLM-dynamic | Concurrent | None | Community |
| MAP balanced | LLM-dynamic | Mixed | None | Community |
| MAP confirm | LLM-dynamic | Gated | Every step | Enterprise |
| MAP step | LLM-dynamic | Gated | After first step | Enterprise |
| Workflow | Predefined | Per schema | Per workflow config | Enterprise |

---

## Summary

| | MAP | Workflow |
|--|-----|----------|
| **Layer** | Planning | Execution |
| **Input** | Natural language | YAML/JSON schema |
| **Generates** | Workflow definitions | Results |
| **Predictability** | Dynamic | Deterministic |
| **Best For** | Exploratory, chat-based | Compliance, batch jobs |
| **Edition** | Community + Enterprise | Enterprise only |
| **Can Call Other** | Generates Workflow | Cannot call MAP or Workflow |

**Key Takeaway:** MAP and Workflow are complementary, not competing. MAP is for dynamic planning from natural language; Workflow is for executing predefined processes. MAP uses the Workflow Engine internally, but the architecture prevents circular dependencies.

---

## Related Documentation

- [Workflow Control Plane](https://docs.getaxonflow.com/docs/orchestration/wcp/overview/) - WCP integration guide
- [SDK Overview](https://docs.getaxonflow.com/docs/sdk/overview/) - MAP and WCP integration patterns across SDKs
- [Community vs Enterprise Features](https://docs.getaxonflow.com/docs/features/community-vs-enterprise/) - Feature availability matrix

---

## Changelog

| Date | Version | Changes |
|------|---------|---------|
| Feb 2026 | 1.1 | Added MAP v1.0 WCP integration section, execution mode comparison |
| Jan 2026 | 1.0 | Initial comparison document |
