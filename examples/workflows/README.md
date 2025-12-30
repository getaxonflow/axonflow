# AxonFlow Example Workflows

Learn how to use AxonFlow with these copy-paste examples. Each example demonstrates a specific pattern or use case.

## Quick Start

All examples follow the same pattern:

```bash
cd examples/workflows/01-simple-sequential
cp .env.example .env
# Edit .env with your configuration
go run main.go
```

## Basic Patterns

### 1. Simple Sequential
**File:** `01-simple-sequential/`
**Lines:** ~20 lines
**What it shows:** Basic query → process → return pattern

Learn the fundamentals: how to connect to AxonFlow, define a simple workflow, and execute it.

### 2. Parallel Execution
**File:** `02-parallel-execution/`
**Lines:** ~30 lines
**What it shows:** Search 3 data sources simultaneously (MAP parallelization)

See AxonFlow's Multi-Agent Planning (MAP) automatically parallelize independent tasks for faster results.

### 3. Conditional Logic
**File:** `03-conditional-logic/`
**Lines:** ~40 lines
**What it shows:** If/else branching based on data

Build dynamic workflows that make decisions based on runtime data.

## Real-World Scenarios

### 4. Travel Booking with Fallbacks
**File:** `04-travel-booking-fallbacks/`
**Lines:** ~50 lines
**What it shows:** Try Amadeus API → if fails, use mock data

Handle API failures gracefully with automatic fallback mechanisms.

### 5. Data Pipeline Orchestration
**File:** `05-data-pipeline/`
**Lines:** ~60 lines
**What it shows:** PostgreSQL → transform → Redis cache

Build multi-step data pipelines with different connector types.

### 6. Multi-Step Approval Workflow
**File:** `06-multi-step-approval/`
**Lines:** ~70 lines
**What it shows:** Submit → manager approval → execute → audit log

Implement approval flows with policy enforcement at each step.

## Enterprise Workflows

For advanced enterprise workflow examples (healthcare, e-commerce, financial reporting, chatbot with memory), see [ee/examples/workflows/](../../ee/examples/workflows/).

## Requirements

- **Go 1.23+**
- **Running AxonFlow stack:** `docker-compose up` in the root directory
- **API Keys:** OpenAI, Anthropic, or other LLM providers (see `.env.example` in each directory)

## Getting Help

- **Documentation:** https://docs.getaxonflow.com
- **Issues:** https://github.com/getaxonflow/axonflow/issues
- **Discussions:** https://github.com/getaxonflow/axonflow/discussions

## Contributing

Have a great example to share? See [CONTRIBUTING.md](../../CONTRIBUTING.md) for guidelines.
