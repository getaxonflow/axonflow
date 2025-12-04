# AxonFlow Python SDK

Enterprise AI Governance in 3 Lines of Code.

[![PyPI version](https://badge.fury.io/py/axonflow.svg)](https://badge.fury.io/py/axonflow)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Type hints](https://img.shields.io/badge/type%20hints-mypy-brightgreen.svg)](http://mypy-lang.org/)

## Installation

```bash
pip install axonflow
```

With LLM provider support:
```bash
pip install axonflow[openai]      # OpenAI integration
pip install axonflow[anthropic]   # Anthropic integration
pip install axonflow[all]         # All integrations
```

## Quick Start

### Async Usage (Recommended)

```python
import asyncio
from axonflow import AxonFlow

async def main():
    async with AxonFlow(
        agent_url="https://your-agent.axonflow.com",
        client_id="your-client-id",
        client_secret="your-client-secret"
    ) as client:
        # Execute a governed query
        response = await client.execute_query(
            user_token="user-jwt-token",
            query="What is AI governance?",
            request_type="chat"
        )
        print(response.data)

asyncio.run(main())
```

### Sync Usage

```python
from axonflow import AxonFlow

with AxonFlow.sync(
    agent_url="https://your-agent.axonflow.com",
    client_id="your-client-id",
    client_secret="your-client-secret"
) as client:
    response = client.execute_query(
        user_token="user-jwt-token",
        query="What is AI governance?",
        request_type="chat"
    )
    print(response.data)
```

## Features

### Gateway Mode

For lowest-latency LLM calls with full governance and audit compliance:

```python
from axonflow import AxonFlow, TokenUsage

async with AxonFlow(...) as client:
    # 1. Pre-check: Get policy approval
    ctx = await client.get_policy_approved_context(
        user_token="user-jwt",
        query="Find patient records",
        data_sources=["postgres"]
    )

    if not ctx.approved:
        raise Exception(f"Blocked: {ctx.block_reason}")

    # 2. Make LLM call directly (your code)
    llm_response = await openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": str(ctx.approved_data)}]
    )

    # 3. Audit the call
    await client.audit_llm_call(
        context_id=ctx.context_id,
        response_summary=llm_response.choices[0].message.content[:100],
        provider="openai",
        model="gpt-4",
        token_usage=TokenUsage(
            prompt_tokens=llm_response.usage.prompt_tokens,
            completion_tokens=llm_response.usage.completion_tokens,
            total_tokens=llm_response.usage.total_tokens
        ),
        latency_ms=250
    )
```

### OpenAI Integration

Transparent governance for existing OpenAI code:

```python
from openai import OpenAI
from axonflow import AxonFlow
from axonflow.interceptors.openai import wrap_openai_client

openai = OpenAI()
axonflow = AxonFlow(...)

# Wrap client - governance is now automatic
wrapped = wrap_openai_client(openai, axonflow, user_token="user-123")

# Use as normal
response = wrapped.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Hello!"}]
)
```

### MCP Connectors

Query data through MCP connectors:

```python
# List available connectors
connectors = await client.list_connectors()

# Query a connector
result = await client.query_connector(
    user_token="user-jwt",
    connector_name="postgres",
    operation="query",
    params={"sql": "SELECT * FROM users LIMIT 10"}
)
```

### Multi-Agent Planning

Generate and execute multi-agent plans:

```python
# Generate a plan
plan = await client.generate_plan(
    query="Book a flight and hotel for my trip to Paris",
    domain="travel"
)

print(f"Plan has {len(plan.steps)} steps")

# Execute the plan
result = await client.execute_plan(plan.plan_id)
print(f"Result: {result.result}")
```

## Configuration

```python
from axonflow import AxonFlow, Mode, RetryConfig

client = AxonFlow(
    agent_url="https://your-agent.axonflow.com",
    client_id="your-client-id",
    client_secret="your-client-secret",
    license_key="optional-license-key",      # For enterprise features
    mode=Mode.PRODUCTION,                     # or Mode.SANDBOX
    debug=True,                               # Enable debug logging
    timeout=60.0,                             # Request timeout in seconds
    retry_config=RetryConfig(                 # Retry configuration
        enabled=True,
        max_attempts=3,
        initial_delay=1.0,
        max_delay=30.0,
    ),
    cache_enabled=True,                       # Enable response caching
    cache_ttl=60.0,                           # Cache TTL in seconds
)
```

## Error Handling

```python
from axonflow.exceptions import (
    AxonFlowError,
    PolicyViolationError,
    AuthenticationError,
    RateLimitError,
    TimeoutError,
)

try:
    response = await client.execute_query(...)
except PolicyViolationError as e:
    print(f"Blocked by policy: {e.block_reason}")
except RateLimitError as e:
    print(f"Rate limited: {e.limit}/{e.remaining}, resets at {e.reset_at}")
except AuthenticationError:
    print("Invalid credentials")
except TimeoutError:
    print("Request timed out")
except AxonFlowError as e:
    print(f"AxonFlow error: {e.message}")
```

## Response Types

All responses are Pydantic models with full type hints:

```python
from axonflow import (
    ClientResponse,
    PolicyApprovalResult,
    PlanResponse,
    ConnectorResponse,
)

# Full autocomplete and type checking support
response: ClientResponse = await client.execute_query(...)
print(response.success)
print(response.data)
print(response.policy_info.policies_evaluated)
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run linting
ruff check .
ruff format .

# Run type checking
mypy axonflow
```

## Documentation

- [API Reference](https://docs.getaxonflow.com/sdk/python/api)
- [Gateway Mode Guide](https://docs.getaxonflow.com/sdk/python/gateway-mode)
- [Examples](https://github.com/getaxonflow/axonflow/tree/main/sdk/python/examples)

## License

Apache 2.0 - See [LICENSE](LICENSE) for details.
