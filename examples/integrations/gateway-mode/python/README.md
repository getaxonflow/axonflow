# Gateway Mode - Python Example

**Lowest latency AI governance** - Add compliance and monitoring to your LLM calls with ~3-5ms overhead.

## What is Gateway Mode?

Gateway Mode separates policy enforcement from LLM calls, giving you:

1. **Full control** - Use any LLM provider directly (OpenAI, Anthropic, etc.)
2. **Lowest latency** - Policy checks happen in parallel, ~3-5ms overhead
3. **Complete audit trails** - Every interaction logged for compliance
4. **Flexibility** - Customize LLM parameters, streaming, etc.

## Quick Start

### Prerequisites

- Python 3.9+
- Docker (for local AxonFlow)
- OpenAI or Anthropic API key

### 1. Start AxonFlow

```bash
# From the axonflow repo root
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

### 4. Run the Example

```bash
# OpenAI example
python main.py

# Anthropic Claude example
python anthropic_example.py
```

## Expected Output

```
AxonFlow Gateway Mode - Python Example

Query: "What are best practices for AI model deployment?"
User: user-123
Context: {'user_role': 'engineer', 'department': 'platform'}

Step 1: Policy Pre-Check...
   Completed in 3ms
   Context ID: abc123-def456
   Approved: True

Step 2: LLM Call (OpenAI)...
   Response received in 850ms
   Tokens: 25 prompt, 150 completion

Step 3: Audit Logging...
   Audit logged in 2ms
   Audit ID: audit-789

============================================================
Results
============================================================

Response:
AI model deployment best practices include...

Latency Breakdown:
   Pre-check:  3ms
   LLM call:   850ms
   Audit:      2ms
   -----------------
   Governance: 5ms (overhead)
   Total:      855ms
```

## Code Walkthrough

### Step 1: Pre-Check

```python
pre_check_result = await axonflow.get_policy_approved_context(
    user_token=user_token,
    query=query,
    context=context,
)

if not pre_check_result.approved:
    print(f"Blocked: {pre_check_result.block_reason}")
    return
```

The pre-check validates:
- SQL injection patterns
- PII in the query (SSN, credit cards, etc.)
- User permissions (RBAC)
- Rate limits
- Custom policies

### Step 2: LLM Call

```python
completion = openai_client.chat.completions.create(
    model="gpt-3.5-turbo",
    messages=[{"role": "user", "content": query}],
)
```

You make the LLM call directly - full control over:
- Model selection
- Parameters (temperature, max_tokens, etc.)
- Streaming
- Retries

### Step 3: Audit

```python
await axonflow.audit_llm_call(
    context_id=pre_check_result.context_id,
    response_summary=response,
    provider="openai",
    model="gpt-3.5-turbo",
    token_usage=TokenUsage(...),
    latency_ms=llm_latency_ms,
)
```

The audit logs:
- Request/response correlation
- Token usage for cost tracking
- Latency metrics
- Provider information

## Files

```
python/
├── main.py              # Main OpenAI example
├── anthropic_example.py # Anthropic Claude example
├── requirements.txt
├── .env.example
└── README.md
```

## Next Steps

- [Proxy Mode](../proxy-mode/python/) - Simpler integration, AxonFlow handles LLM routing
- [LangChain Integration](../../langchain/) - Use with LangChain framework
- [CrewAI Integration](../../crewai/) - Use with CrewAI agents
