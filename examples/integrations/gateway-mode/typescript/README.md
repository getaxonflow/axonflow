# Gateway Mode - TypeScript Example

**Lowest latency AI governance** - Add compliance and monitoring to your LLM calls with ~3-5ms overhead.

## What is Gateway Mode?

Gateway Mode separates policy enforcement from LLM calls, giving you:

1. **Full control** - Use any LLM provider directly (OpenAI, Anthropic, etc.)
2. **Lowest latency** - Policy checks happen in parallel, ~3-5ms overhead
3. **Complete audit trails** - Every interaction logged for compliance
4. **Flexibility** - Customize LLM parameters, streaming, etc.

## Architecture

```
┌─────────────┐      ┌─────────────┐      ┌─────────────┐
│  Your App   │─────▶│  AxonFlow   │─────▶│  Audit DB   │
│             │      │  (Pre-check)│      │             │
└─────────────┘      └─────────────┘      └─────────────┘
       │                                         ▲
       │                                         │
       ▼                                         │
┌─────────────┐                           ┌─────────────┐
│  LLM API    │──────────────────────────▶│  AxonFlow   │
│  (OpenAI)   │        Response           │  (Audit)    │
└─────────────┘                           └─────────────┘
```

## Quick Start

### Prerequisites

- Node.js 18+
- Docker (for local AxonFlow)
- OpenAI or Anthropic API key

### 1. Start AxonFlow

```bash
# From the axonflow repo root
docker compose up -d
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Configure Environment

```bash
cp .env.example .env
# Edit .env with your API keys
```

### 4. Run the Example

```bash
# OpenAI example
npm run start:openai

# Anthropic Claude example
npm run start:anthropic

# Default (OpenAI)
npm start
```

## Expected Output

```
🚀 AxonFlow Gateway Mode - TypeScript Example

📤 Query: "What are the benefits of AI governance in enterprise?"
👤 User: user-123
📋 Context: { user_role: 'developer', department: 'engineering' }

⏱️  Step 1: Policy Pre-Check...
   ✅ Pre-check completed in 3ms
   📝 Context ID: abc123-def456
   ✓ Approved: true

🤖 Step 2: LLM Call (OpenAI)...
   ✅ LLM response received in 850ms
   📊 Tokens: 25 prompt, 150 completion

📝 Step 3: Audit Logging...
   ✅ Audit logged in 2ms

════════════════════════════════════════════════════════════
📊 Results
════════════════════════════════════════════════════════════

💬 Response:
AI governance in enterprise provides several key benefits...

⏱️  Latency Breakdown:
   Pre-check:  3ms
   LLM call:   850ms
   Audit:      2ms
   ─────────────────
   Governance: 5ms (overhead)
   Total:      855ms
```

## Code Walkthrough

### Step 1: Pre-Check

```typescript
const preCheckResult = await axonflow.getPolicyApprovedContext({
  userToken,
  query,
  context,
});

if (!preCheckResult.approved) {
  console.log(`Blocked: ${preCheckResult.blockReason}`);
  return;
}
```

The pre-check validates:
- SQL injection patterns
- PII in the query (SSN, credit cards, etc.)
- User permissions (RBAC)
- Rate limits
- Custom policies

### Step 2: LLM Call

```typescript
const completion = await openai.chat.completions.create({
  model: "gpt-4o-mini",
  messages: [{ role: "user", content: query }],
});
```

You make the LLM call directly - full control over:
- Model selection
- Parameters (temperature, max_tokens, etc.)
- Streaming
- Retries

### Step 3: Audit

```typescript
await axonflow.auditLLMCall({
  contextId: preCheckResult.contextId,
  response: response,
  model: "gpt-4o-mini",
  provider: "openai",
  tokenUsage: { ... },
  latencyMs: llmLatency,
});
```

The audit logs:
- Request/response correlation
- Token usage for cost tracking
- Latency metrics
- Provider information

## Policy Enforcement Examples

### Blocked - SQL Injection

```typescript
const query = "SELECT * FROM users; DROP TABLE users;";
// Result: blocked, reason: "SQL injection attempt detected"
```

### Blocked - PII Detection

```typescript
const query = "Process payment for SSN 123-45-6789";
// Result: blocked, reason: "US Social Security Number pattern detected"
```

### Allowed - Safe Query

```typescript
const query = "What is the weather forecast?";
// Result: approved: true
```

## Files

```
typescript/
├── src/
│   ├── index.ts           # Main OpenAI example
│   └── anthropic-example.ts  # Anthropic Claude example
├── package.json
├── tsconfig.json
├── .env.example
└── README.md
```

## Next Steps

- [Proxy Mode](../proxy-mode/typescript/) - Simpler integration, AxonFlow handles LLM routing
- [LangChain Integration](../../langchain/) - Use with LangChain framework
- [Policy Management](../../../policies/crud/) - Create custom policies

## Gateway Policy Configuration

Gateway mode supports dedicated policy configuration env vars that override the global defaults:

| Variable | Default | Description |
|----------|---------|-------------|
| `GATEWAY_PII_ACTION` | (inherits `PII_ACTION`) | PII detection action in gateway mode: `redact`, `block`, or `log` |
| `GATEWAY_SQLI_ACTION` | (inherits `SQLI_ACTION`) | SQLi detection action in gateway mode: `block`, `warn`, or `log` |

These allow you to have different policy behavior in gateway mode vs. proxy mode. For example, you might want gateway mode to only log PII (since the caller handles redaction) while proxy mode blocks it:

```bash
export PII_ACTION=block              # Default for proxy mode
export GATEWAY_PII_ACTION=log        # Override for gateway mode
```

## Troubleshooting

### Connection Refused

```
Error: connect ECONNREFUSED 127.0.0.1:8080
```

**Solution:** Start AxonFlow with `docker compose up -d`

### Invalid API Key

```
Error: OpenAI API key is invalid
```

**Solution:** Check your `.env` file has a valid `OPENAI_API_KEY`

### Pre-check Blocked

If requests are unexpectedly blocked, check:
1. Query content for PII patterns
2. SQL-like syntax in the query
3. User role permissions in context
