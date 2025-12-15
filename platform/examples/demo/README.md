# AxonFlow Interactive Demo

A quick interactive demo that showcases AxonFlow's governance capabilities in action.

## Prerequisites

- AxonFlow platform running via `docker-compose up -d`
- Services healthy (check with `docker-compose ps`)
- Python SDK installed (for Python examples): `pip install axonflow`

## Quick Start

```bash
# From repository root
./platform/examples/demo/demo.sh
```

## What It Demonstrates

| Demo | Description | Expected Result |
|------|-------------|-----------------|
| **PII Detection** | SSN in prompt | 🛡️ BLOCKED |
| **Safe Query** | Normal question | ✅ ALLOWED |
| **Credit Card Detection** | Card number in prompt | 🛡️ BLOCKED |
| **Latency Check** | 5 policy evaluations | ⚡ Sub-10ms average |

## Sample Output

```
╔═══════════════════════════════════════════════════════════════╗
║               AxonFlow Interactive Demo                       ║
║          Real-time AI Governance in Action                    ║
╚═══════════════════════════════════════════════════════════════╝

Demo 1: PII Detection & Blocking
🛡️  BLOCKED - SSN pattern detected in real-time

Demo 2: Safe Query (Allowed)
✓ ALLOWED - No policy violations

Demo 3: Credit Card Detection
🛡️  BLOCKED - Credit Card Detected

Demo 4: Sub-10ms Policy Evaluation
⚡ Average latency: 4ms
```

## Python SDK Examples

These Python files are **runnable** demos of AxonFlow integration patterns:

| File | Description | Runnable |
|------|-------------|----------|
| `01_unprotected_call.py` | Typical unprotected LLM call (the problem) | Yes (needs OpenAI key) |
| `02_governed_call.py` | Same call with AxonFlow governance | Yes |
| `03_pii_demo.py` | PII detection blocking SSN in prompts | Yes |
| `04_gateway_mode.py` | Gateway mode for existing LLM integrations | Yes (needs OpenAI key) |
| `05_map.yaml` | Multi-Agent Planning workflow definition | Config file |
| `06_map_call.py` | Executing a MAP workflow | Yes |

### Running the Python Demos

```bash
# 1. Install dependencies
pip install axonflow openai

# 2. Set environment variables
export AXONFLOW_AGENT_URL=http://localhost:8080
export AXONFLOW_CLIENT_ID=demo-client
export AXONFLOW_CLIENT_SECRET=demo-secret
export OPENAI_API_KEY=sk-your-key  # for 01 and 04

# 3. Run any example
python 02_governed_call.py
python 03_pii_demo.py  # See PII blocking in action!
```

### Expected Output (03_pii_demo.py)

```
PolicyViolationError: Request blocked (SSN detected)
Policy: pii-ssn
Reason: SSN pattern detected in request
```

## Next Steps

After running the demo:

1. **Try the Support Demo**: A full application with UI
   ```bash
   cd platform/examples/support-demo
   docker-compose up -d
   ```

2. **Explore SDK Examples**: See `examples/hello-world/` for code examples

3. **Read the Docs**: https://docs.getaxonflow.com

## Customization

Set custom agent URL:
```bash
AXONFLOW_AGENT_URL=http://your-agent:8080 ./platform/examples/demo/demo.sh
```
