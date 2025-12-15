# AxonFlow Interactive Demo

A quick interactive demo that showcases AxonFlow's governance capabilities in action.

## Prerequisites

- AxonFlow platform running via `docker-compose up -d`
- Services healthy (check with `docker-compose ps`)
- Python SDK installed: `pip3 install axonflow`

## Quick Start

```bash
# From repository root
./examples/demo/demo.sh
```

## Demo Files

### Full Examples (Runnable)

| File | Description | Run |
|------|-------------|-----|
| `01_unprotected_call.py` | Typical unprotected LLM call (the problem) | `python3 01_unprotected_call.py` |
| `02_governed_call.py` | Same call with AxonFlow governance | `python3 02_governed_call.py` |
| `03_pii_demo.py` | PII detection blocking SSN in prompts | `python3 03_pii_demo.py` |
| `04_gateway_mode.py` | Gateway mode for existing LLM integrations | `python3 04_gateway_mode.py` |
| `05_map.yaml` | Multi-Agent Planning workflow definition | Config file |
| `06_map_call.py` | Executing a MAP workflow | `python3 06_map_call.py` |

### Snippets (For Presentation - Not Runnable)

Minimal code snippets for slides/presentations. Show snippets for understanding, run full files for proof.

| File | Purpose |
|------|---------|
| `snippets/01_unprotected_snippet.py` | Direct LLM call (the problem) |
| `snippets/02_governed_snippet.py` | AxonFlow governed call |
| `snippets/03_pii_snippet.py` | PII blocking |
| `snippets/04_gateway_snippet.py` | Gateway mode (3 steps) |
| `snippets/06_map_snippet.py` | Multi-Agent Planning |

## Running the Demos

```bash
# 1. Install dependencies
pip3 install axonflow openai

# 2. Set environment variables
export AXONFLOW_AGENT_URL=http://localhost:8080
export AXONFLOW_CLIENT_ID=demo-client
export AXONFLOW_CLIENT_SECRET=demo-secret
export OPENAI_API_KEY=sk-your-key  # for 01 and 04

# 3. Run any example
python3 02_governed_call.py
python3 03_pii_demo.py  # See PII blocking in action!
```

## Expected Output

### 03_pii_demo.py
```
🛡️  REQUEST BLOCKED
   Reason: US Social Security Number pattern detected
   Policy: pii_ssn_detection
```

## Next Steps

After running the demo:

1. **Try the Support Demo**: A full application with UI
   ```bash
   cd examples/support-demo
   docker-compose up -d
   ```

2. **Explore Workflow Examples**: See `examples/workflows/` for Go SDK examples

3. **Read the Docs**: https://docs.getaxonflow.com
