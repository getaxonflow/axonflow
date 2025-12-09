# AxonFlow Interactive Demo

A quick interactive demo that showcases AxonFlow's governance capabilities in action.

## Prerequisites

- AxonFlow platform running via `docker-compose up -d`
- Services healthy (check with `docker-compose ps`)

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
