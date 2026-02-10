# Feature Limits Examples

> **Tier compatibility:** Community / Evaluation. These examples work without any license
> (Community mode) and with a free Evaluation license. No paid license required.

These examples test the tier-based feature limits introduced alongside the Evaluation tier:

| Limit | Community | Evaluation | Enterprise |
|-------|-----------|------------|------------|
| LLM providers | 2 | 3 | Unlimited |
| Execution history | 50 | 500 | Unlimited |
| Concurrent executions | 5 | 25 | Unlimited |
| MAP plans | 25 | 100 | Unlimited |
| Versions per plan | 10 | 25 | Unlimited |
| SSE connections | 5 | 25 | Unlimited |

## Running

```bash
# Start AxonFlow
docker compose up -d

# Community mode (default — no license needed)
cd http && bash test_feature_limits.sh

# Evaluation mode (requires free Evaluation license)
AXONFLOW_LICENSE_KEY="<evaluation-key>" bash test_feature_limits.sh
```

## What's Tested

1. **LLM Provider Count** - Register providers up to the tier limit, verify the next registration is rejected
2. **Execution History Cap** - Verify list endpoint caps results to tier limit
3. **Concurrent Execution Limit** - Start executions up to the tier limit, verify the next returns 429
4. **Plan Versioning Limits** - Create plans and versions up to tier limits, verify enforcement
5. **SSE Connection Limits** - Open concurrent SSE streams to verify per-tenant limit enforcement (5/25/unlimited)

## Expected Behavior

### Community Mode (no license)
- 3rd LLM provider registration fails
- Execution list capped at 50
- 6th concurrent execution returns 429
- 26th plan creation fails
- 6th SSE connection returns 429

### Evaluation Mode (free license)
- 4th LLM provider registration fails
- Execution list capped at 500
- 26th concurrent execution returns 429
- 101st plan creation fails
- 26th SSE connection returns 429

### Enterprise Mode (paid license)
- No provider limit
- No execution history cap
- No concurrent execution limit
- No plan limit
- No SSE connection limit
