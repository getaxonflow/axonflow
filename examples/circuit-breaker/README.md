# Circuit Breaker Example (EU AI Act Article 14)

This example demonstrates the **Circuit Breaker** functionality for EU AI Act Article 14 compliance (Human oversight and intervention mechanisms).

## What is the Circuit Breaker?

The circuit breaker is an emergency stop mechanism that allows operators to immediately halt AI processing when:
- An anomaly is detected in AI behavior
- Human intervention is required
- Emergency situations occur
- Regulatory compliance requires an immediate stop

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/circuit-breaker/status` | Get current circuit breaker status |
| `POST` | `/api/v1/circuit-breaker/activate` | Activate circuit breaker (stop all AI) |
| `POST` | `/api/v1/circuit-breaker/deactivate` | Deactivate circuit breaker (resume) |

## SDK Status

> **Note:** SDK methods for circuit breaker are planned for a future release.
> Currently only available via HTTP API.

**Planned SDK Methods:**
- `ActivateCircuitBreaker(reason, scope, duration)`
- `DeactivateCircuitBreaker(reason)`
- `GetCircuitBreakerStatus()`

## Prerequisites

```bash
# Start AxonFlow
cd /path/to/axonflow-enterprise
docker compose up -d

# Verify services are healthy
curl http://localhost:8080/health
```

## Running the Example

### HTTP (curl)

```bash
cd http
chmod +x circuit-breaker.sh
./circuit-breaker.sh
```

## Expected Output

```
AxonFlow Circuit Breaker - HTTP API Example
============================================

1. Get Circuit Breaker Status
------------------------------
Response: {"active":false}
Circuit Breaker Active: false

2. Activate Circuit Breaker
----------------------------
Response: {"success":true,"activated":true}
Circuit Breaker ACTIVATED successfully!

3. Verify Status is Active
---------------------------
Response: {"active":true,"reason":"Demo...","activated_at":"..."}
Circuit Breaker Active: true

4. Test Request During Circuit Breaker Active
----------------------------------------------
Request correctly BLOCKED by circuit breaker

5. Deactivate Circuit Breaker
------------------------------
Response: {"success":true,"deactivated":true}
Circuit Breaker DEACTIVATED successfully!

6. Verify Status is Inactive
-----------------------------
Circuit Breaker Active: false
Circuit breaker is now INACTIVE - normal operation resumed
```

## Circuit Breaker Scopes

| Scope | Description |
|-------|-------------|
| `global` | All tenants (requires admin) |
| `organization` | All tenants in organization |
| `tenant` | Single tenant only |

## Request Body: Activate

```json
{
  "reason": "Emergency: Unusual AI behavior detected",
  "scope": "tenant",
  "activated_by": "operator@company.com",
  "duration_seconds": 3600
}
```

## Request Body: Deactivate

```json
{
  "reason": "Issue resolved, resuming normal operation",
  "deactivated_by": "operator@company.com"
}
```

## Status Response

```json
{
  "active": true,
  "reason": "Emergency: Unusual AI behavior detected",
  "scope": "tenant",
  "activated_by": "operator@company.com",
  "activated_at": "2026-01-04T12:00:00Z",
  "expires_at": "2026-01-04T13:00:00Z"
}
```

## EU AI Act Article 14 Compliance

The circuit breaker helps organizations comply with EU AI Act Article 14:

1. **Human Oversight**: Operators can intervene at any time
2. **Control Mechanisms**: Immediate stop capability
3. **Audit Trail**: All activations are logged with reason and operator
4. **Scope Control**: Granular control at tenant, org, or global level

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AXONFLOW_AGENT_URL` | `http://localhost:8080` | Agent URL |
| `AXONFLOW_TENANT_ID` | `test-org-001` | Tenant ID |
| `AXONFLOW_CLIENT_SECRET` | `demo-secret` | Client secret |

## Related Examples

- [HITL](../hitl/) - Human-in-the-Loop approval workflows
- [Execution Replay](../execution-replay/) - Decision audit trails
- [EU AI Act Compliance](../../ee/examples/compliance/eu-ai-act/) - Full compliance suite

## Troubleshooting

### "Unauthorized" error
Circuit breaker operations require appropriate permissions. Ensure your client has operator-level access.

### "Feature not available" error
Circuit breaker may require an Enterprise license for full functionality.

### Circuit breaker doesn't block requests
Ensure the circuit breaker scope matches your tenant and the activation was successful.
