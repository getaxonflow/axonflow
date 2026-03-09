# AxonFlow SDK Telemetry

AxonFlow SDKs send anonymous usage telemetry to help us understand adoption, prioritize features, and detect version compatibility issues. This document describes exactly what is collected, what is never collected, and how to opt out.

## What Is Collected

When the SDK client is initialized, a single HTTP request is sent with:

| Field | Example | Purpose |
|-------|---------|---------|
| SDK language | `go` | Language distribution |
| SDK version | `4.0.0` | Version adoption tracking |
| Platform version | `4.8.0` | Compatibility monitoring |
| OS | `linux` | Platform support priority |
| Architecture | `amd64` | ARM vs x86 distribution |
| Runtime version | `go1.22.0` | Minimum runtime support |
| Deployment mode | `enterprise` | Community vs enterprise ratio |
| Instance ID | `a1b2c3d4-...` | Dedup (random UUID, not identity) |

The instance ID is a random UUID generated fresh each time the client starts. It is not tied to any user, company, machine, or persistent identity.

## What Is NEVER Collected

- Prompts, responses, or LLM payloads
- Tool arguments or function call data
- API keys, credentials, or tokens
- Tenant names, company names, or user identifiers
- File paths, environment variables, or system configuration
- Raw IP addresses (hashed for dedup server-side, never stored in plaintext)
- Any personally identifiable information (PII)

## Defaults

| Mode | Default |
|------|---------|
| Sandbox | **Off** |
| All other modes (production, enterprise, community, etc.) | **On** |

Telemetry is on by default so we can understand SDK adoption, prioritize features, and detect version compatibility issues. Sandbox mode defaults to off since it's intended for local testing and development. You can always opt out using any of the methods below.

## How to Opt Out

Any of these methods will disable telemetry:

### Environment variables

```bash
# Standard opt-out (respected by many tools)
export DO_NOT_TRACK=1

# AxonFlow-specific
export AXONFLOW_TELEMETRY=off
```

### SDK configuration

```go
// Go
client := axonflow.NewClient(axonflow.Config{
    TelemetryEnabled: axonflow.Bool(false),
})
```

```python
# Python
client = AxonFlow(telemetry=False)
```

```typescript
// TypeScript
const client = new AxonFlow({ telemetry: false });
```

```java
// Java
AxonFlow client = AxonFlow.builder()
    .telemetry(false)
    .build();
```

## Technical Details

- Telemetry is sent once per client initialization (not per request)
- The HTTP call uses a 3-second timeout and runs in a background thread/goroutine
- SDK initialization is never blocked or delayed by telemetry
- If the telemetry endpoint is unreachable, the failure is silent
- Data is retained for 90 days, then automatically deleted

## Endpoint

Telemetry is sent to `https://checkpoint.getaxonflow.com/v1/ping`. The endpoint can be overridden for testing via the `AXONFLOW_CHECKPOINT_URL` environment variable.

## Contact

Questions about telemetry? Email security@getaxonflow.com.
