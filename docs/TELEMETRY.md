# AxonFlow SDK Telemetry

AxonFlow SDKs send anonymous usage telemetry to help us understand adoption, prioritize features, and detect version compatibility issues. This document describes exactly what is collected, what is never collected, how localhost/self-hosted evaluation behaves, and how to opt out.

## What Is Collected

When the SDK client is initialized, a single HTTP request is sent with:

| Field | Example | Purpose |
|-------|---------|---------|
| SDK language | `go` | Language distribution |
| SDK version | `4.1.0` | Version adoption tracking |
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
| All other modes (production, enterprise, community, localhost/self-hosted evaluation, etc.) | **On** |

Telemetry is on by default so we can understand SDK adoption, prioritize features, and detect version compatibility issues. Localhost and self-hosted evaluation environments follow the same default-on behavior unless you explicitly opt out. Sandbox mode defaults to off since it's intended for isolated local testing and development. You can always opt out using any of the methods below.

## How to Opt Out

Any of these methods will disable telemetry:

### Environment variable

```bash
# AxonFlow-specific opt-out (canonical and only)
export AXONFLOW_TELEMETRY=off
```

#### Scope of `AXONFLOW_TELEMETRY=off`

`AXONFLOW_TELEMETRY=off` disables the anonymous SDK/plugin heartbeat (version, OS, architecture). On **self-hosted** and **in-VPC** deployments, that heartbeat is the only data the SDK or plugin sends to AxonFlow, so setting `=off` means we receive nothing. On **Community SaaS** (`try.getaxonflow.com`) the hosted service also processes operational data — registrations, audit logs, policy enforcement records, workflow state, plan data, and request-header metadata aggregated for usage analytics — as part of running the platform; that operational data flow is governed by the [Privacy Policy](https://getaxonflow.com/privacy/), not by `AXONFLOW_TELEMETRY`. If you need no-data-leaves-network guarantees, self-host AxonFlow Community Edition.

> **Note:** `DO_NOT_TRACK` is **not** honored as an opt-out for AxonFlow telemetry. It is commonly inherited from host tools and developer environments (CLIs like Codex and Claude Code inject it unconditionally), which makes it an unreliable expression of user intent. Use `AXONFLOW_TELEMETRY=off` instead.

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
- Localhost and self-hosted endpoints do not suppress telemetry outside sandbox mode
- The HTTP call uses a 3-second timeout and runs in a background thread/goroutine
- SDK initialization is never blocked or delayed by telemetry
- If the telemetry endpoint is unreachable, the failure is silent
- Data is retained for 90 days, then automatically deleted

## Endpoint

Telemetry is sent to `https://checkpoint.getaxonflow.com/v1/ping`. The endpoint can be overridden for testing via the `AXONFLOW_CHECKPOINT_URL` environment variable.

## Contact

Questions about telemetry? Email security@getaxonflow.com.
