# AxonFlow SDK Telemetry

AxonFlow SDKs send an anonymous usage heartbeat to help us understand adoption, prioritize features, and detect version compatibility issues. This page is the short overview; the authoritative behavioral specification — cadence, decision logic, payload contract, and conformance tests — is [TELEMETRY_CONTRACT.md](TELEMETRY_CONTRACT.md).

## Cadence

The SDK emits **at most one anonymous heartbeat per environment every 7 days** during SDK activity (the delivered-heartbeat model — a stamp file records the last successful delivery). Environments with no writable cache directory (e.g. AWS Lambda) fall back to one ping per process. See the [contract](TELEMETRY_CONTRACT.md#cadence--7-day-delivered-heartbeat) for the exact gate behavior.

## What Is Collected

| Field | Example | Purpose |
|-------|---------|---------|
| SDK language | `go` | Language distribution |
| SDK version | `9.0.0` | Version adoption tracking |
| Platform version | `9.12.0` | Compatibility monitoring |
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

Localhost and self-hosted evaluation environments follow the same default-on behavior unless you explicitly opt out.

## How to Opt Out

```bash
# AxonFlow-specific opt-out (canonical and only)
export AXONFLOW_TELEMETRY=off
```

Or via SDK configuration (`TelemetryEnabled: axonflow.Bool(false)` in Go, `telemetry=False` in Python, `{ telemetry: false }` in TypeScript, `.telemetry(false)` in Java). `AXONFLOW_TELEMETRY=off` always wins over configuration; the full precedence rules are in the [contract](TELEMETRY_CONTRACT.md#decision-logic).

`AXONFLOW_TELEMETRY=off` disables the anonymous SDK/plugin heartbeat. On **self-hosted** and **in-VPC** deployments, that heartbeat is the only data the SDK or plugin sends to AxonFlow, so setting `=off` means we receive nothing. On **Community SaaS** (`try.getaxonflow.com`) the hosted service also processes operational data (registrations, audit logs, policy enforcement records, workflow state) as part of running the platform; that flow is governed by the [Privacy Policy](https://getaxonflow.com/privacy/), not by `AXONFLOW_TELEMETRY`. If you need no-data-leaves-network guarantees, self-host AxonFlow Community Edition.

> **Note:** `DO_NOT_TRACK` is **not** honored as an opt-out for AxonFlow telemetry. It is commonly inherited from host tools and developer environments (CLIs like Codex and Claude Code inject it unconditionally), which makes it an unreliable expression of user intent. Use `AXONFLOW_TELEMETRY=off` instead.

## Technical Details

- The heartbeat never blocks or delays SDK initialization or API calls (3-second timeout, background delivery; failures are silent)
- Data is retained for 90 days, then automatically deleted
- Endpoint: `https://checkpoint.getaxonflow.com/v1/ping` (override for testing via `AXONFLOW_CHECKPOINT_URL`)
- Plugins (Claude Code, Codex, Cursor, OpenClaw) ship the same 7-day heartbeat contract — see [TELEMETRY_CONTRACT.md](TELEMETRY_CONTRACT.md#plugin-parity)

## Contact

Questions about telemetry? Email security@getaxonflow.com.
