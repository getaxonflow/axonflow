# AxonFlow Telemetry

AxonFlow sends an anonymous usage heartbeat so we can understand adoption, prioritise features, and detect version-compatibility problems.

**The customer-facing page is <https://docs.getaxonflow.com/docs/telemetry>.** It is the one to send anyone outside the engineering team to, and it is the one whose wording is a public commitment. This page is the in-repo summary; [TELEMETRY_CONTRACT.md](TELEMETRY_CONTRACT.md) is the machine-checkable specification, and its vocabulary tables are pinned to the Go source by a test.

> **Corrections landed 2026-09-02 (#3660).** This page previously said telemetry came from "4 SDKs" (there are five), offered a `TelemetryEnabled` / `telemetry: false` configuration opt-out (removed in SDK v8.0 - `AXONFLOW_TELEMETRY=off` is the only lever), described only the SDK heartbeat, and stated a **90-day** retention when the checkpoint table's TTL has been **180 days** since v6.2.0. The retention line is the one that mattered: it understated how long data is kept, on the page an engineer would reach for when answering a customer.

## Who emits

| Class | Emitters | Cadence |
|---|---|---|
| SDK | Go, Python, TypeScript, Java, Rust | At most one ping per environment per 7 days, from the request path and at client construction |
| Plugin | OpenClaw, Claude Code, Cursor, Codex | At most one ping per environment per 7 days, from the hook path |
| Platform | agent, orchestrator, gateway-adapters | At most one ping per **binary** per 7 days, at startup |

## What Is Collected

| Field | Example | Purpose |
|---|---|---|
| SDK language | `go` | Language distribution |
| SDK version | `9.3.0` | Version-adoption tracking |
| Platform version | `10.4.0` | Compatibility monitoring |
| OS | `linux` | Platform-support priority |
| Architecture | `amd64` | ARM vs x86 distribution |
| Runtime version | `1.25.0` | Minimum-runtime support |
| Deployment mode (topology) | `self_hosted` | Where the platform runs, derived from the endpoint URL. Never the URL itself. |
| **Platform deployment mode** | `in-vpc-enterprise` | The platform's own `DEPLOYMENT_MODE` setting. Omitted when unset. |
| **Edition** | `enterprise` | Which build is running (the enterprise build tag). Not a licence and not an entitlement. |
| Licence tier | `Enterprise` | Coarse tier bucket. No key, no expiry, no seat count, no customer name. |
| Environment class | `ecs_fargate` | Where the platform binary runs |
| **Org ID** | `acme-corp`, or `cs_<uuid>` on Community SaaS | The org the deployment is licensed under. Used to tell AxonFlow's own infrastructure apart from customer deployments. |
| Instance ID | `a1b2c3d4-...` | Dedup. A random UUID; for SDKs it is fresh per client start, for platform binaries it is persisted in the stamp file so the 7-day limit survives restarts. |

## What Is NEVER Collected

- Prompts, responses, or LLM payloads
- Tool arguments or function-call data
- API keys, credentials, or tokens
- Tenant names, company names, or user identifiers
- Hostnames, URLs, file paths, environment variables, or system configuration
- Raw IP addresses (hashed with a rotating salt server-side, never stored in plaintext)
- Any personally identifiable information, or a hash of any of the above

## Defaults

Telemetry is **on** unless `AXONFLOW_TELEMETRY=off` is set. That includes localhost and self-hosted evaluation deployments.

**Sandbox mode does NOT suppress the ping.** A sandbox-mode client sends the heartbeat tagged `stream=sandbox` so analytics can separate development traffic from production without pretending it does not exist.

Platform binaries add one non-user gate: emission is suppressed when `CI` or `GITHUB_ACTIONS` is set, unless the operator sets `AXONFLOW_TELEMETRY=on` explicitly. CI runs are not deployments; their pings are noise. This is defence in depth, not a second opt-out - operators of real deployments never set those variables.

## How to Opt Out

```bash
export AXONFLOW_TELEMETRY=off
```

That is the whole lever, and it is the only one. The SDK configuration flag (`TelemetryEnabled` in Go, `telemetry=False` in Python, and their siblings) was **removed in SDK v8.0**; a build that still accepts it is below the current floor.

`AXONFLOW_TELEMETRY=off` disables the anonymous heartbeat. On **self-hosted** and **in-VPC** deployments that heartbeat is the only data the SDK, plugin or platform sends to AxonFlow, so `=off` means we receive nothing. On **Community SaaS** (`try.getaxonflow.com`) the hosted service also processes operational data (registrations, audit logs, policy-enforcement records, workflow state) as part of running the platform; that flow is governed by the [Privacy Policy](https://getaxonflow.com/privacy/), not by this variable. If you need a no-data-leaves-the-network guarantee, self-host.

> `DO_NOT_TRACK` is **not** honored. Host tools and developer CLIs inject it unconditionally, which makes it an unreliable expression of user intent. Use `AXONFLOW_TELEMETRY=off`.

## Technical Details

- The heartbeat never blocks or delays initialisation or an API call. SDK timeout 3 s, platform timeout 5 s, background delivery, failures silent.
- **Retention: 180 days**, then the row's DynamoDB TTL deletes it (`telemetry.TTLDays`; bumped from 90 in v6.2.0).
- Endpoint: `https://checkpoint.getaxonflow.com/v1/ping`, overridable for testing via `AXONFLOW_CHECKPOINT_URL`.
- Every platform binary prints the exact JSON payload to stderr on delivery, so an operator can audit what leaves.

## Contact

Questions about telemetry? Email security@getaxonflow.com.
