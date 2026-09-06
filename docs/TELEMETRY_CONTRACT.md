# AxonFlow Telemetry Contract

Canonical specification for AxonFlow's anonymous telemetry. It covers three emitter classes:

| Class | Who emits | Where the code lives |
|---|---|---|
| **SDK** | All **five** language SDKs (Go, Python, TypeScript, Java, Rust) | each SDK's own heartbeat module |
| **Plugin** | The IDE / agent plugins (OpenClaw, Claude Code, Cursor, Codex) | each plugin repository |
| **Platform** | The AxonFlow binaries themselves - agent, orchestrator, gateway-adapters | `platform/shared/heartbeat` |

Any deviation is a bug. The customer-facing overview lives at
<https://docs.getaxonflow.com/docs/telemetry>; this file is the machine-checkable contract.

> **This file was materially stale before 2026-09-02 (#3660).** It said "All 4 SDKs" (there are five),
> gave `enterprise` as a `deployment_mode` example (that value was removed from the topology enum in the
> v1 schema), and described only the SDK class. The vocabulary tables below are now **pinned to the Go
> source by `TestDocsVocabularyTablesMatchTheGoSource`** in
> `ee/platform/checkpoint-service/pkg/telemetry`, so a value added on one side and not the other fails
> the build rather than quietly making this page wrong again.

## Cadence - 7-Day Delivered-Heartbeat

> **AxonFlow emits at most one anonymous heartbeat per environment every 7 days during SDK activity.**

The SDK consults the gate at every public HTTP request site (and at client construction). Each gate run:

1. Re-evaluates `AXONFLOW_TELEMETRY=off` cheaply (lock-free) so a mid-process opt-out toggle takes effect immediately.
2. Checks an in-memory 1-hour cache to bound stat() syscall frequency on hot paths.
3. Reads the stamp file mtime as the source of truth for last successful delivery across process restarts.
4. Sends the ping and writes the stamp **only on successful delivery** (HTTP 2xx). Failed POSTs leave the stamp unchanged so the next call after the 1-hour cache expires retries - a transient network failure does not silence telemetry for 7 days.
5. Coalesces concurrent callers via an in-flight flag so a stampede across the boundary fires exactly one POST.

### Stamp file

| Platform | Path |
|---|---|
| macOS | `~/Library/Caches/axonflow/{sdk}-telemetry-last-sent` |
| Linux | `$XDG_CACHE_HOME/axonflow/...` or `~/.cache/axonflow/...` |
| Windows | `%LOCALAPPDATA%/axonflow/...` |

`{sdk}` is one of `go`, `python`, `typescript`, `java`. Resolved via OS-native conventions (`os.UserCacheDir()` in Go, hand-rolled in Python/TS/Java to keep the SDK dependency-free). When no cache directory is available (e.g. AWS Lambda where `HOME`/`LOCALAPPDATA` is unset), the SDK falls back to "one ping per process" - same as the pre-heartbeat behavior. No regression for that runtime.

### Constants

| Constant | Value | Purpose |
|---|---|---|
| `HEARTBEAT_INTERVAL` | 7 days | Maximum interval between successful heartbeats |
| `HEARTBEAT_GUARD_INTERVAL` | 1 hour | In-memory cache to bound stat() syscall frequency |

## Decision Logic

```
Inputs:
  mode:                   string ("sandbox" | anything else)
  config.telemetry:       true | false | undefined/null
  env.AXONFLOW_TELEMETRY: string

Rule order (highest priority first):
  1) if lower(trim(AXONFLOW_TELEMETRY)) == "off" => OFF
  2) if config.telemetry == false                => OFF
  3) if config.telemetry == true                 => ON
  4) if mode == "sandbox"                        => OFF
  5) otherwise                                   => ON
```

`AXONFLOW_TELEMETRY=off` always wins. Config flag overrides mode-based defaults but cannot override the env var. No credential-based logic - credentials do not affect telemetry defaults. Endpoint host does not affect defaults either: localhost, private-network, and self-hosted evaluation endpoints are still ON unless sandbox mode or an opt-out disables telemetry.

### Deployment-shape note: scope of the opt-out

`AXONFLOW_TELEMETRY=off` controls the SDK/plugin **heartbeat**. On self-hosted and in-VPC deployments, that heartbeat is the only data path from the SDK or plugin to AxonFlow, so the env var is the relevant opt-out lever. On **Community SaaS** (`try.getaxonflow.com`) the hosted service also processes operational data - registrations, audit logs, policy enforcement records, workflow state, plan data, and request-header metadata aggregated for usage analytics - as part of running the platform. That operational data flow is governed by the [Privacy Policy](https://getaxonflow.com/privacy/) rather than by this env var; the contract documented here applies to the heartbeat path only.

> **Note on `DO_NOT_TRACK`:** It is **not** honored as an opt-out for AxonFlow telemetry. It is commonly inherited from host tools and developer environments (CLIs like Codex and Claude Code inject it unconditionally), which makes it an unreliable expression of user intent. SDKs do not read this variable at all.

## Runtime Behavior

| Requirement | Value |
|---|---|
| Execution model | Synchronous-bounded at construction (so short-lived processes deliver); asynchronous from request-path hooks (so user API calls are never delayed) |
| Per-call HTTP timeout | 3 seconds |
| Failure handling | Silent - no errors surfaced to user code |
| Frequency | At most one ping per machine per `HEARTBEAT_INTERVAL` (7 days) |
| Endpoint override | `AXONFLOW_CHECKPOINT_URL` env var replaces default endpoint |
| Default endpoint | `https://checkpoint.getaxonflow.com/v1/ping` |

## Payload Contract

### Required fields

| Field | Type | Example |
|---|---|---|
| `sdk` | string | `"go"`, `"python"`, `"typescript"`, `"java"`, `"rust"`. Empty on a platform-class ping. |
| `sdk_version` | string | `"9.3.0"`. Empty on a platform-class ping. |
| `os` | string | `"linux"`, `"Darwin"`, `"Windows"` |
| `arch` | string | `"amd64"`, `"arm64"` |
| `runtime_version` | string | `"1.22.0"`, `"3.12.0"`, `"20.11.0"`, `"21.0.1"` |
| `deployment_mode` | string | The TOPOLOGY bucket: `"self_hosted"`, `"community_saas"`, `"unknown"`. **Not** the platform's own `DEPLOYMENT_MODE` - see `platform_deployment_mode` below. |
| `instance_id` | string | SDK/plugin: a random UUID v4, fresh per client start. Platform: a UUID v4 PERSISTED in the stamp file across restarts. |

### Optional fields

Every field here is `omitempty`. **An omitted field means NOT REPORTED, which is
never the same as any value it could have carried.** A reader that folds an
absent `edition` into `community` invents a claim about a deployment nobody
measured.

| Field | Type | Set by | Meaning when present |
|---|---|---|---|
| `platform_version` | string | all classes | The platform version. SDK and plugin pings report the platform they are configured against; platform pings report their own. **Required** on a platform-class ping - the wire rejects one without it. |
| `features` | string[] | SDK | Free-form feature markers, plus the reserved `adapter:<name>` vocabulary below. |
| `telemetry_type` | string | all classes | `sdk` \| `plugin` \| `platform` \| `synthetic`. |
| `component` | string | platform only | Which binary emitted it. Rejected on any other class. |
| `org_id` | string | all classes | The org identifier the deployment is licensed under. On Community SaaS this is the registration's `cs_<uuid>` tenant id. Used for internal-vs-external classification at the receiver. |
| `license_tier` | string | all classes | The tier the platform reported on its own `/health`. Adoption signal only. |
| `environment_class` | string | platform only | `lambda` \| `ecs_fargate` \| `ecs_ec2` \| `kubernetes` \| `container` \| `bare_metal` \| `unknown`. |
| `edition` | string | platform, relayed by SDK/plugin | Which BUILD is running. See the vocabulary below. |
| `platform_deployment_mode` | string | platform, relayed by SDK/plugin | The platform's OWN `DEPLOYMENT_MODE` setting. See the vocabulary below. |
| `stream` | string | SDK/plugin/platform | `heartbeat` (default) or `sandbox`. |
| `endpoint_type` | string | SDK | `localhost` \| `private_network` \| `remote` \| `unknown`. The raw URL is never sent. |

### Three different things are called a "deployment mode". Do not merge them.

1. **`deployment_mode`** (wire field) - the coarse TOPOLOGY, derived by an SDK
   from the endpoint URL it was pointed at, or by a platform binary from whether
   it is a Community-SaaS stack. Vocabulary: `self_hosted`, `community_saas`,
   `unknown`.
2. **`platform_deployment_mode`** (wire field) - the value of the platform's own
   `DEPLOYMENT_MODE` environment variable, which decides which migration
   categories it applies and therefore which tables its database has.
3. **`edition`** (wire field) - the enterprise BUILD TAG. Orthogonal to both:
   the Community-SaaS fleet runs the *enterprise* build against the
   *community-saas* schema.

On the platform's `/health` response the member is called **`deployment_mode`**
because there the platform is describing itself. **A relaying client maps that
member onto the ping's `platform_deployment_mode`, never onto the ping's own
`deployment_mode`** - the two are different dimensions and conflating them
corrupts every existing deployment-mode breakdown.

### Vocabulary: `edition`

<!-- vocab:edition:begin -->
- `community`
- `enterprise`
<!-- vocab:edition:end -->

Unrecognised values normalise to `unknown` server-side; they are never rejected.
Omitted means not reported.

### Vocabulary: `platform_deployment_mode`

<!-- vocab:platform_deployment_mode:begin -->
- `community`
- `community-saas`
- `enterprise`
- `evaluation`
- `in-vpc-banking`
- `in-vpc-enterprise`
- `in-vpc-healthcare`
- `in-vpc-travel`
- `invpc`
- `saas`
<!-- vocab:platform_deployment_mode:end -->

`enterprise` and `invpc` are accepted ALIASES and fold to `in-vpc-enterprise`
before storage, so one population is never split across two rows. Unrecognised
values normalise to `unknown`. An unset `DEPLOYMENT_MODE` OMITS the field - it
does not report `community`, because the schema default for an unset value is
not a statement about what the operator configured and the runtime posture for
unset is not the community one.

### Vocabulary: `component` (platform class only)

<!-- vocab:component:begin -->
- `agent`
- `gateway-adapters`
- `orchestrator`
<!-- vocab:component:end -->

Unlike the coarse enums above, an unrecognised `component` IS rejected with HTTP
400: it is a class-shape rule, not an adoption dimension.

### Vocabulary: `features[]` adapter markers

<!-- vocab:adapter:begin -->
- `langchain`
- `langgraph`
<!-- vocab:adapter:end -->

Sent as `adapter:<name>` inside `features[]`.

**The bucketing is READ-TIME, not write-time.** `features` is stored VERBATIM -
it is a free-form array and the receiver does not rewrite it, exactly as it does
not rewrite any other free-form field. `telemetry.NormalizeAdapterFeature` is
applied by READERS (the operator digest's `ByAdapter` breakdown) at the moment
an entry becomes a breakdown label, which is the moment an unbounded value would
become a cardinality incident. An unrecognised adapter therefore reaches storage
as written and is RENDERED as `adapter:unknown`, so "someone is using an adapter
we do not know about" stays visible instead of vanishing - and the raw name is
still on the row for whoever goes to look.

The closed set is what bounds the breakdown, not what bounds the wire.

**`features` itself IS bounded, though**, and verbatim storage is exactly why the
bound had to be stated: at most **32 entries**, each at most **128 bytes**. The
excess is **DROPPED, not refused** - entries past the cap are discarded and an
over-long entry is truncated, while the ping still lands with everything else
intact. A client sending an oversized array is far more likely to be buggy than
hostile, and refusing it would throw away an otherwise-good adoption datum over
a field nothing gates on. Before 10.4.0 the only limit was the 64 KiB request
body, which permits thousands of short entries on a single row.

### Constraints

- SDK/plugin `instance_id` must be a random UUID generated fresh per client
  initialisation. It must not be tied to any identity. Platform `instance_id` IS
  persisted in the stamp file - that is what makes the 7-day rate limit hold
  across restarts - and is still tied to nothing but the stamp file itself.
- `sdk` must be one of `go`, `python`, `typescript`, `java`, `rust` for an
  SDK-class ping, and empty for a platform-class ping.
- Every coarse-enum value is bounded at 64 bytes.
- Nothing customer-identifying is ever sent on any field: no hostnames, no URLs,
  no tenant names, no user identities, and no hashes of any of those.

## Platform-binary heartbeat

The AxonFlow binaries emit their own platform-class heartbeat. One
implementation serves all three - `platform/shared/heartbeat` - so the agent,
the orchestrator and the gateway adapters cannot drift.

| Property | Value |
|---|---|
| Cadence | At most one ping per BINARY per 7 days. A host running the agent and the orchestrator emits one each, not one combined. |
| Stamp file | `<AXONFLOW_TELEMETRY_STAMP_DIR>/<binary>-startup-telemetry-stamp`, else the OS user-cache dir. `AXONFLOW_TELEMETRY_STAMP_DIR` is the only persistence override. |
| Opt-out | `AXONFLOW_TELEMETRY=off`, the same lever the SDKs honor. |
| CI auto-suppress | `CI` or `GITHUB_ACTIONS` set to anything other than `false` suppresses emission unless `AXONFLOW_TELEMETRY=on` is explicit. CI runs are not deployments. |
| Transparency | The exact JSON payload is printed to stderr on every delivery. |
| Timeout | 5 s; failures never block or fail startup. |
| Stamp-on-delivery | The stamp advances only on HTTP 2xx, so a transient failure does not silence a deployment for 7 days. |

**Community-SaaS stacks DO emit** (changed 2026-09-02, #3660). They previously
skipped emission entirely, which made the platform table's deployment-mode
column single-valued by construction. They are now classified internal at the
RECEIVER, from their `axonflow-`-prefixed `org_id` - suppressing at the emitter
destroyed the datum, classifying at the receiver keeps it and labels it.

## Conformance Test Matrix

Every SDK must have tests covering all of the following scenarios. The 9-case heartbeat matrix is the new addition for the delivered-heartbeat contract.

### Heartbeat gate (9 cases - pin the new contract)

| # | Scenario | Expected |
|---|----------|----------|
| H1 | Cold start, no stamp file | 1 ping fires; stamp written on success |
| H2 | Stamp written 1 day ago | 0 pings (within `HEARTBEAT_INTERVAL`) |
| H3 | Stamp written 8 days ago | 1 ping fires; stamp re-touched |
| H4 | 5 immediate calls within `HEARTBEAT_GUARD_INTERVAL` | Exactly 1 ping (in-memory cache holds) |
| H5 | Cache expired + stamp stale | 2nd ping fires; stamp updated |
| H6 | Telemetry disabled mid-process | 0 further pings; stamp unchanged |
| H7 | 100 concurrent callers crossing the boundary | Exactly 1 ping (in-flight gate coalesces) |
| H8 | No cache dir (e.g. Lambda restricted env) | Ping per process; no crash; no stamp persistence |
| H9 | Ping returns network failure (5xx, timeout) | Stamp NOT advanced; retry on success works |

### Decision logic (legacy gate - keep these passing)

| # | Scenario | Expected |
|---|----------|----------|
| 1 | `DO_NOT_TRACK=1` alone, config true | ON (regression: DNT no longer honored) |
| 2 | `AXONFLOW_TELEMETRY=off`, config true | OFF |
| 3 | `AXONFLOW_TELEMETRY=OFF` (uppercase) | OFF |
| 4 | `DO_NOT_TRACK=1` + `AXONFLOW_TELEMETRY=off` | OFF (canonical wins) |
| 5 | Config false, production mode | OFF |
| 6 | Config true, sandbox mode | ON |
| 7 | No env, no config, sandbox mode | OFF |
| 8 | No env, no config, production mode | ON |
| 9 | No env, no config, no credentials, production mode | ON |
| 10 | No env, no config, localhost/self-hosted endpoint, non-sandbox mode | ON |
| 11 | Custom `AXONFLOW_CHECKPOINT_URL` is used | Custom URL hit |
| 12 | Network timeout / connection error | No exception thrown |
| 13 | Server returns non-200 | No exception thrown |
| 14 | Payload contains all required fields | Validated |
| 15 | `instance_id` is unique across calls | Validated |

### Cross-process E2E (the 4-run cycle)

Every SDK must have an E2E test exercising the cross-restart stamp-file behavior:

| Run | Setup | Expected |
|---|---|---|
| 1 | Cold: no stamp; mock checkpoint returns 200 | 1 ping; stamp file present |
| 2 | Immediate re-run; fresh stamp | 0 pings |
| 3 | Backdate stamp -8d via `os.Chtimes` / `os.utime` / `Files.setLastModifiedTime` | 1 ping; stamp re-touched |
| 4 | Backdate stamp -8d; mock returns 503 | Attempt counted; stamp NOT advanced; retry against 200-mock lands cleanly |

## Implementation Locations

| SDK | Heartbeat module | Telemetry sender |
|---|---|---|
| Go | `heartbeat.go` | `telemetry.go` |
| Python | `axonflow/heartbeat.py` | `axonflow/telemetry.py` |
| TypeScript | `src/heartbeat.ts` | `src/telemetry.ts` |
| Java | `src/main/java/com/getaxonflow/sdk/telemetry/HeartbeatState.java` | `src/main/java/com/getaxonflow/sdk/telemetry/TelemetryReporter.java` |

## String Handling

All SDKs must:
- **Trim** whitespace from `AXONFLOW_TELEMETRY` before comparison
- **Case-insensitive** comparison for `AXONFLOW_TELEMETRY` (`"off"`, `"OFF"`, `"Off"` all match)

## Plugin parity

Plugins (Codex, Claude Code, Cursor, OpenClaw) ship a sibling 7-day-heartbeat contract via their own per-plugin stamp files. The plugin gate runs at every hook invocation rather than at SDK construction (OpenClaw runs it once per plugin registration). Otherwise the contract is identical:

> AxonFlow emits at most one anonymous heartbeat per environment every 7 days during SDK or plugin activity.

The plugin stamp files retain the legacy v0.4.x filenames rather than the SDK `{sdk}-telemetry-last-sent` convention:

- `$HOME/.cache/axonflow/codex-plugin-telemetry-sent`
- `$HOME/.cache/axonflow/claude-code-plugin-telemetry-sent`
- `$HOME/.cache/axonflow/cursor-plugin-telemetry-sent`
- OpenClaw uses the same `openclaw-plugin-telemetry-sent` filename under its OS-native cache directory (`~/Library/Caches/axonflow/` on macOS, `$XDG_CACHE_HOME/axonflow/` or `~/.cache/axonflow/` on Linux, `%LOCALAPPDATA%\axonflow\` on Windows)

The reason is `instance_id` continuity: the three bash plugins stored a per-machine UUID inside the stamp file at install time, and the 7-day plugin code re-uses that exact filename so existing installs preserve their `instance_id` across the upgrade. Without it, a single machine would appear as two distinct anonymous installs in the telemetry table. The OpenClaw plugin had no stamp file pre-heartbeat, but its filename follows the same convention so all four plugin surfaces stay consistent. SDKs ship the heartbeat from the start, so they use the more descriptive `{sdk}-telemetry-last-sent` naming.
