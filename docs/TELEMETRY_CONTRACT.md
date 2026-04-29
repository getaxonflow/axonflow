# SDK Telemetry Contract

Canonical specification for SDK telemetry behavior. All 4 SDKs (Go, Python, TypeScript, Java) must conform to this contract exactly. Any deviation is a bug.

## Cadence — 7-Day Delivered-Heartbeat

> **AxonFlow emits at most one anonymous heartbeat per environment every 7 days during SDK activity.**

The SDK consults the gate at every public HTTP request site (and at client construction). Each gate run:

1. Re-evaluates `AXONFLOW_TELEMETRY=off` cheaply (lock-free) so a mid-process opt-out toggle takes effect immediately.
2. Checks an in-memory 1-hour cache to bound stat() syscall frequency on hot paths.
3. Reads the stamp file mtime as the source of truth for last successful delivery across process restarts.
4. Sends the ping and writes the stamp **only on successful delivery** (HTTP 2xx). Failed POSTs leave the stamp unchanged so the next call after the 1-hour cache expires retries — a transient network failure does not silence telemetry for 7 days.
5. Coalesces concurrent callers via an in-flight flag so a stampede across the boundary fires exactly one POST.

### Stamp file

| Platform | Path |
|---|---|
| macOS | `~/Library/Caches/axonflow/{sdk}-telemetry-last-sent` |
| Linux | `$XDG_CACHE_HOME/axonflow/...` or `~/.cache/axonflow/...` |
| Windows | `%LOCALAPPDATA%/axonflow/...` |

`{sdk}` is one of `go`, `python`, `typescript`, `java`. Resolved via OS-native conventions (`os.UserCacheDir()` in Go, hand-rolled in Python/TS/Java to keep the SDK dependency-free). When no cache directory is available (e.g. AWS Lambda where `HOME`/`LOCALAPPDATA` is unset), the SDK falls back to "one ping per process" — same as the pre-heartbeat behavior. No regression for that runtime.

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

`AXONFLOW_TELEMETRY=off` always wins. Config flag overrides mode-based defaults but cannot override the env var. No credential-based logic — credentials do not affect telemetry defaults. Endpoint host does not affect defaults either: localhost, private-network, and self-hosted evaluation endpoints are still ON unless sandbox mode or an opt-out disables telemetry.

> **Note on `DO_NOT_TRACK`:** It is **not** honored as an opt-out for AxonFlow telemetry. It is commonly inherited from host tools and developer environments (CLIs like Codex and Claude Code inject it unconditionally), which makes it an unreliable expression of user intent. SDKs do not read this variable at all.

## Runtime Behavior

| Requirement | Value |
|---|---|
| Execution model | Synchronous-bounded at construction (so short-lived processes deliver); asynchronous from request-path hooks (so user API calls are never delayed) |
| Per-call HTTP timeout | 3 seconds |
| Failure handling | Silent — no errors surfaced to user code |
| Frequency | At most one ping per machine per `HEARTBEAT_INTERVAL` (7 days) |
| Endpoint override | `AXONFLOW_CHECKPOINT_URL` env var replaces default endpoint |
| Default endpoint | `https://checkpoint.getaxonflow.com/v1/ping` |

## Payload Contract

### Required fields

| Field | Type | Example |
|---|---|---|
| `sdk` | string | `"go"`, `"python"`, `"typescript"`, `"java"` |
| `sdk_version` | string | `"7.0.0"` |
| `os` | string | `"linux"`, `"Darwin"`, `"Windows"` |
| `arch` | string | `"amd64"`, `"arm64"` |
| `runtime_version` | string | `"1.22.0"`, `"3.12.0"`, `"20.11.0"`, `"21.0.1"` |
| `deployment_mode` | string | `"production"`, `"sandbox"`, `"enterprise"` |
| `instance_id` | string | Random UUID v4, unique per client start |

### Optional fields

| Field | Type | Default |
|---|---|---|
| `platform_version` | string or null | `null` |
| `features` | string[] | `[]` |

### Constraints

- `instance_id` must be a random UUID generated fresh per client initialization. It must not be persisted, reused, or tied to any identity.
- `sdk` must be one of: `go`, `python`, `typescript`, `java`.
- `features` is reserved for future use (currently always `[]`).

## Conformance Test Matrix

Every SDK must have tests covering all of the following scenarios. The 9-case heartbeat matrix is the new addition for the delivered-heartbeat contract.

### Heartbeat gate (9 cases — pin the new contract)

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

### Decision logic (legacy gate — keep these passing)

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
