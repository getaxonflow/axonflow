# SDK Telemetry Contract

Canonical specification for SDK telemetry behavior. All 4 SDKs (Go, Python, TypeScript, Java) must conform to this contract exactly. Any deviation is a bug.

## Decision Logic

```
Inputs:
  mode:                   string ("sandbox" | anything else)
  config.telemetry:       true | false | undefined/null
  env.DO_NOT_TRACK:       string
  env.AXONFLOW_TELEMETRY: string

Rule order (highest priority first):
  1) if trim(DO_NOT_TRACK) == "1"              => OFF
  2) if lower(trim(AXONFLOW_TELEMETRY)) == "off" => OFF
  3) if config.telemetry == false              => OFF
  4) if config.telemetry == true               => ON
  5) if mode == "sandbox"                      => OFF
  6) otherwise                                 => ON
```

Environment variables always win. Config flag overrides mode-based defaults but cannot override env vars. No credential-based logic — credentials do not affect telemetry defaults.

## Runtime Behavior

| Requirement | Value |
|-------------|-------|
| Execution model | Fire-and-forget; client init never blocks |
| Timeout | 3 seconds |
| Failure handling | Silent — no errors surfaced to user code |
| Frequency | Exactly one ping per client initialization |
| Endpoint override | `AXONFLOW_CHECKPOINT_URL` env var replaces default endpoint |
| Default endpoint | `https://checkpoint.getaxonflow.com/v1/ping` |

## Payload Contract

### Required fields

| Field | Type | Example |
|-------|------|---------|
| `sdk` | string | `"go"`, `"python"`, `"typescript"`, `"java"` |
| `sdk_version` | string | `"3.8.0"` |
| `os` | string | `"linux"`, `"Darwin"`, `"Windows"` |
| `arch` | string | `"amd64"`, `"arm64"` |
| `runtime_version` | string | `"go1.22.0"`, `"3.12.0"`, `"v20.11.0"`, `"21.0.1"` |
| `deployment_mode` | string | `"production"`, `"sandbox"`, `"enterprise"` |
| `instance_id` | string | Random UUID v4, unique per client start |

### Optional fields

| Field | Type | Default |
|-------|------|---------|
| `platform_version` | string or null | `null` |
| `features` | string[] | `[]` |

### Constraints

- `instance_id` must be a random UUID generated fresh per client initialization. It must not be persisted, reused, or tied to any identity.
- `sdk` must be one of: `go`, `python`, `typescript`, `java`.
- `features` is reserved for future use (currently always `[]`).

## Conformance Test Matrix

Every SDK must have tests covering all of the following scenarios:

| # | Scenario | Expected |
|---|----------|----------|
| 1 | `DO_NOT_TRACK=1`, config true | OFF |
| 2 | `AXONFLOW_TELEMETRY=off`, config true | OFF |
| 3 | `AXONFLOW_TELEMETRY=OFF` (uppercase) | OFF |
| 4 | Config false, production mode | OFF |
| 5 | Config true, sandbox mode | ON |
| 6 | No env, no config, sandbox mode | OFF |
| 7 | No env, no config, production mode | ON |
| 8 | No env, no config, no credentials, production mode | ON |
| 9 | Custom `AXONFLOW_CHECKPOINT_URL` is used | Custom URL hit |
| 10 | Network timeout / connection error | No exception thrown |
| 11 | Server returns non-200 | No exception thrown |
| 12 | Payload contains all required fields | Validated |
| 13 | `instance_id` is unique across calls | Validated |

## Implementation Locations

| SDK | File |
|-----|------|
| Go | `telemetry.go` |
| Python | `axonflow/telemetry.py` |
| TypeScript | `src/telemetry.ts` |
| Java | `src/main/java/com/getaxonflow/sdk/telemetry/TelemetryReporter.java` |

## String Handling

All SDKs must:
- **Trim** whitespace from `DO_NOT_TRACK` and `AXONFLOW_TELEMETRY` before comparison
- **Case-insensitive** comparison for `AXONFLOW_TELEMETRY` (`"off"`, `"OFF"`, `"Off"` all match)
- **Exact match** for `DO_NOT_TRACK` (only `"1"` after trim)
