# Plugin Batch 1 E2E Scenarios

End-to-end tests for ADR-044 (session overrides) + ADR-043 (explainability) across the 4 plugins. See [docs/test-visibility-policy.md](../../../docs/test-visibility-policy.md) for the hybrid split between this directory and the plugin-repo smoke scenarios.

## Preconditions

1. **Stack running** via `./scripts/setup-e2e-testing.sh` — orchestrator + agent + Postgres.
2. **Migration 070 applied** — `070_policy_batch1_risk_and_override_extensions.sql` from platform v7.1.0.
3. **Evaluation-tier license** active so override creation is unlocked.
4. **Seed policies:**
   - One critical-risk policy (`risk_level=critical`, `allow_override=false`) that denies a known input pattern.
   - One medium-risk overridable policy (`risk_level=medium`, `allow_override=true`) that denies a different pattern.

## Running

```bash
# All plugins (default)
bash tests/e2e/plugin-batch-1/run-scenarios.sh

# One plugin
bash tests/e2e/plugin-batch-1/run-scenarios.sh openclaw
bash tests/e2e/plugin-batch-1/run-scenarios.sh claude
bash tests/e2e/plugin-batch-1/run-scenarios.sh cursor
bash tests/e2e/plugin-batch-1/run-scenarios.sh codex
```

Exit 0 on success, nonzero on failure.

## Scenarios covered

Each plugin exercises these four scenarios:

1. **Block + context enrichment** — block response carries `decision_id`, `risk_level`, `override_available`.
2. **Override lifecycle** — create override, assert `override_created` audit event, revoke, assert `override_revoked`.
3. **Explain returns full context** — call `GET /api/v1/decisions/:id/explain`, verify required fields per ADR-043.
4. **Audit search filter parity** — `POST /api/v1/audit/search` with `decision_id`/`policy_name`/`override_id` filters returns consistent shape.

## Logging

Record each run with:

- Date / SHA tested
- Command run
- Pass/fail counts
- Any bugs found and fixed

Never run silently. Internal teams additionally mirror the run-log into the private engineering log; external contributors should attach the output to the PR description.

## Placeholder endpoints

The script's `fire_step_gate` uses `/api/v1/wcp/step-gate` as the invocation path. If your setup script boots a different surface (e.g. exercise via the orchestrator's internal step gate directly, or simulate plugin hooks locally), swap the endpoint — the rest of the assertions are endpoint-agnostic.

## Next steps

Current scope exercises the HTTP-surface. To exercise the plugin hooks end-to-end (exit codes, stderr format, redaction, richer block context strings) you'd:

1. Drive the plugin's `pre-tool-check.sh` / OpenClaw `governance.ts` with realistic stdin.
2. Assert exit code + stdout/stderr format.

These hook-level tests already live in each plugin repo under `tests/test-hooks.sh` (bash plugins) and `tests/*.test.ts` (OpenClaw). This directory is for full-stack integration.
