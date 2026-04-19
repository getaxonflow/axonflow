# OpenClaw Plugin Install E2E Scenarios

These scenarios exercise `@axonflow/openclaw` v1.3.0+ (installed from npm,
not a local build) against a live orchestrator + agent stack. They are the
post-release "does it actually work when a real user installs it" harness —
the sibling `run-scenarios.sh` in the parent directory exercises the
plugin surface synthetically; these scripts exercise it as a downstream
consumer would.

The first run of these scripts on 2026-04-18 uncovered **six** latent
bugs that the unit-test + synthetic-run layers had all missed — all
closed by platform v7.1.1 (see that release's CHANGELOG entry for the
bug-by-bug breakdown).

## Preconditions

1. Stack up via `./scripts/setup-e2e-testing.sh evaluation` (Evaluation tier
   unlocks override creation).
2. A fresh install of `@axonflow/openclaw` from npm in `/tmp/openclaw-e2e/`:

   ```bash
   mkdir -p /tmp/openclaw-e2e && cd /tmp/openclaw-e2e
   echo '{"name":"openclaw-e2e","type":"module"}' > package.json
   npm install --no-audit --no-fund @axonflow/openclaw@latest
   ```

3. Default credentials from `.env`: `demo-client:demo-secret`.
4. For scenario 6 only: a pre-seeded dynamic policy named
   `E2E cache test blocker` matching step inputs containing
   `CACHE_TEST`. See the seeding command inline at the top of that script.

## Running

```bash
cd /tmp/openclaw-e2e
node <path-to>/scenario-1-richer-context.mjs
node <path-to>/scenario-2-explain.mjs
node <path-to>/scenario-3-override-lifecycle.mjs         # requires plugin v1.3.1+ (X-User-Email)
node <path-to>/scenario-3-override-lifecycle-curl.mjs    # platform-side via curl (works on v1.3.0)
node <path-to>/scenario-5-audit-filters.mjs
node <path-to>/scenario-6-cache-invalidation.mjs
```

Each script exits 0 on PASS, non-zero on FAIL. Output is human-readable,
suitable for pasting into the testing log.

## Scenarios

| # | Covers | Path |
|---|---|---|
| 1 | `mcp/check-input` response carries `decision_id`, `risk_level`, `policy_matches`, `override_available` | Agent |
| 2 | `client.explainDecision(id)` resolves against `audit_logs.policy_details` | Orchestrator |
| 3 | Full override lifecycle (deny → create → apply → revoke → deny) | Plugin-facing (3a) or platform-side (3b) |
| 4 | Critical-risk policy rejects override create with 403 | Orchestrator |
| 5 | Audit search parity (`decision_id`, `policy_name`, `override_id` filters) | Orchestrator |
| 6 | Cache invalidation on override create wipes stale `workflow_steps` rows; WCP re-eval applies override | WCP + Orchestrator |

## Why two scenario-3 variants

Scenario 3a (`...lifecycle.mjs`) uses the plugin client's
`createOverride` / `revokeOverride` methods. Requires plugin v1.3.1+
where the client forwards `X-User-Email`. Fails on v1.3.0 with 401
because the shipped plugin constructor accepts `userEmail` but never
sends it.

Scenario 3b (`...lifecycle-curl.mjs`) exercises the orchestrator's
override endpoints directly via fetch — proves platform-side works even
when the plugin client is behind. Keep both so regressions are isolated
to the right layer.

## Cleanup between runs

WCP workflows default to Evaluation tier's concurrent-execution limit.
If the scenarios abort before completing workflows, run:

```sql
UPDATE workflows SET status='completed', completed_at=NOW() WHERE status='in_progress';
UPDATE execution_history SET status='completed', completed_at=NOW() WHERE status='pending';
```

against the stack's Postgres container. This is a dev-mode workaround —
production flows complete themselves.
