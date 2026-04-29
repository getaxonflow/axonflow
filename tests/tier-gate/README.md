# Tier-Gate Contract

A PR-blocking CI gate that asserts the **published tier behavior** of the
agent + orchestrator HTTP API matches what the handler code actually
enforces, across all three deployment modes (`community`, `evaluation`,
`enterprise`).

## Layout

| File | Purpose |
| --- | --- |
| `expected.yaml` | Machine-readable manifest: every gated endpoint × tier × expected status. |
| `run.py` | Hits each endpoint against a running stack and asserts status matches manifest. |
| `synthetic_failure_test.sh` | Mutates one entry to a known-wrong code, runs the runner, asserts it exits non-zero. |
| `wait_for_stack.sh` | Polls `/health` on agent (8080) + orchestrator (8081) until ready. |
| `setup_license.sh` | Builds the keygen utility, fetches Ed25519 signing keys from AWS Secrets Manager, generates a tier-appropriate license + JWT. |

## Running locally

```bash
# Community mode (no license, fastest)
DEPLOYMENT_MODE=community docker compose up -d
AXONFLOW_TIER=community ./tests/tier-gate/run.py

# Evaluation mode (Ed25519-signed evaluation license)
./tests/tier-gate/setup_license.sh evaluation > /tmp/eval-license.env
# (then export the values it emitted)
DEPLOYMENT_MODE=evaluation AXONFLOW_LICENSE_KEY=<from-output> docker compose up -d
AXONFLOW_TIER=evaluation AXONFLOW_USER_TOKEN=<from-output> ./tests/tier-gate/run.py

# Enterprise mode
DEPLOYMENT_MODE=enterprise docker compose -f docker-compose.yml -f docker-compose.enterprise.yml up -d
AXONFLOW_TIER=enterprise ./tests/tier-gate/run.py
```

## Manifest schema

Each row in `expected.yaml` describes one (method, path, port) tuple:

```yaml
- id: orchestrator-policies-simulate
  method: POST
  port: 8081
  path: /api/v1/policies/simulate
  body: '{"query":"hello","inputs":[{}]}'   # optional; defaults to {}
  expected:
    community:  {status: 403, reason: "...handler citation..."}
    evaluation: {status: 200, reason: "..."}
    enterprise: {status: 200, reason: "..."}
```

`reason` is informational — it cites the handler/registration site that
establishes why this status is expected. When code drifts away from the
manifest, fix one of the two: either the handler (when the manifest is the
intended contract) or the manifest (when handler behavior changed
deliberately, in which case the row's reason needs updating to reflect the
new citation).

## Adding a new endpoint

1. Read the handler — does it block on a tier check (`tierChecker.IsXEnabled()`,
   `isCommunityMode()`, `IsEvaluationOrHigher`)?
2. Add a row to `expected.yaml` with `expected.<tier>.status` for each tier.
3. Cite the source line in `reason`.
4. Run the runner locally in at least one mode to verify.
5. Open the PR — the gate will fail if the manifest disagrees with reality
   in any of the three modes.

## Status code conventions

| Code | Meaning in manifest |
| --- | --- |
| 200 | Handler reached, no tier block |
| 201 | Created |
| 400 | Validation rejection (tier-allowed) |
| 401 | Auth-required, no JWT in this tier (e.g. community has no token) |
| 403 | **Tier block fired** — the gate is the signal |
| 404 | Route not registered for this build/mode (also a tier-block via absence) |
| 422 | Body-shape validation failure (tier-allowed) |
| 503 | Service not yet bootstrapped (tier-allowed) |

## Synthetic-failure probe

`synthetic_failure_test.sh` is the meta-test: it takes the manifest, flips
the `community.status` for `/health` to `599`, runs the runner, and asserts
the runner exits **non-zero**. This guarantees the gate is not a no-op — if
a future change accidentally turned all assertions into log-only warnings,
this probe would catch it.
