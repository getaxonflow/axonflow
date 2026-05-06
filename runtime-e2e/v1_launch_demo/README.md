# V1 launch demo — end-to-end orchestrator

Drives the full V1 paid-tier story end-to-end against a live community-saas
stack. This is the script to run against `try.getaxonflow.com` after the
platform rolls forward and the 4 plugins are tagged.

## What it asserts

| Phase | What |
|---|---|
| 1 | Register a community-saas tenant → Stripe-sign a `checkout.session.completed` body → POST to `/api/v1/billing/stripe-webhook` → assert 200 + AXON token + email captured for the buyer |
| 2 | Each of the 4 plugins (OpenClaw / Cursor / Codex / Claude Code) sends a governed agent request with `X-License-Token` set to the just-issued token. `axonflow_agent_plugin_claim_validations_total{result="valid"}` Prometheus counter must increment ≥ 1 per plugin (proves `PluginClaimMiddleware` is mounted AND validates each request) |
| 3 | Replay the same Stripe webhook → expect IDENTICAL token + jti (regression guard for GAP-2 idempotency fix) |
| 4 | W3 free-tier credential recovery: register fresh tenant → "lose" credentials → `POST /api/v1/recover` → read magic-link token from capture file → `POST /api/v1/recover/verify` → assert new credentials returned + replay rejected |
| 5 | Webhook defense-in-depth: bad-sig → 401, missing-sig → 401, `GET` → 405 |

Exit 0 = V1 paid tier ships. Anything else = blocker.

## How to run (local Docker stack)

The agent container needs these env vars set in your docker-compose
override file:

```yaml
# docker-compose.v1-launch-demo.yml
services:
  axonflow-agent:
    environment:
      COMMUNITY_SAAS_MODE: "true"
      STRIPE_WEBHOOK_SIGNING_SECRET: whsec_test_runtime_v1_paid_tier_2026
      AXONFLOW_BILLING_TEST_CAPTURE_FILE: /tmp/axonflow-billing-captures.txt
      AXONFLOW_RECOVERY_TEST_CAPTURE_FILE: /tmp/axonflow-recovery-captures.txt
      AXONFLOW_PLUGIN_CLAIMED_SIGNING_KEY: ${AXONFLOW_PLUGIN_CLAIMED_SIGNING_KEY}
      AXONFLOW_STRIPE_WEBHOOK_IP_ALLOWLIST: "*"
      AXONFLOW_STRIPE_WEBHOOK_RATE_PER_MIN: "0"
    volumes:
      - /tmp:/tmp
```

Then:

```bash
docker compose -f docker-compose.yml \
               -f docker-compose.community-saas.yml \
               -f docker-compose.v1-launch-demo.yml up -d

./runtime-e2e/v1_launch_demo/test.sh
```

## How to run (live SaaS)

Same script, just override `AGENT_URL` and use the same shared signing
secret as production:

```bash
AGENT_URL=https://try.getaxonflow.com \
STRIPE_WEBHOOK_SIGNING_SECRET=$(aws secretsmanager get-secret-value \
  --secret-id axonflow/billing-stripe-webhook-secret --query SecretString --output text) \
./runtime-e2e/v1_launch_demo/test.sh
```

The capture files don't apply against live (Resend is real); for live runs
the test substitutes "fetch from Resend test inbox" — see the SaaS
deploy runbook for the inbox-poll variant of phases 1 + 4.

## Override knobs

| Env var | Default | What |
|---|---|---|
| `AGENT_URL` | `http://localhost:8080` | Where the agent listens |
| `STRIPE_WEBHOOK_SIGNING_SECRET` | `whsec_test_runtime_v1_paid_tier_2026` | Must match what the agent has |
| `AXONFLOW_BILLING_TEST_CAPTURE_FILE` | `/tmp/axonflow-billing-captures.txt` | Noop billing-email capture file |
| `AXONFLOW_RECOVERY_TEST_CAPTURE_FILE` | `/tmp/axonflow-recovery-captures.txt` | Noop recovery-email capture file |
| `OPENCLAW_PLUGIN_DIR` | `../axonflow-openclaw-plugin` | Sibling checkout |
| `CURSOR_PLUGIN_DIR` | `../axonflow-cursor-plugin` | Sibling checkout |
| `CODEX_PLUGIN_DIR` | `../axonflow-codex-plugin` | Sibling checkout |
| `CLAUDE_PLUGIN_DIR` | `../axonflow-claude-plugin` | Sibling checkout |
| `SKIP_PLUGINS` | _(empty)_ | Comma-separated subset to skip, e.g. `cursor,codex` |
| `TEST_EMAIL` | auto-generated | Lets you re-run against a specific email |
| `JQ` | `jq` | jq binary path |

## Why phase 2 doesn't shell out to each plugin's pre-tool-check.sh

For V1 the orchestrator drives the agent directly with the same headers
the plugins would send (`X-License-Token` + tenant Basic auth). This keeps
the script self-contained — the per-plugin runtime tests in each plugin
repo (`runtime-e2e/v1_paid_tier/test.sh` for OpenClaw, the equivalents in
Cursor/Codex/Claude Code) already prove each plugin sends the header
correctly. Combining "plugin sends header" with "agent middleware accepts
header" is the V1 contract, and that's what each phase-2 step asserts.

If you want to drive the actual plugin shell scripts end-to-end, those
live in their respective repos; this orchestrator stays in axonflow-enterprise
and is the single hard pass/fail gate for the V1 launch.
