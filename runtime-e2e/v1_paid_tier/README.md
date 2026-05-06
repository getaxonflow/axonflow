# V1 paid Pro tier — runtime E2E

Asserts the full Stripe-checkout → token-issued → email-delivered →
plugin-uses-token path against a live community-saas Docker stack.

This is the runtime-path test the V1 paid-tier wire-up PR ships with. Per
`axonflow-internal-docs/engineering/FEATURE_RUNTIME_COVERAGE.md`, every
user-facing feature gets a test that exercises the real HTTP flow against a
live agent + DB. Mock unit tests do not qualify.

## What's covered

| Step | What | Why |
|---|---|---|
| 1 | Register a community-saas tenant with email | Establishes the `tenant_id` the paid license binds to + the email the recovery flow can recover |
| 2 | Stripe-sign a `checkout.session.completed` body via `openssl dgst -sha256 -hmac` | Mirrors what real Stripe sends — same HMAC-SHA256 scheme |
| 3 | POST to `/api/v1/billing/stripe-webhook` | Exercises the route the run.go wire-up mounted |
| 4 | Assert email sender captured the same token | Without this, V1 ships skeleton-only — buyer never gets the token |
| 5 | Replay same body | Documents that V1 does NOT dedupe; idempotency is a documented follow-up |
| 6 | Bad signature → 401 | HMAC defense-in-depth confirmed live, not just unit-tested |
| 7 | Missing `Stripe-Signature` → 401 | Required-header check confirmed live |
| 8 | `GET` on the webhook path → 405 | Misconfigured Stripe Dashboard URLs surface as 405, not 404 |
| 9 | Use the AXON token as `X-License-Token` on `/api/request` | Issuer + middleware contract verified end-to-end |

## How to run

The agent container needs five env vars set so the test can drive the flow
deterministically. The easiest setup is a docker-compose override file
appended to the standard E2E setup:

```yaml
# docker-compose.v1-paid-tier.yml — overlay for runtime-e2e/v1_paid_tier/
services:
  axonflow-agent:
    environment:
      COMMUNITY_SAAS_MODE: "true"
      STRIPE_WEBHOOK_SIGNING_SECRET: whsec_test_runtime_v1_paid_tier_2026
      AXONFLOW_BILLING_TEST_CAPTURE_FILE: /tmp/axonflow-billing-captures.txt
      AXONFLOW_PLUGIN_CLAIMED_SIGNING_KEY: ${AXONFLOW_PLUGIN_CLAIMED_SIGNING_KEY}
      AXONFLOW_RECOVERY_TEST_CAPTURE_FILE: /tmp/axonflow-recovery-captures.txt
      AXONFLOW_STRIPE_WEBHOOK_IP_ALLOWLIST: "*"
      AXONFLOW_STRIPE_WEBHOOK_RATE_PER_MIN: "0"
    volumes:
      - /tmp:/tmp
```

Generate the plugin-claimed signing key once (Ed25519) — same scheme as the
agent license signing key. Anything that the `license` package's
`getPluginClaimPublicKey` accepts will work for the test (the issuer +
middleware both read from the same env var in V1).

```bash
# Start the stack with the overlay
docker compose -f docker-compose.yml \
               -f docker-compose.community-saas.yml \
               -f docker-compose.v1-paid-tier.yml up -d

# Run the test
./runtime-e2e/v1_paid_tier/test.sh
```

## Override knobs

| Env var | Default | What |
|---|---|---|
| `AGENT_URL` | `http://localhost:8080` | Where the agent listens |
| `STRIPE_WEBHOOK_SIGNING_SECRET` | `whsec_test_runtime_v1_paid_tier_2026` | Must match the value the agent has |
| `AXONFLOW_BILLING_TEST_CAPTURE_FILE` | `/tmp/axonflow-billing-captures.txt` | Where the noop email sender appends `to=<email> token=<token>` lines |
| `TEST_EMAIL` | auto-generated | Lets you re-run against a specific email |
| `JQ` | `jq` | jq binary path |

## Why no Resend in this test

The runtime-e2e is for the dev/Docker stack — `RESEND_API_KEY` is
deliberately not set, so `NewLicenseEmailSenderFromEnv()` returns the noop
sender. The noop sender writes to the capture file, which the test reads.
This proves the integration WITHOUT requiring a real Resend account or
sending real email. Production stacks set `RESEND_API_KEY` and skip the
capture file; that path is unit-tested separately in `email_test.go` against
a `httptest.NewServer` mock of Resend. <!-- allow-mocks-here: this README references the unit-test pattern by name; no actual stub is used inside runtime-e2e/. -->
