# Runtime proof — #1894 explicit billing-webhook alarm log tokens

## What this asserts

After deploying a build that contains the #1894 changes, the agent's
billing-webhook handler emits two NEW alarm-stable log tokens:

1. On the success path — `[billing.webhook] event=first_paid_license_issued license=… tenant=… amount_cents=…`
2. On the IssueLicense-failed path — `[billing.webhook] event=paid_but_no_token_issued reason=<canonical> session=… tenant=… err=…`

The CloudWatch metric filters in `infrastructure/cloudformation/community-saas-alarms.yaml`
key off these tokens. This runtime test verifies the contract end-to-end:
the agent actually emits the strings, CloudWatch receives them, and the
metric filters increment the alarm counters.

## Prereqs

- A `community-saas-staging-*` stack on the post-#1894 image (pass `STACK=…` to override the auto-discovered one)
- AWS creds with: read access to the stack's agent log group + the alarms-stack metric namespace, read access to the staging Stripe-webhook signing secret (Secrets Manager)
- Vanity domain reachable at `https://try-staging.getaxonflow.com` (or pass `AGENT_URL=`)
- `aws` CLI on PATH; `python3` (stdlib only — no extra deps)

## Run

```bash
AGENT_URL=https://try-staging.getaxonflow.com \
  bash runtime-e2e/billing_alarm_log_tokens/test.sh
```

## What it does

1. Issues a synthetic checkout.session.completed via `runtime-e2e/v1_paid_tier_staging/lib/synthetic_stripe_webhook.py`.
2. Polls the agent CloudWatch log group for the success token (`event=first_paid_license_issued`) — must appear within 60 s.
3. Polls the alarm metric namespace for `LicensesIssued` — increment must equal 1.
4. (Negative test) Posts a malformed-but-signed event whose checkout session is missing tenant_id — agent rejects with 400 BEFORE the IssueLicense path. Asserts NO `paid_but_no_token_issued` token appears (this path is "stripe paid us but we couldn't issue", not "request was malformed").
5. Captures evidence under `runtime-e2e/billing_alarm_log_tokens/EVIDENCE/<utc-ts>/`.

## Why this is a runtime test, not a unit test

The unit tests in `platform/agent/billing/webhook_test.go` lock the
EXACT log line shape using a `bytes.Buffer` redirect. They cannot prove
that:

- The agent process actually exports the lines via stdout to CloudWatch
- The CloudWatch metric filter actually matches the new pattern
- The metric increment actually fires for the new token

Per CLAUDE.md HARD RULE #0, alarm contracts are user-facing (a missed
metric on a real paying-customer issuance failure means we wouldn't know
money was taken without service delivered). Mocked tests are necessary,
not sufficient.
