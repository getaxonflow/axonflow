# #1895 charge.refunded auto-revoke runtime test

Runtime proof for the `charge.refunded` Stripe webhook handler that auto-revokes
the issued plugin license on a full refund (and explicitly no-ops on partial
refunds).

## What this exercises

The `synthetic_stripe_webhook.py` tool signs synthetic event payloads with the
staging webhook signing secret and POSTs them directly to the agent's webhook
endpoint — bypassing Stripe Dashboard / Live charges entirely. From the agent's
perspective these are indistinguishable from real Stripe deliveries.

Sequence:

1. Issue a Pro license via `--event=checkout.session.completed`.
2. Fire `--event=charge.refunded --refund-amount=999` (full refund) — assert
   row `revoked_at IS NOT NULL`, `revocation_reason='full_refund'`, log line
   `event=license_revoked_on_refund` fires.
3. Replay the SAME `charge.refunded` event — assert idempotent (no double-
   revoke), log line `event=refund_already_revoked` fires.
4. On a fresh license: fire `--refund-amount=500` (partial refund of the
   same `--charge-amount=999`) — assert row `revoked_at IS NULL` is unchanged,
   log line `event=partial_refund_no_op` fires.

## Stack assumptions

- `axonflow-community-saas-staging-<TIMESTAMP>` exists, post-#1895 image deployed
- Stripe webhook signing secret in `axonflow/community-saas-staging/stripe-webhook-signing-secret`
- DB password in `axonflow/community-saas-staging/database-password`
- ECS exec is enabled on the orchestrator service

## Usage

```bash
AGENT_URL=https://try-staging.getaxonflow.com bash test.sh

# Or pin the stack name explicitly:
STACK=axonflow-community-saas-staging-20260505-104000 bash test.sh
```

Evidence (request/response bodies, DB query output, CloudWatch Logs Insights
results) lands under `EVIDENCE/<utc-ts>/`.
