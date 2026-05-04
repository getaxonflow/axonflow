# Runtime E2E — Recovery flow

Tests the full free-tier email-recovery flow through the live `community-saas` docker stack.

## What this test asserts

A user who has set `userEmail` on their plugin config and lost their local registration cache can:

1. POST `/api/v1/recover` with their email → receive 202 with generic message
2. The Noop email sender (active in test mode) captures the magic link
3. GET `/api/v1/recover/verify?token=...` → receive 200 with new tenant credentials bound to the same email
4. Use the new credentials to make an authenticated `audit/tool-call` write through the runtime
5. Assert the new tenant's audit history is empty (it's a fresh tenant; previous-tenant history stays under the old tenant_id, which is the documented v1 free-tier behavior)

This test exercises the **agent runtime** end-to-end (HTTP API as the user-runtime path; the plugin's `--recover` CLI command will exercise the same path from the IDE-runtime side).

## Prereqs

- `docker compose` available
- `community-saas` overlay started: `docker compose -f docker-compose.yml -f docker-compose.community-saas.yml up -d`
- `RESEND_API_KEY` is intentionally NOT set so the noop sender activates and writes captured links to the agent's stdout log

## Run

```bash
bash runtime-e2e/recovery/test.sh
```

Expected exit code: 0 on pass, non-zero on any assertion failure.

## What's NOT in this test (deferred)

- Plugin-side `--recover` CLI command flow (W3 plugin work, separate PR)
- Real Resend API send (would require a live API key + verified sender domain)
- Per-email rate limiting at scale (covered by unit tests)
