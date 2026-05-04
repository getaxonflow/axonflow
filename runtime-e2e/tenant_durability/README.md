# Runtime E2E — Tenant durability across agent restart (W1)

Tests that a community-saas tenant registered before an agent-container restart continues to authenticate successfully after the restart, because the tenant row lives in Postgres (which persists across agent-container restarts in the standard docker-compose deployment).

## What this test asserts

1. POST `/api/v1/register` → fresh tenant + secret
2. Authenticated request → reaches past auth (any non-401 status)
3. `docker restart axonflow-agent` (DB volume untouched)
4. Wait for `/health` to become reachable (max 30s)
5. Same credentials → still reach past auth
6. A second authenticated request → still reach past auth

## Why this is a runtime test, not a unit test

The Phase-0 investigation of the 2026-04-29 auth-failure cluster identified the failure mode as cross-stack continuity (tenant rows don't migrate when CFN stacks rotate). The W3 email-recovery PR addressed the user-facing recovery path. W1 is the standing smoke test that the BASE case — single stack, agent restart, same DB — works.

A unit test would verify that the SQL-side credential lookup returns the expected row; this runtime test verifies the FULL stack — registration HTTP API → DB write → agent restart → DB read → auth pass.

## Out of scope (deferred)

- Cross-stack tenant migration (different concern; future work)
- Postgres failover (DB-tier resilience; not a tenant concern)
- Plugin-side credential persistence across machine reboots

## Prereqs

- `docker compose` available
- A running community-saas docker stack with a persistent postgres volume:

```bash
docker compose -f docker-compose.yml -f docker-compose.community-saas.yml up -d
```

- The agent container is named `axonflow-agent` (override with `AGENT_CONTAINER=name` if different)
- `AGENT_URL` defaults to `http://localhost:8080`

## Run

```bash
bash runtime-e2e/tenant_durability/test.sh
```

Expected exit code: 0 on pass, non-zero on any assertion failure.

## What "reached past auth" means

The test treats any HTTP status that is NOT 401 as "auth succeeded". Specifically: 2xx, 4xx-not-401 (validation errors etc.), and 5xx are all acceptable. The test is checking auth durability, not request correctness — a 400 from a missing field is fine because it means the request reached the handler past the auth middleware.

A 401 specifically indicates the tenant credentials were not recognized — exactly the failure mode this test guards against.
