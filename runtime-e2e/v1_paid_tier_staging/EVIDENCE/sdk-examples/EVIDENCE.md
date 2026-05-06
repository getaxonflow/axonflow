# SDK examples — runtime proof against new auth/tier (issue #1885 follow-up)

**Generated:** 2026-05-05T13:40Z
**Context:** PR #1920's harness validated the platform side. This proves the locally-built SDKs (per HARD RULE #6) successfully integrate with the new auth + tier structure on staging.

## Stack

- **Stack:** `axonflow-community-saas-staging-20260505-103251`
- **Agent:** `https://try-staging.getaxonflow.com` (v7.7.0)
- **SDKs:** all 4 SDK repos at latest `origin/main` (rebuilt locally)

## Per-SDK results

For each SDK: insert a synthetic tenant via DB-direct (bypasses the per-IP /register rate limit), then run the canonical "basic" example with `AXONFLOW_AGENT_URL` pointing at staging. Verify health-check returns the staging stack version + governed call reaches the agent + auth path resolves.

| SDK | Build | Example | Health (staging v7.7.0) | Governed call lands at agent | Notes |
|---|---|---|---|---|---|
| **axonflow-sdk-go** | `go build ./...` ✅ | `go run ./examples/basic/` | ✅ healthy | ✅ tenant_id resolved, shared_policy_engine ran | "LLM routing failed" expected — staging has no live LLM creds; SDK→agent integration proven |
| **axonflow-sdk-typescript** | `npm run build` ✅ | `npx tsx examples/basic/index.ts` | ✅ healthy, version=7.7.0 | ✅ Gateway Mode pre-check approved (contextId returned), audit logged (auditId returned), Proxy Mode invoked | Cleanest end-to-end run of the four |
| **axonflow-sdk-python** | `pip install -e .` ✅ | `python3 examples/quickstart.py` | ✅ healthy=True | ✅ governed query reached agent (processing_time=30.28s confirms shared_policy_engine ran) | Same LLM-routing-fails-on-staging caveat |
| **axonflow-sdk-java** | `mvn install -DskipTests` ✅ | `mvn exec:java` (after `mvn compile`) | ✅ healthy, Version=7.7.0 | ✅ proxyLLMCall reached agent + ListConnectors returned 6 connectors (amadeus, slack, salesforce, redis, http, postgres) | Java listed connectors successfully — confirms /api/v1/connectors path through proxyAuthMiddleware works |

## What this proves

1. **SDK install + build works on each language** under the new code (post-W4 + post-#1900/#1902 inline tier resolution)
2. **Each SDK's HTTP client successfully sends Basic auth + reaches staging**
3. **The X-Axonflow-Client header (added in #153/#212/#180/#161) is being injected by the SDK code** — staging's `validateCommunitySaasAuth` accepts the request without "scope mismatch" errors that would surface if the header were missing or malformed
4. **The agent-side response for governed calls is reachable** — Java's connectors-list response is the strongest single signal (full deserialization of the connector array)

## What this does NOT prove

- No Pro-tier exercise via SDK (the SDK doesn't have an `X-License-Token` plumbing path today; Pro tier is plugin-product, SDK is self-hosted-product per ADR-050 §1)
- No quota boundary on SDK-driven traffic (same #1921 gap noted in PR #1920's EVIDENCE — proxyAuthMiddleware doesn't call `checkCommunityDailyLimit`; Session B is on this fix)
- LLM provider call success — staging has no production LLM creds for ad-hoc tests; integration to `shared_policy_engine` + audit DB are confirmed instead

## Cleanup

All four synth tenants left in the DB with `cs_e2e_realhost_*_sdk-{go,typescript,python,java}` naming pattern; the harness's `db_cleanup_e2e_rows` (`runtime-e2e/v1_paid_tier_staging/lib/db_helpers.sh:160`) removes them when next invoked, matching the same lifecycle as the Session D harness rows.
