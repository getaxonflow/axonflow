# License Rework E2E — cursor (issue #1885)

**Generated:** 2026-05-05T11:49:45Z
**Stack:** `axonflow-community-saas-staging-20260505-103251`
**Agent:** `https://try-staging.getaxonflow.com`
**Client header:** `cursor-plugin/1.1.0`
**Synth token bin:** `/tmp/synth_token`

- ✅ PASS: /health 200, version=7.7.0

## Prelude

- Stack health: `{ status: healthy, version: 7.7.0 }`

## Test surface — apiAuthMiddleware route

All probes hit `/api/policies/test` because that route runs through
`apiAuthMiddleware` (platform/agent/auth.go:503-587), which is the
ONLY middleware that calls `checkCommunityDailyLimit` today. Plugin
and SDK governed traffic in production primarily flows through
`proxyAuthMiddleware` (platform/agent/proxy.go:182-214), which does
not enforce per-tenant daily quota. Filed as a follow-up to #1885 +
#1903; harness will retarget proxy routes once the call is added.

## §1 Free baseline (200/day quota + 3-day retention)

- ✅ PASS: Free §1.0 — pre-populated daily_usage=199 for boundary test
- ✅ PASS: Free §1.1 — 200th request succeeded (HTTP 200; auth path executed at boundary)
- ✅ PASS: Free §1.2 — 201st request rejected with 429 + quota reason

  - 201st response body: `{"error":{"code":429,"message":"Daily request limit reached. Resets at midnight UTC."}}`
- ✅ PASS: Free §1.3 — daily_usage = 201 after boundary hit (increment-then-check semantics confirmed)

## §2 Pro purchase (1000/day quota + 30-day retention)

- ✅ PASS: Pro §2.0 — synthetic webhook minted Pro token (200, token captured)
- ✅ PASS: Pro §2.1 — pre-populated daily_usage=999 for boundary test
- ✅ PASS: Pro §2.2 — 1000th request succeeded with Pro token (HTTP 200; auth path resolved tier=Pro)
- ✅ PASS: Pro §2.3 — 1001st request rejected with 429 (Pro quota=1000)
  - 1001st body: `{"error":{"code":429,"message":"Daily request limit reached. Resets at midnight UTC."}}`

## §3 Cross-quadrant rejection

- ✅ PASS: §3a — self-hosted token rejected with 401 + cross-quadrant reason (is not a SaaS Plugin tier)
  - §3a body: `{"error":{"code":401,"message":"invalid_license_token: SaaS Plugin validation failed: token tier \"Enterprise\" is not a SaaS Plugin tier"}}`
- ✅ PASS: §3b — Pro token + sdk client header rejected with 401 + scope_mismatch reason
  - §3b body: `{"error":{"code":401,"message":"scope_mismatch: token aud \"axonflow.saas.plugin\" does not grant scope \"sdk\" (client \"sdk-typescript/7.7.0\")"}}`
- ⏭️ §3c — self-hosted boot rejection: out of SaaS-runtime scope (covered by unit tests in platform/agent/license/scope_validate_enterprise_test.go)

## §4 Token expiry → drops to Free

- ✅ PASS: §4.0 — minted past-expired token: issued_at=20260401 expires_at=20260402
- ✅ PASS: §4.1 — past-expired token rejected with 401 + 'expired' in reason
  - §4.1 body: `{"error":{"code":401,"message":"invalid_license_token: SaaS Plugin validation failed: token expired"}}`
- ✅ PASS: §4.2 — post-expiry tenant reverts to Free baseline (HTTP 200 without token)

## §5 Token revocation (chargeback simulation)

- ✅ PASS: §5.0 — minted Pro token (jti=c0f61183-a0b1-4ca4-9509-098f78fa2dff) for revocation test
- ✅ PASS: §5.1 — Pro request authenticated pre-revocation (HTTP 200)
- ✅ PASS: §5.2 — DB UPDATE: revoked_at=NOW() applied at 11:50:21Z
- ✅ PASS: §5.3 — revoked token rejected with 401 + license_not_found_or_revoked (latency=3s)
- ✅ PASS: §5.4 — revocation latency 3s ≤ 60s ADR-049 §2 contract

## Retention bucket proofs (Free=3d, Pro=30d)

- ✅ PASS: Retention §1.b — Free tenant retention: 4-day-old row purged (Free=3→2)
- ✅ PASS: Retention §2.b — Pro tenant retention: 35-day-old row purged (Pro=3→2)
- ✅ PASS: Cleanup — synth e2e rows removed from staging DB

## Summary

- **PASS:** 22
- **FAIL:** 0
- **Plugin:** `cursor-plugin/1.1.0`

**Result: ✅ PASS**
