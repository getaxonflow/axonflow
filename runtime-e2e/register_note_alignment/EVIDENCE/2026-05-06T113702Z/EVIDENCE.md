# Runtime E2E evidence — register-note alignment with pricing-page promises (URL-canonicalisation pass)

**Date (UTC):** 2026-05-06 11:37:02
**Stack:** local docker compose (community-saas mode), agent at `http://localhost:8080`, freshly rebuilt from this branch
**Branch:** `chore/community-saas-disclaimer-align-with-pricing-promises`
**Commits:** a570b610c (constant rewrite) + 3eaf86bc8 (initial runtime-e2e) + new commit pending (URL canonicalisation)

## What changed since the prior evidence run

The previous evidence dir (`2026-05-06T111156Z/`) was captured with the URL
`https://docs.getaxonflow.com/deployment/community-saas-pro/` in the disclaimer.
That URL does NOT resolve today (the canonical docs route is
`/docs/deployment/community-saas-pro/` with `/docs/` prefix, AND the page itself
only lands when axonflow-docs#445 ships — which is gated on Stripe Live flip).

This run is against the disclaimer pointing at `https://www.getaxonflow.com/pricing/`,
the actionable upgrade URL (the pricing page that already has the Plugin Pro
buy button).

## Result

**PASS** — all 9 must-contain checks + all 4 must-not-contain checks satisfied.

The new note bytes verbatim:

```
Free tier: 3-day audit retention, 200 events/day. Tenants are deprovisioned after 3 months of inactivity, or 1 year from creation regardless of activity (data disassociated, tenant terminated). Plugin Pro upgrades to 30-day retention and 1,000 events/day for 90 days ($9.99) — see https://www.getaxonflow.com/pricing/.
```

URL verified live (HTTP 200) at the time of capture.

## Reproducing

From an axonflow-enterprise checkout on this branch:

```bash
docker compose -f docker-compose.yml -f docker-compose.community-saas.yml up -d --build
sleep 8
bash runtime-e2e/register_note_alignment/test.sh
```
