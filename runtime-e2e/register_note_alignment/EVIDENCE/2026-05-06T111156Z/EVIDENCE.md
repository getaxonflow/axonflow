# Runtime E2E evidence — register-note alignment with pricing-page promises

**Date (UTC):** 2026-05-06 11:11:56
**Stack:** local docker compose (community-saas mode), agent at `http://localhost:8080`
**Branch:** `chore/community-saas-disclaimer-align-with-pricing-promises`
**Commit:** ad8664c (parent) + this branch's edits

## What was tested

Per HARD RULE #0 (runtime proof is definition of done), this PR rewrites the
customer-facing `note` field returned by `POST /api/v1/register`. The unit-test
coverage in `community_saas_lifecycle_test.go` is necessary but not sufficient —
the rule requires the change be exercised against the actual API surface.

`test.sh` POSTs against the live agent and asserts:

1. The endpoint returns 201 Created with a parseable JSON body
2. `response.note` contains the new operational facts:
   - `3-day audit retention`
   - `200 events/day`
   - `3 months of inactivity`
   - `1 year from creation`
   - `Plugin Pro`
   - `30-day retention`
   - `1,000 events/day`
   - `$9.99`
   - `https://docs.getaxonflow.com/deployment/community-saas-pro/`
3. `response.note` does NOT contain the old "low-quality testing instance" framing:
   - `intended for basic testing and evaluation`
   - `we recommend self-hosting AxonFlow from day one`
   - `we cannot offer reliability or security guarantees`
   - `by using it you accept these constraints`

## Result

**PASS** — all 9 must-contain checks + all 4 must-not-contain checks satisfied.

See `register_response.json` for the actual bytes.

## Reproducing

From an axonflow-enterprise checkout on this branch:

```bash
docker compose -f docker-compose.yml -f docker-compose.community-saas.yml up -d --build
sleep 8  # wait for agent /health to flip to 200
bash runtime-e2e/register_note_alignment/test.sh
```

The script writes a fresh evidence dir under `runtime-e2e/register_note_alignment/EVIDENCE/<UTC-timestamp>/`.
