# The twelve-plane decision-shadow canary

The synthetic traffic that makes the ADR-065 per-plane observation window measurable.

- **Template:** `infrastructure/cloudformation/synthetic-monitoring-decision-shadow.yaml`
- **Deploy:** `.github/workflows/deploy-synthetic-monitoring.yml`, `decision_shadow_probe` input
- **Stack:** `<base stack name>-decision-shadow`
- **Tracking:** #3602. The `synthetic` label it depends on is #3817.

This page carries the design argument. It is here rather than in the template's header because that template sits close to the 51,200-byte `--template-body` cap the deploy commands use (#3694), and a design argument that has to be shortened to fit a deploy limit belongs somewhere it can be read.

---

## What it is for

ADR-065 acceptance gate 18 - *"shadow migration has no unexplained fail-open difference for the agreed window"* - is stated **per plane**, and a per-plane statement needs a per-plane denominator. Measured on the house stacks over 17 hours (2026-09-06T20:26Z .. 2026-09-07T13:29Z, both on 10.4.0, both in shadow on all twelve planes):

| stack | planes with comparisons |
|---|---|
| community-SaaS | 5 of 12 |
| production-US | **0 of 12** |

Seven planes have never been observed in production on either stack. The gate cannot be read for a plane whose denominator is zero, and a zero denominator is indistinguishable from a clean window - which is the failure v10.3.0 exists because of, one axis over.

## What it is *not* for

**It cannot substitute for organic volume.** The gate has two halves and they are read differently:

| half | counts canary traffic? |
|---|---|
| **coverage** - "has this plane been exercised at all" | **yes.** A path only the canary exercises is still an exercised path, and reaching the seven never-observed planes is exactly what this is for. |
| **volume** - "this plane has seen N comparisons" | **no.** Read `axonflow:decision_shadow_organic_comparisons:increase1h`, which filters `synthetic="false"`. |

Both readings exist at once, which is why `synthetic` is a **label** and never a filter on the counter.

---

## Design decisions, and what each one refuses

### 1. A third template

`aws cloudformation create-change-set --template-body` caps a body at 51,200 bytes, and the deploy workflow uses exactly that flag with no S3 staging step. As of this change:

```
synthetic-monitoring.yaml                  28,946 bytes   (56% of the cap)
synthetic-monitoring-identity-compat.yaml  50,630 bytes   (98.8% - 570 of headroom)
synthetic-monitoring-decision-shadow.yaml  49,926 bytes   (97.5% - 1,274 of headroom)
```

The identity-compat template has 570 bytes of headroom. It cannot absorb a twelve-plane probe, which is why there is a third template rather than a bigger second one.

**These figures go stale on every edit and are not the instrument.** An earlier revision of this page gave two of them as "measured on main" and the change that added the third template made both wrong the moment it merged. `tests/regression-test-required/synthetic_monitoring_two_stacks_test.sh` prints the current sizes and fails on the cap, and `scripts/deploy/cfn-change-set.sh` checks it again before the API sees the body and warns above 90%; read those rather than this block. The decision-shadow template is above that warning threshold today, so the warning fires on every deploy of it - correctly: it is nearly full, and one more plane or parameter breaks the deploy outright.

## The openai_compatible plane and its non-functional provider key

`/v1/chat/completions` refuses a request with no `X-Provider-Key` at `openai_compat_handler.go:273`, **before any evaluation**. The probe did not send one, so on every run this plane was refused at the door and produced no evidence at all — and because the run ended on the first unevaluated probe, neither did the other eleven.

The probe now sends a syntactically valid, deliberately non-functional key. **Why that is honest evidence rests on where the handler returns, not on intent:**

- The check is **presence only** (`providerKey == ""`). Any non-empty value passes it; nothing validates the key there.
- A **blocked** payload returns at `:441` — before the upstream request is built at `:450` and before the key is attached as a Bearer token at `:458`. So on the payloads this plane is scored on, **the key is never transmitted anywhere**: no upstream call, no cost, no credential leaving the agent.
- The evidence is the refusal itself. HTTP 400 with `code: policy_denied` is a policy evaluation that happened.

**An allow-shaped payload is a different case and is deliberately not counted.** It is forwarded upstream and fails there with a provider auth error. The evaluation *did* happen — the handler records `VerdictAllow` before forwarding — but the probe cannot distinguish that 401 from its own authentication failing, and evidence resting on an ambiguity is not evidence. It is recorded per plane and scored as unevaluated. The plane earns its coverage from the deny-shaped payloads, and every rotation window carries one (`TestEveryRotationOfTheCorpusIsAdversarial`).

**The key is not a secret and must not become one.** If this plane ever needs a functional key, it belongs in Secrets Manager and referenced by ARN, the way the identity canary's minted credential is — never a literal in a template that syncs to a public mirror.

### Why status alone cannot score this plane

A policy denial here is **HTTP 400**, the same status the same handler uses for `missing_provider_key`. One is the strongest evidence the plane produces; the other is a pre-evaluation refusal. `400` sat in `NOT_EVALUATED_STATUSES`, so the predicate could not tell them apart — the plane would have scored zero even with the header. The rule reads the error **code**, and a denial counts as an evaluation whatever status carries it.

### One refused plane no longer zeroes the run

The run used to end on the first unevaluated probe. The reasoning was that a run pressing on would report eleven healthy planes and one line of prose, and the eleven would be read as the result — but the coverage check **already** fails a plane that produced nothing, by name. So failing fast bought no loudness and cost every other plane its evidence. Failures are now recorded per plane and the run continues; it still ends red if any expected plane produced nothing.

**Packaging the Lambda to S3 was the alternative, and it is the right long-term answer (#3694).** It is not this change because the deploy workflow has no S3 staging step, so packaging means a bucket, an upload step, an IAM grant and a new failure mode - *"the code in S3 is not the code in the repo"* - on a stack whose entire job is to be trustworthy about a number. A third template reuses a reviewed pattern. **A fourth probe should package instead of splitting again.**

`scripts/deploy/cfn-change-set.sh` now checks that cap before the API does and warns at 90%, so the next squeeze is visible on the run that creeps rather than the one that crosses.

### 2. It mints nothing

On community-SaaS the probe **reads** the credential the identity-compat canary already minted and stored, and never calls `/api/v1/register` itself.

`registrationIPLimit` is 5 registrations per hour per IP (`community_saas_register.go:80`), and #3655 / #3698 record the identity canary defeating itself on exactly that cap at twelve runs an hour. A second registering probe on the same Lambda egress IP would re-open that **and** consume the first probe's budget. One registration, two consumers. The IAM grant is `GetSecretValue` only - never `PutSecretValue`, because two writers to one credential is how both canaries lose their tenant at once.

On production-US there is nothing to mint: the probe authenticates **as the deployment**, through the same secret ARNs the identity canary uses.

### 3. Every request carries `X-Axonflow-Synthetic-Probe: 1`

Without it these comparisons are filed under `synthetic="false"` - into the organic volume the coverage gate reads - and the window would be signed off over evidence about ourselves. #3817 adds the label; this canary is the only thing that sets it on the decision axis.

### 4. It never presents the PEP capability handshake

`X-Axonflow-PEP-Handshake` is deliberately absent from every request. Presenting it **resets** the observation window (#3564, comment 2026-09-04), and a canary that resets the window it exists to fill is worse than no canary. If a future revision presents it, the reset must be recorded in `ADR065_RELEASE_AND_COMPATIBILITY_PLAN.md` in the same change.

### 5. A 403 is a success, and a 200 can be a failure

This probe measures whether a **policy evaluation happened**, because an evaluation is what produces a shadow observation. A payload that trips `sys_pii_ssn` and returns 403 with a policy reason is a perfect result. A 200 that matched nothing may be a perfect result too - or a route that accepted the body and never reached an evaluator.

**The base canary is the cautionary case, and it is fixed in the same change.** Its step 2 POSTed JSON-RPC method `mcpCheckInput`. The dispatcher at `/api/v1/mcp-server` implements exactly four methods - `initialize`, `tools/list`, `tools/call`, `ping` (`mcp_server_handler.go:702-714`) - and everything else falls to `writeJSONRPCError(..., jsonRPCMethodNotFound, ...)`, which does **not** call `w.WriteHeader` for method-not-found (`mcp_server_handler.go:2965`). So the response was HTTP 200 carrying a JSON-RPC error, the check was `status != 200`, and the step reported OK every hour while dispatching nothing.

Every probe here therefore carries an **evidence predicate** naming what a real evaluation looks like on that route, and the first probe whose response fails it ends the run with the body in the alert.

### 6. The payload corpus is adversarial

A canary that sends only benign text proves the plumbing and nothing about the diff: with no row matched, both engines produce an empty verdict, the pair classifies `match`, and the plane accumulates a denominator made of comparisons that could not have disagreed. That window would be non-vacuous and worthless at the same time - the most expensive outcome, because it would *satisfy* the gate.

The corpus names real seeded rows from `migrations/core/031_seed_system_policies.sql` and `059_dangerous_command_policies.sql`, across PII, SQL-injection, dangerous-command and compliance categories, plus two benign entries so the **allow** path is measured too. `TestTheCanaryPayloadCorpusIsAdversarial` enforces that spread.

### 7. Every plane is reached through the agent

The orchestrator has **no ALB listener**, deliberately (#3068, `community-saas-ecs.yaml:1195`). It is reachable only over private service discovery. So the four planes it owns - `wcp`, `map`, `policy_simulation`, `orchestrator_response` - are driven through the agent, either by `/api/request`'s `request_type` switch or by the agent's reverse-proxy prefix table. A probe addressing port 8081 directly would reach nothing.

---

## Rate arithmetic

Nine probe shapes cover twelve planes, and several probes drive more than one plane per request, so **the per-plane rate equals `VARIANTS_PER_PLANE`**. At the default 5-minute schedule that is `variants × 12` comparisons per plane per hour, before sampling.

| variants | requests/run | per plane/hour | hours to 3,000 | to 300 | to 60 |
|---|---|---|---|---|---|
| 1 | 9 | 12 | 250.0 | 25.0 | 5.0 |
| 6 (default) | 54 | 72 | 41.7 | 4.2 | 0.8 |
| 32 | 288 | 384 | **7.8** | 0.8 | 0.2 |
| 40 (max) | 360 | 480 | 6.2 | 0.6 | 0.1 |

**On production-US that is the whole story.** No per-tenant quota applies to the deployment credential. `variants=32` reaches the tier-1 floor of 3,000 per plane in under eight hours - the window the operator asked for - and 288 requests per run at a 20-second cap is bounded far inside the 900-second Lambda budget.

### On community-SaaS it is not, by two orders of magnitude

The probe authenticates as the identity canary's registered tenant, and a community-SaaS tenant carries a **daily event quota** and a per-minute burst (`auth_daily_limit.go`, `license/tier_support.go`):

| tier | daily | per-minute | days to 3,000/plane, at *any* variant count |
|---|---|---|---|
| Free | 200 | 25 | ~105 |
| Pro | 2,000 | 200 | ~10.5 |
| Premium | 5,000 | 200 | ~4.2 |

**The divisor is SEVEN probe shapes on this stack, not nine** (R3 round 2, G21). The canary declares nine; two of them - `policy_simulation` and `cowork_ingest` - are `editions: ["enterprise"]`, so the community-saas posture runs seven, and the Lambda builds its own `expected` set from the same filter. An earlier revision of this table divided by nine.

**The binding constraint is the tenant's daily quota, not the schedule and not the Lambda.** The quota caps *total* requests, so raising the variant count buys nothing - it exhausts the budget in fewer runs. A Free tenant fits **28** runs a day at one variant each (200 requests over seven shapes; the 22 first written here was 200 over NINE, and is the same nine-shape leftover as the table above).

**Stated here rather than discovered in a closeout: this canary cannot fill a tier-1 volume floor on community-SaaS.**

What it *does* deliver there, corrected (R3 round 2, G21 - an earlier revision of this paragraph claimed "full per-plane coverage on the first run", and both halves of that were false):

- **Coverage on TEN of twelve planes on the first run.** `policy_simulation` and `cowork_ingest` receive **zero** canary comparisons on community-SaaS, on every run, forever - by construction rather than by starvation, because no probe for them is deployed in that posture.
- **The tier-3 floor (60) in about 2.1 days at `variants=1` for `policy_test`** - 60 / 28.6 runs a day; the "about three days" first written here is 60 / (200/9) = 2.7, the NINE-shape figure, which survived the correction that fixed the table beside it - and **not at all for `policy_simulation`**, which is the other plane in that tier group and is one of the two enterprise-only ones. Not slow: unreachable, at any variant count and any number of days.

The two enterprise-only planes are covered on production-US, where they are the point. 

**RESOLVED 2026-09-07: community-SaaS volume is ORGANIC-ONLY.** A higher-tier canary tenant was the preferred option and is not reachable through any governed surface, so no upgrade step exists in the deploy sequence.

`Client.EffectiveTier` - what `dailyLimitForTier` reads - is assigned in exactly one place (`platform/agent/auth.go:403-465`) and only from an `X-License-Token` the caller presents, with the canonical tier read per request from `plugin_user_licenses` keyed on that token's JTI. **The tier is a property of a presented licence, not a field on the tenant**, so there is nothing for an admin API to raise. The customer-portal handlers carry a `tier` on the *enterprise organization* axis (`Developer / Professional / Enterprise / Plus`), disjoint from the SaaS plugin axis (`Free / Pro / Premium`). And `plugin_user_licenses` has one writer, `billing.IssueLicense`, whose only two callers are Stripe webhook handlers and whose request requires the Stripe customer, session and payment-intent ids that refund reconciliation reads.

Full trace on #3602 (comment 5575194357).

### Ordering within a run: breadth first, with a rotating start

Nine probe entries, `VARIANTS` deep. The obvious loop — fixed order, depth first, unpaced — is **deterministic starvation** on community-SaaS: at the default `variants=6` that is 42 back-to-back requests against a Free tenant's 25-per-minute burst, the first 429 ends the run, and the run therefore always dies inside the fifth entry. `plan_execute` (`wcp`, `map`) and `policy_test` sit after that point and are **never reached, run after run**, with `ok: false` and no alert by design. Each partial report is honest; nothing notices the pattern.

Two independent changes:

- **Breadth first** — one variant of every entry, then the second of every entry. A truncated run then has *one* comparison on every plane rather than six on five planes and none on three. Coverage is the half of gate 18 this canary principally buys; depth is the half a quota caps anyway.
- **A rotating start**, keyed on the run's own id.

**The rotation is keyed on `run_id`, not on the clock, and the reason is arithmetic.** A clock-derived offset (`int(time.time() // 300) % 9`) rotates correctly at the default five-minute schedule and degenerates at other periods the schedule parameter permits — it has no `AllowedValues`:

| schedule | ticks per run `k` | `gcd(k, 9)` | distinct start positions |
|---|---|---|---|
| `cron(1/5 …)` — default | 1 | 1 | **9 / 9** |
| `rate(15 minutes)` | 3 | 3 | 3 / 9 |
| `rate(45 minutes)` | 9 | 9 | **1 / 9** |
| every 3 hours | 36 | 9 | **1 / 9** |
| any, keyed on `run_id` | — | — | **9 / 9** |

At any period that is a multiple of 45 minutes the offset never changes, and the starvation the rotation exists to spread is restored exactly and silently. `rate(45 minutes)` is not an exotic choice for someone making a canary cheaper. `run_id` is a fresh uuid4 per invocation and cannot alias with anything.

### Coverage: evidenced vs inferred

A `PLANE_MAP` entry carries a **list** because one request drives more than one plane — `POST /api/request` runs the proxy request engine, the tier engine and, through the orchestrator forward, the response pass. That is right for *traffic* accounting: counting them separately would triple-count. It is **not** right as evidence.

So the report separates them:

- **`planes_evidenced`** — reached by a probe driving exactly one plane, so an evaluated response is evidence about *that* plane.
- **`planes_inferred`** — reached only by a multi-plane probe, where an evaluated response says something was evaluated and not which. **Four of the twelve planes are only ever inferred.**

The canary has no access to the stack's `/prometheus`, so it cannot close that gap itself. The per-plane counter is the cross-check and the closeout reads it there. Both the normal exit and the rate-limited early exit compute the split through one function — the first version had it inline at the normal exit only, and community-SaaS takes the other one every run.

### Why a 429 is treated differently per posture

On community-SaaS a tenant limit **will** be reached, so a 429 there is the documented steady state: the run stops, reports `ok: false` with the planes it did reach and `rate_limited: true`, and does **not** publish to SNS. Paging on a documented steady state is how an alert gets muted.

On production-US no tenant quota applies, so a 429 is a real finding and alerts like any other unevaluated probe.

### Which limiter refused a 429 is OBSERVED, never inferred (#3865)

At least three limiters on the agent answer 429, and they are enforced in different places:

| limiter | Free value | enforced at | what the response carries |
|---|---|---|---|
| daily quota | 200/day | `apiAuthMiddleware`, `proxyAuthMiddleware`, `mcpCheckInputHandler`, `mcpCheckOutputHandler`, and `enforceMCPSessionDailyCap` for the JSON-RPC MCP session path | `X-Axonflow-Tier-Limit: daily_quota` **and** `limit_type` in the body, with tier, limit, window, `resets_at` |
| per-minute, tier | 25/min | `enforceCommunitySaasDailyCap` (proxy.go) | `Retry-After: 60` and a bare error body - **no** `limit_type` anywhere |
| per-minute, pre-bcrypt | 200/min | `validateCommunitySaasAuth` (auth.go) | `Retry-After: 60`, `{"error": {"code": 429, ...}}` |
| upstream | the provider's own | a provider, surfaced through a probe route | whatever the provider sends |

**The status distinguishes none of them.** An earlier version of this canary reported *"the canary tenant reached its community-SaaS quota"* from `status == 429` and the posture alone - a claim about *which* limiter, derived from a code that cannot carry it. Two readings were built on that sentence before anyone noticed, in opposite directions.

The report now carries `rate_limit_cause`, `rate_limit_cause_source` (header or body), `rate_limit_headers`, `rate_limit_detail` and the clipped body. The cause is the limiter the **response names**, from `X-Axonflow-Tier-Limit` or the body's `limit_type`; anything else is `not_determined`, said out loud, with the raw evidence beside it. Matching on the message prose was rejected: it is the same mistake one layer down, and the two per-minute sites word themselves differently already.

**What the fixed instrument found, once it could look.** The `[CSAAS-RL]` agent log discriminates the limiter classes, and over the 14 hours to 2026-09-08T08:36Z **44 of 44 rate-limit refusals on this tenant were `daily_quota`** (`tenant=axonflow-internal-canary-...` `tier=Free` `limit=200`). The old sentence was *right*; nothing in the canary could have known that, which is the whole point.

**Five of the seven community-SaaS probe shapes are charged against the daily quota, not seven.** The two that are not are the `proxy` and `plan_execute` probes, which both POST `/api/request` - registered with no auth middleware, so it reaches none of the four daily-cap sites. `decide`, `pre_check`, `openai` and `policy_test` are charged through `apiAuthMiddleware`; `mcp_check` is charged by `mcpCheckInputHandler`'s own explicit call.

**And the quota is a TENANT quota shared with the sibling canaries, which is what the earlier arithmetic missed.** This probe authenticates as the credential the identity-compat canary minted, and that canary runs `cron(3/5 ...)` - twelve times an hour - against the same tenant, with the base canary hourly on top. On 2026-09-08 the first `daily_quota` refusal was at **05:01:13Z**, and this canary's own log carries only **17** completed runs before it (its first `REPORT` that day is 01:54:28Z). 17 runs x 5 charged requests is 85, not 200: **the balance was spent by the siblings.** Any calculation that divides 200 by *this* canary's run count attributes a shared budget to one consumer, which is how both earlier readings went wrong - one high, one low.

The consequence for anyone tuning the schedule: **slowing this canary alone does not fit the fleet inside 200/day.** The budget is per tenant and three canaries draw on it.

---

## Reading a run

Each run prints `START`, then either `REPORT` with `ok: true` and `planes_covered`, or a failure naming the probe, the payload, the HTTP status and the reason the response was not evidence of an evaluation. A failure also publishes to the base stack's SNS topic - except the community-SaaS rate-limit case above.

The **numbers that matter are the metrics, not this log.** Read them off `/prometheus/api/v1/query` on the stack:

```
# per plane, canary vs tenant
axonflow:decision_shadow_synthetic_comparisons:increase1h
axonflow:decision_shadow_organic_comparisons:increase1h

# the gate's own operand
axonflow:decision_shadow_gate18_fail_open:increase1h

# a plane that is reached and cannot compare at all
axonflow:decision_shadow_refused_without_comparison
```

## Related

- `docs/security/decision-shadow-mode.md` - the shadow itself, the `synthetic` label and the rules
- `platform/monitoring/rules/decision-shadow.rules.yml` - the recording rules and alerts
- `platform/decision/legacycompile/decision_shadow_canary_shapes_test.go` - the coverage forcing function, which reads the shipped template
- #3694 - package the Lambdas to S3 and deploy by URL, which retires the byte cap this page keeps referring to
