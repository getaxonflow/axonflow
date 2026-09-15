# The twelve-plane enforcement canary

Synthetic traffic that exercises every ADR-065 enforcement plane on a deployed stack, so that what the decision plane decided on each one is counted rather than assumed. It was built in v10.4 to fill the decision-shadow observation window. v11 removed that observer (PRD v11 §1.3), and the probe stays as the enforcement canary's traffic source. The stack, the template and their parameters keep their `decision-shadow` names until #4120 renames them, because renaming a logical ID replaces the deployed resource.

- **Template:** `infrastructure/cloudformation/synthetic-monitoring-decision-shadow.yaml`
- **Deploy:** `.github/workflows/deploy-synthetic-monitoring.yml`, `decision_shadow_probe` input
- **Stack:** `<base stack name>-decision-shadow`
- **Tracking:** #3602. Renaming the stack's `decision-shadow` names, and a `synthetic` label on the enforce counter, are #4120.

This page carries the design argument. It is here rather than in the template's header because that template sits close to the 51,200-byte `--template-body` cap the deploy commands use (#3694), and a design argument that has to be shortened to fit a deploy limit belongs somewhere it can be read.

---

## What it is for

PRD v11 §5.7 asks for evidence, per enforcement plane, that the new engine decided a governed request: `engine=anchored` on the wire and the audit row, counted under the plane's own label. A plane that no traffic reaches produces no evidence, and no evidence reads exactly like a plane that was never reached. Organic traffic does not cover the planes: over 17 hours (2026-09-06T20:26Z .. 2026-09-07T13:29Z, both stacks on 10.4.0) the house stacks recorded shadow comparisons on 5 of 12 planes on community-SaaS and on none on production-US. The canary drives every plane on a schedule, so each one has traffic to count.

## What it is *not* for

**It cannot substitute for organic volume.** A canary answers two questions differently:

| question | counts canary traffic? |
|---|---|
| **coverage** - "has this plane been exercised at all" | **yes.** A path only the canary exercises is still an exercised path. |
| **volume** - "customers sent N requests this plane decided" | **no.** |

Today the second question cannot be answered from the counter at all. `axonflow_decision_enforce_decisions_total` has no `synthetic` label, so canary and customer decisions land in one series (#4120). Until it has one, a count read off that counter is an upper bound on organic volume, never a measurement of it.

---

## Design decisions, and what each one refuses

### 1. A template of its own

`aws cloudformation create-change-set --template-body` caps a body at 51,200 bytes, and the deploy workflow uses exactly that flag with no S3 staging step. As of this change:

```
synthetic-monitoring.yaml                  28,946 bytes   (56% of the cap)
synthetic-monitoring-decision-shadow.yaml  49,926 bytes   (97.5% - 1,274 of headroom)
```

The identity-compat canary's template, then the second, had 570 bytes of headroom and could not absorb a twelve-plane probe, which is why this canary got a template of its own rather than a bigger second one. That template was retired with the identity comparison in v11; its deployed stack stays up until #4166, because it owns the credential this probe reads on community-SaaS (below).

**These figures go stale on every edit and are not the instrument.** An earlier revision of this page gave two of them as "measured on main" and the change that added the third template made both wrong the moment it merged. `tests/regression-test-required/synthetic_monitoring_two_stacks_test.sh` prints the current sizes and fails on the cap, and `scripts/deploy/cfn-change-set.sh` checks it again before the API sees the body and warns above 90%; read those rather than this block. The decision-shadow template is above that warning threshold today, so the warning fires on every deploy of it - correctly: it is nearly full, and one more plane or parameter breaks the deploy outright.

## The openai_compatible plane and the provider key an operator must supply

`/v1/chat/completions` refuses a request with no `X-Provider-Key` at `openai_compat_handler.go:262`, **before any evaluation**. The first version of the probe sent no header at all and was refused at the door on every run.

**The second version sent a hard-coded placeholder, and that was wrong for a reason the argument for it contained.** The argument was that the key is never used, because a blocked payload returns at `:433` — before the upstream request is built and before the key becomes a Bearer token at `:450`. That is true, and it is conditional on the payload being **blocked**. On an **allowed** payload the handler takes the `:450` path and calls the provider for real, and the provider answers `401 invalid_api_key`.

`try.getaxonflow.com` blocks none of this corpus. Every openai probe took the `:450` path, every run reported `status 401: authentication failed, so nothing was evaluated`, and the coverage check paged `dev@` every five to ten minutes naming a plane no operator could do anything about. **A probe that pages unactionably is worse than a probe that says plainly it cannot run.**

### What the plane needs now

`DecisionShadowProviderKeySecretArn` — a Secrets Manager ARN holding a provider key valid for `gpt-4o-mini`. It is optional, and the two states are deliberately different:

| The parameter is | The openai probe | `openai_compatible` in the coverage denominator |
|---|---|---|
| empty | **skipped**, with the reason and the parameter name in the report | **no** — `planes_skipped` says so, and coverage does not fail on it |
| set, secret readable | runs, sending the real key | yes |
| set, secret unreadable or empty | the whole run **fails** with `failed_step: read-provider-key` | — |

The third row is the one worth stating out loud. **A skip is never reachable when the credential is present**: the skip predicate is keyed on the ARN — the *configuration* — and not on the key value, so supplying the key and misconfiguring the IAM grant reports a fault rather than looking identical to not supplying it at all.

**What the key does not buy.** An *allowed* request returns the provider's own completion body verbatim, and that body carries no governance field, so `_evaluated` scores it as evidence of nothing. **This plane earns its coverage from a DENIAL** — HTTP 400 with `code: policy_denied`. The key exists to stop the unactionable 401 page and to let an allowed payload reach the evaluator at all, not because a 200 would be counted. On a deployment whose posture blocks nothing in this corpus, this plane will produce no evidence even with a valid key, and that is a finding about the deployment rather than about the probe.

The key is spent on real tokens (`max_tokens: 1` per call). Scope and budget it as a synthetic-traffic key and rotate it independently of anything a tenant uses.

### Why status alone cannot score this plane

A policy denial here is **HTTP 400**, the same status the same handler uses for `missing_provider_key`. One is the strongest evidence the plane produces; the other is a pre-evaluation refusal. `400` sat in `NOT_EVALUATED_STATUSES`, so the predicate could not tell them apart — the plane would have scored zero even with the header. The rule reads the error **code**, and a denial counts as an evaluation whatever status carries it.

### One refused plane no longer zeroes the run

The run used to end on the first unevaluated probe. The reasoning was that a run pressing on would report eleven healthy planes and one line of prose, and the eleven would be read as the result — but the coverage check **already** fails a plane that produced nothing, by name. So failing fast bought no loudness and cost every other plane its evidence. Failures are now recorded per plane and the run continues; it still ends red if any expected plane produced nothing.

**Packaging the Lambda to S3 was the alternative, and it is the right long-term answer (#3694).** It is not this change because the deploy workflow has no S3 staging step, so packaging means a bucket, an upload step, an IAM grant and a new failure mode - *"the code in S3 is not the code in the repo"* - on a stack whose entire job is to be trustworthy about a number. A third template reuses a reviewed pattern. **A fourth probe should package instead of splitting again.**

`scripts/deploy/cfn-change-set.sh` now checks that cap before the API does and warns at 90%, so the next squeeze is visible on the run that creeps rather than the one that crosses.

### 2. It mints nothing

On community-SaaS the probe **reads** the credential the identity-compat canary already minted and stored, and never calls `/api/v1/register` itself. That canary's stack stays deployed for this reason, and the deploy workflow no longer deploys it, until #4166 gives this probe a credential of its own.

`registrationIPLimit` is 5 registrations per hour per IP (`community_saas_register.go:80`), and #3655 / #3698 record the identity canary defeating itself on exactly that cap at twelve runs an hour. A second registering probe on the same Lambda egress IP would re-open that **and** consume the first probe's budget. One registration, two consumers. The IAM grant is `GetSecretValue` only - never `PutSecretValue`, because two writers to one credential is how both canaries lose their tenant at once.

On production-US there is nothing to mint: the probe authenticates **as the deployment**, through the same secret ARNs the identity canary used.

### 3. Every request carries `X-Axonflow-Synthetic-Probe: 1`

The marker is stamped on the request context at the outermost middleware (`identity.SyntheticProbeMiddleware`). It is what lets a reading separate the canary's decisions from customers'. The enforce counter does not read it yet (#4120), and a probe that dropped the header would make that separation impossible even once it does.

### 4. It never presents the PEP capability handshake

`X-Axonflow-PEP-Handshake` is deliberately absent from every request. In v10.4, presenting it reset the observation window (#3564, comment 2026-09-04). In v11 one reason remains: a caller that presents it is decided under the capabilities it declares, so a probe that presented it would measure a different caller from the one most integrations are. Adding it changes what the canary measures, and belongs in its own change.

### 5. A 403 is a success, and a 200 can be a failure

This probe measures whether a **policy evaluation happened**, because an evaluation is what produces a decision the plane records. A payload that trips `sys_pii_ssn` and returns 403 with a policy reason is a perfect result. A 200 that matched nothing may be a perfect result too - or a route that accepted the body and never reached an evaluator.

**The base canary is the cautionary case, and it is fixed in the same change.** Its step 2 POSTed JSON-RPC method `mcpCheckInput`. The dispatcher at `/api/v1/mcp-server` implements exactly four methods - `initialize`, `tools/list`, `tools/call`, `ping` (`mcp_server_handler.go:702-714`) - and everything else falls to `writeJSONRPCError(..., jsonRPCMethodNotFound, ...)`, which does **not** call `w.WriteHeader` for method-not-found (`mcp_server_handler.go:2965`). So the response was HTTP 200 carrying a JSON-RPC error, the check was `status != 200`, and the step reported OK every hour while dispatching nothing.

Every probe here therefore carries an **evidence predicate** naming what a real evaluation looks like on that route, and the first probe whose response fails it ends the run with the body in the alert.

### 6. The payload corpus is adversarial

A canary that sends only benign text proves the plumbing and nothing about enforcement: with no control matched, every plane answers the same allow, and the count grows with decisions no control took part in. That count would be non-zero and worthless at the same time - the most expensive outcome, because it would *look* like evidence.

The corpus names real seeded rows from `migrations/core/031_seed_system_policies.sql` and `059_dangerous_command_policies.sql`, across PII, SQL-injection, dangerous-command and compliance categories, plus two benign entries so the **allow** path is measured too. `TestTheCanaryPayloadCorpusIsAdversarial` enforces that spread.

### 7. Every plane is reached through the agent

The orchestrator has **no ALB listener**, deliberately (#3068, `community-saas-ecs.yaml:1195`). It is reachable only over private service discovery. So the four planes it owns - `wcp`, `map`, `policy_simulation`, `orchestrator_response` - are driven through the agent, either by `/api/request`'s `request_type` switch or by the agent's reverse-proxy prefix table. A probe addressing port 8081 directly would reach nothing.

---

## Rate arithmetic

Nine probe shapes cover twelve planes, and several probes drive more than one plane per request, so **the per-plane rate equals `VARIANTS_PER_PLANE`**. At the default 5-minute schedule that is `variants × 12` canary decisions per plane per hour.

| variants | requests/run | per plane/hour | hours to 3,000 | to 300 | to 60 |
|---|---|---|---|---|---|
| 1 | 9 | 12 | 250.0 | 25.0 | 5.0 |
| 6 (default) | 54 | 72 | 41.7 | 4.2 | 0.8 |
| 32 | 288 | 384 | **7.8** | 0.8 | 0.2 |
| 40 (max) | 360 | 480 | 6.2 | 0.6 | 0.1 |

**On production-US that is the whole story.** No per-tenant quota applies to the deployment credential. `variants=32` reaches 3,000 decisions per plane in under eight hours, and 288 requests per run at a 20-second cap is bounded far inside the 900-second Lambda budget.

### On community-SaaS it is not, by two orders of magnitude

The probe authenticates as the identity canary's registered tenant, and a community-SaaS tenant carries a **daily event quota** and a per-minute burst (`auth_daily_limit.go`, `license/tier_support.go`):

| tier | daily | per-minute | days to 3,000/plane, at *any* variant count |
|---|---|---|---|
| Free | 200 | 25 | ~105 |
| Pro | 2,000 | 200 | ~10.5 |
| Premium | 5,000 | 200 | ~4.2 |

**The divisor is SEVEN probe shapes on this stack, not nine** (R3 round 2, G21). The canary declares nine; two of them - `policy_simulation` and `cowork_ingest` - are `editions: ["enterprise"]`, so the community-saas posture runs seven, and the Lambda builds its own `expected` set from the same filter. An earlier revision of this table divided by nine.

**The binding constraint is the tenant's daily quota, not the schedule and not the Lambda.** The quota caps *total* requests, so raising the variant count buys nothing - it exhausts the budget in fewer runs. A Free tenant fits **28** runs a day at one variant each (200 requests over seven shapes; the 22 first written here was 200 over NINE, and is the same nine-shape leftover as the table above).

**Stated here rather than discovered in a closeout: this canary cannot reach thousands of decisions per plane on community-SaaS.**

What it *does* deliver there, corrected (R3 round 2, G21 - an earlier revision of this paragraph claimed "full per-plane coverage on the first run", and both halves of that were false):

- **Coverage on TEN of twelve planes on the first run.** `policy_simulation` and `cowork_ingest` receive **zero** canary decisions on community-SaaS, on every run, forever - by construction rather than by starvation, because no probe for them is deployed in that posture.
- **60 decisions in about 2.1 days at `variants=1` for `policy_test`** - 60 / 28.6 runs a day; the "about three days" first written here is 60 / (200/9) = 2.7, the NINE-shape figure, which survived the correction that fixed the table beside it - and **not at all for `policy_simulation`**, which is one of the two enterprise-only ones. Not slow: unreachable, at any variant count and any number of days.

The two enterprise-only planes are covered on production-US, where they are the point. 

**RESOLVED 2026-09-07: community-SaaS volume is ORGANIC-ONLY.** A higher-tier canary tenant was the preferred option and is not reachable through any governed surface, so no upgrade step exists in the deploy sequence.

`Client.EffectiveTier` - what `dailyLimitForTier` reads - is assigned in exactly one place (`platform/agent/auth.go:403-465`) and only from an `X-License-Token` the caller presents, with the canonical tier read per request from `plugin_user_licenses` keyed on that token's JTI. **The tier is a property of a presented licence, not a field on the tenant**, so there is nothing for an admin API to raise. The customer-portal handlers carry a `tier` on the *enterprise organization* axis (`Developer / Professional / Enterprise / Plus`), disjoint from the SaaS plugin axis (`Free / Pro / Premium`). And `plugin_user_licenses` has one writer, `billing.IssueLicense`, whose only two callers are Stripe webhook handlers and whose request requires the Stripe customer, session and payment-intent ids that refund reconciliation reads.

Full trace on #3602 (comment 5575194357).

### Ordering within a run: breadth first, with a rotating start

Nine probe entries, `VARIANTS` deep. The obvious loop — fixed order, depth first, unpaced — is **deterministic starvation** on community-SaaS: at the default `variants=6` that is 42 back-to-back requests against a Free tenant's 25-per-minute burst, the first 429 ends the run, and the run therefore always dies inside the fifth entry. `plan_execute` (`wcp`, `map`) and `policy_test` sit after that point and are **never reached, run after run**, with `ok: false` and no alert by design. Each partial report is honest; nothing notices the pattern.

Two independent changes:

- **Breadth first** - one variant of every entry, then the second of every entry. A truncated run then has *one* decision on every plane rather than six on five planes and none on three. Coverage is what this canary principally buys; depth is what a quota caps anyway.
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

A `PLANE_MAP` entry carries a **list** because one request drives more than one plane — `POST /api/request` runs its one anchored pass and, through the orchestrator forward, the response pass. That is right for *traffic* accounting: counting them separately would double-count. It is **not** right as evidence.

**An inference is not coverage, and until #3555 the report summed the two.** `planes_covered` was `evidenced | inferred` at both exits, and the coverage gate was read off that sum - so a plane reached only by a multi-plane probe satisfied the gate. The `map` plane was reported covered **seventeen times in one day** while its only evaluation site is constructed only when the HITL workflow engine is, so on a deployment that does not enable HITL the plane evaluates nothing, for a structural reason, and the probe it shares with `wcp` is evaluated once, on `wcp`. Four of the five inferred planes happened to carry non-zero counters, so the inference was right four times and wrong exactly where nothing checked it.

So the report separates them, and `planes_covered` now carries **evidence only**:

- **`planes_covered`** - reached by a probe driving exactly one plane, so an evaluated response is evidence about *that* plane. This is the field to read as coverage, and the only one a per-plane claim may be made from.
- **`planes_inferred_only`** — a map from plane to the probe that reached it and the planes it shared that probe with. A list would say an inference happened; this says why the inference is worth nothing for a given plane, so it can be judged rather than trusted.
- **`planes_never_evidenceable`** — derived from `PLANE_MAP`: planes with no single-plane probe in this posture. They can **never** appear in `planes_covered`, so their absence is permanent and is not a regression. The set is **posture-relative** and is derived from `PLANE_MAP` rather than written down — a count beside a table is wrong the first time the table moves and nothing says so, which is how this page came to claim "four of the twelve" when it was five. **The number is deliberately not restated here either**: read it off `planes_never_evidenceable` in any run's report, which is the value the code actually derived. Restating it in prose would reintroduce the same defect one file over, and no test reads this page.

**`ok: true` does not mean twelve planes were covered.** It means every plane was reached and every plane that *could* be evidenced was. There are two coverage failures, checked sharpest-first so both are reachable: a plane with its own probe that produced no evidence, and a plane no evaluated probe touched at all. They have different fixes. A plane that is inference-only *by construction* fails neither — paging on a permanent property of the probe map every run is how an alert gets muted — but it is reported, every run, in the two fields above.

The canary has no access to the stack's `/prometheus`, so it cannot close the inference gap itself. **The cross-check is the plane's own counter, `axonflow_decision_enforce_decisions_total{plane=...}`**, for the agent's enforcing scopes; the orchestrator's scopes gain theirs when they cut over (W3-H). A plane listed in `planes_inferred_only` whose counter reads zero was never decided, and that pairing is exactly what nobody made for the `map` plane in v10.4. Both the normal exit and the rate-limited early exit compute the split through one function - the first version had it inline at the normal exit only, and community-SaaS takes the other one every run.

### The `wcp` and `map` planes: one probe, two requests, and one plane that still cannot answer

`/api/v1/plan/execute` executes a **stored** plan. `executePlanHandler` (`platform/orchestrator/run.go:4872`) reads `context.plan_id`, refuses without one at `:4925`, retrieves the row at `:4960` — `GetPlanForExecution(planID, orgID)`, authorized on the org — and only then evaluates, at `:5051`, over **`plan.Query`: the query stored on the plan, not the query on the execute request.**

The first version of the probe sent `context: {steps: [...]}` and no `plan_id`. It was refused at `:4925` on every run — 126 lines before the wcp evaluator and long before any step executes — and the agent wrapped that 400 into an HTTP **200** whose body carried `error` *and* the proxy plane's `policy_info`, which is why it read as a healthy response with an application error rather than as a dead probe.

The probe now makes **two** requests:

1. `request_type: multi-agent-plan` with the adversarial payload as the query. This routes to `/api/v1/plan` (`agent/run.go:3256`) and mints a plan for *this* tenant on *this* stack. The adversarial text goes here because this is the query `wcp` will evaluate. `multi-agent-plan` rather than `generate-plan`: both route to the same endpoint, but only `multi-agent-plan` and `execute-plan` reach the block at `agent/run.go:2972` that lifts the orchestrator's `plan_id` to the top level of the response.
2. `request_type: execute-plan` carrying that `plan_id`, both top level and in `context` — the agent copies the top-level field into the context it forwards (`agent/run.go:3231`) and the orchestrator reads only the context.

**A generate call that returns no plan is never scored as evidence.** That first request is evaluated by the *proxy* planes; a 403 from it carries `policy_info` and would, returned verbatim, hand `wcp` and `map` an evaluation neither performed — the inference defect this canary exists to refuse, manufactured by the canary itself. The probe wraps what it saw under `probe_precondition_failed`, a key the platform never emits, and the evidence predicate scores it as nothing. A **429** on that first call is the one exception and passes through verbatim, so the run's rate-limited exit fires rather than the run continuing to spend calls against a tenant already refusing them.

#### `map` needs one more thing, and it is not in this repo's control

Fixing the `plan_id` is **necessary and not sufficient** for the `map` plane. `map` has exactly one legacy evaluation call site in the tree - `MAPHITLPolicyChecker.CheckPolicy`, `platform/orchestrator/map_hitl_adapter.go:50`, per `platform/decision/legacycompile/legacy_call_sites.tsv` - and that checker is only constructed when `AXONFLOW_HITL_ENABLED == "true"` (`platform/orchestrator/run.go:1618`). **No CloudFormation template in this repository sets that variable**; the only default in the tree is `false` (`docker-compose.yml:468`). With it unset, `hitlWorkflowEngine` is nil, `hitl_execution.go:406` never calls the checker, and `map` is never evaluated whatever this canary sends.

So `map`'s silence alongside repeated "covered" readings has **two** causes stacked: the probe never evaluated (fixed here), and the plane's only evaluator is not wired on the deployed stacks (an operator action, and a live question for #3555). Until it is, `map` appears in `planes_inferred_only` - reached by a multi-plane probe, and nothing more than that - and never in `planes_covered`, which is exactly the distinction the split above exists to make visible.

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

Each run prints `START`, then either `REPORT` with `ok: true` and `planes_covered` (**evidence only** — read `planes_inferred_only` and `planes_never_evidenceable` beside it, never `planes_covered` alone), or a failure naming the probe, the payload, the HTTP status and the reason the response was not evidence of an evaluation. **Every report shape — success, rate-limited and coverage-failure — carries the same six `planes_*` fields**: `planes_covered`, `planes_inferred_only`, `planes_never_evidenceable`, `planes_no_evidence`, `planes_not_reached` and `planes_skipped`. The sixth is the only one that is not a verdict on a run: it names the planes this run did not probe at all and why, so a run covering ten planes and skipping two cannot read identically to one covering twelve. Every **expected** plane appears in **at least one** of the four non-structural ones, so a plane missing from all of them is a defect in the report and not a quiet pass. A plane named in `planes_skipped` is not expected: the skip predicate builds the denominator, so it leaves every other field rather than appearing in them as a hole. Exactly one is the common case but not a guarantee, and the exception is deliberate: `planes_no_evidence` and `planes_not_reached` do partition each other - the sharper class wins, so no plane is named in both - but a plane that has its own single-plane probe **and** also rides a shared probe can appear in `planes_inferred_only` and `planes_no_evidence` together. That says two different true things about it - a shared probe reached it, and its own probe produced nothing - and it is the shape a plane takes once it gains a probe of its own. A failure also publishes to the base stack's SNS topic - except the community-SaaS rate-limit case above.

The **numbers that matter are the metrics, not this log.** Read them off `/prometheus/api/v1/query` on the stack:

```
# per enforcing scope: which engine decided, with what verdict and reason
sum by (plane, engine, verdict, reason) (increase(axonflow_decision_enforce_decisions_total[1h]))
```

The counter covers the agent's enforcing scopes only; the orchestrator's scopes gain theirs when they cut over (W3-H). It carries no `synthetic` label yet (#4120), so these are canary and customer decisions together.

## Related

- `docs/security/decision-shadow-mode.md` - the retirement of the decision mode and the shadow observer this canary was built for
- `technical-docs/designs/V11_ENFORCEMENT_CANARY_EVIDENCE.md` - how the canary's reading is reported at the tag
- `platform/decision/legacycompile/decision_shadow_canary_shapes_test.go` - the coverage forcing function, which reads the shipped template
- #4120 - rename the stack's `decision-shadow` names, and label the enforce counter `synthetic`
- #3694 - package the Lambdas to S3 and deploy by URL, which retires the byte cap this page keeps referring to
