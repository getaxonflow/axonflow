# Decision Shadow Mode (ADR-065 PDP dual-evaluation, recorded only)

**Platform Version:** v10.3.0 (feature introduced in v10.3.0; ships **dark**, mode `off` by default)

**Status:** Active

**Applies To:** All deployment modes (Community and Enterprise), on both the agent and the orchestrator. Per-organization enablement is **Enterprise only**.

---

## What This Covers

Every enforcement plane in AxonFlow evaluates policy through one of the legacy engines: the shared static engine over `static_policies`, the dynamic engine over `dynamic_policies`, or the proxy tier engine. ADR-065 replaces all three with a single policy decision point, and v11 cuts the planes over to it.

Between those two points sits an observation window. **Decision shadow mode** is what fills it: with the flag on, every plane hands what it just decided - and the inputs it decided from - to a shadow that evaluates the same request against the new decision point and records the difference. It never changes an outcome, and it cannot: the observation entry point returns no value at all, and the evaluation runs on a worker after the plane's response has already been decided.

The window is what ADR-065 acceptance gate 18 is read from: *"shadow migration has no unexplained fail-open difference for the agreed window"*. Until planes dual-evaluate in production, that sentence has no operand.

### The twelve planes

| Plane | Where it evaluates | Substrate |
|---|---|---|
| `decide` | agent `/api/v1/decide` | static |
| `gateway_request` | agent gateway pre-check | static |
| `mcp` | agent MCP tool plane (input, input-redaction, output) | static |
| `openai_compatible` | agent OpenAI-compatible surface | static |
| `proxy_request` | agent proxy, phase 1 | static |
| `proxy_tier` | agent proxy, phase 2 (tier engine) | static |
| `orchestrator_response` | orchestrator response processor + PII detector | static |
| `cowork_ingest` | agent cowork OTEL ingest (**Enterprise only**) | static |
| `wcp` | orchestrator workflow control plane | dynamic |
| `map` | orchestrator multi-agent plane | dynamic |
| `policy_simulation` | orchestrator policy-simulation surface | dynamic |
| `policy_test` | agent and orchestrator policy-test surfaces | both |

`connector_execution`, which ADR-065 Phase 4 also names, is **deliberately absent**: it has no policy-evaluation call site anywhere in the tree, so there is nothing on it to dual-evaluate. Naming it in the plane list is refused at boot.

The list is derived from the compiler's plane model, which is itself pinned to a checked-in call-site census in both directions. It is never hand-maintained, so a plane that acquires an evaluation call site fails CI on the change that adds it rather than being quietly left out of the window.

## The Mode Switch

```bash
# Agent AND orchestrator environment. Default: unset, which is off.
AXONFLOW_DECISION_SHADOW_MODE=off      # no plane dual-evaluates
AXONFLOW_DECISION_SHADOW_MODE=shadow   # every plane dual-evaluates, RECORDED ONLY
```

Parse semantics:

- unset or empty: `off`. The only spelling of "off by omission".
- `off` (also accepted: `false`, `0`, `disabled`), `shadow`; case-insensitive, whitespace trimmed.
- **`enforce` is refused BY NAME.** The ADR-065 decision plane becomes an authority at v11. Until then every plane's verdict is recorded and never applied, so a deployment that set `enforce` would be believing something the system cannot do. The refusal says so, rather than reporting an unrecognized value - an operator who typed it has a calendar problem, not a spelling one.
- **anything else is FATAL at boot.** The process logs the value and exits. There is no safe direction to fall back to: `off` would leave an operator believing their planes are being measured until v11's gate is read off a window that was never open.

**Set it on both services.** Seven of the twelve planes evaluate in the agent and five in the orchestrator, and gate 18 is stated *per plane*. A deployment that shadowed only one binary would have no evidence at all for the other's planes, behind a dashboard reading healthy for the ones it covers.

## The Other Five Variables

All optional, all defaulted, all read on both services.

```bash
AXONFLOW_DECISION_SHADOW_PLANES=""            # empty = every plane (the default)
AXONFLOW_DECISION_SHADOW_SAMPLE_RATE=""       # empty = 1.0
AXONFLOW_DECISION_SHADOW_WORKERS=""           # empty = 2, clamped to [1, 64]
AXONFLOW_DECISION_SHADOW_QUEUE_DEPTH=""       # empty = 1024, clamped to [1, 65536]
AXONFLOW_DECISION_SHADOW_MATCH_LOG_EVERY=""   # empty = 10000; 0 logs no matches
```

**`PLANES`** narrows which planes observe. Empty means every plane, which is the only value that produces a complete window. It exists so one plane can be withdrawn without closing the window: if a single plane floods the not-comparable counter, or its worker cost is not affordable, the alternative to turning it off is turning off the thing v11 is waiting for. A name outside the declared set is fatal at boot.

**`SAMPLE_RATE`** is a float in `(0, 1]`. A rate below 1.0 buys nothing on the request path - the mode has to be resolved before the sampling decision can be made, so the synchronous cost is paid either way - but it does reduce worker cost. It is recorded on every comparison, because a denominator whose sampling rate is unknown cannot be interpreted. **A value outside `(0, 1]` is fatal rather than clamped**: `0` is a deployment that believes it is measuring and is not.

**`WORKERS`** and **`QUEUE_DEPTH`** size the pool that does the evaluation. Both are CloudFormation parameters on ECS (`DecisionShadowWorkers`, `DecisionShadowQueueDepth`). Raising them raises throughput and memory. Lowering them makes the queue more likely to overflow, and an overflow is a *dropped observation* - counted, and a hole in the denominator rather than a request failure. Nothing here can add latency to a request. Unlike the mode, a bad value is not fatal: these decide how the work is scheduled, never whether it happens.

**`MATCH_LOG_EVERY`** samples the "the two engines agreed" log line. Every `expected_change` and every `UNEXPLAINED` difference is logged **in full** and is never sampled away; this only governs how chatty the healthy path is. Lower it temporarily if you need to prove the shadow is running on a plane that is producing no differences - which is otherwise indistinguishable, from outside the process, from a shadow that never ran.

Two more exist for compilation and are rarely set:

```bash
AXONFLOW_DECISION_SHADOW_REALM=""          # trust realm for compiled ADR-060 segment groups
AXONFLOW_DECISION_SHADOW_CONTENT_TARGET="" # field path a legacy static redaction targets
```

Leave both unset unless you have a reason not to. When they are empty the compiler's own defaults apply - `legacy_segment` and `response.content` - and, importantly, the *same* normalized value reaches both sides of every comparison, which is what makes the empty setting safe rather than merely tolerated. (It was not always: until this was normalized at the point the options are stored, an unset `CONTENT_TARGET` gave the legacy side an empty redaction target and the ADR-065 side `response.content`, and every static redaction on every plane classified `UNEXPLAINED`.)

If you set either, set the **same value on both services**. `REALM` changes the *identifiers* a segment-scoped policy compiles to, so a mismatch would silently drop every segment-scoped constraint from the new side while the legacy engine still applies it; `CONTENT_TARGET` names the field a static redaction targets, so a mismatch makes every redaction look like a disagreement.

## Per-Organization Enablement (Enterprise)

The process flag shadows every organization on the deployment or none. The per-organization override is a column on the existing `identity_org_settings` table (enterprise migration 150), written through the customer-portal admin API and read on the same TTL as the identity compatibility mode - one row, one read, two axes.

```
PUT /api/v1/admin/organizations/{org_id}/identity-settings
{ "decision_shadow_mode": "shadow" }
```

The composition rule is the identity plane's, unchanged and shared:

- an organization **with** a record runs in the record's mode, whether that is above or below the process flag;
- an organization **without** one runs in the process flag's mode;
- a record that cannot be read means the process flag, and the fall-back is **counted** (`axonflow_decision_shadow_org_mode_failures_total`).

Raising is the ordinary case: shadow one organization on a deployment that is otherwise off. Lowering is the incident case: exempt an organization whose diff volume is unmanageable without closing the window for everyone else.

`enforce` cannot be stored: the column's `CHECK` refuses it, the parser refuses it, and the read path refuses it a third time - because a `CHECK` governs the writes its own migration governs and says nothing about a row a restore or a later migration might put there.

## Rolling It Out

1. **Deploy with the flag off.** This is the default and it changes nothing: one atomic load per policy evaluation, no allocation, no behaviour change.
2. **Turn one organization on** (Enterprise), or set `AXONFLOW_DECISION_SHADOW_MODE=shadow` on a low-traffic deployment.
3. **Read the denominator before reading the numerator.** `axonflow_decision_shadow_observations_total{disposition="compared"}` must be non-zero and growing. Zero unexplained differences out of zero comparisons passes forever, and passes hardest when the shadow is broken.
Every disposition counter below is scoped to organizations that are IN the window: an organization whose resolved mode is `off` contributes to none of them, whether it was never opted in or was exempted. That is what makes the denominator a denominator - without it, a deployment with the process mode off and one organization shadowing would accumulate counts for every other tenant's traffic.

4. **Check `disposition="not_comparable"`.** In ones and twos it is ordinary - a policy was edited between a plane's cached load and the shadow's read. If it is the *norm*, that is a defect in the shadow, not in the migration, and the window is not accumulating.
5. **Widen** to more organizations, then to the deployment.
6. **Read gate 18's operand**: `axonflow_decision_shadow_fail_open_total{classification="UNEXPLAINED",direction="new_permitted_legacy_denied"}` must be zero for the agreed window, per plane.

### Rolling It Back

| Width | How | Takes effect |
|---|---|---|
| One organization | `PUT .../identity-settings` with `decision_shadow_mode: "off"` | within the settings TTL (60s default) - **no redeploy** |
| One plane, whole deployment | `AXONFLOW_DECISION_SHADOW_PLANES` | redeploy |
| Whole deployment | `AXONFLOW_DECISION_SHADOW_MODE=off` | redeploy |

Only the per-organization path avoids a redeploy, and that is the point of it: it is the lever to reach for during an incident.

Turning the shadow off never changes an enforcement outcome, in either direction, because it never contributed to one.

## What Is Recorded, and What Is Not

Every record carries: the plane and phase, the organization, the mode that organization ran in, the governed tool the plane reported, the sampling rate, the classification, the fail-open direction, the policy row keys that determined each side, the bundle digest, the policy-set digest, and the three **reset stamps** below.

The tool is carried for **attribution only** and deliberately does not address the ADR-065 request: a compiled bundle registers one action, so a request naming a tool would be denied for `unknown_action` and every comparison would classify `UNEXPLAINED`. Per-action evaluation becomes meaningful when the planes cut over against the real action registry, which is v11's work.

**No content.** Not the request body, not the matched text, not the redacted values, not the prompt. The record is logged and queued, and a queue that can hold prompt content is a queue that can leak it into a log aggregator, a heap dump or a crash report.

Log lines are prefixed `[DECISION-SHADOW]`. A match is sampled; an `expected_change` and an `UNEXPLAINED` are always logged in full.

## The Reset Rule

**ADR-065 gate 18 is a statement about a window, and the window RESETS on a material semantic change to the observed path.** A change to how a verdict is reached, translated, evaluated or classified means the records before it and the records after it are measurements of two different systems. Adding them together produces a number that is longer and healthier-looking than any window that was actually observed, which is the failure this whole mechanism exists to prevent, one level up from an empty denominator.

So the boundary is a property **of the records**, never something reconstructed from git history afterwards. Four stamps carry it, and every one of them is derived at build or init rather than typed by hand:

| Stamp | Moves when | Log field |
|---|---|---|
| `bundle` | the policy rows change, or the compiler's Rego rendering of them does | `bundle=` |
| `eval` | the classifier's semantics change, or the OPA build that evaluates the bundle does | `eval=` |
| `adapter` | the translation from a plane's evaluation into a PDP question changes (`translate.go`, `worlds.go`, `rows.go`, `observation.go`, `mode.go`) | `adapter=` |
| `site` | the emitting plane's own observation site changes: which row facts it reports, how it attributes a phase, whether a capped redaction is marked shadowed | `site=` |

**Reading a window.** A run of records is ONE window only across records that agree on all four stamps. Where any of them changes, the window ends and a new one begins at that instant; the records on either side say so without anybody having to remember the change. In practice `bundle` moves constantly and benignly - it tracks the tenant's own policy edits - so the three that bound a *code* reset are `eval`, `adapter` and `site`.

**Why they are digests and not version constants.** A hand-bumped `evaluatorVersion = "3"` is a stamp nobody updates: the person changing what counts as an `expected_change` is not thinking about a string three files away, and the omission fails in the dangerous direction, with the window quietly accumulating across the boundary. Each stamp is instead a SHA-256 over the source that decides the behaviour, so moving it is a consequence of the edit rather than a chore attached to it. The trade is deliberate: a comment-only edit resets a window too. A spurious reset costs a window; a missed one costs the gate its meaning.

The site stamp is the one an operator would otherwise never see. A plane's observation site can start reporting a different set of facts with no change anywhere else in the shadow, and every digest computed inside the shadow package would stay byte-identical. Each site therefore digests its own source; a new site that fails to is a CI failure on the PR that adds it, not a silent gap.

## Metrics

| Metric | Labels | Read it for |
|---|---|---|
| `axonflow_decision_shadow_observations_total` | `plane`, `disposition` | the denominator, and every hole in it |
| `axonflow_decision_shadow_comparisons_total` | `plane`, `classification` | match / expected_change / UNEXPLAINED |
| `axonflow_decision_shadow_fail_open_total` | `plane`, `direction`, `classification` | **gate 18's actual operand** |
| `axonflow_decision_shadow_bundle_builds_total` | `plane`, `outcome` | compilation health |
| `axonflow_decision_shadow_evaluation_seconds` | `plane` | worker cost (off the request path) |
| `axonflow_decision_shadow_enqueue_seconds` | `plane`, `recorded` | **the only cost a caller waits for.** `recorded="true"` is an observation that entered the window; `recorded="false"` is one whose organization resolved to `off` - it still paid the mode read, and on the documented rollout (process mode off, one organization shadowing) that is the overwhelming majority of requests |
| `axonflow_decision_shadow_org_mode_failures_total` | - | per-organization records that could not be read |

The dispositions, and what each one tells you to do:

| Disposition | Meaning | Action |
|---|---|---|
| `compared` | a full comparison was made | this is the denominator |
| `sampled_out` | the sampling rate excluded it | raise `SAMPLE_RATE` |
| `dropped` | the queue was full | raise `WORKERS` or `QUEUE_DEPTH` |
| `not_comparable` | the two sides could not be asked the same question - the policy set moved between the plane's load and the shadow's read, **or** the dynamic engine read a condition field at two values in one evaluation (`modify_risk` mutates `risk_score` mid-loop) | ordinary in small numbers; a defect if it is the norm |
| `evaluation_error` | the plane could not evaluate at all | not a policy verdict, and never compared |
| `refused` | the observation was malformed, **or** a call site named an org scope and no org id | **our** defect; the log line names it. The second shape means the per-organization mode cannot be resolved at that site, so a per-org enablement would never reach it and a per-org exemption would never release it |
| `plane_disabled` | the plane is not in `PLANES` | expected if you narrowed the list |
| `evaluate_failed` | the shadow itself failed | the log line names it |
| `panicked` | the shadow worker panicked and recovered | **always a defect in the shadow.** The request path is unaffected - the worker recovers and keeps draining - but a non-zero value here is a bug report, not a posture |

**Gate 18's operand exists before anything fails open.** `axonflow_decision_shadow_fail_open_total{direction="new_permitted_legacy_denied",classification="UNEXPLAINED"}` is created at zero, at process start, for every implemented plane. A Prometheus vector renders only the label combinations something has written to, so without that the one series the gate is read from would not exist on a healthy deployment - and an alert on an absent series does not fire, which reads as the gate being satisfied by a system that was never measuring it. A zero here is a positive statement; silence is not. The other directions and classifications appear when something is actually observed.

`axonflow_decision_shadow_fail_open_total{direction="legacy_permitted_new_denied"}` is the **safe** direction: the new engine is stricter. It is expected to be non-zero during the window - ADR-065 reverses several legacy fail-open postures on purpose - and is not a blocker.

## Cost

Shadow mode compiles legacy policy into signed Rego bundles and runs in-process OPA over them, per (organization, plane, phase), on a bounded worker pool. That is real memory and CPU, and it is spent **off** the request path.

**The one cost a request waits for** is resolving the organization's mode and building the observation. The mode resolution is a memoized read on all but the first request for an organization in each settings-TTL window; on that first request it is a **bounded (2 s) database round trip, on the request path**, inside the policy engine. It is not moved to the worker on purpose: the mode is what decides whether to record, so resolving it later would enqueue every non-participating organization's traffic and let it displace the participating one's under backpressure.

It is measured per plane by `axonflow_decision_shadow_enqueue_seconds`, whose buckets reach past that deadline so the cost is visible rather than lost in `+Inf`, and whose `recorded` label separates the organizations that are in the window from the ones that paid the mode read and were then discarded. The PR that introduced this states the measured steady-state figures (274-489 ns on the request phase, 1.70 µs on the response phase).

With the flag off, the cost is one atomic load per policy evaluation and nothing else - no slice, no map, no string.

## Community and Enterprise

The dual-evaluation itself is **community code with no build tags**, on every community-visible plane. The per-organization rollout lever is Enterprise: a community build has no organization-management surface, so `NewDBOrgIdentitySettingsStore` returns `ErrEnterpriseOnly`, no per-organization source is wired, and the process flag is the whole answer for every organization. `cowork_ingest` is Enterprise-only because the plane itself is.

## Related

- ADR-065 §Phase 2 (PDP shadow mode) and acceptance gates 15 and 18
- `docs/security/identity-compat-mode.md` - the identity axis, which this composes with
- Epic #3552 (shadow migration), #3564 (per-plane cutover), #3577 (the offline diff harness this reuses)
