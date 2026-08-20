# Changelog

All notable changes to AxonFlow will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Each entry is grouped by edition: **Community** changes also ship in the
community mirror, **Enterprise** changes are EE-only.

---

<!--
  Version decision (Step 0): v9.15.0, MINOR. The train adds new backward-compatible
  capabilities - SSO role auto-provisioning (#3291) and the telemetry digest's
  per-platform-version breakdown (#3277) - so by the 2026-07-30 semver policy it is
  a MINOR, not a patch. It also RELAXES a refusal (the /api/request empty-email
  fail-close now proceeds org-only, #3278), which is not a breaking change. No
  removed capability, no new required credential, no new refusal.
-->

<!--
  Version decision (Step 0): the next train is a MAJOR, pending operator
  sign-off. #2330's headline is additive (portal password recovery by email,
  off by default), which alone would be a MINOR - but by the 2026-07-30
  operator semver policy ("removed fallback / new required credential / new
  refusal / fatal config value = MAJOR") it carries three qualifying changes:

    1. A REMOVED FALLBACK + NEW REFUSAL: forgot-password no longer returns a
       reset token in the body on ENVIRONMENT=staging (or unset), it returns
       501. Any operator scripting against staging token-in-body must move to
       ENVIRONMENT=development or the admin reset endpoint.
    2. A NEW REFUSAL AT BOOT: a portal with RESEND_API_KEY but no
       from-address or no SSO_BASE_URL logs a misconfiguration and keeps
       forgot-password on 501.
    3. Reset links issued before the upgrade stop working (tokens are now
       hashed at rest); they live at most 1 hour.

  Both 1 and 2 are security fixes to unintended behavior, so an argument for
  MINOR exists - flagged here for the release owner to decide rather than
  assumed.
-->

<!--
  Version decision (Step 0): the policy-evaluation consolidation (epic #3293
  Slice 2, #3296) is MINOR in its own right. It does introduce two new
  refusals, which the 2026-07-30 policy would ordinarily read as MAJOR, so
  the reasoning is recorded rather than left implicit. This does NOT override
  the pending-MAJOR decision above: that is driven by #2330 independently,
  and a train's version is the maximum of its contents.

  The two new refusals, and why each is judged niche:

    1. A `regex` condition whose `value` is not a string is now rejected
       (400) instead of being stored and silently never matching. Nothing
       AxonFlow ships is affected - no seeded policy in policy_defaults.go
       or any seed migration uses a non-string regex value - and the portal
       cannot produce one, since its condition-value input is a text field.
       The exposed population is callers who wrote such a value directly
       against the API, where it was always meaningless: a numeric "pattern"
       only ever matched by an accident of stringification.

       The sharp edge, recorded so it is not rediscovered: validateUpdateRequest
       re-validates conditions whenever an update supplies them, so a client
       that round-trips a whole policy object can hit this on a pre-existing
       row while editing an unrelated field. Operators wanting to check their
       own corpus before upgrading:

         SELECT policy_id, tenant_id FROM dynamic_policies
         WHERE conditions @> '[{"operator":"regex"}]'
           AND jsonb_typeof(conditions->0->'value') <> 'string';

    2. An explicitly-empty `conditions` array on update is now rejected;
       omitting the field still means "leave unchanged". This closes the one
       path by which a caller could clear a policy's conditions, and is
       load-bearing for the restored "no conditions means applies to
       everything" semantics - it is what keeps that construct platform-only.
       No customer-authored zero-condition rows exist, so nothing pre-existing
       breaks.

  ImportPolicies' all-or-nothing behavior (validation runs over the whole
  batch and returns on the first failure) is PRE-EXISTING and unchanged here.
  What changes is how often it can trigger: an export-import round-trip of a
  corpus containing one non-string regex value now fails the batch where it
  previously succeeded. Left as-is by decision.
-->

<!--
  Version decision (Step 0): v9.19.0, MINOR. The train's headline is the
  portal-truth wave (#3347 via #3359, #3363 via #3366, #3361/#3364 via #3382,
  #3346 via #3377, #3365 via #3375, #3360 via #3376) and the policy-evaluation
  consolidation (epic #3293 Slice 2, #3296 via #3320) with its
  legacy-conditions follow-up (#3384 via #3387). It removes no operator-facing
  capability, adds no required credential and adds no boot-time refusal.

  The two new API refusals it carries (a non-string `regex` condition value,
  and an explicitly-empty `conditions` array on update) are #3296's, already
  judged niche in the Step-0 comment recorded above; that reasoning stands
  unchanged and is what keeps this MINOR rather than MAJOR under the
  2026-07-30 operator semver policy.

  The one further item that argues for more than MINOR, recorded here rather
  than left implicit: #3387 CHANGES ENFORCEMENT for stored rows whose
  `conditions` column holds an explicitly-empty array. Those rows stop being
  evaluated on the database-backed evaluation surfaces (the in-memory
  fallback engine, in play only while the database is unreachable, still
  loads them as stored). It is a narrowing of a state no
  released create API could produce (only the pre-9.19 update API could), it
  removes nothing an operator deliberately configured, and it is what stops
  #3296's restored vacuous-match semantics from turning that residue into a
  tenant-wide deny at upgrade. Treated as a defect fix, not a breaking
  change; the operator audit query is in the Migration section below.

  No migrations: `git diff v9.18.0..origin/main -- migrations/` is empty.
-->

## [9.19.0] - 2026-08-20 (portal truth across audit, approvals and policy surfaces; policy-evaluator consolidation)

> Scope: the portal's read surfaces (audit, approvals, policies) now agree
> with what the platform actually recorded, and the last four bespoke
> policy-condition matchers are gone in favour of one shared evaluator.
> Operators upgrading a database written before this release should read the
> Migration section: policy rows stored with an explicitly-empty `conditions`
> array stop being evaluated.

### Licensing

- **Beginning with v9.19.0, free production use under the BSL 1.1 Additional
  Use Grant is conditioned on the integrity of the copy you run.** The
  operative wording is in `LICENSE`; read it there rather than relying on this
  summary. In outline: production use of a copy or derivative work is
  permitted only while, in that copy, licence key functionality has not been
  tampered with, and no limit or feature gate has been raised, avoided or
  bypassed relative to the corresponding unmodified AxonFlow distribution it
  was made from. The wording follows the anti-circumvention formulation the
  Elastic License 2.0 has used since 2021, extended to cover mechanisms that
  do not depend on the licence key.
- **Setting configuration is expressly outside this.** The condition does not
  apply to supplying a configuration value through a mechanism the shipped
  software provides for that purpose, so environment variables and config
  files you are documented to set, such as `MEDIA_GOVERNANCE_ENABLED`, are
  unaffected.
- **This is a new prospective condition on free production use, not a
  restatement of the previous grant.** Earlier releases remain governed by the
  terms distributed with them; the change is not retroactive. It does not
  define, or attempt to define, the commercial boundary between the Community
  build and AxonFlow's licensed offerings.
- **The rights to copy, modify, create derivative works, redistribute and make
  non-production use are unchanged.** The Additional Use Grant governs
  production use only, and the new text says so expressly. The licence family
  (BSL 1.1), the Change Date and the Change License are all unchanged. The
  License's own termination provision is unaffected.
- **New `COMMUNITY_LICENSE_BOUNDARY.md` documents what the Community build
  includes.** It is product documentation: expressly **not** a licence term,
  not incorporated into the Additional Use Grant, and not exhaustive. Most
  entries point at where a limit or gate is defined in the published source so
  you can check it; three name source that is not public and say so.

### Security

- **`golang.org/x/mod` raised from v0.37.0 to v0.40.0** (CVE-2026-56864,
  CVE-2026-56865) in every module that declares it: `platform/go.mod`
  *(Community)* and the five Enterprise modules `ee`,
  `ee/platform/license-server`, `ee/platform/community-saas-bridge`,
  `ee/platform/load-testing` and `ee/platform/customer-portal`
  *(Enterprise)*. The package is transitive-only here (reached through
  `golang.org/x/text`) and is never imported by AxonFlow code, so no
  behavior changes; the bump exists so the shipped images stop carrying the
  finding. Nothing else in the module graph requires the fixed version yet,
  so it is pinned explicitly rather than acquired by bumping a parent.

### Community

#### Added

- **Every audit row that names a policy now carries the policy's display
  name, not just its id (#3365).** The decide-plane writer
  (`writeDecisionAuditLog`) and the MCP-plane writer
  (`buildMCPDecisionAuditDetails`, about 25 call sites covering every MCP
  early-return deny and both redaction rows) stamped `policy_ids` and nothing
  else, so no reader could ever render a name for those rows: they surfaced
  as raw ids wherever a policy identity is displayed, including the portal
  audit view and the compliance exports. Both builders now go through one
  shared writer-side normalizer (`stampPolicyIdentityNames`,
  `platform/agent/policy_identity_stamp.go`), so the two cannot drift apart.
  Names resolve in a fixed order: first the evaluation-time name carried on
  the match the engine actually made, then a compiled-in name for the 28
  code-backed guard pseudo-policies that have no `static_policies` row
  (`circuit_breaker`, `rbi_kill_switch`, `tenant_mismatch`, the
  validator-backed detectors, and the rest). There is deliberately no
  write-time catalog lookup: a policy renamed between evaluation and write
  must not be stamped with a name the evaluated policy never carried, and an
  id in neither source is left unnamed rather than guessed. The orchestrator's
  blocked-request and blocked-response writers and the override-lifecycle
  writer gained the same evaluation-time stamping (names only on that
  plane, whose ids are internal UUIDs no reader should see). One residue
  remains and is deliberate scope, not an omission: an orchestrator
  response that was redacted rather than blocked still records only its
  legacy applied-policies detail, which no reader resolves, so those rows
  continue to render without a policy name. Rows written
  before this release are unchanged and still render as ids; the reader side
  labels them explicitly rather than blanking them (see the Enterprise
  section).
- **A stored policy `action` that the detection posture lever displaced is
  now observable (#3360).** On every plane the detection posture lever
  governs, the lever's action (`PII_ACTION` and its siblings, or the
  governance profile's default) replaces whatever `action` a matched
  `static_policies` row carries. That is the documented authority order, not
  a fail-open, and it is why a row with `action=block` can match a request
  that is nonetheless allowed with a redaction obligation. Until now the
  displacement left no trace anywhere: the `action` column read as
  authoritative in the CRUD API and the portal while being dead data at
  evaluation time. Downward displacement (the stored action is stricter than
  the resolved one) now increments
  `axonflow_agent_policy_stored_action_displaced_total` and, on the decide
  plane, appends an advisory reason to the response. **No verdict,
  obligation, redaction or approval field changes**: the loop only appends to
  `AdvisoryReasons` and increments a counter, and it is skipped entirely when
  the result is blocked. Upward displacement (a strict profile tightening a
  `warn` row) is the lever doing its job and is not flagged, and a NULL phase
  column leaves the stored action empty on purpose, so the many seeded rows
  that resolve through the category fallback do not emit an advisory on every
  match. The resolution order, the per-plane action-to-outcome matrix and the
  authoring guidance are written down in
  `docs/governance/policy-action-authority.md`, linked from the PII detection
  guide. The advisory currently surfaces on the decide plane only, because
  that is the only plane that consumes `AdvisoryReasons`; the metric fires on
  every plane that converts through the shared path.
- **`PolicyService.TestPolicy` (the policy-simulator "test" action) is now
  segment-aware**, closing the segment-blindness tracked in #3283. Where a
  verified caller identity is available on the request context, a
  segment-scoped policy's `Matched` result now honors segment membership the
  same way enforcement does (restriction-only, fail-closed on a resolution
  error), instead of unconditionally reporting a match to any caller. Where
  no verified identity is available (today's only production shape, since no
  HTTP entry point yet threads one onto this path), behavior is unchanged and
  the response explanation says so explicitly rather than presenting a
  possibly segment-restricted policy as an unqualified tenant-wide match.
- **New metric: `axonflow_policy_condition_unevaluable_total{reason,plane}`
  - a policy that silently fails to enforce is otherwise invisible.** Until
  now, a dynamic-policy condition that could not be genuinely evaluated (a
  typo'd operator, a numeric comparison against a non-numeric operand, a
  regex value that isn't a string, a stored `conditions` blob that fails to
  unmarshal, or a field the caller could not resolve) was indistinguishable
  from a legitimate no-match: the two existing counters
  (`axonflow_agent_policy_evaluations_total`,
  `axonflow_orchestrator_policy_evaluations_total`) only ever counted how
  many evaluations ran, never how many were structurally unable to run. This
  counter closes that gap for the shared `ConditionEvaluator`
  (`platform/shared/policy/condition_evaluator.go`) and its four callers.
  `reason` is one of six closed constants (`unknown_operator`,
  `empty_conditions`, `non_numeric_operand`, `non_string_pattern`,
  `conditions_unmarshal_failed`, `field_unresolved`) and `plane` identifies
  the caller (`memory`, `database`, `mcp`, `policy_test`) - both are fixed,
  low-cardinality label sets, never a policy ID, tenant ID, field name, or
  operator value. `platform/shared/policy` stays free of any Prometheus
  dependency: the evaluator only ever sees a small `UnevaluableRecorder`
  interface, injected per call, and the real Prometheus counter is wired up
  one layer above, in the orchestrator. The per-caller `OnUnknownOperator`
  logging hook this evaluator used to carry is removed - the evaluator runs
  per request x per policy x per condition, so a single corrupt stored row
  logging unboundedly was the wrong shape; a counted metric is.

> Policy evaluation consolidation (epic #3293, Slice 2, #3296): the agent and
> orchestrator had accumulated multiple independent implementations of the
> same governance primitives - dynamic-condition matching, static-policy
> reads, and override precedence - which had quietly drifted onto divergent
> semantics and produced a real cross-segment enforcement leak (#3266). This
> converges them onto one shared substrate (`platform/shared/policy`) and
> adds the lint that keeps them converged. Core agent/orchestrator code, so
> it ships in both editions from the same binaries.

#### Changed

- **One shared `ConditionEvaluator` replaces five independently-maintained
  dynamic-policy condition matchers** (`DynamicPolicyEngine`,
  `DatabaseDynamicPolicyEngine`, `MCPDynamicPolicyHandler`, and
  `PolicyService.TestPolicy`'s `evaluateCondition` + `evaluateOperator`
  pair) **and converges five behaviors the matchers had drifted onto,
  onto one semantics.** A prior pass unified the five implementations behind
  this type but preserved every difference as a caller-supplied option, so
  it changed no behavior; this pass deletes those options. Each of the five
  is a deliberate, customer-visible change - a stored policy can start or
  stop matching after upgrading - documented as a convergence record (what
  each implementation did, the converged semantics, and which caller changed
  in which direction) in `platform/shared/policy/condition_evaluator.go`:
  - **`contains`/`not_contains` are now case-insensitive on every plane**,
    including MCP/connector/content-type policies, which previously required
    an exact-case match. A blocking policy on this shape now fires on
    additional requests it previously let through.
  - **`contains_any` now matches on a non-string value-list item** (a JSON
    number, bool, or null) on every plane. The database-backed engine
    (all of LLM/MAP/WCP) previously skipped such an item silently, so a
    condition like `contains_any: [0.9, "unrelated-term"]` never matched on
    the `0.9` half; it now does.
  - **`greater_than`/`less_than` false-positive fix.** An operand that is
    neither a number nor a numeric-looking string no longer silently
    compares as `0` - it now makes the condition NOT match. Concretely: a
    non-numeric string field value under a `less_than <positive threshold>`
    condition used to spuriously satisfy a BLOCKING rule; it no longer does.
    Separately (and independently), a numeric-looking string (`"5"`) now
    compares correctly on every plane, including the in-memory engine, which
    previously rejected any numeric string outright and never matched.
  - **A `regex` condition's value must now be a Go string on every plane.**
    The in-memory engine previously accepted any value and stringified it
    before compiling (`value: 1.5` compiled as the pattern `"1.5"`, where
    `.` is a wildcard, not a literal dot); a policy authored that way stops
    matching after upgrading. This is a narrowing - a blocking policy on
    this shape fires LESS than before - and it is paired with an
    authoring-time fix (see below) so the shape cannot be created going
    forward.
  - **Every plane now enforces all 10 policy operators**, closing a standing
    MCP-plane parity gap (#3061): MCP/connector/content-type policies
    previously recognized only 4 of 10 operators (`equals`, `not_equals`,
    `contains`, `regex`), even though the portal has always offered all 10
    and never indicated the other six were inert there. **A policy authored
    with `not_contains`, `contains_any`, `greater_than`, `less_than`, `in`,
    or `not_in` that looked live in the portal but silently never matched on
    the MCP plane begins enforcing there for the first time.** The in-memory
    engine and the policy-test simulator each gain a smaller subset of these
    ten for the same reason.
  - **A policy with zero conditions applies to everything, on every plane -
    restored, not changed.** A condition-less policy vacuously matches: an
    AND-loop with nothing to check has nothing to fail on, the same reason
    an empty `WHERE` clause matches every row. This is, and always was,
    every plane's real behavior except one: the MCP/connector/content-type
    plane carried a deliberate fail-safe (#3061) that made a condition-less
    policy match NOTHING instead, to stop a zero-condition `block` policy
    from denying every governed tool call for a tenant. An earlier revision
    of this same effort converged every plane onto that fail-safe's
    semantics instead of the other way around - making zero conditions
    unmatchable everywhere - and shipped it as convergence 6. **That
    convergence is withdrawn.** Matching unconditionally is not a defect to
    design around; it is what "no conditions" means, and it is what the
    platform's own seed/fallback policies (`DatabaseDynamicPolicyEngine`'s
    in-memory fallback and its three seeded sample rows, which have carried
    no `conditions` key all along) rely on to apply unconditionally. The
    MCP-plane fail-safe is removed too, aligning it with the other three
    planes - this reverses a guard that predates this effort by several
    releases, worth calling out on its own: **a zero-condition `block`
    policy on the MCP plane now matches (and denies) again, where it
    previously did not.** The exposure that guard, and convergence 6 after
    it, existed to prevent - a zero-condition row nobody meant to write,
    carrying a `block` action - is closed at the source instead: creation
    has always rejected zero conditions, update now rejects an
    explicitly-cleared `[]` too (see the `validateUpdateRequest` entry
    below), and a stored `conditions` blob that fails to parse is refused at
    load rather than cached as indistinguishable from a genuinely empty one
    (`cachedPolicyToDynamicPolicy`, `db_dynamic_policies.go`). With every
    path that could produce an accidental zero-condition row closed, the
    only one that can exist at all is a platform-seeded row that means
    exactly what it says.
- **`PolicyService.validateCondition` now rejects a non-string `regex`
  condition value at authoring time** (`"regex pattern must be a string"`),
  closing the gap the regex convergence above narrows: previously a
  non-string regex value silently skipped the compile-time check and could
  be saved as a policy that would go on to never match.
- **`PolicyService.validateUpdateRequest` now rejects an explicitly-provided
  empty `conditions` array** (`PUT` with `"conditions": []`), mirroring the
  error creation has always returned, and stays rejected: the platform may
  seed a condition-less policy meaning "applies to everything," but a
  customer may not author one through the API. Previously this field only
  guarded on `!= nil`, so a JSON `[]` - a non-nil, zero-length slice - passed
  straight through with no error, letting a caller clear a policy down to
  zero conditions while leaving a `block` action attached: exactly the row
  this validation, together with the create-time rejection, exists to keep
  from ever being written by a customer. Omitting `conditions` from the
  request body entirely is unaffected and still means "leave conditions
  unchanged."
- **One shared `EffectiveOverride` resolves policy-override precedence**,
  replacing the second of two independent implementations
  (`PolicyOverrideRepository.GetEffectiveAction` and the inline
  `GetEffective` override map in `static_policy_repository.go`). See the
  Fixed entry below for the precedence bug this closes. A separate,
  unrelated ADR-044 session break-glass override mechanism is untouched -
  `platform/shared/policy/override.go`'s package doc documents why the two
  are not the same feature and must not be conflated.
- **Static-policy evaluation reads converge onto the one shared loader**
  (`platform/shared/policy/loader.go`). The agent's `GetEffective` (backing
  both the Phase-1 shared engine and the tier-aware Phase-2 engine) now reads
  `static_policies` exclusively through `sharedpolicy.ScanEffectivePolicyRows`
  instead of its own parallel query, so the table has exactly one verdict-path
  reader across both evaluation passes - the structural fix behind #3266's
  segment-leak class, generalized past the one field that leaked.
- **The community mirror now carries `scripts/local-dev/`.** `CONTRIBUTING.md`
  has always pointed contributors at `./scripts/local-dev/start.sh`, but the
  sync never copied the directory, so on the mirror that was a dangling
  reference (reported as getaxonflow/axonflow#434). The three scripts are now
  synced. Separately, `CONTRIBUTING.md` referenced
  `scripts/local-dev/test-migrations.sh`, a script that exists on no branch;
  that is replaced with the real local flow (migrations apply on boot, watch
  them in the compose logs), and `start.sh`'s own reference to the same
  nonexistent script is repaired.
- **`/health` recommended client versions advance for the three clients
  released on this train: Go SDK 9.1.0 to 9.1.1, Rust SDK 0.8.1 to 0.8.2, and
  the openclaw plugin 2.8.5 to 2.8.6.** Python, TypeScript and Java stay at
  9.1.0 and every minimum-version floor is unchanged, so a client below a
  recommended version keeps working and only loses the up-to-date advisory.
  Both planes advertise the same values: the plugin map has come from the
  shared `plugincompat` package since #3229, and the SDK maps are still
  per-file literals in the two `capabilities.go` files, so this release adds
  the guard that was missing for them (see CI / Testing below).

#### Fixed

- **Legacy explicitly-empty policy conditions are excluded from evaluation
  (#3384).** Every released create API rejected a policy with zero
  conditions, but the pre-9.19 update API accepted `PUT conditions: []` - so
  a live database can hold rows whose empty conditions list nobody could
  author today. With the #3296 restored vacuous-match semantics those rows
  would have gone from inert to matching every governed MCP call at upgrade
  (a block-action row becoming a tenant-wide denial nobody wrote). A stored
  `[]` is now excluded from every DATABASE-BACKED evaluation surface - the
  engine cache's listing/read path, the `/api/request` enforcement loop,
  and the policy-test preview; the orchestrator's in-memory fallback
  engine, which serves only while the database is unreachable, still loads
  such rows as stored (which now reports the exclusion explicitly instead
  of "matches everything") - and each exclusion is counted under the
  `empty_conditions` label of `axonflow_policy_condition_unevaluable_total`
  (a per-evaluation rate signaling residue is PRESENT, not a row count).
  The CRUD list API and portal still show such rows deliberately:
  remediation needs visibility, and the test endpoint names the fix (give
  the row real conditions, or delete it). A condition-LESS policy (JSON
  `null`, the platform-seeded shape) keeps matching everything, as
  designed. The two shapes are distinguishable at the parse layer by
  construction.
- **A later-created org-level policy override could beat an earlier,
  more specific tenant-level one.** The admin tier-downgrade override path's
  inline precedence resolution (`static_policy_repository.go`'s
  `GetEffective`) ran one query across both scopes ordered by
  `created_at ASC` and let a later row's map-write clobber an earlier one -
  so if an org override was created after a tenant override on the same
  policy, the broader org override silently won, contradicting the intended
  "tenant is more specific, tenant always wins" contract (which the OTHER
  pre-existing override-precedence implementation already enforced
  correctly). `EffectiveOverride` now resolves tenant-beats-org
  unconditionally, independent of creation order, for every caller.
- **A tenant's deliberate policy-disable override could be silently dropped,
  re-enforcing a policy the tenant had turned off; a valid org-level action
  override could be discarded by an unrelated, action-less tenant row.**
  `policy_overrides` carries two independently-nullable columns
  (`action_override`, `enabled_override` - NULL means "no opinion," not
  false), but `EffectiveOverride` resolved them as if a row always changed
  the action: a disable-only row (`action_override` NULL,
  `enabled_override=false`) never registered at all, and any action-less
  tenant row forced scope resolution to "tenant" and then failed to find a
  tenant row whose action matched, discarding a valid org-level action in the
  process. `EffectiveOverride` now resolves `action` and `enabled`
  independently (each tenant-beats-org, then latest-within-scope), so a
  tenant disable and a different org's action downgrade can both be in
  effect on the same policy at once, each attributed to its own row's reason
  and expiry (`OverrideResolution.Contributions`).
- **A silent Free-tier policy-quota bypass is now observable.** The agent's
  bespoke `SELECT COUNT(*) FROM dynamic_policies` behind the Free-tier
  `active_policies` quota is replaced by `PolicyLoader.CountActive`
  (in-process call, same RLS scoping) and kept fail-open on a count error
  exactly as before - a transient DB blip must not block a legitimate Free
  user - but a failure now increments the new
  `axonflow_active_policy_count_errors_total` metric. Previously a
  systematically failing count (e.g. an RLS-blind read on a
  mis-provisioned deployment) fell back to `0` with nothing to alert on, so
  the quota could be silently unenforced indefinitely.

#### CI / Testing

- **The community mirror carries the policy-table choke-point lint it
  runs.** The lint's workflow step reached the mirror one sync before the
  script it invokes did, failing mirror CI with exit 127; the sync now
  includes the script. The seeded-policy shadow census, which walks the
  enterprise-only policy-pack tree, moved behind the enterprise build tag
  so mirror CI never references trees the mirror does not carry.

- **New lint: no evaluator may read `static_policies` or `dynamic_policies`
  directly outside the shared substrate**
  (`scripts/lint-policy-table-choke-point.sh`, wired into the `lint`
  workflow). Guards the invariant this release converges onto: every verdict
  path goes through `platform/shared/policy/loader.go`, so the next feature
  cannot silently add a sixth bespoke reader and reopen #3266's drift.
  Legitimate CRUD/admin/metadata/probe reads are allow-listed by file AND
  exact expected occurrence count, so adding - or silently removing - a query
  in an already-allow-listed file fails the lint until the count is
  consciously updated in a reviewed diff. `platform/shared/policy/loader.go`
  - the sanctioned choke point itself - now carries the same exact-count
  ratchet as every other entry instead of being exempt by file identity: it
  held 5 occurrences when the lint was written and holds 7 today, and an
  identity exemption meant the single most-privileged file in the tree was
  the only one a new query could be added to with zero CI signal.
- **`evaluator-convergence-e2e.yml`'s path trigger now includes
  `platform/shared/policy/loader.go`.** The suite exercises override
  precedence (Leg 4), which resolves the `static_policies` rows it operates
  over through `loader.go`'s `ScanEffectivePolicyRows` - a change there could
  change what the suite observes without triggering it.
- **New guard: the agent and orchestrator SDK compatibility maps must be
  identical.** Both planes serve `/health` from their own copy of the SDK
  min/recommended maps, and the release-prep runbook lists agent-vs-orchestrator
  drift as a real, previously-observed failure mode. Nothing enforced it: the
  orchestrator carried a literal pin test while the agent side only asserted
  its maps were non-empty, so a bump applied to one file and not the other
  made the two ports answer differently with zero CI signal, and the check
  lived only in a human's checklist. `TestSDKCompatibilityMapsMatchOrchestrator`
  compares the two source literals directly and fails on a drift introduced in
  either file. The PLUGIN maps need no such guard: both planes have read them
  from `platform/shared/plugincompat` since #3229, which closes that half
  structurally.
- **The Enterprise-Tagged + Real-PG job reclaims runner disk before it runs.**
  This train's real-Postgres growth pushed `ubuntu-latest` past its
  free-space floor, and the job went red on main for three consecutive runs
  with testcontainers failures that read as three unrelated test bugs (`no
  space left on device`, `database system is in recovery mode`, containers
  exiting at startup) rather than as one environment problem. The job now
  drops the preinstalled toolchains it never uses (about 25 GB of dotnet,
  Android, GHC and CodeQL) and prunes stale images before anything else runs,
  and prints `df` before and after, so a recurrence of this class is visible
  in the log instead of inferred from downstream failures.

### Enterprise

#### Added

- **Cowork / Claude Code storage-plane audit rows carry policy display names**
  (the Enterprise half of #3365). The redact-at-collector path threads the
  evaluation-time names from the same matches its ids come from, and guard
  ids resolve through the same compiled-in table the decide and MCP planes
  use, so this plane's rows render names in the portal and in the OJK / BI /
  UU-PDP exports on the same terms as every other plane.

#### Changed

- Removed the dead `masfeat.KillSwitchService.CheckAndTrigger` (MAS FEAT
  auto-trigger-on-threshold), which had no live caller.

#### Fixed

- **Blocked audit rows showed raw policy ids, or a blank, where step-up rows
  showed names (#3347).** In the portal audit view the Policy column silently
  fell back to joined ids while the expanded row's "Policy name" field
  rendered an empty dash, so a decide-plane block (which stamped ids and no
  names before #3365 above) displayed as an id in one place and as nothing in
  the other. One shared resolver (`resolvePolicyIdentityDisplay`) now feeds
  every audit surface that shows a policy identity: a stamped name renders as
  a name; a row carrying no stamped name renders its ids with an explicit
  `(name not recorded)` marker instead of a silent blank or an id styled as a
  name; versions render as `id (vN)`. A name is never invented from a
  catalog lookup, and the id and name arrays are never zipped positionally,
  because they are not index-parallel on merged rows.
- **The audit page could show a 0.0% block rate above visible blocked rows,
  and could hide or leak end-date rows depending on the viewer's timezone
  (#3363).** Two separate defects on one page. First, the Compliance Summary
  tiles were fetched on page load and date change only, while the table
  refetched on every filter change, so tiles could sit at their page-load
  values while the rows beneath them changed: blocked rows on screen under a
  0.0% block rate, on a compliance surface. The summary now refetches
  whenever the table does, and dims rather than skeletons while it does, so
  pagination cannot reopen the same staleness. Its window stays dates-only,
  so the caption's "not narrowed by the user, action, or tenant filters"
  claim stays true. Second, timestamps render in local time but the range was
  computed as a UTC day: west of UTC an evening row on the end date fell
  outside the window in both the list and the summary, east of UTC rows
  stamped with the next day's local date leaked in, the end date's final
  999 ms were always dropped, and the default range itself was derived from
  the UTC date. One shared helper
  (`ee/platform/customer-portal-ui/lib/dateRange.ts`) now converts a picked
  date to a local start-of-day through local end-of-day window for every
  consumer, and the same UTC-today class was swept out of the compliance,
  usage, export, policies and evidence-export surfaces. Deep-link
  `start`/`end`/`action` parameters are validated at init.
- **The policies page's filters, pagination totals and summary tiles could
  each disagree with the others and with the platform (#3361).** The portal
  aggregator forwarded `tier`, `category` and `enabled` to both upstreams and
  trusted each to filter, but the agent's `/static-policies/effective`
  honours none of them: the dynamic half filtered while static rows rendered
  regardless, and the tiles were computed from pre-filter slices. Rows,
  pagination totals and tiles now derive from one filtered collection through
  one authoritative predicate. Converging that surfaced nine further defects
  in the same aggregator, all fixed here: the Enabled tile counted raw
  `enabled` while the badges counted `effective_enabled`; the Type dropdown
  was a no-op end to end (`policy_type` was sent and only `type` was read);
  `/unified-policies/effective` returned a permanently empty static half as
  clean non-partial truth, because a second decoder read a `policies` key the
  agent never emits; `GET /unified-policies/{id}` returned a 200 carrying an
  all-zero policy for every dynamic id, by decoding the orchestrator's
  wrapped `{"policy":{...}}` flat, and the write dispatcher then resolved on
  it; a `page_size` of 1000 is rejected by the orchestrator, which silently
  truncated the dynamic half to its default 20 rows; `?enabled=TRUE` filtered
  the dynamic half to *disabled* rows while static stayed unfiltered; and an
  override's `created_at` was fabricated as the fetch time, so every override
  reported "created just now". In each decoder case a unit-test mock served
  the wrong shape and certified the bug; the mocks are corrected. The parity
  contract this converges onto is written down as
  `technical-docs/PORTAL_PARITY_CENSUS.md`, which classifies every
  summary/list/detail/export pair in the portal and is now referenced by the
  pull-request template.
- **Decide-plane (agent HITL) approvals never appeared in the portal Approvals
  page (#3346).** The page read the workflow-step queue only, so a decide-plane
  step-up (for example a fraud-and-risk `needs_approval` verdict routing an
  above-threshold score into the agent HITL queue) created a pending approval
  that rendered nowhere in the portal: an operator watched an empty queue
  while oversight work sat waiting, and had to drive the agent HITL API
  directly to see or act on it. The Approvals page now renders both planes as
  ONE merged list with plane badges, plane-routed approve and reject actions
  and per-plane detail panels, and the sidebar badge counts the same merged
  fetch. Expired-but-unswept rows are marked and their actions disabled
  rather than failing on click, and a plane that cannot be reached is named
  in the banner instead of being silently counted as empty. Enforcement is
  unchanged and stays on the agent: the new portal proxy is list, approve and
  reject only, rebuilds its upstream query with `status` pinned to `pending`,
  and cannot pass browser-supplied identity headers through. Reviewer
  attribution on the decide plane records the internal-service credential
  unless `AXONFLOW_TRUST_IDENTITY_HEADERS` is set, which is the agent's
  existing by-id binding contract, not a change made here.
- **A newly-created MAS FEAT kill switch no longer defaults
  `auto_trigger_enabled` to `true`.** MAS FEAT ships a manual-only kill
  switch - every trigger is an explicit, human-initiated API call - but
  `GetOrCreateKillSwitch` defaulted this field to `true`, asserting an
  automatic-disable behavior the system does not implement. The evaluator
  that would have read it and the thresholds alongside it
  (`KillSwitchService.CheckAndTrigger`) had no production caller and was
  already removed as dead code; the default now matches that reality
  (`false`). The threshold columns and `auto_trigger_enabled` itself remain
  on the schema, the Go types, and the Configure API for wire/persisted
  compatibility - they are currently inert, not removed.

### Migration

- **No schema migrations.** `git diff v9.18.0..origin/main -- migrations/` is
  empty, so the migration runner applies nothing new on upgrade and the
  deploy delta from v9.18.0 is images only.
- **Behavior change with no schema change: stored policies whose `conditions`
  column holds an explicitly-empty array stop being evaluated (#3384).** No
  released create API ever accepted a zero-condition policy, but the pre-9.19
  update API accepted `PUT` with `"conditions": []`, so a live database can
  hold rows nobody could author today. With this release's restored
  vacuous-match semantics those rows would have gone from inert to matching
  every governed request at upgrade, turning a `block`-action row into a
  tenant-wide denial nobody wrote. They are now excluded from every
  evaluation surface instead. Such a row remains visible in the CRUD list API
  and the portal on purpose, because remediation needs visibility, and the
  policy-test endpoint reports the exclusion explicitly and names the fix
  (give the row real conditions, or delete it). A condition-LESS policy (JSON
  `null`, the platform-seeded shape) is a different shape and still applies
  to everything, as designed.
  - Operators can enumerate the affected rows before or after upgrading:

    ```sql
    SELECT policy_id, tenant_id, action, enabled
    FROM dynamic_policies
    WHERE jsonb_typeof(conditions) = 'array'
      AND jsonb_array_length(conditions) = 0;
    ```

  - Post-upgrade, residue is also visible as a rate rather than a row count:
    every exclusion increments
    `axonflow_policy_condition_unevaluable_total{reason="empty_conditions"}`.
    A non-zero rate means at least one such row is being skipped on a live
    evaluation path; the query above identifies which.
- **Upgrading from a release older than v9.19.0 also carries the
  condition-matcher convergence** described in the Community section: five
  named behaviors change, and a stored policy can start or stop matching. The
  convergence record (what each implementation did, the converged semantics,
  and which caller moved in which direction) is kept beside the code in
  `platform/shared/policy/condition_evaluator.go`.

<!--
  Version decision (Step 0): v9.18.0, MINOR. The train's headline is the
  Fraud & Risk Add-on (ADR-061): Engine A (FinCrime Policy Pack + context
  schema + evaluator seam + scorer client, #3335) and Engine B (the
  axonflow-risk-scorer training pipeline + scoring service, #3337). Both are
  additive and default-inert: the seam no-ops unless the Enterprise pack is
  seeded and the scorer is explicitly configured, and the community build
  compiles a nil-engine stub. The ops fixes (#3336, #3338, #3339, #3340,
  #3342, #3343) remove no capability, add no required credential and add no
  refusal. MINOR by the 2026-07-30 semver policy. No migrations.
-->

## [9.18.0] - 2026-08-19 (Fraud & Risk Add-on: FinCrime policy pack + ML risk scoring; alarm and deploy fixes)

> Scope: first release of the Fraud & Risk Add-on (Enterprise add-on,
> ADR-061) - deterministic financial-crime policy evaluation on the decide and
> MCP planes plus an optional self-hosted ML risk scorer - and a set of
> CloudFormation alarm/permission fixes on the marketplace template. No
> migrations this train.

### Security

- **The indirect `github.com/moby/go-archive` dependency is bumped to 0.3.0**
  (CVE-2026-17106, crafted tar archive can write outside the extraction
  directory) *(Community: the platform Go module; Enterprise: also the
  customer-portal and ee modules)*. The dependency enters the module graph
  through the test-container tooling, not shipped request paths, so no
  runtime behavior changes in either edition; the bump changes a
  deployment's `go.mod`/`go.sum` and keeps its vulnerability-scan posture
  honest and green. `go mod tidy` also lifts `moby/sys/sequential` to 0.7.0
  and `moby/sys/user` to 0.4.1 as the 0.3.0 requirement set.

### Community

_No functional changes._ Released in lockstep with the Enterprise edition at
v9.18.0. Unlike v9.16.0's lockstep note, the community `agent` binary is NOT
byte-identical to v9.17.0: the Fraud & Risk Add-on's seam files
(`platform/agent/fincrime` and its call sites) compile into both editions, but
on a community build the engine constructor returns nil and the seam is a
strict no-op - every request proceeds bit-identically to a build that never
heard of the add-on. The new FinCrime policy category is only ever evaluated
where the Enterprise policy pack was seeded (community deployments have no
seeder for it), and the community HITL stub continues to reject approval-queue
operations by tier. The community `orchestrator` is unchanged. The version is
cut so the two editions never diverge in version number.

### Enterprise

#### Added

- **Fraud & Risk Add-on Engine A: FinCrime Policy Pack, transaction context
  schema, and evaluator seam** *(Enterprise add-on)* (#3335, ADR-061). A new
  `platform/agent/fincrime` package adds typed extraction and validation of
  the documented `fincrime_transaction` / `fincrime_cohort` context objects,
  a pluggable evaluator seam consulted from the shared input-policy path
  AFTER the static engine, and the Engine B scorer client. The FinCrime
  Policy Pack v1 ships 10 seeded static policies under a dedicated
  `fincrime` category (structuring bands, sanctioned-corridor geography with
  alpha-2/alpha-3/subdivision forms, amount caps, velocity and exposure
  step-ups over caller-supplied cohort aggregates) plus one code-backed
  protocol-integrity policy, each row carrying public-source provenance
  (FATF / OFAC / FFIEC / OWASP). Pattern evaluation is identical on the
  decide and MCP planes because pack patterns bind to the canonical
  serialization both planes scan; outcomes differ by plane by design. The
  seam never denies: on the decide plane it can escalate an allow to
  `needs_approval`, and that verdict always creates a reviewable HITL queue
  entry; on the MCP planes the seam changes no verdict, and an
  above-threshold score or step-up row is recorded as a non-blocking
  attributed detection on the audit row (the request proceeds). A deny, on
  any plane, can only come from blocking static rows through the ordinary
  policy engine - the pack's own, or any other policy matching the scanned
  context, since opted-in fincrime context is subject to the full static
  category scan (PII, injection detection) like any other input. Audit rows for scored or flagged decisions carry
  the fincrime policy ids/names/versions, the `risk_score`, and an
  `ml_inference_layer_status` stamp on every plane.
  Inert unless the pack is seeded; consulted only on planes that install
  its decision metadata (decide + MCP query/execute/check-input at MVP).
- **Fraud & Risk Add-on Engine B: self-hosted ML risk scorer**
  *(Enterprise add-on)* (#3337, ADR-061). A new `axonflow-risk-scorer`
  service (own container image, own CI) scores `fincrime_transaction`
  context on the frozen `POST /v1/score` contract: HMAC service
  authentication only (the community fallback token is rejected,
  authentication is decided before request-shape validation), a
  train/serve-identical feature transform, and per-feature contributions in
  every response. The training pipeline ships with the service: train-only
  encoders (pre-split encoding is reproduced and measured as leakage, not
  assumed), chronological and random splits, validation-only selection, an
  order-statistic review-rate threshold, and a reproducible bundle format
  that hard-rejects older bundle versions; the model bundle is mounted at
  deploy time, never baked into the image. The agent-side client enforces a
  hard per-request budget via context cancellation (default 100ms,
  configurable through `AXONFLOW_FINCRIME_SCORER_TIMEOUT_MS`) and the
  scorer is advisory-only: scorer unavailability means the decision
  proceeds and the audit row records the `unavailable` inference status,
  never a block.
  Disabled by default: the enterprise compose templates the scorer
  environment with disabled defaults, and the agent's scoring layer refuses
  to construct without a valid internal service secret.

#### Fixed

- **ECS alarm coverage: agent outage alarm added, and task-count alarms
  fixed to watch a metric that exists** *(marketplace template +
  AxonFlow-operated SaaS)* (#3336). Two defects of one class, an alarm whose
  name promises coverage its metric cannot deliver, in opposite directions.
  On the marketplace template, a total agent outage was invisible: the
  unhealthy-host alarm counts registered targets failing health checks, and
  a service at zero tasks has no targets to count, so it read healthy; the
  template now gains an `AgentTaskCountAlarm` on
  `ECS/ContainerInsights RunningTaskCount`, mirroring the orchestrator's
  existing one. On the AxonFlow-operated community-SaaS sibling stack (never
  shipped to customers), both task-count alarms were defined on
  `AWS/ECS RunningCount`, a metric that namespace does not publish, so with
  `TreatMissingData: breaching` they sat permanently in ALARM while the
  services were healthy; both now watch the Container Insights metric. A
  regression test pins the class: no ECS alarm may name a metric its
  namespace does not publish, and every service deployment must carry
  task-count coverage. `TreatMissingData: breaching` is kept deliberately - Container
  Insights being disabled must page rather than silently resolve to OK.
- **The marketplace ECS task role could not read the SAML SP keypair**
  *(Enterprise)* (#3338). The customer-portal SAML service loads
  `axonflow/saml/sp-keypair` from Secrets Manager through the TASK role at
  runtime, but the marketplace template's task role shipped with no
  `secretsmanager` permissions, so the load always failed and the service
  fell back to generating a temporary keypair - SAML appeared to work while
  the SP signing certificate changed on every portal restart, silently
  breaking any IdP that had registered it. The template now grants
  `GetSecretValue` scoped to that one secret name (the suffix pattern
  matches only Secrets Manager's 6-char ARN suffix, not sibling secret
  names). The silent-fallback behaviour itself is unchanged this train (a
  new refusal is a semver MAJOR); making it fail loud is tracked separately.
- **The telemetry salt staleness alarm was in ALARM 362 days a year by
  construction** *(AxonFlow-operated infrastructure)* (#3343). The rotation
  age metric was published exactly once per annual rotation while the alarm
  treated a single missing day as breaching, so the alarm fired on emission
  cadence, not staleness. A daily heartbeat now publishes the rotation age
  computed from the secret's last-changed date, with the rotate job gated to
  the annual cron alone so the shared workflow's new daily cron can never
  trigger a rotation.

#### Internal

- prod-us now sends real forgot-password email: the environment config gains
  the Resend key + from-address secrets wiring, and `update-stack.yml`
  plumbs `FromEmailAddress` (#3339) and `PortalExternalBaseURL` (#3342)
  through both the preview and apply jobs - the CloudFormation rule group
  requires all three parameters together, and the first rollout proved it by
  rolling back cleanly at parameter validation when only two were plumbed.
- The daily ephemeral-stack reaper gained a second pass that removes what
  stack deletion deliberately retains (final RDS snapshots, ALB-log buckets,
  log groups) for throwaway benchmark stacks only, via a pure name-filter
  script self-tested against 25 decoy cases before every use; an artifact is
  approved only when its name embeds a full ephemeral-stack name AND that
  stack no longer exists in any non-deleted CloudFormation status (#3340).

### Migration

- **No migrations this train.** No schema changes, no boot-requirement
  changes, no mode-selector changes. The Fraud & Risk Add-on is opt-in
  configuration: the FinCrime pack activates only where its Enterprise
  policy-pack seed is applied, and the risk scorer only when its service is
  deployed and the agent's scorer environment (endpoint + internal service
  secret) is explicitly configured. A deployment that changes nothing
  behaves identically to v9.17.0.

## [9.17.0] - 2026-08-12 (self-service password recovery; forgot-password security hardening; segment-scoped policy targeting)

### Migration

- **One additive migration: `core/159`.** It adds a nullable `segment_id` column to `dynamic_policies` plus a partial index, using `ADD COLUMN IF NOT EXISTS` and `CREATE INDEX IF NOT EXISTS`, so it is idempotent and safe to re-run. No data is rewritten and no existing row changes meaning: a policy with `segment_id IS NULL` is unaffected by segment targeting and continues to match exactly as it did before. Nothing writes a non-NULL `segment_id` unless an operator authors a segment-scoped policy, so the column is inert until then, and inert in Community entirely (there is no segment resolver on that edition).
- **Reset links issued before the upgrade stop working.** `password_reset_tokens.token` now stores a hash rather than the raw token, so any password-reset link already in flight when you upgrade must be requested again. This affects only links that were outstanding at upgrade time.

### Community

#### Added

- **Segment gating extended to the remaining agent policy planes** (#2989, #3051, ADR-060). v9.14.0 introduced segment-scoped static policies on `/api/request` (migration `core/157`) and explicitly left the MCP-server fleet, gateway and OpenAI-compatible planes out of scope. Those planes now apply the same gate through the shared policy engine, so a segment-scoped policy is honoured consistently wherever a caller's identity is validated, instead of only on the request plane. Strictly additive as before: policies with `segment_id IS NULL` behave exactly as they always have, and no policy decision changes anywhere until a segment-scoped policy exists.

### Enterprise

#### Added

- **Segment-scoped DYNAMIC policies on the orchestrator** (#3052, ADR-060). v9.14.0 brought segment targeting to STATIC policies only and named the dynamic policy engine as deliberately not yet segment-aware; that gap closes here. A dynamic policy may now target a governance segment resolved from the caller's SCIM group membership, so a rule can apply to one population rather than the whole tenant. The scoping is additive: a policy with no `segment_id` keeps matching every caller in its tenant exactly as before, and segment targeting only takes effect once an operator authors a scoped policy. Requires the `core/159` column (see Migration above).
- **Customer-portal forgot-password now sends real reset emails** (#2330,
  closing the #2324/#2287 follow-up). When `RESEND_API_KEY` and
  `AXONFLOW_FROM_EMAIL` are both configured, `POST /api/v1/auth/forgot-password`
  on a production portal emails the org's contact address a reset link
  (1-hour expiry, one active token per org) instead of returning 501. The
  response is the generic 200 for existing and non-existing orgs alike, and
  the lookup/token/send work runs off the request path so neither the body
  nor the latency reveals whether an org exists. Reset links resolve from
  `SSO_BASE_URL` (the same base as SAML ACS / OIDC redirect URLs), never a
  hardcoded host. Config surface: compose passthrough
  (`RESEND_API_KEY`, `AXONFLOW_FROM_EMAIL`, `SSO_BASE_URL`) and additive,
  default-empty CloudFormation parameters (`ResendAPIKeySecretArn`,
  `FromEmailAddress`, `PortalExternalBaseURL`) on the customer-portal task
  definition.
- **Portal UI password recovery pages**: a "Forgot password?" link on login,
  `/forgot-password` (always shows the generic confirmation; shows an honest
  "not configured" notice on 501) and `/reset-password` (consumes the emailed
  token; clear errors for expired/used links).
- **Password-reset email can now be sent through your own SMTP relay** (#3311).
  Resend is an HTTPS SaaS: a self-hosted or in-VPC deployment would have to
  sign up for a third-party vendor and verify a sending domain there, which a
  regulated customer generally cannot do, so the recovery flow was true only
  for AxonFlow-hosted portals. Set `AXONFLOW_SMTP_HOST` and
  `AXONFLOW_SMTP_PORT` (plus the same `AXONFLOW_FROM_EMAIL` and portal base
  URL the Resend path needs) and reset mail goes through the relay you already
  run, staying inside your own infrastructure. Optional
  `AXONFLOW_SMTP_USERNAME` / `AXONFLOW_SMTP_PASSWORD`, `AXONFLOW_SMTP_TLS`
  (`starttls` default, `tls` implicit, `none`) and `AXONFLOW_SMTP_CA_FILE` for
  a relay with a private CA. Standard library only, no new dependency.
  Additive default-empty compose passthroughs and CloudFormation parameters
  (`SMTPHost`, `SMTPPort`, `SMTPUsername`, `SMTPPasswordSecretArn`,
  `SMTPTLSMode`); a stack that sets none of them renders exactly the task
  definition it rendered before. **Precedence: `RESEND_API_KEY` wins if both
  transports are configured**, logged loudly at boot, and the CloudFormation
  template rejects setting both outright. The selected transport is now named
  at startup.
- **New `AXONFLOW_PORTAL_BASE_URL`, replacing `SSO_BASE_URL` in the docs**
  (#3311). One value builds the emailed reset link *and* the SAML ACS / OIDC
  redirect URLs, but naming it for SSO led deployments that use password login
  and no SSO to skip it, after which reset mail refused to start or pointed at
  the wrong host. `SSO_BASE_URL` keeps working as a deprecated alias, logged
  once at startup; the new name wins whenever it carries a usable value.
  **No breaking change**: existing deployments are unaffected (a compose
  `${VAR:-}` passthrough yields the empty string, which reads as unconfigured),
  and the CloudFormation template renders both names from the single
  `PortalExternalBaseURL` parameter so a stack update that lands before an
  image update cannot strip the value. Both names are normalized by the one
  shared normalizer *before* precedence is decided, so a value that normalizes
  to nothing (`/`, `//`, whitespace) can never shadow a working value under the
  other name - that ordering is what keeps the rename from re-opening #3289 on
  the SAML/OIDC plane, where an unresolved base URL falls back to the AxonFlow
  SaaS host.

#### Security

- **`POST /api/v1/auth/forgot-password` no longer returns a reset token in the
  response body on `ENVIRONMENT=staging`.** A staging stack is a deployed,
  reachable service (the marketplace CloudFormation template defaults
  `EnvironmentType` to `staging`), and on that branch the endpoint handed a
  live, password-changing token for ANY organization to ANY anonymous caller -
  including organizations with no contact email at all, since the pre-fix path
  minted and returned the token before it ever considered where to send it.
  The token-in-body path is now limited to a developer machine
  (`ENVIRONMENT` unset / `development` / `dev` / `local`) with no email
  backend; every deployed environment returns the honest 501 or, once email
  is configured, sends the link. Operators who relied on staging token-in-body
  for scripted testing should use `development` or the admin reset endpoint.
- **The marketplace CloudFormation template now defaults `EnvironmentType` to
  `production`** (was `staging`). That default is what made the disclosure
  above reachable on a stock deployment, and a non-production posture is the
  wrong default for a template whose primary use is a real deployment. It also
  means a new default-parameter stack requires `X-Admin-API-Key` on
  `/api/v1/admin/*` (with `DEPLOYMENT_MODE=saas`); the template already
  provisions and injects that key, so nothing further is needed.
  **New stacks only** - CloudFormation stores a stack's resolved parameter
  values, so an existing stack keeps `staging` across updates until an
  operator sets the parameter explicitly, which they should. `AllowedValues`
  is unchanged, so stacks still holding `staging` keep updating cleanly.
- **Reset tokens are hashed at rest.** `password_reset_tokens.token` now
  stores a SHA-256 digest instead of the token itself, so read access to that
  table is no longer equivalent to organization takeover. No migration: the
  column is unchanged. Reset links issued before the upgrade stop working
  (request a new one; links live at most 1 hour).
- `POST /api/v1/auth/forgot-password` now has its own per-IP rate limiter
  (same 5/min posture as login), closing an email-bomb / probing vector that
  a real email backend would otherwise open (#2330).
- **The rate limiter's bucket key is no longer attacker-controlled behind a
  trusted front proxy.** It used the entire `X-Forwarded-For` header, so
  rotating a forged prefix put every request in a fresh bucket and the limiter
  never fired; it now keys on the rightmost hop, the address an ALB (or nginx
  with `proxy_add_x_forwarded_for`) actually observed. This restores the login
  endpoint's documented 5-attempts-per-minute limit. Where the portal is
  directly reachable the header remains unverifiable however it is parsed;
  the new `AXONFLOW_TRUST_PROXY_HOPS` setting below makes that trust explicit
  (#3309).
- **New `AXONFLOW_TRUST_PROXY_HOPS` setting for deployments behind more than
  one proxy.** The rate-limit bucket key is the Nth `X-Forwarded-For` entry
  counting from the right, where N is this value. **The default is 1, which is
  exactly the behaviour that ships without it**, so no deployment changes by
  upgrading and the setting can be adopted at any time. Set it to the number of
  trusted proxy layers when the portal sits behind e.g. Cloudflare in front of
  your own nginx; otherwise every user shares one 5/min login bucket and five
  failed sign-ins lock out the whole organization. Set it no higher than the
  real number of proxies: a larger value counts on client-supplied text. The
  resolved posture is logged once at startup. Exposed as the default-empty
  `TrustedProxyHops` CloudFormation parameter and a compose passthrough.
- **New per-organization re-issue cooldown on password reset.** Both limiters
  key on IP, but `org_id` is the portal login username, not a secret, so an
  attacker rotating source addresses could email-bomb any organization's
  contact address and continuously replace its reset token - killing a
  legitimate user's just-delivered link before they could click it, a targeted
  lockout of the recovery path. While an unused, unexpired token issued in the
  last 5 minutes exists, a repeat request is suppressed: no new token, no
  email, the same generic 200, and the link already in the inbox keeps
  working. A used or expired token never blocks a new request.
- Sender selection is fail-closed: no key keeps the honest 501 exactly as
  before; a key without a from-address, or without `SSO_BASE_URL` in ANY
  deployment mode, logs the misconfiguration and stays on 501 rather than
  mailing every customer a link pointing at the SaaS host. A deployment can
  never claim "link sent" without sending.
#### Fixed

- The customer-portal built its SAML and OIDC services from its own direct
  read of `SSO_BASE_URL` rather than the shared resolver used by the
  reset-link builder (#3311). With the alias above that would have meant an
  operator setting only `AXONFLOW_PORTAL_BASE_URL` got correct reset links and
  SAML assertions addressed to the AxonFlow SaaS host, which is #3289 again.
  Both now resolve through the single resolver.

<!--
  Version decision (Step 0): v9.16.1, PATCH. A partner-facing bug fix (the
  compliance exports' blank Policy column) plus additive audit-row keys and an
  additive placeholder/version rendering. No new capability surface, no removed
  fallback, no new required credential, no new refusal - PATCH by the
  2026-07-30 semver policy.
-->

## [9.16.1] - 2026-08-10 (compliance exports: policy attribution across all audit planes)

> Scope: the OJK / BI / UU-PDP, SEBI and EU AI Act export planes, the cowork OTEL
> ingest, the MCP check-input audit writer, and the `/api/v1/decide`
> circuit-breaker deny. Found by a design partner on v9.16.0: the OJK report's
> Policy column was blank for every row.

### Enterprise

#### Fixed

- **Compliance exports resolve policy identity from EVERY audit writer's shape** *(Enterprise)* - the OJK/BI/UU-PDP, SEBI and EU AI Act exporters read only `policy_details->'policy_ids'->>0`, but the audit planes never converged on that key: the MCP check-input writer records `policy_names` + `policy_matches` (+ `policy_versions`), HITL records the singular `policy_id`/`policy_name`, legacy rows carry `policy_names` as a CSV **string**, and cowork OTEL rows recorded nothing at all - so those planes' rows rendered a blank Policy cell on regulator artifacts. All three exporters now resolve through one shared fallback chain (`policy_ids[0]` -> `policy_matches[0].policy_id` -> `policy_names` in either shape -> `policy_id` -> `policy_name`), defined once in `platform/shared/audit` and pinned by a cross-plane writer/reader contract test per writer, so a new writer key the exporters cannot read fails CI. **This part is RETROACTIVE: historical MCP check-input rows (the partner's case) fill in with the real policy id AND recorded version (`id (vN)`) on re-export, with no data migration.** (#3243 follow-up)
- **Cowork / Claude Code OTEL rows now capture what fired** *(Enterprise, FORWARD-ONLY)* - when the ingest's storage redactor masks content, the row now records `policy_ids` (the engine's matched `sys_pii_*` ids and/or `indonesia_pii_protection` from the checksum masker - never an evaluated-but-unmatched policy), `policy_categories`, `ruleset_version` (the platform version whose redaction ruleset produced the match), and a `reason` (`"PII redaction: <categories>"`), so the export's Policy AND Description columns populate. The same ids now flow into the signed decision chain instead of `nil`, so `decision_chain` and `audit_logs` agree. A pure telemetry observation row still records no policy identity - attribution on a no-match row would be mis-attribution. Rows ingested before 9.16.1 cannot be attributed and are not backfilled (see the placeholder below); their recorded `redacted_fields` do surface in the export Description.
- **Rows with no recorded identity render an honest placeholder, never a blank cell** *(Enterprise)* - an ACTED row (blocked / redacted / needs_approval) with no identity under any writer key now renders the single shared `Not recorded (pre-9.16.1)` placeholder across all regulator exporters. No attribution is inferred or backfilled, and rows that did not act get no placeholder (a "not recorded" on an observation row would imply a policy fired). Recorded policy versions are surfaced next to the identity (`id (vN)`) on OJK/SEBI/EUAIACT artifacts; a version never renders beside an empty identity or the placeholder.
- **Acted rows where NO platform policy fired state that affirmatively** *(Enterprise-facing render; writers in both editions)* - a cowork/Claude Code user rejecting a tool call and a HITL gate configured with no policy identity now record a `policy_attribution` marker, and the exporters render the honest labels `None (user decision)` / `Workflow step gate (policy not named)` for them. Without this, freshly-written no-policy rows would have rendered the `(pre-9.16.1)` placeholder: a false era claim and an implied policy (caught in R3 review of this release).
- **`/api/v1/decide` circuit-breaker denies are attributed** *(also in Community, see below)*.

#### Tests

- The `3243_compliance_reports_portal` runtime-e2e now asserts **Policy-column completeness** on a real OJK export: events seeded through the live cowork OTLP ingest and `/api/v1/decide` planes must render attributed cells, a planted pre-9.16.1 check-input-shaped row must heal to `id (vN)` with no new-format write, and no-identity rows must render the shared placeholder - the structural guard the 9.16.0 verification lacked.

### Community

#### Fixed

- **MCP check-input block rows now also record `policy_ids`** - `writeExplainableAuditLog` recorded identity only as `policy_names`/`policy_matches`; it now additionally writes `policy_ids` (additive; `policy_names`/`policy_matches`/`policy_versions` are unchanged for the portal feed and explain endpoint). Forward-only on the write side.
- **`/api/v1/decide` circuit-breaker denies now carry `policy_ids: ["circuit_breaker"]`** - previously the one decide deny path with no attribution (the kill-switch and PII denies were already attributed). Forward-only.
- **The portal decisions feed's policy label resolves every writer key shape** - `GET /api/v1/decisions` read only `policy_id`/`policy_ids[0]`, so MCP check-input rows listed with no policy label; it now uses the same shared fallback chain (retroactive on read, like the exporters). The id-keyed policy *filter* is unchanged.
- The shared policy-identity extraction helper (`platform/shared/audit`) compiles in community builds but has no community read surface - the compliance exporters that consume it are Enterprise-only, so the blank-Policy fix itself is Enterprise-facing.

<!--
  Version decision (Step 0): v9.16.0, MINOR. Adds a new backward-compatible
  capability (interactive OIDC portal login) alongside the existing SAML login,
  plus SSRF-hardening of OIDC endpoint fetches. It also introduces a new opt-in
  env var (AXONFLOW_OIDC_ALLOW_PRIVATE) that internal-IdP deployments MUST set to
  keep private-address IdP fetches working - a required config for those
  deployments, but not a removed capability or a new refusal for anyone else, so
  MINOR by the 2026-07-30 semver policy.
-->

## [9.16.0] - 2026-08-08 (interactive OIDC portal login; OIDC endpoint SSRF hardening)

> **The two editions ship in lockstep at every version.** All v9.16.0 changes are in the **Enterprise** edition (below). The **Community** edition has no functional change from v9.15.0 - its agent and orchestrator binaries are byte-identical - and is released at v9.16.0 so the two editions never diverge in version number. See the Community section below.

### Enterprise

#### Added

- **Interactive OIDC portal login** *(Enterprise)* - the portal now supports a full browser OIDC authorization-code login (`/auth/oidc/{tenant}/login` + `/callback`), alongside SAML. It discovers the authorize/token endpoints from the configured issuer, redirects with the tenant `client_id` and an `SSO_BASE_URL`-derived `redirect_uri` (scopes `openid email profile`), then on callback validates a signed HMAC `state` (CSRF) + `nonce` (replay), exchanges the code via `client_secret_basic`, verifies the `id_token` signature against the JWKS (RS256, issuer, audience==client_id, expiry, `azp` for multi-audience id_tokens), and mints the session into `user_sessions` (the store `portal_session_lookup()` reads). Role auto-provisioning is best-effort and never blocks login. Migration **core/158** adds `oidc_client_id` + `oidc_client_secret` to `sso_configurations`; the client secret is stored with the SAME at-rest posture as `sp_private_key` (a dedicated column under the same FORCE-RLS org isolation, `json:"-"` in the app, masked in every response, never logged, never placed in an audit row) - it is not additionally application-layer encrypted, matching `sp_private_key`. `HandleCheckSSOAvailability` now returns the OIDC login URL for OIDC providers (it previously handed them the SAML URL, which 400s). (#3289)

#### Changed

- **OIDC IdP endpoint fetches (discovery / JWKS / token) are now SSRF-hardened** *(Enterprise)* - both the fleet Path B verifier and the new portal login flow validate resolved IPs at dial time and block redirects that would reach an internal / cloud-metadata address, closing a redirect-follow + DNS-rebinding gap the previous bare HTTP client left open. (#3289)

#### Fixed

- **SSO portal login no longer 500s on an unproxied connection** *(Enterprise)* - both the SAML and OIDC portal-login callbacks passed the request's raw `RemoteAddr` (`host:port`) into the session write, but `user_sessions.ip_address` is a Postgres `inet` column that rejects the port, so every login without an `X-Forwarded-For` header (a direct connection, not behind a load balancer that strips the port) failed at the session INSERT. Both callbacks now use the same port-stripping helper as password login. This is why a direct browser login could fail even where an ALB-fronted one worked. A browser (Playwright) portal-SSO e2e covering both SAML and OIDC now runs on every PR touching the login paths. (#3302)
- **Compliance report generation + exports work out of the box on the enterprise compose** *(Enterprise)* - the enterprise `docker-compose` overlay shipped a MinIO object store but pointed the orchestrator's artifact storage at `local`, which the orchestrator treats as "no backend" (it cannot presign a `file://` URL the portal proxy can fetch), so every compliance report failed with "no artifact storage backend is configured". The overlay now defaults the orchestrator at the MinIO it already ships; all values remain overridable. (#3303)

#### Upgrade notes

- **Internal-IdP deployments must set `AXONFLOW_OIDC_ALLOW_PRIVATE=true` after upgrading.** The SSRF hardening above blocks IdP hosts that resolve to a PRIVATE address (RFC-1918, CGNAT, ULA, link-local, or a Kubernetes ClusterIP / `*.svc.cluster.local`). A self-hosted / in-vpc deployment running an internal Keycloak / ADFS / PingFederate for per-user OIDC tokens or portal login would otherwise have every OIDC fetch fail closed after the upgrade. Set `AXONFLOW_OIDC_ALLOW_PRIVATE=true` on the agent and customer-portal to permit private-IP IdP endpoints; a blocked fetch logs at ERROR naming the IP and this env var. Public-IdP SaaS deployments need no change (default keeps the anti-metadata hardening). This is a per-surface hatch, separate from the HITL / webhook hatches.
- **Compliance report exports require artifact storage on self-hosted deployments.** The compliance posture and readiness dashboards work with no extra config, but *generating* a report and downloading its PDF / CSV / XLSX requires an S3-compatible object store (the orchestrator writes the artifact there and hands the portal a presigned URL). The install bundle now exposes an `AUDIT_EXPORT_*` block on the orchestrator (see `.env.example`); set it to your own durable, in-region bucket to enable exports - an in-region bucket keeps compliance evidence in jurisdiction (OJK / UU-PDP Pasal 56b, RBI locality). Left unset, dashboards still render but report generation returns "no artifact storage backend is configured". This is configuration only, no migration. (axonflow-install)

### Community

_No functional changes._ Released in lockstep with the Enterprise edition at v9.16.0; the community `agent` and `orchestrator` are byte-identical to v9.15.0. Every v9.16.0 change is Enterprise-only (see above) - interactive OIDC portal login and the OIDC verifier live under the enterprise build, and the additive `core/158` migration no-ops on community deployments (its `sso_configurations` table is enterprise-only). The version is cut so the Community and Enterprise editions never diverge in version number.

## [9.15.0] - 2026-08-06 (in-vpc SAML SSO works end-to-end, SSO role auto-provisioning)

> Scope: interactive SAML SSO login is fixed end-to-end for self-hosted in-vpc
> deployments (it was broken in three independent places), and a first-time SSO
> user is now assigned their group-mapped role on login. Plus the governed
> `/api/request` empty-email fail-close is relaxed to proceed org-only, and the
> telemetry digest breaks down by platform version. No migrations.

### Enterprise

#### Added

- **Interactive SAML SSO login works end-to-end in in-vpc mode** *(Enterprise)* - self-hosted (in-vpc) SAML SSO was broken in three independent places and could not complete a login. Fixed: (1) the login URL is now the SSO addressing key (`getSSOTenantID`, the `__platform__` sentinel in in-vpc) instead of the org id, so `sso_config_org_for_tenant` resolves and login can start; (2) the ACS URL host now derives from `SSO_BASE_URL` and is recomputed at every handler build, so it points at the deployment's own portal (self-healing any stored `acs_url` written against the old hardcoded SaaS host) and the IdP delivers the assertion to the right host; (3) the callback now writes the session to `user_sessions` - the store the request validator reads via `portal_session_lookup()` - instead of `portal_users`/`portal_sessions`, tables no migration creates. **Self-hosted deployments must set `SSO_BASE_URL` to their portal's external URL** (a boot warning fires if it is unset on a non-SaaS deployment). SAML only; JumpCloud must be configured as a SAML app. (#3290, #3289)
- **SSO users are assigned their group-mapped role on login** *(Enterprise)* - when the SSO config has `AutoProvisionUsers` enabled, a first-time SSO user (no existing active role in the org) is assigned the role from the IdP group mapping (or `DefaultRole`), so they can use the portal instead of getting 403 on every gated action. This mirrors SCIM's group-to-role sync: a direct `source='sso'` write, assign-if-absent (never downgrades an existing owner, never fights SCIM), best-effort so a provisioning failure never blocks login. Full add-and-remove membership lifecycle remains SCIM's job. (#3291)

#### Changed

- **Governed `/api/request` with an empty email claim now proceeds org-only instead of refusing** *(Enterprise)* - the ADR-060 segment gate previously fail-closed to 403 when a governed `/api/request` token carried no email claim. It now proceeds with org-only scoping, matching pre-v9.14 behavior; segment-scoped targeting still requires an email. This relaxes a refusal introduced in v9.14.0. (#3278)

#### Internal

- The telemetry digest now breaks down usage by platform version, using data already in the ingest pipeline. (#3277)
- The enterprise-leak mirror gate was extracted to a tested, fail-closed script (`.github/scripts/check-enterprise-leak.sh`) with a regression test that fails closed on a grep error too. (#3276)
- The self-hosted upgrade preflight gained three v9.14.0 advisories (export admin authority, `/api/request` email-claim, target-version guidance) and its version guidance now points at v9.15.0 as the release carrying the `/api/request` org-only fallback. (#3288)
- The v9.13.0 cross-tenant forgery test now keys its assertion on the forged email so it cannot pass vacuously. (#3275)

## [9.14.1] - 2026-08-04 (patch: RBI export formats, and enterprise-only source removed from the community distribution)

> Scope: one functional fix (RBI audit export accepts PDF and XLSX) plus
> source-availability and licensing hygiene on the public community mirror.
> One additive migration, no data mutation. No behavior change for community
> binaries. PATCH by the 2026-07-30 semver policy: no removed capability, no
> new required credential, no new refusal.

### Enterprise

#### Fixed

- **RBI compliance audit export rejected PDF and XLSX** *(Enterprise)* - v9.14.0 shipped a `rbi_audit_exports.format` CHECK constraint that only admitted `json` and `csv`, so a request for the PDF or XLSX artifact failed at persistence. Migration `industry/banking/304` widens the constraint to include `pdf` and `xlsx`, matching the formats the facade advertises. (#3269)

#### Changed

- **Enterprise-tagged source is no longer published to the community mirror, and its license header is corrected** *(Enterprise)* - the compliance-reporting modules (RBI, SEBI, EU AI Act, MAS FEAT, OJK and the unified `compliancereport` facade) carry `//go:build enterprise` in normally-named files. The community sync excluded enterprise code by filename (`*_enterprise.go`), so these files were mirrored to the public repository even though they were never part of the community binary, which builds from the community stubs. The sync now excludes enterprise code by build-tag content, a fail-closed gate aborts the sync if any `//go:build enterprise` file would reach the mirror, and the affected files' SPDX headers were corrected from Apache-2.0 to BUSL-1.1. The files were purged from the mirror and the removal is marked as community `v9.14.1`. No functional change: community binaries and their behavior are identical to v9.14.0. (#3270, #3272)
- **Overlaid compliance mirrors removed and the overlay guard hardened** *(Enterprise)* - the last of the `ee/platform/orchestrator/*` compliance overlays are deleted so fixes to those modules reach shipped binaries, and `scripts/ci/check-no-compliance-overlay.sh` plus a runtime overlay check fail the build if an overlay is reintroduced. (#3269)

#### Internal

- Split the compliance-facade route-drift guard across the edition build-tag axis so the community mirror build stays green after the purge: the edition-independent constant check stays in the shared test, and the cross-file source-read assertion moved to an `//go:build enterprise` test that is excluded from the mirror. (#3273)

<!--
  Version decision (Step 0, release-prep RP-9.14): v9.14.0, MINOR, by explicit
  operator ruling 2026-08-04. The train carries two refusal-behavior changes
  (SEBI format=xml export now 501s instead of mislabeling JSON; portal export
  actions now require admin authority, so viewer sessions get 403). Under the
  2026-07-30 semver policy a new refusal is normally a MAJOR; the operator
  ruled MINOR for this train because both refusals are enterprise-gated
  surfaces with zero affected customers (no design partner uses SEBI, and the
  viewer-403 restores the documented authority model). Recorded here so the
  next train does not read this as precedent without the ruling.
-->
## [9.14.0] - 2026-08-04 (jurisdiction-selectable compliance reports: one facade, real renderers, honest refusals)

> Scope: mostly the compliance surface (EU AI Act, SEBI, RBI, MAS FEAT, OJK) and the
> customer portal, plus the first segment-scoped policy increment on the agent static
> plane. Four additive migrations, no data mutation. Two refusal-behavior changes on
> enterprise-gated surfaces; see Migration before upgrading.

### Security

- **EU AI Act by-id compliance routes answered for records the caller's organization does not own** *(Enterprise)* - the conformity-assessment and export by-id families (read, download, update, submit, approve, reject) resolved rows by id alone. Every one of those paths is now scoped to the calling organization in the SQL predicate and additionally runs inside a per-organization RLS session (`rls.WithOrgScope`), and a record outside the caller's organization answers **404**, byte-identical to an unknown id, so the route is not an existence oracle. (#3248)
- **Administrative authority and tenant-wide read scope were one axis on the export plane, so a viewer session could trigger tenant-wide exports** *(Enterprise)* - the tenant-wide export gate keyed on the read-scope grant that every portal session with tenant-wide visibility carries, not on the caller's authority to ACT. A portal session holding only viewer-level read permission could POST the evidence, SEBI, EU AI Act, OJK and media-governance exports and generate or download compliance reports. The gate now keys on administrative authority, asserted by the portal via a new trusted header (`X-Axonflow-Admin-Authority`, stamped only when the session's effective permissions include `policy:write`, which admits exactly admin, owner and policy_admin) and stripped from client requests by the agent at both strip sites. Viewer sessions now receive **403** on export actions; the report-status poll deliberately stays readable by any session in the tenancy. (#3248)
- **Enterprise images shipped an outdated SEBI module without its row-level-security scoping** *(Enterprise)* - the enterprise Docker build overlaid a stale `ee/` copy of the SEBI package over the canonical one at image build, and that copy predated the org-scoping wraps on SEBI audit-export reads. The shipped binary therefore ran those reads without the per-organization RLS session the source tree carries. All compliance-module overlays are removed from the enterprise build (sebi, rbi, euaiact, masfeat in #3248; ojk in #3250), so fixes to those modules now reach shipped binaries, and a CI guard (`scripts/ci/check-no-compliance-overlay.sh`) fails the build if a compliance overlay is reintroduced. (#3248, #3250)
- **The agent's policy-test preview bound its organization scope from a caller-influenced identifier** *(Community)* - `POST /api/policies/test` resolved segment membership for the preview under an organization value derived from the caller-supplied tenant string instead of the organization bound to the validated credential. It now binds from the authenticated context, exactly as the enforcement plane does. On enterprise deployments, where the license organization and the tenant string legitimately differ, this also fixes previews that silently resolved no segment-scoped policies at all. (#3255)

### Community

#### Added
- **Segment-scoped static policy targeting on the agent request plane** - a static policy can now carry a `segment_id` (migration core/157, nullable, orthogonal to `tier`), and the caller's resolved governance-segment set participates in policy selection on `/api/request`. Selection is strictly additive: rows with `segment_id IS NULL` behave exactly as before, and a segment-scoped policy can only add or tighten a restriction (the combiner takes the strictest of the tier decision and any applicable segment policy), never loosen one. A genuine segment-resolution error fails the request closed; an empty resolution proceeds org-only. Segment-scoped rows are excluded from the Enterprise override-downgrade JOIN at three layers. Not yet segment-aware, deliberately: the dynamic policy engine, the MCP-server fleet and gateway check planes, `GET /static-policies/effective`, `/api/policies/test` simulation semantics, and portal authoring (rows are authored via SQL until the write path lands). No behavior change until a segment-scoped row exists. (#3057)
- **Segments resolve from SCIM group membership** - a validated per-user identity on the fleet/MCP-server plane resolves its governance segments from the SCIM directory (`scim_users` to `scim_group_members` to `scim_groups`, org-scoped on both the user and the group row). Zero memberships is success (empty set); a query error fails resolution closed rather than degrading to role-only. In-process cache with clamped TTL; errors are never cached. Prometheus counters and a histogram cover resolution outcomes. (#3038)
- **The self-hosted upgrade preflight answers the v9.13.0 upgrade questions from the running old stack** - `scripts/deployment/v9_self_hosted_preflight.sh` (vendored byte-identically into the install bundle as `preflight.sh`) gained checks 9 to 12: it names every `dynamic_policies` row that migration core/155 will disable (with paste-ready remediation SQL, recoverable only before the migration), validates `DEPLOYMENT_MODE` on the agent and the orchestrator separately, sizes the core/156 ACCESS EXCLUSIVE lock window by measurement, and reports the CORS deny-by-default consequences. The query layer fails closed: results never travel through command substitution, existence probes use `pg_catalog` rather than the privilege-filtered `information_schema`, and a parity guard keeps the partner copy byte-identical. (#3234, #3237)

#### Changed
- `/health` advertises recommended SDK version **9.1.0** for Go, Python, TypeScript and Java (9.0.0 before; Rust stays 0.8.1). The 9.1.0 SDK minors are published as part of this release train, after the platform release: they add the real audit read-model wire fields (`policy_decision`, `policy_details`, `response_time_ms`, `action`) additively and deprecate `request_type`; no existing field is removed or renamed, so 9.0.0 clients keep working unchanged.
- `/health` advertises openclaw recommended plugin version **2.8.5** (2.8.4 before; 2.8.5 has been live since 2026-07-30). The plugin min/recommended maps now come from one shared package (`platform/shared/plugincompat`) read by both planes, so the agent and orchestrator can no longer drift apart on plugin advice; the wire shape is unchanged. (#3229)

#### Fixed
- In-repo documentation stamps (getting-started, SDK and guide headers, the compatibility matrix) now state the current platform version and the real SDK coordinates; the README's install block previously named a Go module path, Java version and Rust version that did not match the registries. (#3218, #3228)

### Enterprise

#### Added
- **One compliance-report API for all five regulators** - `POST /api/v1/compliance/reports` (202 with a job id), `GET /api/v1/compliance/reports/{id}` (poll), `GET /api/v1/compliance/reports/{id}/download` (307 to a presigned URL, 1 hour TTL, `Cache-Control: no-store`). One request shape selects the regulator (EU AI Act, SEBI, RBI, MAS FEAT, OJK) and the format; MAS FEAT gains its first export path of any kind. Every create/poll response carries `report_state`: `not_available`, `enabled_empty` or `populated`, so "the module is off", "the module is on and the period is empty" and "there is data" are three distinct answers instead of one empty 200. A job reaches `completed` only with a durably stored, checksummed artifact (a DB CHECK enforces it); a deployment with no storage backend gets a failed job naming the missing configuration, not a silent success. Report generation and download are admin-gated; the poll is not. Per-org daily generation limits by license tier (Evaluation: 3 per day, then 429). (#3248)
- **Real renderers behind every format** - PDF via go-pdf/fpdf (deterministic output: catalog sort plus a fixed generation timestamp; renderers refuse a zero timestamp), XLSX via excelize, CSV via encoding/csv. CSV and XLSX neutralize formula injection in tenant-controlled strings. RBI's export artifacts were plain text renamed to `.pdf` and CSV labeled `.xlsx`; both are now the real thing. (#3248)
- **The portal compliance page selects jurisdictions and reports states honestly** - a regulator selector covering all five modules (RBI, MAS FEAT and OJK previously had no client code at all), generate/export actions wired to the facade, and one typed three-state contract for every compliance fetch: `populated`, `enabled_empty`, or `not_available` with a reason (`plan`, `permission`, `unauthenticated`, `unsupported`, `unreachable`). Before this, a healthy-empty 200, a license refusal, a permission refusal, a 5xx and a network error all rendered as "module not enabled for this tenant" - a state the backend cannot produce. Refusal reasons render distinctly with the right affordance (the sign-in prompt links to sign-in); the license-gate upsell message is surfaced instead of discarded. The audit page's summary moved to the same contract. Downloads are honest about what they are: truncation caps are surfaced, the evidence export's tier-window clamp is reported, and presigned handoffs report `truncated: unknown` and the delivered `Content-Type` rather than a guess. (#3247, #3260)
- **Indonesia PII detections are persisted and exported** - detections from the gateway, decision and MCP planes are recorded (masked values only; a test parses the persistence seam for raw-bearing field references) into `indonesia_pii_detection_events` (migration enterprise/137, RLS-gated on `org_id`) and reach the OJK audit export under their OJK category. Community builds write nothing. (#3250)
- **Every declared OJK export data type now produces data or an explicit error** - `policy_violations`, `llm_calls` and `decision_chain` were empty stubs, and `hitl_oversight` and `pii_redactions` had no dispatcher case at all (a 200 with a silently missing section). The dispatcher is now exhaustive by construction (handler table keyed from the declared data-type list; unknown types produce a per-section error), and every section plus the summary carries `report_state` and an `error_kind` (`section_not_implemented`, `store_absent`, `query_failed`). The four framework labels (`OJK_AI_GOVERNANCE`, `BI_PJP`, `UU_PDP`, and the combined view) now select different section lists and name the instrument they report under; previously they were a validation whitelist producing identical output. (#3250)

#### Changed
- **SEBI audit export refuses what it cannot produce.** `POST /api/v1/sebi/audit/export?format=xml` returns **501 XML_NOT_IMPLEMENTED**; it previously returned a JSON body under an XML content type, so nothing could have been consuming it as XML. `format=csv` now returns genuine CSV (previously a JSON body under a `text/csv` header). `GET /api/v1/sebi/audit/export/{id}` returns **501 ASYNC_EXPORT_NOT_IMPLEMENTED** naming the synchronous contract; it previously returned 500 on every deployment, because the table it read exists in no migration. (#3248)
- **OJK identity resolution is org-first and header-only** - the scoping organization comes from `X-Org-ID` (then `X-Tenant-ID` only when the org header is absent), trimmed, and a blank or whitespace-only value is refused with **400 missing_org** instead of reaching the repositories as an empty scope. The previous resolver read the tenant header first into org-labelled columns. On `audit_logs`-backed sections (a table with no RLS), the tenancy predicate now matches rows owned by the caller's org plus rows with no org attribution belonging to the caller's tenant; the previous `(tenant_id = $1 OR org_id = $1)` shape could read across the org/tenant distinction on v9 licenses. Deployments that hold `ojk_breach_notifications` rows and send distinct org and tenant values should read `docs/compliance/ojk-org-scope-upgrade.md` before upgrading. (#3250)
- **OJK readiness is measured, not asserted** - four of the five readiness checks were unconditional pass literals and the dashboard carried hardcoded counts; a deployment with no reachable database scored 80 or better. Every check now queries the state it names or reports `unknown`, which scores zero and stays in the denominator, so scores on real deployments will move (typically down) on upgrade. The OJK module also joins the `/health` components map. (#3250)
- The OJK audit-export response's `format` field now states what the body actually is (`json`, and the OpenAPI schema enumerates only that value); a csv or xml ask is echoed in `requested_format` with a `format_note`. The body itself was always JSON. (#3250)
- Compliance-report job failures expose a closed set of stage messages; raw database and storage errors are no longer readable off the poll by any session in the tenancy. (#3248)

#### Fixed
- `GET /api/v1/euaiact/export` returned 500 on every non-travel deployment - the storage columns it read were created only by the travel industry pack. Migration enterprise/138 adds them everywhere the euaiact module runs. (#3248)
- The EU AI Act conformity list no longer 500s when it contains a draft assessment - nullable columns (`submitted_by`, `approved_by`, `rejected_by`, `rejection_reason`, the accuracy/bias metrics, and the export rows' `file_path`/`error`) were scanned into non-nullable Go types. Fixed in the canonical tree and, because the overlay was still live at that merge, in the `ee/` copy as well. (#3247)
- RBI board-report counters no longer fail on NULL aggregate scans, and tenant-controlled strings are no longer written raw into CSV export attachments. (#3248, #3246)
- A transient failed poll tick on the portal report panel no longer leaves a permanent refusal card beside a completed report, and the polling-exhausted banner retires when the job reaches any terminal state. (#3260)
- Compliance-report jobs stranded by a restart or timeout are reaped by derivation on read (no background writer), and the per-day rate-limit backstop survives restarts. (#3248)

### Migration

**Four migrations, all additive, no data mutation.** Take the usual pre-upgrade snapshot (the preflight's backup check applies unchanged), but none of these rewrites existing rows.

| Migration | Applies to | What it does |
|---|---|---|
| core/157 | every deployment mode | nullable `static_policies.segment_id`; NULL on all existing rows, no behavior change until a segment-scoped policy is authored |
| enterprise/136 | enterprise migration sets | new `compliance_report_jobs` table (org- and tenant-keyed, RLS enabled AND forced with its own policy, CHECK-constrained completion states) |
| enterprise/137 | enterprise migration sets | new `indonesia_pii_detection_events` table (RLS on `org_id`, masked values only) |
| enterprise/138 | enterprise migration sets | additive storage columns on `euaiact_exports` (fixes the euaiact export 500 outside travel/saas); its down migration deliberately retains the columns |

**Upgrade notes - the two refusal changes:**

1. **SEBI XML export now refuses.** Anything calling `POST /api/v1/sebi/audit/export?format=xml` gets 501 where it previously got 200 with JSON mislabeled as XML, and `format=csv` responses change body shape from JSON to real CSV. Audit any SEBI export automation for a hardcoded `format=xml` or a JSON parse of the csv response before upgrading.
2. **Portal export actions now require admin authority.** Sessions holding roles without `policy:write` (viewer, developer) receive 403 on tenant-wide export POSTs (evidence, SEBI, EU AI Act, OJK, media-governance, compliance-report generate/download) where they previously succeeded. Admin, owner and policy_admin sessions are unaffected. If an automation drives exports through a portal session, move it to an admin-authority role before upgrading.

Also worth knowing before upgrading: cross-org EU AI Act by-id requests now answer 404 (previously 200 including mutations); blank org identity on OJK routes now answers 400; OJK readiness scores are now measured; and enterprise images no longer apply any `ee/` compliance overlay, so this train's compliance fixes actually reach the shipped binary.

## [9.13.0] - 2026-07-30 (cross-tenant remediation: authoritative principals, pre-auth RLS, deployment-mode validation, and CI guards that can fail)

### Security

- **The governed request plane took `user.role` and `user.email` from the request body - a policy-evasion primitive, not just an attribution one** *(Community)* - `POST /api/v1/process` and `POST /api/v1/workflows/execute` bound the caller's **tenancy** from the gateway (#3066) and left the rest of the decoded user context exactly as the body typed it. `platform/orchestrator/db_dynamic_policies.go` `getFieldValue` resolves the policy-condition field `user.role` straight off that struct, and nothing anywhere in the platform had ever written it from a credential, a header or a JWT claim. Both routes are registered on the AxonFlow Agent's **reverse proxy**, which validates the caller's credential, stamps the tenancy headers and then forwards the caller's body byte for byte - so a tenant policy of the shape `{query contains …} AND {user.role not_equals "admin"} → block` was defeated by putting `"user":{"role":"admin"}` in the request body. That shape is not hypothetical: it is the built-in HIPAA PHI-access template shipped in `migrations/enterprise/109_compliance_templates.sql`, it is expressed in `platform/orchestrator/policy_defaults.go`, `user.role` is offered in the customer portal's policy builder, and it is documented as a supported condition field in the policies API reference. **Be precise about severity:** no *enabled* policy keyed on `user.role` is seeded on a default deployment, so this is latent-by-default rather than live-by-default - but any deployment that instantiated the HIPAA template, ran the e-commerce demo policy installer, or authored a role condition in the portal had an evadable control, and the caller needed only a valid credential for the deployment. One plane down, `user.email` and `user.id` became `audit_logs.user_email` / `user_id` on every verdict these handlers record, so the same body also chose the name on the compliance trail. The actor is now bound by a single choke point (`applyAuthoritativePrincipal`) shared by `/api/v1/process`, `/api/v1/workflows/execute`, `/api/v1/plan` and `/api/v1/plan/execute`: `user.email` from the trust-gated `X-User-Email` header exactly as the MAP planes have bound it since #2896, `user.role` **only** from `X-Axonflow-User-Role` - which the agent deletes unconditionally and re-sets solely from a cryptographically validated per-user token - and `user.id`, `user.region` and `user.permissions` cleared, because no authenticated source for them exists on this plane. The role is deliberately **not** sourced from the trust-gated identity headers: the platform's own contract is that a trusted identity header may set audit attribution fields only and must never influence a verdict. (#3152)
- **The app-role boot guard passed when the administrative pool was configured but unusable** *(Community)* - `RequirePlatformAdminOrFatal` asks only whether `AXONFLOW_DB_PLATFORM_ADMIN_URL` is a non-blank **string**. It never asks whether that string produced a pool. So a DSN the operator *did* set but which yields nothing passes the guard, `OpenPlatformAdminConnection`'s failure is degraded to a warning by every caller, and the process boots green with every cross-organization and pre-authentication read routed onto a `NOBYPASSRLS` pool that **returns zero rows instead of an error**. Three ways in, none of them a forgotten variable: a DSN authenticating as the master/owner role rather than `axonflow_platform_admin` (the role assertion correctly refuses it, and the refusal was swallowed); a brief database outage inside the three-attempt boot window while the main pool's five attempts succeed; a rotated password that has not propagated to the secret yet. On the customer portal this is what made the two fixes below **silent**: every `SetAdminDB` is skipped, so the pre-authentication SCIM and API-key lookups resolve nothing and the handlers report that as an authentication failure - and the operator rotates a credential that was never wrong. A configured-but-unusable administrative pool is now **fatal at boot** under `AXONFLOW_DB_USE_APP_ROLE=true`, applied at twelve boot-path call sites: the portal, the agent's marketplace metering, node monitor, Community-SaaS sweep/recovery/deletion, idempotency sweep and HITL expiry pools, and the orchestrator's node monitor, idempotency, audit retention and cross-organization read pool. **Operator action: none for a correctly configured deployment, and no migration.** The guard keys on *"the DSN is configured but unusable"*, never on *"the pool is nil"*, so an **unset** DSN is untouched: it remains the documented fallback for single-role and owner-connected deployments, is still owned by the existing guard where the DSN is mandatory, and unit tests that build engines without one are unaffected. **Three sites deliberately do NOT get the guard, and the gap is stated rather than hidden:** the connector registry and both dynamic-policy engine constructors. The orchestrator is designed to boot with an unreachable database, and those three are reachable in that state - a fatal there would turn a database failover into a crash-loop, and an orchestrator with zero running tasks is itself the fail-open shape this class of fix exists to prevent. So on those three paths a configured-but-unusable administrative pool still degrades silently, which for the dynamic-policy engines means tenant dynamic policies stop being enforced. Closing that needs the pool opened at the boot path and injected into the constructor, not a fatal inside it. Every site that does carry the guard sits behind a boot path that already refuses to start without a working database, so this adds no new failure mode to a deployment that boots today. A deployment that was silently running degraded will now refuse to start and name the variable and the underlying error - which is the intended outcome, because the alternative is metering that undercounts, sweeps that observe nothing, and policies that do not enforce. (#3159)
- **The portal's pre-authentication API-key lookup ran inside the row-level-security scope it exists to discover** *(Enterprise)* - `KeysHandler.ValidateAPIKey` resolves which organization owns a presented key, so it cannot set `app.current_org_id` - which is exactly what migration 018's `tenant_isolation_select` policy on `customer_portal_api_keys` tests. Read through the ordinary connection the predicate is never true, the lookup returns zero rows, and `sql.ErrNoRows` is reported as `invalid API key`. **The outcome was conditional on the connecting role:** migration 018 `ENABLE`s row-level security on this table and no migration ever applies `FORCE` to it - migration 099, which `FORCE`s the sparse audit/config tables, does not list it, for the auth-bootstrap chicken-and-egg reason its own commentary gives. `ENABLE` alone is bypassed by the table owner and a portal connected as the owner worked by accident; one connected as `axonflow_app_role` - the v9 default - did not. `KeysHandler` had no `SetAdminDB`, unlike the SSO service and the SCIM middleware, so one is introduced rather than a query merely rerouted. The lookup now runs on that `BYPASSRLS` pool through a `preAuthDB()` accessor with **exactly one call site**; every other method on the handler keeps its organization scope or the migration-109 `SECURITY DEFINER` helper. Not a widening: `key_hash` is unique, the lookup is by the SHA-256 of a secret the caller already presented, and the only fact it yields is which organization owns *that* key. The scope is applied *after* the lookup resolves it - the `last_used_at` write now runs inside `withOrgScope` on the resolved organization with `org_id` in the predicate, and a zero-row update is logged rather than passing silently; a key row resolving to an empty organization is refused. **Reachability, stated plainly: `ValidateAPIKey` currently has no production caller** - no route or middleware invokes it. This is a latent defect on an exported method, fixed rather than left armed for whoever wires it up, so **no deployment is currently affected**. Separately, and recorded because two earlier drafts of this entry got it wrong in opposite directions: there is **no timezone defect here at all.** The first draft claimed key expiry was stored with the host's UTC offset baked in; the second claimed the write path was safe only because the migration-109 helper takes a `TIMESTAMPTZ` parameter. Both were reasoning about `TIMESTAMP WITHOUT TIME ZONE` columns that **migration enterprise/133 retyped to `TIMESTAMPTZ` in platform 9.8.0** - `expires_at`, `created_at`, `last_used_at` and `revoked_at` on this table are all timezone-aware on any supported deployment. A round-trip test now pins the property that a key expires at the instant its request asked for. **Operator action: none, and no migration.** (#3163)
- **The SCIM directory returned an empty directory instead of an error, and identity providers acted on it** *(Enterprise)* - every statement in the SCIM directory repository went through a `queryable()` accessor that returned the raw connection pool whenever no transaction was open. An organization scope is a session variable, so a statement on a pooled connection carries none, and migration 117's policies on `scim_users`, `scim_groups` and `scim_group_members` all test `tenant_id = current_setting('app.current_org_id', true)`. Under `axonflow_app_role` that predicate is never true. Writes raised `42501`; **reads returned zero rows with no error at all.** The request authenticates, the handler returns `200`, and the body reports `totalResults=0` for a tenant that holds users. An identity provider reading that does not conclude something is broken - it concludes the directory needs repopulating and **re-creates every user**. The deprovision direction is worse: `DELETE /scim/v2/Users/{id}` returned `404` while the row survived, and RFC 7644 §3.6 makes `404` terminal success on a delete for every major IdP, so the directory believed the user was gone while its `source='scim'` role grants stayed live - the state #3030 was written to prevent, reached through a different door. `queryable()` is **deleted** rather than fixed at its call sites: the only path to a statement is now a helper that establishes the scope first and **fails closed** when it cannot resolve one, so the compiler enumerates the call sites instead of a reviewer remembering them. **The scoping value is the SCIM addressing tenant, not the organization** - despite the GUC's name the value compared is the `tenant_id` column, and keying the directory on the organization would lock out every deployment where the two diverge (the #3067 failure). The four group-membership methods take no tenant argument, because a membership row has no tenant column; migration 117 scopes them through the group they point at, so they resolve the tenant the authentication boundary already bound on the request context - the same value, by the only route available to them. `WithTx` used to open a bare transaction, so in-transaction paths stayed broken while no-transaction paths worked; it now binds the scope too. **Operator action: none, and no migration.** Two behaviour changes to expect: a directory statement that cannot resolve a tenant now returns an error rather than silently reading nothing, and a statement whose explicit tenant disagrees with the authenticated context is refused rather than scoped to either. (#3156)

- **`DEPLOYMENT_MODE=enterprise` was not a recognised mode, so every self-hosted enterprise stack applied the SaaS schema** *(Community)* - `getMigrationPaths()` had cases for `community`, `evaluation`, `saas`, the four `in-vpc-*` verticals and `community-saas`. It had no case for `enterprise` - the value `docker-compose.enterprise.yml` has always defaulted to on all three services, that `docker-compose.test.yml` and `docker/docker-compose.base.yaml` set, and that `scripts/setup-e2e-testing.sh` writes into `.env`. It therefore hit the `default:` arm, which logged `⚠️ Unknown DEPLOYMENT_MODE=%s, defaulting to saas` and applied `core/` + `enterprise/` + **`industry/healthcare/` + `industry/banking/` + `industry/travel/`**: eight industry migrations, and the SEBI/RBI/MAS-FEAT/EU-AI-Act tables they create, on a general-purpose enterprise deployment that asked for none of them. **No misconfiguration was required and the schema event is live on stacks running today.** `enterprise` is now an alias for `in-vpc-enterprise` - core + enterprise, which is what the mode has always meant - and an **unrecognised** value is no longer widened to the largest set: the agent refuses to boot and names both the value it rejected and every value it accepts. A selector that widens on input it does not understand cannot distinguish "the operator asked for the SaaS schema" from "the operator typed something we have never heard of", which is the same shape as `isAdminAuthRequired` before #2287/#3068, `isCommunityMode` before #3096, and the portal proxy catch-all. Matched exactly - not trimmed, not case-folded - so `" enterprise"` and `"Enterprise"` are refusals, not guesses. **No corrective migration ships.** The surplus vertical tables on stacks that already applied them are inert, and issuing `DROP` against a customer database to tidy a cosmetic surplus is a worse operation than the surplus; they simply stop being re-selected. (#3167, #3181)
- **AxonFlow's own E2E fixtures and demo tenants were seeded into every customer deployment** *(Community)* - `migrations/enterprise/115_e2e_test_policies.sql` inserted five `dynamic_policies` rows for **our** portal-UI test tenant `e2e-test-saas`, named "E2E Content Filter Policy" and similar, under a header claiming *"This migration ONLY runs in SaaS mode (not OSS or In-VPC)"* - which was never true of any code path, because the file was in `enterprise/`, which every `in-vpc-*` mode loads. `migrations/enterprise/125_demo_customer_mapping.sql` inserted `customers` rows for the AxonFlow demo orgs `travel-us` and `ecommerce-prod-us`. Both land in tables the customer's own portal renders, so a customer saw our test policies in their policy list and our demo organisations in their organisation list. Measured on an `in-vpc-enterprise` install: `policy_templates` 24 / `dynamic_policies` 17 / `customers` 7, against community's 7 / 12 / none. Both files move to a new `migrations/internal/` category that **no deployment mode selects**, guarded by a test that reads every file the selector returns for every recognised mode and fails if one names an AxonFlow tenant - so the next such seed is caught wherever it is put, not just in `internal/`. The `e2e-test-saas` organisation and four of these five policies are seeded for real through the portal API by `.github/workflows/seed-test-data.yml`, against a named environment chosen at dispatch; the migration was a superset that ran everywhere instead. The fifth, `e2e-pii-detection-001`, has no counterpart in that workflow - if a suite turns out to need it, seed it there rather than from a migration. **Rows already seeded are not deleted** - see the Migration section. (#3168, #3181)
- **MAP HITL approve/reject took the approver's name from the request body** *(Community)* - `POST /api/v1/plans/{id}/steps/{step_id}/approve` and `.../reject` read `approved_by` / `rejected_by` out of the JSON body and consulted the identity header only when that field was absent. The value is written to `workflow_steps.approved_by` and, through the workflow audit entry, to `audit_logs.user_email`, so an authenticated caller could name **any** approver on a human-in-the-loop decision and that name is what the trail recorded. It is the exact inverse of the rule the MAP execute path already stated - *"the actor EMAIL is authoritative from the trust-gated header, NEVER the request body"* - and of the WCP siblings of the same operation (`/api/v1/workflows/{id}/steps/{step_id}/approve|reject`), which have always resolved the approver from headers only. **Be precise about what this is:** it does not cross a tenant boundary (the caller must already be authenticated, and cross-tenant approval is separately blocked), and it grants no access the caller did not have. What it defeats is **attribution and non-repudiation on an approval** - the entire purpose of a HITL audit trail, and ADR-044's subject matter. It is a compliance defect, not an access-control one. Both handlers now resolve the actor from `X-User-ID`, then `X-User-Email`, matching the WCP resolver exactly so the same human is stamped identically on either plane; the body fields are removed from the request structs rather than merely ignored, and are no longer read even as a fallback. Both handlers also now run the agent proxy-auth gate its WCP siblings run. (#3135)
- **The dynamic-policy verdict cache was tenant-blind** *(Community)* - `DynamicPolicyEngine.EvaluateDynamicPolicies` keyed its cached verdict on `user.email`, `user.role`, `request_type` and the query text, with **no tenant and no organization**, in a single process-global map shared by every tenant in the deployment. `user.email` is empty on the agent's governed forward for every caller without a per-user token and `user.role` is frequently empty too, so in practice the key collapsed to `::<request_type>:<query>` - deployment-wide. Two tenants issuing the same query shared one verdict, in **both** directions: the second tenant received the first tenant's `applied_policies_detail[]` (`policy_id`, `policy_name`, `description`, `action`, `risk_level`), and - worse than the disclosure - if the first tenant's verdict was `allowed`, the second tenant's **own blocking policy never ran**, because the cache is consulted before any tenant-scoped policy set is loaded. **Which deployments were exposed:** this cache belongs to the orchestrator's **in-memory fallback** policy engine, which is selected when the database-backed engine fails to initialise at boot - an unreachable or not-yet-ready database, or an app-role connection whose role assertion fails. A stack whose database-backed engine came up is not affected. In the fallback state the engine still loads tenant policies from the database on its own connection when it can, so the cross-tenant sharing described above is real there, on `POST /api/v1/process` and every other caller, with nothing but an ordinary tenant credential. The key is now a struct carrying the organization and the tenant, and the cache accepts no other key type, so a lookup cannot name a request without *supplying* the tenancy it was evaluated under - the compiler enumerates the call sites rather than a reviewer remembering a filter. (A zero-valued tenancy is still constructible, and one plane - workflow step gates - legitimately produces an empty organization because it carries that value in a different field; the key covers that field too, so the entries stay distinct.) The tenant half is derived by the same function that selects the policy set, so the key and the policy set cannot disagree; the key also now covers every remaining field a policy condition can read (`user.region`, `user.permissions`, `client.id`, `client.name`), because a verdict cached under a key that omits one of its own inputs is served to a request that would have evaluated differently. Separately, the cache used to hand out the **stored pointer**, and `ApplyOverrideToResult` mutates a verdict in place - so one tenant's ADR-044 session override was written into the shared entry and read back by every later caller. Verdicts are now deep-copied in and out. This was S-7 of #3067, enumerated and deferred there. **Operator action: none.** No migration, no configuration, no re-provisioning. The cache key is finer than it was, so expect a lower hit rate and a correspondingly small increase in policy-evaluation work - that is the cost of not sharing a verdict between requests the engine would answer differently. (#3142)
- **SCIM bearer-token authentication rejected every valid token on app-role deployments** *(Enterprise)* - `validateToken` is the **pre-authentication** lookup: it exists to discover which tenant owns a presented bearer token, so it cannot set `app.current_org_id` - which is precisely what the `scim_tokens` row-level-security policy tests. Read through the ordinary connection, the predicate is never true, the query returns zero rows, and `sql.ErrNoRows` is reported as `401 invalid token`. The same file already solved this exact shape one layer up: `orgForTenant` resolves the tenant→organization mapping through a `BYPASSRLS` administrative connection with a comment explaining that the read is inherently pre-organization. `validateToken` now uses that same connection, and the tenant scope is applied *after* the token resolves it. **The outcome was conditional on the connecting role** - `scim_tokens` is `ENABLE`, not `FORCE`, so a deployment whose portal connects as the table owner was unaffected and worked by accident; a deployment connecting as `axonflow_app_role` (the v9 posture, `AXONFLOW_DB_USE_APP_ROLE=true` with an app-role DSN provisioned) had SCIM provisioning entirely down. Verified by execution against a real PostgreSQL as `axonflow_app_role` with `rolbypassrls = false` asserted on the connection under test. This does not widen access: `token_hash` is unique, the caller already presented the secret being hashed, and the only fact the lookup yields is which tenant owns that token. **Operator action: no migration and no re-provisioning, but check one variable.** The fix uses the administrative connection the portal already opens from `AXONFLOW_DB_PLATFORM_ADMIN_URL` - the same one SSO cookie lookups and the admin handlers use. A portal running under `AXONFLOW_DB_USE_APP_ROLE=true` already refuses to boot when that variable is unset, so a single-role or owner-connected deployment needs nothing. **The value must be usable, not merely present** - and as of #3159 (below) the portal enforces that: a configured DSN that authenticates as the wrong role, or a database briefly unreachable during boot, used to be downgraded to a start-up warning, leaving the administrative connection unattached and this bug fully intact on an otherwise green boot. That case is now fatal. SCIM authentication also emits a one-time warning naming the variable when a token lookup finds nothing and no administrative connection is attached, so the two causes are distinguishable in the log. (#3134)
- **SCIM token management wrote and read outside its row-level-security scope** *(Enterprise)* - every statement in the SCIM token manager (`create`, `list`, `get`, `revoke`, `delete`) targets the same RLS-enabled `scim_tokens` table without establishing an organization scope. Unlike the pre-authentication lookup these paths are session-authenticated and already hold the tenant they are acting on, so they now set that scope rather than reaching for the administrative connection. Under `axonflow_app_role` creating a token raised `42501`, listing returned nothing, and revoke/delete reported "not found" having matched no row - so the portal could not issue a SCIM token at all, and there was nothing for bearer authentication to resolve. Found and fixed alongside #3134 because the two halves are the same defect on the same table and neither is usable without the other. A token-less token row is now refused at authentication rather than authenticating a request no scope can constrain, and a zero-row `last_used_at` update is logged instead of passing silently. (#3134)
- **If you run SCIM on an app-role deployment, read this** *(Enterprise)* - the SCIM fixes in this release land together and the ordering matters. #3134 restored **authentication** and **token management**; #3156 fixed the **directory** repository, which set no organization scope either. Until both were in, the consequence on an app-role deployment was asymmetric, and the asymmetry is worth understanding because it shaped the release: **provisioning failed loudly** - `POST /scim/v2/Users` was refused by the row-level-security check and returned 500, so an identity provider alarmed at once - while **deprovisioning failed silently**. `DELETE /scim/v2/Users/{id}` and `PATCH {"active": false}` returned 404 because the lookup that precedes them read nothing; the service treats that as an already-completed delete, skips the SCIM grant revocation added in #3030, and RFC 7644 makes 404 terminal success on a DELETE for every major identity provider. The directory believed the user was gone while their SCIM-sourced role assignments stayed live. **#3134 did not cause that - it unmasked it:** before it the same request returned 401, which an identity provider retries and alerts on. **Both halves now ship together, so no out-of-band verification is required.** The runtime-e2e suite that pinned the broken state now asserts the fixed one: the directory read returns the tenant's real rows, and the delete returns 204 with the row gone. (#3134, #3156)

- **Org binding failed open on eight-plus governance call sites** *(Community)* - every one shared the idiom `if callerOrg != "" && row.OrgID != "" && row.OrgID != callerOrg { reject }`, which passes whenever **either** side is empty. The caller's org arrived as a self-asserted `X-Org-ID` header, or for budgets an `org_id` **query parameter**, on routes that mostly lacked the proxy-auth gate - so *omitting a header was the exploit*. Reproduced against a live 9.12.2 stack: aborting another tenant's workflow with no tenancy headers returned HTTP 200 and the operation succeeded across tenants. Scope now comes from a single `platform/shared/tenantscope` choke point that fails closed when either side is empty with no trusted-caller bypass in any deployment mode. A row whose key does not match the caller's returns **404**, so the endpoint is not an existence oracle. On the routes that bind scope at the handler edge (workflow-control, cost, replay) a caller carrying no resolvable scope at all returns **401**, because that answer does not depend on the id; the agent HITL by-id routes deliberately collapse that case to **404** too, so an unbound caller cannot distinguish a missing request from another org's. A syntactic lint pins the idiom so it cannot return in Go or in SQL - the previous fix had moved the same fail-open compare *into* a SQL `WHERE` clause while claiming isolation. (#3065)
- **Workflow-control routes took tenancy from client-supplied headers** *(Community)* - the WCP handlers read `X-Tenant-ID`/`X-Org-ID` directly. All 14 routes now require the internal proxy-auth token and resolve tenancy from the authenticated scope; the header-reading helpers are deleted rather than left callable. (#3065)
- **MCP tool-governance plane: deployment-wide dynamic policies were silently not evaluated** *(Community)* - `POST /api/v1/mcp/evaluate-policies` applied its own tenant predicate, the inverse of the canonical one on every stored shape: policies stored with `tenant_id = 'global'` or a NULL `tenant_id` (the `'default'` sentinel) were skipped, while the empty-string shape - which applies to no tenant, and which migration `core/155` forbids - was admitted. A deployment-wide `content` baseline therefore enforced on the LLM / MAP / WCP planes and was silently skipped on every governed MCP tool call. The MCP evaluator now resolves tenant scope through the same engine function that decides enforcement, so a stored policy's **tenant scope** is identical on every plane. (Field resolution and the set of admitted policy types still differ between planes - only scoping is unified here.) (#3061)

- **Dynamic-policy list endpoint disclosed every tenant's policies** *(Community)* - `GET /api/v1/policies/dynamic` returned the orchestrator's deployment-wide in-memory policy cache verbatim to any authenticated tenant: each policy's identifier, name, type, category, priority, owning tenant, and full conditions (regex patterns) and actions, for every tenant in the deployment. A newly created tenant with no policies of its own received policies belonging to unrelated tenants. The endpoint now returns only the calling tenant's policies plus the shared global/default baseline, and returns 401 without a body when no tenant can be resolved rather than falling back to the unscoped list. (#3059)
- **Policy simulation disclosed the deployment-wide policy count** *(Community)* - `POST /api/v1/policies/simulate` reported `total_policies` as the number of active policies across all tenants. It now counts only the policies visible to the calling tenant. (#3059)
- **List and enforcement scoping now share one decision point** *(Community)* - each policy engine's "does this policy apply to this tenant?" check is a single function used by both the evaluator and the list endpoint, so a policy can be listed to a tenant only if it is also enforced for that tenant. Previously the two were separate predicates that disagreed on policies carrying an empty tenant value. (#3059)
- **Orchestrator API required no authentication at all** *(Community)* - the orchestrator installed no authentication middleware, so any party able to reach its port performed unauthenticated reads AND writes on the governance control plane, selecting the target tenant with a client-supplied `X-Tenant-ID` header. On production this was reachable from the public internet: both CloudFormation templates published the orchestrator on an internet-facing ALB listener (port 8081), and the marketplace template's ALB security group opened that port to `0.0.0.0/0`. A router-level gate now requires a valid HMAC-signed `X-Axonflow-Proxy-Auth` internal-service token on every route except `/health`, `/metrics` and `/prometheus`, before routing and with no deployment-mode carve-out. (#3068, #3064)
- **The customer portal's orchestrator catch-all forwarded any path to any authenticated session** *(Enterprise)* - the portal proxies `/api/v1/*` to the orchestrator through a `PathPrefix("/")` catch-all with no method restriction, and the permission gates in front of it are an allowlist of *prefixes*. Every orchestrator route those prefixes did not enumerate was therefore reachable by **any** authenticated portal session, of any role - viewer and developer included - with the portal's internal-service HMAC minted on its behalf. The census of what that actually reached found, among others: the MCP policy-evaluation plane (`POST /api/v1/mcp/evaluate-policies`, the instance this was filed on), the LLM data plane (`POST /api/v1/process`), the deployment's LLM routing weights (`PUT /api/v1/providers/weights`), audit *ingestion* (`POST /api/v1/audit/tool-call`), the agent-config CRUD family (`/api/v1/agents/*`), the SDK's workflow-completion and checkpoint-resume callbacks, and the MAS FEAT and RBI kill switches (`POST /api/v1/masfeat/killswitch/{id}/trigger`, `POST /api/v1/rbi/killswitches/{id}/deactivate`). This is the recurring shape the programme keeps finding - a default branch that permits input it does not recognise, as in `isAdminAuthRequired`, `isCommunityMode` and the migration selector - and it is fixed the same way: **the default is now refusal**, and an orchestrator route is reachable through the portal only by being named in `api.ProxyAllowedRoutes`, entry by entry, with the portal surface that needs it. The allowlist is keyed on *(method, path template)*, so a path admitted for `GET` is not thereby admitted for `DELETE`; a refused request is answered `403 ROUTE_NOT_PROXIED` **before** the internal token is minted, so it never reaches the orchestrator. The reachability decision is deliberately a separate axis from the two that already exist: it does not widen or narrow read scope (`X-Axonflow-Read-Scope` still decides that) and it does not confer a permission (`sessionPermGate` still decides that). A companion test re-derives the orchestrator's route set from source on every run and fails until each new route is classified - admitted, refused with a reason, or answered by the portal's own handler - so the census cannot go stale the first time somebody adds a route. **Operator-visible behaviour changes:** paths the portal exposes are unaffected, and the whole portal UI was re-verified against the table page by page; two paths change status code, both already dead - `POST /api/v1/dynamic-policies/{id}/override` (the override route removed under #2768) and the `/api/v1/rbac/*` family the RBAC settings page calls, which the backend has never served under that prefix, now answer `403` where they previously answered `404` from the orchestrator. Note what this does **not** do: it decides reachability, not authority, so a viewer session admitted to (say) workflow creation is still not permission-checked there - the role model has no permission to check, and adding one is a role-model change tracked separately.

- **Portal admin API served anonymously outside `DEPLOYMENT_MODE=saas`** *(Enterprise)* - the admin-auth requirement was keyed on the literal mode string `saas` and every other mode fell through a `default: return false` branch, so a production deployment running `DEPLOYMENT_MODE=enterprise` served `/api/v1/admin/*` - organization listings, org PATCH/DELETE, and `GET /organizations/{id}/license`, which discloses the plaintext license key used as the platform's HTTP Basic credential - with no credential, even though `ADMIN_API_KEY` was configured. Admin authentication is now required whenever `ENVIRONMENT=production` in any mode, and unknown mode strings fail closed. This is #2287 re-opened through a mode string. (#3068)
- **In-VPC deployments could not enable admin authentication at all** *(Enterprise)* - setting `ADMIN_API_KEY` only caused a *wrong* key to be rejected; a request presenting no key still passed through as an anonymous, unauthenticated caller, and no configuration expressed the other choice. A configured `ADMIN_API_KEY` now requires authentication in every deployment mode and environment. (#3068)
- **MCP dynamic-policy evaluation authenticated its orchestrator hop, and now fails closed when that credential is refused** *(Community)* - the shared dynamic-policy evaluator posted to the orchestrator without an internal-service token. Combined with the new gate and the default `MCP_DYNAMIC_POLICIES_GRACEFUL=true`, connector policy evaluation would have degraded silently to allow-all with zero policies evaluated. The hop is now signed, **and an orchestrator response of 401/403 is treated as a permanent condition that graceful degradation must not absorb**: it blocks instead of allowing, with a one-time security banner. Graceful degradation still absorbs transient failures (timeouts, 5xx, an orchestrator that is restarting) exactly as before. This matters because an authentication rejection needs no operator error to occur - the internal-service token is timestamp-signed with a five-minute window, so clock drift on either host, a secret rotation caught mid-flight, or two task definitions that disagree all produce a deterministic 403 that would otherwise have silently disabled connector policy enforcement for the life of the process. (#3068)
- **The orchestrator's embedded Execution Viewer UI is no longer reachable by addressing the orchestrator directly** *(Community)* - `/ui/executions/*` is served by the orchestrator, and a browser pointed at the orchestrator's own port cannot mint an internal-service token, so that route now returns 403 like every other non-exempt route. **The feature itself still works:** the agent proxies `/ui/executions/*` and stamps the token on the way through, so the UI remains reachable at the agent's address (`http://<agent>:8080/ui/executions/`), which is the documented single entry point (ADR-026). Bookmarks pointing at the orchestrator's port must be repointed at the agent. (#3068)
- **An unset `DEPLOYMENT_MODE` selected the most permissive posture the platform has** *(Community)* - `isCommunityMode()` had `mode == ""` in its true set in **both** `platform/agent` and `platform/orchestrator`, so a deployment that merely *forgot* to configure itself ran Community: authentication and license validation disabled, the MCP connector permission check skipped, `require_approval` policies auto-approved, a request body allowed to assert its own tenant, and - before any token or role was examined - `{tenant-wide, admin}` read authority granted to every caller. Nothing about that deployment looked wrong; it booted, passed its health check and served. This is the same fail-open-on-unset shape #2287/#3068 fixed in the portal's `isAdminAuthRequired`. The burden of proof is now inverted: the permissive posture must be asked for **by name**, and everything else - the empty string, an unrecognised value, a typo - gets the enterprise posture. The value is matched **exactly**, deliberately not trimmed or case-folded: every widening of this particular predicate *disables authentication*, and there is no dominating rule to make normalisation safe, so `" community"` fails closed. (#3096)
- **CORS advertised `*` together with credentials, and the MCP endpoint reflected any origin at all** *(Community)* - the agent and orchestrator both installed a hardcoded `AllowedOrigins: ["*"] + AllowCredentials: true`. Severity was established by executing `rs/cors` v1.11.1 rather than by reading it: the library emits a **literal** `*`, not a reflected Origin, so browsers reject the credentialed request and the exposure was **latent, not live**. It is fixed anyway, because the obvious repair - reflect the Origin, keep credentials - converts it into a cross-origin read of authenticated responses from any site. The policy is now configuration-driven through `AXONFLOW_CORS_ALLOWED_ORIGINS` and **denies all cross-origin requests by default outside Community mode**; credentials are enabled only for a named allowlist, which is the only combination the Fetch spec permits. Denial is expressed as an `AllowOriginFunc`, not as an empty `AllowedOrigins` slice, because `rs/cors` reads a zero-length slice as *allow-all* - the intuitive lockdown is a silent no-op. Separately, `/api/v1/mcp-server` answered its own preflight with `Access-Control-Allow-Origin: <request Origin>` **unconditionally**, a second origin policy that kept echoing attacker origins under the new deny-all default; it now resolves through the same policy, so the origin allowlist has one definition. (#3096, #3117)
- **OPTIONS requests ran auth-gated handlers anonymously** *(Community)* - both agent auth middlewares short-circuited `OPTIONS` by invoking the wrapped handler **without authenticating**. `rs/cors` only answers a preflight that also carries `Access-Control-Request-Method`, so a *plain* `OPTIONS` with a body passed straight through it into the router: an anonymous `OPTIONS /api/v1/decide` returned a real verdict and wrote an `audit_logs` row with empty tenancy. The more dangerous half was `proxyAuthMiddleware`, whose early return sat **above** the tenancy-header scrub while the reverse-proxy Director appends a valid internal HMAC unconditionally - making a preflight the one request shape on which a caller could *supply* `X-Tenant-ID` / `X-Axonflow-User-Role` rather than merely omit them, and have the agent vouch for them downstream. Both middlewares now terminate the preflight (204, handler never invoked), scrub every client-assertable tenancy/authority header on that branch so the guarantee survives a future edit that restores the pass-through, and `handleDecide` / `handleOpenAICompat` refuse a non-POST themselves. Genuine browser preflights are unaffected. (#3092)
- **The orchestrator is no longer published host-wide by any Compose file in this repository** *(Community)* - `docker-compose.yml` bound every published port to all host interfaces, including the orchestrator on 8081; `docker-compose.enterprise.yml` published only minio and the portal, never the orchestrator. In those two customer-facing files all published ports are now bound to `127.0.0.1`, matching the shipped `axonflow-install` bundle. The four remaining files that published 8081 on all interfaces are now bound as well: `docker/docker-compose.base.yaml` (orchestrator 8081, Postgres 5432), `platform/orchestrator/docker-compose.yml` (8081, Postgres 5433, Redis 6380), `docker-compose.test.yml` (all six - Postgres 5432, Redis 6379, agent 8080, orchestrator 8081, customer-portal 8082, Grafana 3000) and `docker-compose.scaled.yml` (the `orchestrator-lb` on 8081). **The most exposed of those bindings were not the orchestrator:** `docker-compose.test.yml` and `platform/orchestrator/docker-compose.yml` each published a Postgres whose password is hardcoded in the file, and the test stack's Grafana ships a hardcoded admin password - all reachable from the local network. Every consumer of these ports is either inside the compose network or on the host itself, so no working setup changes; add a compose override if you need one of them reachable remotely. **Deliberately still published on all interfaces, as out of scope for #3097:** the agent (8080) and dashboard (9001) in `docker/docker-compose.base.yaml`, where the bundled nginx on 80/443 remains the intended ingress, and `agent-lb` (8080), `dashboard-frontend` (9000) and `dashboard-backend` (9001) in `docker-compose.scaled.yml`. If you run either stack and do not want those on the network, restrict them at the host firewall or security group. (#3068, #3097)

- **RBI compliance actors were read from the request body** *(Enterprise)* - eight handlers in the RBI FREE-AI module took the *acting principal* from the JSON body and persisted it as the actor of a compliance action: `requested_by` / `requested_by_email` on an audit export, `generated_by`, `submitted_by`, `approved_by` and `rejected_by` on a board report, `actor_id` / `actor_email` / `actor_role` / `actor_ip` on arming and releasing a kill switch, and `approver` on an AI system's board approval. The whole module was the outlier - a grep for `X-User` across it returned exactly one hit, a CORS header string nothing read - while its siblings `euaiact` and `masfeat` already resolved the actor from `X-User-ID` then `X-User-Email`. **This crosses no tenant boundary and grants no access:** the caller must already hold a credential and #3066 binds every one of these to the authenticated organization. What it defeats is **attribution and non-repudiation** on the artefacts an RBI FREE-AI submission is made of - a board approval, a kill-switch release, an audit-export request - which is the point of recording them. The actor is now derived from the authenticated request through one resolver: the trust-gated `X-User-Email` / `X-User-ID` when a per-user identity is present, otherwise the validated client credential recorded in the reserved `@axonflow.local` synthetic domain so the record reads as *"approved by this credential"* rather than as a named person, otherwise `system`. `actor_role` now states **how** the caller authenticated (`user` or `service`) instead of carrying a free-text claim like `chief_risk_officer` with nothing behind it, and `actor_ip` is taken from the connection rather than from a body field with no relationship to it. Following #3135, the body fields are removed from the wire (`json:"-"`) rather than merely ignored, so a caller-typed identity cannot be read back out by accident. Non-identity body fields - approval notes, rejection reasons, kill-switch reasons - are unchanged. Four of the eight handlers were reachable on the orchestrator's live router and four only through the `ServeMux` registrar; all eight are fixed, and the registrar divergence is left as-is rather than widening the live surface. (#3150)
- **RBI compliance routes took their tenant scope from a client-supplied query parameter** *(Enterprise)* - the RBI FREE-AI handler families resolved the scoping organization from `?org_id=`. On the audit-export family the parameter **outranked** the gateway-stamped `X-Org-ID` header, so any caller could name another organization and read, download, **destroy** (`DELETE` returned 204 and the row was gone) or **run** (`POST .../process` generated the victim organization's full compliance export, wrote the file and marked the row completed) that organization's RBI audit exports. On the other five families (AI-system registry, model validations, incidents, kill switches, board reports) the parameter was a fallback, which still let a caller presenting **no** authenticated organization name any organization it liked. All six families now resolve scope from one choke point that reads only the authenticated `X-Org-ID`, and a whitespace-only header is rejected rather than reaching the repositories as a blank organization scope. (The `rbi_*` tables declare `org_id ... NOT NULL`, so a blank scope would not alias unstamped rows on read - the hazard is the write side, where an INSERT under a blank scope plants a row no later scoped read can reach). A package-level AST guard fails the build if any handler reads a scope-bearing key from a request parameter or re-inlines the header read. (#3066)
- **MCP dynamic-policy evaluation took its tenant scope from the request body** *(Community)* - `POST /api/v1/mcp/evaluate-policies` resolved the tenancy it evaluated under from the body's `tenant_id` and never read the `X-Tenant-ID` header the agent gateway stamps onto every request it proxies. Any holder of a valid credential could therefore name another tenant and receive that tenant's `matched_policies` - `policy_id`, `policy_name`, `action`, and the human-authored `reason` string, which routinely names the control and the data class it guards. The same body field keys the in-memory rate-limit and budget stores, so such a request also consumed the named tenant's shared rate-limit window and budget period: disclosure plus resource consumption, from any credential in the deployment. The handler now selects its plane on whether the request **carries** the stamped tenancy headers - presence, not emptiness, so a hop that stamped an empty tenancy fails closed at **401** rather than falling through to the body. On that plane the authenticated scope is authoritative: a body `tenant_id` naming a different tenant is refused with **403** as an explicit authorization failure rather than silently coerced to the caller's own, one that is absent or matching is replaced by the authenticated value, and `organization_id` is stamped from the authenticated scope so a future consumer of that field cannot inherit a forged one. Scoping still routes through the single per-engine tenant predicate introduced in #3061 - no fourth predicate was added. **The agent's own policy-enforcement hop is unchanged and needs no configuration change:** it authenticates with the internal-service HMAC, sends no tenancy headers, and carries its own validated tenant in the body. That plane is not a fallback a tenant can select - the orchestrator's router-level gate (#3068) admits nothing without the internal-service token, and the gateway stamps the headers on everything it forwards. (#3066)
- **The governed request plane fell back to a body-supplied tenancy** *(Community)* - `POST /api/v1/process` resolved the tenant and organization it evaluated under by overlaying the gateway-stamped `X-Tenant-ID`/`X-Org-ID` onto the decoded body with `if header != ""` and **no else branch**, so a caller reaching the orchestrator without them kept whatever tenancy the body named. That tenancy keys the dynamic-policy set the evaluator loads and the `applied_policies_detail[]` array echoed back on a block, so varying the query while naming a victim tenant **bisected the victim's policy conditions** - policy id, name, action and matched rule - and every attempt also wrote a `policy_metrics` row under the victim's organization. Tenancy is now bound from the authenticated scope before any policy is loaded, any counter is written or any policy name is echoed: a request carrying no bindable scope is refused **401** before the evaluator runs, and a body `client.tenant_id` / `client.org_id` naming a different tenancy is refused **403** as an explicit authorization failure rather than silently coerced. The `X-Org-ID`-versus-deployment-`ORG_ID` comparison stays a diagnostic log and is deliberately **not** escalated to a refusal - on Community-SaaS every customer's organization differs from the deployment's by design. (#3066)
- **Workflow execution and multi-agent planning stamped rows with a body-supplied - or absent - tenancy** *(Community)* - `POST /api/v1/workflows/execute` and `POST /api/v1/plan` carried the same conditional overlay, and their tenancy is what the workflow engine's replay recorder writes onto execution rows and what `CreatePlanRequest.{OrgID,TenantID}` stamps onto the `plans` row. A caller could therefore create rows owned by another tenant or - when the body was silent too - create rows carrying **no tenancy key at all**, which is precisely the unstamped-row class that #3065's fail-open predicates then made readable and writable by every tenant. Both handlers now bind from the authenticated scope and fail closed at **401**, a body tenancy naming a different tenant is **403**, and a write-side guard refuses to persist a row whose `org_id` or `tenant_id` is empty, whitespace or the migration `core/156` unowned sentinel. `POST /api/v1/plan/execute` shares the same binder and is fixed with them. (#3066)

- **Nine SSRF egress classifiers with five distinct behaviours, unified onto one range table** *(Community)* - every surface that dials a configured URL carried its own reserved-IP predicate: the connector layer, HITL `notify_url`, circuit-breaker notifications, orchestrator webhook subscriptions, the orchestrator media fetcher, the SAML metadata fetch and the OIDC issuer/JWKS validator, plus two `ee/` twins that override at Docker build. Measured by execution over 35 probe addresses, **21 were classified differently by at least two of them**. Some divergence was deliberate; none of it was expressed anywhere a test could read. Concretely: `platform/agent/circuitbreaker` and `platform/orchestrator/webhooks` both permitted `0.0.0.0/8` - the loopback bypass `platform/agent/hitl` had identified and closed as "R3 R2 HIGH-2" and never propagated, so an operator-supplied callback URL of `http://0.0.0.0:PORT/` reached the service's own host; and the orchestrator webhook classifier returned "public" for a `nil` IP, so a resolved address it could not parse was dialled. `platform/orchestrator/media` and the SAML metadata fetch each ran a *strong* pre-flight and a *weaker* socket-level check - the layer that exists to catch DNS rebinding and redirects was strictly weaker than the one it backstops, and on a redirect it was the only host check at all. The range table now lives once in `platform/shared/egress`; a surface consumes it through a named `Policy` that lists the ranges it **exempts**, so a range added to the table is blocked on every surface unless a surface names it. Three presets: `ConnectorEgress` (exempts `198.18.0.0/15` only, because `runtime-e2e/3067_cross_tenant_cache_isolation` stands its sentinel backend there), `CallbackEgress` (exempts nothing) and `OIDCLiteral` (exempts loopback, the documented local-dev-issuer allowance). A repo-wide AST guard fails the build if any file outside that package collects reserved-range CIDR literals or declares a classifier-shaped predicate over `net.IP` that is not a single delegation, and a lockstep test fails if either `ee/` twin diverges from its platform original by so much as a line. (#3104, #3095)
- **`2001:db8::/32`, NAT64 and 6to4 were treated as public by all nine classifiers** *(Community)* - the IPv6 documentation range was rejected by none of them (#3101 pinned it as permitted *with a comment* so that closing it would be a visible edit; this is that edit). Separately, four IPv6 encodings carry an IPv4 address that `net.IP`'s predicates do not unwrap: `64:ff9b::7f00:1` (RFC 6052 NAT64), `2002:7f00:1::` (RFC 3056 6to4), `::7f00:1` (RFC 4291 IPv4-compatible, deprecated) and `::ffff:0:7f00:1` (RFC 2765 IPv4-translated, deprecated) all encode `127.0.0.1`, and every classifier called them public. The embedded address is now unwrapped and classified on its own merits, so a wrapped *public* address stays reachable. **This is an observed gap, not a demonstrated exploit** - reaching the embedded address requires the host to have a NAT64/DNS64 path or a 6to4 pseudo-interface, and that was not verified on any AxonFlow deployment. It is closed anyway because a classifier that reports `64:ff9b::7f00:1` as public is wrong on its face and the fix is mechanical. RFC 6052 network-specific prefixes and the RFC 8215 local-use prefix `64:ff9b:1::/48` are deliberately **not** unwrapped (their prefix length is a deployment choice this table cannot know), nor is Teredo `2001::/32` (it carries the client's IPv4 XOR-obfuscated *and* the server's, so which one a dial reaches is not decidable from the address). Both are pinned as permitted with a comment so the omission stays visible. (#3104)
- **The HTTP connector had no socket-level egress guard at all** *(Community)* - `validateHost` ran once, inside `Connect()`, and the transport dialer was a bare `net.Dialer`. Every request after `Connect` re-resolved the operator-supplied `base_url` host with nothing checking the answer, so a host that resolved public at connect time and into a reserved range afterwards was dialled and its response returned to the caller. This was the only egress path in the codebase with no per-dial check whatsoever - on the surface the code itself calls "the weakest and most general-purpose egress path". The transport now uses the same guarded dialer as every other surface; `allow_private_ips` bypasses it exactly as it already bypassed `validateHost`. (#3104)

- **Four callback dialers validated the DNS answer and then dialled the hostname, which resolved again** *(Community)* - HITL `notify_url`, circuit-breaker notifications and orchestrator webhook delivery each resolved the target, checked every returned address, and then handed the untouched `host:port` back to `net.Dialer`. That is a second lookup: a resolver returning a public address to the check and `169.254.169.254` to the dial was allowed through, and the socket was genuinely opened to the cloud metadata service - demonstrated with a rebinding resolver, where only the absence of a listener stopped it. On the HITL surface the hostname is tenant-supplied. All now go through one helper that resolves once, refuses if **any** returned address is blocked, and dials only the addresses it validated, by literal - trying each in resolver order, so multi-record failover is preserved. An empty DNS answer with a nil error fails closed instead of falling through to a dial. The SAML metadata fetch *(Enterprise)*, which already dialled a validated literal, moved onto the same helper: it indexed `ips[0]` with no empty-answer guard and dialled only that one address, losing failover. (#3104)

- **Operator action - circuit-breaker notifications and orchestrator webhooks now refuse ranges they previously accepted** *(Community)* - adopting `CallbackEgress` on those two surfaces means a notification or webhook-subscription URL resolving into `0.0.0.0/8`, `100.64.0.0/10`, `192.0.0.0/24`, the TEST-NET ranges, `198.18.0.0/15`, multicast, `240.0.0.0/4` or `255.255.255.255` now fails - at subscription create/update as well as at delivery. **The most likely real-world breakage is `100.64.0.0/10`: that is carrier-grade NAT *and Tailscale's address range*, so a receiver reachable over Tailscale has an address in it.** Two per-surface escape hatches exist for the migration, both default-off and honoured only for the exact value `true` (`1` and `yes` do not count): `AXONFLOW_CIRCUITBREAKER_NOTIFY_ALLOW_PRIVATE` and `AXONFLOW_ORCH_WEBHOOK_ALLOW_PRIVATE`. There is deliberately **no global egress bypass** - one flag serving several surfaces would make re-permitting one re-permit all. Engaging either emits a startup WARN naming the surface, the variable and every range it re-permits; the pre-existing `AXONFLOW_HITL_WEBHOOK_ALLOW_PRIVATE`, which engaged silently, now logs the same way. **The orchestrator media fetcher moved to `CallbackEgress`, not `ConnectorEgress`** *(Community)* - `media[].url` arrives per request in the governance API body, so it is caller-supplied rather than operator-configured infrastructure. Routing it through `ConnectorEgress` would have been the one place the `198.18.0.0/15` test-harness exemption met untrusted input. Its pre-flight and its socket-level guard now state the same posture, and `198.18.0.0/15` is refused for media while staying permitted for connectors. **Both escape hatches disable their surface's IP guard entirely rather than partially** - with one set, that surface will dial `169.254.169.254`. That matches the pre-existing `AXONFLOW_HITL_WEBHOOK_ALLOW_PRIVATE` and connector `allow_private_ips` semantics, but note it is net-new bypass surface on two surfaces that previously had none, which is why it is default-off, per-surface and loud. The OIDC issuer/JWKS write path is hardened on the same table with **no** hatch: it already refused RFC 1918 without one, so a self-hosted internal issuer was already blocked. Two further surfaces tighten with no hatch and near-zero practical impact, because their own pre-flight already refused everything else: the SAML metadata fetch *(Enterprise)* now refuses `198.18.0.0/15` and the wrapped-IPv4 encodings at the socket, and the connector and orchestrator-media surfaces now refuse `2001:db8::/32` and the wrapped-IPv4 encodings. `allow_private_ips` on connectors is unchanged. (#3104)

- **MAS FEAT compliance module never scoped a single statement to its organization** *(Enterprise)* - migration 400 enables row-level security on all five `mas_*` tables, but `platform/orchestrator/masfeat` (and its `ee/` twin, which is the tree the enterprise image compiles) never called `WithOrgScope` and never set `app.current_org_id`. All 19 statements per tree - 11 reads and 8 writes across the AI-system registry, FEAT assessments and kill switches - ran unscoped. One root cause, two failure directions, **both reproduced on a real `axonflow_app_role` connection before the fix rather than inferred from the migration**: on an `axonflow_app_role` pool `get_current_org_id()` is NULL, so every read returned **silent zero rows** and every write was refused with `new row violates row-level security policy`; on a master/BYPASSRLS pool there was **no database backstop at all**, so application scoping was the entire tenant boundary. The safety-critical case is the kill switch - `GET /api/v1/masfeat/killswitch/{system_id}` answers *"is this AI system halted?"*, zero rows there is spelled `nil`, and `GetOrCreateKillSwitch` turns `nil` into a freshly created **`enabled`** switch, so an RLS-blind read did not merely fail to report a TRIGGERED kill switch, it reported the system as running. Every statement now runs inside `rls.WithOrgScope`; the hand-written `WHERE org_id = $n` predicates are **kept** - the wrap is an additive backstop, not a replacement, verified by a token comparison of every pre- and post-fix SQL body. The five tables are now in `rlsGatedTables()`, so a future unscoped MAS FEAT read or write fails CI. Same class as #3103/#3127 (`rbi_*`); the remaining `euaiact_*` / `ojk_*` / `scim_*` tables in that gap are tracked by epic #3071. (#3133)

### Community

#### Added
- **`AXONFLOW_CORS_ALLOWED_ORIGINS`** - comma-separated exact browser origins (scheme + host + optional port) permitted to call the agent and orchestrator HTTP APIs. `*` is accepted but then credentials are never advertised. Unset means allow-all-without-credentials in Community mode and **deny-all everywhere else**. Documented in `docs/configuration.md` and `.env.example`. (#3096)
- **A lint that a *deployment surface* must set `DEPLOYMENT_MODE`.** `scripts/lint-deployment-mode.sh` previously governed only how the variable is *read* in Go; nothing governed whether it was ever *written*. It now also fails CI when a Compose service or an ECS container definition that runs the agent or the orchestrator omits it. The recogniser resolves Compose build contexts rather than pattern-matching paths, and its default answer for anything it cannot classify with certainty - tab indentation, `extends:`, `include:`, merge keys, anchors, an `env_file:` it cannot read, or a declared agent image no service parse explains - is **fail**, never skip. Compose *override* files must declare themselves with an explicit `# axonflow-lint: compose-overlay` marker, which is reported on every run. (#3117)

#### Changed - behaviour change on upgrade

- **A stack whose `DEPLOYMENT_MODE` is not a recognised value now REFUSES TO BOOT.** Previously it started, logged one warning line, and applied the SaaS migration set. The agent now exits with a message naming the rejected value and listing every accepted one: `community`, `community-saas`, `enterprise`, `evaluation`, `in-vpc-banking`, `in-vpc-enterprise`, `in-vpc-healthcare`, `in-vpc-travel`, `invpc`, `saas`. **Check the value on the agent before upgrading** - a typo, a trailing space, or a capitalised spelling that has been booting quietly will stop the container. This is deliberate: the alternative is a deployment silently running a schema nobody chose. (#3167)
- **An UNSET `DEPLOYMENT_MODE` is unchanged and is still NOT fatal.** It still selects `core/` only, and still means the enterprise posture at *runtime* - the #3128 asymmetry, which this change deliberately does **not** close. Pointing the selector at an enterprise mode was measured against a real PostgreSQL 15: the flip succeeds, 33 applied and 0 failed, and leaves `connector_configs` with no `org_id`, RLS **off** and **zero policies**, plus `sso_configurations` / `sso_sessions` / `sso_login_attempts` with no `org_id` and RLS unforced - because `core/106`, `core/107` and `core/138`, which add exactly those columns and policies, already ran and no-op'd on a stack whose community schema had none of those tables. That is #2782 re-created inside a fix for #3167, and closing it needs a bundled re-repair migration and an operator decision. The measurement and the four options are in `technical-docs/DEPLOYMENT_MODE_MIGRATION_SELECTOR_DECISION.md`; #3167 narrows the population that can reach the asymmetry from "unset or mistyped" to exactly "unset". (#3128)
- `approved_by` / `rejected_by` in the body of a MAP step approve or reject is **ignored**. The request still succeeds - unknown JSON keys are dropped, so no client needs a code change to keep working - but the recorded approver now comes from the caller's authenticated identity headers, or is `"system"` when the request carries none. Two consequences worth checking before upgrading: (1) a fleet whose approvals arrive through the agent with `AXONFLOW_TRUST_IDENTITY_HEADERS` **off** (the default) has its identity headers stripped at the agent, so its MAP approvals will record `"system"` where they previously recorded whatever the client typed - set that flag if you need per-user attribution on this plane, exactly as for the other identity-attributed surfaces; (2) an automation that supplied a human's name in the body to make an unattended approval look reviewed will now record `"system"`, which is the honest answer and is what the WCP plane has always recorded for the same request. Historical rows are untouched. (#3135)
- Deployments with `MCP_DYNAMIC_POLICIES_ENABLED=true` **and** a dynamic policy stored with `tenant_id = 'global'` or a NULL `tenant_id` will begin enforcing that policy on MCP tool calls - for **any** MCP-admitted policy type, not only `content`. This is the correction above, not a new capability: the policy already enforced everywhere else. Single-tenant policies are unaffected, and cross-tenant isolation is unchanged - a policy belonging to another tenant is still never evaluated. (#3061)
- The condition-less fail-safe (a dynamic policy carrying zero conditions no longer matches, so a `block` action on such a row cannot deny every call for its tenant) applies to `mcp` and `connector` policy types as well as `content`. **This is a deny → allow change.** `POST /api/v1/policies` rejects a zero-condition policy, but `PUT /api/v1/policies/{id}` and `PUT /api/v1/dynamic-policies/{id}` accept `"conditions": []` and clear them - the update path guards on `!= nil`, and an empty JSON array is non-nil with length zero - so a tenant that cleared a policy's conditions while leaving a `block` action attached **does** have such a row today. A conditions JSON the engine cannot unmarshal produces the same shape. **Audit for zero-condition `block` policies before upgrading.** Note the fail-safe is MCP-plane only: on the LLM/MAP/WCP planes a zero-condition policy still matches and still denies. (#3061)


#### Fixed
- **Three shipped Java examples did not compile, and nothing in CI compiled any of them** *(Community)* - `examples/` rsyncs to the public community mirror, so these are artifacts a reader gets: `examples/cost-controls/enforcement/java` imported `com.axonflow.sdk.*` (the published SDK ships `com.getaxonflow.sdk`) and additionally referenced an undeclared variable, so it could never have compiled against any SDK version; `examples/llm-providers/mistral/hello-world/java` referenced `PreCheckResult` and `ProxyLLMCallResult`; `examples/mcp-connectors/cloud-storage/java` referenced `ConnectorMetadata` and called a three-argument `mcpExecute`. None of those four symbols exists in `axonflow-sdk` 9.0.0. **Two corrections to the filed diagnosis, established by compiling each project:** the mistral failures are `PreCheckResult` and `ProxyLLMCallResult`, not `ProxyLLMCallResult` and `TokenUsage` - `TokenUsage` is present - and cloud-storage's only missing type is `ConnectorMetadata`; `ConnectorResponse` is present. All three now build against 9.0.0's actual API, and the enforcement example's source package and its `<mainClass>` agree, so `mvn exec:java` reaches `main` instead of failing to resolve the class. Three runtime defects that compilation cannot see were fixed alongside, each confirmed by running the example: the mistral example threw `userToken cannot be null` before its first HTTP call (`PolicyApprovalRequest` requires one, unlike `ClientRequest`); all three passed the LLM provider through `ClientRequest.llmProvider()`, which serialises as `llm_provider` and is a field no platform struct carries - the provider is read from `context["provider"]`, so those calls silently used the deployment default; and both LLM examples tested `response.isBlocked()` on a returned value, which `proxyLLMCall` can never produce because it throws `PolicyViolationException` on a block first, making the SQLi demonstration reachable only via an uncaught stack trace. The enforcement example's four `BudgetInfo` assertions are replaced by three equivalents on `getBudgetStatus` (the fourth, presence of `BudgetInfo` itself, has no equivalent and is dropped), because the SDK discards the 402 body; both SDK gaps are recorded in #3192 rather than papered over. **The same two defects remain in ~13 other Java examples** - they were not swept here because 13 behavioural edits cannot be verified by compilation, which is exactly what failed to catch them; enumerated with evidence in #3202. **Why this was invisible:** nothing in `.github/workflows/` ran `mvn` at all before #3155, and what #3155 added is `dependency:go-offline` - a project whose sources reference deleted symbols *resolves* perfectly and still cannot be *built*. A new `Java Examples Compile` workflow now compiles every project under `examples/` on the JDK each pom declares (57 declare 11 or 17, `examples/llm-providers/azure-openai/hello-world/java` declares 21), failing rather than falling back when a declared level has no installed JDK, and failing when a build exits 0 having emitted no class files or having produced no class matching a declared `<mainClass>` - `mvn compile` on a project with no source root is BUILD SUCCESS, and a `<mainClass>` naming a package the class does not declare compiles fine while `mvn exec:java` cannot run. It is a separate workflow, not a step in `security.yml`, because `Security Scan Summary` is a required check whose filter fires on nearly every product PR; the compile job here is gated behind a `detect-changes` filter so a PR touching no example reports in seconds without a JDK, while still reporting a `Java Examples Summary` check that an operator can make required. Its own fail-closed properties are mutation-tested in `tests/regression-test-required/java_examples_compile_gate_test.sh`, which also runs as a step of the workflow - including an assertion that the goal really is `compile` and not a resolve-only goal, without which this gate could be reverted to the `dependency:go-offline` behaviour it exists to replace and stay green. What the per-project JDK selection does **not** prove: every pom declares its level through `maven.compiler.source`/`target` rather than `release`, so a project declaring 11 can still call a Java 16 API and build clean on JDK 17; moving the poms to `maven.compiler.release` is tracked in #3197. **The Jackson override pins in the example poms are deliberately retained**: `axonflow-sdk` 9.0.0 is still on jackson 2.17.0 on Maven Central and the SDK-side bump is prepared but unreleased, so dropping them would put the vulnerable jars back on every reader's compile classpath; the two stale pin notes that still named "SDK 5.5.0" and only the Moderate advisory are corrected to name the current SDK line and all seven advisories the pin clears. (#3185, #3158, #3110)
- **The `DEPLOYMENT_MODE` surface lint checked presence, never value, and its feed was two globs** *(Community)* - the check added earlier in this release tested for the substring `DEPLOYMENT_MODE` anywhere in a service block. `DEPLOYMENT_MODE: ""`, `${DEPLOYMENT_MODE}` with no `:-` default, a trailing comment reading `# TODO: set DEPLOYMENT_MODE`, the unrelated `NEXT_PUBLIC_DEPLOYMENT_MODE`, and - the one that mattered - an **unrecognised value** all satisfied it. `enterprise` was unrecognised by the migration selector for the entire life of that lint, on surfaces the lint scanned, and it reported ✅ on every run. The key is now anchored and the **value** is validated against the recognised set, which the Go side pins so the two lists cannot drift. Five further fail-open leaks are closed with it: an `image:` that names an agent or orchestrator under a non-canonical repository (`${REGISTRY}/af-agent:${TAG}`) is now UNPARSEABLE rather than silently skipped; discovery is the union of the old name globs and *any* YAML with a top-level `services:` key, so a Compose file named `stack.yml` is no longer invisible; ECS **container definitions** are counted individually rather than one-per-task-definition; `Value: !Ref <Param>` is resolved against that parameter's `AllowedValues`, and a parameter with none is refused because any string then reaches the container; and the scan root is derived from the script's own path rather than `$PWD`, with a floor assertion listing six named root surfaces - each required only if its file is present, because this script is rsynced to the public community mirror where `ee/` does not exist, and at least two must be satisfied overall - so a run against a tree the lint never saw fails instead of reporting a vacuous pass. The feed now also covers `docker run` launchers in non-test shell scripts and workflows - resolving simple `VAR="literal"` assignments first, which is what makes `docker run … $IMAGE` in **`scripts/marketplace/deploy-with-metering.sh`, the AWS Marketplace production deploy path**, visible at all - and the published `platform/agent` and `platform/orchestrator` READMEs, whose Kubernetes manifest shipped with no `env:` block. Test-harness prefixes are excluded, and both the exclusions and every `docker run` whose image never resolved to a literal name are **printed on each run**, so the residual gap is visible rather than implied. (#3170, #3137)
- **Four CI guards reported success without checking** *(Community)* - all four are test infrastructure; no product behaviour changes. (1) `tests/regression-test-required/openapi_validator_synthetic_failure_test.sh` exited 0 with `skip: swagger-cli not installed locally` and wrapped its spectral section in `if command -v spectral`. Neither tool ships on the GitHub-hosted runner and the job installed neither, so the entire synthetic-failure half - the part proving the OpenAPI gate would *reject* a broken spec - never ran; both are now hard failures, the job installs both at pinned versions, `masfeat-api.yaml` joins the three specs the guard pinned, and positive controls catch a linter that rejects everything. (2) The partner-name denylist gate's hand-maintained `paths:` filter missed 111 of the 2,575 files that sync to the public mirror, including `CHANGELOG.md`, `README.md`, `VERSION`, `Makefile`, `tests/**` and 24 workflows; the filter is removed - a static `paths:` list cannot be derived from the sync workflow's rsync rules at trigger time, so no filter is the only formulation that covers what syncs by construction - and a new regression test replays those rules and fails if any synced file would not fire the gate. (3) The production-posture runner now refuses a *self-booting* registry entry before dispatching anything, and refuses a registry that declares zero entries; `runtime-e2e/3060_community_saas_reads` moves to its own workflow, which removes the specific mechanism that let buildkit eat the dispatch loop's stdin. (4) `runtime-e2e/3068_orchestrator_authn` - the runtime proof for the orchestrator authentication gate - was registered nowhere and ran nowhere; it is now a posture-registry entry, with the three credentials it needs exported by the job so its prerequisite doors fail rather than skip. (#3140, #3122, #3115, #3105)
- **Transitive Java CVEs were invisible to CI, and 51 shipped example projects carried them** *(Community)* - the Trivy filesystem scan runs with `TRIVY_OFFLINE_SCAN=true` (it exists to avoid a FATAL crash resolving a remote parent POM), but offline mode disables *resolution*, not the analyzer - anything transitive or BOM-imported is invisible unless the analyzer can read it from a local Maven repository, and the job had no `setup-java`, no `mvn` and no `~/.m2`. Measured against one consumer pom: offline + empty `~/.m2` reported **0** findings, offline + warm `~/.m2` reported **5**. Maven dependency scanning was therefore effectively off, which is why #3110's jackson exposure - which reached consumers transitively - could never have been caught in CI. The job now warms `~/.m2` with `mvn dependency:go-offline` over exactly the pom set Trivy will scan, fails if any pom cannot resolve, and asserts the resulting repository is genuinely populated rather than trusting the loop's exit code. With the scan un-blinded, **51 example projects reported CRITICAL/HIGH findings**: 50 pulled `jackson-databind` 2.17.0 transitively from the SDK (CVE-2026-54512, CVE-2026-54513) and are now pinned to 2.22.1, and `examples/integrations/spring-boot` is bumped to Spring Boot 3.5.14 + Tomcat 10.1.55 (CVE-2026-40973; CVE-2026-41293 / -43512 / -43515 CRITICAL and CVE-2026-41284 / -42498 / -43513 HIGH). A further **19 poms under `ee/examples/`** carry the identical transitive exposure and are pinned the same way; they are outside the scanner's `skip-dirs` and outside the community sync, so nothing would have reported them either - the earlier #3110 note that "the pins cover the `examples/` and `ee/examples/` poms" was true of `jackson-core` and not of `jackson-databind`, which is the artifact the CVEs are in. Every Trivy action reference is also pinned to a release SHA rather than `@master`. **Operator note:** with Java resolution working, a future transitive CVE in an example dependency will now fail the Security Scan job, where previously it was silently invisible. (#3116, #3110)
- **Removing the orchestrator's load balancer by omitting `LoadBalancers` was a silent no-op that stops the service placing tasks** *(Community + Enterprise)* - #3068/#3073 deleted the `LoadBalancers:` block from `OrchestratorService` in both CloudFormation templates. Established by execution against a throwaway stack, not by reading: on an **update** of an existing stack CloudFormation reports `UPDATE_COMPLETE`, deletes `OrchestratorTargetGroup`, and leaves the live service's `loadBalancers` entry **untouched**, still naming the target group it just deleted. ECS then places no task at all - `desiredCount 1, runningCount 0, pendingCount 0`, no task, no failure event, `"has reached a steady state"`. With the same template but an explicit `LoadBalancers: []` the association really is cleared and the service places tasks normally. The two are **indistinguishable in a change set** - both plans read `Modify OrchestratorService … Details: [LoadBalancers, …]` - so a dry run would not have caught it. Both templates now set the explicit empty array, which is the idiom AWS documents for this property and for `UpdateService`. Fresh deploys were never affected. (#3100)
- **`AXONFLOW_CORS_ALLOWED_ORIGINS` was documented but unreadable by any deployment surface** *(Community + Enterprise)* - #3096 introduced the variable as the escape hatch from its own deny-by-default policy and documented it in `.env.example` and `docs/configuration.md`, but neither the bundled `docker-compose.yml` nor the marketplace CloudFormation template passed it to the agent or the orchestrator. An operator following the documentation set a variable no process read, and their browser stayed blocked with no signal that the setting had not taken. Every non-community Compose surface now takes `${AXONFLOW_CORS_ALLOWED_ORIGINS:-}`, and both the marketplace and the community-SaaS templates gain a `CorsAllowedOrigins` parameter (default empty) wired into their agent and orchestrator task definitions. `community-saas` needed it as much as the partner path: `isCommunityMode()` matches `community` exactly, so that deployment is in the deny-all branch too. An empty value is indistinguishable from unset to `os.Getenv`, so the deny-by-default posture is unchanged - the lever simply exists now. Pinned by `tests/community-saas/cors_surface_test.py`, which is a census over every Compose file and every ECS task definition rather than a list - run over the whole tree it found three surfaces a hand-fix had missed. (#3129)
- **The partner-template parity guard passed on a missing file** *(Community)* - `scripts/check-partner-template-parity.sh` warned and exited 0 when the partner copy in `axonflow-install` was absent, so it reported "OK" for the one state in which it had verified nothing; and because it compared only header-stripped bodies, two templates each truncated to their header block compared equal. Absence and truncation are now distinct hard failures (exit 3 for the partner side, 2 for the canonical), checked on both files, and `infra-validation.yml` treats them as errors on pull requests as well as on `main` - unlike content drift, which stays advisory on a PR because it is legitimately transient while a cross-repo round is open. 39 mutation tests in `tests/community-saas/partner_parity_guard_test.py` pin each condition, including tests that execute the workflow's own `run:` block at every exit code so a caller that flattens them cannot pass. (#3129)
- **`HealthCheckGracePeriodSeconds` had the identical silent-no-op defect as `LoadBalancers`, and the reason given for not fixing it was untested and false** *(Community + Enterprise)* - the same commit that removed the orchestrator's load-balancer association also deleted `HealthCheckGracePeriodSeconds: 600` from `OrchestratorService` in both CloudFormation templates, and left a comment asserting that ECS *rejects* the property on a service with no load balancer ("The health check grace period is only valid for services configured to use load balancers"), offered as the reason it could not simply be set to `0`. Omitting a CloudFormation property means "no change", so on an in-place `update-stack` the live service kept its `600` while a fresh deploy got `0` - permanent, invisible fresh-versus-upgraded drift, on the plane that governs every decision. Current AWS documentation says the grace period suppresses "Elastic Load Balancing, VPC Lattice, **and container** health checks", and `OrchestratorTaskDefinition` has a container `HEALTHCHECK`, so an upgraded stack ignored an unhealthy orchestrator for ten minutes where a fresh one acted immediately. **Settled by execution against a throwaway stack, not by reading** - a change set cannot discriminate here either, for the same reason as #3100. The refusal claim is **false** on the current API: a fresh `CreateService` with `LoadBalancers: []` and a grace period of `111` is accepted and reports `111`; an `update-stack` that clears the association and sets the grace period in the **same** update is accepted, reports the new value, and leaves the service running; and `aws ecs update-service --health-check-grace-period-seconds 0` against an already-load-balancer-less service is accepted. Both templates now set an explicit `HealthCheckGracePeriodSeconds: 0`, which converges fresh and upgraded stacks. Startup tolerance is unaffected - it comes from the container health check's own `StartPeriod`, which the grace period only ever *suppressed*. Pinned in `tests/community-saas/cfn_template_test.py`, parameterised over both templates and mutation-tested against omission, against `600`, and against any non-zero value. (#3164)
- **A wildcard *pattern* in `AXONFLOW_CORS_ALLOWED_ORIGINS` granted credentialed cross-origin access to every matching origin, while the documentation said it matched nothing** *(Community + Enterprise)* - #3096 guarded the literal `*` (which drops credentials) but treated `https://*.example.com` as an ordinary entry and enabled credentials for it. `github.com/rs/cors` does **not** compare entries as exact strings: it splits an entry on the first `*` and matches prefix + suffix, so that entry admitted every subdomain. Every surface that documented this variable stated the opposite ("no wildcards inside an entry and no suffix matching"), so an operator writing such an entry had every reason to believe it was inert. All five are corrected: both CloudFormation parameter descriptions, `docs/configuration.md`, `.env.example`, and `technical-docs/CUSTOMER_PORTAL_ARCHITECTURE.md`. Measured, not inferred: with `AXONFLOW_CORS_ALLOWED_ORIGINS=https://*.example.com`, a preflight from `https://evil-sub.example.com` came back `Access-Control-Allow-Origin: https://evil-sub.example.com` **and** `Access-Control-Allow-Credentials: true`. Such an entry is now honoured - silently dropping a configured origin is its own failure mode, and it does match - but **credentials are not advertised for any entry in the list**, and a warning is logged once at startup. Credentials remain enabled only for a list of exact origins, which is the only case where the admitted set is one somebody wrote down. This applies to the agent and the orchestrator as much as to the customer-portal: the policy now resolves in one place. (#3161)
- **The orchestrator's replacement alarm claimed a sensitivity it does not have, and could go silent without anyone noticing** *(Community + Enterprise)* - `OrchestratorTaskCountAlarm` (`ECS/ContainerInsights` `RunningTaskCount`) replaced `OrchestratorUnhealthyHostAlarm` (`AWS/ApplicationELB` `UnHealthyHostCount`) when #3068 removed the target group, and its description said it fires on a task "crash-looping **or failing its container health check**". The second half is true only indirectly and minutes late: `RunningTaskCount` moves only once ECS has already *stopped* the task, which needs `Interval 30 × Retries 10` - plus the `180s StartPeriod` on a task that never became healthy - before ECS acts, then two evaluation periods. That is 7-10 minutes against roughly 90 seconds before. The description now states what it detects, what it does not, and how stale a page from it is; a test asserts those numbers are still the ones `OrchestratorTaskDefinition` actually uses, so retuning the health check without updating the description fails CI. `TreatMissingData` also moves from `notBreaching` to **`breaching`**: this is the only alarm on the orchestrator, so under `notBreaching` anything that stopped the metric publishing resolved it to OK and the control plane lost its last monitor silently and permanently. The cost was measured rather than assumed - once `RunningTaskCount` starts publishing it is gapless (37/37 consecutive one-minute datapoints across three services, zero gaps), but it does not begin until about three minutes after the cluster is created, so a **brand-new** stack now shows this alarm in ALARM for three to five minutes and then clears itself. It should not recur on `update-stack` - the series already exists by then, and `MinimumHealthyPercent: 100` holds the running count at desired through a task replacement - though that one is reasoning, not measurement: the probe stack was a fresh cluster and no `update-stack` was run against the alarm itself. **The same argument for `breaching` applies to the three alarms left at `notBreaching` in both templates - `AgentUnhealthyHostAlarm`, `DatabaseConnectionAlarm` and `High4XXErrorAlarm` - and they are deliberately not changed** - #3162 is scoped to the orchestrator alarm, and widening it to alarms whose metrics come from the load balancer and from RDS is a separate change with a separate blast radius. A genuinely faster signal is not available from a CloudWatch metric - Container Insights publishes no per-container health-check state - so closing that gap needs new machinery and stays open on #3162 rather than being invented here. **Note for anyone relying on these alarms: `AlarmNotificationTopic` ships with no subscriptions in either template, so by default every alarm in them is a console state and not a notification.** (#3162)
- **The customer-portal shipped a second, hardcoded, credentialed CORS allowlist that a self-hosted operator could neither remove nor extend** *(Community + Enterprise)* - `ee/platform/customer-portal/main.go` installed its own policy, independent of the resolver #3096 introduced, with `AllowCredentials: true` over `localhost:3000`, `localhost:3001`, `https://customer.getaxonflow.com`, `https://app.getaxonflow.com`, and **a bare IPv4 address on port 80 and on port 3000**. That address is not AxonFlow infrastructure: it holds no Elastic IP and no network interface in any region of the account, and it lies in `3.64.0.0/12` - the eu-central-1 EC2 pool, from which AWS reassigns addresses to whichever customer next requests one. It is a leftover from an EU staging load-test host decommissioned in April. (Deliberately not reproduced here: this file is published, and the whole point is that somebody unrelated may hold that address now. It is named in the code comment and in the regression tests, which are not.) Unlike the `*`-plus-credentials pairing #3096 removed, which no browser honours, **a named allowlist paired with credentials is honoured**, so this was live rather than latent: every stack built from the image advertised credentialed cross-origin access to an origin its operator did not control, with no environment variable and no stack parameter behind it. The portal now resolves its policy through a new shared package, `platform/shared/corspolicy`, which the agent and the orchestrator also read - the duplication is what drifted - and `AXONFLOW_CORS_ALLOWED_ORIGINS` reaches it through the existing `CorsAllowedOrigins` stack parameter on `CustomerPortalTaskDefinition` and through `docker-compose.enterprise.yml`. One branch differs deliberately: the portal API is authenticated by a session cookie, and `*` can never be paired with credentials, so in **Community mode only** and only when nothing is configured it falls back to `http://localhost:3000` and `http://localhost:3001` *with* credentials, for local `next dev` front ends. `community-saas` is not Community mode and gets no such carve-out. `infrastructure/cloudformation/community-saas-ecs.yaml` declares no customer-portal task definition at all, so there was nothing to wire there. (#3161)
- **The staging smoke test could not fail** *(Community)* - `.github/workflows/staging-session.yml` ran a five-attempt retry loop per endpoint and then simply ended: nothing recorded the outcome, nothing exited non-zero, and the next line printed `✅ Smoke tests complete` unconditionally, so the job summary reported `Smoke Tests | success` whatever had happened. #3073 turned that from latent into active by removing the orchestrator's ALB listener, which made the `8081/health` probe permanently unsatisfiable - the step failed five times, slept 50 seconds, and still reported success, so **the staging leg of a deploy sequence was green by construction.** The dead probe and the summary line advertising it are gone (the orchestrator is reached over private service discovery, not the load balancer); exhaustion is now tracked per endpoint and exits 1; an unreadable, `None` or `pending` load-balancer address fails instead of being curled as a hostname; and an emptied endpoint list fails instead of passing vacuously. Proven by making it fail: `tests/community-saas/staging_smoke_guard_test.py` extracts the workflow's own `run:` block and executes it against stubbed `aws` and `curl`, asserting the exit code on the success path, on six failure paths, and on a positive control that would catch a harness which always reports failure. `infra-validation.yml` is also now triggered by `staging-session.yml`, which it was not - the suite guarding that workflow would not have run for the edit it guards against. (#3106)
- **Tenant policies created by `axonflow_create_tenant_policy` now enforce on MCP tool calls** *(Community)* - the Pro tool (exposed by all four host plugins) reported "It will apply to subsequent governed calls", but the policy could never block one in any configuration: the MCP evaluator dropped `policy_type='content'` before evaluation, and it could resolve neither the `query`/`statement` field nor the `regex` operator that the tool writes. Content policies are now evaluated on the MCP tool-governance plane, `query`/`statement` resolve to the governed statement, and `regex` matches the orchestrator content engine's semantics exactly (unanchored, case-sensitive, compile-error fails safe). (#3061)

#### Changed
- `total_policies` in the policy-simulation response is now tenant-scoped rather than deployment-wide. Integrations that treated it as a deployment-level total will see a smaller number. (#3059)
- `GET /api/v1/policies/dynamic` requires a resolvable tenant. Requests reaching the orchestrator without the gateway-stamped tenant header now receive 401 instead of a policy list. Callers going through the AxonFlow Agent are unaffected - the agent sets that header from the validated credential. (#3059)
- **BEHAVIOR CHANGE - `content` policies now govern MCP tool calls where the dynamic plane is enabled** *(Community)* - `content` is the DEFAULT policy type (`refreshPolicies` coalesces a null `policy_type` to `'content'`), so on a deployment already running with `MCP_DYNAMIC_POLICIES_ENABLED=true`, existing tenant policies of the form `{query contains|regex …} + block` begin governing MCP tool calls on upgrade, where previously they governed only the LLM / MAP / WCP planes. Deployments on the default posture (`MCP_DYNAMIC_POLICIES_ENABLED=false`, both Docker-Compose and the community-SaaS CloudFormation template) are unaffected until they opt in. Note that a condition naming a field the MCP evaluator cannot resolve fails to no-match, but a KNOWN field with a negated operator can match on an empty value - for example `{user.role not_equals "admin"}` is true when the role is unset, which is common on this plane. Review tenant `content` policies before enabling. (#3061)
- **`axonflow_create_tenant_policy` now reports real enforcement state** *(Community)* - the response carries an `enforced` boolean and, when the policy is inert, an `enforcement_blocked_reason` naming the lever to flip, instead of an unconditional success promise that was false on every default install. It also discloses that `connector_type` is recorded but **not** enforced as a scope (the policy matches its pattern on every governed connector), and that only the `block` action denies on this plane. (#3061)
- **`POST /api/v1/mcp/evaluate-policies` derives its tenancy from the authenticated caller, not from `tenant_id`.** On a request carrying the gateway-stamped tenancy headers the body field is now an assertion that is checked, not a selector: naming a different tenant returns **403**, and naming the caller's own tenant - or omitting the field entirely, which previously returned `400 tenant_id is required` - evaluates the caller's own policies. `organization_id` in the body is ignored and overwritten on that plane. Callers going through the AxonFlow Agent are unaffected; so is the agent's own connector-governance hop, which reaches this route header-less over the internal-service credential and still takes its tenant from the body. Two narrower changes: a proxied request whose deployment resolves an **empty** organization now returns 401 instead of evaluating (both dimensions are required - every shipped mode populates the org, so this is the contract the cost, webhook and workflow-control routes already ship with), and a whitespace-only `tenant_id` on the internal-service plane now returns 400 instead of reaching the engine verbatim, where it matched almost nothing and looked like a successful evaluation. (#3066)
- **The four governed request-plane routes require an authenticated tenancy.** `POST /api/v1/process`, `POST /api/v1/workflows/execute`, `POST /api/v1/plan` and `POST /api/v1/plan/execute` now return **401** when the request does not carry both `X-Org-ID` and `X-Tenant-ID` with usable values, instead of falling through to the tenancy named in the request body. Both are set from the validated credential by the AxonFlow Agent - on the reverse-proxy path and on the agent's own governed forward - and by the customer portal's orchestrator proxy, so **callers going through either are unaffected**. Anything addressing the orchestrator directly must present them, on top of the internal-service token #3068 already requires. Note the requirement is on **both** dimensions: a deployment that resolves an organization but no tenant, or the reverse, is refused rather than half-scoped. (#3066)
- **A request body naming a different tenancy is refused, not corrected.** `client.tenant_id`, `client.org_id` and `user.tenant_id` in the bodies of those four routes are now assertions that are *checked* against the authenticated scope: naming a different value returns **403**, and naming the same value - or omitting the field, which remains the normal case - proceeds. Previously a divergent value was silently replaced whenever the header happened to be present, so a misconfigured client got a working request under a tenancy it did not ask for. `user.org_id` is the one exception: the agent **derives** it from the user JWT rather than receiving it as an assertion, and it legitimately differs from the licensed organization, so it is overwritten from the authenticated scope without being refused. (#3066)
- **The community mirror no longer receives CI workflows it cannot satisfy** *(Community)* - the sync excludes `ee/`, `runtime-e2e/` and the `*_enterprise.go` half of every `//go:build` tag pair, but shipped 13 `*-e2e.yml` workflows that drive `runtime-e2e/` suites plus `migrations-gate.yml`, which runs `go test -tags enterprise`. On the mirror an enterprise-tagged build selects the absent half of each build-tag pair and every symbol in it goes undefined, so those 14 checks were guaranteed-red - and one of them feeds the **required** `Test Summary`, which blocked the release PR. They are now excluded, the `*-e2e.yml` case by a pattern derived from the `runtime-e2e/` exclusion rather than by a list of names, so a new e2e workflow is covered without anyone remembering to add it. A guaranteed-red required check on a public repository is worse than no check: it trains every contributor to merge past it. (#3215)
- **`TestShellCopiesOfRecognisedModesMatchGo` no longer fails on a community checkout** *(Community)* - the test pins three shell copies of the recognised deployment-mode list against the Go source, but the sync re-includes only `scripts/lint-deployment-mode.sh` by name from an otherwise wholesale `/scripts/*` exclusion. Its two siblings cannot exist on the mirror, so the test read a missing file and reddened community CI for a reason unrelated to the community payload. A missing file is now skipped **only** when the checkout is positively identified as a community one by the absence of `ee/`; absent-with-`ee/`-present still fails, because "the script was deleted or moved" is exactly the drift this test exists to catch and a bare `os.IsNotExist` skip would have reported success for it. (#3215)

### Enterprise

#### Changed
- **BEHAVIOUR CHANGE - the five MAS FEAT kill-switch routes now fail loudly on a request that resolves no organization.** These five routes are served from a gorilla/mux registration (`platform/orchestrator/run.go` calls `masfeatModule.RegisterRoutesWithMux`), and each mux entry dispatches straight into a kill-switch sub-handler. The `400 X-Org-ID or X-Tenant-ID header required` guard lives in `handleKillSwitchRoute`, which belongs to the `http.ServeMux` registration the served binary never uses - so no request reaches it, and the five sub-handlers carry no guard of their own. A caller presenting neither `X-Org-ID` nor `X-Tenant-ID` therefore reached the repositories with a blank organization. Before this change that meant `WHERE ks.org_id = ''`, which matches nothing: `GET /api/v1/masfeat/killswitch/{system_id}/history` answered `200 {"history":[],"count":0}` - a clean, empty, wrong answer. It now fails with **500**, because `rls.WithOrgScope` refuses a blank scope by construction. **That refusal is currently the only control preventing those five routes from operating under a blank organization scope** - it is the live control here, not defence in depth. Two rough edges are tracked rather than fixed inside this security diff: the failure should be the intended `400` rather than a `500`, and the response body echoes the internal error string `rls.WithOrgScope: orgID must be non-empty (cross-org work belongs on the admin role)` to the client (#3177). **Kill switches only** - the registry (`/api/v1/masfeat/registry*`) and assessment (`/api/v1/masfeat/assessments*`) families place the same guard inside their handler bodies, so it survives gorilla routing and those routes genuinely have no behaviour change. Callers going through the AxonFlow Agent are unaffected: it stamps the organization from the validated credential. Community builds are unaffected - the MAS FEAT route registration is a no-op there. This is not the only HTTP-visible change on this train: the `rows.Err()` bullet below is a separate one, on a different set of routes and for a different reason. (#3133)
- **`KillSwitchRepository.RecordHistory` takes an explicit `orgID` parameter.** `mas_kill_switch_history` has no `org_id` column - migration 400 resolves its owner through `kill_switch_id IN (SELECT id FROM mas_kill_switches WHERE org_id = get_current_org_id())` - so there is nothing on the entity to derive the wrap's organization from. Internal Go API of an Enterprise-only package with no callers outside it; no HTTP surface changes. (#3133)
- **A MAS FEAT kill-switch history entry can no longer be attached to another organization's kill switch, on any pool.** `mas_kill_switch_history` has no `org_id` column, so - uniquely in this package - there was no hand-written predicate for the RLS wrap to back up, and migration 400's `WITH CHECK` is inert wherever RLS does not apply (`axonflow_platform_admin`, or a master pool on a deployment that has not adopted the app role). The `kill_switch_id` foreign key proves only that the parent row exists, not that the caller owns it. The INSERT now carries its own ownership predicate (`INSERT … SELECT … WHERE EXISTS`) and checks `RowsAffected`, because a refused insert affects zero rows and is otherwise silent at the Exec boundary. Callers recording history against their own kill switch are unaffected. (#3133)
- **Row-iteration errors in the MAS FEAT list readers now surface.** `RegistryRepository.List`, `AssessmentRepository.List`, `RegistryRepository.CountByStatus` and `KillSwitchRepository.GetHistory` discarded `rows.Err()`, so a failure part-way through a result set returned a truncated slice with a nil error. They now return the error. (#3133)
- **Unaffected, checked deliberately:** #3127 found that `rbi_kill_switches` rows with `scope='global'` carried the *creating* tenant's `org_id`, so scoping them narrowed a cross-tenant halt to one tenant. `mas_kill_switches` has **no `scope` column** - it is `UNIQUE(org_id, system_id)` and always organization-scoped - so no MAS FEAT kill switch ever spanned tenants and there is no equivalent behaviour change here. (#3133)
- **`/api/v1/rbi/*` no longer accepts an `org_id` query parameter.** It is ignored: every route derives its organization from the gateway-stamped `X-Org-ID` header. A client that passed `?org_id=` to select an organization now operates on its own. The in-repo `ee/examples/compliance/audit-export-cloud/*` samples pass their own client identifier and are unaffected. (#3066)
- **`/api/v1/rbi/audit-exports*` returns 401 instead of 400 when no organization can be resolved.** The other five RBI families already returned 401; the audit-export family returned `400 MISSING_ORG_ID`. Callers going through the AxonFlow Agent are unaffected - it sets the header from the validated credential. (#3066)

### Migration

#### `DEPLOYMENT_MODE` - do this before upgrading (#3167, #3128, #3168)

- **Internally-deployed stacks: `deploy-application.yml` no longer overrides the mode your environment config declares.** The workflow hardcoded `DEPLOY_MODE="enterprise"` in three places and **stripped and replaced** `DEPLOYMENT_MODE` on the agent, orchestrator and portal task definitions, so `production-us` (config: `saas`), Banking (`in-vpc-banking`) and Healthcare (`in-vpc-healthcare`) were all deployed as `enterprise` regardless. That was invisible while `enterprise` fell through to the widest migration set; with the alias it would have silently stopped selecting `migrations/industry/` on the whole fleet - no future industry migration would ever have reached production, and a rebuilt stack would have come up without those tables. The declared value now wins, is validated against the recognised set before anything is registered, and the old hardcoded pair remains only as the fallback for a config that declares none (`staging` is the one such config today). **One behaviour change worth knowing: `production-us` now deploys as `saas`, and the portal's first-boot credential bootstrap is enabled for `enterprise`/`in-vpc-*` and not for `saas`** - an existing stack's credentials are untouched, but the portal will stop auto-provisioning the deployment org on that stack. Banking and Healthcare see no portal change (`in-vpc-*` keeps the bootstrap, and both already resolved to the SaaS portal shape).
- **An UNSET `DEPLOYMENT_MODE` still boots and still selects `core/` only.** Nothing about the unset case changes on this upgrade.
- **`scripts/marketplace/deploy-with-metering.sh` now REFUSES to run without an explicit `DEPLOYMENT_MODE`.** It had none, so its containers ran the community schema under the enterprise runtime posture. Neither default was safe to pick for you: `community` would disable authentication on a production Marketplace deployment, and an enterprise mode would apply ~33 previously-unapplied migrations to a live customer database - the #3128 decision, not a deploy script's to take. Pass the mode: `DEPLOYMENT_MODE=in-vpc-enterprise bash scripts/marketplace/deploy-with-metering.sh …`.
- **Read the value on the agent and the orchestrator, and confirm it is one of:** `community`, `community-saas`, `enterprise`, `evaluation`, `in-vpc-banking`, `in-vpc-enterprise`, `in-vpc-healthcare`, `in-vpc-travel`, `invpc`, `saas`. Anything else - including a leading space or a capitalised spelling - now **stops the agent at boot** instead of silently applying the SaaS schema. `docker compose exec axonflow-agent printenv DEPLOYMENT_MODE` answers it.
- **If you run `DEPLOYMENT_MODE=enterprise`, nothing needs to change and nothing is dropped.** It is now an alias for `in-vpc-enterprise`. The industry tables your stack acquired through the old fallback (`sebi_*`, `rbi_*`, `mas_feat_*`, the EU-AI-Act templates) stay exactly where they are, still recorded in `schema_migrations`, and simply stop being re-selected. **No corrective migration drops them.** They are inert; a `DROP` issued against a customer database to remove a cosmetic surplus is a worse operation than leaving it. If you want them gone, that is a deliberate, separately-planned operation with a backup - not something an upgrade should do to you.
- **If you deliberately wanted all three industry verticals on a self-hosted stack, set `DEPLOYMENT_MODE=saas` explicitly.** That is what the old fallback was giving you by accident.
- **On a FRESH install, `DEPLOYMENT_MODE=enterprise` no longer creates the industry tables - and the compliance routes that read them will answer 500.** An existing stack keeps everything it has; this is only about a database that has never been migrated. `/api/v1/rbi/*`, `/api/v1/masfeat/*`, the SEBI and EU-AI-Act families are registered by the enterprise **build**, independently of the mode, so the routes exist and the queries fail. **Two failure shapes, not one:**
  - *missing relation* - `mas_ai_system_registry`, `mas_feat_assessments`, `rbi_*`, the SEBI tables: `pq: relation "…" does not exist`.
  - *missing COLUMN on a table that does exist* - `euaiact_exports` is created by `enterprise/116` but `download_url`, `storage_type` and `storage_key` are added by `industry/travel/201`, and `rbi_audit_exports` is extended the same way by `industry/banking/303`. On `enterprise`, `in-vpc-enterprise`, `in-vpc-banking` **or** `in-vpc-healthcare` those exports fail with `column "download_url" does not exist`. Two migrations patching an enterprise-tier table from a vertical directory is a packaging error that predates this change and is not fixed here; it is disclosed because it means "grep the logs for `relation … does not exist`" would miss half of it.
  - **The RBI kill switch is on the Decision Mode hot path and fails OPEN.** `KillSwitchEnabled()` is an unconditional `return true` in the enterprise build, and `checkRBIKillSwitch` runs per request on `POST /api/v1/decide` and the gateway path. On a fresh `enterprise`-mode database it logs `relation "rbi_kill_switches" does not exist` on **every governed decision** and does not block - a compliance control structurally unable to fire, plus per-request log volume on the PEP. Neither is new behaviour for `in-vpc-enterprise`, which has always been in this state; what is new is that `enterprise` joins it. That is the same state `in-vpc-enterprise` has always been in, which is the point of the alias - but if you run one of those compliance modules, name its vertical (`in-vpc-banking`, `in-vpc-healthcare`, `in-vpc-travel`) or `saas`. In-repo, `docker-compose.test.yml`, the tier-gate enterprise job and the four `docker/docker-compose.<client>.yaml` demo overlays have each been moved onto the mode they actually need.
- **AxonFlow's own seed data is no longer applied, but rows already present are NOT removed.** If your `dynamic_policies` table contains five rows for tenant `e2e-test-saas` (`e2e-content-filter-001`, `e2e-pii-detection-001`, `e2e-risk-threshold-001`, `e2e-user-role-001`, `e2e-cost-control-001`), or your `customers` table contains `travel-us` / `ecommerce-prod-us`, they came from the old `enterprise/115` and `enterprise/125`. They are scoped to tenants you do not use and enforce nothing for yours. To remove them, run `migrations/internal/115_e2e_test_policies_down.sql` **after reading it** - it is `DELETE FROM dynamic_policies WHERE tenant_id = 'e2e-test-saas' AND policy_id LIKE 'e2e-%'`, a prefix match on that tenant rather than an enumeration of the five ids, so anything else you have created under `e2e-test-saas` with an `e2e-` prefix goes with them. If you would rather be exact, delete the five ids listed above by name. The two `customers` rows can be deleted by `organization_id`. Both are operator decisions, taken on your schedule. (These files live in the source repository only; they are not part of the community mirror.)
- **No new migration ships on this change.** `115` and `125` keep their version prefixes in `migrations/internal/`, and `schema_migrations` is keyed by `(version, name)`, so a stack that already applied them records them as applied and nothing re-runs.


- **HAS MIGRATION: core/156** - makes the tenancy keys `NOT NULL` and adds a `CHECK` forbidding blank strings on `plans`, `workflows`, `workflow_checkpoints`, `execution_summaries` and `webhook_subscriptions`, after stamping orphaned rows with the inert sentinel `__axonflow_unowned__`. `SET NOT NULL` and `ADD CHECK` are scans, not table rewrites, so there is no full rewrite - but **every ALTER runs in ONE transaction, so the ACCESS EXCLUSIVE locks on all five tables are held until COMMIT rather than released per table. Size the maintenance window for the SUM of the five scans, not for the largest table.** Idempotent - a re-run stamps zero rows. Tables whose columns are absent are skipped rather than raising, and the verification predicate is byte-identical to the repair predicate, so no row is asserted over that was not repaired. Schema-reversible; the down migration deliberately leaves the sentinel stamps in place, so the data change is not undone. (#3065)
- **Behaviour change: rows with a blank tenancy key become unreachable AND unwritable.** Previously such a row was readable by *every* tenant, which is the vulnerability. Every blank-keyed row is stamped `__axonflow_unowned__` **unconditionally - the migration does not attempt to determine an owner, so no such row is recovered to a real tenant**; re-attributing one requires direct SQL. The application guards reject the sentinel exactly as they reject an empty key, so **an execution that started before the upgrade and finishes after it will fail its final `UpdateSummary` rather than be marked completed.** That window is the upgrade itself. (#3065)
- **`budgets` is deliberately NOT constrained by this migration.** Its scope lookup treats an empty org as apply-to-all, so adding the constraint would silently disable deployment-global spend caps - a loosening of control, not a tightening. The exclusion is documented in the migration itself. (#3065)

- **HAS MIGRATION: core/155** - normalizes any `tenant_id = ''` rows on `dynamic_policies` and `static_policies` to `NULL` (the documented "no tenant" value) and adds a `CHECK` constraint forbidding the empty string. The empty string had no defined meaning: the evaluator applied such rows to no tenant while the pre-fix list endpoint returned them to every tenant. No current code path creates the shape, so on almost all deployments this migration touches zero rows. Additive, idempotent, reversible; no table rewrite and no maintenance window.
- **Behavior change (only if you have such rows): affected `dynamic_policies` rows are also DISABLED.** A `NULL` tenant is loaded as the apply-to-all sentinel, so normalizing alone would flip these rows from "enforced for no tenant" to "enforced for every tenant" - a dormant policy, possibly with a `block` action, would start firing deployment-wide on upgrade. Disabling them preserves their prior behavior on the database-backed policy engine, which is what deployments run. (On the in-memory fallback engine, used only when the database engine is unavailable, an empty tenant applied to every caller - there the same repair stops such a policy from being enforced. Both the shape and that fallback are unreachable in normal operation, but the asymmetry is documented in the migration.) The migration logs a `WARNING` listing the affected `policy_id`s. Such a row is **not** visible in the portal or the policy API - a `NULL` tenant matches no scope - so to make one live, use direct SQL to give it a real `tenant_id` and set `enabled = true`. `static_policies` rows are **not** disabled: there the tenant predicate excludes `''` and `NULL` alike, so the normalization changes no enforcement.
- **`AXONFLOW_INTERNAL_SERVICE_SECRET` is now mandatory.** The orchestrator refuses every non-exempt request when it is unset, in every deployment mode including Community - there is deliberately no carve-out. Set the SAME value on the agent, the orchestrator and the customer-portal. All shipped topologies already provision it (both Compose files, the install bundle, and both CloudFormation templates); a hand-rolled deployment that omitted it must add it before upgrading.
- **CloudFormation: the orchestrator is no longer attached to the load balancer.** Its ALB listeners, target group, the service's load-balancer association, `HealthCheckGracePeriodSeconds`, and the ALB→orchestrator security-group rules are removed from both templates; the marketplace template's `0.0.0.0/0` rule for port 8081 is gone. `LoadBalancers` is documented **Update requires: No interruption**, and a change set confirms `Replacement: False`, so this does NOT replace the ECS service and needs no maintenance window for that reason. Ports 8090 (Customer Portal API) and 3000 (Customer Portal UI) are deliberately unchanged - the Portal UI reaches the portal API through the ALB.
- **⚠️ Do NOT verify this one with `create-change-set` - it cannot see the failure.** An earlier revision of this note said the removal risked *failing* the update, and prescribed a change-set dry run against a non-production stack. **Both claims are now known false**, disproven by executing the two variants against a throwaway stack (#3100, full write-up under *Fixed* above). The update does **not** fail: it reports `UPDATE_COMPLETE` and deletes the target group either way. And the change sets for the correct and the broken template are **byte-identical** - both read `Modify OrchestratorService … Details: [LoadBalancers, …]` - so a dry run reports success for the broken one. What differs is only the effect: with the `LoadBalancers` block *omitted* the live service keeps its association to the target group the same update just deleted, and ECS then places **no task at all** while reporting `"has reached a steady state"`. Both templates now ship the explicit `LoadBalancers: []` that AWS documents for removal, pinned by `tests/community-saas/cfn_template_test.py`, so a stack deployed from an unmodified template is safe. **Verify after the update, not before it:**
  ```bash
  # MUST print []
  aws ecs describe-services --cluster "$CLUSTER" --services "$SVC" --query 'services[0].loadBalancers'
  # and the service must still be placing tasks
  aws ecs describe-services --cluster "$CLUSTER" --services "$SVC" --query 'services[0].{desired:desiredCount,running:runningCount}'
  ```
  If the association survived (only possible from a hand-modified template), clear it out of band **before the next task replacement**, adding `--health-check-grace-period-seconds 0` if ECS refuses the call:
  ```bash
  aws ecs update-service --cluster "$CLUSTER" --service "$SVC" --load-balancers
  ```
- **The exposure is immediate on this train, not deferred to some later event.** This release also adds `AXONFLOW_CORS_ALLOWED_ORIGINS` and (on the marketplace template) `DEPLOYMENT_MODE` to `OrchestratorTaskDefinition`, so the task definition changes in the **same** `update-stack` and ECS starts a deployment inside it. **And the consequence is not only availability.** With zero orchestrator tasks the agent's connector-governance hop cannot reach the policy engine; `MCP_DYNAMIC_POLICIES_GRACEFUL` defaults to **true** and is set in neither template, and a connection failure is transient-class rather than one of the permanent conditions that force fail-closed - so MCP connector governance degrades to `Allowed: true, PoliciesEvaluated: 0`. That is the #3048/#3049 shape: an **enforcement** defect, not just downtime. (#3100)
- **After ANY ECS `update-stack`, assert `runningCount == desiredCount`. `UPDATE_COMPLETE` is not enough.** This train contains two properties that were removed from `OrchestratorService` by deleting their lines (#3100's `LoadBalancers` and #3164's `HealthCheckGracePeriodSeconds`), and omission means *no change* - CloudFormation reports `UPDATE_COMPLETE` either way, and in the `LoadBalancers` case the service then places **zero tasks** while reporting `"has reached a steady state"`. Both are fixed in the shipped templates, so a stack deployed from an unmodified template is safe; the check below is what tells you whether a hand-modified one is:
  ```bash
  # MUST print equal numbers. UPDATE_COMPLETE with running=0 is the #3100 failure.
  aws ecs describe-services --cluster "$CLUSTER" --services "$SVC" \
    --query 'services[0].{desired:desiredCount,running:runningCount,pending:pendingCount}'
  # MUST print [] and 0. A service still reporting 600 is the #3164 drift:
  # an unset grace period reports 0, not null, so 600 is unambiguously the old value.
  aws ecs describe-services --cluster "$CLUSTER" --services "$SVC" \
    --query 'services[0].{lb:loadBalancers,grace:healthCheckGracePeriodSeconds}'
  ```
  If a hand-modified template left either behind, repair it out of band - both calls were verified against a throwaway stack:
  ```bash
  aws ecs update-service --cluster "$CLUSTER" --service "$SVC" --load-balancers
  aws ecs update-service --cluster "$CLUSTER" --service "$SVC" --health-check-grace-period-seconds 0
  ```
- **On a brand-new stack, `${AWS::StackName}-orchestrator-running-tasks-low` goes to ALARM for three to five minutes and then clears.** That is `TreatMissingData: breaching` doing its job: `ECS/ContainerInsights RunningTaskCount` does not start publishing until roughly three minutes after the cluster is created, and this is the only alarm on the orchestrator, so treating an absent series as OK would have let it go silent permanently. It **should** not recur on an upgrade - the series already exists by then, and `MinimumHealthyPercent: 100` holds the running count at desired through a task replacement - but say that as reasoning rather than as measurement: the probe stack was a fresh cluster and no `update-stack` was run against the alarm itself. (#3162)
- **Self-hosted portal deployments that relied on a hardcoded cross-origin allowlist must now name their origins.** The customer-portal previously accepted credentialed cross-origin requests from `localhost:3000`, `localhost:3001`, `customer.getaxonflow.com`, `app.getaxonflow.com` and one bare IPv4 address, compiled into the image. Only the two `localhost` entries survive, in Community mode only, and only when nothing is configured. Everything else must be listed in `AXONFLOW_CORS_ALLOWED_ORIGINS` (Compose) or the `CorsAllowedOrigins` stack parameter. **The shipped Customer Portal UI needs nothing**: it calls its own Next.js origin and is proxied server-side, so that path never involves a preflight. (#3161)
- **Anything that called the orchestrator directly must now send a token.** Nothing outside the cluster should; within it, the agent, the customer-portal proxies and the MCP forwarders all do so automatically. Test harnesses can mint one with `runtime-e2e/lib/proxy_auth.sh`.
- **Self-hosted Compose:** `docker-compose.enterprise.yml` defaults `ENVIRONMENT=production`, so admin authentication is now enforced there. `ADMIN_API_KEY` gained a local-development default (`localdev-admin-api-key-change-me`); send it as `X-Admin-API-Key` and override it in any real deployment.

- **`DEPLOYMENT_MODE` is now mandatory, and an unset value fails CLOSED.** Set it explicitly on the agent **and** the orchestrator, with the same value, before upgrading. Previously unset meant `community`; it now means the enterprise posture. **The failure is silent, which is the whole reason this note exists:** an unconfigured deployment starts normally and passes its health check, and then the orchestrator stops granting `{tenant-wide, admin}` read authority, so audit, decisions, cost and replay reads answer `403` or return no rows for any caller carrying no role. Symptom: healthy containers, empty dashboards. The value is matched exactly - not trimmed, not case-folded - so `" community"` and `"Community"` are *not* the Community posture. (#3096)
- **Which surfaces were missing it.** All shipped topologies now set it, but four were not setting it before this release and are worth checking against any deployment you derived from them: `docker-compose.scaled.yml` (agent **and** orchestrator), `platform/orchestrator/docker-compose.yml`, `docker-compose.test.yml` (orchestrator only), `docker/docker-compose.base.yaml` (the demo overlay base, agent **and** orchestrator), and the two published `examples/integrations/decision-mode-*-adapter/poc/` Compose files. **The marketplace/self-host CloudFormation template's `OrchestratorTaskDefinition` was also missing it** while the agent, portal and performance-testing task definitions all had it - internally-deployed stacks were masked from this because `deploy-application.yml` injects the variable into all three task definitions at deploy time, but a stack created directly from the template was not. (#3117)
- **The container images deliberately do NOT carry an `ENV DEPLOYMENT_MODE` default,** and one was considered and rejected. A baked-in default recreates the same defect one layer down - whatever value is baked in becomes the posture you get by forgetting to configure one, and the process can no longer distinguish "the operator chose this" from "the operator chose nothing". `community` would restore the fail-open default outright; `enterprise` would fail closed but would silently satisfy the new lint and hide an unconfigured surface. The same Dockerfile also builds both editions. Set the variable per deployment. (#3117)
- **The customer portal does NOT share the agent's reading of `enterprise`, and this change does not make it.** `ee/platform/customer-portal/config/deployment.go` maps `enterprise` to the SaaS portal shape on the stated ground that it is "the hosted multi-tenant production topology (production-us)" - which is not true of the repository (`config/environments/production-us.yaml` declares `saas`), but flipping it to the in-vpc shape **disables tenant-isolation enforcement in the portal** and widens `org_scope` from tenant-scoped to deployment-scoped. That is a widening, it belongs to the #3130 portal class, and it is not done here. The practical consequence is bounded: the two answer different questions - which schema, versus which portal shape - and `in-vpc-enterprise` deployments have always run without the industry tables. `ee/platform/customer-portal/api/provision_admin_password.go` likewise treats `enterprise` as in-vpc for the first-boot credential bootstrap; that is why the note above about `production-us` moving to `saas` exists.
- **Known asymmetry, deliberately still not changed:** migration-path selection treats an unset `DEPLOYMENT_MODE` as `community` and runs core migrations only, so an unconfigured deployment gets the enterprise posture with the community schema. **`DEPLOYMENT_MODE=evaluation` is in the same position** - `isCommunityMode()` matches the literal `community` only, so `evaluation` is the enterprise posture on the community schema by the same mechanism, and `scripts/setup-e2e-testing.sh` and the tier-gate evaluation job both use it. Setting the variable resolves both. Closing it in code was measured to leave four tables `org_id`-less and RLS-blind on existing stacks - see the behaviour-change note above and `technical-docs/DEPLOYMENT_MODE_MIGRATION_SELECTOR_DECISION.md`. What #3167 does change is that an **unrecognised** value is now a hard boot failure rather than the widest migration set, so the only configuration that reaches this asymmetry is a genuinely unset one. (#3128, #3167)
- **Tier gating moves the other way on an unset value.** Enterprise-only routes are registered when the mode is *not* `community`, so an unset value now registers budget management, WCP approve/reject, agent CRUD, the `confirm`/`step` execution modes, plan resume and plan rollback. Those routes still require the internal proxy-auth token, so this is a licensing consequence rather than an access one - but it is another reason to name the mode rather than leave it unset. (#3096)
- **Cross-origin browser access is denied by default outside Community mode.** If a browser served from some *other* origin calls the agent or orchestrator APIs directly, set `AXONFLOW_CORS_ALLOWED_ORIGINS` to its exact origin before upgrading. The shipped Customer Portal UI is unaffected - it calls its own Next.js origin and is proxied server-side, so it is same-origin by construction, and the orchestrator has had no browser-facing ALB listener since #3068. (#3096)
- **Deployment-wide in-memory caches were served to callers without a tenant filter** *(Community)* - four process-global structures are loaded cross-tenant by design (the evaluator needs every tenant's data in one process) but were then handed to callers by name alone. All four are now keyed by tenancy, so the lookup itself cannot return another tenant's row. (#3067)
  - **Connector registry** - a workflow step naming another tenant's connector (`step.connector` arrives verbatim in the `POST /api/v1/workflows/execute` and MAP plan-execute bodies) executed against it with the victim's connection URL and decrypted credentials. The tenancy now comes from the execution's authenticated identity, on both the local path and the agent-routing fallback.
  - **LLM provider registry** - `POST /api/v1/llm-providers/{name}/test` ran a real completion through another tenant's provider, spending and billing their API key. The read, test and routing handlers now enforce the tenancy check their `PUT`/`DELETE` siblings already made; `/test` additionally requires ownership, so the deployment's own key cannot be spent by a tenant.
  - **HITL execution store** - the MAP legacy approve/reject path matched on plan id alone and could release another tenant's paused, human-gated workflow. Approve, reject and approval lookup are bound to the caller's organization.
  - **Connector inventory + cache routes** - `GET /mcp/connectors`, `GET /mcp/connectors/{name}/health`, `POST /api/v1/connectors/refresh*` and `GET /api/v1/connectors/cache/stats` were unauthenticated; the refresh routes additionally took the tenant straight from the URL path, so anyone could evict any tenant's connector pool. All are now authenticated and bound to the caller.
#### Changed (behavior)
- `GET /mcp/connectors` and `GET /mcp/connectors/{name}/health` now require authentication and return only the caller's connectors. (#3067)
- `POST /api/v1/connectors/refresh` refreshes the caller's connector pool; a deployment-wide eviction requires the internal-service credential. `POST /api/v1/connectors/refresh/{tenant_id}` returns 403 when the path tenant is not the authenticated one. (#3067)
- `GET /api/v1/connectors/cache/stats` returns the caller's `cached_connectors` only. The deployment-wide hit/miss/eviction counters remain on `/prometheus`, and are returned inline only for the internal-service credential. (#3067)
- `GET` and `PUT` on `/api/v1/llm-providers*` now require `X-Tenant-ID` or `X-Org-ID`, matching what `POST`/`DELETE` already required. The agent's auth chain sets both on proxied requests. (#3067)
- An LLM provider registered by a tenant is no longer selected by the deployment router - routing to it would spend that tenant's key on another tenant's traffic. Deployment providers (bootstrapped from environment/config) are unaffected. **Consequence: the tenant-facing provider CRUD API is management-only, not routing - a tenant that registered its own provider for data residency now silently gets the deployment default on the preferred-provider path.** A request naming that provider in its `provider` field resolves against the deployment pool only, so `Router.selectProvider` logs `Requested provider %q not available` and **falls through** to the healthy/enabled deployment providers rather than failing (`platform/orchestrator/llm/router.go:292` → `:301-344`). The **policy** path does fail closed: a `route` policy action always yields a non-empty allowed-provider list - explicitly via `allowed_providers`, or otherwise built from `preferred_provider` (+ `fallback_provider`) - and that list filters the deployment pool to empty, returning `no compliant providers available`. `strict_provider: true` on the request has the same fail-closed effect. Express a residency requirement as a policy `route` action or `strict_provider`, or bootstrap the regional provider as a deployment provider from environment/config; do not rely on a plain `provider` field naming a tenant-registered provider. (#3067)
- `GET /mcp/health` remains unauthenticated as a liveness probe but live-checks only deployment-shared connectors; it previously opened a connection to every tenant's backend on each anonymous request. (#3067)
- Two tenants can no longer register the same connector name on a persistence-backed deployment: `connectors.id` is a deployment-wide primary key, so the collision is refused at registration rather than silently diverging from storage. (#3067)
- The legacy in-memory MAP HITL approve/reject path requires an asserted organization scope (`AXONFLOW_HITL_ENABLED` is default-off). (#3067)
- `GET /api/v1/workflows/executions/{id}/hitl-status` is scoped to the caller's organization; an execution owned by another organization is reported as not-found. (#3067)
- `GET /api/v1/llm-providers/{name}/health` requires ownership of the provider, matching `/test`. A health check is an outbound call on the provider's credential and it updates the cached health the router selects on. (#3067)


---

## [9.12.2] - 2026-07-25 (security patch: static-policy enforcement restored under the least-privilege DB posture, plus tenant-isolation hardening)

> **Who was affected:** the enforcement and visibility fixes apply to deployments running the hardened least-privilege DB posture (`AXONFLOW_DB_USE_APP_ROLE=true`). Default Docker-Compose, install-bundle, and CloudFormation deployments connect as the database owner and were NOT affected by the silent-enforcement issue. The tenant-isolation hardening (global-baseline write guard, HITL org isolation) and the fail-closed policy-load guard benefit every deployment.

### Security

- **Static-policy enforcement silently evaluated zero policies on least-privilege deployments** *(Community)* - the agent's `static_policies` readers and the shared policy loader ran unscoped on the restricted DB role, so row-level security matched zero rows and the request/response content gates (SQL-injection, dangerous-command, PII block/redact) allowed everything with `policies_evaluated: 0`. All readers now run org-scoped (two disjoint passes: caller scope + global baseline), restoring full enforcement. (#3048)
- **Policy engine now fails closed on an empty system policy set** *(Community)* - a successful policy load that contains zero system-tier policies is an impossible state on a healthy deployment (they are migration-seeded) and is now treated exactly like a load failure on both the request and response planes, with a distinct `policy_load_empty_system_set` log line and metric. Any future defect class that produces an empty policy load blocks at the gate instead of silently allowing. Note: a deployment booted without its migrations directory now fails closed at the gates instead of running ungoverned. (#3048)
- **Global baseline policies are no longer mutable by tenant callers** *(Community)* - update/delete/disable of shared `org_id='global'` policy rows (SQL-injection guards, PII detection, EU-AI-Act templates, integration policies) through the tenant policy API is now rejected with 403 for every caller. (#3048)
- **HITL approval queue is organization-isolated** *(Community + Enterprise)* - queue listing, request lookup, history, approve, reject, and override now bind to the authenticated caller's organization; cross-organization requests return not-found. Previously these flows were unavailable on least-privilege deployments and deployment-wide on owner-connection multi-tenant deployments. (#3048)
- **Enforcement gates pass the caller's organization** *(Community)* - all policy-evaluation gates (MCP check-input/check-output, gateway pre-check, OpenAI-compat, cowork telemetry redaction, response processing) now scope policy loads by the validated caller organization, closing a silent under-enforcement gap for organizations whose organization and tenant identifiers differ. (#3048)

### Community

#### Fixed
- Customer portal "Static (Read-only)" policy count and the unified policies view showed 0 static policies on least-privilege deployments; the dashboard "Total Policies" tile counted only dynamic policies. (#3048)
- HITL approve/reject flows returned "approval request not found" on least-privilege deployments. (#3048)
- Integration activation enabled zero `int_*` policies on least-privilege deployments. (#3048)
- Policy explain, override lookups, decision-chain reads, LLM provider listing, connector runtime configuration, and policy version history (including organization-tier parents) returned empty results on least-privilege deployments. (#3048)
- Policy version history (`GetVersions`) now includes organization-tier parent policies for all tenants of the owning organization. (#3048)

#### Changed
- Effective-policy responses collapse multiple live overrides on one policy to the latest-created entry (previously duplicate rows could appear). (#3048)

### Enterprise

#### Fixed
- HITL approval repository (enterprise edition), SCIM role readers, EU-AI-Act and evidence export repositories, and portal API-key handlers returned empty results on least-privilege deployments. (#3048)

### Migration

- ⚠️ **HAS MIGRATION: core/154** - re-runs the `org_id='global'` backfill for `tenant_id='global'` policy rows (covers industry template seeds applied after core/153) and installs `BEFORE INSERT` triggers on `static_policies` and `dynamic_policies` that default the organization key on global-sentinel rows. Additive and idempotent; no maintenance window needed.
- Behavior change: tenant-API writes to global baseline policy rows now return 403 (previously rejected only for system-tier rows).
- Behavior change: a deployment booted with no migrations applied (no seeded system policies) fails closed at the enforcement gates instead of running ungoverned.

## [9.12.1] - 2026-07-24 (RLS-blind reads under the app-role posture: policy enforcement, portal sessions, RBAC checks and execution reads restored)

> **Who was affected:** only deployments whose database pools actually run as `axonflow_app_role` (`AXONFLOW_DB_USE_APP_ROLE=true` **with** the app-role DSNs provisioned - e.g. CloudFormation stacks flipped to `AppRoleProvisioned=true`, or self-hosted operators who followed the hardened-posture provisioning guide). Default docker-compose, default install-bundle, and default CloudFormation deployments connect as the table-owning role and were **not** affected.

### Security

- **A policy's version history was readable across tenants by ID (Community).** `GetVersions` had no tenant predicate of its own, so on deployments whose pool bypasses RLS (the non-app-role default), any authenticated tenant could read any other tenant's full policy version snapshots given the policy ID. The read now verifies parent ownership (tenant or `global`) in SQL, and runs org-scoped under RLS. (#3039)
- **Override policy lookups can no longer act as a cross-tenant existence oracle (Community).** The ADR-044 override create/list lookups resolve a policy by UUID, slug, or name; they now run as scoped two-pass (tenant, then `global`) lookups with explicit tenancy predicates, so a caller can never probe or resolve another tenant's policy identities regardless of the pool's RLS posture. (#3039)

### Community

#### Fixed

- **Tenant dynamic policies were silently NOT ENFORCED on app-role deployments.** The dynamic-policy engine's gate-evaluation cache is loaded by a deliberate all-tenants `SELECT ... WHERE enabled = true`. That refresh ran on the request pool - `axonflow_app_role`, `NOBYPASSRLS` - where `dynamic_policies`' RLS predicate (`org_id = get_current_org_id()`, migration 018) evaluates against an unset GUC and admits **zero rows**. The cache loaded empty on every refresh cycle, fell back to the built-in defaults, and every **tenant-created** dynamic policy stopped being enforced at WCP step gates and the decide plane - an over-threshold wire transfer whose policy demands `require_approval` sailed through as `allow`, observed on a live deployment. Reads under RLS fail to *silent zero rows* (unlike writes, which error on `WITH CHECK`), which is why five weeks of green health checks never surfaced it. The refresh and the boot-time policy count now run on the BYPASSRLS `axonflow_platform_admin` pool - the same split the node monitor and idempotency sweep already use - and the orchestrator now **refuses to boot** (`RequirePlatformAdminOrFatal`) when the app-role gate is on without the admin DSN, because silently not enforcing policies is strictly worse than not starting. (#3039)
- **Policy CRUD read-back, exports and tier counts read zero under app-role RLS.** The policy repository's writers were org-scoped in the v9 Phase-8 sweep; its readers never were. On app-role deployments a freshly created dynamic policy 404'd on GET-by-id, the list and export came back empty, and the tenant/org tier-limit counts read 0 (which, combined with fail-open semantics, meant limits never engaged). All repository reads now run org-scoped like their sibling writers; the list/get read the tenant scope and then the `'global'` scope with explicit per-scope tenancy predicates, so system-wide wildcard policies stay visible without double-counting on non-RLS pools. Policy **export** now pages through the list (a page-size clamp silently truncated exports to 20 policies). Agent-side free-tier usage counts (active policies, HITL approvals-per-window) are org-scoped so those limits actually engage. (#3039)
- **Executions API returned zero rows; execution status updates silently failed.** `execution_history` is RLS-keyed on the legacy tenant GUC (migration 042); its writers were scope-wrapped, its readers were not. On app-role deployments `GET /api/v1/unified/executions` returned `{"executions":null,"total":0}` for tenants with live workflows, by-id lookups 404'd - and because the tracker's lifecycle updates re-read the row before writing, execution status updates failed too, stranding rows at their initial state. The by-id/by-metadata lookups (discovery reads: the row itself establishes the tenant, and every caller post-authorizes the result against the caller's tenant) now run on the BYPASSRLS pool; list/count reads scope-wrap with the caller's tenant. The per-tenant execution-history retention purge, whose cross-tenant enumeration read zero rows and never purged, now runs on the retention admin pool the cleanup service already held. (#3039)

#### Changed

- **`/health` recommended openclaw plugin version: 2.8.0 → 2.8.4.** Advertises the already-published npm release carrying the self-hosted endpoint fix and audit hardening; no floor change.

### Enterprise

#### Fixed

- **Portal sessions bounced to /login on every hard navigation.** `GET /api/v1/auth/session` read `user_sessions` with a bare pre-auth SELECT - the same lookup class migration 118 fixed for the auth middleware with a `SECURITY DEFINER` helper, but the session endpoint was never converted, so under app-role RLS every valid cookie answered `authenticated:false` and the portal SPA bounced to /login on any full page load. The endpoint now uses `portal_session_lookup` with the middleware's exact fallback, and the session mutations (logout delete, expiry delete, last-activity update - all silent 0-row no-ops under RLS, so logout never invalidated the server-side session) run org-scoped. (#3039)
- **RBAC permission checks denied everyone on app-role deployments.** Every reader in the RBAC roles repository was unscoped - including `GetUserPermissions`, the read every portal permission gate funnels through - so on an app-role deployment running 9.12.0's role-gated routes, **every** gated route (policy CRUD, roles management, SSO configure) answered 403 for every user, regardless of role. All seven readers now scope-wrap like the repository's writers; override create no longer 404s "policy not found" and stale-deny cache invalidation actually fires. (#3039)

### Migration

**⚠️ HAS MIGRATION: core/153** - backfills `org_id='global'` onto the migration-seeded `tenant_id='global'` system policy rows (the earlier org-id backfill deliberately skipped them), without which they are invisible to every scoped read. Fast, idempotent, self-testing, with a down; applies automatically on boot. **App-role deployments:** `AXONFLOW_DB_PLATFORM_ADMIN_URL` is now a boot requirement on the orchestrator when the app-role gate is enabled.

---

## [9.12.0] - 2026-07-22 (the five-role RBAC model made real: enforced per-role behavior, owner bootstrap & permission-driven PII)

### Fixed

- **`POST /api/v1/policies/test` was 403'd for `viewer`/`developer` (Enterprise).** *(Enterprise)* #3012's fail-closed prefix guard hands `policy:write` to every mutating verb on a policy family the portal does not explicitly register. `/api/v1/policies/test` is the orchestrator's ad-hoc policy **dry-run** - it evaluates a sample query against the loaded dynamic policies and creates, edits or deletes no policy - but the portal never registered it, so the guard swept it up and a read-only session got `403` on a read. It is **not** `/policies/{id}/test`: with no `{id}` segment mux never matched it against that pattern, which is how it escaped the route census. It is now registered explicitly and ungated, ahead of the prefix guard, alongside `/simulate`, `/impact-report` and `/conflicts`. **Related hardening:** the dry-run is not side-effect free - it records a `policy_metrics` analytics row whose `org_id` is also the `app.current_org_id` binding that row's INSERT is checked against. Both `/policies/test` and `/policies/simulate` took that tenant from the **request body**, so an authenticated caller could attribute metrics rows to any org they named, with the RLS `WITH CHECK` passing by construction. Both now take it from the gateway-stamped `X-Tenant-ID` and reject the request without one. A new coverage test censuses the routes the **orchestrator** registers - the catch-all's actual destination - and fails CI until every mutating-verb policy route there is classified on the portal side as read or write, so this class cannot recur. (#3012, #3014)
- **Break-glass owner assignment reported success while granting nothing (Enterprise).** *(Enterprise)* `ensure_org_owner_assignment` is the single SQL choke point every first-owner path routes through. Migration `core/149` gave it an `ON CONFLICT DO UPDATE` that revives an already-**expired** owner row; migration `core/150` redefines the same function and carried a bare `DO NOTHING`. 150 applies second, so on every complete chain the revive did not exist. The failure was silent by construction: the insert conflicted with the expired row, `ROW_COUNT` was 0, and the choke point reported "already held" - while every permission read filters `expires_at`, so the org had **no owner at all**. `POST /api/v1/admin/organizations/{org_id}/owner`, the documented way *out* of an owner lockout, answered `{"success":true,"outcome":"already_held","owners":[]}` to an operator who was still locked out. Three parts: the revive now lives in **150's** definition (the one that survives the chain), scoped by a new shared `axonflow_owner_grant_may_revive()` to the **intentional** first-owner callers (the migration backfill and break-glass) so the **ambient** ones (org-creation trigger, portal boot) keep strict `DO NOTHING` and cannot silently make a lapsed, deliberately time-boxed owner grant permanent; `GrantOrgOwner` now verifies the **postcondition** and returns `not_effective` when no live owner resulted, so no caller can report success on a grant that did not take; and the endpoint returns `500 OWNER_GRANT_NOT_EFFECTIVE` with the real owner set instead of a success with an empty list. (#3005)
- **Break-glass and owner revoke silently broke when the platform-admin connection degraded (Enterprise).** *(Enterprise)* `adminConn()` falls back to the ordinary **app-role** pool when `OpenPlatformAdminConnection` fails at boot - a ping race, or a DSN pointed at the wrong role; `main.go` logs a `WARNING` and boots anyway. `organizations` is `ENABLE` **+ `FORCE`** RLS and `role_assignments` is RLS-enabled, so on that pool every unscoped read returns zero rows. The owner endpoints' first read (`orgLoginIdentityAdmin`) then answered **`404` "Organization not found"** for an org that exists, and the post-grant owner list read empty - so a *successful* break-glass grant reported `500` and audited as a failure, on every retry with every address, in exactly the degraded deployment where break-glass is reached for. `HoldsDurableOwner` and the revoke path's lock `SELECT` had the same defect, and there they fail the other way: the revoke reports `not_found` and silently **retains** the superseded owner. All four reads are now org-scoped, and `TestBreakGlassOnAppRolePool_RealPostgres` drives the endpoints as a real non-`BYPASSRLS` `axonflow_app_role` - every prior real-Postgres test ran as the container superuser, which bypasses RLS unconditionally and is why the class was invisible. (#3005, #3016)
- **Migrations warn instead of silently no-op'ing when the migration role cannot see `organizations` (Enterprise).** *(Enterprise)* Migrations run on the raw `DATABASE_URL` and never bind `app.current_org_id`, while `organizations` is `FORCE` RLS - which applies to the **table owner** too. A migration role that is neither superuser nor `BYPASSRLS` therefore sees **zero** orgs - whether it owns the table (`FORCE` binds the owner) or not (`ENABLE` binds everyone else), so `core/149`'s backfill enumerates nothing from that leg and its orphan report - the operator's only signal - is blind as well. `core/151` already documented the hazard and claimed `core/149` did too; it did not. `core/149` now carries the canary, using a role/catalog predicate rather than `COUNT(*) = 0` - a fresh install legitimately has zero orgs, so a count-shaped canary is ambiguous exactly when it fires - and a `WARNING` rather than an abort (`run.go` `log.Fatalf`s on a failed migration, so aborting would crash-loop the agent at boot). Repairing the enumerations themselves is tracked in **#3025**. (#3002, #3005)
- **Migration NOTICE/WARNING output now reaches the agent log at all (Community).** *(Community)* The migration connection was opened with a plain `sql.Open`, and `lib/pq` **discards every server `NOTICE` and `WARNING`** unless the connection carries a `pq.ConnectorWithNoticeHandler`. Nothing installed one, so the migrations' entire diagnostic story has always been invisible: how many owner assignments were backfilled, the orphan-org report naming the orgs that need the break-glass endpoint, and the RLS canaries above. A migration that "warns" into a connection that throws warnings away is not a signal. The runner now installs a handler that logs every message, marking `WARNING` and above distinctly. (#3002)
- **Migration 150's collapse stranded migration 149's own marker, boot-looping a hand re-run (Enterprise).** *(Enterprise)* 150 collapses each `(org, role, canonical-email)` class to one row so its re-key `UPDATE` cannot collide. On a replay the class it finds usually holds two rows for **one** principal - the org-login identity's original owner grant (keyed on the raw `contact_email`) and the canonical row 149's backfill created for the same identity - and the canonical one wins. The row that justified the survivor was therefore deleted while the survivor kept the `migration:149_owner_backfill` marker, so a hand re-run of 149 aborted with *"N backfilled owner assignment(s) went to principals that did not hold `sso:configure` pre-upgrade (escalation)"*, and `run.go` `log.Fatalf`s on a failed migration - a permanent agent boot loop. It also left 149's DOWN pointed at a grant that predates it. The collapse now **transfers the collapsed row's attribution** to the survivor, and 149's no-escalation check tolerates a qualifier 150 legitimately collapsed - scoped to the org-**login** identity, derived from 150's own collapse predicate, because that is the only principal whose qualifier the collapse can remove. A genuine widening still aborts the migration, pinned by its own test. The `Migrations apply cleanly` gate's seeded-**replay** leg, which was passing without exercising a real replay (every row it replayed over was already canonical), now de-canonicalizes first and asserts its own non-vacuity marker. (#3005, #3002)
- **Security - an anonymous admin-API caller could confer `owner` by rewriting `contact_email` (Enterprise).** *(Enterprise)* Migration 149 installed an `AFTER UPDATE OF contact_email` trigger that granted the `owner` system role to whatever address landed in `organizations.contact_email`. Its only HTTP writer, `PATCH /api/v1/admin/organizations/{org_id}`, had **no strict-admin check**, while `AdminAuthMiddleware` passes callers through anonymously in `in-vpc-*`/`saas-staging` when `ADMIN_API_KEY` is unset - the shipped default. On a default self-hosted bundle, anyone who could reach the portal admin API could therefore grant `owner` on an arbitrary email in **any** org (`source='system'`, so it survived SCIM re-sync), audited only as `UPDATE_ORG` - never `ASSIGN_OWNER`. Under Path B that address then resolved to fleet role `owner` (tenant-wide audit reads + `sso:configure`), routing around the #2993 anti-escalation gate. **Fix:** changing `contact_email` now requires an authenticated admin, and migration **`core/152`** drops the trigger - the owner re-seed moved into the handler, which emits a real `ASSIGN_OWNER` audit row. A bare `UPDATE organizations` no longer mints an owner. Org-creation bootstrap is unaffected. (#3003)
- **Upgrade lockout - orgs with no role assignments lost policy editing (Enterprise).** *(Enterprise)* #2996 gated policy CRUD on `policy:write`/`policy:delete`, but an org's password-login identity (`org_id` + password) carries **no role assignment**, and migration 149 deliberately grants such orgs nothing. On upgrade every pre-existing org with zero assignments - every SaaS customer org and every non-deployment in-vpc org - could no longer edit policies, and could not grant itself a role either (`rolesManagementGate` requires `roles:write`), leaving no in-product recovery. Migration **`core/151`** now grants **`policy_admin`** (not `owner` - that would be a widening, since this identity never held `sso:configure`) to the org's login identity, resolved through `axonflow_org_login_identity(contact_email)` - the shared expression, **never** a bare `''`. An org with no `contact_email` returns `NULL` and is **skipped**, not granted: SQL cannot read `AXONFLOW_PORTAL_ADMIN_EMAIL`, so guessing there would re-create the blank-keyed wildcard #3000 abolished, one role down. Those orgs get their authority from the portal boot grant or the break-glass endpoint instead. The predicate is **no live policy authority** - the login identity holds no unexpired assignment to a role carrying `policy:write` or the `*` wildcard - not merely "no assignment": an org whose login identity happens to hold a `viewer` row is still locked out of policy editing, and an assignment-existence test would silently skip it. It is identity-scoped, not org-scoped, so an org whose only assignment belongs to some *other* identity is still covered. Capability-preserving: `policy:write`/`policy:delete` restore what #2996 took, and `audit:read` preserves the tenant-wide audit reads the zero-assignment carve-out used to provide. Idempotent; the DOWN removes only the rows it added. Note one deliberate cross-plane consequence: on a Path-B (OIDC) deployment, an IdP identity whose email equals the org `contact_email` now also resolves to fleet role `policy_admin` and gains tenant-wide audit/decision REST reads on the fleet plane. (#3004)

### Added

- **Owner lifecycle: `DELETE` (revoke), and a contact-email change now MOVES ownership instead of accumulating it (Enterprise, #3016).** *(Enterprise)* The owner admin surface was append-only - `POST` (assign) and `GET` (list), with no revoke - so an org that changed its contact address kept the **previous identity as `owner` forever**, and an operator could not correct owner state at all. Deliberately **no migration**: revoking a live privileged grant from SQL cannot see operator intent and its only failure mode is an aborted chain and a crash-looping agent, which is where every boot loop in this epic came from. Lifecycle now lives in the handler, where it is authenticated, audited, retryable and reversible.
  - **`DELETE /api/v1/admin/organizations/{org_id}/owner`**, gated by the same strict `Authenticated==true` check as assign - so it fails closed with `401` even in the auth-OPTIONAL modes (`in-vpc-*`, `saas-staging`) where `AdminAuthMiddleware` passes anonymous callers through. Audited as a new `REVOKE_OWNER` action on **every** branch, refusals included. `user_email` is required and has no default: unlike assign, revoke has no safe one.
  - **The last owner can never be removed** (`409 LAST_OWNER`), and there is **no force flag for it** - that would be a self-inflicted #2997 lockout with no in-product recovery, since the anti-escalation gate stops an admin from growing a new owner. The check and the delete run in one transaction that locks every live owner row, so two concurrent revokes of two *different* owners cannot each conclude "not the last one" and between them leave the org with zero. A **time-boxed** co-owner does not count as a survivor: it would let the removal succeed today and the org fall to zero owners when that grant lapsed, so only a grant with **no expiry** proves the org keeps an owner.
  - **The guarantee holds at every door, not just the new one.** The same shared predicate now guards every path that can remove or de-power an owner grant, each returning `409 LAST_OWNER`: the RBAC role-assignment API (`DELETE /api/v1/users/{email}/roles/{roleId}` - previously unguarded and reachable with only `user:write`, which a plain `admin` holds via `*`); **SCIM** (`SetGroupRoleMapping` removes a group's old role from every member with no source filter, so clearing a group→`owner` mapping could strip an org's only owner); the `DELETE /api/v1/roles/{id}` **FK cascade**; and `PUT /api/v1/roles/{id}` **stripping the owner-reserved permissions** - the same lockout reached without deleting anything, which is why an enumeration of deletion paths alone missed it. Note this corrects a previously-stated assumption: `source='system'` does **not** mean "a later SCIM re-sync never strips the grant" - true of `SyncUserRoles`, which filters on source, but not of `SetGroupRoleMapping`.
  - A SCIM sync that hits the refusal **keeps deprovisioning the user's other roles** instead of aborting, and reports the refused members in `owner_removals_refused` - a guard that produced privilege *retention*, or that let displayed group mappings diverge silently from effective privilege, would be a worse trade than the lockout it prevents.
  - **`manual`/`scim` grants are not touched by default** (`409 PROTECTED_OWNER_SOURCE`); only `source='system'` - what the choke point writes - is removable without `{"force":true}`. A SCIM grant is the IdP's to manage and would re-sync straight back.
  - **A genuine `contact_email` change now revokes the superseded identity's `system` owner grant**, resolving stale-owner retention at the moment the change happens rather than retroactively. Only when the re-seed actually succeeded (clearing `contact_email` is refused by the identity guard, so that path revokes nothing and cannot strand an org), only on a real change (a case- or whitespace-only rewrite is a no-op), and a retained grant is audited as a **failure** so it stays visible.
  - **A grant that cannot confer does not count as an owner.** A `role_assignments` row that is blank, or that carries leading/trailing whitespace, can never match a session - the conferring path lowercases the stored value but does not trim it, while the old write path (`lower(btrim(...))`) stripped ASCII space only, so a tab or NBSP survived verbatim. Such rows are excluded from the "does another owner survive?" census at every door; counting one is precisely how a guard licenses removing the only real owner while reporting the org still has one. The write path now also **refuses** such an identity (`400 INVALID_IDENTITY`) and stores canonically, so they cannot be created going forward.
  - **Identity matching is canonical on both sides** (`axonflow_canonical_email`, the same function the choke point uses to *store* the row), so a revoke of `Ops@Acme.com` cannot silently miss a grant stored as `ops@acme.com` and report success while the privilege keeps working.

- **The five-role RBAC model is now real - distinct, enforced behavior per role + anti-drift lockstep guards (Enterprise).** *(Enterprise)* The `admin`/`owner`/`policy_admin`/`developer`/`viewer` tiers each now do something enforced and distinct, and three role vocabularies (fleet `knownRoles`, mint `mintableRoles`, seeded system roles) plus the enforced-permission set are pinned in lockstep so they can never silently drift again. (#2993)
  - **`policy_admin` reads tenant-wide** on the fleet plane (`RoleCanReadTenant`), so a per-user `policy_admin` token sees the whole tenant audit/decision trail; `developer`/`viewer` stay own-rows.
  - **owner ≠ admin:** `sso:configure` (SSO + SCIM + detection-posture config) is now **owner-reserved** - the `*` wildcard no longer grants it. `owner` holds it explicitly; `admin` does not.
  - **admin ≠ policy_admin:** the RBAC role/user management API (`/api/v1/roles`, `/api/v1/permissions`, `/api/v1/users/*/roles`, `/api/v1/users-with-roles`) - previously unmounted dead code - is now mounted behind `roles:*`/`user:*`, which `admin` holds (via `*`) and `policy_admin` does not.
  - **`owner` is a true superset of `admin`:** owner's seeded bundle is `["*", "sso:configure"]` - everything the `*` wildcard grants PLUS the owner-reserved `sso:configure` - so owner is never *below* admin on any permission. The fleet role resolver classifies a role named `owner` as owner even though it carries `*` (owner now outranks the wildcard→admin rule).
  - **`policy_admin` administers policies (#2996):** policy CRUD is now RBAC-gated at the route layer, and `policy_admin` seeds `policy:write`/`policy:delete` (plus tenant-wide `audit:read` and `token:rotate:self`) - a genuine policy administrator, no longer just a tenant-wide auditor.
  - **Anti-escalation:** creating, updating, or assigning a role that confers an owner-reserved permission now requires the actor to hold that permission - so an `admin` (who can manage roles via `*` but lacks `sso:configure`) cannot mint or self-assign the `owner` role to acquire it (returns `403 PRIVILEGE_ESCALATION`).
  - **Fixed:** the SSO/SCIM/detection-posture permission gate (`checkSCIMPermission`) keyed on `session.TenantID`; on a multi-tenant SSO org (where TenantID ≠ OrgID) this resolved zero permissions and wrongly denied a legitimate owner. It now keys on `session.OrgID`, matching how role assignments are stored.
  - **developer ≠ viewer:** a new self-serve endpoint `POST /api/v1/me/user-token/rotate` (gated on the new `token:rotate:self` permission) lets a developer rotate **their own** per-user token (own-scoped, always developer-scoped - never an escalation vector); `viewer` lacks the permission and is denied.
  - **Seed-vs-enforce gap closed:** every seeded system-role permission is now actually enforced somewhere; unenforced permissions were dropped from the seeds. A lockstep guard test fails CI if a role/permission is seeded without a gate.
  - **Reconcile for existing tenants:** migration **`core/148`** upserts the system roles to the canonical five-tier spec for every existing org (and via the org-creation trigger for new ones), pruning the dropped `member` role where unreferenced. It never clobbers custom (`is_system=false`) roles or manual/SCIM role assignments.
  - **Fixed:** the `usage:platform_wide` gate resolved a permission through a context key that was never populated, so platform-wide usage queries were silently denied for **every** caller; it now resolves through the RBAC service (admin/owner qualify via `*`).

- **Somebody is actually assigned `owner` - the upgrade no longer strands orgs without one (Enterprise, #2997).** *(Enterprise)* Making `sso:configure` owner-reserved (above) only works if an owner EXISTS. Nothing assigned one: migration `core/148` seeds the role *definition* and deliberately leaves `role_assignments` untouched, so an upgraded org would have had **no owner → no `sso:configure` → and admins blocked by the anti-escalation gate from creating one**, leaving SSO/SCIM/detection-posture configuration permanently unreachable through the portal. Four closers, all routed through one SQL choke point (`ensure_org_owner_assignment`, `SECURITY DEFINER`, idempotent, `source='system'` so SCIM re-sync never strips it):
  - **Backfill (migration `core/149`).** Every principal that held `sso:configure` under **pre-upgrade** semantics - a non-expired assignment to a role carrying `"*"` **or** `sso:configure`, which is exactly `admin`, `owner`, and any custom role that granted it - is granted the `owner` role. **Capability-preserving, never widening:** `policy_admin`/`developer`/`viewer` get nothing (their bundles never contained `sso:configure`), already-expired assignments are skipped, and a time-limited admin's owner grant **carries the same expiry** rather than becoming permanent. The migration self-verifies both directions (no principal under-covered; no backfilled grant unjustified) and fails loudly otherwise.
  - **New orgs.** The org-creation trigger now seeds the owner **assignment**, not just the definitions, keyed on the identity that org's password login actually presents - `contact_email`, or the configured bootstrap operator (`AXONFLOW_PORTAL_ADMIN_EMAIL`) when it has none, the same expression `HandleLogin` uses. (An earlier revision keyed it on `""` and re-seeded on every `contact_email` change; `core/150` now refuses a blank identity outright and `core/152` drops that trigger - see #3000 and #3003.)
  - **Default install.** In `enterprise` / `in-vpc-*` modes the portal grants the deployment-org bootstrap operator `owner` on every boot (idempotent), right after provisioning its password - so a default `axonflow-install` deployment ships with a working root principal instead of a role-less operator. This also restores that operator's ability to write policies, which #2996's `policy:write` gate would otherwise have removed.
  - **Break-glass.** `POST /api/v1/admin/organizations/{org_id}/owner` (+ `GET` to list current owners) assigns an org's first owner from outside the RBAC plane. `ADMIN_API_KEY`-gated with a strict `Authenticated==true` check - fails closed with `401` even in the auth-OPTIONAL deployment modes (`in-vpc-*`, `saas-staging`) - idempotent, and every attempt (including rejected ones) writes an `ASSIGN_OWNER` row to `admin_audit_log`. The portal anti-escalation gate is **not** weakened: an `admin` self-assigning `owner` still gets `403`.

- **Audit reads say which scope they were served under; the dev-token endpoint takes a role (Enterprise, #2991).** *(Enterprise)*
  - The four orchestrator audit-read handlers (report, search, session-summary, export) now return an additive **`X-Axonflow-Read-Scope`** response header - `tenant`, `own-rows`, or `none` - so a caller that receives `200` with zero rows can tell RBAC read-scoping from an empty trail, instead of guessing. Response bodies are unchanged, and the `none` path also emits a diagnostic log.
  - `POST /api/v1/dev/token` (non-production only) accepts an optional `{"role":"..."}`, defaulting to **`developer`** (own-rows, no escalation); an unknown role is rejected with `400` before minting, and `admin`/`owner` are a loud-logged opt-in. The dev token is also now minted as the fleet-acceptable claim superset - previously it lacked `iss`/`email`/`jti`, so the read plane `401`-rejected it outright and any role on it was inert.

- **First-class JumpCloud SSO/OIDC provider preset (Enterprise, #3028).** *(Enterprise)* `jumpcloud` is now a supported `provider` value on the SSO-config surface alongside `okta`/`azure_ad`/`auth0`/`custom_saml`/`oidc`. It is a standard OIDC IdP: the preset derives `provider_type=oidc` server-side (never client-set), pre-fills JumpCloud's well-known OIDC endpoints (issuer `https://oauth.id.jumpcloud.com/`, JWKS `https://oauth.id.jumpcloud.com/.well-known/jwks.json`) and a default `email→email` claim mapping, and validates the same issuer/audience/JWKS inputs as generic `oidc`. It powers Path B per-user fleet identity - developers authenticate with a JumpCloud-issued OIDC token AxonFlow validates against JumpCloud's JWKS, and **roles resolve from the SCIM-synced directory, not from token claims**. The setup surface lists JumpCloud in the provider catalog and returns per-provider setup instructions.

- **Audit-export CSV now includes a `tokens` column (Community, #3027).** *(Community)* `POST /api/v1/audit/export?format=csv` gains a `tokens` column, sourced from `tokens_used`, positioned between `response_time_ms` and `correlation_id`. JSON export already carried `tokens_used`, so it is unchanged.

- **Internal - shared `IdentityAttributeResolver` seam extracted (no behavior change) (Enterprise, #3018).** *(Enterprise)* Role and (future) segment resolution now share one SCIM-backed fetch/cache/wiring seam; role resolution delegates to the existing resolver unchanged (same query, precedence and expiry handling), segment resolution is a no-op stub. Groundwork only - no observable behavior change.

### Changed

- **Behavior change - `policy_admin` per-user tokens now read tenant-wide (Enterprise).** *(Enterprise)* Previously `policy_admin` collapsed to own-rows on the fleet plane; it now reads the full tenant audit/decision trail (matching `admin`/`owner`). (#2993)
- **Behavior change - `member` is no longer a mintable/known role (Enterprise).** *(Enterprise)* The mint API returns `400` for `role="member"`, and the fleet validator/SCIM resolver no longer recognize it. `member` mapped to no distinct behavior. Existing `member` tokens/assignments normalize to `""` (own-rows) - **unchanged runtime**. Migration `core/148` prunes the seeded `member` system role where nothing references it. (#2993)
- **Behavior change - admins no longer configure SSO/SCIM/detection-posture (Enterprise).** *(Enterprise)* `sso:configure` is now owner-reserved and the `*` wildcard no longer satisfies it, so a session/token that holds only `admin` (wildcard) is denied on the SSO-config, SCIM-token/role-mapping, and detection-posture routes - these require the `owner` role. A user assigned both `admin` and `owner` keeps the capability. (#2993)
- **Behavior change - policy CRUD is now RBAC-gated (Enterprise, #2996).** *(Enterprise)* Creating/updating/importing a governance policy now requires `policy:write` and deleting requires `policy:delete`, enforced at the route layer across **every** policy route family (#3012): `/policies`, `/unified-policies`, `/static-policies`, `/policy-overrides` and `/dynamic-policies`. Before this any authenticated session could edit policies - the route was session-auth-only. **A session without `policy:write` (e.g. a `viewer`/`developer` role, or a role-less operator) can no longer create/edit/delete policies**; `admin`/`owner`/`policy_admin` can. Policy **reads** stay session-only (the policy-list/settings pages need them). The dead `EndpointPermissions` declaration map - which advertised route→permission mappings that nothing enforced (incl. `connector:*`/`settings:*`) - was removed; enforcement lives in the real route-layer gates. (#2993, #2996)

- **Behavior change - the remaining policy-write routes are now gated too (Enterprise, #3012).** *(Enterprise)* #2996 gated `/api/v1/policies`, but the portal UI writes through **`/unified-policies`** and **`/static-policies`**, whose mutating routes were all still session-auth-only - so a `viewer` or `developer` session could create, update, delete, toggle and override governance policies, including flipping a blocking policy to allow, through the exact routes the UI calls. Two further families were ungated and are closed in the same change: `/policy-overrides` (PUT/DELETE), and **`/dynamic-policies`**, which the portal never registered at all and which therefore fell through to the orchestrator catch-all - that proxy authenticates the session but applies no permission check.
  - Every mutating route across all five families now requires `policy:write`, and deleting a *policy* requires the stronger `policy:delete`. Override create/delete is `policy:write`: removing an override does not destroy a policy, it restores the policy's original (usually stricter) action.
  - **Reads are unchanged** - list/get/effective/versions/export and the evaluation endpoints (`/test`, `/test-pattern`) stay session-only, so the policy screens still load for a read-only user.
  - **Impact:** a session without `policy:write` can no longer edit policies through *any* route. `admin`/`owner` (via the `*` wildcard) and `policy_admin` can. Combined with the `core/151` backfill above, an upgraded org's login identity holds `policy_admin`, so operators retain policy editing - **the two must ship together**; gating without the backfill would lock a role-less operator out of policy editing on every path with no in-product recovery.
  - A route-coverage test derives the route list from the source on every run and fails CI if a new mutating policy route is registered without a gate, so this class cannot recur silently.

### Security

- **The bootstrap `owner` grant now requires a REAL identity - an empty `user_email` no longer confers owner (Enterprise, #3000).** *(Enterprise)* #2997 keyed the org-bootstrap `owner` assignment on the identity an org's password login presents: `organizations.contact_email`, or `''` when the org has none. On a **default install** that granted `owner` to `user_email = ''`. Permission resolution is `UserHasPermission(org_id, user_email, perm)`, so an empty `user_email` is not a principal but a **wildcard**: any session in that org resolving to `''` inherited the top role - including the owner-reserved `sso:configure`. The most plausible second such session is **SSO/OIDC with a missing or unmapped email claim**. It also left owner actions with blank audit attribution. Closed in two halves:
  - **The operator now has a real identity.** New `AXONFLOW_PORTAL_ADMIN_EMAIL` (default `portal-admin@axonflow.invalid`) is the session identity an org-level (`org_id` + password) login presents when the org has no `contact_email`, and the identity the bootstrap `owner` grant is keyed on. Both the login and the grant derive it through one function (`ResolveOrgBootstrapIdentity`), so the identity a session *presents* and the identity owner is *granted to* cannot diverge - divergence is the #2997 lockout. A configured value that is blank, not an address, or on the reserved `@axonflow.local` / `@axonflow.internal` domains is rejected with a loud log and the default is used.
  - **The database refuses non-identities outright.** Migration **`core/150`** makes `ensure_org_owner_assignment` return the new sentinel `-2` for a blank or `IsSharedSyntheticIdentity`-class target. That guard sits in the single choke point every **first-owner-creation** path already routes through - the migration backfill, the org-creation trigger, the contact-email drift guard, the portal boot grant and the admin break-glass API - so all of them fail closed at once. (It is a guarded *function*, not a table constraint: the portal RBAC `AssignRole` API, SCIM `SyncUserRoles`, and direct `psql` access still write `role_assignments` themselves and are gated by their own authorization instead.) It also **deletes the blank-keyed and synthetic-keyed `source='system'` owner grants a prior run of `core/149` created**; the portal re-grants owner on the real identity at its next boot, and the break-glass endpoint covers every other shape. Migration `core/149`'s down migration now removes the same rows.
  - **Not a lockout:** the default-install operator still receives `owner` and can still configure SSO - proven end to end in `runtime-e2e/3000_bootstrap_owner_identity/` and against a live Postgres through the real login handler.

- **Behavior change - unredacted PII in LLM responses is now an explicit opt-in, never a role privilege (Enterprise, #3001).** *(Enterprise)* The orchestrator response plane decided PII visibility with a role literal - `if user.Role == "admin" { return ["*"] }`, where `"*"` is the blanket allow-all - so an admin-role caller was handed the LLM response completely unredacted. **Reachability:** this sits on the *legacy* fallback branch of `ProcessResponse`, taken only when the shared policy engine is absent; the orchestrator installs that engine whenever it has a database, so on a DB-backed deployment the shared engine governs the response and this branch is not reached. The bypass was therefore **latent, not live**. It is removed anyway - a role-keyed allow-all has no business existing on a redaction path, and it encoded two defects: (1) it was a string compare on `"admin"`, so `owner` did **not** match - after #2993 made owner a strict superset of admin everywhere else, this one site inverted the model and gave the *more* privileged role *less* visibility; (2) whether an administrator sees raw customer PII is a compliance decision that must be claimed deliberately, not inherited from a role name.
  - Allowed PII now derives **only** from the caller's permissions (`view_full_pii` → ssn, credit_card, bank_account, email, phone, address; plus the existing `view_basic_pii`/`view_financial`/`view_medical`). No role is special-cased anywhere on this path, and the blanket `"*"` allow-all is gone.
  - **`view_full_pii` is deliberately NOT held by any system role - including `admin` and `owner`.** It is seeded on no role *and* excluded from wildcard expansion (`ExplicitGrantOnlyPermissions`), because merely registering it would have made `"*"` grant it - silently handing it to both `admin` and `owner` and re-creating, one layer down, the exact "role implies raw PII" relationship this change removes. A guard test pins `WildcardGrants("view_full_pii") == false`.
  - **Known gap, stated plainly:** the response plane reads `UserContext.Permissions` off the **request**, and nothing yet resolves a portal role assignment into it. So granting `view_full_pii` on a role in the portal does **not** currently reach the enforcement site, and the visibility claim on that plane is caller-asserted - exactly as the role literal was. This change does not alter that trust model; it makes the grant explicit and role-agnostic and removes a blanket allow-all. Server-side resolution of the response plane's permissions is tracked separately. Do not describe this as a working portal control until that lands.
  - **Impact:** on a DB-backed deployment (shared engine active) there is **no behavior change** - that plane already redacted regardless of role. On a deployment running the legacy fallback, an `admin`-role caller that relied on receiving unredacted responses now receives **redacted** responses until `view_full_pii` is granted. This is intentional and is the compliant default.
  - **Runtime proof:** `runtime-e2e/3001_pii_permission_driven/` drives a live agent + orchestrator and asserts that across privileged and unprivileged roles and every PII-visibility permission - including a caller literally claiming `"*"` - the response is *served* and the SSN is *masked*. It pins the invariant on the plane that actually runs.
  - Also fixed in the same class: the risk calculator's `admin_query` weight matched only the `"admin"` literal, scoring `owner` - the strictly more privileged role - as *lower* risk. Both roles now carry the weight, via the shared `identity.RoleIsAdministrative` predicate (a local helper here would be a second definition of "administrative role" - exactly the drift this entry is about). **Behavior change with the same reachability caveat:** `risk_score` is an evaluable dynamic-policy condition field, so on an org with a `risk_score >= 0.5` deny/approval policy an `owner` may now be gated where it previously was not. `RiskCalculator` lives only on the in-memory `DynamicPolicyEngine`, which is selected only when the database-backed engine fails to initialise - i.e. the same no-DB deployments as the PII change above.

- **SCIM deprovisioning now revokes the roles it granted (Enterprise, #3030).** *(Enterprise)* Deleting a user over SCIM (`DELETE /Users`) or deactivating them (`active=false`, PATCH or PUT) removed only the directory row - the `role_assignments` rows the SCIM group→role mapping had granted survived, and the fleet identity resolver keys on `role_assignments`, not on the directory. A deprovisioned user whose OIDC access token had not yet expired therefore **kept their role, and with it their audit-read scope, until the token's TTL ran out** - observed live as a deactivated *and* a deleted `policy_admin` still reading the whole tenant trail. Path B (OIDC/SCIM) only; admin-minted Path A tokens carry the role in-token with their own revocation path and were unaffected. Fixed at both layers:
  - **Deprovision revokes, fail-closed.** User deletion revokes the SCIM-sourced role assignments **before** removing the directory row, so a revoke failure is a retryable error while the row still exists - never a committed delete with grants left behind; a transient directory lookup failure fails the DELETE rather than silently skipping the revoke. Deactivation (`active` transitioning to `false` on either the PATCH op or a PUT replace - including Azure AD's stringly-typed `"True"`/`"False"` wire shape) revokes the same way. Reactivation re-syncs roles from the user's **current** group memberships, so re-enabling a user restores exactly what their groups confer today - not what they held when deactivated.
  - **Group syncs never re-grant a deactivated user.** The group→role sync computes a deactivated (or absent) directory identity's expected roles as **empty** - so a routine directory push that touches a group a deactivated user still belongs to (adding a different member, a mapping change, a group replace) revokes lingering grants instead of silently resurrecting the revoked role.
  - **The resolver refuses stale grants.** Defense-in-depth in the fleet identity resolver: no role is conferred while the SCIM directory row for that identity is marked inactive - even a missed revoke cannot confer read authority for a deactivated identity. This refusal is deliberately blanket on the fleet plane: a manually-granted role on the same email stays in **storage** (directory lifecycle only ever deletes `source='scim'` rows) but is not **conferred** while the directory says inactive; the portal plane does not use this resolver, so a deactivated last owner can still act in the portal - no lockout. Existence-guarded - deployments without a SCIM directory (community builds, pre-SCIM schemas) and principals that never came from SCIM are untouched.
  - **Runtime proof:** `runtime-e2e/3028_sso_scim_full_lifecycle/` drives the full lifecycle against a live stack (real OIDC issuer, real `/scim/v2` wire shapes from two IdP families) and asserts the deprovision legs strictly: a deactivated or deleted user's still-valid token resolves to no role and reads zero tenant rows; a routine group touch after deactivation does not re-grant (while the active member added by the same touch does receive its role); reactivation restores scope.

### Upgrade notes - the RBAC bundle (#2993 / #2995 / #2996 / #2997 / #3000 / #3001)

This release turns RBAC roles into real, enforced authorization. Read this before upgrading: some sessions that could act yesterday get a `403` today, **by design**.

**Migrations:** `core/148` (reconcile the system-role definitions), `core/149` (owner assignment backfill + bootstrap), `core/150` (the owner grant requires a real identity, #3000), `core/151` (backfill `policy_admin` for zero-assignment orgs, #3004) and `core/152` (drop the `contact_email` owner-drift trigger, #3003). All are idempotent and ship down migrations. None rewrites a large table; no maintenance window is required.

| Who | What changes on upgrade day |
|-----|----------------------------|
| **Existing `admin`s** | **Keep SSO/SCIM/detection-posture config.** `sso:configure` becomes owner-reserved, but migration `core/149` grants every principal that effectively held it before the upgrade the `owner` role - so the capability is preserved through a real role, not through the wildcard. |
| **Newly granted `admin`s (after the upgrade)** | Do **not** get `sso:configure`. The `admin` ≠ `owner` split applies to roles granted from now on; assign `owner` to whoever should configure identity. |
| **`viewer` / `developer`** | **Can no longer create, edit, or delete policies** (#2996). Policy reads are unchanged. Grant `policy_admin` (or `admin`/`owner`) to anyone who needs to author policy. |
| **A role-less operator** (the default self-hosted `org_id` + password login) | **Could no longer write policies** under #2996 alone. #2997 restores it: on `enterprise`/`in-vpc-*` deployments the portal grants that operator the `owner` role at boot, which carries `policy:write`/`policy:delete` and `sso:configure`. Tenant-wide **reads** were never affected. |
| **`policy_admin` per-user tokens** | Now read **tenant-wide** on the fleet plane (previously own-rows). |
| **`member` tokens/assignments** | Normalize to own-rows - runtime unchanged. `member` is no longer mintable. |
| **The default self-hosted operator's identity** (#3000) | Now a real address instead of `""`. An org with no `contact_email` presents `AXONFLOW_PORTAL_ADMIN_EMAIL` (default `portal-admin@axonflow.invalid`); set it to your operator's real address **before upgrading** so the audit trail names a person. Owner is re-granted on that identity at portal boot - **no action required, and no lockout**. Any pre-existing `''`-keyed owner grant is deleted by `core/150`. <br/><br/>**Changing it later** does not move an existing grant: the previous identity keeps `owner` and the new one holds nothing. `EnsureDeploymentOrgOwner` re-grants only the *deployment* org, and only in `enterprise`/`in-vpc-*` modes - for anything else, re-grant with the break-glass endpoint after changing the value. |
| **Audit attribution for org-password portal sessions** (#3000) | Portal-proxied writes (canonical audit rows, `workflow_steps.approved_by`) for an org-level password session were attributed to the synthetic `<org>@axonflow.local`; they now carry the real bootstrap identity. **Historical rows keep their old value**, so a dashboard or drill-down that filters on `<org>@axonflow.local` needs updating to also match `AXONFLOW_PORTAL_ADMIN_EMAIL`. |
| **Any session with an empty/unmapped email claim** (#3000) | **No longer inherits `owner`.** If an SSO/OIDC integration was (unintentionally) relying on an unmapped email claim resolving to the bootstrap owner, map the claim to a real identity and assign it a role explicitly. |
| **A changed `contact_email` no longer re-keys `owner`** (#3003) | The DB trigger that re-seeded the owner grant onto whatever address `contact_email` was changed to is **dropped** (`core/152`): it conferred the top role anonymously to anyone able to write that column. Re-keying the operator identity is now an explicit, audited admin-API action. |
| **Stale owner grants after a contact-email change** (#3003) | Because that trigger only ever **added** grants, an org that changed `contact_email` in the past still has `owner` on the **OLD** address - and it is reachable by any SSO/OIDC/SCIM principal still presenting it. Neither `core/150` nor `core/152` revokes a live owner (removing one from a migration is its own outage risk). **Audit `role_assignments` for owner rows on addresses you no longer recognise and prune them through the roles API.** |
| **Callers relying on admins seeing raw PII** (#3001) | **Now receive redacted LLM responses.** The implicit `role == "admin"` redaction bypass is removed. To restore it deliberately, grant `view_full_pii` to the role that should hold it. |

**If an org still ends up with no owner** - possible when *no* principal held `sso:configure` before the upgrade (e.g. an org whose only assignments are viewers), the migration logs it as a `NOTICE` rather than failing. Recover with the break-glass endpoint:

```bash
# Who owns this org right now?
curl -s -H "X-Admin-API-Key: $ADMIN_API_KEY" \
  https://<portal>/api/v1/admin/organizations/<org_id>/owner

# Assign the first owner. Omit the body to use the org's own login identity.
curl -s -X POST -H "X-Admin-API-Key: $ADMIN_API_KEY" \
  -H 'Content-Type: application/json' -d '{"user_email":"ops@example.com"}' \
  https://<portal>/api/v1/admin/organizations/<org_id>/owner
```

It is idempotent, requires an authenticated admin key in **every** deployment mode, and writes an `ASSIGN_OWNER` row to `admin_audit_log` on every attempt. A `409 NO_SYSTEM_OWNER_ROLE` means a **custom** role is occupying the canonical name `owner`; rename it, then re-seed with `psql "$DATABASE_URL" -c "SELECT ensure_org_system_roles('<org_id>');"` and retry. (Restarting does not help - the seeder is not re-run at boot for an already-seeded org.)

## [9.11.0] - 2026-07-17 (streaming prompt-DLP, seam-capability obligations & Path B fleet-identity fixes)

Makes inline prompt-DLP work on **streaming** LLM chat, moves the "what happens when a seam can't redact" decision from the enforcement point back into the platform behind an org-configurable posture, closes a class of governance-signal gaps where a **matched PII policy could return a bare allow**, and fixes the SSO/SCIM org-key and role-seeding defects that blocked fleet OIDC (Path B). **Migrations `core/144`-`core/147`** (existence-guarded, with down migrations). **Three deliberate behavior changes** - see Changed.

### Added

- **Streaming-safe ext_proc request redaction for SSE completions (Enterprise).** *(Enterprise)* The `axonflow-gateway-adapters` ext_proc seam now validates gateway body modes **per direction** instead of OR-ing them: `requestBodyMode: buffered` + `responseBodyMode: none` is accepted under a new adapter-side opt-in, `AXONFLOW_EXTPROC_RESPONSE_GOVERNANCE=off` (default `buffered` keeps today's fully-governed contract; any other value refuses to boot). On such a leg the prompt is still decided and engine-redacted in full before the provider sees it - deny blocks pre-stream, `AXONFLOW_FAIL_MODE` and the body-size bound unchanged - while the completion streams back as SSE with no adapter latency. **The response body is not scanned on an opted-in `none` leg**; the posture is logged at startup and once per stream. This is the seam for inline prompt-DLP on streaming LLM chat, which previously required disabling body inspection entirely. (#2959, PR #2966)
- **Seam-capability-aware obligations + `obligation_fallback` posture (Enterprise).** *(Enterprise)* `POST /api/v1/decide` now emits **only the obligations the calling seam can fulfill**: a PEP advertises its seam via `DecideRequest.fulfillment_capabilities` (vocabulary `request_body_redaction`, `request_header_mutation`; a capability-aware seam always advertises ≥1). A request-body redaction suppressed on a non-body-capable seam (e.g. Envoy ext_authz, headers-only) applies the org's new **`obligation_fallback`** detection-posture category - `log` (default: allow, no obligation, canonical audit row records the suppressed redaction + detected categories) or `block` (deny) - resolved server-side from the org, never from the request. Absent/empty capabilities = legacy caller, byte-identical pre-9.11.0 behavior (all SDKs unaffected). The gateway adapter's local `allow → 403` conversion is deleted; a never-fires fail-closed backstop remains for platform-version skew. Advertised as capability `seam_capability_decisioning`. Portal: Settings → Governance → Detection Posture; migration `core/144`. (#2958, PR #2961)
- **Per-org fleet system roles seeded + non-fleet SCIM role mappings rejected (Enterprise).** *(Enterprise)* Every organization now has the six fleet system roles (`admin`, `owner`, `policy_admin`, `developer`, `member`, `viewer`) via an org-creation trigger + one-time backfill (`core/146`), so `GET /api/v1/scim/roles` returns a mappable set and Path B group→role mapping works on every org. Mapping a SCIM group to a non-fleet role name is rejected with `400` instead of silently dropping members to least privilege. (#2963, PR #2969)
- **`caller_name` replaces the misnamed `tool_type` on the tool-call audit surface (Community).** *(Community)* The `audit_tool_call` MCP tool and the orchestrator `ToolCallAuditEntry` gain a `caller_name` field identifying which client/integration made the call (e.g. `claude_code`, `codex`, `cursor`, `openclaw`). `tool_type` - which every real caller used to identify *itself*, never to classify a tool - is **soft-deprecated**: still accepted as a legacy input fallback, but no longer authoritative. The value is resolved centrally in the orchestrator through the chain `caller_name` → legacy `tool_type` → an **`"unknown"` terminal default (#2903)**; an unidentified caller is no longer attributed to the specific client `claude_code`. **New audit rows write `policy_details.caller_name` and no longer write `policy_details.tool_type`.** **SIEM impact:** consumers keying on `policy_details.tool_type` for tool-call attribution must move to `policy_details.caller_name`; unattributed calls now read `caller_name = "unknown"` rather than `tool_type = "claude_code"`. Historical rows are not backfilled, and the WCP/HITL plane still writes a genuine `tool_type` call-kind (`function`/`mcp`/`api`), which is unaffected. In the portal audit detail *(Enterprise)*, a new-style row surfaces its client under a **Client** row while a WCP `tool_type` stays under **Tool type** - the two render as independent rows. (#2953, #2903, #2912)
- **Response-plane two-field tool identity on check-output (Community).** *(Community)* `MCPCheckOutputRequest` gains a `tool` field (mirroring the check-input `server`/`tool` split added in 9.10.0), threaded into the response-plane capability-scoping identity so it stays `server.tool` once the langgraph de-concatenation SDKs - which send bare `server` plus a `tool` key the platform previously ignored - ship. Without it those SDKs degrade response-plane scoping to `server`, re-running execution-class detectors on document-classified tool output and regressing the #2802 documentation-FP hardening for LangGraph users. (#2955, PR #2975)
- **Client support for `caller_name` (dual-send).** The Claude Code, Cursor, Codex, and OpenClaw plugins add `caller_name` to their `audit_tool_call` payloads, **dual-sent alongside the legacy `tool_type`** for the deprecation window. Attribution is exact on a #2953+ platform (where `caller_name` wins) and unchanged on any pre-#2953 platform (where the legacy `tool_type` still attributes the row), so the plugin minors can ship independently of a customer's platform upgrade without an attribution regression; `tool_type` is dropped in a later plugin release once the platform floor includes #2953. Ships as Claude Code **1.11.0**, Cursor **1.7.0**, Codex **1.7.0**, OpenClaw **2.8.0**; `/health` recommendations advertise these plus the **9.0.0 SDK majors** (go/python/typescript/java - langgraph de-concatenation; rust unchanged at 0.8.1; min floors unchanged). (#2912)

### Changed

- **Behavior change - ext_proc `responseBodyMode: none` now requires the adapter opt-in (Enterprise).** *(Enterprise)* Earlier adapters accepted a `none` response advertisement silently (the response plane simply never ran), so a gateway-config edit alone could switch response governance off. A `none` leg is now rejected fail-closed unless the adapter runs with `AXONFLOW_EXTPROC_RESPONSE_GOVERNANCE=off` - deployments already running `responseBodyMode: none` must set the variable when upgrading the adapter. Partial modes (`bufferedPartial`, `streamed`, `fullDuplexStreamed`) remain rejected in both directions and both postures. (#2959, PR #2966)
- **Behavior change - `pii-indonesia` is now evaluated on the proxy and OpenAI-compatible planes (Community).** *(Community)* Those planes hand-listed their PII categories and omitted `pii-indonesia`; all request planes now converge on one canonical PII category set. Under the default `redact` posture a matched KTP/NIK is now redacted on those planes (previously forwarded untouched); under a `block` posture those planes now **deny KTP/NIK traffic they previously forwarded** - the largest-impact change in this release; review your Indonesian-PII posture before upgrading. Under `warn`/`log` these planes gain evaluation + telemetry parity only (no new redactions). Relatedly, `warn`/`log` PII postures **no longer silently redact** - they emit an advisory reason and leave content unmodified. (#2965, PR #2970)
- **Behavior change - headers-only seams default to `log`, not deny, on an unmaskable redaction (Enterprise).** *(Enterprise)* Where the gateway adapter previously converted an allow-with-redaction into a local 403 on a headers-only seam, the platform now applies the org's `obligation_fallback` posture, default `log` (allow + audited suppressed-redaction). **Set `obligation_fallback = block` to restore deny-on-unmaskable.** (#2958, PR #2961)
- **Advertised plugin recommendations updated to the published v9.10.0-train versions** - claude-code 1.10.0, cursor 1.6.0, codex 1.6.0, openclaw 2.7.0 (claude-desktop stays 0.3.1); min floors unchanged. (#2962)

### Fixed

- **Matched PII policy can no longer yield a bare allow (Community).** *(Community)* `/api/v1/decide` returned `allow` with no obligation and no reason while `evaluated_policies` named a matched, block-configured Indonesian KTP policy: the obligation bridge classified PII with a duplicate agent-local category switch that omitted `pii-indonesia` and derived redaction from category rather than the resolved action. The duplicate predicate is deleted (converged on the shared prefix predicate), the verdict mapping is action-aware (`redact` ⇒ obligation, `warn`/`log`/other ⇒ advisory reason, `block` ⇒ deny), and a registry cross-check + class guard pin that a matched `pii-*` policy always produces a governance signal. Code-only. (#2965, PR #2970)
- **In-VPC Path B / OIDC: SSO configuration org key decoupled from tenant id (Enterprise).** *(Enterprise)* The portal wrote a deployment-collapsed tenant sentinel into `sso_configurations.org_id` (the RLS isolation key), so org-scoped readers missed the row and the fleet OIDC verifier rejected every in-VPC Path B token fail-closed. `org_id` now always carries the real org; migration `core/145` repairs sentinel rows in place. (#2960, PR #2968)
- **SCIM `role_assignments.org_id` keyed on the real org, not the portal tenant id (Enterprise).** *(Enterprise)* The SCIM plane wrote `role_assignments.org_id` from the session tenant while the fleet role resolver reads by authenticated org - where the two diverge, Path B developers silently resolved to least privilege. Writes now key on the real org across both the session and bearer/IdP-sync paths (the bearer tenant→org lookup runs on the BYPASSRLS admin pool and fails closed on resolution errors), `SyncUserRoles` validates mapped roles under the org, and migration `core/147` repairs historically mis-keyed rows (skipped rows are reported for operator re-sync). (#2964, PR #2971)
- **Migration `enterprise/117` made idempotent + migration-wait hardened (Community).** *(Community)* Five `CREATE POLICY` + two `CREATE TRIGGER` statements had no drop-guards, so a container recreate mid-migration left objects created but the migration unrecorded - bricking every subsequent boot; the SDK-smoke workflow also polled `/health`, which the agent serves before migrations complete. Both layers fixed. (PR #2961)

## [9.10.0] - 2026-07-17 (per-user identity & role-scoped authorization for fleet deployments)

Closes the fleet broken-access-control epic: in a fleet where every developer's plugin authenticates with one shared `org:license` credential, that credential granted **attribution, not authorization** - any holder could read the entire tenant's audit trail, decisions, overrides, per-user cost, and execution history. This release resolves the caller into a validated, non-forgeable `{identity, role}` on the fleet plane and role-scopes every cross-user read. **Migrations `core/143` + `enterprise/135`** (existence-guarded, with down migrations). **Behavior change:** a shared-credential caller with no per-user token now reads **zero rows** from the governed read tools - see Changed.

### Security

- **Role-scoped audit / decision / override reads (Enterprise).** *(Enterprise)* The presenting fix: the fleet read tools (`search_audit_events`, `list_recent_decisions`, `list_overrides`) and the equivalent API reads are now scoped server-side (SQL `WHERE`, never post-fetch) - a developer role reads only their own `user_email` rows, an admin/owner reads the full tenant. The census is exhaustive: audit/decision/override, plus the whole-tenant compliance/evidence **exports** (admin-gated, since a per-user export is meaningless) and the adjacent **cost/usage** and **replay/execution** surfaces - a different data domain reachable with the same credential; both stamp a shared license identity, so a non-admin is denied (403) rather than given a vacuous filter, with cross-org isolation on every by-id route.
- **Shared synthesized identities fail closed (Enterprise).** *(Enterprise)* Every shared synthesized identity the platform mints (`mcp-client:*`, the reserved `@axonflow.local` / `@axonflow.internal` service domains, the evaluator identity) is matched against a single canonicalized census predicate at the read-scope boundary and empties the scope, so a read can never resolve to a multi-developer pool. A validated per-user identity reads its own rows normally; near-miss customer domains are untouched.

### Added

- **Per-user identity foundation for the fleet plane (Enterprise).** *(Enterprise)* `authenticateMCPServerRequest` resolves a validated, non-forgeable `{identity, role}` - replacing the forgeable `X-User-Email`-only identity and the hardcoded `role: unknown` - on a pluggable validator seam shared by both provisioning backends below.
- **Per-user token provisioning - the two validator backends for fleet identity (Enterprise).** *(Enterprise)* Part of the fleet-identity epic: fleets that authenticate every developer's plugin with one shared `org:license` credential get attribution, not authorization. This delivers per-user credentials on two paths, both producing a validated, non-forgeable `{identity, role}` for the fleet plane's pluggable validator. **Path A (AxonFlow-managed):** an admin-plane API (`/api/v1/admin/organizations/{org_id}/user-tokens`) mints, rotates, and revokes per-user HS256 tokens with an admin-assigned role. Because the role travels as a JWT claim, mint/rotate/revoke require a valid `X-Admin-API-Key` **even in deployment modes where admin auth is otherwise optional** - a developer can never mint themselves `role: admin`. Tokens carry a required `exp` (default 30d, capped 1y) and a `jti`; revocation is a server-side deny-list (enterprise migration 135) consulted on every validation, fail-closed. **Path B (IdP-issued OIDC):** a per-tenant OIDC configuration on `sso_configurations` (core migration 143, CRUD now gated on `sso:configure`) drives a new asymmetric verifier that validates JumpCloud/Okta/Azure-AD tokens against the IdP JWKS - RS256 only (`alg:none` and HS256 algorithm-confusion rejected before any key is consulted), `iss`/`aud`/`exp`/`nbf` enforced, JWKS cached with kid-miss refetch for signing-key rotation, and the role resolved from the SCIM-synced directory rather than any token claim so IdP misconfiguration cannot escalate privilege. The SSO-config mutation endpoints, which rewrite an org's authentication trust anchors, are now enforced behind `sso:configure` (previously declared but unenforced). Migrations `core/143` + `enterprise/135` are existence-guarded with down migrations. Fleet-scale provisioning for both paths, including end-to-end JumpCloud OIDC, is documented in `docs/enterprise/per-user-token-provisioning.md`.
- **Advisory-plane server / tool identity fields.** *(Community)* The `check_policy` / MCP check-input schema and `DecisionTarget` gain distinct `server` and `tool` identity fields (previously one caller-supplied string was duplicated into both), surfaced in the portal audit view. Additive and backward-compatible (`omitempty`). This is one self-contained addition from the separate audit-identity epic that landed ahead of this release; the remainder of that epic follows in a later release.
- **Client support for per-user tokens.** The Claude Code (**1.10.0**), Cursor (**1.6.0**), Codex (**1.6.0**), and OpenClaw (**2.7.0**) plugins now send the per-user token as `X-User-Token` on every governed surface (unconfigured behavior unchanged); the LiteLLM integration (**1.0.4**) fails **closed** on a platform policy rejection even under `fail_open`, while still honoring `fail_open` on a genuine engine outage. `/health` advertises the new recommended plugin versions.

### Fixed

- **Token-machinery robustness (Enterprise).** *(Enterprise)* Per-user token revocation on the request hot path is short-TTL cached (invalidated by the per-user mass-revoke watermark, fail-closed on any checker error); fleet-validator registration moved to a deterministic startup step with a warning when a token is presented but no validator is registered.

### Changed

- **Behavior change - fleet read tools require a per-user (or admin) identity (Enterprise).** *(Enterprise)* The MCP read tools and equivalent API reads are role-scoped: a caller presenting only the shared `org:license` credential with no per-user token resolves to a shared identity and reads **zero rows**, where it previously read the whole tenant trail. Provision per-user tokens (admin-minted or IdP/OIDC) or call with an admin-role token to restore reads. Single-operator and Community-mode deployments are unaffected.

---

## [9.9.0] - 2026-07-11 (per-user audit attribution unified + session-override forgery hardening)

**Security + correctness.** v9.9.0 unifies per-user audit attribution across all four governance planes behind an opt-in trust gate (`AXONFLOW_TRUST_IDENTITY_HEADERS`, default off), and closes a forged-identity session-override hijack - a deny→allow flip in which one governed user could apply another user's active session override - across the request-plane governance and workflow endpoints. No database migration. **Behavior change:** the planes that previously honored client-asserted identity headers unconditionally now ignore them unless the gate is on - set `AXONFLOW_TRUST_IDENTITY_HEADERS=true` on the agent (after confirming your identity source is trusted) to retain per-user attribution.

### Fixed

- **Per-user audit attribution unified across all four governance planes, behind a trust gate.** *(Community)* The client-asserted `X-User-Email` / `X-Session-Id` / `X-User-ID` headers were honored on only two of the four governance planes - MCP check-input and MCP-server `tools/call` read them unconditionally, while `/api/v1/decide` and MCP check-output ignored them entirely. The split had two consequences: PEPs that front many principals behind one org:license credential (the Claude Desktop proxy calls only decide + check-output) silently lost per-user attribution - every action attributed to the fleet service identity - and on the two planes that did read the headers, ANY governed caller could forge another principal's audit identity, including hijacking another user's active ADR-044 session override (a deny→allow flip keyed on the unvalidated header). All four planes now resolve the headers through one shared trust gate, `AXONFLOW_TRUST_IDENTITY_HEADERS` (default **off**; only the exact string `true` opts in - the same contract as the 9.8.0 gateway adapters): with the gate on, the headers attribute `audit_logs.user_email` / `session_id` on every plane, and per-user features (ADR-044 session overrides, user-scoped dynamic policies) key on that trusted identity - a forged header can never influence a verdict, authz decision, policy selection, or tenant/org resolution; with the gate off, the headers are ignored everywhere and attribution falls back to the validated identity, with a once-per-process detection warning when a request carries identity headers so an operator never silently loses attribution. Additionally, no platform-synthesized SHARED identity - the `mcp-client:<client-id>` pseudo-identity, the `<client-id>@axonflow.local` / `unknown@axonflow.local` service fallbacks, the internal-service and community-SaaS evaluator identities, or the community `local-dev` identity when asserted outside community mode - can create, be offered, or apply an ADR-044 session override on any plane; a shared identity's override would flip a deny for every caller on the client. And every orchestrator ingress that keys an ADR-044 override apply - override-create, the WCP step-gate, the MAP confirm-mode plan-execute and plan-resume, and both workflow checkpoint-resume paths (which re-evaluate a step under the checkpoint's stored actor identity) - now requires the Agent gateway's HMAC proxy token, so a caller reaching the orchestrator directly cannot forge the override identity (Community mode is exempt, matching the existing audit-tool-call enforcement). The MAP execute path additionally derives the checkpoint's actor email from the trust-gated `X-User-Email` header rather than the request body, closing a channel the header gate does not cover. Complementing that, the Agent proxy now trust-gates the per-user identity headers (`X-User-Email` / `X-User-ID` / `X-Session-Id`) on **every** proxied route rather than a per-prefix allowlist: with the gate off (default) a forged per-user identity is stripped before it can reach any orchestrator route, and the auth-derived tenant/org headers and the proxy-auth token are never touched. Advertised as the `identity_header_attribution` capability. **Upgrade note:** deployments relying on plugin-supplied identity headers must set `AXONFLOW_TRUST_IDENTITY_HEADERS=true` on the agent after confirming their identity source is trusted (MDM-managed plugin fleet, desktop proxy, gateway jwtAuth) - until then, per-user attribution, the session-summary/Claude-Code dashboards' per-session drill-down (`session_id` stays NULL on new rows), and per-user session overrides all fall back to the client-scoped identity. The previous always-trust behavior was a forgery exposure and is deliberately not preserved.

---

## [9.8.0] - 2026-07-10 (agentgateway PEP adapters, TIMESTAMPTZ retype, API-reference reconciliation)

**Minor.** v9.8.0 makes AxonFlow directly consumable as the Policy Decision Point behind an agentgateway (or any Envoy-based) data plane: a new Enterprise adapter binary serves agentgateway's three external-PDP seams - ExtMcp, Envoy ext_authz, and Envoy ext_proc - translating each into Decision Mode verdicts and engine-backed redaction with the platform's fail-closed postures intact. On the fix side, every remaining timezone-naive `TIMESTAMP` column is retyped to `TIMESTAMPTZ` (41 columns across 19 tables), closing a class of wrong-instant bugs on deployments whose database session zone is not UTC, and the published API reference (OpenAPI specs plus the Enterprise API pages) is reconciled with the shipped platform surface. One core migration (142) and one enterprise migration (133), both with down migrations and an upgrade-path test covering existing banking/SaaS databases. No SDK or plugin releases ride this train; the advertised compatibility matrix is unchanged from 9.7.0.

### Added

- **agentgateway / Envoy PEP adapters.** *(Enterprise)* A new gRPC adapter binary (`axonflow-gateway-adapters`) lets an agentgateway data plane call AxonFlow as its Policy Decision Point across all three of the gateway's external-PDP seams: `ExtMcp` (MCP `tools/call` governance with engine-mutated tool params and results), Envoy `ext_authz` (headers-only allow/deny), and Envoy `ext_proc` (streaming body inspection with engine redaction of the buffered request body and check-output governance of the response body). The adapters contain zero local policy or redaction logic - every verdict and every mutated byte comes from the engine - and enforce the platform's postures: the request plane defaults to fail-closed (the fail-open opt-in applies only to an unreachable PDP; an engine 4xx or an unfulfillable redaction obligation always blocks, and the headers-only ext_authz seam denies rather than forwards when a verdict carries a redaction obligation it cannot fulfil), while the response plane is unconditionally fail-closed, including when the engine reports redaction was not evaluated. Deny responses carry the decision and trace ids for audit correlation, inbound bearer tokens are passed to the PDP for validation, and a bounded circuit breaker fails fast per plane posture when the engine is repeatedly unreachable. Requires a PDP at platform 9.7.0 or later (the check-output `redaction_evaluated` contract). Ships in the enterprise build, with a reference agentgateway configuration covering all three seams in the runtime-e2e harness; the shared Go PEP package gains a `CheckOutput` response-governance round-trip with its wire shape pinned by contract tests.

### Fixed

- **Timezone-naive timestamp columns retyped to `TIMESTAMPTZ`.** *(Community)* 41 `TIMESTAMP` (without time zone) columns across 19 tables - sessions, API keys, gateway contexts, audit and violation logs, organizations, connectors, evidence exports, and others - stored wall-clock digits with no offset, so components reading or writing them under a non-UTC session silently shifted instants (the original symptom: gateway pre-check approvals expiring at the wrong moment on non-UTC hosts). Core migration 142 retypes the shared tables and enterprise migration 133 the five enterprise-only ones, each in a single transaction with the conversion timezone pinned to UTC regardless of the session zone, dependent views dropped and recreated around each retype - including existence-guarded handling of the banking-vertical retention views that would otherwise abort the migration on upgrades of existing banking/SaaS databases - and exact down migrations. Defensive UTC normalization is added at the confirmed local-time write sites (gateway pre-check expiry and the audit-queue writers), and the test/demo/bootstrap schema copies plus the connector registry's fallback DDL are updated to match. An upgrade-path test applies the real per-mode migration chains to an existing-release database pinned to a +05:30 session zone and asserts stored instants convert exactly and round-trip through the down migrations.
- **API reference reconciled with the shipped platform surface.** *(Community)* The four OpenAPI specs in `docs/api/` (agent, orchestrator, policy, MAS-FEAT) and the Enterprise API reference pages had drifted from the shipped code: phantom paths that never existed (unprefixed MCP check routes, top-level accuracy/conformity families, circuit-breaker activate/deactivate), missing shipped endpoints (audit session-summary, audit export and report, the OJK module, the dynamic-policies family, OTLP metrics/logs ingest, the full HITL surface), and wrong shapes (the audit-search response envelope, check-output response fields, the circuit-breaker schema). Every documented operation is now verified against handler source, the MAS-FEAT spec is re-wired into the OpenAPI CI gates it had silently dropped out of, and the agent spec is kept in lockstep with the path-template registry used by analytics (enforced by a regression test). The EU-AI-Act endpoint family the reconciliation had initially removed is restored as documented proxied endpoints - those routes are real and served through the agent's proxy to the orchestrator.

### Changed

- **The agent spec now states the single-entry-point contract explicitly.** *(Community)* `docs/api/agent-api.yaml` carries a cross-reference note that every `/api/v1/*` endpoint is reachable through the agent - the deployment's single entry point - and that endpoints the agent transparently proxies to the orchestrator are documented in `orchestrator-api.yaml`, rather than duplicating the roughly twenty proxied endpoint families into the agent spec and maintaining both copies in lockstep.

---

## [9.7.0] - 2026-07-10 (fail-closed hardening sweep, per-client version telemetry, SDK/plugin compat refresh)

**Additive minor.** v9.7.0 ships the hardening found by an adversarial end-to-end sweep of the platform, portal, and all five SDKs. The policy engine's request plane now fails closed when policies cannot be loaded, the gateway pre-check no longer executes a query it has just blocked, MCP check-output now tells a policy-enforcement point whether redaction actually ran, and the portal session drill-down that v9.6.1 enabled at the API is now reachable from the UI and honored on export. Enterprise deployments gain per-client version-distribution telemetry, and the advertised SDK/plugin compatibility matrix is refreshed: SDKs 8.5.1 (Rust 0.8.1 joins the matrix), Claude Code plugin 1.9.1, and the Claude Desktop governance proxy joins at 0.3.1. No migration.

### Added

- **Per-client version-distribution telemetry.** *(Enterprise)* Self-hosted Enterprise deployments previously had no visibility into which client versions their fleet runs - how the Claude Code plugin's version drift went unnoticed, and a total blind spot for the Claude Desktop proxy. The agent now records the validated `X-Axonflow-Client` client id + version pair on the decide and MCP check-output planes into a new Prometheus counter, `axonflow_client_version_requests_total{plane, client, client_version}`, with an `axonflow_client_version_dropped_total{reason}` companion for absent/invalid/over-cap values. Values are shape-validated and series-capped so a hostile header cannot mint unbounded label series, and the capture is telemetry-only - it is never consulted for auth or a verdict. Community builds compile the capture to a no-op and register no series. Advertised as the `client_version_telemetry` capability. The Claude Desktop proxy v0.3.1 companion release identifies itself as `mcp-proxy/<version>` on both planes.
- **Rust SDK and the Claude Desktop proxy join the `/health` compatibility matrix.** *(Community)* `/health` on both ports now advertises min/recommended versions for the Rust SDK (floor 0.7.0 - the first Rust release speaking the Decision Mode PEP contract - recommended 0.8.1) and for the Claude Desktop MCP governance proxy (floor 0.2.0 - the first release with engine-backed, unconditionally fail-closed response redaction - recommended 0.3.1), so both clients can run the same upgrade-warning gate the other SDKs and plugins already use.

### Fixed

- **The request plane now fails closed when policies cannot be loaded.** *(Community)* On a policy-load / database-unavailable error, the shared policy engine's request plane logged the failure and allowed the request through, silently disabling SQL-injection, dangerous-command, and PII-block enforcement on every request-plane gate (decide, MCP check-input, MCP resources/query and tools/execute, the gateway pre-check, and the OpenAI-compat gateway) for the duration of the outage. The request plane has no "return unprocessed content" middle ground - a request either proceeds ungoverned or is blocked - so it now blocks, symmetric with the response plane's v9.4.x fail-closed hardening, and the result carries an evaluation-error marker so an availability block is distinguishable from a policy verdict in the audit trail.
- **MCP check-output now reports whether redaction actually ran.** *(Enterprise)* `POST /api/v1/mcp/check-output` never populated the `redaction_evaluated` response field the SDKs' PEP contract depends on ("fail closed when false - the redactor did not run, so absent redacted output cannot be trusted as *nothing to mask*"). The field was always false on the wire, forcing a strict response-phase PEP to either over-block every redaction or forward output it wrongly believed had been scanned. check-output now emits `redaction_evaluated` exactly as check-input already did, restoring the advertised two-touch redaction contract.
- **The gateway pre-check no longer returns connector data on a blocked or pending request.** *(Enterprise)* The pre-check handler fetched connector data for requests it had already denied and attached the rows to the `approved:false` response - a blocked query still executed against the live connector, and a HITL-pending request surfaced data before a human approved it. The connector query now runs only for a clean-approved request; blocked, pending-approval, and approved-with-redaction outcomes return no pre-fetched data.
- **The portal session drill-down is now reachable, and exports honor the active filters.** *(Enterprise)* v9.6.1 fixed the audit-search API's `session_id` filter, but the customer portal never exposed it: the Log Explorer had no session filter input, the detail panel's Session ID was inert text, and both the portal and orchestrator export paths silently dropped `session_id` (plus `decision_id`, `policy_name`, and `override_id`) - so a session-filtered "Export" returned the tenant's entire window. The Log Explorer now has a Session ID filter with a `?session_id=` deep link, the detail-panel Session ID drills into that session, and CSV/JSON exports apply the same filter set the search does, with `session_id` as an export column.
- **Retired unavailable Anthropic model defaults.** *(Community)* A retired model id that the Anthropic API now rejects was baked into roughly a dozen fallback surfaces - compose defaults, provider-config code fallbacks, the Anthropic provider's model constants (which the unified router's failover uses), Bedrock adapter defaults, CloudFormation templates, and demo/example routers - so any provider failover through Anthropic (or the equivalent non-region-prefixed Bedrock id) failed with "all providers failed" whenever the primary provider was unavailable. Fallback ids are now centralized in a shared `llmdefaults` package pinned to current catalog ids (`claude-haiku-4-5-20251001`, and the region-prefixed `us.anthropic.claude-haiku-4-5-20251001-v1:0` on Bedrock), drift tests ban the retired ids from every named config surface, the pricing maps cover the new default ids, and both compose files now map `ANTHROPIC_MODEL` into the agent environment so the override actually reaches agent-side gateway calls.

### Changed

- **Recommended SDK and plugin versions.** *(Community)* `/health` now recommends SDK 8.5.1 for Python, TypeScript, Go, and Java (Go 8.5.1 fails closed on 4xx auth errors; Python 8.5.1 runs sync interceptors on a persistent event loop and detects AsyncOpenAI clients; TypeScript 8.5.1 authenticates `getPlanStatus`; Java was already 8.5.1) and Rust 0.8.1, plus Claude Code plugin 1.9.1 (correct on-wire version reporting) and Claude Desktop proxy 0.3.1. This also closes an agent/orchestrator drift - the orchestrator's `/health` still recommended claude-code 1.8.0 while the agent's advertised 1.9.0. Minimum-version floors are unchanged. All example projects and repo docs are swept to the 8.5.1 / 0.8.1 pins (including several stale doc pins predating 8.5.0).

---

## [9.6.1] - 2026-07-08 (patch on 9.6.0: audit-search session_id drill-down)

**Patch.** Fixes a correctness bug in the audit-search API surfaced while documenting the v9.6.0 session-summary reporting: a `session_id` filter was silently dropped, so the per-session drill-down returned the tenant's rows across all sessions instead of the one requested. Within-tenant only; tenant isolation was never affected. No migration.

### Fixed

- **`session_id` filter on `POST /api/v1/audit/search` is now applied.** *(Community)* The audit-search request handler's body-decode struct was missing the `session_id` field the query layer already supported, so a `session_id` filter was silently dropped and the session-summary "drill into this session" flow returned all of the tenant's rows across every session with a `200`. The filter now reaches the query as a parameterized, tenant-scoped condition, so drilling into a session bucket returns exactly that session's rows. Tenant scoping (from the trusted tenant header) was never affected. Pinned by a handler-level regression test and a runtime-e2e drill-down leg.

---

## [9.6.0] - 2026-07-07 (session-summary reporting API + Claude Code usage dashboard)

**Additive minor.** v9.6.0 turns the Claude Code and Cowork activity v9.5.0 began ingesting into reporting. A new session-summary API rolls governed activity into per-session (or per-user-day) buckets, additively enriched with the developer and session usage metrics when the OTLP ingest is wired; a new operator Grafana dashboard visualizes that usage; and the bundled Grafana datasources are provisioned with stable uids, closing a pre-existing bug that broke provisioned dashboards. One idempotent migration (`core/141`) auto-applies on deploy.

### Added

- **Session-summary reporting API.** *(Enterprise)* `GET /api/v1/audit/session-summary` aggregates `audit_logs` into per-session (or per-user-day fallback) buckets: request totals, an allow / block / redact breakdown, a per-tool (request-type) usage breakdown with tokens / cost / latency, and session-level totals - tenant-scoped, filterable by user, with a bucket cap (`?limit=`, default 200, max 1000) and a `truncated` flag. When the OTLP `/v1/metrics` ingest is configured, each bucket is additively enriched with the Claude Code usage metrics (lines of code, active time, commits, pull requests, tool-permission decisions, session count, and the metrics-export token and cost aggregates); the enrichment is best-effort and gracefully absent when the ingest is not wired, so the base view always works from `audit_logs` alone. In Community the endpoint returns `501` (it is an Enterprise capability).
- **Claude Code Usage Grafana dashboard.** *(Enterprise)* New dashboard `axonflow-claude-code-usage` over the v9.5.0 OTLP-ingest usage records: per-developer and per-session tokens, cost, lines of code, tool-permission decisions, and active time (PostgreSQL panels over `usage_events`), plus an ingest-health row over `axonflow_otel_ingest_rejected_total` (Prometheus). It is an operator/admin cross-org reporting surface - its org filter is a display slice, not a tenant-isolation boundary. Provisioned by the OTel/Grafana overlay and baked into the deployed Grafana image.

### Changed

- **Grafana provisioned datasources now carry stable uids** (`prometheus`, `axonflow-postgres`). *(Community)* The baked dashboards already referenced `uid: prometheus`, which the deployed entrypoint never defined - those panels resolved to "datasource not found" on a fresh deployed Grafana. Dashboards referencing datasources by name are unaffected. **Upgrade note:** a user-authored dashboard saved against the previous auto-generated datasource uid must be re-pointed once. The deployed entrypoint also accepts `USAGE_DB_*` variables so the SQL datasource can target the platform database when `GF_DATABASE_*` points at a dedicated Grafana metadata DB.

### Migration

- **`core/141`** *(Community)*: adds an idempotent `(tenant_id, timestamp, session_id)` composite index to `audit_logs` so the session-summary aggregate scans are index-assisted on large tenants. Additive - no rewrite of existing rows; auto-applies on deploy.

---

## [9.5.0] - 2026-07-06 (Claude Code & Cowork OTLP ingest: /v1/metrics, record-level identity, ingest reject visibility)

**Additive minor.** v9.5.0 completes AxonFlow's ingest of the native OpenTelemetry stream that Claude Code and Claude Cowork emit. A new `POST /v1/metrics` endpoint lands the tools' usage counters (tokens, cost, sessions, lines of code, tool-permission decisions, active time) as canonical, governed usage records; the log-ingest plane now reads the acting developer's identity and session from each record (not only the resource) so activity attributes to a real person; and both ingest planes now emit a per-tenant rejection counter and log line so a mis-configured exporter is diagnosable instead of failing silently. One idempotent migration (`core/140`) auto-applies on deploy.

### Added

- **OTLP metrics ingest (`POST /v1/metrics`).** *(Enterprise)* Claude Code and Cowork export usage as OpenTelemetry metrics (token, cost, session, lines-of-code, commit, pull-request, tool-permission-decision, and active-time counters). AxonFlow now accepts that OTLP metrics stream and lands each datapoint as a canonical `usage_events` row - delta-normalized from cumulative exports, keyed on session and developer, org-tagged from the authenticated license (never from the telemetry) - so aggregate per-developer and per-session usage reporting works over the same store the portal already reads. In Community the endpoint is present but returns 501 (it is an Enterprise capability).
- **Record-level identity on the log-ingest plane.** *(Enterprise)* The OTLP log ingest now reads `user.email`, `session.id`, and the Anthropic account identifiers from each individual log record, with a resource-level fallback - real Claude Code and Cowork exporters place these per record, not on the resource - so governed activity attributes to the acting developer instead of an anonymous placeholder. Per-developer attribution requires the client to be signed in with an Anthropic account; an API-key-only client emits no developer email, and those records remain correctly session-keyed.
- **Per-tenant ingest-reject visibility.** *(Enterprise)* Both ingest planes now emit an `axonflow_otel_ingest_rejected_total{route,tenant,reason}` counter and a log line for every rejected request, so a mis-configured or mis-authenticated exporter is diagnosable rather than appearing as a silent "zero rows, no error." Tenant labels are bounded so an unauthenticated caller cannot inflate metric cardinality.

### Fixed

- **Client control bytes in an OTLP field no longer lose an audit record or drop a metrics batch.** *(Enterprise)* A NUL or other C0/DEL control byte in a client-supplied OTLP field is valid UTF-8, so it survived the prior UTF-8 repair, but the database rejects it and would abort the insert - losing the governed audit row on the log-ingest plane, and rejecting the entire export batch (including every well-formed sibling datapoint) on the metrics plane. Every client-supplied string that reaches storage on either plane is now sanitized - control bytes stripped, ordinary prose whitespace preserved - before persistence.

### Migration

- **`core/140`** *(Community)*: adds nullable OTLP usage columns and three partial indexes to `usage_events` to back the metrics-ingest records above. Additive - no rewrite of existing rows, and a no-op for the new columns until Enterprise OTLP metrics ingest writes them. Auto-applies on deploy.

## [9.4.0] - 2026-07-03 (capability-scoped detection, documentation false-positive hardening, fresh-deploy and audit fixes)

**Additive minor.** v9.4.0 sharpens detection so governed documentation workflows stop tripping execution-oriented detectors, while keeping every real attack governed. Execution-class detectors (SQL injection, dangerous commands) now skip tools whose input is prose rather than executable statements, the loose-verb and comment-based SQL-injection detectors are hardened against documentation text, and several fixes close a self-blocking override path, an empty signed decision chain, a response-plane fail-open on a policy-load error, and portal display and fresh-deploy issues. Three idempotent migrations (`core/135`, `core/138`, `core/139`) auto-apply on deploy.

### Added

- **Capability-scoped policy evaluation.** *(Community)* Execution-class detectors (SQL injection and dangerous-command families) no longer evaluate tools positively classified as text-document tools (documentation editors whose input is prose, not executable statements), so legitimate documentation edits are no longer blocked as though they were code or SQL. Classification happens server-side against a built-in registry and is never taken from an untrusted caller; unknown or unclassified tools get full evaluation (fail-closed), and content-borne families (all PII, sensitive-data, compliance, and prompt-injection guards) evaluate everywhere, including for text-document tools. The `AXONFLOW_CAPABILITY_SCOPING_DISABLED` kill switch restores full evaluation on every tool in both editions. Enterprise deployments can extend the built-in registry with additional tool names via `AXONFLOW_TEXT_DOCUMENT_TOOLS`.
- **Per-category detection corpus gate.** *(Community)* A labeled per-category detection corpus (attack and benign cases) now scores recall on attacks and false-positive rate on benign input in CI, so a change that raises false positives or weakens recall on a governed category fails the build.

### Fixed

- **Documentation text no longer trips the loose-verb, agent-config, and IP detectors.** *(Community)* Several false-positive-prone detectors matched plain English and Markdown as though it were executable input. The SQL-injection detectors for authentication bypass and for `GRANT` / `REVOKE` / `DROP` / `CREATE USER` now require SQL grammar (a quote or paren breakout, or a privilege-and-object clause) instead of a bare English verb; the dynamic-code-execution detector requires call syntax so a hyphenated identifier no longer matches; the agent-config-file detector requires a write or execute context rather than a filename mentioned in prose; and RFC-special and documentation IP ranges (for example the `0.0.0.0/0` allow-all shorthand in a hardening note) are no longer flagged as a person's address. Each replacement pattern is narrower than the one it replaces, so real attacks stay governed, proven by a paired attack corpus.
- **Comment-out SQL-injection authentication bypass is now detected.** *(Community)* The classic comment-out bypass (a string-literal terminator followed by a SQL line comment that comments out the rest of a `WHERE` clause, for example `admin' --`) passed clean through every governed input plane, because the existing comment detectors required a SQL keyword after the comment. A new detector matches a breakout string terminator directly followed by a line comment that ends the line, gated so ordinary quoted arguments and documentation prose (a balanced quoted token, or a comment carrying trailing text) do not match.
- **Override justification no longer blocks its own override request.** *(Community)* A policy-override request whose justification quoted the very content it was overriding was blocked by that justification, making some overrides impossible to submit. The override metadata is now exempt from content evaluation on the governance override tool only; the same content in the override's target scope, or on any other tool, is still evaluated normally.
- **Response-plane now fails closed on a policy-load error.** *(Community)* When the policy engine could not load its policies while processing a response, the response plane failed open and let the content through. It now fails closed on a policy-load error, matching the request plane.
- **Signed decision chain is no longer silently empty.** *(Community)* The non-repudiation decision chain stored no rows at all: the parent request identifier was written through a failing type cast, so every chain-record insert failed (silently, since the write is best-effort). The cast is fixed, so signed decision chains now persist and capture their parent references.
- **Portal fixes: in-VPC deployment mode, policy count, synthetic-identity affordance, and more.** *(Enterprise)* A sweep of customer-portal fixes: the portal now honors the in-VPC enterprise deployment mode, the dashboard shows the unified total policy count rather than the dynamic-only count, the audit Log Explorer gains a synthetic-identity affordance, and a further set of display and data-loading issues across the portal are resolved.

### Migration

- **`core/135`** *(Community)*: hardens the false-positive-prone SQL-injection and dangerous-command detector patterns (pattern-row updates via a new migration; shipped migrations stay immutable). Each update is guarded on the original seeded pattern, so a tenant-customized row is never clobbered. Auto-applies on deploy.
- **`core/138`** *(Enterprise)*: re-applies the v9 `org_id` and row-level-security completion for enterprise tables created by later-numbered migrations (SSO and connector-config tables), which on a fresh enterprise deploy came up without `org_id` or their RLS policies, and additionally allows `redact` as an override action. Every step is guarded and idempotent: it is a no-op on upgraded deploys where the tables already carried the columns, and on community deploys where the tables do not exist. Auto-applies on deploy.
- **`core/139`** *(Community)*: seeds the comment-out SQL-injection detector row (`security-sqli`, warn base action). Idempotent insert; auto-applies on deploy.

## [9.3.1] - 2026-07-02 (patch on 9.3.0)

**Patch.** Two fixes on top of [9.3.0]: policy action override and organization-tier static-policy creation now work for deployments whose organization id is not UUID-shaped, and the customer-portal audit Log Explorer now shows the matched policy on redact/block rows. No new behavior; one idempotent migration (`core/133`) that auto-applies on deploy. See the 9.3.0 entry below for the feature release.

### Fixed

- **Policy override and organization-tier static-policy create no longer 500 for non-UUID organization ids.** *(Community)* AxonFlow organization ids are free-form strings sourced from the signed license, not UUIDs. Four policy tables (`static_policies`, `dynamic_policies`, `policy_overrides`, `policy_evaluations`) carried a legacy `organization_id` column typed `uuid`; binding a non-UUID org id into it failed with `invalid input syntax for type uuid`, which surfaced in 9.3.0 as a hard 500 on the policy action override create path (`POST /api/v1/static-policies/{id}/override`) and on organization-tier static-policy create (`POST /api/v1/static-policies` with `tier: organization`). Migration `core/133` retypes `organization_id` to `text` on all four tables, and `HandleCreateOverride` now scopes the override by the canonical varchar `org_id` plus `tenant_id`, leaving the legacy column NULL. The `valid_override_scope` CHECK constraint, the partial indexes on `organization_id`, and row-level security (which keys on `org_id`) are all type-transparent across the retype. `org_id` is the canonical organization column and RLS key; the legacy `organization_id` remains deprecated and is scheduled for removal.
- **Portal audit Log Explorer shows the matched policy on redact and blocked rows.** *(Enterprise)* The customer-portal audit Log Explorer's Policy column and detail panel rendered blank on PII-redact and blocked rows, because the matched policy is nested in `policy_details` (a `policy_names` array plus `policy_matches` on blocks, and `policy_ids` only on PII redacts) and was never lifted for display. The portal now lifts the human policy name across every shape (scalar, `policy_names` string or array, and all `policy_matches[*].policy_name` joined) and falls back to the matched policy ids on redact rows that carry no name, so a genuinely-matched row is never rendered blank.

### Migration

- **`core/133`** *(Community)* - retypes the legacy `organization_id` column from `uuid` to `text` on the `static_policies`, `dynamic_policies`, `policy_overrides`, and `policy_evaluations` tables. Idempotent and guarded: it only alters a column still typed `uuid`. The retype is a full table rewrite, but the affected tables are small, bounded configuration tables, so it completes near-instantly. Auto-applies on deploy; no operator action required.

## [9.3.0] - 2026-07-02 (audit visibility: per-developer + per-session identity, audit read/report/export API, portal Log Explorer)

**Additive minor.** v9.3.0 makes governed activity visible end to end: per-developer and per-session identity now flows through to the canonical audit row, a read/report/export API exposes the audit trail, and the customer portal gains a filterable, expandable Log Explorer. Claude Code traffic is brought into the same governed view via a Grafana dashboard and OpenTelemetry ingest. One additive migration (`core/129`); the new endpoints are backward-compatible and the remaining changes are behavior-preserving fixes.

### Added

- **Per-developer and per-session identity through to the canonical audit row.** *(Community)* Requests carrying `X-User-Email` and `X-Session-Id` now propagate that identity into `audit_logs`, so every governed decision can be attributed to the developer and session that produced it. Migration `core/129` adds the nullable `audit_logs.session_id` column; the user email lands on the existing identity columns.
- **Audit read / report / export API.** *(Community)* New read-only endpoints expose the audit trail: `GET /api/v1/audit/{id}` returns a single decision record, `POST /api/v1/audit/report` returns per-action counts and top policies for a filter, and `POST /api/v1/audit/export` streams the filtered rows (with a truncation header when a row cap is reached). Redacted values are served as stored - there is no unmask path.
- **Portal audit-logs Log Explorer.** *(Enterprise)* The customer-portal Audit Logs page is rebuilt as a Log Explorer: combinable filters (user email, action, tenant, date range) with pagination, per-row expansion to the full decision record, a report-by-action view, and export of the active filter. Redacted content is rendered as stored and labelled.
- **Claude Code Grafana dashboard and decision origin label.** *(Community)* A new Grafana dashboard visualizes Claude Code governed traffic, and decisions now carry a bounded `origin` metric label (with obligations and blocks series) so decision volume can be sliced by call origin without unbounded cardinality.
- **Cowork / Claude Code OpenTelemetry ingest to canonical `audit_logs`.** *(Enterprise)* An authenticated `POST /v1/logs` endpoint lands Cowork and Claude Code OpenTelemetry log events as canonical `audit_logs` rows (`plane=cowork` / `plane=claude_code`), so agent activity from those hosts is a first-class audit source rather than a satellite table. The ingest is a force-redact storage plane: PII is masked before the row is stored, and it fails closed (withholds the row) when detection is unavailable.
- **Unified policy write dispatcher.** *(Enterprise)* A single `/unified-policies/*` write path now dispatches policy create/update/delete across the system and tenant policy stores, replacing the scattered per-store write handlers.

### Fixed

- **Portal Usage reflects governed Claude Code traffic.** *(Enterprise)* The portal Usage page under-counted governed activity because Claude Code MCP traffic was not attributed to the usage rollup; it now surfaces that traffic.
- **Grafana agent and orchestrator blocked/allowed panels use the real metric names.** *(Community)* The agent and orchestrator dashboards referenced defunct synthetic-exporter series, so the blocked/allowed panels were empty; they now query the real emitted metric names.
- **Policy action override on the static / system path.** *(Community)* The policy action override now applies on the static (system) policy path: it authenticates through the proxy, reads back via the agent `GET`, and keys on `policy.id`, with an allow-flip guard. The redundant dynamic-override path is removed - action override is a system/static-only capability (dynamic policies are edited or deleted directly).
- **Cross-tenant static-policy read/write isolation.** *(Community)* Static-policy reads and writes are now scoped to the caller's tenant, closing a path where one tenant could read or write another tenant's static policies.
- **Executions and Approvals no longer 500 on NULL columns.** *(Community)* The executions list and the approvals list / approve / reject paths failed to scan rows with legitimately-NULL columns (for example a MAP-plan row with a NULL `source`, or workflow-step rows with NULL identity or step fields); those scans now tolerate NULL.
- **SSO setup flow.** *(Enterprise)* The portal SSO page treated a "not configured" backend response as already-configured and never showed the provider selector; the setup flow now renders correctly.
- **SCIM and SSO modal z-index.** *(Enterprise)* The SCIM token and SSO confirmation modals sat beneath their own backdrop, leaving their buttons unclickable; the modal panels are now layered above the backdrop.
- **Compliance evidence export no longer drops audit rows.** *(Enterprise)* The compliance evidence export selected columns that do not exist on the audit row, dropping every `audit_logs` entry from the export; it now derives the blocked flag from the policy decision and the risk score from the stored decision details, and includes the rows.

### Migration

- **`core/129`** *(Community)* - adds the nullable `audit_logs.session_id` column (additive; existing rows and existing callers are unaffected).

## [9.2.2] - 2026-07-01 (patch on 9.2.1)

**Patch.** Three fixes on top of [9.2.1]: the MCP `check_policy` advisory tool now redacts PII on its allow path, the Java example dependencies clear three Jackson CVEs, and an internal license-generation doc is corrected. No new behavior and no migrations; see the 9.2.0 entry below for the feature release.

### Fixed

- **`check_policy` now runs PII detection on the allow path.** *(Community)* The MCP `check_policy` advisory tool returned `allowed: true` without running input PII detection, so a write call carrying an Indonesian NIK (or other PII) could execute with raw PII before the host model had a chance to retry. It now runs the same input redaction as the `check-input` PEP gate and, when redaction fires, returns `requires_redaction: true` plus a `redacted_statement`, so a PEP/plugin (for example `pre-tool-check.sh`) denies the first call and retries with engine-masked content before raw PII reaches the tool. A latent nil-pointer dereference in `evaluateInputPolicies` on the fail-closed path - engine `Blocked` with `BlockedBy` nil when the database is unavailable and `GracefulDegradation=false` - is also guarded.
- **Jackson bumped to 2.22.0 across the example poms.** *(Community)* `jackson-databind` resolved to a version affected by CVE-2026-54512 / CVE-2026-54513 (HIGH) and CVE-2026-54515 (MEDIUM) across the Java examples; 2.22.0 is the lowest published version clear of all three jackson CVEs at CRITICAL/HIGH/MEDIUM. The pins cover the `examples/` and `ee/examples/` poms (literal versions and the `jackson.version` / `jackson-bom.version` properties), with explicit `jackson-databind` overrides added to the gateway-mode and spring-boot examples that previously pulled it transitively via the OpenAI client. `**/pom.xml` is also added to the security-scan path filters so a Maven dependency CVE now blocks a PR instead of only turning the nightly scheduled scan red.
- **Corrected a stale build command in the internal license-generation doc.** *(Enterprise)* The internal license-generation workflow doc (under `technical-docs/`, excluded from the community sync) described the deprecated V1 build - omitting `-tags enterprise` and building from `platform/` instead of the `ee/` module - which produces a binary that emits and validates stale keys. It now documents the correct `-tags enterprise` build from the `ee/` module and points to the canonical generation runbook.

### Changed

- **`/health` now advertises Claude Code plugin 1.7.0 as the recommended version.** *(Community)* The `RecommendedPluginVersion["claude-code"]` value reported by the agent and orchestrator `/health` capability blocks is bumped 1.6.0 → 1.7.0 to ride this patch; the recommended openclaw (2.6.6), cursor (1.5.3), and codex (1.5.2) versions, and every minimum-version floor, are unchanged.

## [9.2.1] - 2026-06-23 (patch on 9.2.0)

**Patch.** A consistency fix on top of [9.2.0]; see the 9.2.0 entry below for the feature release.

### Fixed

- **Audit-verification endpoints registered in path normalization.** *(Community)* The three audit-verification endpoints added in 9.2.0 (`/api/v1/audit/chains/{chainID}/verify`, `/api/v1/audit/records/{recordID}/verify`, `/api/v1/audit/signing-key`) were present in the OpenAPI spec but missing from the request-path template table, so the spec/template consistency check (`TestTemplatesMatchAgentAPISpec`) failed and those paths were not normalized for telemetry roll-up. They are now registered. Routing and behavior were unaffected.

## [9.2.0] - 2026-06-23 (read-only MCP posture, tamper-evident audit signing, turnkey SIEM export, compliance-category enforcement)

**Additive minor.** v9.2.0 hardens governance and audit assurance: a one-config read-only MCP posture, a connector-level database backstop, per-record cryptographic signing of the decision chain (now capturing live traffic) with read-only verification endpoints, a turnkey central-store / SIEM audit exporter, and automatic cross-border `transfer_basis` stamping on the canonical audit row. **Two behavior changes to note (both in Fixed):** the seeded RBI / SEBI / MAS-FEAT / EU-AI-Act compliance policies now actually fire on `/decide` and the gateway (they were silently excluded by a category-spelling mismatch), and a tool/connector response carrying an indirect prompt-injection pattern is now sanitized by default on the response plane (the statement carrying the injection is removed). Everything else is additive and off by default.

### Added

- **Read-only MCP enforcement posture: one config flag blocks every write-path MCP call.** *(Community)* Setting `MCP_READ_ONLY=true` (env, default off) blocks write-intent MCP calls across all connector-execution planes: the `check_policy` advisory tool, the `check-input` PEP gate, `tools/execute`, `resources/query`, and the gateway pre-check. A method-name verb classifier (`classifyMCPCall`) handles tool-call intent, and a SQL statement classifier (`statementIsWritePath`) handles the raw-statement query plane: it masks string literals and comments, rejects stacked statements and dollar-quoted bodies, and catches `SELECT ... INTO` and `EXPLAIN ANALYZE <dml>`, failing closed on anything it cannot prove read-only.
- **Connector-level read-only database transaction backstop.** *(Community)* A new per-call `base.Query.ReadOnly` field lets a connector run a read inside a database-enforced read-only transaction. The PostgreSQL connector honors it by opening `BEGIN READ ONLY`, so the database itself rejects (SQLSTATE `25006`) any write that a statement classifier might miss; it is the durable backstop under the read-only MCP posture above. Byte-identical behavior when the flag is off (no extra round-trip, no transaction). MySQL and Snowflake can adopt the same flag in a follow-up; Cassandra has no read-only-transaction primitive and stays verb-path only.
- **Tamper-evident audit signing + read-only verification endpoints.** *(Community)* Each decision-chain record is now signed with a per-record Ed25519 signature and linked by a `prev_hash` hash chain with a monotonic `chain_seq`, appended race-free under an advisory lock (migration `core/125`). A single record can be verified standalone offline: the response republishes the digest pre-image, record digest, prev_hash, and chain hash so an auditor can recompute and re-verify trusting neither the endpoint nor its digest. Three new read-only endpoints (documented in `docs/api/agent-api.yaml`): `GET /api/v1/audit/chains/{id}/verify` (linkage + every signature, with an `authorship_proven` flag for the strong non-repudiation claim), `GET /api/v1/audit/records/{id}/verify` (one record standalone), and `GET /api/v1/audit/signing-key` (publish the current public key). Signing key and retired-key rotation are configured via `AXONFLOW_AUDIT_SIGNING_KEY` (+ optional `AXONFLOW_AUDIT_SIGNING_KEY_ID`) and `AXONFLOW_AUDIT_VERIFY_KEYS`; when no key is set, records are hash-chained but reported honestly as unsigned.
- **Decision-chain signing now captures live traffic.** *(Community)* The production decision-chain tracker is now a writing instance: real `/decide`, OpenAI-compatible, gateway pre-check, and early-deny decisions are enqueued and signed + hash-chained off the request hot path by async workers (the same instance still backs the verify endpoints, so a record signed here verifies against the keys loaded here). Previously the tracker was instantiated verify-only, so no production decision was ever signed. A `/decide` redaction signs as `approved` (an obligation on an `allow` verdict per the decide → fulfill contract); only the gateway plane records a `redacted` → modified verdict.
- **Turnkey central-store / SIEM audit exporter.** *(Community)* A new exporter ships each decision to an external store off the decision hot path (non-blocking queue with timeout and circuit breaker), so a denied or redacted decision can land in a customer's SIEM or object store without touching request latency. Enabled via `AXONFLOW_AUDIT_SINK=s3` (default empty = disabled; decision path byte-for-byte unchanged when off), with `AXONFLOW_AUDIT_S3_BUCKET` / `AXONFLOW_AUDIT_S3_PREFIX` / `AXONFLOW_AUDIT_S3_REGION` / `AXONFLOW_AUDIT_S3_ENDPOINT` / `AXONFLOW_AUDIT_S3_PATH_STYLE`. Shipped, dropped, failed, and skipped records are metered on `axonflow_central_store_records_total`.
- **Automatic cross-border `transfer_basis` stamping on the canonical audit row.** *(Enterprise)* The orchestrator now auto-stamps the UU PDP Pasal 56 cross-border transfer basis (and derived data-residency) onto the canonical `audit_logs` decision row (columns added in migration `core/126`), resolved per-request, then per-org via `AXONFLOW_ORG_TRANSFER_BASIS`, then a global `AXONFLOW_DEFAULT_TRANSFER_BASIS`, so Pasal 56(b) attestation is turnkey rather than hand-stamped.

### Fixed

- **Indirect prompt-injection is now governed on the response / tool-output plane.** *(Community, behavior change)* The four indirect prompt-injection patterns (instruction-override, role-reassignment, system-prompt exfiltration, and template/bracket markers; migration 116) were seeded `phase='request'`, so `evaluateOutputPolicies` never evaluated them: a malicious instruction returned in a connector free-text field (for example a back-office CRM note) re-entered the model's context ungoverned, even though the response plane already covered SQL-injection, PII, and sensitive-data. Migration `core/128` flips those four `sys_dangerous_injection_*` policies to `phase='both'` and sets their previously-NULL `action_response` (the request-plane action stays `block`), and a new `EnabledSecurityDangerousCategories` helper folds the security-dangerous category into the response evaluation set (the phase flip alone is inert, because `filterByCategories` would otherwise drop the category). Only the injection patterns are promoted; the dangerous-command patterns (migration 059: reverse shell, `/etc/passwd`, `eval`, credential-file access) stay request-only by design, since matching a command description against connector output would hard-block benign data. **The default response-plane action is redact (sanitize):** the sentence/line/clause containing the injection is removed (JSON-aware, preserving valid structure and sibling fields), so no injectable instruction reaches the model, while surrounding legitimate data passes through, overridable per-org to warn or block via the detection-posture override; the input plane still blocks. The outcome is recorded as a canonical `plane=mcp` response audit row. **Behavior change:** a tool/connector response carrying one of these injection patterns now has the injection-bearing statement removed by default.

- **Seeded compliance policies now enforce on `/decide` and the gateway.** *(Community, behavior change)* The seeded RBI, SEBI, MAS-FEAT, and EU-AI-Act compliance policies stored drifted category spellings (`rbi_compliance`, `sebi_compliance`, `mas_feat_compliance`, `eu_ai_act_compliance`) that did not match the canonical category constants (`compliance-rbi`, `compliance-sebi`, `compliance-masfeat`, `compliance-euaiact`). Because the decision filter matches category exactly, those rows were silently excluded and the policies never fired. The industry seeds are canonicalized at source for fresh deployments, and a forward-fix migration (`core/127`, plus `core/014` for EU) realigns existing deployments. **Behavior change:** deployments seeded with these compliance packs will start enforcing them on `/decide` and the gateway.
- **Matched policies surface the policy name, not an opaque UUID.** *(Community)* The orchestrator's active-policy cache is keyed by `policy_id` to avoid cross-tenant name collisions, but `ListActivePolicies` copied that key into the policy's `Name`, so `matched_policies` reported a UUID. It now reads the stored policy name.
- **The OJK cross-border export reads the canonical audit row.** *(Enterprise)* The Indonesian OJK cross-border export is repointed to read the canonical `audit_logs` decision row carrying the stamped `transfer_basis`, consolidating it onto the same source as the rest of the compliance exporters.

### Security

- **`golang.org/x/net` and `golang.org/x/crypto` bumped to clear Trivy HIGH advisories** (`x/net` 0.52 → 0.56, `x/crypto` 0.49 → 0.53) across the flagged modules, restoring a green repo-wide vulnerability scan. Dependency-only; no code or behavior change.

## [9.1.1] - 2026-06-16 (security patch: container CVE, CodeQL hardening, IaC encryption)

**Security-only patch.** No feature or behavior changes. Remediates the high and critical findings from the 2026-06-16 security sweep (epic #2711).

### Security

**Community.**

- **Base image: OpenSSL/libssl3 bumped past CVE-2026-45447.** The agent and orchestrator runtime images now run `apk upgrade libssl3 libcrypto3` so the layer ships OpenSSL >= 3.5.7-r0 (was 3.5.6-r0). A local Trivy rescan confirms the container CVE is gone.
- **Reflected-XSS hardening on the HTTP response paths.** The community-SaaS recovery confirmation page now renders through `html/template` (contextual auto-escaping) instead of `fmt.Sprintf` with a hand-rolled escaper; the transparent response-writer wrappers (idempotency replay, transparency headers, telemetry status capture, customer-portal request logging) now set `X-Content-Type-Options: nosniff` so a reflected value cannot be MIME-sniffed as HTML.
- **Session identifiers are masked in logs.** The MCP server handler now logs only a short prefix of session IDs (bearer-style handles), never the full value.
- **Path-injection guard on the cross-system HITL webhook test harness.** Dump filenames are restricted to a flat token, so a crafted `approval_id` cannot traverse outside the dump directory.

**Enterprise / infrastructure.**

- **Alert SNS topics are now encrypted with a customer-managed KMS key.** The alarm, first-payment, and synthetic-monitoring alert topics use a CMK whose key policy grants exactly the CloudWatch alarm service / canary Lambda the publish permissions they require.
- **New gitleaks CI workflow.** Runs the existing `.gitleaks.toml` rules on every PR/push commit delta, complementing the pre-commit hook and GitHub push-protection. The esbuild dev-dependency in the MCP-policies example was bumped to 0.28.1.

## [9.1.0] - 2026-06-12 - Audit coverage made permanent, policy-inventory truth, a portal policy-display fix, and the sensitive-data lever now enforced

**Community.** v9.0.0 converged every enforcement plane onto one canonical audit vocabulary and closed the then-known early-return-deny holes by hand. v9.1.0 makes that coverage **durable** instead of a recurring pre-release sweep: a deterministic CI gate now fails the build whenever a Policy Enforcement Point's deny path doesn't write a canonical `audit_logs` row, the last remaining agent-plane gaps are closed (so the gate reports zero deferred exceptions), the built-in policy inventory is pinned to a single source of truth, a customer-portal bug that silently hid most seeded system policies is fixed, and the `sensitive-data` governance lever - long documented but inert - now actually enforces. **One behavior change to note:** the `strict` and `compliance` profiles now BLOCK credential/secret detections that previously only logged (see Fixed); set `SENSITIVE_DATA_ACTION=log` to retain the prior behavior. The audit and inventory changes are otherwise additive; a single data migration realigns a legacy sensitive-pattern phase column to the active action with no behavior change.

### Added

- **A deterministic audit-coverage CI gate that ends the recurring "this deny path forgot to audit" surprises.** A new test walks every non-test `.go` file under `platform/` and `ee/platform/`, resolves from the parsed AST every function that calls the policy decision engine (`EvaluateRequest` / `EvaluateResponse` / `EvaluateDynamicPolicies` / `EvaluatePolicy` / `EvaluateStepGate` / `EvaluateMCPPermission` / `EvaluateWithGracefulDegradation`, plus a one-hop set of in-tree policy-delegating helpers), and fails the build if any such enforcement point's deny path doesn't write a canonical row through a blessed audit writer. Every conscious exception lives in a checked-in, reviewed allowlist with a one-line reason - `BY-DESIGN` (engine-internal / adapter / dry-run whose audit is the caller's responsibility, with the auditing caller named) or a tracked deferred gap. This replaces the hand-run coverage sweeps that historically found a fresh batch of holes only after they shipped. The gate's known structural limits - single-hop helper resolution and single-deny-per-function detection - are documented.

### Fixed

- **Every Policy Enforcement Point now audits - the gate reports zero deferred exceptions.** The last agent-plane gaps the new gate flagged are closed so a denied request can no longer return before recording its decision:
  - **Agent `/api/request` denials write a canonical `plane=agent` row.** The agent proxy's terminal denials (circuit breaker, static / tenant policy, HITL gate, budget) previously landed only in the reader-less legacy `agent_audit_logs` table, so an agent-side block was invisible in the portal `/decisions` feed and the compliance exporters. Each deny now also writes a canonical `audit_logs` row via the established decision writer, keyed on the authenticated user / tenant.
  - **The MCP service-license permission gate audits its `403`.** An authorization failure now writes a canonical `plane=mcp` `blocked` row, keyed on the authenticated request identity (never the service-license deployment id, which is the licensee - not a customer tenant); the license key is never passed to the writer.
  - **The legacy in-memory HITL engine audits a fail-open policy-check error.** When the optional in-memory HITL gate's policy check itself errors, the engine still fails open for availability, but the errored governance verdict is no longer lost - it writes a canonical `error` `step_gate` row instead of being silently treated as an allow.
- **The `sensitive-data` governance lever now actually enforces - on both the request and response planes.** *(Community)* The built-in sensitive-data system policies (credentials, tokens, secrets, connection strings) resolved to a hardcoded `log` regardless of `AXONFLOW_PROFILE` or `SENSITIVE_DATA_ACTION` - the documented `default=warn` / `strict=block` posture was a no-op. Sensitive-data is now wired into the action-override map (mirroring SQL-injection and PII) and evaluated on every request plane and the response plane, so the profile and env lever drive it.
  - **⚠️ Behavior change:** the **`strict` and `compliance` profiles now BLOCK** sensitive-data detections that previously only `log`ged, and the **`default` profile now WARNs** (was `log`) - on **both the request and response planes** (a credential-shaped LLM response is withheld under strict/compliance). This matches the long-documented [Governance Profiles](https://docs.getaxonflow.com/docs/guides/governance-profiles/) matrix and the [System Policies](https://docs.getaxonflow.com/docs/policies/system-policies/) reference. A deployment running `AXONFLOW_PROFILE=strict`/`compliance` will start blocking content carrying credentials/secrets. Set `SENSITIVE_DATA_ACTION=log` (or `=warn`) to retain the prior pass-through behavior.
- **Three privileged mutations that were unaudited now write a persistent, secret-free audit row.** Reusing the established writers (no new table):
  - **SCIM bearer-token mint / revoke.** *(Enterprise)* Token create / revoke now emit an `admin_audit_log` event on every outcome, keyed on the session tenant; the row carries only the token id / display prefix / name through an allowlist - the minted plaintext value and its hash structurally cannot be logged.
  - **Deployment upgrade trigger.** *(Enterprise)* The portal's trigger-upgrade endpoint now audits every post-auth outcome (validation / lookup / cloud-API failures and the terminal success / partial / all-failed result) with the session org, initiator, and targeted service; a decode failure is recorded with a fixed label, never the request body.
  - **Legacy in-memory HITL gate verdicts.** A `block` / `require_approval` verdict from the optional in-memory HITL engine now emits a canonical `step_gate` `audit_logs` row.
- **The customer-portal Policies page now shows all seeded system policies instead of silently dropping them.** *(Enterprise / Community)* The unified-policies view fetches the seeded **system** (static) policies from the agent over an internal-service-authenticated call. Both `docker-compose.yml` and `docker-compose.enterprise.yml` defaulted the shared internal-service secret to empty, so on a local / evaluation **enterprise** stack the agent rejected the unauthenticated call with a `401`, and the portal handler silently dropped every static policy - leaving a short list (≈17) that looked complete. The compose files now default that secret to a shared local-dev value across the agent, orchestrator, and portal (real deployments still inject their own secret), and the list / summary / effective unified-policies endpoints now return an additive `partial` flag with `source_errors` so a degraded policy view is never presented as complete.

### Changed

- **The built-in policy inventory has a single source of truth: the migrations.** *(Community)* A dead, never-consumed in-code seed file (`platform/agent/system_policies_seed.go`) that advertised a phantom 106-policy count - and caused confusion about the real number - is deleted, along with the four test files that solely exercised it. The authoritative inventory is now pinned by a red-on-revert real-Postgres test against a fully-migrated database: **79 immutable system policies** (69 static + 10 dynamic), **103 enabled out of the box** (any tier), **112 seeded** rows total. Stale count comments and references to the deleted file were corrected. No runtime behavior change - the deleted Go definitions never reached the database or the engine.
- **A legacy sensitive-pattern phase column realigned to the active action.** *(Community)* A data migration realigns the per-phase action column on the built-in SQL-injection system policies to match their already-relaxed base action, so the stored value no longer contradicts the runtime posture (which is profile-driven). No behavior change - the runtime already used the profile/override action; this removes a stale column that misrepresented the default posture.

### CI / Internal

- **The audit-coverage gate runs as a dedicated, DB-free CI job** wired into the test summary, so every change that adds or moves an enforcement point is checked automatically.

## [9.0.0] - 2026-06-12 - Canonical audit vocabulary: one decision spelling across every plane, enforced at the database

**Community.** v9.0.0 completes the audit-trail consolidation begun in v8.7.0: every enforcement plane now writes the **same canonical `policy_decision` vocabulary**, a database `CHECK` constraint makes a non-canonical write fail loudly, and every reader - the decisions feed, the audit summary, and the SEBI / EU AI Act compliance exports - consumes that vocabulary through one shared normalizer. The audit-coverage work also closes the remaining early-return-deny holes on the MCP, gateway, `/decide`, and control-plane surfaces, so a denied request can no longer slip through unaudited. This is a **major release** because the canonical-verdict cutover changes externally-observable values: the `policy_decision` an integrator reads back, the `decision` filter the `/decisions` API accepts, the outcome strings in regulator-facing exports, and the status of a timed-out HITL approval. See the [v8 → v9 migration guide](https://docs.getaxonflow.com/docs/deployment/v8-to-v9-migration/) for the full impact analysis and upgrade steps. The decision-record convergence this release executes is specified in [ADR-058](technical-docs/architecture-decisions/ADR-058-unified-audit-decision-log.md).

### Breaking changes at a glance

- **`policy_decision`** values are canonicalized and DB-`CHECK`-enforced - `allow`→`allowed`, `deny`/`denied`→`blocked`, `pending_approval`→`needs_approval`.
- **`/decisions?decision=`** rejects the legacy `allow` / `deny` / `require_approval`; filter on `blocked` / `needs_approval` (historical rows still match).
- **SEBI / EU AI Act export outcomes** canonicalized - `allowed`→`approved`, `needs_approval`→`pending_review`. *(Enterprise)*
- **HITL timeout status** - `rejected` → `expired`.

### ⚠️ BREAKING CHANGES

- **`policy_decision` is canonicalized to a single vocabulary, enforced by a DB `CHECK`.** Every writer now persists one of `allowed` · `blocked` · `redacted` · `needs_approval` · `error` (plus the non-verdict marker `override_lifecycle`), and migration `core/123` adds a `CHECK` constraint on `audit_logs.policy_decision` that rejects anything else.
  - **Old → new:** the agent `/decide` writer previously persisted the wire verdicts `allow` → now `allowed` and `deny` / `denied` → now `blocked`; the orchestrator workflow gate previously wrote `pending_approval` → now `needs_approval`. Migration `core/122` backfills the historical `allow` / `deny` / `denied` rows and `core/123` normalizes any residual divergent spelling (an unrecognized value fails **safe** to `error`, never `allowed`) before adding the constraint, so existing history is preserved and uniform.
  - **Impact:** any consumer that reads `audit_logs.policy_decision` directly (or the `decision` field of the `/decisions` list / `/explain` responses) must expect the canonical spellings. A custom writer that inserts a non-canonical value will now be rejected by the database.
- **The `/decisions?decision=` filter is validated against the canonical vocabulary.** The endpoint now accepts the canonical set (including `needs_approval`, which the old `allow` / `deny` / `require_approval` allowlist rejected with a `400`) and **returns `400` for the legacy / phantom spellings** `allow`, `deny`, and `require_approval`. The SQL still expands each canonical value to every historical spelling it covers, so a filtered query matches legacy rows. **Old → new:** filter on `blocked` (was `deny`) and `needs_approval` (was `require_approval`).
- **SEBI and EU AI Act export outcomes use the canonical-derived strings.** *(Enterprise)* Both exports now run each raw `policy_decision` through the shared normalizer before mapping it to a regulator-facing outcome, closing a leak where a raw `allowed` reached the export un-mapped. **Old → new:** `allowed` → `approved`, `needs_approval` → `pending_review` (a human-deferred decision is flagged as requires-review, never silently downgraded to `approved`).
- **A timed-out evaluation-tier HITL approval is recorded as `expired`, not `rejected`.** The auto-timeout path (`expireEvalApprovals`) now writes `status='expired'` to `hitl_approval_queue` and `approval_status='expired'` to `workflow_steps`, and no longer stamps `reviewed_at` (an auto-expiry is not a human review). **Old → new:** a consumer that treated a timed-out request as `rejected` must now handle the terminal `expired` status (the OpenAPI approval-status enum is widened accordingly); the regulator-facing `eu_ai_act_hitl_metrics` view now buckets these as `expired_count` instead of over-counting `rejected_count`.

### Added

- **Canonical audit vocabulary + shared normalizer.** A shared `platform/shared/audit` package (with a TypeScript mirror) defines the canonical verdict set, a `Normalize` function that maps every legacy / divergent / case / whitespace spelling to its canonical value (failing safe to `error`), `IsCanonical` / `All` validation helpers, and a read-side `Spellings` expansion so a canonical filter still matches historical rows. (#2638, #2655)
- **Every writer plane emits the canonical vocabulary.** The agent, orchestrator, MCP, gateway, and decision-API writers were converged onto the shared package; `LogWorkflowOperation` now emits `needs_approval`. (#2638, #2659)
- **Audit-coverage completeness across every early-return-deny path.** A denied request can no longer return before writing its audit row:
  - `/decide` early-return denies (decode / stage / empty-input errors, impersonation / tenant-mismatch blocks) now write a canonical `audit_logs` row with `plane=decision`, carrying the attempted-vs-actual tenant. Migration `core/122` backfills history. (#2643)
  - MCP-plane completeness: previously `StaticResult`-gated dynamic-policy, SQL-injection, and redaction decisions, plus the early-return holes, now write a canonical row via the MCP-plane decision writer (carrying `redacted_fields`). (#2641)
  - The gateway pre-check writes a canonical `audit_logs` row on every verdict and on every deny, with redaction distinguishable from a clean allow. (#2642)
  - Control-plane and auth completeness: `AdminAuthMiddleware` records `AUTH_SUCCESS` / `AUTH_FAILURE`, every admin early-deny audits, and SCIM missing-tenant / invalid-JSON requests write to their dedicated audit tables. (#2644)
  - MCP connector-execution routes (`/mcp/resources/query`, `/mcp/tools/execute`) write a canonical row on every terminal verdict - block, redaction (with `redacted_fields`), and error - that previously landed only in a reader-less satellite, so a connector-level block/redaction is now visible in the decisions feed and exports. (#2625)
  - The OpenAI-compatible `/v1/chat/completions` plane records a policy block as a canonical `audit_logs` row (`plane=openai_compat`), previously trace-only. (#2625)
  - Control-plane mutation completeness: detection-posture set/delete, SSO-config create/update/toggle/delete, and API-key issue/revoke write a config/admin audit row on every outcome (secret-free); the orchestrator media fail-closed block writes a canonical `audit_logs` row before the 403; SCIM group-role-mapping missing-tenant / invalid-JSON early-returns audit like every sibling. (#2625)

### Changed

- **`/health` reports the version baked into the binary.** The platform version is now stamped into the binary at build time via `-X` ldflags (new `platform/shared/version` package) rather than read from the `AXONFLOW_VERSION` environment variable at runtime, so `/health.version` and the `io.opencontainer.image.version` image label can no longer drift. (#2664)

### Fixed

- **MCP `list_recent_decisions` advertises the canonical decision filter.** The agent MCP tool's `decision` argument is forwarded verbatim to `GET /api/v1/decisions`, whose `?decision=` filter now rejects non-canonical values with a `400` (above). The tool's advertised enum was still the legacy `allow` / `deny` / `require_approval`, so any client that picked one of those values got a `400`. The enum is now built from the shared canonical set (`allowed` · `blocked` · `redacted` · `needs_approval` · `error`). (#2676)
- **Removed the broken Request Type filter from the `/audit` page.** *(Enterprise)* The portal filter offered six options (`query`, `completion`, `embedding`, `chat`, `search`, `connector`) that never matched the internal `request_type` values actually stored in `audit_logs` (e.g. `decision_llm`, `llm-call`, `mcp-query`), so five of the six always returned zero rows and the sixth missed the primary LLM path. The dead control is removed, along with the now-unused `request_type` field on the `/api/v1/audit/search` request and its orchestrator filter branch. (#2678)
- **Audit retention advances `last_cleanup_at`.** The retention executor now records `audit_retention_config.last_cleanup_at` per `(org, data_type)` after an enforce-prune run, so an operator can see when each table was last pruned. (#2663)
- **RBI board-report generation method + unsent-notification visibility.** *(Enterprise)* The board-report `generation_method` value is corrected to `automatic` (aligned with the migration `CHECK`), and `GenerateReport` now surfaces pending regulatory notifications. (#2640)
- **OJK breach-status lifecycle + 72-hour deadline evaluator.** *(Enterprise)* The breach-notification state machine (`draft → submitted → acknowledged`, with `overdue` / `failed`) now persists and reads `submitted_at` / `acknowledged_at`, evaluates the 72-hour deadline, and exports real values. Migration `enterprise/131` adds the status `CHECK`. (#2639)

### CI / Internal

- **Enterprise-tagged and real-Postgres tests now run in CI.** A new job runs `go test -tags enterprise` plus the `TEST_PG_INTEGRATION` testcontainer suites over `platform/` and `ee/` (orchestrator + agent), wired into the test summary, closing the gap where `//go:build enterprise` code and real-DB tests were shipped but never exercised in standard CI. (#2666)

## [8.7.0] - 2026-06-11 - Governance integrity: audit-trail consolidation, per-org detection posture on every plane, and compliance-export fixes

**Community.** Every change in this release lives in the `platform/` binaries - the agent, the orchestrator, and the shared policy engine - so this release ships to the community mirror; Enterprise-only surfaces (the customer-portal write paths, the SEBI / EU AI Act compliance exports, SCIM) are tagged inline. v8.7.0 consolidates policy decisions onto a single canonical audit record, lets each organization set its own detection enforcement posture independently on every plane, closes a class of compliance-export defects that let regulator-facing exports report success with no data, and corrects audit-feed pagination and PII detection false positives. **No breaking changes.** The new `audit_logs` columns are additive and nullable (migrations 119-121) and require no backfill; every API addition is additive and backward-compatible.

### Audit-trail consolidation

- **`decision_id` and `plane` are now first-class `audit_logs` columns.** Every governed decision writes a canonical row carrying a stable `decision_id` and a `plane` discriminator (`llm`·`mcp`·`agent`·`gateway`·`decision`·`openai_compat`) so a single query returns every block across every enforcement surface. Migration `core/119`. On its own, this makes a cross-plane block queryable in one place.
- **MCP `check-output` blocks emit the canonical `audit_logs` decision row.** A PII block on the MCP response path previously did not produce a decision row in the consolidated shape, so it did not appear in the portal decisions feed. It now writes the same canonical record as every other plane.
- **`correlation_id` groups decisions into chains.** A new nullable `audit_logs.correlation_id` column (migration `core/121`, partial index `WHERE correlation_id IS NOT NULL`) carries the W3C `trace_id` a Policy Enforcement Point propagates across the hops (LLM → tool → agent) of one logical request. Rows sharing a `correlation_id` are the ordered steps of one decision chain; the SEBI and EU AI Act exporters group by it. Legacy rows (no trace) are single-step chains, so grouping never drops a decision.

### Audit-coverage hardening

A pre-release coverage review mapped every enforcement decision to its audit write and closed the highest-impact gaps below.

- **Orchestrator LLM-response decisions now write canonical `audit_logs` rows - and redactions are no longer mislabeled `allowed`.** The response-redaction plane previously recorded a redacted response (including Indonesian NIK/NPWP masking) as `policy_decision="allowed"` with empty `redacted_fields`, and a validation-withheld response wrote no row at all. It now writes a canonical row carrying the true verdict (`redacted` with the masked fields, `blocked` for a withheld response, `allowed` for a clean one), `plane=llm`, `decision_id`, and `correlation_id`.
- **MCP `check-input` emits the canonical `audit_logs` row for every terminal verdict.** Mirroring the `check-output` fix above, a dynamic-policy block and a terminal allow (including allow-with-redaction) on the request plane previously did not appear in the portal decisions feed or `/explain`. They now write the canonical decision row (`plane=mcp`), with no double-write on the static-block or override paths that already record their own row.
- **Self-service password changes are audited.** *(Enterprise)* Forgot-, reset-, and change-password now record audit events (`PASSWORD_RESET_REQUESTED` / `PASSWORD_RESET_COMPLETED` / `PASSWORD_CHANGED`) on success **and** on the security-relevant failure (e.g. a wrong-current-password attempt), closing the asymmetry with the already-audited admin reset path. Rows carry only the event, actor, org, and request metadata - never the password, reset token, or hash.

### Per-org detection posture

- **Agent enforces per-`(org, category)` detection-action overrides.** New `detection_action_overrides` table (migration `core/120`, ENABLE+FORCE RLS by `org_id`) lets each org override the deployment-global action (`PII_ACTION` and the SQLi / dangerous-query / dangerous-command levers) per category, resolved as `effective = per-org override ELSE deployment-global default`. A short-TTL per-org cache keeps the hot path DB-free (`AXONFLOW_DETECTION_OVERRIDE_TTL_SECONDS`, default 60s) and **fails safe to the deployment-global action** on any lookup error. Wired across `check-input`/`check-output`, the gateway pre-check, `/decide`, the proxy, the policy-test surface, and the OpenAI-compatible endpoint.
- **Orchestrator honors per-org posture on the LLM-response redaction plane.** The orchestrator is a separate binary whose response redaction (proxy / gateway / MAP) previously always used the deployment-global action - so a per-org redact under a global warn was reverted and leaked. It now resolves the same per-org override, fail-safe to global.
- **Customer-portal authenticated write path to set posture.** *(Enterprise)* A new `/api/v1/detection-posture[/{category}]` surface (List/Set/Delete) on the session-auth router, gated by `sso:configure`, plus a **Settings → Governance → Detection Posture** UI (`/settings/detection-posture`). The org is taken from the session, never a header/body.

### Compliance-export integrity

- **EU AI Act exports no longer fake success.** *(Enterprise)* Every EU AI Act export processor except decision-chain was a stub returning no rows while the job was marked `Completed` at 100%. Unimplemented export types now **fail honestly** (job → `Failed`) instead of reporting a zero-record success.
- **EU AI Act exports query real, org-scoped data.** *(Enterprise)* The `full_audit`, `conformity_evidence`, `hitl_summary`, `policy_violations`, and `accuracy_metrics` processors now read real data from `audit_logs`, `policy_violations`, the HITL records, and the `euaiact_*` tables.
- **SEBI and EU AI Act exports reconstruct decision chains from `audit_logs`.** *(Enterprise)* Both exports derive their lineage from the canonical decision rows and group by `correlation_id` - SEBI returns `data.decision_chains`; the EU AI Act export returns `decision_chains` + `chain_count`.
- **Audit retention is actually executed.** A retention executor prunes the six config-governed audit tables on schedule - **dry-run by default**, deleting only when retention enforcement is explicitly enabled, with an admin-portal surface to inspect a run.
- **`admin_audit_log` + `scim_audit_log` writers are wired.** *(Enterprise)* Administrative and SCIM operations are now recorded to their dedicated tables (the SCIM writer RLS-scoped to the acting org via `withOrgScope`).

### Decisions / audit feed

- **`total` is the true count of matching rows**, not the size of the returned page, so a UI can render an accurate "1-N of M".
- **`offset` is applied** to the search query - pagination no longer repeats the first page.
- **`tenant_id` and `user_email` filters do case-insensitive partial (ILIKE) matching**, so an operator can search by a fragment.
- **`action` filter on `policy_decision`** (`allowed`/`blocked`/`redacted`/`error`) added to audit search.
- **The portal audit view no longer steals input focus** on each filter fetch - typing in a filter while results refresh no longer drops keystrokes. *(Enterprise)*
- **SCIM group-to-role mapping endpoints are mounted.** *(Enterprise)* The previously-unreachable group→role mapping routes are mounted on the session-auth router behind `sso:configure` (a privilege grant, so deliberately not the bearer `/scim/v2` provisioning router); org resolved from the session; every change written to the SCIM audit log.

### PII detection false positives

- **Context-gated broad detectors.** Bare-12-digit Aadhaar and Singapore NRIC/FIN now require an adjacent label/indicator before they fire, so a benign order ID or barcode is not masked.
- **JSON-structure-aware masking.** A redacted response always stays valid JSON: a numeric-position value (e.g. a NIK stored as an integer) is masked **and** coerced to a string; escaped PII (`\uXXXX`) is decoded and matched; an unsafe result **fails closed** rather than emitting broken JSON.
- **Closed IP-on-version-string and phone-on-tracking-ID false positives.**

### Capabilities

- **`/health` recommends claude-code plugin v1.6.0** (the version carrying the Enterprise self-hosted MCP login fix). The recommended claude-code plugin version is bumped 1.5.3 → 1.6.0; SDK and other plugin recommendations unchanged.

## [8.6.0] - 2026-06-09 - Decision Mode PII governance: validator-assignment fixes, request + response NIK/NPWP redaction on every plane, and engine-fulfillable obligations

**Community.** Every change in this release lives in the `platform/` and `platform/shared/` binaries - the agent, the orchestrator, and the shared policy engine - so this release ships to the community mirror. The fixes and additions are reachable in both editions; where behavior differs by edition it is called out inline. In particular, the **Enterprise** build supplies checksum/province-validated Indonesian NIK/NPWP detection (the precision behind the redaction below), while **Community** uses pattern-based Indonesian PII detection - and as of this release both editions govern that PII on the **request and the response** path. No breaking changes; every API and policy-engine change is additive and backward-compatible.

### Fixed (Community)

- **PII validators were misassigned for every database-loaded policy - email, phone, and IP detection were silently inert for all tenants.** The policy loader selected a value validator with an exact `ValidatorRegistry[policyID]` lookup that never matched the `sys_pii_*` policy IDs, so every PII policy fell through to its category default - the **credit-card** validator for `pii-global`, which rejects every non-card string. The net effect: `email` / `phone` / `ip` detection never fired on the request **or** response path, on any deployment, and `pan` was validated against the **Aadhaar** validator. The loader and the evaluator now share a deterministic `ValidatorForPolicyID` (ordered segment-token match, replacing a non-deterministic map-iteration matcher in the evaluator). After the fix: `email` / `phone` / `ip` resolve to their correct validators (were inert); `pan` → `ValidatePAN` (was Aadhaar); `sys_pii_indonesia_phone` / `sys_pii_singapore_phone` → `ValidatePhone` (were accept-all). This has the broadest blast radius of anything in the release - it restored basic PII detection for every tenant. (#2565)
- **Indonesian NIK/NPWP leaked on the agent response path.** The agent's response engine (`POST /api/v1/mcp/check-output`, used by the PEP/gateway response flow and the MCP `tools/call` path) derived its PII category whitelist from a hardcoded literal that omitted `pii-indonesia`, and ran no checksum-validated NIK/NPWP detector on responses. Response evaluation now derives the category whitelist from the enabled policies (`UnifiedPolicyEngine.EnabledPIICategories` plus a convention classifier for any `pii-`-prefixed category), and runs the Indonesian detector on the response - blocking critical NIK/NPWP under `PII_ACTION=block` and masking under `PII_ACTION=redact`, while `warn`/`log` detect without mutating. Redaction is surfaced uniformly via `OutputPolicyOutcome.WasRedacted` so an Indonesia-only redaction can neither leak the unmasked original nor be recorded as un-redacted in the audit trail. (#2565)
- **Indonesian NIK/NPWP leaked on the orchestrator / LLM-gateway response path.** The orchestrator's `ResponseProcessor.ProcessResponse` (proxy / gateway / MAP LLM responses) carried no checksum-validated NIK/NPWP detector. The same Indonesian detector is now wired into the response path via a side-effect-free deep walk (`maskIndonesiaPIIDeep`) that masks string leaves in any decoded-JSON shape and folds detected type names into the audit `RedactionInfo`, with the same `PII_ACTION` semantics (detect-don't-modify on `warn`/`log`, mask/deny on `redact`/`block`). (#2568)
- **Indonesian NIK/NPWP was not redacted on the request path under `PII_ACTION=redact`.** The request-phase entry points only hard-denied NIK under `PII_ACTION=block`; under `redact` they let it through. The validator-backed redact flag is now wired on all three request entry points - Gateway pre-check, `POST /api/v1/decide`, and `POST /api/v1/mcp/check-input` - so a checksum-valid NIK is redacted under `redact` (mirroring the existing RBI handling). Block mode still hard-denies. (#2573)
- **`sys_pii_passport` (block) and `sys_pii_dob` policies were validator-inert.** Same misassignment class as the email/phone fix above: with no matching token they were stamped the credit-card default and never matched on any path. Added `ValidatePassport` and `ValidateDOB`, both **proximity-gated** - the passport/birth-date indicator must immediately precede the value - because the underlying patterns are broad and the shared engine's `EvaluateAll` has no confidence threshold (a valid match always fires). This prevents a generic order number from being blocked as a passport, or an invoice/due date from being redacted as a date of birth. (#2570)
- **Context-gated the broad Singapore PII detectors (postal code, UEN).** They now redact only when a nearby label confirms the value; previously they fired on any matching number and - under engine-backed response redaction - could hard-block a benign tool response. No loss of real PII coverage; labelled values still redact. (#2575)

### Added (Community)

- **Decision Mode obligations are now self-describing and engine-fulfillable.** `POST /api/v1/decide` stays a pure Policy Decision Point and never mutates content. Each `redact_pii` obligation it returns now carries a `fulfillment` block - `endpoint`, `method`, `phase`, and the `content_types` the endpoint can redact - that tells a Policy Enforcement Point exactly which engine call discharges the obligation. Client-side redaction is impossible by construction: a conforming PEP POSTs the content to the named endpoint and forwards the engine-redacted result, rather than hand-rolling its own patterns. (ADR-056 / ADR-057.) (#2564)
- **`POST /api/v1/mcp/check-input` returns engine-redacted request content.** `check-input` now returns `redacted` / `redacted_statement` (the engine-masked request statement) plus `redaction_evaluated` (whether the detector actually ran). This is the request-phase home that makes a `/decide` `redact_pii` obligation fulfillable, and is symmetric with `check-output`'s response-phase `redacted_data`. Request redaction is policy-derived and connector-agnostic, and a PEP fails closed when `redaction_evaluated` is false (the detector did not run) so an un-evaluated request can never be forwarded as if it were clean. (#2564)
- **`platform/shared/pep` - the blessed PEP client.** A shared client that runs the decide → fulfill-via-named-endpoint → forward flow with HTTP Basic auth. It holds no redaction logic of its own and fails closed if an obligation is not engine-fulfillable or the redactor did not run. The reference LLM and MCP adapters were corrected to fulfill (not silently drop) the `redact_pii` obligation. (#2564)
- **`/health` capability discovery advertises the new Decision Mode surface.** The agent capability list (surfaced at `GET /health`) now includes `decision_obligations` and `two_touch_redaction` (`since: 8.6.0`), so SDKs, plugins, and PEPs can feature-detect the obligation contract and request + response redaction without version sniffing.

### Tests (Community)

- Per-plane deterministic CI tests for the request-phase Indonesian redaction (red on revert), validator-selection regressions (locale-phone narrowing, credit-card-default lock, passport/DOB proximity-gating both directions), and the response-path leak locks (`WasRedacted` gate, non-vacuous empty-set guard). Runtime end-to-end proofs against a live agent + orchestrator over real HTTP: `2563_response_pii_categories`, `2566_orchestrator_indonesia_response`, `2567_passport_dob_validators`, `2563_obligation_pep`, `2571_indonesia_nik_redaction`, and a `2563_v860_release_smoke` that boots the version-bumped tree and asserts `/health` reports `8.6.0` + the new capabilities, `/decide` emits a self-describing `fulfillment` obligation, and `check-input` returns `redacted_statement`.

---

## [8.5.2] - 2026-06-08 - Portal works over HTTP self-host + MCP plugin auth connects on self-hosted/Enterprise + audit stats count denials correctly

**Community + Enterprise.** The portal fixes are enterprise-only (`ee/platform/customer-portal[-ui]` plus an additive helper migration). The MCP-auth and audit-summary fixes below are in the **community** `platform/agent` and `platform/orchestrator` binaries, so - unlike the original `8.5.2` plan - this release **does** ship to the community mirror (community sync is **not** skipped).

### Fixed (Community)

- **Agent returns parseable JSON, not plaintext, on OAuth-discovery probes.** The MCP server authenticates with HTTP Basic (`base64(org_id:license_key)`) and sends `WWW-Authenticate: Basic` on its `401`, but some MCP clients (e.g. Claude Code) respond to the `401` by probing an open-ended set of OAuth-discovery URLs (`/.well-known/oauth-protected-resource[/<resource-path>]`, `/.well-known/oauth-authorization-server`, `/.well-known/openid-configuration`, `/register`, …) and parse each non-2xx body as an OAuth error JSON. gorilla/mux's default `404`/`405` emit Go's plaintext `404 page not found` / `Method Not Allowed`, so the client crashed with `HTTP 404: Invalid OAuth error response … Raw body: 404 page not found` and marked the server failed - even though the real problem was just a missing credential. The agent router now returns RFC 6749 §5.2-shaped JSON for every unmatched route / wrong method (global `NotFoundHandler` + `MethodNotAllowedHandler`), and serves `/.well-known/oauth-protected-resource` / `/.well-known/oauth-authorization-server` (covering the resource-path-suffixed forms) with a specific advisory naming `AXONFLOW_AUTH` / `AXONFLOW_ENDPOINT` and advertising **no** authorization server - so the client renders a clear message instead of crashing, and never starts an OAuth flow this server can't complete.
- **Audit summary counts policy denials as blocked.** `get_policy_stats` and the portal compliance card under-reported blocks: a denied tool call (e.g. an SSN caught by `sys_pii_ssn` via a plugin's `PreToolUse` hook calling `check_policy`) is recorded in `audit_logs` with `policy_decision="deny"`, but the summary aggregation only bucketed `"blocked"` - so `"deny"` fell through to the "allowed" branch and a real block showed as `0 blocked / 100% compliance / all-info severity`. The write-path vocabulary is split (agent `check_policy` → `"deny"`; gateway-mode → `"blocked"`); the summary now counts `blocked`/`deny`/`denied` as blocked in both the action-triage and the top-policies block-count queries. This is server-side, so it corrects the stats for **every** plugin (Claude Code, Cursor, Codex, openclaw) - they all route blocks through the agent's `check_policy` path.

### Changed (Community)

- **Recommended host-CLI plugin version bumped to 1.5.3** for Claude Code and Cursor. The agent and orchestrator capability response (surfaced at `/health`) now advertises `1.5.3` as the recommended version for those two; plugins below it receive an actionable upgrade-warning header on every governed call. 1.5.3 carries the plugin-side fix that sends HTTP Basic auth correctly against self-hosted / Enterprise endpoints (the `${CLAUDE_PLUGIN_ROOT}` headers-helper expansion), which pairs with the agent OAuth-discovery fix above. Codex stays at `1.5.2` (its v8.5.2 fix was documentation-only). The minimum-supported floor is unchanged (`1.4.0`; openclaw `2.4.0`), and openclaw's recommended version stays `2.6.1`.

### Tests (Community)

- Agent: `mcp_oauth_discovery_test.go` pins the JSON 404/405 responses and the well-known advisory (no `authorization_servers`, names `AXONFLOW_AUTH`). Orchestrator: `TestAuditSummaryHandler_HandleSummary_CountsDenyAsBlocked` asserts `deny`/`denied` count as blocked. Both verified end-to-end through the real `claude` binary against a self-hosted in-vpc-enterprise bundle with a real license.

---

**Enterprise (customer-portal) - original `8.5.2` scope, unchanged below.** Every portal change is under `ee/platform/customer-portal[-ui]` plus an additive helper migration and version/compose bumps.

Patch release closing out self-hosted portal access. Two complementary halves of the same symptom: the deployment org now gets a login credential provisioned at boot, and the session cookie is no longer dropped when the portal is served over plain HTTP (the install bundle / evaluation deployments). Together a fresh HTTP install is loginable and the login sticks - previously a fresh install had no portal password, and even once one was set every authenticated request returned `401`. Also stops the dashboard from masking a fetch failure with a fabricated license. HTTPS/production deployments are unaffected and stay secure by default. No breaking changes; additive migration only.

### Added (Enterprise)

- **Portal login credential auto-provisioned at boot.** In `enterprise` / `in-vpc-*` deployments the deployment organization (`ORG_ID`) is the portal login identity, but the agent's license-tier promotion created that organization row without a `password_hash` - so a fresh install had a portal no one could log into until someone ran manual SQL. The portal now bootstraps the deployment org's password from `AXONFLOW_PORTAL_ADMIN_PASSWORD` at startup: fail-closed (it refuses to boot in those modes if the password is unset, rather than coming up un-loginable), no-clobber (an operator-set password is never overwritten on restart), and create-if-missing. A `reset-portal-credential.sh` operator script is included for recovery. (#2552)

### Fixed (Enterprise)

- **Session cookie `Secure` attribute is now conditional.** The `axonflow_session` cookie was set with a hardcoded `Secure` attribute at all three session-cookie sites (login, logout, SAML callback). When the portal is served over plain HTTP, the browser silently drops a `Secure` cookie, so every authenticated request reached the auth middleware with no cookie and returned `401 Unauthorized` ("no session") before any database query - and the dashboard then rendered a placeholder license. The attribute is now gated on `AXONFLOW_PORTAL_COOKIE_SECURE`, which defaults to `true` so HTTPS/production keeps the `Secure` attribute with no configuration change; operators set it to `false` for an HTTP self-host or evaluation deployment on a trusted internal network. The logout (cookie-clearing) attributes match the set cookie so logout reliably clears the cookie. The bundled `docker-compose.enterprise.yml` defaults the override to `false` for the local/eval HTTP flow.

- **The dashboard no longer fabricates a license on a fetch failure.** When the license-status call failed (e.g. the `401` above), the dashboard previously substituted a hardcoded `Community / DEVELOPER` placeholder, which read as a real downgraded license and masked the true Enterprise entitlement. It now captures the error, leaves the license unset, and renders an explicit "License status unavailable" state. This is display-only and does not change any entitlement.

- **Portal session lookup is now RLS-safe under the application role.** The portal auth middleware reads `user_sessions` by session id before any organization context is established (the lookup is what discovers the session's org), so it could not use the request-scoped tenant GUC. Under the NOBYPASSRLS application role with `FORCE ROW LEVEL SECURITY`, that direct read returned zero rows and would have rejected every portal session. The lookup now goes through a new `SECURITY DEFINER` helper (additive migration) that resolves the session without exposing the underlying table, falling back to the direct read on databases that predate the migration. No effect on current deployments (which connect as a role that bypasses RLS); this hardens the path for the application-role posture.

### Tests

- Added a runtime end-to-end test (`runtime-e2e/portal_cookie_secure_http`) that drives the real agent + portal binaries over HTTP: it asserts the cookie keeps `Secure` by default, drops it under `AXONFLOW_PORTAL_COOKIE_SECURE=false`, and that an HTTP login then returns `200` with the correct licensed tier from `GET /api/v1/license/status`. Plus a unit test pinning the `AXONFLOW_PORTAL_COOKIE_SECURE` parsing (default-true, case-insensitive `false`).

## [8.5.1] - 2026-06-08 - Licensed tier reported correctly in the portal/database + dev-mode token endpoint

Patch release. Fixes a tier-reporting divergence where the licensed tier was held only in agent memory and never written to the `organizations` table, so the portal and other database consumers could lag behind `/health`. Also adds a non-production developer convenience for minting user tokens. Additive migration only; no breaking changes.

### Added (Community)

- **Dev-mode token endpoint (`POST /api/v1/dev/token`).** In an explicitly non-production deployment, mints a short-lived HS256 `user_token` from the authenticated Basic-auth credential, so local and CI integrations don't have to hand-run a JWT signing script. Fail-closed: the endpoint is **only registered** when an explicitly non-production `ENVIRONMENT` / `DEPLOYMENT_MODE` / `DEPLOYMENT_KIND` is set - otherwise the route returns `404`; and when registered but `JWT_SECRET` is not configured it returns `503` rather than minting. The token's tenant is inherited from the Basic-auth username, and the signing algorithm is pinned to HS256. Never reachable in production.

### Fixed (Community)

- **The agent now writes the licensed tier into the database at boot.** After validating the deployment license, the agent upserts the deployment organization's `tier` and `max_nodes` to the licensed values, using a new RLS-safe `SECURITY DEFINER` migration so the write clears `FORCE ROW LEVEL SECURITY` without giving the request path elevated privileges. Previously the licensed tier lived only in agent memory (surfaced at `/health`) while `organizations.tier` stayed at the seeded `Community` default - so the portal UI, node-limit enforcement, and compliance-evidence paths could report `Community` on a valid Enterprise license. The promotion runs at boot and is idempotent: it writes only when the tier or node limit actually differs.
- **Tests:** added a runtime end-to-end test that boots a freshly-installed Enterprise deployment and asserts the database reports `Enterprise` with no prior request traffic, plus a migration-level unit test for the promotion helper.

### Documentation

- Expanded architecture documentation: a "Five Runtime Modes" overview with Decision / MAP / WCP sequence diagrams describing how governance is enforced in each runtime mode.

## [8.5.0] - 2026-05-30 - Decision Mode context propagation + Pasal 56(b) attestation + multi-arch images

Minor release. Decision Mode gains request-context propagation and durable audit persistence, OJK compliance gains an explicit UU PDP Pasal 56(b) transfer-basis tag plus a wired cross-border-transfers export, and all six platform images now ship for both `linux/amd64` and `linux/arm64`. Indonesia compliance migrations (OJK + UU PDP + BI) relocated from `industry/banking/` to `enterprise/` so they load in every in-vpc-enterprise deployment by default. No breaking changes. SDKs are also updated in this release train - Go / Python / TypeScript / Java to **v8.4.0** and Rust to **v0.6.0** - adding the typed `context` field on `DecisionSummary` / `DecisionExplanation` and the `pasal_56b_dpa` transfer-basis value; see each SDK's own release notes for details.

### Added (Community)

- **Decision Mode request-context propagation (`request.context`).** `POST /api/v1/decide` accepts an optional top-level `context` object - arbitrary caller-supplied key/value metadata (e.g. `tenant_tier`, `region`, `feature_flag`) that rides alongside the decision for audit and correlation. Keys are filtered against an allowlist, canonicalized, capped at 256 bytes per value and 10 keys per request, and a `request.context.truncated` flag is set when either cap trims the payload. Allowed keys land as OTel span attributes under `request.context.<key>` for trace-side filtering. The allowlist is configurable via `AXONFLOW_DECISION_CONTEXT_ALLOWLIST` (comma-separated); the default ships a curated set of agent/session/leader identity headers plus a tenant-scoped header family. Closes #2509.

- **Decision Mode decisions now persist to `audit_logs`.** Previously `POST /api/v1/decide` emitted only an OTel span, so `GET /api/v1/decisions` returned empty for Decision Mode callers who had not wired an OTel backend. Each decision now also writes a best-effort row to `audit_logs` (mirroring `writeExplainableAuditLog`), with the propagated context stored under `policy_details->'context'`. `GET /api/v1/decisions` surfaces a 5-key truncated view of the context; the explain endpoint returns the full context plus a `context_truncated` flag. OpenAI-compatible callers continue to use `llm_call_audits` unchanged. (BUKU-A scope expansion on #2509.)

- **`examples/mcp-decision-mode/` reference adapter.** A runnable Python MCP server demonstrating the PEP/PDP pattern: the MCP server (PEP) calls AxonFlow `POST /api/v1/decide` (PDP) before exposing tool results, with Indonesia PII detection and a fail-closed default. Includes a stdio end-to-end harness and unit tests. Closes #2510.

### Added (Enterprise)

- **UU PDP Pasal 56(b) transfer-basis tag (`transfer_basis = "pasal_56b_dpa"`).** Cross-border transfer records can now carry an explicit Pasal 56(b) Data Protection Agreement basis alongside the existing `safeguards` field. The tag is backward-compatible and never auto-translated from other bases. New `TransferBasisCanonicalForms` and `TransferBasisValid` helpers validate the accepted set. Closes #2511.

- **OJK cross-border transfers audit export wired.** `OJKDataTypeCrossBorder` was a declared export data type whose switch arm fell through, returning empty. This release ships the missing `queryCrossBorderTransfers` query (org-scoped and parameterized), so `POST /api/v1/ojk/audit/export` with `data_type=cross_border_transfers` returns the logged cross-border transfer records. (BUKU-C scope expansion on #2511.)

### Fixed

- **Grafana Prometheus datasource 404 in the bundled stack.** The bundled `axonflow-grafana` image generated a Prometheus datasource URL with no path, but `axonflow-prometheus` runs with `--web.external-url=/prometheus`. Datasource provisioning now references `http://prometheus:9090/prometheus`, so Grafana panels query Prometheus successfully out of the box. Closes #2507.

### Changed (Self-hosted)

- **Multi-architecture platform images.** All six platform images (agent, orchestrator, customer-portal, customer-portal-ui, and the bundled prometheus/grafana) now build and publish for both `linux/amd64` and `linux/arm64`. Apple Silicon Macs, AWS Graviton, and Ampere ARM Linux hosts run AxonFlow natively - no Rosetta/QEMU emulation and no `platform: linux/amd64` pin required in `docker-compose`. Closes #2506.

- **Indonesia compliance migrations relocated** from `migrations/industry/banking/` to `migrations/enterprise/` (versions 127-130). `in-vpc-enterprise` deployments now load the OJK + UU PDP + BI compliance tables and the cross-border `transfer_basis` / `data_residency` audit columns by default, so `POST /api/v1/ojk/audit/export` works in `in-vpc-enterprise` mode (previously returned HTTP 500 because these migrations only loaded under `saas` / `in-vpc-banking`). No customer action required for existing `saas` / `in-vpc-banking` deployments - the migrations are idempotent and re-apply cleanly under their new version numbers. Closes #2516.

### Notes for self-hosted operators

- **OTel collector attribute namespace.** Decision Mode now emits span attributes under the `request.context.*` namespace (one attribute per allowlisted context key). If you filter or index decision spans by attribute, add `request.context.*` to your collector's keep/allow rules so the new attributes are retained.
- **`audit_logs` now receives Decision Mode rows.** Any consumer that tails `audit_logs` (SIEM forwarders, retention sweepers, dashboards) will begin seeing rows originating from `POST /api/v1/decide` in addition to the existing Proxy/Gateway sources. The new rows carry the decision context under `policy_details->'context'`. No schema migration is required - the column already existed.
- **Platform-pin removal.** If you added `platform: linux/amd64` to your `docker-compose` services as a v8.4.0 workaround on ARM hosts, you can remove it in v8.5.0 - the images now resolve a native `linux/arm64` manifest.
- **Indonesia compliance migration relocation** (above) - if you query `schema_migrations` directly, expect to see versions 127-130 register on next boot for `saas` and `in-vpc-banking` deployments (they re-apply the previously-applied SQL under the new version numbers; the SQL is idempotent so the operations are no-ops).

## [8.4.0] - 2026-05-28 - Self-hosted deployment alignment + OpenAI-compatible gateway endpoint

### Added (Self-hosted)

- **`docker-compose.enterprise.yml` aligned with production CFN templates.** Closes the hand-authoring drift class (#2498). Self-hosted operators upgrading from prior versions must set `AXONFLOW_INTERNAL_SERVICE_SECRET` (32+ chars, e.g. `openssl rand -hex 32`) on the agent, orchestrator, and customer-portal env blocks - without it, the customer-portal can't authenticate calls to the agent and the unified-policies UI silently shows 0 system policies. AWS CFN-deployed stacks are unaffected (the secret was always injected from `InternalServiceSecret`). Also added: `audit-data` named volume for audit-fallback persistence across restarts, resource limits mirroring CFN sizing, and `curl -f` healthchecks matching the CFN-defined commands.

- **`DEPLOYMENT_KIND` overlay default kept at `dev`.** Self-hosted operators flipping `DEPLOYMENT_KIND=production` must also set a real `ORG_ID` (not the `local-dev-org` sentinel) at the same time - migration 094's prod-safety guardrail aborts boot on the (`production` + `local-dev-org`) combo to prevent silent dev-sentinel stamping of audit rows.

- **`axonflow-install` bundled stack** with OpenTelemetry collector + Tempo + a Decision Mode Traces Grafana dashboard (at `http://localhost:3001/d/decision-mode-traces`) out of the box for self-hosted deployments on non-AWS (e.g. GCP). One-command deploy via `./install.sh`. Closes #2496.

Milestone 1 of the OpenAI-compatible gateway. Existing OpenAI SDK users can route calls through AxonFlow for policy enforcement and audit by changing a single line (`baseURL`). No new SDK to learn, no request format changes - the endpoint accepts and returns standard OpenAI Chat Completions wire format. Verified end-to-end with the Python and TypeScript OpenAI SDKs against real OpenAI API.

### Added (Community)

- **OpenAI-compatible gateway endpoint (`POST /v1/chat/completions`).** Drop-in governance for OpenAI SDK users. The agent accepts a standard [OpenAI Chat Completions](https://platform.openai.com/docs/api-reference/chat/create) request, evaluates AxonFlow policies (PII detection, SQL injection blocking, dangerous query prevention, compliance rules), and either blocks the request with an OpenAI-compatible error or forwards it to the upstream provider and returns the response unchanged. Verified with Python `openai` v2.38.0 and TypeScript `openai` latest.

  **Quick start (Python):**
  ```python
  from openai import OpenAI
  client = OpenAI(
      base_url="http://localhost:8080/v1",
      default_headers={"X-Provider-Key": OPENAI_API_KEY}
  )
  response = client.chat.completions.create(model="gpt-4o-mini", messages=[...])
  ```

  **Key behaviors:**
  - Policy denials return HTTP 400 with `{"error": {"type": "policy_violation", "code": "policy_denied"}}` - the OpenAI SDK parses this as `BadRequestError`, so existing error handling works unchanged.
  - Every request is audited: model, provider, prompt/completion token counts, estimated cost, latency, and policy decision (`allow` or `deny`).
  - Response headers `X-AxonFlow-Decision-Id` (UUID) and `X-AxonFlow-Trace-Id` (W3C 32-hex) enable audit correlation and OTel tracing.
  - Provider API key supplied via `X-Provider-Key` header (not stored by AxonFlow).
  - `stream: true` returns a clear HTTP 400 error - streaming support is planned for a future release.
  - Same authentication as all AxonFlow endpoints (community mode: no auth; enterprise: Basic Auth).

  **Documentation:** [OpenAI-Compatible Gateway](https://docs.getaxonflow.com/docs/sdk/openai-compatible-gateway/)

## [8.3.0] - 2026-05-27 - Indonesia compliance + OTel exporters

Minor release. Adds Indonesia regulatory compliance coverage: PII detection patterns for Indonesian identifiers, OJK (Otoritas Jasa Keuangan) AI governance module for financial services, and UU PDP (Law No. 27/2022) breach notification support. SDKs updated to v8.3.0 (Rust v0.5.0) with Indonesia category support and audit fields.

### Added (Community)

- **Indonesia PII detection (`pii-indonesia` category).** Eight context-anchored patterns: NIK (national ID, province-code validated), NPWP legacy 15-digit, NPWP new 16-digit, +62 phone numbers, and four major bank account formats (BCA, Mandiri, BRI, BNI). All bank and NPWP patterns are context-anchored to minimize false positives against credit card numbers, UUIDs, and timestamps.

- **OTel observability exporter configurations.** Pre-built OTel Collector configs for Datadog (`docker-compose.otel-datadog.yml`) and Grafana + Tempo + Prometheus (`docker-compose.otel-grafana.yml`). The spanmetrics connector generates `calls_total` and `duration_milliseconds` Prometheus metrics from decision spans. A 9-panel Grafana dashboard (`grafana/dashboards/decision-mode-overview.json`) provides verdict distribution, latency percentiles, policy trigger rates, and per-tenant breakdown out of the box.

### Added (Enterprise)

- **OJK compliance module.** Six API endpoints under `/api/v1/ojk/`: audit export (list + by-ID), audit retention configuration, audit readiness check, breach notification, and compliance dashboard. Supports `AXONFLOW_COMPLIANCE_REGION=ID` with enforced 1825-day (5-year) minimum retention floor per OJK AI governance requirements.

- **UU PDP breach notification.** Article 46 compliant breach notification with required fields, 72-hour SLA calculation, and MOCDA (Ministry of Communication and Digital Affairs) as default authority. Integrates with the OJK audit export pipeline.

- **Cross-border transfer audit fields.** New columns on audit tables for logging cross-border data transfer metadata required by Indonesian financial regulators.

- **Four industry migrations.** OJK compliance tables, OJK policy templates, audit cross-border fields, and breach notification tables (migrations 500-503 under `industry/banking/`).

### Changed

- **SDK version recommendations.** Platform `/health` now advertises SDK v8.3.0 (Go, Python, TypeScript, Java) and Rust SDK v0.5.0 as recommended versions. Minimum SDK floor remains v8.0.0.

## [8.2.1] - 2026-05-25 - Customer Portal bug sweep + SEBI compliance fix

Bug-fix patch. Resolves all customer portal console errors on both self-hosted and managed deployments. The customer portal now renders all 16 pages with zero console errors in enterprise mode. Includes a critical SEBI compliance export fix where 6 of 11 projected columns didn't match the actual database schema.

### Fixed (Enterprise)

- **SEBI audit export decision chain query.** The `exportDecisionChain` SQL query projected 6 columns that don't exist in the `decision_chain` table: `decision` (real: `decision_outcome`), `confidence` (real: `risk_level`), `rationale` (removed), `human_override` (real: `requires_human_review`), `override_by` (removed), `override_reason` (removed). Added missing columns: `policies_evaluated`, `policy_triggered`, `processing_time_ms`. Every SEBI compliance export that included decision chain data would fail with a Postgres column-not-found error.

- **Customer portal docker-compose routing.** The portal-ui proxy was pointing at the agent instead of the customer-portal backend. All session-authenticated requests returned 401. The proxy now routes to the customer-portal, which handles session auth natively and proxies governance calls internally.

- **LLM Provider create form.** The portal UI sent `name` but the backend expects `provider_name`. Every Add Provider form submission failed with "provider_name is required".

- **Policy Override dialog unusable.** The Override System Policy modal had a z-index bug where the backdrop overlay intercepted all clicks. Fixed with proper z-index layering and added Escape key handler. Same fix applied to all other modal dialogs (Add Provider, Add Connector, Create API Key).

- **Raw JSON errors shown to users.** API error responses were displayed verbatim. Added error formatting that maps HTTP status codes to user-friendly messages.

- **SCIM endpoint URLs showing localhost.** The SCIM configuration page showed incorrect URLs in docker-compose. Fixed by wiring the base URL as a build-time configuration.

- **SCIM tokens page crash.** The SCIM page crashed when the tokens endpoint returned `null` instead of an empty array. Added null-safety guards.

- **Dashboard empty fields.** Welcome message, Organization ID, and license tier showed empty or raw values. Added fallbacks for all empty-state fields.

- **Subtitle text empty on 3 pages.** LLM Providers, Connectors, and Export pages showed empty subtitle text. Added "your organization" fallback.

### Changed (Community SaaS - Plugin Tiers)

- **Per-minute burst rate limits.** Tier-aware enforcement: Free tier 25 requests/minute, Pro tier 200 requests/minute. Applied consistently across API auth, proxy, and MCP session paths.

- **Plugin tier limit adjustments.** Free tier active custom policies increased from 2 to 4. Free tier HITL approvals per week increased from 1 to 2. Pro tier caps added: 50 active policies, 20 HITL approvals per week.

## [8.2.0] - 2026-05-24 - Decision Mode (PDP/PEP policy decision service) + OTel decision tracer

Additive minor release. Decision Mode brings the Policy Decision Point / Policy Enforcement Point pattern (established by OPA, XACML, Cedar) to AI governance: infrastructure gateways query AxonFlow for a policy verdict before forwarding traffic. The OpenTelemetry decision tracer wires every policy decision into a standard observability pipeline. Three new ecosystem integration packages land on PyPI and npm. No breaking changes, no schema changes, no migration impact.

### Added (Community)

- **Decision Mode - PDP/PEP policy decision service (`POST /api/v1/decide`).** Brings the Policy Decision Point / Policy Enforcement Point pattern to AxonFlow. Infrastructure gateways (the PEP) query AxonFlow (the PDP) for a synchronous policy verdict before forwarding requests upstream. Request: `{stage, caller_identity, target, query}` where `stage` is `llm`/`tool`/`agent`. Response: `{verdict, decision_id, trace_id, reasons, obligations, evaluated_policies}`. Same shared-policy engine as Gateway Mode's `POST /api/policy/pre-check`. Available at all tiers.

- **OTel decision tracer + exporter pipeline.** One decision = one OTel span (`axonflow.decision`) with eight attributes covering decision metadata and identity. W3C `trace_id` returned in pre-check and decide responses for gateway-layer trace correlation. Configurable via `AXONFLOW_OTEL_ENDPOINT` (empty = noop, no required infra), `AXONFLOW_OTEL_SERVICE_NAME`, `AXONFLOW_OTEL_SAMPLE_RATE`. `docker-compose.otel.yml` overlay provides a local Jaeger setup.

- **Decision Mode reference PEP adapters.** Two reference adapters: LLM + Agent gateway (`examples/integrations/decision-mode-adapter/`, Go HTTP middleware) and MCP gateway (`examples/integrations/decision-mode-mcp-adapter/`, JSON-RPC 2.0 interceptor). Both include docker-compose PoC harnesses with test scripts.

### Added (Ecosystem - standalone repos, announced here)

- **axonflow-litellm** ([PyPI](https://pypi.org/project/axonflow-litellm/)). LiteLLM SDK callback integration via `CustomLogger` subclass. `pip install axonflow-litellm`. Standalone repo: [getaxonflow/axonflow-litellm](https://github.com/getaxonflow/axonflow-litellm).

- **axonflow-google-adk-plugin** ([PyPI](https://pypi.org/project/axonflow-google-adk-plugin/)). Google Agent Development Kit plugin for policy checks and HITL approval within ADK agent flows. Standalone repo: [getaxonflow/axonflow-google-adk-plugin](https://github.com/getaxonflow/axonflow-google-adk-plugin).

- **@axonflow/n8n-nodes-axonflow** ([npm](https://www.npmjs.com/package/@axonflow/n8n-nodes-axonflow)). n8n community node with four operations: Check Policy, Record Decision, Audit Log, Wait for Approval. Standalone repo: [getaxonflow/axonflow-n8n-node](https://github.com/getaxonflow/axonflow-n8n-node).

### Changed

- **Decision Mode architecture.** New integration mode using the PDP/PEP pattern alongside Gateway Mode, Proxy Mode, and WCP. Integration packages follow MIT license and `axonflow-` naming conventions.

- **Integration package stubs.** `examples/integrations/google-adk-plugin/` and `examples/integrations/n8n-axonflow-node/` replaced with stub READMEs pointing to their standalone repos.

### Fixed

- **HITL `require_approval` policies now correctly return the `require_approval` sentinel in Gateway Mode pre-check.** When a custom policy with `action=require_approval` matched, the pre-check response returned the policy description as `block_reason` instead of the `require_approval` sentinel string that SDKs and plugins check to trigger the HITL approval flow. The approval flow silently did not activate. Now `require_approval` policies return `block_reason="require_approval"` so SDK-side HITL detection works correctly.

## [8.1.0] - 2026-05-23 - HITL outbound webhook callback + HTTP Idempotency-Key dedup

Minor release on top of v8.0.1. Two additive features that close gaps surfaced during the Google ADK plugin + n8n community node R3 - workflow tools that pause on a webhook can now resume without a polling sidecar, and `Retry on Fail` retries no longer double-create approval rows or double-record audit entries.

No breaking changes. No schema reshuffle. Existing v8.0.0 SDKs and plugins (claude/cursor/codex at v1.4.0, openclaw at v2.4.0) continue to work unchanged - both features are opt-in via headers / request fields. Self-hosted deployments running v8.0.0 can apply the two new migrations and ship.

### Added

- **HITL outbound webhook callback (`notify_url`).** `POST /api/v1/hitl/queue` accepts an optional `notify_url` field (https or http). When set, the platform fires a signed HTTP POST to that URL after the row reaches a terminal state - `approved`, `rejected`, `overridden`, or `expired`. The envelope carries `approval_id`, `status`, `decided_by`, `decided_at`, `original_query`, `request_type`, `severity`, and a `decision_envelope` bag with the comment / justification / triggering policy. Signature is HMAC-SHA256 over the body keyed by `AXONFLOW_HITL_WEBHOOK_SIGNING_KEY`, sent as `X-AxonFlow-Signature: sha256=<hex>`. Delivery is async (never blocks the approve/reject response), retries on non-2xx at `5s/30s/5m`, and logs `[HITL.Webhook] OK|non-2xx|transport_err|GIVE-UP` lines per attempt. Closes #2419.

- **HTTP `Idempotency-Key` header dedup on the three integration endpoints.** `POST /api/v1/mcp/check-input` (agent), `POST /api/v1/audit/tool-call` (orchestrator), and `POST /api/v1/hitl/queue` (agent) now consume the `Idempotency-Key` header. A retry within 24h returns the cached response byte-for-byte plus an `Idempotent-Replayed: true` header. 2xx and 4xx responses are cached; 5xx is intentionally skipped so a caller's retry can hit a fresh attempt. Cross-tenant isolation is enforced by the row-level-security policy on the new `idempotency_keys` table (key + tenant_id + endpoint composite PK). Keys are validated against `^[A-Za-z0-9_.:\-/]+$`, max 256 chars; a malformed key produces a 400 before the handler runs. Closes #2420.

- **HITL `GET /api/v1/hitl/status` feature map advertises `notify_url: true` + `idempotency_key: true`** so the ADK plugin + n8n node can feature-detect at boot.

- **Schema changes.** Migration `114_hitl_notify_url.sql` adds `notify_url TEXT NULL` to `hitl_approval_queue`. Migration `115_idempotency_keys.sql` creates the `idempotency_keys` table with FORCE Row-Level Security keyed on `tenant_id = current_setting('app.current_tenant_id', true)` and a composite primary key on `(key, tenant_id, endpoint)`. Both ship a paired `_down.sql`. The dedup store is wired through `WithOrgAndTenantScope` (parity with the v9 Phase 8 wrap convention); the periodic sweep job runs hourly through the platform admin pool, deleting rows whose `expires_at` has passed.

### Fixed

- **HITL stale-request expiration now actually runs under FORCE Row-Level Security.** The 1-hour expiration ticker previously called `expire_hitl_requests` against the agent's app-role pool with no `app.current_org_id` GUC set, so the cross-tenant scan silently matched zero rows - sister bug to the heartbeat path closed in v8.0.0. The ticker now routes through `OpenPlatformAdminConnection` per tick and uses the new `ExpireStaleAcrossTenants` path, which selects expiring rows with `FOR UPDATE SKIP LOCKED`, marks them `expired`, writes the history rows, and dispatches the new outbound webhook for any expired row that carried a `notify_url`. The legacy `ExpireStaleRequests` function is retained for back-compat with the `POST /api/v1/hitl/expire` HTTP path + existing tests.

### Configuration

- **`AXONFLOW_HITL_WEBHOOK_SIGNING_KEY`.** New env var (no default). Required to enable the outbound webhook - when unset, the dispatcher logs `[HITL.Webhook] DROP AXONFLOW_HITL_WEBHOOK_SIGNING_KEY=unset` per attempted delivery and the approve/reject response succeeds unchanged. Rotate by replacing the value and restarting; receivers should accept signatures from the prior key for the duration of their secret-sync cadence.

### Testing infrastructure

- **Cross-system HITL end-to-end harness.** Nine-probe script exercising the full `create → poll → approve/reject → webhook callback` lifecycle against a live platform stack. Covers both happy-path and error-class assertions (bad scheme, auth failure, missing required fields, 404 on unknown ID). CI-gated via the `Runtime E2E` workflow. Closes #2424.

## [8.0.1] - 2026-05-22 - CI green on community mirror (no runtime change)

Patch on top of v8.0.0. No platform behavior change; no migration impact; no SDK/plugin floor change. The [8.0.0] section below is the headline release.

### Fixed

- `TestBootLogCanonicalShape`, `TestProbeBootLogShimMatchesCanonicalShape`, `TestProductionPostureRegistryWellFormed`, and `TestEveryWriteIntoRLSTableIsWrapped` now run cleanly across all checkouts.
- `SDK Smoke Tests` and `Validate OpenAPI` workflows updated to pass on all checkouts.

## [8.0.0] - 2026-05-22 - v8 identity model enforcement + Row-Level Security default-on + cross-org admin routing

**Major-version cut.** v8.0.0 separates three previously-conflated identifiers - customer organization, API credential, and license deployment identity - and turns on Row-Level Security as the default tenant-isolation mechanism (FORCE RLS + non-owner application role) with cross-org admin routing for sweeps, recovery, and node-monitor workers. Pre-v8.0 the agent connected to the application database as the table owner, so RLS policies were defined but inert; v8.0.0 makes them load-bearing.

This is a major version because Row-Level Security enforcement changes the behaviour of direct SQL queries against the AxonFlow application database under the application role. **For customers using only the SDKs / plugins / HTTP API there is no breaking change** - JSON field names are unchanged, the `X-Tenant-ID` header is accepted as a deprecated alias, and Basic Auth credentials keep working. Existing v7.x SDKs (v8.0.0 SDK train) continue to work against v8.0.0 platform unchanged; the agent derives identity from Basic Auth when `X-Client-ID` is absent.

For the full mapping see the [v8 migration guide](https://docs.getaxonflow.com/docs/deployment/v8-to-v9-migration/).

### Breaking changes

- **`AXONFLOW_DB_USE_APP_ROLE` env gate, default `true`.** Agent + customer-portal connect to the application database as `axonflow_app_role` (NOBYPASSRLS) unless `AXONFLOW_DB_USE_APP_ROLE=false` is set explicitly. FORCE-RLS-protected tables return zero rows from any read that hasn't first set `app.current_org_id` via `set_config('app.current_org_id', '<value>', true)`. Verify before upgrade:
  1. `AXONFLOW_DB_APP_ROLE_URL` is set (or `DATABASE_URL` connects as the same role as master for dev / docker-compose).
  2. `AXONFLOW_DB_PLATFORM_ADMIN_URL` is set if any background worker iterates across orgs.
  3. All custom workers that iterate across orgs have been audited; they will silently return 0 rows under the app role.
  4. The `axonflow_app_role` + `axonflow_platform_admin` Postgres roles exist with `NOBYPASSRLS` / `BYPASSRLS` respectively (`scripts/operators/provision-app-role.sh` is the canonical bootstrap).
  Set `AXONFLOW_DB_USE_APP_ROLE=false` explicitly during a phased rollout to preserve v7.x semantics.

- **Direct SQL against the AxonFlow application database under the application role.** RLS is now enforced. SELECTs return zero rows unless `app.current_org_id` is set first. Use the `axonflow_platform_admin` role (or master) for legitimate cross-org access.

- **`middleware.RLSMiddleware` + `SetRLSContextForSession` + `ResetRLSContext` + `WithRLS` removed.** The four pool-scope GUC functions issued `SELECT set_org_id($1)` on the `*sql.DB` pool - pool-unsafe because the GUC landed on one connection and the next handler statement might run on a different one. Forks calling these directly must migrate to `withRequestOrgScope(r, h.db, fn)`. Diagnostic helpers (`GetCurrentOrgID`, `VerifyRLSActive`, `GetRLSStats`, `RLSHealthCheck`) retained.

### Identity model - three distinct identifiers

- **`RequestIdentity` + `ClientIDFromContext` + `X-Client-ID` header forwarding.** Agent derives identity once per request and exposes a structured accessor; `X-Client-ID` is the canonical API-credential header and is forwarded agent → orchestrator. The agent's auth middleware overwrites any caller-supplied `X-Client-ID` with its own auth-derived value before forwarding, so spoofed inbound headers have no effect. `X-Tenant-ID` accepted as deprecated alias through v8; planned removal in the next major.

- **Additive `client_id` schema + idempotent `org_id` backfill.** Migrations 088-095 add `client_id` columns to credential, audit, policy, execution, and service-identity tables; backfill `client_id = tenant_id` for hot-path credential tables; composite indexes `(org_id, client_id, timestamp/created_at)` on audit tables.

- **v8 compat aliases retained.** `tenant_id` columns kept as deprecated; `X-Tenant-ID` header accepted; SDK config `clientId` semantics unchanged. Slated for removal in the next major.

### Row-Level Security enforcement

- **`axonflow_app_role` (NOBYPASSRLS) + `axonflow_platform_admin` (BYPASSRLS) Postgres roles.** Application traffic runs as the non-owner app role; background workers that iterate across orgs use `axonflow_platform_admin`.

- **`WithOrgScope` transaction-scoped GUC.** `platform/agent/rls_session.go` `WithOrgScope` sets `app.current_org_id` per request transaction via `set_config('app.current_org_id', $1, true)` (third argument `true` = txn-local), guaranteeing isolation between concurrent requests on a shared connection pool.

- **`OpenPlatformAdminConnection` helper.** New entrypoint in `platform/agent/db_connection.go` for cross-org workers to open a `*sql.DB` authenticated as `axonflow_platform_admin`. Asserts `current_user` matches on connect. Returns `nil, nil` when env unset (callers fall back to single-role behavior, with a startup-log declaration).

- **Main connection pools open via `OpenAppRoleConnection`.** Agent `authDB`, orchestrator `usageDB` + dynamic-policy + metrics + audit-logger pools, customer-portal main pool, and the connector-registry runtime pool all open through the helper, which resolves the DSN from `AXONFLOW_DB_APP_ROLE_URL` when `AXONFLOW_DB_USE_APP_ROLE=true` and asserts the connected role is `axonflow_app_role` at boot. Each pool emits a `current_user=<role> (UseAppRoleEnabled=<bool>, ...)` startup log line so a misconfigured DSN that silently falls back to the master role is caught at boot instead of bypassing RLS at runtime. Customer-portal's admin (BYPASSRLS) pool routes through `OpenPlatformAdminConnection` with the same role assertion. The connector-registry storage retains a one-shot master pool only for its `initSchema` step (axonflow_app_role lacks DDL privileges); the master pool is closed immediately after schema init and runtime traffic uses the app-role pool exclusively. Orchestrator-side handlers that touch FORCE-RLS tables wrap their access via `withRequestOrgScope` / equivalent SECURITY DEFINER helpers, matching the customer-portal contract.

- **Local-dev docker-compose defaults to single-role mode.** `docker-compose.yml` + `docker-compose.enterprise.yml` pin `AXONFLOW_DB_USE_APP_ROLE=false` so the stack boots without role provisioning. Override to `true` after running `scripts/operators/provision-app-role.sh` to soak the production path locally.

- **Cross-org workers route through admin role.** `StartCommunitySaasSweep`, `RegisterCommunityRecoveryHandler`, and `NewNodeMonitor` now call `OpenPlatformAdminConnection` and use the admin DB for their cross-org queries. Each emits a startup log declaring admin-vs-fallback for verification. Self-hosted deployments running `COMMUNITY_SAAS_SWEEP_ENABLED=true` or `ENABLE_NODE_MONITOR=true` (or any fork with custom cross-org workers) must set `AXONFLOW_DB_PLATFORM_ADMIN_URL` before upgrade - without it, these workers silently return 0 rows under the app role.

- **Customer-portal handlers wrap FORCE-RLS table access.** `nodes.go`, `export.go`, `connectors.go`, `sso.go`, `auth/saml/service.go` now wrap reads/writes of `organizations`, `tenants`, `community_saas_registrations`, `sso_*`, and `connector_configs` in `withRequestOrgScope` / `withOrgScope`. SAML INSERTs populate `org_id` (migration 106 marks the column `NOT NULL`).

- **MCP cache-miss path stamps auth context.** `resolveMCPSession`'s cache-miss branch + `handleMCPInitialize` now capture `*Client` + `AuthKind` into the cached `mcpSession`. `requireMCPAuth` stamps the four auth context keys (`TenantID` / `OrgID` / `ClientID` / `AuthKind`) on `r.Context` so MCP `tools/call` traffic sees the authenticated identity downstream - matching the REST middleware contract that the latent gap on this path had been missing.

- **FORCE RLS on audit, identity, config, and SSO tables.** Migrations 098, 099, 101, 102, 103, 106, 107 enforce row-level security on `deployment_upgrades`, `saml_configurations`, `audit_archive`, `mcp_query_audits`, `audit_retention_config`, `decision_chain`, identity tables (`custom_roles`, `role_assignments`, `service_identities`), `sso_configurations`, and additional config tables. First `FORCE ROW LEVEL SECURITY` in repo history; direct SQL against any of these tables under `axonflow_app_role` returns zero rows unless `app.current_org_id` is set first.

- **SECURITY DEFINER auth-bootstrap helpers.** Migrations 104, 108, and 109 introduce SECURITY DEFINER functions that bypass the FORCE-RLS chicken-egg for the auth-bootstrap step (the application role needs to read `customer_portal_api_keys` to authenticate the request that will then set `app.current_org_id`). Migration 104 ships `auth_lookup_api_key(text)` + `auth_touch_api_key(text)` for SELECT/UPDATE on the auth path; migration 108 ships the in-VPC variant for AWS deployments routing through a Lambda-side helper; migration 109 ships five additional helpers covering pre-auth `INSERT`/`UPDATE` paths (license claim, registration, telemetry-ack, etc.). All functions hardcode `search_path = pg_catalog, public` and are owned by `axonflow_platform_admin`.

- **Refuse-to-boot guard for `AXONFLOW_DB_USE_APP_ROLE=true` without `AXONFLOW_DB_PLATFORM_ADMIN_URL`.** The agent, orchestrator, and customer-portal binaries now exit on startup with a `FATAL` log line when `AXONFLOW_DB_USE_APP_ROLE=true` (the v8.0.0 default, also active when the env var is unset) and `AXONFLOW_DB_PLATFORM_ADMIN_URL` is not set. The previous behavior was a `WARNING` log followed by a silent fallback to the request-traffic pool, which under FORCE Row-Level Security caused cross-org workers (marketplace metering, community-saas sweep / recovery, node monitor, customer-portal admin handlers) to silently return zero rows. The FATAL log names both env vars so the configuration can be corrected without source diving. To preserve the legacy single-role posture, set `AXONFLOW_DB_USE_APP_ROLE=false` explicitly; the guard is a no-op under that flag.

### Migrations

- **`AXONFLOW_MIGRATIONS_PATH` env override.** Overrides the agent's hard-coded `/app/migrations/` Docker mount for deployments that don't use the canonical Docker layout. Leave unset for the standard Docker / `docker-compose` topology.

- **Migrations 042 + 069 made idempotent.** `CREATE INDEX IF NOT EXISTS` + `DROP TRIGGER IF EXISTS; CREATE TRIGGER` patterns make migrations safe to re-attempt when their `success=true` row is absent.

### Schema changes

- **`custom_roles.tenant_id` and `role_assignments.tenant_id` renamed to `org_id` (migration 111).** mig 023 (Nov 2025) created these two tables with a legacy `tenant_id` column predating the v8 identity rename. The RLS policies compared the column against the canonical `app.current_org_id` GUC, so the wraps elsewhere in this release worked - but the column/GUC mismatch was transitional. Migration 111 normalizes both tables to the canonical `org_id` column, recreates the RLS policy with the canonical `*_org_id_isolation` name shape, adds an explicit `WITH CHECK` clause (mig 023 specified `USING` only), and renames the dependent unique constraint (`uq_custom_roles_tenant_name → uq_custom_roles_org_name`) and indexes (`idx_custom_roles_tenant_id → idx_custom_roles_org_id`; same for `role_assignments`). `ALTER TABLE RENAME COLUMN` is data-safe (Postgres tracks column refs by `attnum`); the migration takes a brief `AccessExclusiveLock` on each table while the metadata flip and the DROP/CREATE POLICY run inside a single transaction. The Go-side `Role.TenantID` / `RoleAssignment.TenantID` struct fields rename to `OrgID` with `json:"org_id"` tags - direct consumers of the customer-portal roles API over HTTP must update their parsers; the customer-portal UI is unaffected (it never read the field).

### Administrative tooling

- **`scripts/operators/provision-app-role.sh`.** Reusable preflight script that idempotently creates `axonflow_app_role` + `axonflow_platform_admin` Postgres roles, grants the role-membership chain, and asserts `NOBYPASSRLS` / `BYPASSRLS` on the respective roles. Run before bumping `AXONFLOW_DB_USE_APP_ROLE=true`.

- **AWS CFN integration provisions `axonflow_app_role` automatically on stack deploys.** A new `provision-app-role` workflow runs as part of the AWS CFN deploy pipeline: it stages the role-bootstrap step against the deployment's RDS instance (deriving VPC + subnets from the RDS subnet group), gates the stack update on successful provisioning, and surfaces an `AppRoleProvisioned` CFN parameter so subsequent updates skip the step. Self-hosted AWS deployments no longer need to run the bash script by hand.

### Self-hosted upgrades

- **Keep `AXONFLOW_DB_USE_APP_ROLE=false` until you audit forks.** Stock v8.0.0 ships every hot-path write wrapped against FORCE RLS, but self-hosted deployments running customized or forked handlers (custom connectors, in-tree auth shims, fork divergence) must audit their write paths before flipping the env to `true`. Customized handlers that `INSERT`/`UPDATE` into Row-Level-Security-enabled tables without wrapping `WithOrgScope` or going through a SECURITY DEFINER helper will fail with `pq: new row violates row-level security policy`. The self-hosted preflight script gained a check that surfaces the env-pair requirement plus a customized-handler audit advisory; the [v8 migration guide](https://docs.getaxonflow.com/docs/deployment/v8-to-v9-migration/) gained a `Change 4` section detailing the audit recipe and the staged-rollout pattern.

### Security

- **Admin-API anonymous-callable fix.** Closed an admin-API endpoint that was anonymous-callable despite Basic Auth being declared in the OpenAPI spec; admin operations now require Basic Auth in all environments.

### Telemetry

- **`org_id` now included in SDK heartbeat payloads.** v8.1.0 SDKs (Go / Python / TypeScript / Java) + Rust v0.3.1 emit the caller's `org_id` alongside the existing instance / endpoint / deployment-mode fields. The platform's central heartbeat receiver tags incoming records with this value. `AXONFLOW_TELEMETRY=off` remains the sole opt-out and disables the heartbeat entirely. No other fields added; the previous v1 schema continues to work with v8.0.0 SDKs.

### Examples

- **End-to-end sweep across all five SDKs.** Every example in `platform/examples/` exercised end-to-end against a live agent with Go, Python, TypeScript, Java, and Rust SDKs. Examples that depended on stale env-var names, removed flags, or pre-v8 license shapes refreshed to match v8.0.0 platform behavior.

### SDK + plugin floor (advertised by `/health`)

- **Min SDK v8.0.0 (unchanged).** v8.0.0 SDK callers keep working against v8.0.0 platform - agent derives identity from Basic Auth when `X-Client-ID` is absent.
- **Recommended SDK v8.0.0.** v8.1.0 SDKs (Go / Python / TypeScript / Java) + Rust v0.3.1 are on each SDK's `main` carrying the `X-Client-ID` outbound emission, but not yet released to registries. Recommended will bump to v8.1.0 / v0.3.1 once the SDKs tag + publish.
- **Min plugins openclaw v2.4.0 / claude-code v1.4.0 / cursor v1.4.0 / codex v1.4.0 (unchanged).** Recommended unchanged.

## [7.9.0] - 2026-05-09 - Decision History API + policy_version recorded on every decision

**Decision-record release.** Closes the loop on programmatic decision audit:
callers can now `list` recorded decisions, `explain` any specific one, and
read the policy version that was active at decision time. The complete
read-side audit surface (list + explain + version provenance) is enough for
"show me everything we blocked yesterday and why" workflows without operators
leaving the API.

No breaking changes for self-hosted Enterprise deployments.

### Community

#### Added

- **`GET /api/v1/decisions` list endpoint** for paging recorded policy decisions. Companion to `/api/v1/decisions/{id}/explain` shipped in v7.4.0 - callers can now both list and drill in. Tier-aware caps (Free 24h × 5; Pro 30d × 100; Self-hosted Evaluation 14d × 100; Self-hosted Enterprise full retention × 1000).
- **`list_recent_decisions` MCP tool** wraps the new list endpoint so the AI in any host CLI can answer "what just got blocked?" inline without the user leaving their tool surface. Same tier caps as the HTTP endpoint.
- **`policy_version_at_decision` on the explain response.** Records and surfaces the policy version that was active when the decision was made - an audit drill-in shows not just *which* policy fired but the exact rule text the decision was made against. Crucial for compliance reviews of decisions made before a policy was edited. Additive field; existing readers ignore it cleanly.

#### Telemetry

- **Anonymous platform startup heartbeat (agent + orchestrator).** One classification-only ping per binary per 7 days; single opt-out `AXONFLOW_TELEMETRY=off`; disclosure line printed on every send. Closes the gap where `docker compose up` deployments that never instantiate an SDK looked invisible to adoption analytics.
- **v1 schema additions on `POST /v1/ping`** - additive `telemetry_type`, `component`, `license_tier`, `environment_class`, `stream` fields with closed-enum normalization on both sides. `"rust"` joins the language-SDK allowlist. Existing SDK / plugin pings continue working unchanged.

#### Fixed

- **Community-SaaS daily-cap 429 events now persist with full attribution.** Previously the auth middleware populated the telemetry tenant_id after the daily-cap check, so rate-limit rejections terminated before attribution and the telemetry table was blind to the very rejections it should have been counting. Tenant_id now resolves immediately after auth, before the daily-cap gate, so every 429 event ingests with full attribution.

## [7.8.0] - 2026-05-07 - V1 Plugin Pro graduated freemium + structured upgrade envelope + 5 new MCP tools + Rust SDK announcement

**V1 Plugin Pro completion release.** Builds on v7.7.0's launch with the graduated freemium model that turns every Free-tier limit into a conversion moment instead of a dead-end 401/429. Pro buyers now get the right caps everywhere, MCP governance traffic counts against daily quota, and a structured upgrade envelope replaces five different per-route ad-hoc 429 bodies with one wire shape that all four plugins parse identically. No breaking changes for existing self-hosted Enterprise deployments; Free / Pro / Premium SaaS Plugin tiers all keep their v7.7.0 wire shape, plus richer fields.

**5th SDK live - Rust preview at v0.1.0.** First-ever AxonFlow Rust SDK shipped 2026-05-05 to [crates.io](https://crates.io/crates/axonflow-sdk-rust) covering proxy + audit + basic MAP + basic MCP + OpenAI interceptor. Repo: [getaxonflow/axonflow-sdk-rust](https://github.com/getaxonflow/axonflow-sdk-rust). Quickstart: [docs/sdk/rust-quickstart.md](docs/sdk/rust-quickstart.md). Foundation contributed voluntarily by Francesco Pierfederici.

**V1 customer-facing surfaces in this release:**

- **Five Pro differentiators, all enforced.** Daily quota (Free 200 → Pro 2,000), audit retention (Free 3d → Pro 30d), custom tenant policies (Free 2 active → Pro unlimited), HITL approvals (Free 1 per rolling 7d → Pro unlimited), LLM cost pre-flight (Pro only). Existing Pro buyers automatically receive the higher daily-quota cap on this release.
- **Structured upgrade envelope across every Free-tier limit hit.** One JSON shape (`{error, limit_type, tier, limit, remaining, window, resets_at, upgrade.{tier, wording, compare_url, buy_url}}`) on 429 daily-quota AND 403 graduated / Pro-only paths. Three locked headers (`X-Axonflow-Tier-Limit`, `X-Axonflow-Upgrade-URL`, `Retry-After`). Plugin parsers read the same envelope on the HTTP path and on the JSON-RPC path (where it rides inside `result.content[0].text` with `isError: true`).
- **Five new MCP tools on `/api/v1/mcp-server`.** `axonflow_get_tenant_id` (Free + Pro), `axonflow_request_approval` (Free 1 per rolling 7d, Pro unlimited), `axonflow_create_tenant_policy` (Free 2 active max, Pro unlimited), `axonflow_get_cost_estimate` (Pro only - wraps `/api/v1/plans/estimate`), `axonflow_list_pro_features` (data only, all tiers). All five carry an explicit `success: true` field so LLM consumers in Cursor / Claude Code / Codex / OpenClaw see an unambiguous positive signal on every successful call.
- **Tier-aware `tools/list` filtering.** Free callers see N tools, Pro callers see N+M. Honest visibility - `axonflow_get_cost_estimate` does not appear in a Free user's tool list at all (not just rejected on call).

**Companion plugin release planned at v1.3.0 / v2.3.0** with envelope-aware error handling (parse → display → honor `Retry-After`) and skill / README mentions of the new MCP tools. Plugin tags + npm / ClawHub publishes follow on their own release schedule.

**Stable SDKs (Go / Python / TypeScript / Java) unchanged at v7.1.0.** Existing SDK callers inherit the higher Pro daily quota with zero code change - V1 Plugin Pro is server-side and plugin-side only.

### Community

#### Added

- **Tier-gating framework on MCP tools.** Tool definitions can now declare `RequiredTier` ("Pro" / "Premium") which drives `tools/list` filter visibility and `tools/call` dispatch rejection, and `FreeUsageLimit` which enforces graduated-cap behavior - `MaxCount` for object-creation limits ("2 active custom policies") and `WindowSeconds` + `MaxInWindow` for rolling-window action limits ("1 HITL approval per 7 days"). Both fields default zero / nil so every existing tool is unchanged.
- **Structured V1 upgrade envelope.** One shape across HTTP (429 daily-quota, 403 active-policies / hitl-approvals / feature-pro-only) and JSON-RPC (wraps the same envelope inside `result.content[0].text` with `isError: true`). Locked URLs `https://getaxonflow.com/pricing/` (compare) + `https://buy.stripe.com/bJe28qbztcdVchjdkw8k800` (buy) are the single source of truth across agent code, license email body, Stripe Dashboard, and customer-facing landing pages.
- **`axonflow_get_tenant_id` MCP tool.** Returns `{success, tenant_id, tier, upgrade_url, buy_url}`. The AI in any host CLI can answer "what's my tenant ID?" / "what tier am I on?" inline without running a shell script - replaces the per-plugin discovery scripts with auto-discovered MCP tool dispatch.
- **`axonflow_request_approval` MCP tool.** Inline HITL approval gate before risky operations (e.g. `rm -rf`, `git push --force`, production deploy). Free tier supports 1 approval per rolling 7-day window; Pro unlimited.
- **`axonflow_create_tenant_policy` MCP tool.** Lets the AI create tenant-scoped governance policies on the fly - *"block any tool call that writes to ~/.ssh/"*, *"require approval for any `rm -rf`"*. Free tier supports 2 active policies (delete to make room); Pro unlimited.
- **`axonflow_get_cost_estimate` MCP tool.** LLM cost pre-flight before running multi-step plans - the headline anti-runaway-bills feature. Pro tier only; Free callers see the tool filtered out of `tools/list`. Wraps the orchestrator's `/api/v1/plans/estimate` so per-token pricing follows the orchestrator's authoritative pricing config - no drift between proxy enforcement and tool-reported estimate.
- **`axonflow_list_pro_features` MCP tool.** Returns the V1 Pro feature list as data - five differentiators, exact pricing, tone-direction quote - so a Free user's AI can faithfully answer "what would I get if I upgraded?" without reading docs.
- **Daily-cap enforcement on every governance route.** Three previously-leaking routes - `/api/v1/mcp-server tools/call`, `/api/v1/mcp/check-input`, `/api/v1/mcp/check-output` - now consume daily quota and emit the V1 envelope on rejection. Pre-fix: Free tenants could get unlimited governance evaluation by routing through MCP. Post-fix: every governed event counts.
- **`success: true` field on every V1 MCP tool response.** Plus companion `submitted: true` / `awaiting_review: true` on `axonflow_request_approval` and `created: true` on `axonflow_create_tenant_policy` so LLM consumers don't misread `status: "pending"` (HITL row state) or `enabled: true` (policy state, not operation outcome) as failure. Locks unambiguous tool-success semantics for AI consumers across host CLIs.
- **Telemetry stream classifier.** Every heartbeat row tagged `Stream=heartbeat` so the SDK / plugin heartbeat stream and a future Community SaaS operational stream remain distinguishable when both flow through the same telemetry pipeline.

#### Changed

- **Pro daily quota 1,000 → 2,000.** Existing Pro buyers automatically receive the higher cap on this release. Heaviest observed Free-tier daily volume in the week leading up to release was ~780 events for a single power user; 2,000 leaves comfortable headroom for a Pro user's normal day.
- **MCP `tools/list` is tier-filtered.** Free callers see N tools (Pro-only ones omitted); Pro callers see N+M. The filter is honest visibility, not security - `tools/call` dispatch re-enforces the gate so a determined Free caller invoking by name still gets the structured rejection envelope.
- **All daily-cap-exceeded responses now emit the V1 envelope.** Auth-path and proxy-path rejection bodies used to differ in shape for the same condition (one wrapped, one flat); both now emit the V1 envelope verbatim. Plugins or direct API consumers that previously parsed the auth-path's nested `{error: {code, message}}` shape will need to update to read the V1 envelope's top-level `error` string + richer surrounding fields - the v1.3.0 / v2.3.0 plugin train carries the parser change on the client side.
- **`AXONFLOW_TELEMETRY=off` scope clarified in docs.** Controls the SDK / plugin heartbeat path only. Community SaaS operational data (registrations, audit logs, policy-enforcement records, request-header metadata) is processed inherent to running the hosted service and is independent of the heartbeat opt-out.

#### Fixed

- **Apache Thrift CVE-2026-41602 (HIGH - Integer Overflow).** Indirect dependency `github.com/apache/thrift` bumped from v0.22.0 to v0.23.0 via the Snowflake connector chain.

### Enterprise

#### Changed

- **`RecommendedPluginVersion` advertised in `/health`** bumps to claude / cursor / codex 1.3.0 and openclaw 2.3.0. `MinPluginVersion` floors stay at 1.0.0 / 2.0.0 - pre-1.x plugins ran the pre-DNT-removal contract and remain blocked; pre-V1-Plugin-Pro plugins continue to work but log an actionable upgrade warning on every governed call.
- **`RecommendedSDKVersion` unchanged at v7.1.0.** This release is server-side and plugin-side only; the `X-Axonflow-Client` header semantics + scope-aware license validation that v7.1.0 SDKs already speak cover all V1 Plugin Pro paths.

## [7.7.0] - 2026-05-06 - V1 SaaS Plugin Pro launch + free-tier credential recovery + license matrix

**V1 launch release.** First public release of the paid Pro tier and credential recovery for AxonFlow Community SaaS. Self-hosted deployments are unaffected; existing Self-Hosted licenses keep validating via the documented backward-compat path.

**V1 customer-facing surfaces shipping together:**

- **Paid Pro tier ($9.99 one-time, 90 days).** Stripe Checkout success mints
 an Ed25519-signed plugin license token, persists it on the tenant, and
 emails it to the buyer. The token paste activates Pro features immediately
 on every governed request through the plugin. Full Stripe refunds within
 the 14-day window auto-revoke the license; partial refunds are an explicit
 no-op.
- **Free-tier credential recovery.** A Community SaaS tenant who opted into
 recovery at sign-up time can self-recover a lost secret via emailed magic
 link. Capped at 3 active tenants per email; per-IP rate limit prevents
 enumeration probes.
- **GDPR right-to-erasure.** Two-step email-verified tenant deletion
 atomically scrubs registration, license, audit history, daily-usage
 counters, and per-tenant usage records. An immutable deletion log row
 survives the cascade for Article 30 compliance.

**Companion plugin and SDK release.** All four plugins
(axonflow-claude-plugin, axonflow-cursor-plugin, axonflow-codex-plugin)
advance to v1.2.0 and axonflow-openclaw-plugin advances to v2.2.0. All
four stable SDKs (Go, Python, TypeScript, Java) advance to v7.1.0 with
the new `X-Axonflow-Client` header and scope-aware license validation.
Existing v7.0.x SDK / v1.1.x plugin callers continue to work without
the header - they receive a one-time upgrade hint. (Per-version detail
in the Plugin / SDK release-companion sections below.)

No breaking platform changes for existing self-hosted Enterprise tenants.
Existing license tokens validate cleanly via the missing-`aud` fallback
documented in the License Matrix below.

### Community

#### Added

- **`POST /api/v1/billing/stripe-webhook`** - Stripe webhook receiver for
 the V1 SaaS Plugin Pro tier. Subscribes to `checkout.session.completed`
 (issues the license) and `charge.refunded` (revokes on full refund).
 Defended by Stripe-Signature HMAC + IP allowlist (Stripe's published
 webhook CIDRs, env-overridable) + per-source rate limit (60 req/min
 default). `GET` returns 405 so misconfigured webhook URLs in the Stripe
 Dashboard fail loudly. Idempotent over `stripe_session_id` - Stripe's
 at-least-once delivery returns the original token byte-identically on
 retry, never a new one.
- **License token validation on every governed request.**
 `validateCommunitySaasAuth` now reads `X-License-Token`, validates the
 Ed25519 signature, checks the token's audience claim against the SaaS
 Plugin accept list, verifies the tenant binding matches the auth-resolved
 tenant, and looks up the active row in `plugin_user_licenses`. Free tier
 (no header) passes through unmodified; Pro / Premium tier promotes the
 request when both token and row are valid. Per-request DB lookup keeps
 revocation effective within ~60s of a chargeback or dispute. Token
 tenant_id mismatch returns 403; missing/revoked row returns 401; DB
 unavailability returns 503 so the plugin retries rather than silently
 degrading to Free.
- **Per-tenant daily request quota.** Daily event quota now follows the
 resolved tier from the license token: Free 200/day, Pro 1,000/day,
 Premium 5,000/day (reserved, not yet sold). Quota fires on both admin
 routes (`apiAuthMiddleware`) and plugin / SDK governed routes
 (`/api/v1/process`, `/api/v1/audit/*`, `/api/v1/mcp/evaluate-policies`,
 `/api/v1/connectors`). The legacy `COMMUNITY_SAAS_DAILY_LIMIT` env var
 is preserved as a fallback for callers without a resolved tier
 (perf-testing rigs, etc.).
- **Per-tenant audit retention.** Audit log cleanup now buckets tenants by
 retention tier - Free 3 days, Pro 30 days, Premium 90 days (reserved).
 Self-hosted deployments without the SaaS schema fall through cleanly
 via a `relation does not exist` guard on the SaaS table.
- **`POST /api/v1/recover`** - request a magic-link recovery email for a
 Community SaaS tenant bound to a given email. Always returns 202
 (anti-enumeration); the delivered email contains a single-use 15-minute
 magic link.
- **`POST /api/v1/recover/verify`** - consume a magic-link token and
 receive fresh credentials bound to the same email. `GET` on the same
 path serves an HTML confirmation page (no state change) so email-link
 prefetchers don't burn the token.
- **Email field on `POST /api/v1/register`** so Community SaaS registrants
 can opt into recovery at sign-up time.
- **`POST /api/v1/tenant/<id>/delete-request`** +
 **`POST /api/v1/tenant/<id>/delete-confirm`** - GDPR right-to-erasure
 endpoints. `delete-request` accepts the email-on-file and emails a
 single-use 1-hour confirmation token; `delete-confirm` consumes the
 token and atomically scrubs the tenant from the SaaS registration table,
 license table, audit logs, daily-usage counter, and usage events. Stripe
 customer archive runs best-effort post-commit (DB-side erasure completes
 regardless of Stripe reachability). Per-IP (1/min) and per-tenant
 (1/hour) rate limits prevent spam. Tokens stored as HMAC-SHA256 (with
 optional `AXONFLOW_TENANT_DELETE_TOKEN_PEPPER` for at-rest hardening).

#### Changed

- **License Matrix - explicit `aud` claim per hosting-mode × scope.** Six
 canonical audience values now describe the matrix:
 `axonflow.{saas,self_hosted}.{plugin,sdk,full}`. Each license-validation
 context (SaaS Plugin path, SaaS SDK path, self-hosted loader) ships an
 explicit accept list - cross-quadrant misuse (e.g. a SaaS Plugin Pro
 token pasted into `AXONFLOW_LICENSE_KEY`, or a self-hosted Enterprise
 license sent as `X-License-Token`) is rejected at the validator
 boundary with an explicit reason. **Existing tokens predating the
 rename have empty `aud` and validate via a documented fallback to
 `axonflow.self_hosted.full` - no production breakage on upgrade.** Two
 new helpers (`HostingMode` and `HasScope(scope)`) on the parsed
 license payload derive the matrix coordinates so callers don't
 string-parse inline. The deprecated `origin` claim (redundant with
 the new `aud`) is no longer set on newly issued tokens or read by
 validators.
- **SaaS Plugin tier rename + schema simplification.** Internal V1
 paid-tier names `plugin-claimed` and `plugin-subscription` rename to
 `Pro` and `Premium`, with a new `Free` baseline applied when no
 `X-License-Token` is sent. Per-tier limits move out of a JSONB blob
 and into a typed struct shared with the self-hosted ladder. The
 forward-only schema migration drops the JSONB column, renames any
 existing rows, and tightens the tier CHECK constraint. No production
 tokens existed for the prior design; staging fixtures re-seed cleanly
 under the new schema.
- **Stripe webhook now issues 90-day Pro tokens by default.**
 Configurable per-deploy via `AXONFLOW_BILLING_PRO_VALIDITY_DAYS`;
 per-tenant token validity is independent of the plugin install
 lifetime.
- **Eval-license endpoint mints a quadrant-aware token.** The
 `/api/evaluation-license` Cloudflare Pages Function on `getaxonflow.com`
 now sets `aud` explicitly per the originating form: the platform
 Self-Hosted Eval form at `/evaluation-license` mints
 `axonflow.self_hosted.full`; the Plugin In-VPC Eval form at
 `/plugins/evaluation-license` mints `axonflow.self_hosted.plugin`.
 Existing eval tokens issued before this release validate unchanged
 via the missing-`aud` fallback.
- **Cross-quadrant license rejection.** A self-hosted Enterprise
 license sent as `X-License-Token` on a SaaS request is now rejected
 at the validator boundary with an explicit "wrong hosting mode"
 reason instead of silently failing further down the stack.

#### Fixed

- **Stripe webhook idempotency held only on the day a token was issued.**
 The token's payload `IssuedAt` came from `time.Now` while the
 persisted row's `issued_at` defaulted to the DB's `NOW` and was read
 back via `RETURNING`. A replay landing on a different UTC day produced
 a byte-different re-minted token, breaking the V1 Stripe-retry
 guarantee. Issuer now passes `IssuedAt` explicitly into both the
 token and the INSERT so the persisted value matches what the token
 signs.
- **`POST /api/v1/audit/search` returns `entries: []` (not `null`) on
 empty result sets.** Iteration code that walked the array
 (`for entry of entries`) or read its length without a null guard now
 works correctly. Callers that already handled the null case remain
 compatible.
- **`POST /api/v1/overrides` rejects critical-severity system policies
 with HTTP 403.** Authentication-bypass, time-based blind SQL injection,
 stacked DROP/DELETE/UPDATE/INSERT/EXEC patterns, government IDs, and
 financial PII patterns are no longer overridable. Pre-existing active
 overrides on these policies are revoked at upgrade time.
- **Per-tenant daily cap fires on plugin / SDK governed routes.**
 Previously the cap was only enforced on admin routes; plugin and SDK
 traffic flowing through `/api/v1/process`, `/api/v1/audit/*`,
 `/api/v1/mcp/evaluate-policies`, and `/api/v1/connectors` was
 effectively un-capped. The cap now mirrors onto these proxy routes
 with the same per-tenant tier-aware limit and the same HTTP 429
 response shape.
- **Per-IP rate limits behind ALB now key on the trusted last-hop IP.**
 Community SaaS register and recovery rate limits previously read the
 first `X-Forwarded-For` entry, which is client-controlled behind
 AWS ALB; the limits now read the last entry (the ALB-observed peer
 IP) so spoofed first-entry values cannot bypass the per-IP cap.
- **AWS Secrets Manager-derived secrets are trimmed at boot.**
 RESEND_API_KEY, STRIPE_WEBHOOK_SIGNING_SECRET,
 AXONFLOW_INTERNAL_SERVICE_SECRET, JWT_SECRET, and LLM provider API
 keys are read via a dedicated helper that strips trailing whitespace.
 SM-CLI-quirky values with stray newlines previously caused
 Authorization-header rejection or HMAC mismatch in confusing ways at
 first request.

#### Documentation

- **License Matrix architecture decision** documents the
 six-quadrant license model, per-context accept lists, and the
 missing-`aud` backward-compat fallback used by every existing
 self-hosted token.
- **V1 paid Pro tier integration guide** covering Stripe Checkout setup,
 webhook configuration, license token format, plugin-side activation,
 and the refund window. Included in `docs/api/agent-api.yaml` for the
 Community Stripe webhook endpoint.

#### CI / Testing

- **Definition-of-Done CI gate.** Every PR that touches user-facing
 surface (platform, ee/platform, migrations, docs/api) must include a
 corresponding `runtime-e2e/` test that exercises the change against a
 live agent + DB stack. Skipped via `[skip-runtime-e2e]` PR title prefix
 + a justification block in the PR body for build / deps / lint /
 connector-builder tooling changes.
- **License-flow runtime E2E** (the runtime test bundle) drives the
 full Stripe-checkout → token-issued → email-delivered →
 plugin-uses-token path against a Docker community-saas stack.
- **Tenant-durability runtime E2E** (the runtime test bundle)
 asserts a Community SaaS tenant survives an agent-container restart
 because the tenant row lives in Postgres.
- **Free-tier recovery runtime E2E** (the runtime test bundle) drives
 the magic-link recovery flow end-to-end including the post-recovery
 audit-write check.

### Operator

- **`AXONFLOW_BILLING_PRO_VALIDITY_DAYS`** - override the 90-day default
 Pro license validity. Bad / non-positive values fall through to the
 default rather than failing boot.
- **`AXONFLOW_BILLING_FROM_EMAIL`** - override the from-address on
 post-purchase license-delivery emails (default
 `AxonFlow <hello@getaxonflow.com>`).
- **`AXONFLOW_PLUGIN_CLAIMED_PUBLIC_KEY`** - verifier-only split. When
 set, the agent verifies plugin tokens without holding the signing
 seed; only the issuer service holds the seed. Recommended production
 posture so a runtime compromise of the agent cannot mint forged
 tokens. Backward-compatible: when unset, the agent derives the
 pubkey from the existing signing-key env var.
- **`AXONFLOW_STRIPE_WEBHOOK_IP_ALLOWLIST`** +
 **`AXONFLOW_STRIPE_WEBHOOK_RATE_PER_MIN`** - knobs for tuning the
 Stripe webhook IP allowlist (default = Stripe's published webhook
 CIDRs) and per-source rate limit (default 60/min).
- **`AXONFLOW_TENANT_DELETE_TOKEN_PEPPER`** - optional pepper for the
 at-rest HMAC of GDPR-deletion confirmation tokens.
- **AWS Marketplace template** (`cloudformation-ecs-fargate.yaml`)
 gains an optional `StripeWebhookSecretArn` parameter that wires the
 agent container's `STRIPE_WEBHOOK_SIGNING_SECRET` env var from a
 Secrets Manager ARN. Default empty (Stripe-paid tier disabled, agent
 webhook handler exits early). The IAM TaskExecutionRole grants
 `secretsmanager:GetSecretValue` on the supplied ARN only when set,
 so customers running the marketplace template without Stripe see no
 policy bloat.
- **CloudWatch alarms for Stripe billing** attach three
 metric-filter-driven alarms to the agent log group: webhook delivery
 failures (≥5 in 5 min → page), license issuance failures (1 in 1
 min → page - money taken without service delivered), and a
 first-payment milestone (1 in 1 min → separate SNS topic for the
 launch celebratory ping). Gated by `EnableStripeAlarms=true`
 (default) so staging stacks can opt out.
- **Synthetic monitoring canary.** Stand-alone CFN stack deploys a
 Python Lambda that runs hourly via EventBridge and exercises
 `/api/v1/register` → `/api/v1/mcp-server` → `/api/v1/audit/search`
 end-to-end against the public community-saas endpoint. Failures
 publish a structured failure report to a dedicated SNS topic.

### Evaluation

- All Community changes apply.
- Self-Hosted Evaluation licenses continue working unchanged. The
 `/api/evaluation-license` issuance endpoint now stamps the explicit
 `aud` claim per the originating form (Self-Hosted Full vs. Plugin
 In-VPC), but tokens issued before this release validate cleanly via
 the missing-`aud` fallback.

### Enterprise

- All Community + Evaluation changes apply.
- No Enterprise-only behaviour changes in this release. The portal,
 customer-portal-ui, and the rest of the Enterprise tree pick up the
 Community-side fixes (license matrix validators, daily-cap on proxy
 routes, secret-trimming) automatically.

### SDKs

- **Go SDK v7.1.0** - `axonflow-sdk-go@v7.1.0`. Sends `X-Axonflow-Client`
 on every governed request; SDK identifies itself by the canonical
 `sdk-go/<version>` pattern.
- **Python SDK v7.1.0** - `axonflow>=7.1.0`. Same `X-Axonflow-Client`
 injection.
- **TypeScript SDK v7.1.0** - `@axonflow/sdk@^7.1.0`. Same.
- **Java SDK v7.1.0** - `<version>7.1.0</version>`. Same.

The `X-Axonflow-Client` header is consumed by the agent's scope
validator: a SaaS Plugin Pro token paired with an SDK client header is
rejected at the validator boundary, and vice versa. Existing v7.0.x
callers continue to authenticate without the header - the agent emits
a one-time upgrade hint per process and treats the request as `full`
scope.

axonflow-sdk-rust remains at v0.1.0 (preview). The `X-Axonflow-Client`
header support lands in a future preview release.

### Plugins

- **OpenClaw v2.2.0** - `npm install @axonflow/openclaw@^2.2.0`. Sends
 `X-Axonflow-Client: openclaw/<version>` on every governed agent
 request. Pro license token paste via
 `clawhub config set license-token <token>` activates Pro features
 immediately.
- **Claude Code plugin v1.2.0** - graduates from the v1.1 line. Sends
 `X-Axonflow-Client: claude-code/<version>`. License token paste via
 `/axonflow login --token <token>`.
- **Cursor plugin v1.2.0** - graduates from the v1.1 line. Sends
 `X-Axonflow-Client: cursor/<version>` via `mcp.json` `headers` field.
 License token paste via Cursor settings (`AXONFLOW_LICENSE_TOKEN`).
- **Codex plugin v1.2.0** - graduates from the v1.1 line. Sends
 `X-Axonflow-Client: codex/<version>` via `.mcp.json` `http_headers`
 block. License token paste via `~/.codex/axonflow.toml`.

All four plugins continue to query `/health` at startup and emit a
one-time upgrade hint when the agent's `min_plugin_version` floor is
above the plugin runtime.

## [7.6.0] - 2026-05-02 - Policy-engine response cleanup + per-category enforcement controls

MINOR release. Adds new API surfaces on the marketplace CFN template and
on the policy enforcement response, plus two bug fixes on the audit-trail
side. No breaking changes; existing SDK / dashboard consumers continue
to work.

**Bug fixes:**

- **`policy_info` no longer reports duplicate matched policies.** When a
 policy's pattern matched both the query string and a request parameter,
 the response field listed the same policy twice (e.g.
 `["sys_sqli_grant", "sys_sqli_grant"]`). Each policy is now reported
 once per evaluation regardless of how many contexts it matched in.
 Block-decision behaviour is unchanged.
- **`sys_pii_booking_ref` no longer fires on SQL keywords.** The original
 pattern `\b[A-Z0-9]{6}\b` matched any 6-char alphanumeric token,
 including SELECT, INSERT, DELETE, UPDATE, CREATE - generating a
 booking-reference audit-log entry for every benign SQL query and
 inflating "PII detected" counts in compliance dashboards. The pattern
 now requires a booking-context label (booking, reservation, reference,
 ref, pnr, confirmation, conf) before the alphanumeric token. Real
 booking refs like `booking ABC123` or `PNR XYZ789` continue to match.
 Action remains `log` - requests are not affected, only audit-trail
 noise. A follow-up SQL migration (074) updates already-deployed
 systems in place; new deployments seed the corrected pattern from
 the start.

**API additions:**

- **`policy_info.matched_policies` field added** alongside the existing
 `policies_evaluated`. The new field name is the canonical one; the
 legacy `policies_evaluated` is kept populated with the same values
 for backward compatibility and will be removed in the next major
 release. The original field name suggested "every policy the engine
 ran against the input" but the value has always been the matched-
 policies list - the new name reflects what's actually reported.

**Enterprise:**

- **Per-category detection action overrides on the marketplace CFN
 template.** Self-hosted enterprise stacks gain four new optional
 CloudFormation parameters - `SQLIAction`, `PIIAction`,
 `SensitiveDataAction`, `DangerousQueryAction` (each: `block` / `warn` /
 `log`, `PIIAction` also accepts `redact`). Empty leaves the active
 `AXONFLOW_PROFILE` default in place; setting one overrides only that
 category without flipping the global profile. Lets operators tighten
 enforcement on a single category (e.g. `SQLIAction=block` for a
 benchmark stack) without inheriting the strict profile's PII redact
 behaviour. No change for existing deployments - the parameters
 default to empty.

- **Per-category circuit breaker threshold overrides on the
 marketplace CFN template.** Two new optional CloudFormation
 parameters - `CBErrorThreshold` and `CBPolicyViolationThreshold`
 (integers) - let operators tune the agent's per-client circuit
 breaker without forking the template. Production defaults stay
 at the Article-14 posture (10 errors / 20 policy violations per
 5-min window per client); empty values leave defaults in place.
 Useful for benchmark stacks running attack-pattern load that would
 otherwise trip the breaker after the first second.

## [7.5.0] - 2026-04-29 - Production, quality, and security hardening - upgrade encouraged

**Upgrade strongly recommended.** Over the past month we've shipped substantial
production, quality, and security hardening across the AxonFlow platform -
upgrade for a more secure, reliable, and bug-free experience.

**Security highlights from this release cycle:**
- **Multi-tenant isolation in MAP execution** (v7.4.5). A body-supplied
 `org_id` could override the authenticated org for both recording AND
 policy evaluation. Identity is now sourced from authenticated headers
 consistently across recording, read filters, and policy evaluation.
- **SQL-injection enforcement restored on `try.getaxonflow.com`** (v7.5.0).
 The Community SaaS endpoint had inherited the `warn` default since
 v6.2.0; SQLi-shaped requests passed through to the LLM. Default flipped
 back to `block`; configurable per deploy.
- **Cross-tenant audit-log isolation** (v7.2.0). Evidence and explain
 handlers fail-closed when tenant context is missing instead of
 returning data scoped to a different tenant.

The full set of platform-side security fixes addressed in this cycle -
including five additional access-control and DoS hardening items not
listed above - is documented in the consolidated security advisory
[GHSA-9h64-2846-7x7f](https://github.com/getaxonflow/axonflow/security/advisories/GHSA-9h64-2846-7x7f).

**Reliability and bug-fix highlights:**
- **`/health` now reports the deployed platform semver** (v7.5.0). Was
 returning `1.0.0` on every deployed stack because the image tag
 failed the version-resolver regex. New `PlatformVersion` CFN parameter
 + repo-root `VERSION` file as single source of truth.
- **ALB idle timeout 300s on Community SaaS** (v7.5.0). Long MAP plan
 generation requests no longer 504 at the load balancer before the
 orchestrator finishes.
- **`decision_id` on every governance decision path** (v7.5.0).
 Allow paths on `/api/v1/mcp/check-input` and `/api/v1/mcp/check-output`
 no longer silently drop the audit correlator; every allow / deny /
 redact decision now surfaces `decision_id` for forensic correlation.

No breaking platform changes. Existing SDK and plugin callers continue
to work; they receive a one-time upgrade hint when they sit below the
new floor.

### SDKs and Plugins

Coordinated major-version bump across all eight artifacts. The four
SDKs (Go, Python, TypeScript, Java) advance to **v7.0.0**. The OpenClaw
plugin advances to **v2.0.0**; the Claude Code, Cursor, and Codex CLI
plugins graduate from `v0.x.x` to **v1.0.0**. The breaking change
driving all eight is the `DO_NOT_TRACK` telemetry opt-out removal -
`AXONFLOW_TELEMETRY=off` is now the canonical and only opt-out across
every SDK and every plugin.

### Community

#### Added

- **`/health` advertises plugin version compatibility.** New
 `plugin_compatibility` field declares `min_plugin_version` and
 `recommended_plugin_version` per plugin id (`openclaw`, `claude-code`,
 `cursor`, `codex`), mirroring the long-standing `sdk_compatibility`
 shape. Plugins query `/health` at startup, log a one-time upgrade
 warning when they're below the floor, and stay quiet otherwise - the
 same downgrade-warning gate every SDK already runs. The
 `HealthResponse` OpenAPI schema gains the new field; older platforms
 without the field degrade silently on the plugin side.
- **Community-SaaS registration lifecycle.** Registration TTL bumped
 from 30 days to 1 year; existing 30-day registrations within 60 days
 of expiry are auto-extended at deploy time so no live tenant gets
 locked out. New tombstone semantics keep the `tenant_id` slot
 reserved indefinitely after a cascade-delete so a UUID is never
 reused, and a distinct `ErrRegistrationTerminated` error returns an
 actionable "re-register" message instead of the generic invalid-
 credentials response. The disclaimer returned by
 `POST /api/v1/register` now matches the public privacy policy and
 the plugin first-run setup message - single source of truth across
 surfaces.
- **Daily Community-SaaS inactivity sweep** terminates tenants idle for
 more than 3 months and tenants past the 1-year hard cap, cascade-
 deleting their tenant-scoped data (audit logs, policies, workflows,
 plans, etc.) in a single transaction so a partial failure rolls the
 whole tick back. The cascade table list is reflected from
 `information_schema` at agent startup with a hard non-cascade
 allowlist for structural tables. Multi-instance correctness via
 Postgres advisory lock - only one agent task runs the sweep per
 tick. Opt-in per deploy via `COMMUNITY_SAAS_SWEEP_ENABLED=true`,
 with `COMMUNITY_SAAS_SWEEP_DRYRUN=true` available so operators can
 soak the predicate logic for 24h before flipping the real switch.
 Per-termination audit-log line plus Prometheus counters for
 inactivity terminations, hard-cap terminations, lock-skip events,
 cascade row counts, and tick failures.

#### Changed

- **OpenAPI specs now declare 24 fields the platform has been emitting
 on the wire but the spec hadn't documented.** `AuditLogEntry`
 (`metadata`, `model`, `policy_violations`), `DynamicPolicy` (7 CRUD
 fields), `PlanResponse` (4 plan-context fields),
 `ResumePlanResponse` (7 resume-context fields), plus 16
 lower-priority schemas covering audit query params, budget/usage
 fields, execution-snapshot HITL fields, workflow step audit context,
 and the multimodal payload field on `ClientRequest`. Closes the
 spec-side gap surfaced by the Python SDK's wire-shape contract gate.

#### Fixed

- **`/health` now reports the deployed platform semver.** Previously
 the `version` field returned `1.0.0` on every deployed stack because
 the CloudFormation templates wired `AXONFLOW_VERSION` to the agent
 image tag (`latest`, git SHA, etc.), which failed the semver regex
 in the agent's version resolver. A new dedicated `PlatformVersion`
 CFN parameter with a built-in semver `AllowedPattern` is now wired
 to `AXONFLOW_VERSION` independently of the image tag, and a new
 `VERSION` file at the repo root is the single source of truth read
 by both the build pipeline and the deploy script. A version-
 alignment validator runs on every push.
- **`MCPCheckInputResponse` now emits `decision_id` on the allow path**
 of `POST /api/v1/mcp/check-input` (it was already emitted on every
 deny path). Every governance decision was supposed to surface
 `decision_id` so callers can correlate the decision back to
 the audit log via `/explain/{id}` without a round-trip - the allow
 path silently dropped it. Same fix applied to
 `MCPCheckOutputResponse` (which gains a `decision_id` field) and to
 the MCP-tool variants so plugin-visible shape is consistent across
 HTTP and MCP-tool surfaces.
- **`try.getaxonflow.com` blocks SQL injection again.** Community SaaS
 deployments now pin `SQLI_ACTION=block` on the agent task,
 overriding the v6.2.0+ relaxed default profile that demoted SQLi
 enforcement to `warn`. Configurable per-deploy via the new
 `SqliAction` CFN parameter (`block` / `warn` / `log`, default
 `block`). Takes effect on the next community-saas deployment.
- **`try.getaxonflow.com` plan generation no longer 504s at 60 seconds.**
 The community-saas CFN template's `AlbIdleTimeoutSeconds` parameter
 (default 300) ships pre-set; the next deployment of the running
 stack picks up the 300s idle timeout so long MAP plan-generation
 requests complete without hitting the front-door gateway timeout.
- **`docs/api/agent-api.yaml` and `docs/api/orchestrator-api.yaml` now
 lint clean.** 21 broken `$ref` references to a non-existent `Error`
 schema in `agent-api.yaml` are repointed to the existing
 `ErrorResponse` (same shape both handlers return). Five additional
 broken refs in `orchestrator-api.yaml` are resolved by adding the
 missing `OrgIDQuery` parameter and three EU AI Act conformity
 schemas. Several malformed-example errors and `no-$ref-siblings`
 violations across the two specs are corrected.

#### Documentation

- **SDK telemetry contract: 7-day delivered-heartbeat.** All four SDKs
 follow the same contract: AxonFlow emits at most one anonymous
 heartbeat per environment every 7 days during SDK activity. The
 telemetry contract document is rewritten with the new cadence
 section, per-OS stamp-file specification, and a 9-case heartbeat
 conformance test matrix plus a 4-run cross-process E2E. Plugin
 parity (sibling 7-day-heartbeat at hook-fire time) noted at the
 bottom of the contract, including the deliberate stamp-filename
 split: SDKs use `{sdk}-telemetry-last-sent` while plugins keep the
 legacy `{codex,claude-code,cursor,openclaw}-plugin-telemetry-sent`
 so existing installs preserve their `instance_id` across the
 upgrade.
- **Telemetry opt-out is `AXONFLOW_TELEMETRY=off` everywhere.**
 `DO_NOT_TRACK` is no longer honored as an opt-out across all four
 SDKs and all four plugins. `DO_NOT_TRACK` is commonly inherited from
 host tools and developer environments - host CLIs like Codex and
 Claude Code inject it unconditionally - making it an unreliable
 expression of user intent. Documentation, ADRs, and the README
 callout are updated.
- **Examples and SDK reference docs updated for the v7 majors.**
 Install-command snippets, dependency declarations, getting-started
 guides, tutorials, gateway/proxy guides, compliance pages, MCP audit
 logging, execution tracking, and the configurable-agents reference
 now point at the new SDK majors. Historical "Since vX" references
 are intentionally left as-is - those document when a feature was
 added.

#### CI / Testing

- **Tier-gate contract CI** now runs every PR that touches the agent
 or orchestrator code paths against a fresh docker-compose stack in
 community, evaluation, and enterprise modes, and asserts that each
 guarded endpoint returns the documented status code per tier.
 Catches drift between the published tier matrix and actual handler
 enforcement before merge.
- **OpenAPI validation now covers all three specs.** Previously only
 `policy-api.yaml` was linted in CI; `agent-api.yaml` and
 `orchestrator-api.yaml` were silently exempt and accumulated
 structural defects (broken refs, duplicate schemas, malformed
 examples). The validator now loops over all three specs and runs
 per-spec breaking-change diffs against the base branch.

### Evaluation

- All Community changes apply.
- The plugin-compatibility check, the openapi corrections, and the
 Community-SaaS lifecycle additions all flow through Evaluation
 unchanged. No new Evaluation-tier endpoints, no Evaluation-only
 behaviour changes in this release.

### Enterprise

- All Community + Evaluation changes apply.
- No Enterprise-only behaviour changes in this release. The portal,
 customer-portal-ui, and the rest of the Enterprise tree pick up the
 Community-side fixes (correct `/health` semver, `decision_id` on
 allow, etc.) automatically.

### SDKs

- **Go SDK v7.0.0** - module path advances from `/v6` to `/v7`.
 `DO_NOT_TRACK` is no longer honored; use `AXONFLOW_TELEMETRY=off`.
 Anonymous heartbeat now follows the 7-day-per-environment cadence.
- **Python SDK v7.0.0** - `axonflow>=7.0.0`. `StaticPolicy` and
 `PolicyVersion` now serialize wire fields in snake_case to match
 the OpenAPI spec; camelCase keys still accepted on input via field
 validation aliases so existing consumers keep working - round-trip
 identity is no longer preserved for callers that built models from
 camelCase dicts. `DO_NOT_TRACK` removed; 7-day heartbeat cadence
 shipped.
- **TypeScript SDK v7.0.0** - `@axonflow/sdk@^7.0.0`. `DO_NOT_TRACK`
 removed; 7-day heartbeat cadence shipped.
- **Java SDK v7.0.0** - `<version>7.0.0</version>` on the
 `axonflow-sdk` dependency. `DO_NOT_TRACK` removed; 7-day heartbeat
 cadence shipped.

See each SDK's release notes for the per-language migration shape.

### Plugins

- **OpenClaw v2.0.0** - `npm install @axonflow/openclaw@^2.0.0`.
 `DO_NOT_TRACK` removed; `AXONFLOW_PLUGIN_VERSION_CHECK=off` to skip
 the new platform compatibility check.
- **Claude Code plugin v1.0.0** - graduates from the 0.x line to a
 stable 1.x. `DO_NOT_TRACK` removed.
- **Cursor plugin v1.0.0** - graduates from the 0.x line to a stable
 1.x. `DO_NOT_TRACK` removed.
- **Codex plugin v1.0.0** - graduates from the 0.x line to a stable
 1.x. `DO_NOT_TRACK` removed.

All four plugins query the platform's `/health` at startup, read
`plugin_compatibility.min_plugin_version[<canonical id>]`, and emit a
single upgrade hint to stderr when the runtime version is below the
floor. Below recommended-but-above-min logs an info-level note;
at-or-above recommended is silent. Older platforms that don't
advertise the field degrade silently. Skippable per-plugin via
`AXONFLOW_PLUGIN_VERSION_CHECK=off`.

## [7.4.5] - 2026-04-28 - Phase 1 quality-freeze fixes + MAP execution-tracking org isolation

PATCH: bug fixes only. The headline platform fix is a pair of org-identity propagation bugs in the MAP execution path that made `GET /api/v1/executions` return zero rows for newly-completed plans and let body-supplied identity override the authenticated org/tenant on policy evaluation. The rest is the close-out of the Phase 1 quality-freeze sweep against the bundled examples - every example now compiles, runs, and exits with a clear PASS/FAIL summary against a stock community-mode docker-compose stack.

No breaking changes. No new endpoints, SDK methods, or features.

### Community

#### Fixed

- **`GET /api/v1/executions` returned zero rows for newly-completed MAP plans.** Plans executed via `POST /api/request` with `request_type=execute-plan` were recorded in the execution-tracking store with an empty `org_id`, while the read-side filter (driven by the authenticated org from Basic auth) required a non-empty match - so every MAP plan execution produced a row that was invisible to subsequent list calls. The execution recorder now persists the same authenticated org used for filtering on read, and policy evaluation, plan storage, and replay tracking all read org and tenant from the same authoritative source on every request. A request can no longer be recorded under one org and policy-evaluated under another, even if a caller bypasses the agent and supplies mismatched values directly.
- **MAP examples updated to current SDK releases** - Go 5.8.0, TypeScript 6.1.0, Python 6.8.0, Java 6.1.0 - so `go run`, `npm start`, `python main.py`, and `mvn exec:java` work against the published SDKs on a fresh checkout.
- **`examples/cost-estimation/http/execution-cost-validation.sh`** now exits with a clear PASS/FAIL summary instead of aborting mid-run with exit code 5 when a response is malformed (e.g. on auth failure). The script was rewritten to use the generate-plan → execute-plan → fetch-cost flow that actually surfaces a non-zero plan cost in Community.
- **`examples/risk-tiered-approvals/go`** now compiles from a clean checkout. The directory was missing `go.mod` and `go.sum`, so `go run main.go` failed with `no required module provides package`. The example also referenced an SDK type that was renamed before release; corrected to the published name. Both Go and Python variants now pass end-to-end. Test 3 (HITL queue listing) skips on Community and Evaluation with an accurate message - the queue endpoint is Enterprise-only and was previously mis-labelled.
- **`examples/media-governance-policies/typescript`** Test 4b no longer fails with `tenant_id=undefined`. The TypeScript SDK exposes `MediaGovernanceConfig` fields in camelCase (`tenantId`); the example was asserting on the wire-shape snake_case field. Aligned the assertion and the log line.
- **`examples/audit-logging` (TypeScript and Java)** now match the Python variant's authentication setup so `auditToolCall` succeeds without `Missing authentication` errors.
- **`examples/llm-routing/go`** updated to the current routing API shape so the demo works against a stock stack.
- **`examples/mcp-connectors/cloud-storage`** rewritten to exercise a working S3-compatible flow against the MinIO instance bundled in the docker-compose stack.
- **`examples/.gitignore`** no longer excludes `go.sum`. Every Go example now ships with its lockfile committed so a clean clone runs without needing `go mod tidy`. Two stale `replace` directives in `examples/wcp-retry-idempotency/{community,evaluation}/go/go.mod` (pointing at sibling-checkout SDK paths) and a 0-byte orphan `examples/policies/go/go.mod` were also cleaned up.
- **`examples/policies/http/policies.sh`** Create Custom Policy now sends a valid request body - a single `pattern` regex with a recognized category - instead of an invalid array shape that the platform was rejecting with HTTP 400. The script previously printed "Status: Created" without checking the response, masking the failure.
- **`examples/gateway-policy-config/python`** no longer crashes with `TypeError: get_env missing 1 required positional argument`.
- **`examples/workflow-control/go`** now compiles. `ApproveStep` and `RejectStep` were called with two arguments after the SDK signatures had added a third (approver_id).
- **`examples/hello-world/typescript`** is now a policy-only demo matching the other three SDKs. The Gateway Mode TypeScript example moved to `examples/integrations/gateway-mode/typescript/`.

#### Documentation

- **Python version prerequisite for examples.** `examples/README.md` and a new `examples/retry-semantics/python/README.md` now state that several Python examples require Python 3.10+ and the current `axonflow` PyPI release. The older pinned `axonflow==4.1.0` from earlier examples does not expose retry-policy or lifecycle fields used here and will fail on import or with a missing-attribute error. Users on systems where `python3` defaults to 3.9 (e.g. older macOS) should create a venv on a newer interpreter before running these examples.

## [7.4.4] - 2026-04-25 - `CreateOverrideResponse` schema split

PATCH: documentation-grade correction - no platform behaviour change. Splits the `POST /api/v1/policies/{id}/overrides` create-response shape from the at-rest `PolicyOverride` entity, matching what the platform server has been emitting all along and the precedent established by `CreateWorkflowResponse` (orchestrator-api.yaml). Code-generated clients written against the prior spec would have read `undefined` for the create-time TTL clamping fields (`ttl_seconds`, `requested_ttl`, `clamped`, `clamped_reason`) and looked for at-rest fields (`action_override`, `enabled_override`, `tool_signature`) that the create response doesn't carry.

### Community

#### Fixed

- **`CreateOverrideResponse` schema added** to `docs/api/agent-api.yaml`. The `createStaticPolicyOverride: 201` response now references this dedicated schema instead of the at-rest `PolicyOverride`. Carries `id`, `policy_id`, `policy_type`, `expires_at`, `ttl_seconds`, optional `requested_ttl` / `clamped` / `clamped_reason` (populated when server-side TTL clamping kicked in), and `created_at`. The at-rest `PolicyOverride` schema retains its role on `GET /api/v1/policy-overrides` / `GET /api/v1/policy-overrides/{id}`.

 AxonFlow's hand-written OpenClaw plugin already implements `CreateOverrideResult` matching the actual server shape - this fix aligns the spec with the plugin's reality and unblocks code-generated clients.

## [7.4.3] - 2026-04-25 - Plugin Batch 1 spec corrections

PATCH: documentation-grade corrections - no platform behaviour change. Companion to the 4 plugin wire-shape contract gates landing alongside (parity with the four SDK gates). Auto-resolves the bulk of those plugins' initial baseline drift entries.

### Community

#### Fixed

- **OpenAPI spec corrections - Plugin Batch 1 explainability fields.** Two MCP-response schemas have been stale relative to what the agent has emitted since Plugin Batch 1 shipped. The fix unblocks code-generated clients and auto-resolves baseline drift entries on every AxonFlow plugin's wire-shape contract gate.
 - **`MCPCheckInputResponse`** gains the five Plugin Batch 1 fields the agent has emitted since v7.1.0 (`decision_id`, `risk_level`, `policy_matches`, `override_available`, `override_existing_id`).
 - **`MCPCheckOutputResponse`** gains `redacted_message` (text-redaction counterpart to `redacted_data`), `decision_id`, and `policy_matches`.
 - **`ExplainPolicy`**, **`ExplainRule`**, **`DecisionExplanation`** schemas added - these are the explainability shapes returned by the `explain_decision` MCP tool. Hand-written SDKs and plugins are already aligned with what the agent emits; this just documents the wire contract.

## [7.4.2] - 2026-04-25 - OpenAPI spec corrections

PATCH: documentation-grade corrections - no platform behavior change.
Two OpenAPI schemas were stale relative to what the server has been
emitting. Code-generated clients written against the prior spec would
have read `undefined` for the affected fields. AxonFlow's hand-written
SDKs (TS, Python, Go, Java) are correct against the server and gain
no functional change from this release; the fix lives entirely in the
spec artefacts.

### Community

#### Fixed

- **`AISystemRegistry.materiality` → `materiality_classification`**
 in `docs/api/masfeat-api.yaml`. Server has emitted
 `materiality_classification` since the 3-dimensional risk rating
 refactor for MAS AI Risk Management Guidelines 2025.
- **`DynamicPolicyInfo`** in `docs/api/agent-api.yaml` rewritten from
 8 aspirational fields to the 4 actual server fields
 (`policies_evaluated`, `matched_policies`, `orchestrator_reachable`,
 `processing_time_ms`).

## [7.4.1] - 2026-04-23 - Portal HITL + audit trail fixes

PATCH: portal-visible bugs fixed around human approval visibility -
approver identity on the execution timeline, Compliance Summary card
aggregates, HITL audit trail row emission, workflow-level aborted
status propagation, stale-snapshot reconciliation for pre-patch
workflows, and a sidebar badge refresh on approve/reject. Platform-only
release - no SDK or plugin changes. All fixes hit the same HITL audit
and approval visibility story so operators can answer "who approved
what, when, and did the compliance summary count it?" without joining
three tables.

### Community

#### Fixed

- **Unified execution step now distinguishes approver from rejector.**
 The unified execution API (`/api/v1/unified/executions/{id}`)
 populated `approved_by` with the rejector's email on rejected steps
 because the serializer projected `workflow_steps.approved_by`
 verbatim regardless of terminal state. The step serializer now
 splits into `approved_by` / `approved_at` on the approval path and
 `rejected_by` / `rejected_at` on the rejection path, mirroring the
 split already done by `workflow_control.ProjectStepGateToHTTP` on
 the WCP HTTP response. `execution.StepStatus` gains two new fields
 (`RejectedBy`, `RejectedAt`).
- **`/api/v1/audit/summary` returns six card-view aggregates.** The
 response previously emitted `total_events` / `by_severity` /
 `by_action` / `top_policies` / `compliance_score` - the handler
 now additionally computes and returns `total_requests`,
 `allowed_requests`, `blocked_requests`, `modified_requests`,
 `block_rate_percent`, `avg_latency_ms`. Legacy fields retained for
 back-compat. Block rate is derived from the allowed/blocked/modified
 counts; average latency is a separate query over `response_time_ms`
 excluding rows where latency wasn't measured (HITL decisions,
 workflow-lifecycle events).
- **Compliance Summary arithmetic always closes.** The summary
 handler previously only counted `allowed` / `blocked` / `redacted`
 decisions explicitly; `pending_approval` (from `workflow_step_gate`
 rows where HITL fires require_approval) and `error` decisions were
 dropped between the buckets, so `total_requests` could exceed
 `allowed_requests + blocked_requests + modified_requests` by the
 number of orphan rows. Now every non-blocked, non-redacted decision
 rolls into Allowed - Total = Allowed + Blocked + Modified is
 always true. `pending_approval` counts as allowed because the
 policy didn't block; the subsequent human decision writes its own
 `workflow_step_approved` / `workflow_step_rejected` row.
- **Historical workflows decided before v7.4.1 deployed now render
 their terminal approval state.** The unified-execution cache was
 written at `/gate` time (approval_status=pending) and pre-v7.4.1
 approve/reject paths did not re-sync it - so any workflow decided
 before the fix deployed would forever show "Approval: pending" on
 the execution API. `GetWorkflowStatus` now reconciles cached step
 snapshots against current `workflow_steps` state on every read via
 a new `reconcileStepApprovals` helper. Steps present in the cache
 but absent from the fresh rows are left untouched so partial WCP
 state can't clobber the cache; WCP fetch failure falls back to the
 cached snapshot.

### Evaluation

#### Fixed

- **WCP step approve + reject now emit rows in `audit_logs`.** The
 WCP step-approve/reject endpoints
 (`/api/v1/workflows/{id}/steps/{step_id}/approve|reject`, Evaluation+)
 previously updated `workflow_steps.approval_status` and fired a
 webhook but never wrote to `audit_logs`, so any audit pipeline that
 reads `audit_logs` had no trace of approvals or rejections - rejected
 steps never appeared as "Blocked" rows, compliance summaries ignored
 the events, and operator dashboards showed "N/A" under user. Both
 paths now write an `audit_logs` row via the existing
 `WorkflowAuditEntry` pipeline with `request_type="workflow_step_approved"`
 / `"workflow_step_rejected"`, `policy_decision="allowed"` on approve
 / `"blocked"` on reject, and the reviewer's `X-User-Email` populated
 on `user_email`. `WorkflowAuditEntry` gains `UserEmail` / `UserRole`
 so reviewer identity carries through the audit adapter end-to-end.
- **Reject propagates the aborted status to the unified execution
 tracker.** `RejectStep` flipped `workflow_steps.approval_status`
 and called `repo.Abort(.)` on the workflow, but never notified
 `executionTracker.OnWorkflowAborted(.)`. `GetWorkflowStatus`
 prefers the cached unified execution when one exists, so
 `/api/v1/unified/executions/{id}` kept reporting the overall
 execution as running/pending even though the rejection had already
 aborted the workflow. Now calls `OnWorkflowAborted` after the abort
 succeeds - only when the abort actually landed, so we don't lie
 about workflow state on an abort failure.

### Enterprise

#### Fixed

- **HITL queue approve + reject now emit rows in `audit_logs`.** The
 Enterprise HITL queue endpoints
 (`/api/v1/hitl/queue/{id}/approve|reject`) previously wrote only to
 `hitl_approval_history` (the immutable compliance audit trail), so
 the audit-logs-based portal audit page had no trace of queue-driven
 approvals/rejections - the USER / TENANT column showed "N/A" and
 rejections never appeared as "Blocked" rows. Both paths now write
 an `audit_logs` row via a new `Repository.WriteHITLAuditEvent`
 helper with `request_type="workflow_step_gate"`,
 `policy_decision="allowed"` on approve / `"blocked"` on reject,
 the reviewer's email and role populated, and `workflow_id` /
 `step_id` / `request_id` / `policy_name` in `policy_details`. Write
 is best-effort - a DB failure does not fail the mutation because
 `hitl_approval_history` remains the authoritative record.
- **Portal execution timeline renders rejector identity correctly.**
 The portal execution page already read `approved_by` and
 `rejected_by` as separate fields, but the Community-side serializer
 only populated `approved_by` - so a rejected step appeared as
 "approved by \<rejector\>". Paired with the Community-side split
 above, the timeline now renders "Approval: rejected by \<email\>
 on \<date\>" when `approval_status=rejected` and the approved
 variant when approved, suppressing the other field in each case.
 `ExecutionStep` on the portal API client gains `rejected_by` /
 `rejected_at`.
- **Sidebar approvals badge refreshes immediately after approve or
 reject in the same tab.** The Navigation component polls
 `getPendingApprovals` every 30 s. When a reviewer approved or
 rejected from the side panel, the approvals list removed the row
 optimistically but the `1` badge next to "Approvals" in the sidebar
 lingered until the next poll - visually making the queue look
 unreclaimed. The approvals page now dispatches an
 `approvals:updated` CustomEvent on success; Navigation listens and
 re-fetches immediately. Event listener cleaned up on unmount
 alongside the polling interval. Cross-tab approvals (second browser
 window, SDK, or CLI) still fall back to the 30 s poll - same-tab
 only is the scope of this fix.

---

## [7.4.0] - 2026-04-22 - HITL Response Parity

MINOR: both HITL planes now return the same rich response shape, MAP's
plan-scoped approve/reject endpoints are now available at **Evaluation** tier
(previously Enterprise-only), and MAP gains a plane-scoped pending-approvals
listing symmetric with the existing WCP endpoint. `decision` resolves to
`"allow"` / `"block"` once the mutation lands, `retry_context` mirrors the
gate response retry state, approver metadata comes from the same persisted
row, `approval_id` surfaces the HITL queue entry UUID, and `policies_matched`
reconstructs the governance trail. Contract tests in CI lock the two planes'
response shapes together so future additions surface on both endpoints by
default - both for approve/reject and for the plane-scoped pending listings.

No breaking changes. Purely additive - the legacy `workflow_id` / `step_id` /
`status` / `approval_status` / `approved_by` / `message` fields existing
callers rely on are unchanged.

### Community

#### Added

- **Shared HITL response projection helper** in the community codebase -
 `workflow_control.ProjectStepGateToHTTP` and `DeriveHITLApprovalID`. Both
 planes' handlers use it, so the wire shape stays consistent and the
 deterministic HITL queue UUID reappears on every response where the
 backing workflow_steps row exists.
- **Plan-to-workflow lookup** - `GetWorkflowByPlanID` service method +
 PostgreSQL repository implementation (index on `metadata->>'plan_id'`).
 Enables plan-scoped HITL endpoints to project from the same
 `workflow_steps` row that /gate and /complete use.

#### Deprecated

- `DO_NOT_TRACK=1` as an AxonFlow SDK telemetry opt-out - scheduled for
 removal after 2026-05-05 in the next major release. Use
 `AXONFLOW_TELEMETRY=off` instead. All 4 SDKs emit a one-line migration
 warning when `DO_NOT_TRACK=1` is the active control and
 `AXONFLOW_TELEMETRY=off` is not also set. See the SDK CHANGELOGs for
 per-language notes.

### Evaluation

#### Added

- **Rich WCP approve/reject responses.** `POST /api/v1/workflows/{id}/steps/{step_id}/approve`
 and `./reject` now return `decision`, `reason`, `retry_context`,
 `approval_id`, `approved_by` / `approved_at` (or `rejected_by` /
 `rejected_at`), `policies_matched`, `status`, and `message`. Documented
 in OpenAPI as `ApprovalResponse`; mirrors the step-gate response field set.
- **Rich MAP approve/reject responses** at the `/api/v1/plans/{id}/steps/{step_id}/approve|reject`
 endpoints. Same shape as WCP plus a `plan_id` field. Two underlying flows -
 confirm/step mode (WCP-backed) and legacy policy-driven pause/resume -
 now surface a uniform shape so clients don't branch on which mode the
 plan ran in.
- **Plane-scoped pending-approvals listing** - new
 `GET /api/v1/plans/approvals/pending` endpoint (Evaluation+), the MAP
 counterpart of the existing `GET /api/v1/workflows/approvals/pending`.
 Returns `{pending_approvals, count}` with every entry carrying `plan_id`
 (populated from `workflows.metadata->>'plan_id'`). Optional `?plan_id=`
 query param scopes the listing to a single plan so reviewer tools can
 render per-plan context without filtering client-side. Tier-gated on
 `IsHITLApprovalEnabled` - same gate as the plane-scoped approve/reject.

#### Changed

- **MAP plan-scoped HITL tier gate lowered to Evaluation+** (was Enterprise-only
 pre-v7.4.0). Tier check now matches WCP: community + Evaluation license →
 accepted; community + no license → 403; enterprise mode → accepted. Error
 message updated from "requires Enterprise license" to "requires Evaluation
 or Enterprise license."
- **Cross-plane contract test** in CI asserts the WCP and MAP response field
 sets stay aligned modulo the intentional `plan_id` asymmetry. Guards
 against silent future drift when either plane grows a new field. A sibling
 `TestPendingApprovalsPlaneParity` does the same for the plane-scoped
 pending-approvals listings - the intentional `plan_id` asymmetry is
 enforced: populated on every MAP entry, never on WCP entries.

### SDKs

- **Go SDK v5.6.0** - `ApproveStepResponse` / `RejectStepResponse` gain
 `Decision`, `Reason`, `ApprovalStatus`, `ApprovalID`, `ApprovedBy` /
 `ApprovedAt` / `RejectedBy` / `RejectedAt`, `PoliciesMatched`,
 `RetryContext`, `Message`, `PlanID`. New `GetPendingPlanApprovals` method
 covers the MAP-plane listing. `PendingApproval` extended with `PlanID`,
 `StepIndex`, `Decision`, `DecisionReason`, `PoliciesMatched`, `StepInput`,
 `ApprovalStatus`. Also fixes three pre-existing URL bugs on
 `ApproveStep` / `RejectStep` / `GetPendingApprovals` (they were hitting
 non-existent `/api/v1/workflow-control/` paths) and renames the response
 wire shape to match the server (`PendingApprovals` / `Count`).
- **TypeScript SDK v5.6.0** - same rich fields on `ApproveStepResponse` /
 `RejectStepResponse` interfaces, new `getPendingPlanApprovals`, extended
 `PendingApproval` interface, and the same WCP URL / response-shape fixes.
- **Python SDK v6.6.0** - rich optional fields on the pydantic
 `ApproveStepResponse` / `RejectStepResponse` models, new
 `get_pending_plan_approvals` method (sync wrapper included), extended
 `PendingApproval` model, and the same WCP URL / response-shape fixes.
- **Java SDK v5.7.0** - rich fields on `WorkflowTypes.ApproveStepResponse`
 and `.RejectStepResponse`, plus back-compat 3-arg constructors so existing
 test fixtures keep compiling. New `getPendingPlanApprovals` + async
 variant. Extended `PendingApproval` class with back-compat 6-arg
 constructor. Same WCP URL / response-getter fixes.

---

## [7.3.0] - 2026-04-21 - Retry Semantics & Idempotency

MINOR: first-class retry and idempotency surfaces on the Workflow Control
Plane. The `cached: bool` signal every gate response has been returning is
now a deprecated alias - responses carry a `retry_context` block that
answers "how many gate calls?", "did any prior attempt complete?", and
"what was the prior decision?" unambiguously. A new caller-supplied
`idempotency_key` on gate + complete anchors a workflow step to a
business-level identity (payment intent, invoice, claim reference), with
strict match validation between the two endpoints.

No breaking changes. Purely additive.

### Community

#### Added

- **`retry_context` on every `StepGateResponse`** - always present, including
 on the first gate call (where counters are 1/0 and
 `prior_completion_status` is `"none"`). Fields: `gate_count`,
 `completion_count`, `prior_completion_status` (enum `none` / `completed` /
 `gated_not_completed`), `prior_output_available`, `prior_output`,
 `prior_completion_at`, `first_attempt_at`, `last_attempt_at`,
 `last_decision`, `idempotency_key`. Counter bookkeeping is atomic inside
 the repository UPSERT; a separate cached-hit update keeps counters
 accurate across idempotent retries without re-evaluating policy.
- **`?include_prior_output=true` query param on `/gate`** - opt-in inclusion
 of the prior `/complete` payload in `retry_context.prior_output`. Default
 is `false` (null) because output may be large and/or contain sensitive
 data. When the opt-in is set AND a prior completion exists, the full
 output is returned so agents can safely short-circuit re-execution.
- **Caller-supplied `idempotency_key` on `/gate` and `/complete`** -
 optional opaque string up to 255 chars. Recorded on the first gate call
 that sets it; immutable for the step's lifetime. Surfaced on every
 subsequent `retry_context.idempotency_key`. Audit log records the key
 on every `step_gate` and `step_completed` event.
- **`HTTP 409 IDEMPOTENCY_KEY_MISMATCH`** returned when `/complete` (or a
 subsequent `/gate`) passes a different key than the one recorded on the
 first gate, or when one side supplies a key and the other omits it.
 Response envelope includes `expected_idempotency_key` and
 `received_idempotency_key` so SDKs can build typed errors.
- **`cached` and `decision_source` fields remain on every response** so
 existing SDK versions continue working unchanged. Both are marked
 deprecated in the wire docs; `retry_context.gate_count > 1` replaces
 `cached: true` and `retry_context.prior_completion_status` replaces the
 string-typed `decision_source`.

#### Changed

- **`MarkStepCompleted` HTTP handler** now reads tenant identity from
 `X-Tenant-ID` consistently with `StepGate` rather than from
 `X-Client-ID`. A real multi-tenant caller setting the tenant header now
 works on both endpoints; previously the complete path rejected the
 request as "workflow not found" because the isolation check compared
 against the wrong attribute. No behavior change for callers using
 empty headers.

### Evaluation

#### Added

- **Retry-aware dynamic policy conditions** - the policy engine now
 resolves seven new `step.*` fields: `step.gate_count`,
 `step.completion_count`, `step.prior_completion_status` (enum `none` /
 `completed` / `gated_not_completed`), `step.prior_output_available`,
 `step.last_decision`, `step.first_attempt_age_seconds`, and
 `step.idempotency_key`. Policy authors can write rules like
 "retry on un-completed payment requires approval", "more than three
 attempts = block", or "rapid retry within 30 seconds escalates severity"
 without custom code. These fields are added to `ValidPolicyFields` so
 the create/update policy APIs accept them.
- **Tier-gated create:** attempting to author a dynamic policy with any
 `step.*` condition on a Community license is rejected at create time
 with `FEATURE_REQUIRES_EVALUATION_LICENSE`. Evaluation and Enterprise
 tiers accept. Enforcement sits in `PolicyService.validateTierForCreate`
 before the tenant policy-count check, so the rejection fires cleanly
 without a DB roundtrip.
- **UX note for policy authors:** retry-aware policies only fire when
 callers pass `retry_policy: "reevaluate"` on subsequent `/gate` calls.
 Default-idempotent retries hit the cache and bypass the policy engine,
 consistent with the existing cache semantics. Documented in the
 bundled Evaluation-tier example.

### Enterprise

No Enterprise-exclusive additions in this release. Cross-workflow
idempotency lookup, windowed operators like `idempotency_key_seen_within`,
retry-pattern correlation across workflows, and compliance-grade
audit/reporting for duplicate prevention are on the roadmap for a
later release.

---

## [7.2.1] - 2026-04-21

PATCH: surface the HITL approval metadata that was already being captured
internally but dropped on the way out of the API. No schema changes, no
breaking changes - callers that previously handled `null` simply start
seeing real values.

### Community

#### Fixed

- **`/api/v1/workflows/{id}` now surfaces `approved_by` and `approved_at` on
 each step.** The `StepInfo` DTO used by the workflow-detail response was
 missing both fields, so callers polling for approval completion saw
 `approval_status: "approved"` but no approver identity or timestamp.
 Both fields were already captured by `ApproveStep` and persisted on the
 `WorkflowStep` row - the DTO just wasn't copying them over. Portal and
 SDK consumers now get the full provenance without a second round-trip
 to the audit log.
- **`StepGateResponse.approval_id` populated on `require_approval`
 decisions.** The HITL adapter was creating the approval queue entry and
 setting `StepGateEvaluation.ApprovalID`, but the API response struct
 didn't carry the field. SDK clients that want to correlate a paused
 step with its HITL queue row (for Slack/PagerDuty routing, direct
 portal deep-links, or programmatic approval) now get `approval_id` on
 the same response that reports the `require_approval` decision.

### Enterprise

#### Fixed

- **Customer Portal `/approvals` page no longer crashes on expand.** The
 `PendingApproval.policies_matched` TypeScript type declared the field
 as `string[]`, but the `/api/v1/workflows/approvals/pending` endpoint
 returns an array of `PolicyMatch` objects (`{policy_id, policy_name,
 action, risk_level, allow_override, policy_description}`). React
 tried to render the object directly and threw error #31 ("Objects
 are not valid as a React child"), dumping the approver into the
 ErrorBoundary fallback the moment they clicked a row to expand the
 detail panel. The approvals page now accepts either shape, extracts
 `policy_name` when given an object, and surfaces `policy_description`
 as a tooltip on the matched-policy chip.

---

## [7.2.0] - 2026-04-20 - The Bug Bash Bonanza 🪲🔨

A focused hardening release: a full sweep across the Customer Portal
HTTP surface, tenant-scope fail-closed enforcement on every
read-and-action endpoint, three new public platform knobs for the
MAP plan-execution budget, dedicated HTTP examples for every route
the Portal calls, a login-endpoint fix that closes an
org-enumeration leak via both response body and timing, and fixes
to make MAP plans run the full 5 minutes the server is happy to
give them. MINOR per semver - additive surface only; every 7.1.x
caller keeps working without changes.

### Added

#### Community

- **`AXONFLOW_MAP_MAX_TIMEOUT_SECONDS` orchestrator env.** Caps the
 MAP plan-execution budget without a binary rebuild. Clamped to
 60..1800 seconds; default 300. The effective value is logged at
 startup when non-default. If you front the orchestrator with a
 reverse proxy or load balancer, set its idle / read timeout to
 at least the orchestrator cap - otherwise long plans will be
 cut off at the proxy before the orchestrator finishes.

#### Enterprise

- **`AlbIdleTimeoutSeconds` CloudFormation parameter on the
 AWS Marketplace template.** Mirror of the Community knob.
- **`middleware.MaxBodyBytesMiddleware` exported on the Customer
 Portal.** Caps every POST/PUT/PATCH request body at 1 MiB by
 default; `MaxBodyBytesMiddlewareWithLimit(n int64)` returns a
 variant for routes that legitimately need a larger ceiling (SAML
 metadata, future file uploads). GET/HEAD are not wrapped.
- **Per-feature HTTP examples for every route the Portal UI
 calls.** Each example is runnable against a local Docker Compose
 stack and covers one topic end-to-end:
 - Full RBI AI-system lifecycle: register → validate → incident
 → kill-switch → board report → audit export.
 - SEBI dashboard, retention, readiness, and audit export.
 - EU AI Act conformity, accuracy/bias, and async export jobs.
 - Compliance evidence bundle (summary + stream-download).
 - Decision explainability with the cross-tenant 404 guard
 asserted.
 - License, deployment, nodes, and session metadata.
 - Policy bundle export/import with `overwrite_mode` semantics.
 - Full `/api/v1/auth/*` walkthrough: login, session, logout,
 SSO availability, forgot-password, reset-password,
 change-password - including the auth-enum identical-body
 assertions.
 A curl-based smoke runner covers every Portal API route (44
 total) without needing a browser, pairing with the Playwright
 health spec so CI and demo-freeze runs have a Playwright-free
 verification path. Every script passes `shellcheck` and runs
 green against local compose.
- **Compliance → Evidence Export Download button.** The Compliance
 page showed per-type record counts (audit logs, workflow steps,
 HITL approvals) but had no way to actually download the bundle.
 Added a Download Evidence button that streams the JSON bundle as
 a blob with a 30-day default window (the backend caps by tier)
 and saves as `axonflow-evidence-<start>-to-<end>.json`. Disabled
 with a tooltip explanation when counts are zero. Surfaces any
 backend error (tier / license / quota) as an inline alert
 instead of silently doing nothing.

### Fixed

#### Community

- **Agent now proxies `/api/v1/euaiact/*` to the orchestrator.**
 The single-entry-point mux listed `/rbi`, `/sebi`, and
 `/masfeat` alongside the rest of the compliance family but
 omitted `/euaiact`, so every EU AI Act call that landed on the
 front-door ALB returned `404 page not found` and the Portal's
 Compliance page reported the module as "not enabled for this
 tenant" even though peer modules rendered fine. Added the prefix
 to both the router and the proxy-allow-list.
- **Canonical `/api/v1/policy-overrides` alias on the agent.** The
 Portal's overrides handler proxies to this path, matching the
 `policy-categories` / `static-policies` / `dynamic-policies`
 naming pattern; the agent previously only exposed the tenant
 override list under `/api/v1/static-policies/overrides`.
 Callers using the canonical path hit 404 and the Portal's
 Policies → Overrides tab rendered empty. Same handler, new
 path, auth unchanged.
- **Agent `/health` includes `tier`.** The validated license tier
 (`Community` / `Evaluation` / `Professional` / `Enterprise` /
 `starting`) is now surfaced on the health response. Operators
 querying `curl /health | jq.tier` used to get `"unknown"`
 because the field was not present.
- **Orchestrator MAP plan-execution budget now caps at 300s by
 default.** MAP plans chain multiple LLM calls (~15s each); a
 typical 5-step plan routinely ran past the old 60s server-side
 default and truncated mid-stream even though the orchestrator
 was still working. The cap is now 300s out of the box and
 tunable via `AXONFLOW_MAP_MAX_TIMEOUT_SECONDS`. SDK note: the
 TypeScript SDK's default `mapTimeout` is 120s; clients relying
 on the default will cut off at 120s before the server cap
 takes effect. Pass `mapTimeout: 300000` on the SDK client
 config to match.
- **Orchestrator policy type allowlist accepts `context_aware`.**
 Three seeded system policies (Tenant Isolation, Debug Mode
 Restriction, Sensitive Data Control) ship with
 `policy_type=context_aware`; any update through
 `PUT /api/v1/policies/{id}` returned 400 because that type was
 missing from the allowlist.
- **`POST /api/v1/policies/{id}/overrides` accepts
 `require_approval` (HITL).** The override validator's allow-list
 was hand-written as `{block, redact, warn, log}`, silently
 dropping the HITL action even though the rest of the stack
 accepted it end-to-end. Standardised on a single canonical list
 of valid actions:
 - Policy authoring - `alert`, `block`, `log`, `modify_risk`,
 `redact`, `require_approval`, `route`, `warn`.
 - Override endpoint (terminal-action subset) - `block`,
 `require_approval`, `redact`, `warn`, `log`. Authoring-only
 actions are deliberately excluded - they have no
 terminal-action meaning and the agent's override repository
 would reject them anyway.
- **Test / Edit / Delete / Versions of legacy-named policies no
 longer 400.** The policy-ID validator only accepted UUIDs and
 the `sys_*` prefix, so seeded policies like
 `sensitive_data_control` and `tenant_isolation` failed every
 per-policy action with "Invalid policy ID format". Allowlist now
 also accepts the legacy snake-case form.
- **`GET /api/v1/policies` honours the `tier` and `category` query
 params.** The orchestrator's list handler dropped both at the
 handler boundary even though the repo supported them. Without
 this every Tier / Category dropdown in the Portal's
 `/policies` page returned the full unfiltered list.
- **Legacy V1 HMAC license format purged from active code.** The
 V2 Ed25519 format has been the only accepted key for months;
 stale HMAC references would have produced confusing failures
 in a clean shell. The rejection-path code that returns `"V1
 license format no longer supported"` is kept so an old key
 ever surfacing gets a clear error, not silent acceptance.

#### Enterprise

- **RBI FREE-AI: registering an AI system no longer 500s.** The
 repository's INSERT listed `board_approval_required`, but that
 column is a stored-generated column computed from
 `risk_category`. PostgreSQL rejected every write with
 `cannot insert a non-DEFAULT value into column
 board_approval_required`, so the Portal's RBI compliance page
 could never progress past step 1. Removed the column from the
 INSERT and UPDATE statements; the Go struct field is still
 populated at read time.
- **RBI FREE-AI: generating a board report no longer 500s.** The
 service layer set `generation_method = "automated"` but the
 database check constraint only accepts `'automatic'` or
 `'manual'`. Fixed the literal.
- **Marketplace CloudFormation: Agent security group can reach the
 Customer Portal.** Per the single-entry-point architecture,
 every public request funnels through the Agent, which then
 proxies `/api/v1/auth/*`, `/api/v1/portal/*`,
 `/api/v1/code-governance/*`, and `/api/v1/git-providers/*` to
 the Customer Portal over Cloud Map. The security group allowed
 ALB → Portal and Portal → Agent but nothing allowed Agent →
 Portal, so every auth call hitting the raw stack domain timed
 out after 30 seconds and fell back to `503 Backend service
 unavailable`. The vanity-domain host-header rule routed
 directly to the UI and masked the issue during demo prep; only
 requests on the raw stack domain surfaced it. Applies on
 `update-stack` without recycling ECS tasks.
- **Usage & Billing no longer returns zeros for every tenant.**
 The daily rollup was defined but never invoked - no scheduler,
 no goroutine, no on-demand call - so the rollup table stayed
 empty forever and the Portal's summary and time-series queries
 returned zeros even when the underlying events had rows. The
 aggregator is now idempotent (re-running an overlapping window
 recomputes the bucket rather than adding to it) and is called
 on-demand from the Usage handlers before they query the
 rollup - self-healing, no scheduler required. A pre-existing
 latent bug that surfaced once rollups populated
 (`COALESCE(AVG)` returns numeric, the scan target was int)
 is fixed in the same change.
- **`GET /api/v1/export/usage` no longer 500s.** The handler
 queried columns that didn't exist (`policy_id`, `latency_ms`,
 `success` - the real columns are `policy_decision`,
 `response_time_ms`, and a derived success flag), constructed
 `INTERVAL '$2 days'` which is not valid PostgreSQL
 parameterization (the `$2` inside a string literal is treated
 as literal characters, not a placeholder), and ignored the
 `start` / `end` query params the UI sends (only honouring a
 legacy `days=` param). Rewritten against the per-request
 metering table with correct columns, proper date-range handling
 for RFC3339 timestamps or `YYYY-MM-DD` dates, and surfaced DB
 errors in the server log instead of swallowing them behind the
 generic `"Database error"` response.
- **`GET /api/v1/license/status` no longer 500s for orgs without
 an `expires_at`.** The handler scanned the column into a
 non-nullable type; NULL expiry blew up inside `Scan`. Switched
 to a nullable target and treats NULL as ACTIVE.
- **`GET /api/v1/admin/organizations/{id}` no longer 500s.** The
 join against the SSO configuration table used the wrong join
 column; every org detail page 500'd with `pq: column
 s.org_id does not exist`.
- **Admin org list queries fixed against the heartbeat schema.**
 Both the list and detail endpoints joined `agent_heartbeats` on
 column names that don't exist (`organization_id`,
 `last_heartbeat_at`); the real columns are `org_id` and
 `last_heartbeat`. Both endpoints returned 500 with
 `pq: column "organization_id" does not exist`.
- **Customer Portal Docker image builds with the Enterprise Go
 tag.** The Portal Dockerfile previously hard-coded a Community
 build, so `license.GenerateLicenseKey` always returned the
 Community stub and admin onboarding 500'd on every call,
 leaving the orgs table empty and the SaaS deployment with no
 orgs to log in as.
- **Dashboard "Workflows Run" counts MAP plans too.** The
 dashboard summary queried the WCP-only execution endpoint, so
 MAP-only tenants saw `Workflows Run: 0` even after running
 plans. Now queries the cross-type unified executions endpoint
 with a fallback to the legacy shape for older server builds.
- **Dashboard no longer renders "Welcome," with an empty name.**
 The page mounted before `AuthContext.checkSession` resolved,
 so the heading printed "Welcome," and the License Status card
 printed an empty Organization ID. The dashboard now waits on
 the session-loading gate.
- **Sidebar pending-approvals badge no longer fires a console
 401 on first paint.** The poll fired from a `useEffect` on
 mount without a user guard; on a hard refresh the first poll
 raced the session check and hit the catch-all orchestrator
 proxy without an authenticated session. The poll now waits
 for the user to be non-null and re-runs when the user
 changes.
- **`setup-vanity-domain` workflow overwrites stale CFN-managed
 ALB private-DNS aliases.** When a stack is rebuilt the old ALB
 DNS goes away; the workflow used to refuse to touch the
 existing record, leaving the Portal UI's API backend URL
 resolving to a deleted ALB inside the VPC - surfaced as 503
 "Backend service unavailable" on the login page. The workflow
 now upserts when the existing target matches the CFN naming
 pattern, and continues to skip operator-managed records.
- **Policy editor accepts `context_aware` and exposes
 `require_approval`.** Mirrors the orchestrator allowlist change
 above; users can now author HITL policies end-to-end without
 the request-level 400 that previously dropped the action at
 the Portal boundary.
- **Policy modal interactions no longer swallowed by the
 backdrop.** A CSS stacking-context bug made Save Changes,
 Cancel, and every form input unclickable; the Edit-policy
 flow looked broken. Promoted the dialog content to a higher
 z-index.
- **Modal form inputs readable in OS dark mode.** A leftover
 `prefers-color-scheme: dark` block from the create-next-app
 template repointed form text to near-white over a hardcoded
 white modal, so field values looked empty. The block is
 removed and native controls (checkboxes, scrollbars) now
 follow the light color scheme.
- **`/export` page no longer logs a React hydration error.** The
 date-range hint rendered `new Date.toLocaleDateString`
 directly in JSX, producing different output on the SSR pass
 vs the client. Deferred the dates behind a `mounted` flag.
- **`POST /api/v1/admin/onboard-customer` accepts an optional
 `license_key`.** Lets operators register an org against an
 already-minted license (Lambda bootstrap, key-rotation
 scripts, existing SDK customers) without forcing the Portal
 to re-key. When set, in-process generation is skipped and
 the existing Secrets Manager entry is left untouched.
- **Marketplace CloudFormation: orchestrator connector secrets
 resolve under the per-stack environment name.** Fourteen
 connector secret paths used the wrong path component; on any
 non-default stack every connector came up with empty
 credentials. The `TaskExecutionRole` IAM grant now matches
 the per-stack path as well, with an `AllowedPattern` on
 `EnvironmentName` so typos fail at `CreateChangeSet` time
 rather than at runtime.

### Security

#### Community

- **Internal-service auth no longer accepts a static fallback
 token in non-Community deployments.** When the
 internal-service secret was unset, the agent fell through to
 a literal-string compare against a constant. Any caller
 knowing that constant could supply internal-service headers
 and impersonate the orchestrator, injecting arbitrary
 `X-Tenant-ID` / `X-Org-ID` for cross-tenant access. The
 fallback path is now gated to Community / Community-SaaS
 modes only; outside those a one-time security warning is
 logged at startup. HMAC and legacy plain-secret paths are
 unchanged.
- **Orchestrator audit handler fails closed when proxy auth is
 missing in non-Community deployments.** The handler
 previously skipped the proxy-auth validation entirely when
 the token validator was nil - the same misconfiguration
 shape that enabled the agent fallback bypass above. An
 attacker reaching the orchestrator directly could spoof
 `X-Org-ID` for cross-tenant audit attribution. The handler
 now returns 403 if the validator is nil and the deployment
 mode is not Community.
- **`GET /api/v1/decisions/{id}/explain` filters tenant in the
 SELECT clause.** The handler used to look up the audit entry
 by `decision_id` only and post-check the tenant; the
 short-circuit on email failed open whenever the user-email
 column was NULL, and the email check itself was bypassable
 by an attacker who happened to share an email with the
 decision owner across tenants. Now: `X-Tenant-ID` is
 required, the SELECT binds on `(decisionID, callerTenant)`,
 and cross-tenant requests return 404 (not 403) so the
 response shape doesn't leak whether `decision_id` exists in
 another tenant. The post-fetch tenant comparison is kept as
 defense-in-depth.
- **`POST /api/v1/evidence/export` and `GET /api/v1/evidence/summary`
 fail closed when the tenant scope is missing.** Both endpoints
 previously fell back to an empty-string tenant when neither
 `X-Tenant-ID` nor a context-stored `tenant_id` was set, then
 ran SQL with `WHERE tenant_id = ''` - zero rows in practice
 but silently burned a daily-export quota slot for an empty
 bucket and would have leaked data the moment a downstream
 query stopped filtering. Both now return 401
 `TENANT_REQUIRED` when neither source provides a scope.
- **`POST /api/v1/policies/simulate` and
 `POST /api/v1/policies/{id}/impact-report` adopt the same
 fail-closed tenant resolution.** Same header-then-context-
 then-fall-through-to-empty pattern as evidence/export; would
 have shared a global empty-tenant rate-limit bucket when
 called without `X-Tenant-ID`.
- **`POST /api/v1/cost/estimate` and
 `GET /api/v1/plans/{id}/cost` reject anonymous callers.**
 Both substituted a `"_default"` literal for an empty
 `X-Tenant-ID`, so every unauthenticated caller drained the
 same daily quota. Both now return 401 `TENANT_REQUIRED`.
- **`GET /api/v1/audit/tenant/{tenant_id}` requires
 `X-Tenant-ID`.** The URL-vs-session tenant mismatch check
 was gated on a non-empty session tenant, so omitting the
 header bypassed the cross-check entirely. The header is now
 required; mismatches still return 403.
- **`/api/v1/audit/search` enforces tenant scoping from the
 trusted header.** The handler ignored the proxy-injected
 tenant header and only filtered on caller-supplied criteria,
 so a Portal user for tenant A could read tenant B's audit
 logs by POSTing to `/api/v1/audit/search`. The header is now
 required and decoded into a JSON-tag-ignored field so a
 malicious payload cannot override it. The same path also
 silently-disabled tenant filtering on
 `/api/v1/audit/tenant/{id}` because the tenant-only struct
 shape no longer matched after a `StartTime` field was added;
 the new SQL filter fixes that too.
- **`/api/v1/audit/tenant/{tenant_id}` rejects URL paths that
 don't match the session tenant.** Without the cross-check a
 Portal user for tenant A could read tenant B's audit history
 by browsing to `/api/v1/audit/tenant/B`.

#### Enterprise

- **Customer Portal login no longer leaks org existence or auth
 mode.** `POST /api/v1/auth/login` returned three
 distinguishable failure responses that together let an
 unauthenticated caller enumerate valid org IDs and classify
 each org by auth mode:
 - Unknown org: `401 "Invalid credentials"` (no bcrypt work).
 - Known org with no password set (SSO-only): `401 "Password
 authentication not enabled for this organization"` (no
 bcrypt work).
 - Known org, bad password: `401 "Invalid credentials"`
 (full bcrypt compare).
 The distinct no-password body outed which orgs existed and
 which were password-backed; even with a uniform body the
 missing bcrypt on the first two branches leaked the same bit
 through response timing. Every failure now returns `"Invalid
 credentials"`; the no-password branch runs a throwaway
 bcrypt compare against a fixed placeholder hash so the
 timing profile matches a real check. SSO-only orgs cannot
 log in through this path - they are simply indistinguishable
 from wrong-password attempts to an external caller.
- **Customer Portal request-body size capped at 1 MiB.** The
 Portal had no upstream bound on JSON-decode; a single
 multi-GB POST could pin goroutines and memory. The new
 middleware caps POST/PUT/PATCH bodies at 1 MiB by default
 and is wired into the Portal's outer chain so SCIM, admin,
 and session-protected handlers all inherit it.
- **System policies visible in the Customer Portal.** The
 Portal's fetch-static-policies call landed on the agent
 without internal-service credentials and was denied 401, so
 the Static (Read-only) count showed 0 next to a Total
 Policies of 17 - the 80+ PII / SQLi / dangerous-commands
 rules were invisible. Three paired changes restore
 visibility: the agent accepts internal-service credentials
 from headers alongside the hint-based path, the Portal
 signs every agent call with the internal-service secret,
 and CloudFormation injects that secret into the Portal task
 definition. Missing-secret deployments log a startup
 warning and continue with empty static policies so dev
 environments degrade gracefully.
- **`POST /api/v1/admin/onboard-customer` is no longer
 unauthenticated, and supplied `license_key` payloads are
 verified.** The route was registered on the bare router
 with a "legacy / no auth for backward compatibility"
 comment; anyone reachable on the Portal could hit it,
 write rows into the orgs table, mint license keys, and
 overwrite Secrets Manager entries. Two paired fixes close
 the gap: the route now lives under the admin subrouter
 that runs the admin auth middleware (API key required in
 SaaS production; optional otherwise), and when the request
 supplies `license_key` the handler validates the Ed25519
 signature, expiry, and signed org/tier match before
 accepting. The signed payload's `expires_at` and
 `max_nodes` win over the request body - the body cannot
 widen what the license actually grants.

## [7.1.1] - 2026-04-19

Patch release: closes ten Plugin Batch 1 gaps surfaced across two rounds
of post-release install-and-use E2E testing - first with
`@axonflow/openclaw@1.3.0` (six HTTP-path gaps), then with Claude Code /
Cursor / Codex plugins (four MCP-tool-path gaps the first round missed).
All features from v7.1.0 are unchanged in scope; this release makes them
actually work end-to-end for plugin consumers across both the HTTP and
MCP JSON-RPC surfaces.

### Fixed

- **MCP check-input responses now carry richer context.** Block responses
 include `decision_id`, `risk_level`, `policy_matches`, and
 `override_available`/`override_existing_id` when the caller provides
 `X-User-Email`. Previously the agent returned only the legacy
 `allowed`/`block_reason`/`policies_evaluated` trio, so plugins could
 not surface a useful reason on a block or offer an override CTA.
- **`explainDecision` resolves MCP-path decisions.** MCP
 check-input/check-output decisions are now dual-written to
 `audit_logs` with the decision id in `policy_details`, so the
 existing explain endpoint returns the full `DecisionExplanation`
 rather than 404.
- **MCP check-input now consults active overrides.** Previously the
 handler surfaced `override_available: true` but still returned
 `allowed: false` because override enforcement was wired into the WCP
 path only. A flip-to-allow emits an `override_used` audit event
 mirroring the WCP path.
- **Audit search tolerates NULL columns.** `SearchAuditLogs` previously
 aborted the row scan on a NULL `provider`/`model`/`error_message`/`cost`/
 `response_time_ms`/`tokens_used` and dropped the entire result set,
 hiding every Plugin Batch 1 audit row. The scan now uses nullable
 types and maps to zero values for the caller's `AuditEntry`.
- **Cache invalidation on override create matches WCP cache shape.**
 `invalidateCachedDeniedDecisions` previously matched the policy UUID
 against `workflow_steps.policies_matched[].policy_id`, but the WCP
 adapter writes the policy NAME in that slot. The helper now resolves
 UUID + slug + name synonyms and matches any of them, so overrides
 actually flush the WCP cache.
- **WCP-path overrides now apply.**
 `DatabaseDynamicPolicyEngine.EvaluateDynamicPolicies` (used by the WCP
 step gate) now populates `result.AppliedPoliciesDetail`. Previously
 only the in-memory engine did, so `ApplyOverrideToResult` iterated an
 empty slice on the WCP path and no override ever flipped a deny.
- **MCP `tools/call` path now emits richer-context on blocks.** Same
 fix as the HTTP check-input path, mirrored into `mcpToolCheckPolicy`
 and `mcpToolCheckOutput`. Pre-fix, Claude Code / Cursor / Codex
 plugins (which use the MCP server's JSON-RPC surface rather than the
 HTTP endpoint OpenClaw uses) saw a terse "blocked" string with no
 `decision_id` / `risk_level` / `policy_matches` / `override_available`.
 Override apply + audit dual-write are now mirrored identically across
 both surfaces.
- **`createOverride` / `listOverrides` accept UUID *or* slug/name for
 `policy_id`.** Plugins read `policy_id` from a check-input response's
 `policy_matches[]` (where static policies carry the slug, not the
 UUID) and pass that straight to the override endpoints. Pre-fix, the
 orchestrator required the UUID and returned 404 for slug callers.
 `policyRiskAndOverride` now resolves either and stores the canonical
 UUID in `policy_overrides.policy_id`.
- **`DatabaseDynamicPolicyEngine` schema covers the new columns.**
 `dbPolicyEngineSchema` now includes `id UUID`, `risk_level`, and
 `allow_override` so integration tests and fresh clusters match
 migration 070's shape.
- **`policy_override_repository.policyRiskAndOverride` returns the
 canonical UUID.** Callers can no longer store the user-supplied
 value (which may be a slug) in `policy_overrides.policy_id`.

### Changed

- **Workflow handler `getUserID` falls back to `X-User-Email`.** Matches
 the Plugin Batch 1 convention of per-user identity via the email
 header, so WCP workflows capture per-user scoping and the cache
 invalidation query finds the right rows.

### Internal

- New `platform/agent/mcp_richer_context.go` helper module.
- New install-E2E scenario scripts at
 the e2e test suite
 covering the post-release "install from npm / GitHub release and use
 as a real user would" layer that caught these ten gaps across both
 the HTTP check-input path and the MCP tools/call path.
 `PLUGIN_E2E_TESTING_WORKFLOW.md` now mandates both paths as separate
 install-E2E layers for every future plugin batch.

---

## [7.1.0] - 2026-04-18

Combined release: Workflow State Management & HITL Enhancement +
Plugin Batch 1 - Governed Overrides & Explainability.

### Added

#### Workflow State Management & HITL Enhancement

- **Execution boundary semantics** - Step gate decisions are now idempotent
 by default. Calling the same `(workflow_id, step_id)` returns the cached
 decision without re-running the policy evaluator. Pass
 `retry_policy: "reevaluate"` to force a fresh evaluation when external state
 has changed. Responses include `cached` (boolean) and `decision_source`
 ("fresh" or "cached") so callers always know the provenance of the decision.

- **Workflow checkpoints** - Every step gate evaluation automatically creates
 a checkpoint capturing the decision, policy context, and full step metadata
 (model, provider, tool context, actor identity). Checkpoints are
 governance-aware resume boundaries, not arbitrary snapshots.
 - Community: list checkpoints via `GET /api/v1/workflows/{id}/checkpoints`
 - Evaluation: resume from last checkpoint via `POST /api/v1/workflows/{id}/checkpoints/resume`
 - Enterprise: resume from any checkpoint via `POST /api/v1/workflows/{id}/checkpoints/{id}/resume`

- **Risk-tiered approval routing** - HITL approval requests now carry a
 severity level (critical, high, medium, low) derived from the triggering
 policy's action config or the policy evaluation risk score. When multiple
 policies match, the highest severity wins. The HITL queue can be filtered
 by severity.
 - Enterprise: auto-approve low-risk actions after a configurable delay,
 escalate critical-risk actions past SLA threshold. Configure via
 `AXONFLOW_RISK_TIER_ENABLED`, `AXONFLOW_RISK_TIER_ORG_ID`,
 `AXONFLOW_LOW_AUTO_APPROVE_DELAY_MIN`, `AXONFLOW_CRITICAL_ESCALATION_SLA_MIN`.

- **Deterministic approval deduplication** - WCP approval creation uses a
 deterministic UUID derived from `(workflow_id, step_id)` combined with
 `ON CONFLICT` to guarantee exactly one approval per execution boundary,
 even under concurrent first-time calls.

#### Plugin Batch 1 - Governed Overrides & Explainability

- **Governed session overrides** - users can grant themselves a time-bounded,
 audit-logged override on a policy that would otherwise deny, closing the
 dev-mode UX gap without weakening governance. TTL is clamped server-side
 (default 60 minutes, hard cap 24 hours, zero for critical-risk policies).
 A free-text justification is mandatory on every override. Four new audit
 event types record the full lifecycle: `override_created`, `override_used`,
 `override_expired`, `override_revoked`. New endpoints: `POST /api/v1/overrides`,
 `GET /api/v1/overrides`, `GET /api/v1/overrides/{id}`,
 `DELETE /api/v1/overrides/{id}`.
- **Policy risk level + override flag** - every policy now carries an explicit
 `risk_level` (`low` | `medium` | `high` | `critical`) and an
 `allow_override` boolean. The combination is enforced as a contract: a
 database trigger forces `allow_override=false` whenever `risk_level=critical`,
 and the override creation endpoint rejects with 403 if either condition
 forbids the override. Existing policies are migrated with sensible defaults
 (dangerous commands, RCE, and privilege-escalation categories set to
 `critical`; SQLi, prompt injection, and secret leaks set to `high`).
- **Richer approval context** - `PolicyMatch` now includes `risk_level`,
 `allow_override`, `matched_rule`, and `policy_description` fields. Plugins
 can surface a structured reason on every block rather than a terse string.
 Existing consumers are unaffected - all new fields use `omitempty`.
- **Explain-on-demand endpoint** - `GET /api/v1/decisions/{id}/explain`
 returns a stable `DecisionExplanation` payload: matched policies with
 descriptions, decision + reason, risk level, override availability and any
 existing active override, historical hit count for the same rule in the
 caller's rolling 24-hour session window, and a tool signature. Authorization
 is scoped to the decision owner or same-tenant callers. Payload shape is
 frozen - additive fields only until a major version bump.
- **Audit search filter parity** - `POST /api/v1/audit/search` accepts three
 new optional filters: `decision_id` for explain flows, `policy_name` for
 "what did this policy block" queries, and `override_id` to reconstruct the
 full lifecycle of a single override. Existing filters remain unchanged.
- **MCP tool surface** - `explain_decision`, `create_override`, `delete_override`,
 and `list_overrides` are now exposed as MCP tools on the agent's MCP server,
 alongside the existing `check_policy` / `check_output` / `audit_tool_call`
 / `list_policies` / `get_policy_stats` / `search_audit_events` tools. Agents
 running in the plugin ecosystem can drive the full override lifecycle and
 decision explainability without leaving the MCP surface.

### Changed

- **Step gate upsert** - Re-evaluation (`retry_policy: "reevaluate"`) now
 updates all step metadata (step_name, step_type, step_input, model,
 provider) in the persisted step record, not just the decision columns.

- **Concurrent safety** - After upserting a step decision, the service reads
 back the persisted row to ensure the response matches what actually landed
 in the database. If a concurrent call won the race with a different
 decision, the persisted (winning) decision is returned.

- **Feature matrix** - Updated with checkpoint and risk-tiered approval rows
 across Community, Evaluation, and Enterprise tiers.

- `DynamicPolicy` and `StaticPolicy` structs gained `risk_level` and
 `allow_override` fields. Policy repositories persist them via migration 070.

### Fixed

- **Severity was hardcoded** - HITL approval severity was always set to
 "high" regardless of the triggering policy's risk level. Now derived from
 the policy's `require_approval` action config or the evaluation risk score.

### Database

- Migration `069_*` - workflow state management.
- Migration `070_policy_batch1_risk_and_override_extensions.sql` adds
 `risk_level` and `allow_override` columns (with seeded defaults per category)
 to `static_policies` and `dynamic_policies`; extends the existing
 `policy_overrides` table with `tool_signature`, `revoked_at`, `revoked_by`;
 adds `audit_logs` indexes on `decision_id` for the new filters; installs a
 trigger that enforces the critical-risk no-override invariant at the
 database level.

### Plugin ecosystem

The companion plugin releases for Plugin Batch 1 (OpenClaw v1.3.0,
Claude Code v0.5.0, Cursor v0.5.0, Codex v0.4.0) ship the user-facing
consumption of the new override, explain, and audit-search endpoints.

---

## [7.0.1] - 2026-04-11

### Fixed

- **Authentication on all endpoints** - Unified auth handling across gateway,
 MCP, proxy, and API routes. Fixes 401 errors on community-saas (try.getaxonflow.com)
 for gateway pre-check, audit, proxy, and MCP endpoints. Proxy routes
 (dynamic policies, cost controls) were previously inaccessible in
 community-saas mode.
- **Community mode tenant isolation** - Requests in community mode now
 preserve per-tenant scoping. Previously all requests collapsed to a
 single synthetic client, mixing audit and policy data across tenants.
- **Telemetry tracking** - All authenticated requests (including MCP and
 JSON-RPC sessions) now correctly record telemetry in community-saas mode.
- **Audit identity** - Audit records now use the authenticated client identity
 instead of trusting the request body, preventing cross-tenant attribution.
- **MCP server DB auth** - MCP JSON-RPC handler now validates clients
 registered via database, not just the in-memory whitelist.
- **Example credentials** - 139 example files updated to read auth credentials
 from environment variables, fixing failures on authenticated servers.
- **Deploy workflow** - Stack discovery excludes auxiliary services when
 deploying community-saas.
- **Next.js security update** - Customer portal updated to 16.2.3
 (GHSA-q4gf-8mx6-v5v3).

## [7.0.0] - 2026-04-09

### Breaking Changes

#### Changed - Default detection actions relaxed

- **Breaking:** the default `PII_ACTION` is now `warn` (previously `redact`). SQLi and
 sensitive-data categories also default to `warn`. Compliance categories (HIPAA, GDPR,
 PCI, RBI, MAS FEAT) default to `log`. Only unambiguously dangerous patterns - reverse
 shells, `rm -rf /`, SSRF to `169.254.169.254`, `/etc/shadow`, credential files - block
 by default.

 **Why this is a major version bump:** upgrading without explicit config reduces enforcement.
 A governance product silently weakening default protections is exactly the kind of change
 that warrants a major version signal.

 **Migration path:**
 - To restore previous behavior: set `AXONFLOW_PROFILE=strict` or `PII_ACTION=redact`
 - To keep new defaults: no action needed
 - Explicit `*_ACTION` env vars are unaffected - they always take highest precedence

- **Database migration for system-default policies.** A migration rewrites system-default
 policies to match the new defaults. User-created and tenant-owned policies are untouched.
 An accompanying down migration restores the previous strict defaults.

### Community

#### Added - Community SaaS evaluation server (try.getaxonflow.com)
- `DEPLOYMENT_MODE=community-saas` - new deployment mode for shared evaluation server.
 Requires self-registration via `POST /api/v1/register`. Rate-limited: 20 req/min +
 500 req/day per tenant. Ollama is the only LLM provider. No license required.
- `POST /api/v1/register` - generates UUID tenant_id (prefixed `cs_`) and one-time-display
 secret (bcrypt-hashed at cost 12). Credentials expire after 30 days. IP-rate-limited
 to prevent registration abuse (5/hour/IP).
- Migration 068: `community_saas_registrations` + `community_saas_daily_usage` tables +
 `increment_csaas_daily` atomic counter function for daily rate limiting.
- Community SaaS usage telemetry to dedicated DynamoDB table (`community-saas-telemetry-events`).
 Records endpoint, method, status_code, platform version, correlation_id per request.
 Never records request content, query params, or IP addresses. 30-day TTL, PITR enabled,
 server-side encryption enabled.
- Ollama EC2 infrastructure template (`infrastructure/cloudformation/ollama-ec2.yaml`)
 with security-group-scoped port 11434, SSM management, GPU driver auto-install for
 g4dn/g5 instance types.
- Dedicated community CloudFormation template (`community-saas-ecs.yaml`) - stripped-down
 stack with Agent, Orchestrator, Prometheus, and Grafana only. No Customer Portal,
 no Portal UI, no enterprise connectors. Deploy script auto-selects the right template
 based on `deployment_mode` in the environment config.
- Docker Compose overlay (`docker-compose.community-saas.yml`) for local E2E testing with
 bundled Ollama service and automatic model pull.
- `community-saas` added to deploy-application and deploy-platform workflow dropdowns.
- Checkpoint telemetry accepts `community-saas` as a valid `endpoint_type` value.

#### Added - Governance profiles and per-category enforce

- **`AXONFLOW_PROFILE` env var** (`dev` | `default` | `strict` | `compliance`). Resolved at agent and orchestrator startup, applied to the policy engine, and logged on boot. A single env var picks the enforcement posture instead of tuning eight individual `*_ACTION` env vars. The matrix is documented in the Governance Profiles guide. Explicit category env vars (`PII_ACTION=block`, `SQLI_ACTION=warn`, etc.) continue to override the profile, so existing automation keeps working.

- **`AXONFLOW_ENFORCE` env var** for per-category opt-in enforcement. Accepts a comma-separated subset of `pii`, `sqli`, `sensitive_data`, `high_risk`, `dangerous_queries`, `dangerous_commands`, plus the sentinels `all` and `none`. `all` is a true alias for the strict profile; `none` is a true alias for the dev profile - both match the documented profile matrices exactly. An explicit category list forces listed categories to `block` while leaving non-listed categories at the active profile's value (non-listed are no longer silently downgraded to `warn`). Unknown tokens are rejected at startup - previously this used `log.Fatalf` which crashed test binaries when developers had stale env vars set; it now returns an error cleanly. Precedence (highest → lowest): explicit `*_ACTION` env vars > `AXONFLOW_ENFORCE` > `AXONFLOW_PROFILE` > built-in defaults.

- **Profile banner at startup.** Both the agent AND the orchestrator now log the active profile and resolved per-category actions on boot, so operators can confirm what posture each component is running in without grepping the env. Example: `[Profile] agent active: dev - PII=log, SQLI=log, SensitiveData=log, HighRisk=log, DangerousQuery=warn, DangerousCommand=warn`.

- **Precedence chain regression tests** - unit tests verify `ProfileDefaults → ApplyEnforce → *_ACTION env var` end-to-end through `DetectionConfigFromEnv`, plus the invalid-value-preserves-profile guarantees under both strict and dev profiles.

#### Fixed - Invalid env var values now preserve the active profile

- **`DetectionConfigFromEnvWithBase` fallback bug.** On a `dev` or `default` deployment, a typo like `PII_ACTION=blok` used to silently tighten behavior back to `redact` - the hardcoded legacy fallback in `parseDetectionAction` ignored the already-resolved profile base and reverted to the v6.1.0 default. Now the fallback preserves the base config's value (`cfg.PIIAction`, `cfg.SQLIAction`, etc.) so an invalid value on a dev profile stays at `log` and on a strict profile stays at `block`. Applies to PII, SQLi, sensitive data, high risk, dangerous queries, and dangerous commands. Regression tests verify the behavior on both strict and dev profiles.

#### Fixed - `AXONFLOW_ENFORCE=all` and `none` now match their documented profile aliases

- **Sentinel semantics corrected.** The comments and docs said `AXONFLOW_ENFORCE=all` was equivalent to `AXONFLOW_PROFILE=strict` and `none` equivalent to `dev`, but the old `ApplyEnforce` implementation turned listed categories into `block` and all others into `warn`. In practice `all` over-blocked `high_risk` (strict leaves it at warn), and `none` produced `warn`-only behavior instead of dev's `log`-only posture for PII/SQLi/sensitive data. `ApplyEnforce` now reads the sentinel and returns `ProfileDefaults(ProfileStrict)` / `ProfileDefaults(ProfileDev)` directly, so the sentinels match the documented profile matrices exactly.

- **Non-listed categories preserved.** When an explicit category list is provided (e.g. `AXONFLOW_ENFORCE=pii,sqli`), listed categories are forced to `block` as before, but non-listed categories now preserve the active profile's value instead of being silently downgraded to `warn`. A dev-profile deployment with `AXONFLOW_ENFORCE=pii` now blocks PII and keeps everything else at `log`, not `warn`.

#### Fixed - `LoadEnforceFromEnv` no longer calls log.Fatalf

- **`LoadEnforceFromEnv` returns an error instead of calling `log.Fatalf`.** Any developer with a stale `AXONFLOW_ENFORCE=garbage` in their shell used to crash the entire test binary at package init. Now the error is returned cleanly and the calling code logs and continues with the profile base.

#### Fixed - `deploy-client.sh` JWT path silent failure

- **`scripts/multi-tenant/deploy-client.sh` no longer silently falls back to a hardcoded Secrets Manager path.** The "Path B" fallback was reading a hardcoded `axonflow/clients/travel/production/user-token` regardless of the client being deployed, swallowing AWS errors with `2>/dev/null || echo ""`, and silently passing an empty `USER_TOKEN` into the container - which the agent then rejected at runtime with a misleading "token signature is invalid" error. The variable `AXONFLOW_STACK_PREFIX_JWT` is now required; the script fails loudly if missing. The generated `USER_TOKEN` is now validated with a structural check: three base64url segments, header that decodes to JSON with an `alg` field, payload that decodes to JSON with an `exp` or `iat` field (previously the check was a regex that accepted any `a.b.c` literal). All client environment files under `configs/environments/clients/` have been updated to declare the variable. A new runbook documents the underlying JWT secret rotation flow.

#### Fixed - Evaluation tier `MaxPendingApprovals` outlier

- **`EvaluationLimits.MaxPendingApprovals` corrected from 100 to 25** to match the rest of the evaluation tier caps (`MaxConcurrentExec`, `MaxSSEConnections`, `MaxVersionsPerPlan`). The previous value of 100 was an outlier that contradicted the tier boundary test and inflated evaluation-tier capacity above what was documented and tested.

### Security

- **Ed25519 enterprise license signing key rotated.** The previous private seed was found embedded in `scripts/setup-e2e-testing.sh`, where it had been since the script was authored. Anyone with read access to the repo could mint valid Enterprise / Professional / Plus licenses for any `org_id`, bypassing tier gating in any deployment. As part of this release the key has been rotated, all active customer and per-stack licenses re-signed under the new key, and the agent's embedded `enterprisePublicKey` byte array updated. The previous public key (first 8 bytes `9a b6 f6 b2`) is no longer accepted. A new internal-only runbook documents the rotation procedure for any future operator.

- **Rotation tool now enumerates secrets dynamically.** The initial rotation tool held a hardcoded list of license secrets, which missed the per-stack `axonflow-<stack>-license-key` boot license secrets and broke running agents mid-rotation. The rewritten tool paginates `ListSecrets` and `DescribeParameters` across all configured regions, filters by name + value prefix, re-signs every enumerated Ed25519 and legacy V2 license, and writes re-signed licenses back to AWS BEFORE rotating the signing-key secret (so a write-back failure never leaves SM in a split-brain state where the new signing key is active but some licenses still hold signatures under the old key).

- **Re-signed V2 licenses preserve both `tenant_id` and `org_id`.** The legacy V2 HMAC format only carried `tenant_id`; the fresh Ed25519 payload now writes both fields so downstream consumers that key off either stay compatible.

- **`scripts/setup-e2e-testing.sh` no longer hardcodes any signing keys.** The eval and dev-only enterprise keys are sourced from the environment (CI uses GitHub Actions secrets) or fetched at runtime from AWS Secrets Manager. A separate dev-only enterprise keypair has been created so local E2E never touches the production signing key. The `.env` file written by the script is `chmod 600` so the signing-key material it contains is not world-readable.

- **Pre-commit `gitleaks` rule** added at `.gitleaks.toml` and wired into `.pre-commit-config.yaml`. The rule blocks any commit that introduces a base64 Ed25519 seed near a `*_SIGNING_KEY` env var assignment. CI runs gitleaks on every PR.

- **Checkpoint telemetry retention bumped from 90 → 180 days.** Evaluation-to-production conversion windows run 2-4 months in observed data, so 90 days was cutting off the tail. 180 days still fits comfortably in DynamoDB free tier at current volume.

#### Fixed - Multi-tenant SaaS correctness and security

- **`X-Org-ID` now derived from the validated client license, not the deployment env var.** The agent's Single Entry Point proxy middleware (`platform/agent/proxy.go`) was forcibly overwriting the authenticated client's `org_id` with the deployment's `ORG_ID` environment variable on every request, preventing a single deployment from serving multiple organizations. Every tenant on a shared stack was being stamped with the same `org_id`, making true multi-tenant workflow scoping impossible. The middleware now forwards `X-Org-ID` from the cryptographically validated client license payload (`client.OrgID`) - matching the behavior of `apiAuthMiddleware` in `auth.go`, which was already correct. The Ed25519 signature on the client license guarantees the `org_id` claim cannot be forged, so trusting it is both safe and required for multi-tenant operation. Deployments with a single org per stack are unaffected; deployments serving multiple orgs now correctly scope workflows, policies, and audit data per-tenant.

- **Internal orchestrator forwarding path fixed.** `platform/agent/run.go` also had the same bug in the direct HTTP forwarding path that bypasses the Single Entry Point mux. It was checking whether the client had an `org_id` and then setting the header to `getDeploymentOrgID` anyway. Now uses `client.OrgID` directly.

- **MCP check-input and check-output audit log OrgID.** `platform/agent/mcp_handler.go` was writing every MCP audit record with `OrgID: getDeploymentOrgID` regardless of which client authenticated. Multi-tenant audit trails were structurally broken - all records from all tenants were attributed to the deployment. Both handlers now lift `orgID` into function-level scope alongside `tenantID`, populated from `client.OrgID` in enterprise auth, `X-Org-ID` header in internal-service auth, and `getDeploymentOrgID` in community mode.

- **Removed `validateClient` mock authentication fallback.** `platform/agent/run.go` had a `validateClient(clientID)` function that accepted any `client_id` from the request body and returned a fake "Demo Client" with the deployment's own `org_id`, no credential validation. All four MCP handlers (`/api/v1/mcp/query`, `/api/v1/mcp/execute`, `/api/v1/mcp/check-input`, `/api/v1/mcp/check-output`) called this as a fallback when Basic auth was missing. Effectively: in enterprise mode, any request without Basic auth but with a `client_id` field in the JSON body was silently authenticated as that client. Removed the function and all four call sites now reject unauthenticated requests with 401.

- **Orchestrator workflow tenant/org ownership checks.** `platform/orchestrator/workflow_control/service.go` - **nine** service methods now enforce tenant/org ownership before acting on a workflow: `GetWorkflow`, `StepGate`, `MarkStepCompleted`, `ApproveStep`, `RejectStep`, `ResumeWorkflow`, `CompleteWorkflow`, `FailWorkflow`, `AbortWorkflow`. Previously `GetWorkflow` (called from `GET /api/v1/workflows/{id}`) did no tenant/org filtering - any authenticated client that knew a workflow ID could fetch any workflow (classic IDOR). The same gap existed on every other workflow state transition: an attacker could approve, reject, resume, complete, fail, or abort any other tenant's workflow, or inject fake cost/token metrics into another tenant's audit trail by calling `MarkStepCompleted`. All matching HTTP handlers in `handlers.go` extract tenant/org from request headers (`X-Tenant-ID`, `X-Org-ID`) and pass them through. Callers in `run.go` (MAP confirm mode) and `unified_execution_handler.go` also updated. `ListWorkflows` was already filtering correctly.

- **Unified execution handler `checkTenantOwnership` hardened.** `platform/orchestrator/unified_execution_handler.go` previously had permissive fallbacks: requests without `X-Tenant-ID` were allowed through, and executions without a `tenant_id` were accessible to any caller. Both were cross-tenant data leak vectors. The check now:
 - Requires **both** `X-Tenant-ID` and `X-Org-ID` on every request (401 if missing).
 - Rejects executions that lack either `tenant_id` or `org_id` (404).
 - Requires exact match on both fields (404 on any mismatch).
 - All mismatch responses return 404 (not 403) to prevent cross-tenant existence leakage.

#### Added - Customer portal multi-tenant identity

- **`tenant_id` column on `user_sessions`** (migration 065). The customer portal previously aliased `tenantID:= orgID` in `auth.go` with the comment *"organizations table doesn't have tenant_id column"*. That collapsed two concepts and prevented a single portal org from representing multiple tenants (prod, staging, dev). The new column lets a portal session track which tenant within an org the user is currently viewing.

- **`portal_default_tenant_id` SQL helper** (migration 065). Resolves the default tenant for an org: prefers `tenant_id = org_id` (canonical default) and falls back to the oldest tenant in the `tenants` table, then to `org_id` itself for community deployments. Used at login time to populate the session.

- **Automatic default tenant backfill** for every existing organization (migration 065). Every org gets a canonical tenant row inserted into the `tenants` table if one doesn't already exist, so portal login can deterministically resolve a tenant without schema changes to customer data.

#### Changed - Customer portal auth and proxy

- **`AuthHandler.HandleLogin`** now resolves `defaultTenantID` via `portal_default_tenant_id` at login time, inserts it into `user_sessions.tenant_id`, and returns both `org_id` and `tenant_id` in the login response. Legacy fallback kicks in if migration 065 hasn't been applied yet.

- **`AuthHandler.HandleCheckSession`** (GET /api/v1/auth/session) now reads and returns `tenant_id` alongside `org_id`.

- **`middleware/dev_auth.go`** stops joining `customers.tenant_id` and reads `user_sessions.tenant_id` directly. The previous `orgID + "_tenant"` fallback is replaced with a deterministic fallback to `org_id` for legacy sessions.

- **`api/orchestrator_proxy.go`** forwards `X-Tenant-ID` from `session.TenantID` (the currently-selected tenant within the org) and `X-Client-ID` from the tenant identifier - previously both collapsed to `session.OrgID`. `X-Org-ID` continues to carry `session.OrgID`. A warning log fires when `session.TenantID` is empty (legacy session, unexpected after migration 065).

- **`ORG_ID` environment variable role clarified.** Previously documented as "canonical org identity (single source of truth)", the env var is now understood as:
 - **Stack-level deployment label** (used in logs, metrics, startup validation against the stack's own boot license)
 - **Community mode fallback** (when no client license is present)
 - **NOT a routing key** for per-request multi-tenant data scoping - that comes from the authenticated client license

#### Fixed - Deployment tooling

- **`deploy-cloudformation.sh` missing required `OrganizationID` parameter.** The script built the `aws cloudformation deploy --parameter-overrides` list without passing `OrganizationID`, so creating a new stack from a clean state failed with `Parameter 'OrganizationID' must have a value`. Existing stack updates worked because CloudFormation falls back to `UsePreviousValue` for parameters not passed explicitly. The script now reads `deployment.organization_id` from the environment yaml config, falling back to the environment name if not set, and passes it on every deploy. This unblocks creating fresh environments from `deploy-platform.yml`.

### Security

- **IDOR on `GET /api/v1/workflows/{id}` closed.** Before v6.2.0, any authenticated client could fetch any workflow by ID regardless of which tenant or org it belonged to. Combined with the `X-Org-ID` deployment-env-var override, this meant a compromised tenant could enumerate workflow IDs and read every other tenant's execution state. Both the header source fix and the service-layer ownership check are required to close the hole end-to-end.
- **No-auth fallback on MCP handlers closed.** Before v6.2.0, in enterprise mode, any request with a `client_id` field in the JSON body (but no Basic auth credentials) was silently authenticated as that client and attributed to the deployment's own org. Removed entirely.
- **Permissive cross-tenant fallback on unified execution endpoints closed.** Before v6.2.0, executions without a `tenant_id` were accessible to any caller, and requests without `X-Tenant-ID` were accepted. Both now rejected.

---

## [6.1.0] - 2026-04-06

### Community

#### Added

- **Mistral AI LLM provider.** Full integration with Mistral's OpenAI-compatible API. Supports `mistral-small-latest` (default), `mistral-large-latest`, `codestral-latest`, and other models. Includes streaming, cost estimation, health checking, and automatic bootstrap from `MISTRAL_API_KEY` environment variable. Six example suites with 42 total assertions.
- **Cursor IDE plugin launch.** AxonFlow governance for Cursor via `preToolUse`/`postToolUse` hooks. Enforces policy on Shell, Write, Edit, Read, Task, NotebookEdit, and MCP tools. PII detection in file writes with configurable `PII_ACTION` (block, redact, warn, log). 3 skills, 1 governance rule, 6 MCP tools. Plugin at [axonflow-cursor-plugin](https://github.com/getaxonflow/axonflow-cursor-plugin).
- **OpenAI Codex plugin launch.** Hybrid governance for Codex: enforcement via hooks for terminal commands (`exec_command`), advisory governance for other tools via skills with implicit activation. 6 skills, 6 MCP tools. Plugin at [axonflow-codex-plugin](https://github.com/getaxonflow/axonflow-codex-plugin).
- **Integration activation for Cursor and Codex.** Auto-detection via connector type prefix (`cursor.*`, `codex.*`) and client name matching. Integration-specific policies enabled on first request (migration 064).
- **GovernedTool examples for TypeScript, Go, Java.** Framework-agnostic tool governance examples matching the existing Python example, with 8 E2E-verified test cases per language.

#### Changed

- **Telemetry defaults clarified for SDKs and plugins.** Anonymous telemetry remains enabled by default for all endpoints, including localhost/self-hosted evaluation, unless `DO_NOT_TRACK=1`, `AXONFLOW_TELEMETRY=off`, or an explicit SDK/plugin setting disables it. Related docs now also describe plugin timeout tuning for remote or high-latency deployments.

---

## [6.0.0] - 2026-04-05

> **Upgrade note:** Most users running with default settings are unaffected. If you customized `ORG_ID` or `AXONFLOW_CLIENT_ID` in your docker-compose, verify they still match your deployed identity before upgrading. See [deployment/licensing](https://docs.getaxonflow.com/docs/deployment/licensing) for details.

### BREAKING CHANGES

- **Unified identity model.** `tenant_id` (from Basic auth `clientId`) for data isolation, `org_id` (from deployment `ORG_ID` env var) for entitlement scope. SDKs send credentials, server derives identity - no client-supplied identity headers.
- **License payload field renamed: `tenant_id` → `org_id`.** Existing licenses with `tenant_id` will not be recognized; regenerate with the updated keygen tool.
- **`X-Client-ID` header removed.** Redundant with `X-Tenant-ID`. All orchestrator reads changed to `X-Tenant-ID`.
- **License `org_id` must match deployment `ORG_ID`.** Agent validates at startup; mismatch causes a fatal error.
- **`X-Tenant-ID` header no longer accepted from clients.** The server derives tenant context from OAuth2 Client Credentials (Basic auth). SDKs must be updated to v5.0+ (Python), v5.0+ (Go), v5.0+ (TypeScript), v5.0+ (Java).
- **Legacy DatabasePolicyEngine removed.** All policy evaluation flows through the unified SharedPolicyEngine.
- **Basic auth required in evaluation/enterprise mode.** All proxied API endpoints require `Authorization: Basic base64(clientId:clientSecret)` when `DEPLOYMENT_MODE` is not `community`.

### Community

#### Added

- **`tenants` table** (migration 062) maps tenant_id → org_id. Auto-populated on first authenticated request. Enables multi-tenant deployments (prod, staging, dev under one org).
- **`org_id` column** on `audit_logs` (migration 059) and `mcp_query_audits` (migration 061) with backfill from `tenant_id`. All audit write paths now populate `org_id`.
- **Auto-registration of organizations and tenants.** In-memory cache skips DB on subsequent requests. Self-hosted users never need to manually seed identity tables.
- **Claude Code plugin** ([getaxonflow/axonflow-claude-plugin](https://github.com/getaxonflow/axonflow-claude-plugin)) - automatic policy enforcement, PII scanning, and audit trails via PreToolUse/PostToolUse hooks and 6 MCP tools.
- **MCP server protocol endpoint** (`/api/v1/mcp-server`). JSON-RPC 2.0 over Streamable HTTP with 6 governance tools: `check_policy`, `check_output`, `audit_tool_call`, `list_policies`, `get_policy_stats`, `search_audit_events`.
- **Integration policy activation system.** Integration-specific policies auto-enabled when an integration is detected via `AXONFLOW_INTEGRATIONS` env var, connector type auto-detection, or MCP client identification.
- **10 dangerous command system policies** (migration 059): reverse shells, destructive filesystem ops, credential access, download-and-execute, SSRF, path traversal, dynamic code execution.
- **`DANGEROUS_COMMAND_ACTION` config** split from `DANGEROUS_QUERY_ACTION`. Different risk profiles, configured independently.
- **OAuth2 Client Credentials authentication** for all policy API endpoints.
- **Community mode identity headers.** Agent injects `X-Tenant-ID` and `X-Org-ID` in community mode. Orchestrator identity always server-derived.
- **MCP handler Basic auth support.** All 4 MCP handlers accept Basic auth (service license validation), falling back to legacy whitelist.
- **Startup org_id mismatch validation.** Agent fails fast if license `org_id` doesn't match deployment `ORG_ID`.
- **Response PII detection uses database-driven policy engine.** Shared engine wired in orchestrator for response scanning.
- **PII detection modes example** (`examples/pii-detection/http/pii-modes.sh`). Tests request-side and response-side PII with ISO timestamp false positive regression test.
- **Proxy routes** for MCP processing, MAP cost estimation, unified execution cancel, legacy policy reads.
- **Runtime table creation moved to migrations.** `audit_logs`, `dynamic_policies`, `policy_metrics`, `media_governance_config`.
- **Organization and Tenant Identity Separation.
- **Setup script repo override.** `COMMUNITY_REPO` environment variable in `setup-e2e-testing.sh` allows pointing community-mode testing at any repo path.

#### Changed

- **All example CLIENT_ID defaults standardized to `"community"`.** Previously random per-example defaults.
- **All examples migrated to Basic auth.** 15 examples converted from `X-Client-ID`/`X-Client-Secret` headers.
- **All examples use agent single entry point.** 106 files migrated from orchestrator-direct (port 8081) to agent (port 8080).
- **`PII_ACTION` environment variable** controls enforcement on both request and response sides: `block`, `redact` (default), `warn`, `log`.
- **Static policy API endpoints** protected by `apiAuthMiddleware` via gorilla/mux subrouter.
- **License keygen parameter renamed.** `tenantID` → `orgID`.
- **Enterprise compose stale V2 secret removed.** `AXONFLOW_CLIENT_SECRET` default cleared. Use `setup-e2e-testing.sh` to generate valid Ed25519 licenses.
- **Orchestrator `ORG_ID` fallback changed from `"default"` to `"local-dev-org"`.** Logs a warning when not explicitly set.

#### Removed

- **`DatabasePolicyEngine`** (`db_policies.go`, ~744 lines).
- **`StaticPolicyEngine`** struct and methods (~634 lines collapsed to ~39 lines).
- **`db_policies_test.go`** (~1,648 lines), **`static_policies_test.go`** (~1,964 lines), **`agent_bench_test.go`** (~400 lines).

#### Fixed

- **Agent auth collapsed tenant_id and org_id.** Now `TenantID` comes from Basic auth clientId, `OrgID` from deployment `ORG_ID` env var.
- **Community mode X-Tenant-ID was spoofable.** Now always overrides with server-derived value.
- **Response PII redaction now respects `PII_ACTION` env var.** `warn`/`log` modes skip redaction but still run detection for audit.
- **4 PII false positives on ISO timestamps** (migration 063). SSN, phone, bank account, Singapore UEN patterns tightened.
- **MCP execute/check-input/check-output handlers ignored Basic auth.** All 4 handlers now use same auth pattern.
- **check-input/check-output rejected Basic auth requests.** `tenant_id` validation moved to after authentication.
- **Validator substring matching** in policy evaluator. Fixed with word-boundary matching.
- **System policies counted against tenant limit.** System-tier policies now excluded from quota.
- **MAP confirm mode end-to-end.** Three bugs fixed (org_id forwarding, execution tracker sync, response envelope).
- **13 HTTP examples missing Basic auth.** `AUTH_B64` variable defined after migration.
- **Compliance module log messages misleading in community mode.** Now shows "routes inactive - Enterprise build required".
- **SSE streaming missing `X-Tenant-ID`.** Updated 6 examples.
- **Cloud-storage example SDK API mismatch.** Updated for SDK v4.3.0.
- **Version-check example SDK struct mismatch.** Rewrote to use raw HTTP.
- **Policy example used wrong agent paths.** Updated to `/api/v1/static-policies`.
- **Support-demo Docker build.** `go.sum` was gitignored under `examples/`. Changed Dockerfile to use `go mod tidy`. Docker network name configurable via `AXONFLOW_NETWORK` env var.
- **Python 3.10+ compatibility in test scripts.** `test-all.sh` and `demo.sh` now respect `PYTHON` env var.
- **Proxy community mode tenant injection.** Agent proxy now derives tenant from Basic auth `clientId` (or defaults to `community`).
- **`AXONFLOW_CLIENT_SECRET` not exported in evaluation mode.** Setup script now exports both `LICENSE_KEY` and `CLIENT_SECRET`.
- **Enterprise setup reused stale `DEPLOYMENT_MODE=evaluation` from.env.** `start_enterprise` now explicitly sets `DEPLOYMENT_MODE=enterprise`.
- **Community mode `org_id` defaulted to `"demo-org"`.** Changed to `getDeploymentOrgID` (resolves to `"local-dev-org"` by default).

### Enterprise

#### Added

- **Missing proxy routes for enterprise endpoints.** Policy simulation, evidence export, RBI/SEBI compliance, webhooks, media governance config.

#### Changed

- **Static policy API auth middleware.** All 12 endpoints use `apiAuthMiddleware`.
- **MAP confirm/step mode execution.** WCP workflows correctly store `org_id`. Resume handler syncs execution tracker.

#### Fixed

- **Circuit breaker routes bypassed auth.** All routes now use auth-protected subrouters.
- **Auth middleware didn't inject identity headers.** `apiAuthMiddleware` now sets `X-Tenant-ID` and `X-Org-ID`.
- **MCP permission evaluator rejected `mcp:*:*` wildcard.**
- **HITL queue creation failed with nil JSON context.**
- **Enterprise HITL handler missing `/api/v1/hitl/status` endpoint.**
- **MCP enterprise examples missing `client_id` and `user_token` in request body.**
- **Tier-limits example used Bearer auth instead of Basic auth.**
- **Bedrock inference profile ID** missing `us.` prefix.

### SDK

#### Fixed

- **Missing `status` field on `PlanResponse`** across Go, Python, and TypeScript SDKs.
- **All SDKs reject `client_secret` without `client_id`** to prevent wrong-tenant data storage.
- **Bedrock inference profile ID** in E2E setup script.

---

## [5.5.0] - 2026-04-01

### Community

#### Added

- **OpenClaw integration**: E2E examples and architecture documentation for the `@axonflow/openclaw` plugin. Demonstrates tool input governance, outbound message scanning, and audit logging using `openclaw.*` connector types.
- **Computer Use governance**: E2E examples for Anthropic Computer Use with `ComputerUseGovernor` (Python SDK) and raw HTTP tests. Covers bash command blocking, PII detection, credential exfiltration prevention, and output redaction.
- **Claude Agent SDK integration**: TypeScript example demonstrating MCP tool governance with Claude Agent SDK using existing `mcpCheckInput`/`mcpCheckOutput`.
- **GovernedTool E2E examples**: LangChain AgentExecutor, LangGraph ToolNode, and HTTP examples for framework-agnostic tool governance.
- **SSRF prevention**: Pre-flight URL validation (scheme allowlist, DNS resolution, private IP blocking) on SSO metadata fetch and media URL fetch, complementing existing socket-level protections.
- **Log injection prevention**: Sanitized user-controlled values in log statements across agent proxy, orchestrator, and HITL handler to prevent newline/ANSI injection.
- **Dockerfile hardening**: Non-root user directives, pinned base image tags, and health checks across all Dockerfiles.
- **Go binary hardening**: Strip debug symbols, symbol tables, and build paths from production binaries.
- **Source map prevention**: Disabled source map generation in frontend Docker builds to prevent source code exposure.

#### Changed

- **Docker Compose version default**: Updated `AXONFLOW_VERSION` from `5.1.0` to `5.5.0`. The stale default caused missing endpoints (e.g., `audit/tool-call`) for users running `docker compose up` without explicitly setting the version.

#### Security

- **Amadeus connector SSRF enforcement**: Added pre-flight URL validation for Amadeus connector callbacks.
- **SQL injection prevention in demo backends**: Demo backends now use read-only transactions to prevent SQL injection in example queries.
- **Version alignment CI check**: New CI workflow validates that version defaults in Docker Compose, Dockerfiles, and CHANGELOG stay in sync.

#### Fixed

- **Stale docker-compose/Dockerfile version defaults**: Updated hardcoded version defaults from `5.1.0`/`4.8.0` to `5.5.0` across Docker Compose files and Dockerfiles.

- **Broken docs links**: Fixed 15+ stale links across platform surfaces (AWS Marketplace, SCIM, axonctl, Cloudflare Access setup).
- **Spring Boot/Tomcat update**: Bumped Spring Boot to 3.5.13, Spring Framework to 6.2.17, and Tomcat to 10.1.52 in integration example (CVE fixes).
- **Dependency update**: Bumped `golang.org/x/image` to v0.38.0, fixing out-of-memory vulnerability via crafted TIFF file.

#### Documentation

- **Computer Use governance architecture**: Sampling loop governance boundary, tool action taxonomy, default blocked bash patterns.
- **OpenClaw integration architecture**: Plugin hook flow, connector type convention, approval flow integration, lightweight HTTP client design.

### Enterprise

#### Added

- **Infrastructure hardening**: CloudFormation template updated with RDS private access, restricted security group egress, KMS encryption for SNS/Secrets Manager/CloudWatch, HTTP-to-HTTPS redirect, and ALB invalid header dropping. Terraform modules updated with KMS encryption for DynamoDB, CloudWatch, and Secrets Manager, plus Lambda X-Ray tracing.
- **GovernedTool integration comparison**: Internal documentation comparing GovernedTool, tool_output_wrapper, and mcp_tool_interceptor across framework compatibility, governance scope, and deployment patterns.

---

## [5.4.1] - 2026-03-30

### Community

#### Fixed

- **Cloud storage connectors now available in Community edition**: S3, Azure Blob, and GCS connectors were implemented in the community code path but only registered in the enterprise connector factory. Moved registration to the community factory so all users can use cloud storage connectors without an enterprise license.

#### Added

- **Cloud storage connector examples**: New E2E examples for S3/MinIO operations with hardened assertions in HTTP, Go, Python, TypeScript, and Java (`examples/mcp-connectors/cloud-storage/`).
- **MinIO service in community Docker Compose**: Added MinIO to `docker-compose.yml` for local S3-compatible storage testing without requiring enterprise mode.

---

## [5.4.0] - 2026-03-25

### Community

#### Security

- **Log injection prevention** (CodeQL): Sanitize user-controlled values in log statements across agent proxy, WCP service, and HITL handler using `logutil.Sanitize`. Prevents newline/ANSI injection into structured logs. Affects `platform/agent/proxy.go`, `platform/orchestrator/workflow_control/service.go`, `platform/orchestrator/hitl_wcp_community.go`.

#### Added

- **Policy conflict detection**: New `POST /api/v1/policies/conflicts` endpoint analyzes active policies for contradictions (`contradictory_action`), shadows, and redundancies. Helps teams validate policy configurations before deploying changes. Available at Evaluation tier and above, sharing the simulation rate limiter.
- **Policy simulation examples**: 8-step deterministic E2E examples in HTTP/cURL, Python, TypeScript, Go, and Java demonstrating simulate, impact report, and conflict detection workflows.
- **LangGraph tool output enforcement example**: Python example demonstrating `tool_output_wrapper` for policy enforcement on local `@tool` outputs in LangGraph workflows.
- **LangGraph 1-line wrapper example**: New `langgraph_wrapper_example.py` demonstrating `wrap_langgraph` for transparent governance of compiled LangGraph StateGraphs without modifying the graph definition.
- **Per-tool governance in HTTP example**: `workflow-control.sh` now uses the `tool_context` field in step gate requests for tool_call steps, demonstrating structured tool-level policy evaluation.

### Enterprise

#### Security

- **Log injection prevention** (CodeQL): Sanitize user-controlled values in checkpoint-service and customer-portal log statements. Affects `ee/platform/checkpoint-service/pkg/{notification,handler,bakeoff}`, `ee/platform/customer-portal/api/orchestrator_proxy.go`.
- **Prototype pollution fix** (Dependabot GHSA-rf6f-7fwh-wjgh): Updated `flatted` dependency in customer-portal-ui via `npm audit fix`.

#### Added

- **Portal: Policy Simulation Modal**: "Simulate Policies" button on the Policies page for dry-running all active policies against test queries. Shows allowed/blocked status, risk score, applied policies, and daily usage.
- **Portal: Policy Impact Modal**: "Preview Impact" per-policy button for batch-testing a policy against multiple inputs. Displays match/block rates with per-input results table. Auto-detects conflicts on the target policy.
- **OpenAPI spec**: Added `POST /api/v1/policies/conflicts` endpoint definition.

---

## [5.3.1] - 2026-03-24

### Community

#### Added

- **Audit compliance summary endpoint**: `POST /api/v1/audit/summary` returns aggregated compliance stats for a date range including total events, breakdown by severity and action type, top triggered policies, and a compliance score. Used by the Customer Portal audit page.

#### Fixed

- **Cross-tenant dynamic policy cache collision**: Dynamic policy cache was keyed by policy name, causing policies with the same name across different tenants to silently overwrite each other. In multi-tenant deployments, this could result in step gate evaluations using the wrong tenant's policy or skipping policies entirely due to tenant mismatch. Cache key changed from `name` to `policy_id` to ensure all policies coexist regardless of naming. Includes `GetPolicy` fallback search by name field for backward compatibility.
- **step_input/tool_input field resolution in dynamic policies**: Dynamic policy conditions referencing `step_input.*` and `tool_input.*` fields now resolve correctly during step gate evaluation. Previously these fields were not extracted from the policy evaluation context, causing conditions like `step_input.query contains "DROP"` to never match.
- **Step gate policy matching for step_input fields**: Fixed policy matching logic to correctly evaluate conditions against step_input fields in the dynamic policy engine. Added comprehensive test coverage for step_input and tool_input condition matching.

### Enterprise

#### Added

- **SSO metadata URL fetcher**: `POST /api/v1/sso/fetch-metadata` in the Customer Portal fetches and parses SAML IDP metadata from a URL. Includes SSRF protection (HTTPS-only, private IP rejection, DNS validation), per-session rate limiting (5/min), 1MB response size limit, and automatic provider detection (Okta, Azure AD, Google, OneLogin, Auth0).

#### Fixed

- **Portal proxy missing headers**: Customer Portal orchestrator proxy now forwards `X-Org-ID` and `X-Client-ID` headers from session context, fixing 401 errors on SEBI compliance endpoints and other handlers that require these headers.
- **SEBI audit export integer-only org IDs**: SEBI audit export service migrated from `int orgID` to `string tenantID` for consistency with the rest of the platform. Portal tenants with string IDs (e.g., `travel-us`) now work correctly with SEBI endpoints.
- **SEBI org name lookup**: `getOrgName` now queries `org_id` column first (matching the varchar tenant ID from portal), with fallback to numeric `id` for backward compatibility.
- **Compliance page crash on EU AI Act data**: Fixed `StatusBadge` component crash when `status` is undefined. Added null-safety guard. Also fixed `getEUAIActConformity` API function to transform the backend list response (`{assessments: [.]}`) into the single-object shape (`{status, risk_level, last_assessment, requirements}`) expected by the compliance page UI.
- **SCIM page smoke test false positive**: Playwright smoke test `afterEach` filter now catches browser-level "Failed to load resource: 403/404" console errors that lack endpoint URL context, preventing false failures on the SCIM settings page when SCIM provisioning is not configured.

---

## [5.3.0] - 2026-03-17

### Community

#### Added

- **Circuit breaker error auto-trip**: Upstream LLM errors (orchestrator hard failures, orchestrator-level errors, proxy 502s) now automatically trip client-scoped circuits after threshold exceeded within a sliding window. Previously, `RecordError` was implemented but not wired into the request pipeline.
- **Sliding window for circuit breaker thresholds**: Error and policy violation counting now uses a time-windowed approach (default 5 minutes) instead of lifetime counters. Errors outside the window are automatically discarded.
- **Per-tool governance examples**: LangGraph adapter examples for TypeScript, Go, and Java demonstrating per-tool gate checks within tools nodes.
- **WCP guide updated**: Workflow Control Plane documentation expanded with TypeScript, Go, and Java LangGraph adapter examples alongside Python.

### Enterprise

#### Added

- **Per-tenant circuit breaker thresholds**: Tenants can override global circuit breaker defaults (error threshold, violation threshold, window duration, timeout, auto-recovery) via `GET/PUT /api/v1/circuit-breaker/config`. Null fields fall back to global defaults. In-memory cache with 1-minute TTL.
- **Circuit breaker notification fan-out**: Auto-trip events trigger notifications via webhook (HMAC-SHA256 signed), Slack (Block Kit), or PagerDuty (Events API v2). CRUD endpoints at `/api/v1/circuit-breaker/notifications`. Includes SSRF protection (private IP rejection) and retry with exponential backoff.
- **SDK circuit breaker observability**: New methods across all 4 SDKs: `GetCircuitBreakerStatus`, `GetCircuitBreakerHistory`, `GetCircuitBreakerConfig`, `UpdateCircuitBreakerConfig`.

#### Fixed

- **Customer Portal UI fixes**: SaaS dashboard rendering, navbar overflow on long org names, graceful 404 handling, sidebar navigation cleanup, and React hooks ordering fix.

#### Docs

- **Customer Portal access guide**: Step-by-step guide for enterprise portal authentication, JWT setup, and role-based access.

---

## [5.2.0] - 2026-03-14

### Community

#### Security

- **Proxy route authentication**: Agent gateway now validates client credentials on all proxied `/api/v1/*` routes before forwarding to backend services. Previously, proxy routes forwarded requests without authentication.
- **Proxy auth token hardening**: Reject static fallback proxy token when `AXONFLOW_INTERNAL_SERVICE_SECRET` is configured; only HMAC-signed tokens accepted in hardened deployments.

#### Added

- **Tool call audit endpoint**: `POST /api/v1/audit/tool-call` records non-LLM tool call audit entries (API calls, MCP executions, function invocations) for compliance tracking. Includes Basic auth enforcement and 1MB request body size limit.
- **Audit query SDK methods**: `GetAuditLogsByTenant` and `SearchAuditLogs` for programmatic audit log retrieval with pagination and filtering. Supported in all 4 SDKs (v4.1.0+).

#### Fixed

- Allow tenant/client ID mismatch on proxy-verified requests where the Agent maps client IDs to different tenant IDs (e.g., `healthcare-demo` -> `healthcare_tenant`)
- AWS Marketplace CloudFormation template updated to v5.0.0
- Deploy workflow resolves version from ECR instead of HEAD
- Migration 122 FK ordering fix + GCP secret backup docs

---

## [5.1.0] - 2026-03-12

### Community

#### Security

- **`check-input` parameter scanning**: The `check-input` endpoint now inspects `parameters` field values individually for SQLi, PII, and compliance violations. Previously, a caller could pass a benign `statement` while embedding payloads in parameters that bypassed all policy checks. Each parameter value is scanned independently by the static policy engine; string values are scanned directly, nested objects/arrays are JSON-serialized before scanning, numeric values are converted to strings for PII/compliance detection, and boolean values are skipped.

#### Added

- **Audit: parameter tracking in MCP query audits**: Added `parameters_hash` (SHA-256) and `parameter_count` columns to `mcp_query_audits` table for forensic analysis of check-input requests. Migration: `057_mcp_audit_parameters.sql`
- **Dynamic policy: parameter condition fields**: Dynamic policies can now match on `parameters.<key>` (individual parameter values) and `parameter_count` (number of parameters) as condition fields

### Enterprise

#### Added

- **Execution Timeline page**: New customer portal page showing unified MAP and WCP execution history with real-time status, step-level drill-down, cost tracking, and policy decision visibility. Supports filtering by execution type and status, pagination, and keyboard-accessible expandable rows.
- **HITL Approval Flow Dashboard**: New customer portal page for human-in-the-loop approval queue management. Displays pending approval steps with workflow context, policy triggers, and matched policies. Supports approve/reject with mandatory justification, expandable detail panels with step input inspection, and real-time badge count polling in navigation. Migration `058_approval_justification.sql` adds `approval_comment` column to `workflow_steps`.
- **Enterprise portal documentation**: Added enterprise docs for Execution Timeline and Approval Dashboard. Fixed OpenAPI spec paths and added `minLength` constraints on approval comment/reason fields.

---

## [5.0.0] - 2026-03-09

### Community

#### Breaking Changes

- **Removed `total_steps` from `CreateWorkflowRequest` API**: The field was deprecated since Platform v4.5.0. Total steps are now exclusively auto-computed when the workflow reaches a terminal state (completed, aborted, or failed). Clients sending `total_steps` in create requests will have the field silently ignored. The `total_steps` field remains in `WorkflowStatusResponse`.
- **MCP `operation` default changed from `"query"` to `"execute"`**: `mcpCheckInputHandler` now defaults to `"execute"` when no `operation` is specified. Callers relying on the implicit `"query"` default must now pass `operation: "query"` explicitly.

#### Added

- **Python SDK: MCP Tool Interceptor**: New `mcp_tool_interceptor` factory method on `AxonFlowLangGraphAdapter` for enforcing AxonFlow input/output policies around MCP tool calls in LangGraph agents. Includes `MCPInterceptorOptions` configuration and JSON serialization fix.
- **Python LangGraph MCP Interceptor Example**: New example demonstrating MCP input/output policy checks integrated into a LangGraph agent with tool interception

#### Fixed

- Community sync workflow: include `docs/tutorials/` in sync using include-before-exclude rsync pattern
- Community sync workflow: fixed commit detection to use merged PRs instead of workflow runs, fixed pathspec with positive `.` anchor
- Community sync workflow: fixed jq parse error, split detection step permissions, added GH_TOKEN to sync step
- Restored historical version annotations incorrectly bumped in docs sweep

### Enterprise

#### Fixed

- Customer portal UI: removed vulnerable `@tootallnate/once` dependency

### Note

This major version also formally acknowledges a breaking change shipped in a prior minor release:
- `MediaAnalysisResult.extractedText` replaced by `hasExtractedText` + `extractedTextLength` (v4.4.0)

---

## [4.8.0] - 2026-03-03

### Community

#### Added

- **External Trace ID for Workflows**: Add optional `trace_id` field to workflows for correlation with external tracing systems (Langsmith, Datadog, OpenTelemetry)
 - `trace_id` on `CreateWorkflowRequest` and `CreateWorkflowResponse`
 - `trace_id` on `WorkflowStatusResponse` and `GET /workflows` query parameter
 - Partial index on `trace_id` column for query performance (NULL values not indexed)
 - Migration 055: `ALTER TABLE workflows ADD COLUMN trace_id VARCHAR(255)`
- **Per-Tool Governance (Phase 1)**: Add `ToolContext` to step gate requests for tool-aware policy evaluation within tool_call steps
 - New `ToolContext` struct: `tool_name`, `tool_type` (function/mcp/api), `tool_input`
 - Policy adapter propagates tool context into policy evaluation (tool_name, tool_type, tool_input.* keys)
 - Optional field - fully backward compatible with existing SDKs
 - Phase 1 (context enrichment) and Phase 2 (tool-scoped policies, future)
- **Per-Tool Governance Example**: New `langgraph_tools_example.py` demonstrating `check_tool_gate` and `tool_completed` for individual tool invocations within a LangGraph tools node
- **SDK-Platform Version Discovery**: Health endpoints now report real platform version, capability registry, and SDK compatibility information
 - `/health` response includes `version` (from `AXONFLOW_VERSION` env var), `capabilities` array, and `sdk_compatibility` object
 - Capability registry lists all platform features with the version that introduced them (15 capabilities from v1.0.0 through v4.8.0)
 - `sdk_compatibility` reports `min_sdk_version` and `recommended_sdk_version` for programmatic upgrade guidance
 - Applies to both Agent and Orchestrator health endpoints
- **Version Check Examples**: New `examples/version-check/` with HTTP, Go, Python, TypeScript, and Java variants demonstrating capability discovery
- **Compatibility Matrix**: New `docs/COMPATIBILITY_MATRIX.md` mapping platform versions to minimum SDK versions
- **SDK Telemetry Documentation**: New `docs/TELEMETRY.md` and `docs/TELEMETRY_CONTRACT.md` describing what SDK telemetry collects (version, OS, architecture), what is never collected (prompts, payloads, PII, API keys), defaults by deployment mode, and opt-out methods (`AXONFLOW_TELEMETRY=off` or `DO_NOT_TRACK=1`)

#### Changed

- **WCP Examples Updated**: All 6 existing workflow-control examples (Go, Python, Python LangGraph, TypeScript, Java, HTTP) updated with trace_id support and verification assertions

#### Fixed

- **Hardcoded health endpoint versions**: Agent and Orchestrator `/health` previously returned `"1.0.0"` regardless of actual platform version
- **Dockerfile version labels**: Agent and Orchestrator Dockerfiles now use `AXONFLOW_VERSION` build arg with `ENV` propagation for runtime access

### Enterprise

#### Added

- **SDK Telemetry Checkpoint Service**: New Lambda service at `checkpoint.getaxonflow.com` for anonymous SDK runtime telemetry
 - `POST /v1/ping` receives SDK telemetry, stores in DynamoDB, returns latest version info
 - `GET /v1/version` returns latest SDK versions (cacheable)
 - Privacy-preserving: IPs hashed (SHA256), 90-day TTL, no PII stored
 - Terraform infrastructure: Lambda, API Gateway, DynamoDB, CloudWatch alarms
- **Per-Tool Governance Policy Adapter**: `wcp_policy_adapter.go` propagates `ToolContext` fields into the dynamic policy evaluation context, enabling tool-aware governance rules
- **Evaluation Tier Feature Unlock**: Three high-impact features unlocked for Evaluation license holders, giving evaluators immediate demo value for governance control, safety simulation, and compliance proof
 - **HITL Approval Gates**: `require_approval` policy action now routes to a real HITL queue with Evaluation+ licenses. Approve/reject API, max 100 pending approvals, 24h fixed expiry with auto-reject, expiry cleanup goroutine
 - **Policy Simulation + Impact Report**: Two new endpoints for dry-run policy evaluation
 - `POST /api/v1/policies/simulate`: Run all active policies against input (Evaluation: 300/day, Enterprise: unlimited)
 - `POST /api/v1/policies/impact-report`: Test a single policy against N inputs with aggregate stats (Evaluation: 50 inputs, Enterprise: 100)
 - **Evidence Export Pack**: Bundled JSON export of audit logs, workflow steps, and HITL approvals
 - `POST /api/v1/evidence/export`: Synchronous JSON export with date range and type filters (Evaluation: 5K records, 14-day window, 3/day; Enterprise: unlimited, no watermark)
 - `GET /api/v1/evidence/summary`: Counts by evidence type within the tier's lookback window
 - Evaluation exports include `"NOT FOR REGULATORY SUBMISSION"` watermark; Enterprise exports are clean
 - Updated `TierLimits` struct with 9 new fields for feature gating
 - Updated `LicenseChecker` interface with 9 new methods
 - MaxPendingApprovals for Evaluation tier raised from 25 → 100
 - Database migration 056: `evidence_exports` table for export tracking and rate limiting
 - OpenAPI spec updated with 4 new endpoint definitions

---

## [4.7.0] - 2026-02-28

### Community

#### Added

- **Standalone MCP Policy-Check Endpoints**: Two new endpoints for external orchestrators (LangGraph, CrewAI) to validate MCP requests and responses against AxonFlow policies without executing connector queries
 - `POST /api/v1/mcp/check-input`: Validate SQL/commands against input policies (SQLi detection, dangerous query blocking, PII in queries, dynamic policies). Returns `allowed: true` or `403` with `block_reason`
 - `POST /api/v1/mcp/check-output`: Validate response data against output policies (PII redaction, exfiltration limits, dynamic policies). Returns original or redacted data with `policy_info`
 - Supports both query-style (`response_data`) and execute-style (`message` + `metadata`) output validation
 - Full audit logging for both endpoints
 - 1033-line test suite covering both endpoints with edge cases
- **MCP Check Endpoint Examples**: Full examples in 6 language variants - HTTP curl scripts, Python SDK, Python-HTTP (raw requests), Go SDK, TypeScript SDK, Java SDK
- **OpenAPI Spec for MCP Check Endpoints**: 4 new schemas (`MCPCheckInputRequest`, `MCPCheckInputResponse`, `MCPCheckOutputRequest`, `MCPCheckOutputResponse`) added to `agent-api.yaml`

#### Fixed

- **Python-HTTP MCP check example**: Added standalone `python-http/` variant with `requirements.txt` and virtual environment setup; refactored Python SDK example for clarity

#### Security

- **CVE-2026-24051**: Bumped `go.opentelemetry.io/otel/sdk` v1.38.0 → v1.40.0 in platform module (HIGH - OTel SDK resource attribute injection)
- **GHSA-72hv-8253-57qq**: Overrode transitive `jackson-core` 2.17.0 → 2.18.6 across 69 Java example pom.xml files (HIGH - async JSON parser `maxNumberLength` bypass)
- **OpenTelemetry BOM**: Added `opentelemetry-bom` dependency management to all Java examples for transitive CVE remediation

### Enterprise

#### Added

- **Circuit Breaker Pipeline Wiring** (#1176, Phase 1): Wire existing circuit breaker state machine into the Agent request pipeline - previously `Check`, `RecordError`, `RecordPolicyViolation` were dead code
 - `CB.Check` runs before policy evaluation in both `clientRequestHandler` and `handlePolicyPreCheck` - returns HTTP 503 with dynamic `Retry-After` header when circuit is open
 - `RecordPolicyViolation` called on every policy block, tracking violations toward auto-trip threshold (default: 20 violations in 5 minutes)
 - Active circuits loaded from DB on startup for restart persistence; background goroutine expires circuits every minute for auto-recovery
 - Community stubs added (`Check`, `IsAllowed`, `RecordError`, `RecordPolicyViolation`, `LoadCircuits`, `ExpireCircuits`) - no-op, always allowed
 - Example README updated with correct endpoint names and auto-trip documentation; shell script updated with auto-trip demonstration

---

## [4.6.0] - 2026-02-26

### Community

#### Fixed

- **Open-ended WCP workflows require hardcoded `total_steps`**: `total_steps` is now optional in `CreateWorkflow`. Omitting it (or passing `null`) creates an open-ended workflow - the step count is finalised automatically to `current_step_index` when the workflow reaches any terminal state (completed, aborted, or failed). Fixes LangGraph adapter use case where the graph iterates an unknown number of times. LangGraph example updated to omit `total_steps`; OpenAPI spec and guide updated

### Enterprise

#### Added

- **Cloud Storage Backends for Audit Exports**: S3, Azure Blob Storage, and GCS implementations of `StorageBackend` for durable, compliance-grade audit log export storage
 - S3: SSE-KMS encryption, Object Lock (WORM compliance), presigned URL downloads, configurable retention
 - Azure Blob Storage: SAS URL generation, shared key and connection string authentication
 - GCS: Signed URL generation, ADC / credentials file / credentials JSON authentication
 - Factory constructor: `AUDIT_EXPORT_STORAGE_TYPE` env var selects backend (`s3` | `azure` | `gcs` | `local`)
 - MinIO integration: Docker Compose enterprise config with MinIO for local S3-compatible testing
- **RBI Audit Export to Cloud Storage**: `AuditExportService` uploads exports to configured cloud backend, generates presigned download URLs on-demand, and manages cloud lifecycle (delete, cleanup expired). New `download_url`, `storage_type`, `storage_key` columns on `rbi_audit_exports`. Download handler returns HTTP 307 redirect for cloud exports. Falls back to local filesystem when no backend configured
- **SEBI Audit Export to Cloud Storage**: Large exports (>1000 records) automatically uploaded to cloud storage with presigned URL population. Small exports retain inline data response
- **EU AI Act Export to Cloud Storage**: `ExportService` wired with `StorageBackend` for cloud uploads during async export processing. Download handler generates presigned URLs for cloud-stored exports. New `download_url`, `storage_type`, `storage_key` columns on `euaiact_exports`
- **RBI Module Consolidation**: RBI module merged into `ee/` Go module - removed separate `go.mod`/`go.sum`, aligning with SEBI/EUAIACT/MASFEAT which already share the `ee/` module
- **Compliance Examples**: `audit-export-cloud/` examples (HTTP, Go, Python, TypeScript, Java) demonstrating full round-trip cloud export with presigned URL download and checksum verification

#### Fixed

- **India PII detector test failures**: 5 pre-existing test expectations corrected - UPI positive indicator precedence, sequential bank account rejection, Verhoeff all-zeros checksum, short bank account masking, `extractContext` boundary calculation

---

## [4.5.0] - 2026-02-22

### Community

#### Added

- **Media Governance Policy Engine**: Tiered media governance with system-managed policies
 - 5 default media governance rules seeded automatically: NSFW blocking, violence warning, biometric audit, PII blocking, sensitive document detection
 - Media governance enable/disable: Community deployments opt-in via `MEDIA_GOVERNANCE_ENABLED=true` environment variable
 - Media governance status API: `GET /api/v1/media-governance/status` returns feature availability per tier
 - Media policy categories: `media-safety`, `media-biometric`, `media-pii`, `media-document`
 - System media policy toggle: All tiers can enable/disable system media policies
 - New examples: `media-governance-policies/` demonstrating policy CRUD and governance outcomes (HTTP, Go, Python, TypeScript, Java)
- **Per-Step Token Tracking**: `tokens_in`/`tokens_out` fields through the full WCP step execution pipeline - types, migration 051, repository, service, and all 3 tracker mapping paths
- **Per-Step Cost Tracking**: `cost_usd` field through the full WCP step execution pipeline - types, migration 052, repository, service, and tracker. MAP workflows already had cost tracking; WCP now has parity
- **MAP/WCP Step Result Sync**: `SyncStepResults` syncs step-level data (status, provider, model, tokens, cost) from `WorkflowExecution` to the unified execution tracker. Called from `executePlanHandler` before `SyncPlanStatus` in all 3 code paths
- **Prompt-Aware Cost Estimation**: `EstimatePlanCost` now uses actual step prompt length (`len(prompt)/4 + 50` input tokens) and `max_tokens` for output estimates, instead of hardcoded 1000/500. Output schema overhead calculated via `json.Marshal`. 5 new unit tests added
- **Stale Model ID CI Guardrail**: CI workflow scans docs and technical-docs markdown files on PRs for deprecated LLM model IDs. Fails CI when stale Anthropic, OpenAI, Ollama, or Bedrock model identifiers are introduced. Hardened with `fetch-depth: 0`, `rg` availability check, and runtime error handling

#### Fixed

- **StepComplete ignores post-execution metrics**: `MarkStepCompleted` handler silently dropped request body - `tokens_in`, `tokens_out`, `cost_usd` were only set at gate time, never updated at completion. Now accepts `StepCompleteRequest` with actual post-execution values that override gate-time estimates via COALESCE. Also stores `step_output` (migration 054). All 4 SDKs updated on v3.6.0 branches
- **Execution viewer token/cost rendering**: Token display showed "undefined" when value was `0` (used `!= null` check and `?? 0` nullish coalescing). Cost display skipped legitimate `$0.0000` values. Policy events rendered blank rows due to type mismatch between `[]string` and expected objects
- **WCP gate decisions invisible in unified execution**: `Decision`, `DecisionReason`, `PoliciesMatched`, `ApprovalStatus`, `ApprovedBy` were never mapped into unified `StepStatus`. Added conversion helpers: `extractPolicyNames`, `mapWCPGateDecision`, `mapWCPApprovalStatus`
- **Step status clobbering**: `BaseExecutionTracker.AddStep` unconditionally overwrote step status to `pending`, discarding WCP-computed status. Now preserves pre-set status
- **Execution cost null in API**: `actual_cost_usd` always null in API responses. Added `TotalCost` calculation in `resolveExecution` and `ListExecutions`
- **WCP steps stuck at "running"**: Steps remained in running state when workflow completed. Replaced O(n) `ListExecutions` scan with O(1) indexed `GetByMetadata` lookup
- **Cost estimation used hardcoded tokens**: `EstimatePlanCost` ignored `Prompt` and `MaxTokens` fields on `WorkflowStep`, always using 1000/500. All 5 cost-estimation examples sent non-existent `estimated_tokens_in`/`estimated_tokens_out` fields silently dropped by JSON unmarshaling

#### Changed

- **LLM Model ID Sweep**: ~200 files updated across code defaults, pricing tables, tests, examples, infrastructure, and technical docs. Migration 053 updates COALESCE default for Bedrock model in `llm_provider_configs`
 - Anthropic: `claude-3-*`/`claude-3-5-*` → `claude-opus-4-20250514`/`claude-sonnet-4-20250514`/`claude-haiku-4-5-20251001`
 - Bedrock: Updated to region-prefixed inference profile IDs (`us.anthropic.claude-sonnet-4-20250514-v1:0` etc.)
 - OpenAI: `gpt-3.5-turbo` → `gpt-4o-mini`, `gpt-4-turbo` → `gpt-4o`
 - Ollama: `llama3.1` → `llama3.2`, `codellama` → `qwen2.5-coder:32b`, `mistral:7b` → `mistral:latest`, `mixtral:8x7b` → `mixtral:latest`
- **LLM provider diversity in examples**: 20 WCP and HITL example files updated from hardcoded `openai/gpt-4` to a mix of providers (ollama, anthropic, gemini, bedrock, azure) demonstrating provider-agnostic governance
- **Execution viewer UI**: Wired to unified execution API (`/api/v1/unified/executions`) with correct field mappings, gate decision/approval display, and step_index handling
- Media governance disabled by default on Community tier - previously ran globally if analyzers were registered
- Dynamic policy API (`/api/v1/dynamic-policies`) now accepts `media-*` category prefixes alongside `dynamic-*`
- Dynamic policy listing now includes system/global policies alongside tenant policies
- Documentation: All LLM model references updated to current versions across docs and technical-docs
- SDK version references bumped to v3.5.0
- Docker base images: Go 1.25-alpine → 1.26-alpine for agent and orchestrator
- CI dependencies: `actions/github-script` 7→8, `docker/build-push-action` 5→6, `actions/upload-artifact` 4→6, `aws-actions/configure-aws-credentials` 4→6, `actions/download-artifact` 4→7 (#1197-#1201)

### Enterprise

#### Added

- **Per-Tenant Media Governance Configuration**: `GET/PUT /api/v1/media-governance/config` for enable/disable and analyzer restriction per tenant
- **System Media Policy Modification**: Enterprise tier can modify actions and priority on system media policies
- **Media Governance Audit Export**: `GET /api/v1/media-governance/audit/export` for compliance reporting (CSV/JSON)

#### Fixed

- **Customer portal Docker build failure**: `go.mod` in `ee/platform/customer-portal/` pinned `golang.org/x/crypto v0.45.0` while platform bumped to `v0.47.0` during v4.4.0 merge

### Breaking

- Community deployments that previously had media governance running globally must now set `MEDIA_GOVERNANCE_ENABLED=true` to opt back in

---

## [4.4.0] - 2026-02-18

### Community

#### Added

- **Multimodal Image Governance Pipeline**: Images are governed the same way as prompts - analyzed before routing, policies can block, and everything is audited.
 - `platform/orchestrator/media/` package: registry, factory, pipeline, audit, cost tracking, and license gating
 - Pluggable `MediaAnalyzer` interface with Name, Type, Analyze, HealthCheck, Capabilities
 - Local OCR analyzer via Tesseract (`exec.CommandContext`, stdin/stdout, no temp files)
 - PII detection via composition - OCR text feeds existing `PIIDetectorFunc`, no drift
 - Pipeline runs analyzers in parallel per image, aggregates worst-case signals
 - Community default: fail-open (warn and audit), never blocks
 - 11 policy fields: `media.has_pii`, `media.has_faces`, `media.nsfw_score`, `media.violence_score`, `media.content_safe`, `media.has_biometric_data`, `media.is_sensitive_document`, `media.document_type`, `media.face_count`, `media.has_extracted_text`, `media.extracted_text_length`
 - API: `media` array on request, `media_analysis` object on response with per-image results
 - SHA-256 hashing for base64 and URL-sourced images (URL download with 30s timeout, 20MB limit, cached)
 - Validation: MIME type allowlist, max 20MB per image, max 8192px per dimension, max 10 images per request
 - Audit logging: hash, MIME type, file size, PII detection, content safety, timing (Enterprise adds biometric, safety scores, per-analyzer details)
 - New examples in 5 languages (HTTP/curl, Go, Python, TypeScript, Java) with strict field validation
- **SDK Media Types**: All 4 SDKs updated with `MediaContent`, `MediaAnalysisResult`, `MediaAnalysisResponse`
 - Go: `ProxyLLMCallWithMedia` method
 - Python: `proxy_llm_call_with_media` async + sync, caching disabled for media requests
 - TypeScript: media support in `proxyLLMCall` options
 - Java: media in `ClientRequest.Builder`

### Enterprise

#### Added

- **Cloud Media Analyzers** (build tag `enterprise`): AWS Rekognition, Google Cloud Vision, Azure Computer Vision
- **Biometric and NSFW detection**: Face detection with count, NSFW and violence scoring, biometric data detection
- **Document classification**: Sensitive document detection (tax forms, medical records, bank statements, etc.)
- **Rich audit fields**: Per-analyzer details, biometric data, safety scores, document classification (gated behind `isEnterprise`)
- **Fail-closed enforcement**: Configurable to block requests when media analysis fails (Enterprise only)

#### Changed (Hardening)

- **Structured warning codes**: All media warnings now include a `code` + `message` (e.g., `WarnMediaAnalyzerError`). Both `warnings` (string array, backward-compatible) and `structured_warnings` (code/message objects) are returned in API responses.
- **Pre-decode base64 size check**: Oversized base64 payloads rejected before decode (avoids memory allocation).
- **Base64 decoded bytes cache**: Decoded bytes from `Validate` are reused by `ComputeSHA256` and `GetRawData`, eliminating redundant base64 decoding.
- **Decompression bomb guard**: Images exceeding 100M pixels are rejected via `image.DecodeConfig` header check (fail-open for unparseable formats). New error code `ErrMediaDecompressionBomb`.
- **Analyzer concurrency cap**: Default max 10 concurrent analyzers per image via semaphore (configurable via `WithMaxConcurrentAnalyzers`).
- **Context cancellation**: Pipeline respects `ctx.Done` during result collection; fail-open returns partial results with `WarnMediaPartialResults`, fail-closed returns error.
- **Deterministic analyzer result ordering**: `AnalyzerResults` sorted by `AnalyzerName`.
- **Fail-closed when no analyzers**: If enforcement is fail-closed and no analyzers are registered, pipeline returns error instead of empty results.
- **Orchestrator fail-closed handler**: When media analysis fails in fail-closed mode, orchestrator responds `403 Forbidden`.
- **Audit redaction**: Enterprise audit records redact `ExtractedText` to `[redacted: N chars]` and `PIIFinding.Value` to `[redacted]`.
- **SDK cache skip for media**: Go and Java SDKs skip response caching when media is present (binary content makes cache keys unreliable).

#### Breaking

- **`extracted_text` removed from API responses and policy context.** Replaced by `has_extracted_text` (bool) and `extracted_text_length` (int). Existing policies referencing `media.extracted_text` must be updated to use `media.has_extracted_text` or `media.extracted_text_length`.

---

## [4.3.1] - 2026-02-16

### Community

#### Fixed

- **Execution cost always $0.0000**: `recordStepSnapshot` now calculates actual cost from tokens using pricing config instead of leaving `CostUSD` as zero. Costs visible in Execution Viewer UI and API responses
- **Router cost used pre-execution estimates**: LLM router now uses actual response token counts for cost calculation instead of pre-execution estimates, with fallback for providers that only report total tokens

---

## [4.3.0] - 2026-02-13

### Community

#### Fixed

- **WCP error sentinel consistency (Bugs A, I)**: All repository methods (`CompleteWorkflow`, `AbortWorkflow`, `FailWorkflow`, `ResumeWorkflow`) now wrap `ErrWorkflowNotFound` with `%w` instead of creating new errors. `errors.Is(err, ErrWorkflowNotFound)` works correctly across all WCP operations. Added missing `rows.Err` checks in `List`, `GetStepsForWorkflow`, `GetPendingApprovals`.
- **MAP execution tracking accuracy (Bugs C, D)**: `SyncPlanStatus` replaced O(n) `ListExecutions` scan with direct `GetExecutionByPlanID` lookup using new GIN index on `metadata->>'plan_id'`. Expired plans now tracked as `expired` status instead of incorrectly mapping to `completed`.
- **StepModeEvaluator idempotency (Bug J)**: Step gate evaluation keyed on `(planID, stepIndex)` via `sync.Map` instead of a plain counter. Retries return the cached decision instead of advancing the counter.
- **Connection tracker tenant validation (Bug K)**: SSE connections with missing `X-Tenant-ID` header now return `400 Bad Request` instead of silently falling back to a shared `"default"` bucket.
- **SyncPlanStatus error visibility (Bug L)**: `SyncPlanStatus` errors logged as warnings instead of silently discarded via `_ =`.
- **json.Marshal error handling (Bug B)**: Abort and fail reason marshaling errors in WCP repository now propagated instead of suppressed with `_:=`.

#### Added

- **Cost Estimation Endpoints**: Pre-execution cost analysis for MAP plans
 - `POST /api/v1/plans/estimate`: Estimate cost from provider/model/steps specification
 - `GET /api/v1/plans/{id}/cost`: Get cost estimate for an existing plan
 - Tiered response: community gets aggregate total only (10/day), evaluation gets per-step breakdown (100/day), enterprise unlimited
- **WCP Community Approve/Reject**: Basic approval flow via step gates with HITL status endpoint (`GET /api/v1/hitl/status`)
 - Tiered limits: community max 5 pending approvals, evaluation max 25, enterprise unlimited
- **Direct Metadata Lookup**: `GetExecutionByPlanID` and `GetExecutionByMetadata` methods for efficient execution lookups
- **Expired Execution Status**: `ExecutionStatusExpired` constant and `ExpireExecution` method for proper lifecycle tracking
- **Migration 050**: GIN index on `execution_history.metadata->>'plan_id'`, `expired` enum value for `execution_status`
- **New examples**: `workflow-fail/`, `cost-estimation/`, `hitl-queue/` across Go, Python, TypeScript, Java, and HTTP

### Enterprise

#### Added

- **MAP-HITL Integration**: Enterprise HITL approval workflow for MAP plan steps
 - `POST /api/v1/plans/{id}/steps/{step_id}/approve` and `reject` endpoints
 - `HITLWorkflowEngine` wired when enterprise license present
 - Community mode returns 403 for HITL endpoints
- **HITL Expiration Background Job**: Automatic expiration of stale approval requests
 - 1-hour ticker interval with configurable schedule
 - `ExpireRequests` method in service and repository layers
 - Graceful shutdown via stop channel
- **HITL Queue API in SDKs**: All 4 SDKs now include HITL queue methods (list, get, approve, reject, stats)
- **New enterprise examples**: `ee/examples/hitl-queue/`, `ee/examples/hitl-expiration/`, `ee/examples/map-hitl/`, `ee/examples/cost-estimation-enterprise/`, `ee/examples/tier-limits/`

---

## [4.2.2] - 2026-02-12

### Community

#### Fixed

- Unified execution `CancelExecution` and `StreamExecutionStatus` endpoints returned 404 when given a WCP workflow ID or MAP plan ID. Now uses the same multi-strategy resolution as `GetExecutionStatus` (direct ID → WCP tracker → MAP tracker → metadata fallback)
- Execution history FK constraint on `tenant_id` prevented record creation in community mode when SDK sends a default client ID. Dropped FK constraint in favor of RLS policy for tenant isolation (migration 049)

## [4.2.1] - 2026-02-10

### Community

#### Fixed

- `FailWorkflow` missing webhook notification, audit log, and HTTP endpoint (`POST /api/v1/workflows/{id}/fail`)
- WCP example fixes: TypeScript `PendingApprovalsResponse.items` → `.approvals`, Java `WorkflowStatus` enum-to-string comparison

#### Added

- FailWorkflow test coverage across all 5 WCP examples and 4 webhook unit tests with `MockWebhookNotifier`

---

## [4.2.0] - 2026-02-10

### Community

#### Added

- **Evaluation Tier Licensing**: Free 90-day license with elevated limits for production proof-of-concepts
 - Request at [getaxonflow.com/evaluation-license](https://getaxonflow.com/evaluation-license)
 - Limits: 50 tenant policies, 5 org policies, 5 connectors with custom policies, 3 LLM providers, 14-day audit retention, 100 plans, 25 versions/plan
 - Graceful degradation to Community tier on expiry. No downtime, no data loss
- **Ed25519 License Signing**: Asymmetric cryptographic signatures replace HMAC-SHA256
 - Public keys embedded in binary; private keys stay in infrastructure (AWS Secrets Manager)
 - Format: `AXON-{PAYLOAD}.{SIGNATURE}`. Old V2 (`AXON-V2-.`) and V1 formats rejected with clear upgrade message
 - Two keypairs: evaluation (for free licenses) and enterprise (for paid licenses). Blast radius isolation
- **Feature Limits Boundary Testing**: `examples/feature-limits/http/test_feature_limits.sh` validates all tier limits across Community, Evaluation, and Enterprise modes
- **E2E Setup Script**: `scripts/setup-e2e-testing.sh` now supports `evaluation` mode alongside `community` and `enterprise`
- **Workflow Control Plane v1**: Governance gates for external orchestrators (LangChain, LangGraph, CrewAI)
 - `POST /api/v1/workflows`: Register workflow with name, source, total_steps, metadata
 - `GET /api/v1/workflows`: List workflows with status/source filters
 - `GET /api/v1/workflows/{id}`: Get workflow status and step history
 - `POST /api/v1/workflows/{id}/steps/{step_id}/gate`: Policy-based step gate (allow/block/require_approval)
 - `POST /api/v1/workflows/{id}/steps/{step_id}/complete`: Mark step completed with output data
 - `POST /api/v1/workflows/{id}/complete`: Mark workflow completed
 - `POST /api/v1/workflows/{id}/abort`: Abort workflow with reason
 - `POST /api/v1/workflows/{id}/resume`: Resume after approval
 - Step gate responses include `policies_evaluated` and `policies_matched` for policy transparency
 - Audit logging: `workflow_created`, `workflow_step_gate`, `workflow_completed`, `workflow_aborted`
- **MAP Plan Versioning & Rollback**: Full plan lifecycle management with optimistic locking
 - `UpdatePlan`: Update plan with version conflict detection (`ErrVersionConflict` on mismatch)
 - `GetPlanVersions`: Retrieve full version history with change tracking (changed_by, change_type, change_summary)
 - `RollbackPlan`: Restore to a previous version snapshot (creates pre-rollback snapshot first)
 - `CleanupExpiredPlans`: Background worker removes expired plans (configurable interval, default 15min)
 - Community limits: max 25 plans with versioning, max 10 versions per plan
 - Migration `047_plan_versioning.sql`: adds `version` column to plans, creates `plan_versions` table
- **MAP Confirm & Step Execution Modes**: HITL execution modes via WCP infrastructure
 - Confirm mode: every step requires explicit approval before proceeding
 - Step mode: first step auto-allowed, subsequent steps require approval
 - Creates WCP workflow (`map-confirm-{planID}` / `map-step-{planID}`) to track step gates
 - Maps plan steps to WCP step types (llm-call, tool-call, connector-call, etc.)
- **MAP Plan Cancellation**: `PlanStatusCancelled` constant and `CancelPlan` method in planning service
- **Unified Execution Tracking**: Consistent status tracking across MAP plans and WCP workflows
 - `GET /api/v1/unified/executions`: List executions with type/status filters
 - `GET /api/v1/unified/executions/{id}`: Get status by execution ID, workflow ID, or plan ID
 - `POST /api/v1/unified/executions/{id}/cancel`: Cancel execution (propagates to MAP or WCP)
 - MAPExecutionTracker: adapts planning service to unified format, syncs plan state changes
 - WCPExecutionTracker: adapts WCP service to unified format, maps step decisions to unified status
 - Lookup by execution ID, `wf_*`/`wcp_*` prefix, `plan_*` prefix, or metadata search
- **SSE Execution Streaming**: `GET /api/v1/unified/executions/{id}/stream` provides real-time execution events
 - Events: `execution.started`, `execution.completed`, `execution.failed`, `execution.cancelled`, `step.started`, `step.completed`, `step.failed`, `step.decision`
 - Auto-closes on terminal state; no external dependencies (pure Go channels)
 - Per-tenant connection limits: Community (5), Evaluation (25), Enterprise (unlimited)
 - HTTP 429 with `Retry-After: 30` header when limit exceeded
 - `ConnectionTracker` with atomic acquire/release pattern (handles disconnect, timeout, panic)
- **EventHub Pub-Sub**: Channel-based event bus in `platform/shared/execution/event_hub.go`
 - Buffered channels (cap 16), non-blocking publish with slow subscriber protection
 - Both MAP and WCP trackers publish events on state transitions
- **Unified Execution Handler Tests**: Tests covering list, get, cancel, CORS, and route registration
- **CancelPlan Tests**: 6 tests covering cancel from pending/executing states, validation
- **Cost Estimation**: `GET /api/v1/plans/{id}/cost` and `POST /api/v1/plans/estimate` for pre-execution cost estimation with per-step breakdowns
- **MAP + WCP Examples**: `map-confirm-mode/`, `map-lifecycle/`, `workflow-control/` across all 5 languages (Go, Python, TypeScript, Java, HTTP)

#### Fixed

- **Tenant ownership check on unified execution endpoints**: Execution list/get/cancel now validates tenant ownership, preventing cross-tenant data access
- **Agent gateway always returned `success: true`**: Orchestrator errors (409 cancelled, 410 expired, 403 blocked) were buried in nested response data. Agent never propagated them to `ClientResponse`. SDKs never raised exceptions for failed operations. Also fixed metrics counting errors as successes and usage recorder status codes.
- **MAP confirm mode not enforced**: `ConfirmModeEvaluator` was defined but never wired into WCP `StepGate`. Policy engine always returned "allow" instead of "require_approval". Fixed by adding `GateOverride` to `StepGateRequest`, used by `ExecuteWithConfirm` and `resumePlanHandler`.
- **MAP execution timeout too tight**: Hardcoded 60s timeout caused `context deadline exceeded` on multi-step balanced mode plans. Now scales to 30s per step with 60s minimum floor.
- **Examples hardcoded user tokens**: All examples now read `AXONFLOW_USER_TOKEN` env var with safe community defaults
- **25 broken documentation links**: Replaced stale `docs.getaxonflow.com` URLs across 15 markdown files
- **Down migrations 045/046 destructive**: Replaced destructive Down sections with no-ops to prevent CI `psql -f` from reversing Up migrations

#### Changed

- **License format migration**: All licenses must use Ed25519 format (`AXON-{PAYLOAD}.{SIGNATURE}`). Old V2 HMAC format (`AXON-V2-.`) returns Community tier with upgrade guidance. No action needed for users without a license (Community mode unchanged).
- **HMAC startup check removed**: `ValidateHMACSecretAtStartup` is now a no-op. No HMAC secret environment variable required at startup
- **BaseExecutionTracker**: Now publishes events via EventHub after every state change (start, complete, fail, cancel, step transitions)
- **UnifiedExecutionHandler**: Accepts EventHub and PlanService; registers cancel, stream, and list/get routes
- **Updated with SSE streaming, cancellation, and versioning architecture patterns
- **License tier names normalized**: `PRO`→`Professional`, `ENT`→`Enterprise`, `PLUS`→`Plus`, `BASIC`/`EVALUATION`→`Evaluation`. Migration 122 updates all tier-related tables. DB constraint enforces canonical names.
- **SDK versions bumped to v3.3.0** across all examples and docs
- **CI dependencies bumped**: actions/checkout v6, actions/setup-go v6, Go 1.25, Docker Alpine 3.23
- **Coverage thresholds raised to 76%** for orchestrator and connectors modules
- **Documentation quality improved** across 36 files: correct auth patterns, SDK method names, "source-available" terminology, current versions

### Enterprise

#### Added

- **WCP HITL Approval Gates**: Human-in-the-loop approval for workflow steps
 - `POST /api/v1/workflows/{id}/steps/{step_id}/approve`: Approve a pending step (requires approval_id from gate)
 - `POST /api/v1/workflows/{id}/steps/{step_id}/reject`: Reject step with optional reason
 - `GET /api/v1/workflows/approvals/pending`: List all workflows awaiting human approval
 - Approval URLs generated for notification links
- **Webhook Notification System**: Event-driven notifications for workflow and approval events
 - `POST /api/v1/webhooks`: Create webhook subscription
 - `GET /api/v1/webhooks`: List subscriptions
 - `GET /api/v1/webhooks/{id}`: Get subscription details
 - `PUT /api/v1/webhooks/{id}`: Update subscription
 - `DELETE /api/v1/webhooks/{id}`: Delete subscription
 - 7 event types: `step.approval_required`, `step.approved`, `step.rejected`, `step.completed`, `workflow.completed`, `workflow.aborted`, `workflow.failed`
 - HMAC-SHA256 request signing when secret configured; secret never exposed in API responses
 - SSRF protection: blocks private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8)
 - Retry strategy: exponential backoff (1s, 2s, 4s), max 3 retries, 10s timeout per attempt
 - Migration `048_webhook_subscriptions.sql`: subscription and delivery tracking tables

---

## [4.1.0] - 2026-02-05

### Community

#### Added

- **AES-256-GCM Connector Credential Encryption**: Credentials encrypted at rest via `CONNECTOR_ENCRYPTION_KEY` env var
 - Credentials stored separately from connection URLs. No secrets in `connection_url` column
 - Supports encrypted, JSON-quoted encrypted, and plain JSON formats (backward compatible)
- **Connector SDK Runtime Wiring**: Connector installs persist to `connector_configs` table; Agent reads runtime configs from DB with static fallback
 - All SDK-backed connectors (Postgres, MySQL, MongoDB, Redis, Cassandra, HTTP) migrated to `connectors/sdk.BaseConnector`
 - Runtime config service loads connector credentials and options from DB, reconstructs connection URLs at runtime
- **LLM Provider SDK Registration**: SDK-backed LLM providers (OpenAI, Anthropic, Gemini) registered at orchestrator startup via factory pattern
 - Azure OpenAI runtime config parity across env/config/DB paths
- **Strict Provider Pinning**: `context.strict_provider=true` hard-pins to a specific provider; default remains preference with failover
- **Direct LLM Config Passing**: `BootstrapFromConfig` replaces goroutine-unsafe `ApplyLLMConfigToEnv` / `os.Setenv`
- **Atomic LLM Provider Update**: `Registry.Update` method prevents gap where provider is missing during reconfiguration
- **Audit Logging Examples**: Complete audit logging examples across Go, Python, TypeScript, Java SDKs
- **Testcontainers for Integration Tests**: PostgreSQL integration tests use testcontainers instead of mock DB
- **Runtime Connector Config Migrations**: `007_runtime_connector_configuration.sql`, `045_connector_configs_credentials.sql`

#### Fixed

- **Encrypted credentials never decrypted on load**: `RuntimeConfigService` now uses `CredentialEncryptor.Decrypt` instead of `json.Unmarshal`
- **MySQL DSN credentials persisted in stored URLs**: `StripURLCredentials` now handles `@tcp` and `@unix` DSN formats
- **Connector uninstall DB/registry divergence**: Unregister from memory first, then delete DB record
- **PII detection examples require `PII_ACTION=block`**: Updated examples and docs with prerequisite
- **Migration runner safety**: `_down.sql` files skipped by migration runner to prevent accidental rollbacks
- **Internal MCP calls carry tenant ID**: Orchestrator→Agent MCP calls now include tenant ID for correct access isolation

#### Changed

- **Connector install/uninstall requires `tenant_id`** when a DB is present: Prevents silent inconsistent state; matches schema constraints
- **`context.provider` remains preference**: Failover still default unless `strict_provider` is set
- **LLM provider runtime constraints**: Expanded allowed provider names to include `gemini`, `azure-openai`, and `custom`
- **Connector runtime constraints**: Expanded allowed connector types to include SDK-backed connectors (http/mysql/mongodb/redis/s3/etc)
- **SDK versions bumped to v3.2.0** across all examples and docs
- **README**: Design Partner program CTA, Feedback Week, LLM provider scope clarification

### Enterprise

#### Added

- **Enterprise runtime config bootstrap**: Ensures runtime connector/LLM config tables are created after `customers` exists
- **Bedrock example hardening**: Enterprise Bedrock example now uses standard env aliases + enterprise JWT for policy pre-checks

## [4.0.0] - 2026-02-03

### Community

#### Added

- **Configurable System Policy Architecture**: Per-mode policy control for MCP and Gateway modes
 - `MCP_STATIC_POLICIES_ENABLED` / `GATEWAY_STATIC_POLICIES_ENABLED`: enable/disable static policies per mode
 - `MCP_PII_ACTION` / `GATEWAY_PII_ACTION`: override PII action per mode (block/redact/warn/log)
 - `MCP_SQLI_ACTION` / `GATEWAY_SQLI_ACTION`: override SQLi action per mode
 - `MCP_STATIC_POLICIES_SKIP_CATEGORIES` / `GATEWAY_STATIC_POLICIES_SKIP_CATEGORIES`: skip specific categories
 - Env var precedence: mode-specific → global (`PII_ACTION`) → engine defaults
- **Policy Engine Consolidation**: Single evaluation path across all modes
 - Proxy, Gateway, and MCP all use `UnifiedPolicyEngine` as primary path (was three separate engines)
 - Standalone `AuditManager` decoupled from `DatabasePolicyEngine`; shared engine now receives audit adapter
 - Admin role handling via `SkipCategories` instead of engine-level role checks
- **MCP Execute Policy Responses**: `policy_info`, `redacted`, `redacted_fields` in MCP execute responses
- **Execution Replay CLI + Embedded Execution Viewer UI**:
 - `axonctl executions list/get/replay/export`: CLI commands for inspecting workflow executions from the terminal
 - Browser-based execution viewer at `/ui/executions/` via Go `embed.FS`. Filterable execution list, step timeline visualization, JSON export
 - Supports both MAP (Multi-Agent Planning) and WCP (Workflow Control Plane) executions
- **HMAC-Signed Internal Service Tokens**: HMAC-SHA256 signed tokens replace plain shared-secret for orchestrator-to-agent auth. 5-minute replay protection. Backward-compatible with deprecation warning.
- **Singapore PII patterns documentation**: SDK feature coverage docs updated with NRIC, FIN, UEN patterns

#### Fixed

- **Gateway pre-check ignoring `GATEWAY_STATIC_POLICIES_ENABLED=false`**: Fell through to `dbPolicyEngine` which didn't check the flag
- **Orchestrator ignoring action overrides**: `processWithSharedEngine` and `DetectWithSharedEngine` now respect per-mode config
- **Proxy mode ignoring per-mode policy config**: Now uses `UnifiedPolicyEngine` with `GATEWAY_*` env vars
- **Shared policy engine had nil audit queue**: Policy evaluations in MCP/Gateway now log through audit infrastructure
- **Dockerfile missing `/var/lib/axonflow/audit/`**: Audit queue fallback failed for non-root user
- **Gateway enterprise integration tests**: Fixed OAuth2 Basic auth with valid V2 license format
- **Marketplace connector persistence tests**: Fixed lazy-loaded connectors after `ReloadFromStorage`
- **HITL examples only tested CRUD**: All 4 SDKs now test actual enforcement via `ProxyLLMCall`

#### Changed

- **SDKs v3.0.0**: All four SDKs bumped to v3.0.0 (Python skips v2.0.0 for cross-SDK version consistency):
 - **Removed `executeQuery`** (deprecated since v2.5): Use `proxyLLMCall` for proxy mode or MCP connector queries
 - **TypeScript**: Removed 5 deprecated LLM interceptors, added `wasRedacted` helper
 - **Python**: Skipped v2.0.0 → v3.0.0 for consistency. Added `was_redacted`, fixed internal MCP call serialization, fixed null `policies_evaluated` validation
 - **Go**: Updated module path to `axonflow-sdk-go/v3`, added `WasRedacted`
 - **Java**: Removed `executeQuery`/`executeQueryAsync`, verified `isRedacted`
- **Gateway mode examples enhanced**: PII detection (SSN, India PAN, Aadhaar) and SQLi blocking (DROP TABLE, UNION SELECT) assertions added across all 4 SDKs
- **New examples**: `policy-configuration/` and `gateway-policy-config/` (Go, Python, TypeScript, Java)
- **Enhanced examples**: `pii-detection/`, `sqli-detection/`, `mcp-policies/`, `map/` updated with multi-action mode and `policy_info`

#### Breaking Changes

- **`executeQuery` removed from all SDKs**: Use `proxyLLMCall` or MCP connector queries. Deprecated since v2.5.
- **Env var behavior change**: Global detection env vars (`PII_ACTION`, `SQLI_ACTION`) now control the primary shared engine. Existing deployments may see different behavior in MCP and Gateway modes. Use mode-specific vars (`MCP_PII_ACTION`, `GATEWAY_PII_ACTION`) for precise control.

---

## [3.6.1] - 2026-01-30

### Community

#### Fixed

- **MCP Community Auth**: MCP query/execute endpoints incorrectly required license validation in community mode, returning HTTP 401
 - Replaced raw environment variable check with canonical `isCommunityMode` helper
 - Extracted duplicated license validation into shared `validateServiceLicense` helper
- **MAP Replay Recording**: Parallel execution path was missing replay recording. MAP executions left no trace in `execution_snapshots`
 - Added `StartExecution`, `recordStepSnapshot`, `CompleteExecution`/`FailExecution` calls to parallel path
- **MAP Parallel Data Race**: Input map shared across parallel goroutines without protection
- **MAP Silent Error Swallowing**: `FailExecution` errors silently discarded in 4 call sites
- **EU AI Act Export Data Race**: `CreateExport` returned shared pointer mutated by async goroutine, causing flaky tests under `-race`
- **Anthropic Default Model**: Updated default from `claude-3-5-sonnet-20241022` (404) to `claude-sonnet-4-20250514`

#### Added

- **HTTP Examples**: Added missing HTTP examples for `mcp-connectors` and `map` (completing 30/30 cross-language coverage)

### Enterprise

#### Fixed

- **V1 License Error Messaging**: Renamed error code to `V1_LICENSE_NOT_SUPPORTED`, removed internal tool paths from user-facing errors
- **DEPLOYMENT_MODE Case Handling**: Removed unnecessary case normalization in admin auth middleware

#### Security

- **Next.js** (GHSA-h25m-26qc-wcjf): Bumped in customer-portal-ui (16.0.10→16.1.6) and banking-demo (15.5.9→15.5.10)

---

## [3.6.0] - 2026-01-26

### Community

#### Added

- **Unified Execution Tracking**: Consistent status tracking for MAP plans and WCP workflows
 - New unified execution history table (`execution_history`) for both MAP and WCP executions
 - `GET /api/v1/executions/{id}` - Get unified execution status by ID
 - `GET /api/v1/executions` - List executions with type/status filters
 - `ExecutionType`: `map_plan`, `wcp_workflow`
 - `ExecutionStatusValue`: `pending`, `running`, `completed`, `failed`, `cancelled`, `aborted`, `expired`
 - `StepStatusValue`: `pending`, `running`, `completed`, `failed`, `skipped`, `blocked`, `approval`
 - `UnifiedStepType`: `llm_call`, `tool_call`, `connector_call`, `human_task`, `synthesis`, `action`, `gate`
 - Unified step tracking with duration, cost, and policy decision fields
 - SDK support in Go v2.7.0, Python v1.7.0, TypeScript v2.7.0, Java v2.7.0

- **Singapore PII Detection**: MAS FEAT compliance patterns for PII detection
 - NRIC pattern detection (S/T/M/F/G prefixes) with critical severity
 - FIN pattern detection (F/G prefixes) for foreign identification
 - UEN pattern detection for business entities
 - Singapore phone numbers (+65 format)
 - Singapore postal codes (6-digit)
 - Examples: Go, Python, TypeScript, HTTP

- **Compliance Policy Categories**: New policy category constants for compliance evaluation
 - Added `CategoryComplianceEUAIAct` and `CategoryComplianceMASFEAT` constants
 - Added `IsComplianceCategory` and `AllComplianceCategories` helper functions
 - RBI, SEBI, EU AI Act, and MAS FEAT categories evaluated at gateway and MCP handlers

- **Redis Policy Store**: Distributed rate limiting and budget tracking for MCP policies with automatic fallback

- **Budget Enforcement Wiring**: Budget limits now block requests when exceeded
 - Gateway calls `CheckBudget` before processing requests
 - HTTP 402 returned when budget exceeded with `on_exceed=block`
 - `X-Budget-Warning` header for `on_exceed=warn`
 - `BudgetInfo` in response

- **HITL Workflow Engine Wiring**: Human-in-the-Loop integrated with workflow execution
 - `ExecuteWithHITL` wired to production execution path
 - Enterprise: Database persistence; Community: In-memory with auto-approve

- **WCP to HITL Connection**: `require_approval` decisions create HITL queue entries

- **MAP Conditional Branch Execution**: Branches now execute steps, not just record intent

- **MAP Parallel Execution Tolerance**: Configurable `SoftFailureTolerance` replaces hardcoded logic

- **Policy Cache Refresh API**: Immediate policy availability after CRUD operations
 - New `PolicyEngineRefresher` interface for policy engines
 - `RefreshPolicies` method on both `DynamicPolicyEngine` and `DatabaseDynamicPolicyEngine`
 - `PolicyService` triggers refresh after create, update, delete, and import operations
 - Eliminates 30-second cache delay for WCP HITL integration

- **Dynamic Policy `require_approval` Action**: HITL trigger from dynamic policies
 - New `require_approval` action type in dynamic policy evaluation
 - Sets `Allowed=false` and adds `require_approval` to `RequiredActions`
 - Supports `reason` field in action config for approval context

- **Nested Context Path Support**: Enhanced dynamic policy field matching
 - `context.step_input.query` now correctly resolves to `req.Context["step_input.query"]`
 - Supports arbitrary depth in dotted notation (e.g., `context.a.b.c`)

#### Fixed

- **HMAC Secret Panic**: Enterprise Docker images no longer panic when HMAC secret not initialized
 - Added `isHMACSecretInitialized` thread-safe check using RLock
 - `IsEnterpriseTier` returns false gracefully instead of panicking
 - Allows enterprise images to run in community mode without configuration changes

- **MCP Dynamic Policy Evaluation**: Fixed multiple pre-existing bugs preventing MCP dynamic policies from working
 - Added MCP policy types to validation, fixed DATABASE_URL propagation, created interface for both in-memory and database engines
- **Agent DB Auth**: Fixed JSON parsing for permissions from JSONB array
- **Cassandra Connector**: Apply timeout from query config to CQL operations

- **SDK Examples with Assertions**: Examples now have proper pass/fail testing and exit with code 1 on failure
 - Added assertions across all 4 SDKs (Go, Python, TypeScript, Java)
 - Community examples fixes: workflow examples, policy examples, integration examples

- **HITL Enforcement for Compliance Frameworks**: Fixed HITL not triggering in Proxy Mode
 - Root cause: Database constraint missing `require_approval` action + runtime wiring gap
 - Migration 044: Added `require_approval` to `action_request`/`action_response` constraints
 - Added `ActionRequireApproval` action type to shared policy types
 - Multi-strategy HITL detection: `eu_ai_act_article_14`, `requires_hitl` + compliance context, high-risk + compliance framework
 - EU AI Act and RBI-SEBI examples now achieve 100% HITL compliance rate

#### Deprecated

- **API: page_size → limit**: Standardized pagination parameter name
 - **Action Required:** Migrate from `page_size` to `limit` before v4.0.0
 - `page_size` query parameter is deprecated and **will be removed in v4.0.0**
 - Affected endpoints: `/api/v1/static-policies`, `/api/v1/dynamic-policies`
 - Both parameters work during transition period; `limit` takes precedence

- **SDK: ExecuteQuery → ProxyLLMCall**: Renamed for clearer Proxy Mode semantics
 - **Action Required:** Migrate from `executeQuery` to `proxyLLMCall` before the next major release
 - Old methods emit deprecation warnings and **will be removed in v4.0.0**
 - New names clarify the two integration modes:
 - **Proxy Mode:** `proxyLLMCall` - AxonFlow proxies your LLM request
 - **Gateway Mode:** `getPolicyApprovedContext` + `auditLLMCall` - You call LLM directly
 - All SDK examples and demos updated to use new method names
 - Applies to: Go SDK, TypeScript SDK, Python SDK, Java SDK

### Enterprise

#### Added

- **MAS FEAT Compliance Module**: Singapore financial services AI governance framework
 - Implements Monetary Authority of Singapore FEAT (Fairness, Ethics, Accountability, Transparency) guidelines
 - AI System Registry with 3-Dimensional Risk Rating (Customer Impact × Model Complexity × Human Reliance)
 - Materiality Classification: High (sum≥12), Medium (sum≥8), Low (sum<8)
 - FEAT Assessment lifecycle: pending → in_progress → completed → approved/rejected
 - Four pillar scoring: Fairness, Ethics, Accountability, Transparency (with detailed sub-metrics)
 - Kill Switch with automatic triggering based on accuracy, bias, and error rate thresholds
 - 7-year audit retention for regulatory compliance
 - Singapore-specific PII detection with Verhoeff checksum validation (NRIC, FIN, UEN)

- **MAS FEAT Database Schema**: New tables for compliance data
 - `ai_system_registry` - AI system registration with materiality tracking
 - `feat_assessments` - FEAT assessment records with pillar scores
 - `kill_switch` - Kill switch configuration and status
 - `kill_switch_events` - Kill switch event audit log

- **MAS FEAT API Endpoints**: Full REST API for compliance operations
 - AI System Registry CRUD (`/api/v1/masfeat/registry/*`)
 - FEAT Assessment lifecycle (`/api/v1/masfeat/assessments/*`)
 - Kill Switch management (`/api/v1/masfeat/killswitch/*`)

- **Compliance Runtime Wiring**: Enterprise compliance module initialization
 - RBI, SEBI, EU AI Act, and MAS FEAT module initialization with health checks
 - Compliance route registration (`/api/v1/rbi/*`, `/api/v1/sebi/*`, `/api/v1/euaiact/*`, `/api/v1/masfeat/*`)
 - Compliance examples with strict HITL assertion validation

- **HITL Execution Store**: In-memory store with SaveExecution/GetExecutionStatus for pause/resume workflow

- **SCIM Provisioning Examples**: User, group, token management examples

- **WCP HITL Queue Integration**: `require_approval` policy actions now create HITL queue entries
 - Enterprise: Database persistence in `hitl_approval_queue` with `wcp_step_gate` request type
 - Community: No-op stub with informational logging
 - 24-hour default expiry for approval requests
 - New E2E example at `ee/examples/workflows/wcp-hitl/go` verifying queue entry creation

#### Fixed

- **WCP HITL Approval Queue Insert**: Fixed INSERT query for `hitl_approval_queue` table
 - Removed explicit `id` column from INSERT (now auto-generated by sequence)
 - `request_id` (UUID) is the primary identifier for approval requests

- **SDK Examples Fixes**: Fixed enterprise examples (eu-ai-act, rbi-sebi, healthcare, llm-providers/e2e-tests) across all 4 SDKs

#### SDK Support

- TypeScript SDK v2.7.0: `client.masfeat.*` namespace, `budgetInfo`
- Python SDK v1.7.0: `client.masfeat.*` namespace, `budget_info`
- Go SDK v2.7.0: `client.MASFEAT*` methods, `BudgetInfo`
- Java SDK v2.7.0: `client.masfeat.*` namespace, `getBudgetInfo`

---

## [3.5.0] - 2026-01-18

### Added

- **Workflow Policy Enforcement**: Policy evaluation at workflow transitions
 - **MAP Policy Enforcement**: Dynamic policy evaluation before plan execution
 - Policy check in `executePlanHandler` with allow/block decisions
 - `PolicyInfo` field in `PlanResponse` with evaluated policies and risk score
 - Policy results recorded in step execution snapshots for replay/audit
 - **WCP Policy Enforcement**: Connect WCP to dynamic policy engine
 - New `WCPPolicyAdapter` bridges workflow_control to orchestrator policy engine
 - `policies_evaluated` and `policies_matched` fields in `StepGateResponse`
 - Detailed policy match information (policy_id, policy_name, action, reason)
 - Support for allow/block/require_approval decisions based on policy evaluation

### Tests

- Added unit tests for MAP policy enforcement (blocked/allowed scenarios)
- Added unit tests for WCP policy adapter (allow/block/require_approval/nil engine)
- Added unit tests for WCP policy info in response (4 new test cases)

### Documentation

- Updated `docs/api/orchestrator-api.yaml` with policy info fields in PlanResponse and StepGateResponse
- Added `PolicyMatch` schema for detailed policy evaluation results

---

## [3.4.0] - 2026-01-17

### Added

- **Workflow Control Plane V1**: Governance gates for external orchestrators (LangChain, LangGraph, CrewAI)
 - "LangChain runs the workflow. AxonFlow decides when it's allowed to move forward."
 - Register workflows from external orchestrators with `POST /api/v1/workflows`
 - Step gate checks with allow/block/require_approval decisions
 - Policy evaluation at step transitions with new `workflow` scope
 - Workflow lifecycle tracking (in_progress/completed/aborted/failed)
 - New database tables: `workflows`, `workflow_steps`
 - SDK support: Go, TypeScript (Python and Java in standalone repos)
 - Examples: HTTP, Go, Python, TypeScript, Java + LangGraph adapter

- **Grafana Dashboard**: Security & Compliance section with PII detection, provider distribution, and policy metrics panels

### Fixed

- Improved enterprise license validation consistency

### Documentation

- New guide: `docs/guides/workflow-control-plane.md` - Workflow Control Plane user guide
- Updated API spec: `docs/api/orchestrator-api.yaml` - Workflow endpoints

---

## [3.3.0] - 2026-01-16

### Added

- **MCP Connector Audit Logging**: Full audit trail for all MCP connector queries and commands
 - New `mcp_query_audits` table captures all MCP operations with policy evaluation results
 - REQUEST phase logging: SQLi detection, PII blocking, matched policies
 - RESPONSE phase logging: PII redaction, redacted field paths (JSONPath format)
 - EXFILTRATION logging: Row counts, volume limit violations
 - Compliance mode (sync) for violations, performance mode (async) for success
 - Statement privacy: SHA256 hash stored instead of raw queries
 - `audit_id` field correlates with SDK `PolicyInfo` for traceability

- **MCP Audit Examples**: Comprehensive examples for all 4 SDKs + HTTP API
 - `examples/mcp-audit/http/` - HTTP API examples (curl/bash)
 - `examples/mcp-audit/go/` - Go SDK example
 - `examples/mcp-audit/python/` - Python SDK example
 - `examples/mcp-audit/typescript/` - TypeScript SDK example
 - `examples/mcp-audit/java/` - Java SDK example

### Documentation

- New guide: `docs/guides/audit-logging.md` - Comprehensive audit logging architecture guide
- New guide: `docs/guides/mcp-audit-logging.md` - MCP audit logging configuration and usage
- Updated API docs: `docs/api/agent-api.yaml` - Added audit logging details to MCP endpoints

---

## [3.2.0] - 2026-01-14

### Added

- **MCP Exfiltration Detection**: Row and data volume limits for MCP connector queries
 - Configurable row count limits (default: 10,000 per query)
 - Configurable data volume limits (default: 10MB per response)
 - Returns 403 with detailed limit information when exceeded
 - `ExfiltrationCheck` field in `PolicyInfo` response

- **MCP Dynamic Policy Evaluation**: Real-time policy evaluation via Orchestrator
 - Pre-query policy evaluation for rate limits, budgets, time/role access
 - Graceful degradation when Orchestrator is unavailable
 - `DynamicPolicyInfo` field in `PolicyInfo` response

### Fixed

- Removed unused `MCP_DYNAMIC_POLICIES_ENDPOINT` environment variable

### Tests

- Added integration tests for MCP exfiltration and dynamic policy features

### Documentation

- Updated community/enterprise feature matrix with MCP policy features

---

## [3.1.0] - 2026-01-09

### Added

- **MCP Tiered Policy Enforcement**: Phase-aware policy enforcement for MCP connector requests
 - REQUEST phase: SQLi pattern blocking (DROP TABLE, UNION SELECT, OR 1=1, DELETE, TRUNCATE)
 - REQUEST phase: Critical PII blocking (SSN, Credit Card, India PAN, Aadhaar)
 - RESPONSE phase: PII redaction in connector data (SSN, Credit Card masked)
 - PolicyInfo metadata in all MCP responses (`policies_evaluated`, `redactions_applied`, `processing_time_ms`)
 - Non-critical PII (Email, Phone) allowed through with logging

- **MCP PII Redaction Examples**: Comprehensive examples for all 4 SDKs + HTTP API
 - `examples/mcp-policies/pii-redaction/go/` - Go SDK example
 - `examples/mcp-policies/pii-redaction/python/` - Python SDK example
 - `examples/mcp-policies/pii-redaction/typescript/` - TypeScript SDK example
 - `examples/mcp-policies/pii-redaction/java/` - Java SDK example
 - `examples/mcp-policies/pii-redaction/http/` - HTTP API examples (curl)

### Enterprise

- **Healthcare PHI Patterns**: Enterprise example for HIPAA-compliant PHI detection
 - Medical Record Number (MRN) detection
 - DEA Number detection
 - NPI (National Provider Identifier) detection
 - Medicare Beneficiary Identifier (MBI) detection
 - ICD-10 code detection

### Fixed

- **Healthcare example**: Fixed policy verification to use `GetStaticPolicy` instead of `ListStaticPolicies`

---

## [3.1.1] - 2026-01-09

### Fixed

- **MAP GetPlanStatus API**: Fixed response fields to match SDK expectations
 - Changed `step_count` to `total_steps` in API response
 - Added `completed_steps` field (0 when pending, equals total_steps when completed)
 - SDK methods `GetPlanStatus` / `get_plan_status` now correctly receive step tracking info

---

## [3.0.2] - 2026-01-08

### Fixed

- **Agent proxy routes**: Fixed missing proxy routes for `/api/v1/pricing`, `/api/v1/plan`, and `/api/v1/audit` endpoints. SDK methods like `getPricing`, `generatePlan`, `executePlan`, and `searchAuditLogs` now work correctly through the Agent single entry point. Previously these returned 404 errors.

### Changed

- **GoReleaser upgraded to v2**: Release workflow now uses GoReleaser v2 configuration format for better compatibility.

### Enterprise

- **OAuth2 Basic auth support**: Agent now accepts `Authorization: Basic base64(clientId:clientSecret)` for authentication, in addition to existing `X-License-Key` header.
- **Code governance: ClosePR endpoint**: Added endpoint for closing PRs without merging, useful for cleaning up test/demo PRs.

---

## [3.0.1] - 2026-01-07

### Fixed

- **Multi-Agent Planning (MAP) Two-Step Execution**: Fixed race condition where plan execution started before DB commit
 - `GeneratePlan` now stores workflow plan in database with 1-hour TTL before returning
 - `ExecutePlan` retrieves stored plan by `plan_id` and executes workflow
 - New `migrations/core/037_plans.sql` - Plans table for deferred execution
 - New `migrations/core/038_plans_composite_index.sql` - Composite index for cross-tenant queries
 - New `platform/orchestrator/planning/` package (service, repository, types)
 - Agent routes `execute-plan` requests to `/api/v1/plan/execute`

- **Agent Environment Variable Support for ECS/K8s**: Fixed orchestrator URL detection in containerized environments
 - Agent now checks `ORCHESTRATOR_URL` env var first (required for ECS, Kubernetes)
 - Priority: env var → Docker detection → localhost fallback
 - Increased MAP timeout to 60s

- **Support Demo Fixes**: Fixed broken support-demo in community repo
 - Removed vendor dependency causing Docker build failures
 - Fixed network naming (`axonflow_axonflow-network` requires `COMPOSE_PROJECT_NAME=axonflow`)
 - Removed direct orchestrator calls (all requests go through Agent)
 - Fixed role/region provider display for EU users

- **Dynamic Policy API Path**: Fixed incorrect API path in examples
 - Changed `/api/v1/policies/dynamic` → `/api/v1/dynamic-policies`

- **Dynamic Policy Payload Format**: Fixed condition format in examples
 - Changed `conditions: "{}"` → `conditions: "[]"` (array, not object)

### Added

- **Portal Proxy Routes (Enterprise)**: Agent now proxies `/api/v1/auth/*` for portal authentication

---

## [3.0.0] - 2026-01-05

### Breaking Changes

- **Single Entry Point Architecture**: All API routes now go through the Agent (port 8080)
 - Agent proxies `/api/v1/dynamic-policies/*`, `/api/v1/budgets/*`, `/api/v1/usage/*`, `/api/v1/executions/*` to Orchestrator
 - Agent proxies `/portal/*` routes to Customer Portal
 - SDKs now use single `endpoint` parameter (default: `http://localhost:8080`)
 - **Deprecated**: `agent_url` and `orchestrator_url` SDK parameters (use `endpoint` instead)
 - **Deprecated**: Direct Orchestrator access on port 8081 (still works but not recommended)

- **Detection Defaults Changed**: More nuanced default actions based on detection confidence
 - PII detection: `block` → `redact` (non-blocking, better UX)
 - High risk score (>0.8): `block` → `warn` (composite score needs tuning)
 - SQL injection: remains `block` (high confidence attacks)
 - Dangerous queries (DROP/TRUNCATE): remains `block` (destructive operations)

- **Environment Variable Changes**:
 - **New**: `SQLI_ACTION` (values: `block`, `warn`, `log`) - replaces `SQLI_BLOCK_MODE`
 - **New**: `PII_ACTION` (values: `block`, `warn`, `redact`, `log`) - replaces `PII_BLOCK_CRITICAL`
 - **New**: `SENSITIVE_DATA_ACTION` (values: `block`, `warn`, `log`) - credentials/secrets detection
 - **New**: `HIGH_RISK_ACTION` (values: `block`, `warn`, `log`) - high risk score threshold
 - **New**: `DANGEROUS_QUERY_ACTION` (values: `block`, `warn`, `log`) - DROP/TRUNCATE detection
 - **Deprecated**: `SQLI_BLOCK_MODE` (use `SQLI_ACTION` instead)
 - **Deprecated**: `PII_BLOCK_CRITICAL` (use `PII_ACTION` instead)

### Added

- **Sensitive Data Patterns in Database**: Credential and secret detection patterns now stored in `static_policies` table
 - Password, API key, token, secret, credentials, connection string patterns
 - Context exclusions for SQL keywords (PRIMARY KEY, FOREIGN KEY no longer false positives)
 - Per-tenant customization via policy overrides (Enterprise)

- **Environment Variable Precedence**: Clear hierarchy for detection configuration
 1. Per-tenant policy override (API) - highest priority
 2. Environment variable (docker-compose)
 3. Per-policy DB default (migration seed) - lowest priority

- **PII Redaction Support in SDKs**: New `requiresRedaction` field in `PolicyApprovalResult`
 - Returns `true` when PII was detected with `redact` action
 - Callers should process response for redaction when this flag is set
 - Available in all SDKs: `isRequiresRedaction` (Java), `requires_redaction` (Python), `RequiresRedaction` (Go), `requiresRedaction` (TypeScript)

- **Strict Provider Enforcement for Dynamic Policies**: Compliance-aware LLM routing
 - Policies can specify `allowed_providers` to restrict which LLM providers handle requests
 - Requests **fail** (instead of fallback) if no compliant provider is available
 - Multiple policies use **intersection logic** (least privilege - most restrictive wins)
 - Enables GDPR, HIPAA, RBI compliance scenarios (e.g., EU data stays on-premise)
 - Example: `{"allowed_providers": ["ollama"]}` ensures only local model handles sensitive data

### Fixed

- **Dynamic policy condition evaluation**: `DatabaseDynamicPolicyEngine` now correctly evaluates conditions before applying actions
 - Previously, all policy actions were applied regardless of whether conditions matched
 - Now supports operators: `equals`, `not_equals`, `contains`, `not_contains`, `contains_any`, `regex`, `greater_than`, `less_than`, `in`, `not_in`

- **Tenant extraction bug**: Fixed `Client.ID` → `Client.TenantID` in policy evaluation

### Changed

- **SDK Method Signatures**: All SDKs updated for single endpoint
 - Go: `axonflow.NewClient(axonflow.AxonFlowConfig{Endpoint: "http://localhost:8080"})`
 - Python: `AxonFlow(endpoint="http://localhost:8080")`
 - TypeScript: `new AxonFlow({ endpoint: "http://localhost:8080" })`
 - Java: `AxonFlow.create(AxonFlowConfig.builder.endpoint("http://localhost:8080").build)`

### Migration Guide

**SDK Migration:**
```python
# Before (v2.x)
client = AxonFlow(
 agent_url="http://localhost:8080",
 orchestrator_url="http://localhost:8081"
)

# After (v3.0)
client = AxonFlow(endpoint="http://localhost:8080")
```

**Environment Variable Migration:**
```yaml
# Before (v2.x)
SQLI_BLOCK_MODE: "block"
PII_BLOCK_CRITICAL: "true"

# After (v3.0)
SQLI_ACTION: "block"
PII_ACTION: "redact"
SENSITIVE_DATA_ACTION: "warn"
HIGH_RISK_ACTION: "warn"
```

---

## [2.6.0] - 2026-01-04

### Added

- **Decision & Execution Replay API**: Debug and audit workflow executions with full state capture and policy decisions
 - `GET /api/v1/executions` - List executions with filtering (status, time range, agent/workflow)
 - `GET /api/v1/executions/{id}` - Get execution with all step snapshots
 - `GET /api/v1/executions/{id}/steps` - Get individual step snapshots
 - `GET /api/v1/executions/{id}/timeline` - Timeline view for visualization
 - `GET /api/v1/executions/{id}/export` - Export for compliance and archival
 - `DELETE /api/v1/executions/{id}` - Delete execution records
 - SDK examples for Go, Python, TypeScript, Java

- **Cost Controls Phase 1**: Budget management and LLM usage tracking
 - Budget scopes: Organization, Team, Agent, Workflow, User
 - Budget periods: Daily, Weekly, Monthly, Quarterly, Yearly
 - Enforcement actions: Warn, Block, Downgrade on exceed
 - Configurable alert thresholds (default 50%, 80%, 100%)
 - Usage aggregation: Hourly, Daily, Weekly, Monthly
 - Provider pricing for OpenAI, Anthropic, Azure, Gemini, Bedrock, Ollama
 - SDK examples for Go, Python, TypeScript, Java

### Fixed

- **Replay Data Race**: Fixed race condition in background summary update when multiple goroutines access execution state

### Documentation

- **SDK method inclusion criteria for feature parity decisions
- **SDK Feature Coverage**: Cross-SDK method availability matrix

---

## [2.5.0] - 2026-01-02

### Added

- **Azure OpenAI Provider** (Community): Native Azure OpenAI Service integration
 - Supports both Azure AI Foundry (`cognitiveservices.azure.com`) and Classic (`openai.azure.com`) endpoints
 - Automatic authentication detection (Bearer token vs api-key header)
 - Streaming support via `GenerateContentStream`
 - Health checks and provider status endpoints
 - Environment variables: `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_DEPLOYMENT_NAME`, `AZURE_OPENAI_API_VERSION`

- **Azure OpenAI Examples**: Complete example suite
 - Hello World (Go, Python, TypeScript, Java, HTTP)
 - PII Detection (Python)
 - SQL Injection Scanning (TypeScript)
 - Proxy Mode (Go)

- **README Philosophy Section**: Added positioning section explaining AxonFlow's "secure-by-default, configurable enforcement" approach for LLM discoverability

### Changed

- **Docker Compose UX**: Reorganized environment variables for better developer experience
 - **CORE CONFIGURATION**: 10 essential variables (LLM API keys, Azure config, ports, deployment mode)
 - **ADVANCED CONFIGURATION**: Defaults work for most users (database, internal services, routing)
 - Added explicit security configuration toggles (`SQLI_SCANNER_MODE`, `SQLI_BLOCK_MODE`)

### Documentation

- Added Azure OpenAI to Supported LLM Providers in README
- Provider documentation at `docs/llm/azure-openai.md`
- Updated Community vs Enterprise feature matrix

---

## [2.4.0] - 2025-12-31

### Changed

- **DEPLOYMENT_MODE Unification**: Single env var for auth (`community` = no auth, `enterprise` = license required)
 - Replaces `SELF_HOSTED_MODE` with clearer naming
 - New `isCommunityMode` helper for consistent mode checks

### Added

- **MCP Connector Examples**: Python, TypeScript, Java implementations
- **Workflow Examples**: 6 patterns (sequential, parallel, conditional, fallbacks, pipelines, approvals)

### Fixed

- Shell script audit endpoint URL corrected
- Unit tests for enterprise mode validation

---

## [2.3.0] - 2025-12-30

### Changed

- **LLM Router Consolidation**: Completed migration to interface-based router architecture
 - Removed legacy `LLMRouter` concrete implementation (~1,700 lines)
 - All routing now through `LLMRouterInterface` abstraction introduced in v2.2.0
 - Cleaner codebase with single routing implementation path

- **Docker Compose Architecture**: Simplified deployment configuration
 - `docker-compose.yml` now serves as Community base configuration
 - Enterprise features available via overlay pattern

- **Default Anthropic Model**: Updated to `claude-sonnet-4-20250514` (Claude 4)

### Added

- **LLM Provider E2E Tests**: Comprehensive end-to-end test suite
 - Coverage for OpenAI, Anthropic, Google Gemini, and AWS Bedrock
 - Multi-language test implementations (Go, Python, TypeScript, Java)

### Removed

- `llm_router.go` - Superseded by `UnifiedRouterWrapper`
- `llm_routing_strategy.go` - Consolidated into unified router
- Legacy router test files

---

## [2.2.0] - 2025-12-29

### Added

- **LLM Router Interface Abstraction**: Components now depend on standard interface rather than concrete implementations
 - `LLMRouterInterface` - Standard interface for router abstraction
 - `UnifiedRouterWrapper` - Adapter enabling UnifiedRouter as drop-in LLMRouter replacement
 - Type conversion utilities between legacy and new router types

- **LLM Provider Routing Examples**: New HTTP/curl examples for direct API access
 - Shell script examples for all supported providers (OpenAI, Anthropic, Ollama, Gemini)
 - Gateway mode pre-check and audit examples
 - Java SDK example for provider routing

### Changed

- Orchestrator now uses interface type for LLM router configuration
- Improved test coverage for audit logging and routing strategies

---

## [2.1.0] - 2025-12-28

### Added

- **Human-in-the-Loop (HITL)**: New `require_approval` policy action for human oversight
 - Enterprise: Pauses execution, creates approval request in HITL queue
 - Community: Auto-approves (upgrade path to Enterprise)
 - EU AI Act Article 14 and SEBI AI/ML compliance support

- **Code Governance**: Automatic detection and audit of LLM-generated code
 - Identifies language, code type, potential secrets, unsafe patterns
 - Detects eval, exec, shell injection risks
 - Metadata logged for compliance

- **LLM Provider Routing**: Runtime control over provider selection
 - Weighted routing across providers
 - Health-based automatic failover
 - Per-request provider preferences

### Fixed

- Anthropic provider now respects `ANTHROPIC_MODEL` environment variable
- Support demo build and runtime fixes
- HITL example tier filter fixes

---

## [2.0.0] - 2025-12-25

**Unified Policy Architecture - Major Release**

This major release introduces enterprise-grade policy management to AxonFlow with a new three-tier hierarchy for granular control at every level.

### ⚠️ Breaking Changes

**Category Enum Values Changed in Responses**

| Old Category | New Category |
|--------------|--------------|
| `sql_injection` | `security-sqli` |
| `admin_access` | `security-admin` |
| `pii_detection` | `pii-global`, `pii-us`, `pii-eu`, `pii-india` |
| `dangerous_queries` | `security-sqli` |

**Migration Notes:**
- Old category values are still accepted in **request** parameters (backwards compatible)
- Update your code if you're parsing category values from **responses**
- SDKs don't require updates - they pass through category values as strings

### Added

- **Three-Tier Policy Hierarchy**: New policy architecture with System → Organization → Tenant inheritance
 - **System Tier**: 63 immutable security policies (53 static + 10 dynamic)
 - **Organization Tier**: Company-wide policies (Enterprise only)
 - **Tenant Tier**: Team-specific policies with full CRUD
 - Tier-aware policy resolution with caching

- **63 System Policies**: Comprehensive security and compliance coverage out-of-the-box
 - **Security - SQL Injection** (37): UNION, boolean-based, time-based, stacked queries, etc.
 - **Security - Admin Access** (4): Users table, audit log, config table access
 - **PII - Global** (7): Credit card, email, phone, IP, passport, DOB
 - **PII - US** (2): SSN, bank accounts
 - **PII - EU** (1): IBAN
 - **PII - India** (2): PAN, Aadhaar
 - **Dynamic** (10): Risk, compliance (HIPAA, GDPR), cost, access control

- **Policy CRUD APIs**: Full create, read, update, delete for organization and tenant policies
 - `GET /api/v1/static-policies` - List with tier/category filtering
 - `POST /api/v1/static-policies` - Create custom policy
 - `PUT /api/v1/static-policies/{id}` - Update policy
 - `DELETE /api/v1/static-policies/{id}` - Delete policy
 - `GET /api/v1/effective-policies` - Get merged hierarchy for tenant

- **Policy Overrides** (Enterprise): Customize system policy behavior
 - Disable system policies for organization
 - Change action (only to more restrictive)
 - Expiration dates for temporary overrides
 - Audit trail with reason requirement

- **SDK Policy Methods**: All 4 SDKs support policy management
 - TypeScript: `listStaticPolicies`, `createStaticPolicy`, etc.
 - Python: `list_static_policies`, `create_static_policy`, etc.
 - Go: `ListStaticPolicies`, `CreateStaticPolicy`, etc.
 - Java: `listStaticPolicies`, `createStaticPolicy`, etc.

- **Customer Portal UI**: Visual policy management for Enterprise customers
 - Unified policy dashboard
 - Override management
 - Policy testing interface

### Changed

- **Policy Categories**: New category naming convention
 - `security-sqli`, `security-admin` for security policies
 - `pii-global`, `pii-us`, `pii-eu`, `pii-india` for PII detection
 - `dynamic-risk`, `dynamic-compliance`, `dynamic-cost`, `dynamic-access` for context-aware policies

- **Performance**: Static policy evaluation maintains < 5ms p99 latency
 - Tier-aware caching with configurable TTL
 - Optimized regex pattern compilation

### Fixed

- **PII Detection Priority**: Credit card detection now correctly takes priority over phone number detection
 - Root cause: Policies were sorted by severity string (alphabetically "medium" > "critical")
 - Fix: Changed to `ORDER BY priority DESC` using numeric priority field

- **Tenant Policy Isolation**: Tenant-specific policies now only apply to their respective tenants
 - Root cause: `LoadPoliciesFromDB` was loading ALL policies without tier filtering
 - Fix: Added two-phase evaluation - system policies via fast path, tenant policies via tier-aware engine

### Enterprise Features

- Organization-tier policy management
- System policy override capabilities
- Policy version history
- Customer Portal policy UI

---

## [1.1.3] - 2025-12-21

### Fixed

- **Usage Recording:** Fixed postgres errors in Community mode when `usage_events` table doesn't exist ([#96](https://github.com/getaxonflow/axonflow/issues/96))
 - Usage metering is now properly separated as an Enterprise-only feature
 - Community builds have zero-overhead no-op implementation using build tags
 - Thanks to [@gzak](https://github.com/gzak) for identifying and contributing the initial fix ([#97](https://github.com/getaxonflow/axonflow/pull/97))

- **OpenAI Provider:** Fixed "you must provide a model parameter" error when `OPENAI_MODEL` not explicitly set ([#100](https://github.com/getaxonflow/axonflow/pull/100))
 - `OpenAIProvider` now reads `OPENAI_MODEL` environment variable with `gpt-4o` fallback
 - Consistent with other providers (Anthropic, Gemini, Ollama)

### Changed

- **Code Cleanup:** Removed 450+ lines of dead code
 - Removed unused `AnthropicProvider` struct (superseded by `EnhancedAnthropicProvider`)
 - Usage package refactored with build tags for clean Community/Enterprise separation

---

## [1.1.2] - 2025-12-20

### Fixed

- **LLM Router:** Use provider's configured model instead of hardcoded defaults ([#94](https://github.com/getaxonflow/axonflow/pull/94))
 - Previously, `selectModel` returned hardcoded model names (e.g., `gpt-3.5-turbo`, `claude-3-5-sonnet`) which caused failures when the API key didn't have access to those specific models
 - Now respects `OPENAI_MODEL`, `ANTHROPIC_MODEL`, and other provider-specific environment variables
 - Model specified in request context takes highest priority

### Changed

- Added `OPENAI_MODEL` and `ANTHROPIC_MODEL` environment variable passthrough in docker-compose.yml

---

## [1.1.1] - 2025-12-20

### Fixed

- **Self-hosted mode:** Fixed authentication bypass not working when `userToken` is empty or omitted ([#89](https://github.com/getaxonflow/axonflow/pull/89))
 - Previously, self-hosted mode required a dummy `userToken`/`apiKey` even though it should accept requests without credentials
 - Now correctly bypasses authentication when `SELF_HOSTED_MODE=true` and `SELF_HOSTED_MODE_ACKNOWLEDGED=I_UNDERSTAND_NO_AUTH` are set
 - Thanks to [@gzak](https://github.com/gzak) for the contribution

---

## [1.1.0] - 2025-12-19

**SDK Feature Parity & Terminology Update**

### Added

- **Google Gemini LLM Provider**: Native Gemini integration now available in Community edition
 - Supports Gemini Pro and Gemini Pro Vision models
 - Automatic failover and routing alongside OpenAI, Anthropic, Ollama

- **SDK Feature Parity**: All four SDKs now have complete feature parity
 - **TypeScript SDK** (v1.4.0): 85.75% test coverage
 - **Python SDK** (v0.3.0): 71.39% test coverage
 - **Java SDK** (v1.1.0): 81.9% test coverage
 - **Go SDK** (v1.5.0): 82.8% test coverage

- **LLM Interceptors** (all SDKs): Wrapper-based governance for LLM providers
 - OpenAI, Anthropic, Gemini, Ollama, AWS Bedrock interceptors
 - Gateway Mode: Two-phase policy checking with `getPolicyApprovedContext` and `auditLLMCall`
 - Proxy Mode: Single-call governance with `executeQuery`

### Changed

- **Terminology**: Renamed "OSS" to "Community" across the entire codebase
 - Environment variable: `AXONFLOW_MODE=community` (previously `oss`)
 - API responses: `"mode": "community"` (previously `"oss"`)
 - Documentation updated throughout

### Breaking Changes

- **`AXONFLOW_MODE` Environment Variable**: If you were using `AXONFLOW_MODE=oss`, update to `AXONFLOW_MODE=community`
- **API Response**: The `mode` field in API responses now returns `"community"` instead of `"oss"`

### Migration Notes

To upgrade from 1.0.x:

1. Update environment variables:
 ```bash
 # Before
 AXONFLOW_MODE=oss

 # After
 AXONFLOW_MODE=community
 ```

2. Update any code that checks for `mode === "oss"` to check for `mode === "community"`

3. Update SDKs to latest versions for LLM Interceptors support

---

## [1.0.1] - 2025-12-16

### Added

- **Internal Service Authentication**: Shared secret authentication for secure agent↔orchestrator communication via `AXONFLOW_INTERNAL_SERVICE_SECRET`

### Changed

- **PII Detection**: Made critical PII blocking configurable per-policy (Aadhaar, PAN patterns)

---

## [1.0.0] - 2025-12-14

**Community Launch Release**

This is the first public release of AxonFlow, a self-hosted governance and orchestration platform for production AI systems.

### Core Platform

- **Policy Enforcement Agent**: Real-time policy enforcement with single-digit millisecond overhead
 - Static policy engine with configurable rules
 - PII detection (SSN, credit cards, PAN, Aadhaar)
 - SQL injection blocking in user inputs
 - Rate limiting and request validation

- **Multi-Agent Planning (MAP)**: Declarative agent orchestration
 - YAML-based agent configuration
 - Natural language to workflow conversion
 - Sequential and parallel execution modes
 - Error handling with fallbacks

- **MCP Connectors**: Model Context Protocol integration
 - PostgreSQL, MySQL, MongoDB, Redis, HTTP connectors (Community)
 - Salesforce, Slack, Snowflake, ServiceNow (Enterprise)

- **Gateway Mode**: Wrap existing LLM calls with governance
 - Pre-check → your LLM call → audit trail
 - Incremental adoption path for existing codebases

- **Multi-Model Routing**: Intelligent LLM provider management
 - OpenAI, Anthropic, Ollama (Community)
 - AWS Bedrock, Google Gemini (Enterprise)
 - Automatic failover and cost-based routing

### Security & Compliance

- **SQL Injection Response Scanning**: Detect SQLi payloads in MCP connector responses
 - 37 regex patterns across 8 attack categories
 - Monitoring mode by default (detect and log, configurable blocking)
 - Per-connector configuration overrides
 - Audit trail integration for compliance
 - Basic scanner (Community), Advanced ML-based scanner (Enterprise)

- **EU AI Act Compliance** (Articles 12, 13, 14, 15, 43):
 - Decision chain tracing with full audit trails
 - Transparency headers (X-AI-Decision-ID, X-AI-Model-Provider, etc.)
 - Human-in-the-Loop (HITL) workflows (Enterprise)
 - Conformity assessment endpoints (Enterprise)
 - Emergency circuit breaker (Enterprise)

- **RBI FREE-AI Framework**: Data integrity monitoring for financial AI (India)

- **SEBI AI/ML Guidelines**: Security audit trail for investment platforms (India)

### Infrastructure

- **Docker Compose Deployment**: Local development in under 5 minutes
- **Row-Level Security**: Database-level multi-tenant isolation
- **Production Migrations**: Idempotent, versioned database migrations
- **Test Coverage**: 70%+ coverage across core packages

### Documentation

- Getting Started Guide
- LLM Provider Configuration
- MCP Connector Development Guide
- Security Best Practices
- EU AI Act Compliance Guide

---

## Links

- [GitHub Repository](https://github.com/getaxonflow/axonflow)
- [Documentation](https://docs.getaxonflow.com)
- [AWS Marketplace](https://aws.amazon.com/marketplace)
- [Security Policy](./SECURITY.md)
- [Contributing Guide](./CONTRIBUTING.md)

---

**For a complete list of changes, see the [commit history](https://github.com/getaxonflow/axonflow/commits/main).**
