# Replay corpus and production capture

How the ADR-065 shadow harness gets its inputs today, and how a live
deployment plugs into the same seam later. Design note; the production capture
is deliberately NOT implemented in this phase.

## What exists now

Two inputs, both offline, both replayable.

**The policy set** comes from `scripts/legacy-policy-capture.sh`. It boots one
ephemeral Postgres, applies `migrations/core`, and writes every
`static_policies` and `dynamic_policies` row as JSON keyed by column name -
`row_to_json`, so the capture is lossless by construction and a column added by
a later migration arrives without anybody remembering to add it.

It takes the tables **twice**, and the difference is the point:

| file | read as | what it answers |
|---|---|---|
| `capture-owner.json` | table owner, unfiltered | what rows EXIST; reconciles against `SELECT count(*)` |
| `capture-approle.json` | non-owner app role, one scoped transaction per org | what rows ENFORCEMENT can see under row-level security |

The org scope is not decoration. The compiler builds ONE document set per
plane PER ORG, because the runtime reads `WHERE org_id = $1` under
strict-equality RLS and one org's policies never reach another org's requests
(ADR-065 invariant 1). A compilation that merged them would erase the isolation
boundary, and both sides of the diff would be equally org-blind about it.

`static_policies` and `dynamic_policies` carry RLS (`migrations/core/018`:
`org_id = get_current_org_id()`), which is why the runtime loader issues one
scoped pass per org plus a separate `'global'` pass rather than one
`org_id IN ($org,'global')` - inside a single transaction the second half of
that predicate returns nothing under the app role, and the global baseline
disappears while the read still looks successful. A capture that read as the
owner and called itself the runtime read would hide exactly that population.

The script proves RLS is actually enforcing before trusting the scoped capture:
it reads BOTH tables under an org scope no row carries and requires zero rows
back from each. On a seed set with a single org scope the two captures are
otherwise identical, which is indistinguishable from RLS being switched off.

That probe proves the boundary exists. It does not make a single-scope
substrate multi-scope, and on a fresh stack the seeds ARE single-scope: every
system-tier row carries `org_id='global'` (migration core/153). The
owner-versus-app-role comparison is then structurally unable to report a
difference, and both the script and `TestCapturedCorpusReconciles` say so
explicitly rather than reporting zero RLS-invisible rows as a clean result. A
zero there is UNEXERCISED, not clean.

The script also sets `app.deployment_org_id` before applying migrations,
because `core/094` refuses to run its `org_id` backfill without it - and 094 is
the migration that gives policy rows a per-org `org_id`, the column RLS keys
on. A capture taken without it describes a data distribution no migrated
deployment has.

**The requests** come from `shadow.BuildCorpus`, which generates cases from the
compiled policy set rather than sampling traffic. Per plane, PER ORG SCOPE:

| family | rows | what it shows |
|---|---|---|
| `baseline_nothing_matches` | once per plane | nothing fires; this is where default-deny shows up |
| `all_rows_fire` | once per plane, when the plane has more than one row | every row at once, which is the only case that exercises COMBINING and, on the proxy tier, the first-match/strictest-segment reduction |
| `<row>/fires` | static and dynamic | the row's detector matched, or its conditions hold |
| `<row>/detector_did_not_run` | static only | the detector never ran at all |
| `<row>/does_not_fire` | dynamic only | the conditions ran and did not hold |

`detector_did_not_run` is the family the legacy engines cannot express, and it
is where ADR-065's tri-state changes the answer. It exists for the STATIC
substrate only. The dynamic substrate now has detectors too - a row's content
conditions (contains/contains_any/regex) compile to one per-row detector
(`DynamicContentDetectorPath`), and every case carries a KNOWN verdict for it,
derived from the case's final field values with the legacy operator semantics -
but no unrun family is generated for those detectors yet, so the tri-state
consequence of a dynamic content detector that never ran is still unexercised.
That is a real gap in ADR-065 gate 4's coverage, and it is stated here rather
than left to be inferred from the case names. (A dynamic condition field
OUTSIDE the resolver's explicit cases is NOT a detector and NOT dead: it reads
the caller-forwarded `req.Context[field]` and compiles to an ordinary typed
condition over `args.context.*` - #3515.)

Every other row's inputs are held at their non-firing values in each case, so a
case varies one thing. Leaving them out would make every attribute they read
unknown, an unknown constraint makes the whole decision Indeterminate, and
every case on a plane carrying a dynamic row would then differ for a reason
that has nothing to do with the row the case was generated for.

## What this does not cover, and why that is stated rather than hidden

`shadow.ModelLimitations()` is copied onto every run and printed by the gate.
It is the reader's only protection against mistaking this harness for a
complete one, which makes UNDERSTATING it the dangerous direction.

**This document deliberately does not reproduce the list, or say how long it
is.** An earlier version did both, and was left describing a third of the items
after the function grew in a single commit - so the shipped design note gave a
materially more reassuring picture than the code, which is the exact failure
this whole harness exists to prevent. Read the function, or run the gate and
read its output. `TestCaptureDocDoesNotRestateTheLimitations` fails if a count
claim reappears here.

The largest item, quoted only because a reader deciding whether to trust a
green gate needs it before they get to the code: **`DEPLOYMENT_MODE=community`
turns `require_approval` into ALLOW**, and the model reports it as a deny - so
a shadow run taken against a community stack is wrong in the fail-open
direction for an entire deployment mode.

An approximation in the legacy side of a differential harness is
indistinguishable from a real difference, which is why each limitation is a
recorded gap rather than a best guess.

## The production capture seam

`shadow.LegacyEvaluator` is a one-method interface:

```go
type LegacyEvaluator interface {
    Evaluate(ctx context.Context, c Case) (Verdict, error)
}
```

`ModelEvaluator` is the offline implementation, and it is what CI runs, because
the decision module carries no database and no orchestrator. A production
capture supplies a second implementation and changes nothing else: the runner,
the classifier, the coverage accounting and the gate are all written against
the interface.

### Where a production adapter would live

The main platform module, not here. It needs `platform/shared/policy`'s engine
and `platform/orchestrator`'s dynamic evaluator, and the decision module is
deliberately standalone so it can pin its own OPA. A package such as
`platform/shadowcapture` would:

1. sit behind the existing enforcement call sites in report-only mode, taking
   the verdict the plane already computed - never re-running policy, because a
   second evaluation is a second answer, not the same one;
2. record the plane, the resolved segment set, the detection posture in force,
   the detector verdicts and the condition field values the resolver returned -
   the same fields `shadow.Case` already carries;
3. normalize the plane's own result into a `shadow.Verdict` using the legacy
   vocabulary (`LegacyEffect(RowKey(table, policy_id), action)`), NOT into obligations. The
   classifier's correspondence table is the second, independent statement of
   the compiler's mapping, and an adapter that emitted obligations would
   collapse the two sides into one.

### What a production capture must carry that the offline one does not

- **The bundle digest and the policy epoch in force at capture time.** A replay
  that cannot name the bundle it was measured against is not a replay. The
  `Snapshot` on every request already has the fields.
- **Provenance per attribute.** ADR-065 forbids an untrusted namespace from
  establishing authority, and the offline corpus assigns provenance from the
  path's namespace. A live capture must record what the Policy Information
  Point actually said, or the shadow run will validate a provenance the
  deployment did not have.
- **Sampling policy, stated.** Coverage here is per-plane and per-policy-row by
  construction. A traffic sample is not, so a production run must report which
  compiled rows the sample never reached - `Run.Coverage.UnexercisedRows`
  already carries it, and `Gate` already fails on it unless the operator
  explicitly opts out.

### What must not change when the adapter arrives

The gate's denominator. `Gate` fails on an empty corpus, on a plane with
compiled policy and zero cases, and on any compiled row the corpus never
reached. Those checks exist because zero unexplained differences out of zero
comparisons passes forever, passes hardest when the capture is broken, and
passes silently. A production capture makes the numerator more meaningful; it
does not make the denominator optional.

## A note for community-mirror readers

`platform/decision` syncs to the community repository and this file goes with
it. `scripts/legacy-policy-capture.sh` does NOT: the sync excludes `/scripts/`
and never re-includes it. So a community reader has the design note and the
skip message that points at the script, and not the script. That is a
deliberate consequence of the sync filter rather than an oversight, and it is
recorded here so nobody spends time looking for a missing file.

## Running it

```bash
# capture
scripts/legacy-policy-capture.sh /tmp/legacy-capture

# reconcile the compilation against SELECT count(*)
cd platform/decision
AXONFLOW_LEGACY_CAPTURE_DIR=/tmp/legacy-capture \
  go test ./legacycompile/ -run TestCapturedCorpusReconciles -v

# gate 18 over the REAL capture, every plane
AXONFLOW_LEGACY_CAPTURE_DIR=/tmp/legacy-capture \
  go test ./legacycompile/shadow/ -run TestRealCaptureShadowGateIsGreen -v

# the fixture diff gate over every plane
go test ./legacycompile/... -count=1
```

Without `AXONFLOW_LEGACY_CAPTURE_DIR` both capture-backed tests SKIP, and say
so loudly, so a green run cannot be read as either having passed. CI does not
rely on the skip: the `Unit Tests: Enterprise-Tagged + Real-PG` job runs the
capture script and BOTH tests on every PR, and its step requires their
`--- PASS` lines, so a skip there is a red step rather than a green one.
