---
title: SDK audit methodology
description: How AxonFlow audits SDK changes for wire-shape and transformer drift before each release.
---

# SDK audit methodology

This is the procedure AxonFlow maintainers run on every SDK PR that touches
wire-bound types, transformers, or any cross-language alignment surface. It
codifies what we learned from three rounds of review on the wire-canonicalization
sweep (TS PR #185, Python PR #155, Go PR #133, Java PR #138) where each round
surfaced a class of bug the prior rounds had missed.

The CI gates (wire-shape contract, TS AST `transformer-coverage`, Python
`no-falsey-clobber`, TS `prefer-nullish-coalescing`) catch most of these
classes automatically. This runbook is the methodology that produced the
gates and that maintainers still walk through manually for complex PRs —
"what would the gates miss?"

If you are an external contributor opening a PR against an SDK, you are not
expected to run this end to end yourself. You should know it exists so you
can write changes that pass it on first review.

## When to run this

- A PR touches one or more wire-bound interface / dataclass / struct /
  POJO. Wire-bound = a type that maps to an OpenAPI schema. The
  wire-shape baseline file lists which types are tracked.
- A PR adds, renames, or removes a field on an existing wire-bound type.
- A PR adds a new transformer (a hand-written function that builds a
  wire-bound return value from raw response data).
- A PR adds or changes a sync facade over an async method (Python).

If none of those apply, the standard CI gates are sufficient.

## The four passes

Each pass catches a different class of bug. Run them in order — later
passes assume the earlier ones are clean.

### Pass 1 — diff-based field enumeration

For each wire-bound type touched by the PR, list the property names
**before and after** and confirm:

- Every server field (per the OpenAPI spec at the pinned SHA) is
  present on the type, or marked `@deprecated` with a migration note.
- Every property on the type maps to either (a) a server field, (b) an
  `@sdkDerived` property (Cat C — see ADR-047), or (c) a `@deprecated`
  hold-over with a removal target.
- No property name silently changed casing or shape. Renames must be
  explicit in the changelog, never side-effects of a refactor.

**How**:

```bash
# For TypeScript:
git diff origin/main..HEAD -- src/types/ | grep -E "^[+-]\s+[a-zA-Z_]+:"

# For Python:
git diff origin/main..HEAD -- axonflow/types.py axonflow/masfeat.py | grep -E "^[+-]\s+[a-zA-Z_]+:"

# For Go:
git diff origin/main..HEAD -- *.go | grep -E "^[+-]\s+[A-Z][a-zA-Z]*\s+\S+\s+\`json:"

# For Java:
git diff origin/main..HEAD -- src/main/java/ | grep -E "@JsonProperty"
```

Diff each output against the OpenAPI spec source of truth — that is
the wire shape, not the SDK.

### Pass 2 — transformer reachability walk

For each wire-bound type a transformer returns, confirm every non-
`@deprecated` field on the type appears in the transformer's return
literal (or is propagated by a passthrough call like `orchestratorRequest<T>(...)`).

This is what the TS AST `transformer-coverage` gate does
automatically. Walk it by hand when:

- The transformer uses dynamic construction (variable returns,
  spread operators) the static gate skips.
- The transformer is in a language without an AST gate yet (Python).
- You are reviewing a sweep that touches many transformers at once.

**Specific bug shapes to look for**:

- `return { id, name }` where the type also declares `success` →
  `success` is unpopulated. Caller reads `undefined`.
- `return mapFoo(data, ...args)` where `mapFoo` builds a partial
  literal. Recurse into `mapFoo`'s return.
- Conditional branches with different shapes: `cond ? { a, b } : { a, b, c }`.
- Spread-into-literal: `{ ...other, foo: x }` — verify `other` has
  the right shape, otherwise this looks fine but propagates a
  partial.

For each transformer touched by the PR, write the type's required
keys on one side, the literal's keys on the other, and confirm they
match.

### Pass 3 — sync wrapper / facade signature check (Python only)

Python SDK exposes both async and sync versions of many methods.
The async version is canonical; the sync version is a facade
(usually `asyncio.run(self._async_self.method(...))`).

When a kwarg is added to the async version, the sync facade often
lags. The bug is silent — the sync version simply doesn't accept
the new kwarg, and Python's `**kwargs` plumbing makes it invisible
to mypy.

**How**: For every async method touched by the PR, check the
corresponding `axonflow.sync.SyncClient` method. The signatures
must be byte-for-byte identical (kwarg names, defaults, types).
Same for the `check_tool_*` aliases over `mcp_check_*`.

`grep -A5 "def mcp_check_input"` on both `client.py` (async) and
the sync wrapper, and visually diff. If you find a drift, the
sync method needs the same kwargs propagated, with the same
defaults, and the same `client_id` / `tenant_id` / `user_id`
threading.

### Pass 4 — falsey-clobber audit

In TypeScript and Python, `||` and `or` short-circuit on every
falsy value (`0`, `false`, `""`, `[]`, `{}`), not just `null`/`None`.
Wire fields can legitimately be any of those, so:

```python
result = response.result or fallback   # WRONG: drops result=0
```

The Python `no-falsey-clobber` lint and the TS `prefer-nullish-coalescing`
ESLint rule catch this. Walk it by hand when:

- The lint baseline is hiding pre-existing instances near your diff
  and you want to confirm they aren't worse than they look.
- You are reviewing a transformer that uses `||` / `or` in a way
  the lint allows (e.g. inside a conditional test).

**Replacement idioms**:

```python
# Python
result = response.result if response.result is not None else fallback
```

```typescript
// TypeScript
const result = response.result ?? fallback;
```

```go
// Go — already explicit, this is the idiom:
result := response.Result
if result == nil {
    result = fallback
}
```

```java
// Java — already explicit:
var result = response.getResult() != null ? response.getResult() : fallback;
// or:
var result = Optional.ofNullable(response.getResult()).orElse(fallback);
```

Go and Java are not affected by this bug class — `||` / `or` aren't
implicit-truthiness operators in either language.

## What "done" looks like

A PR that has been audited has:

- All four passes complete (Pass 3 only for Python).
- Every CI gate green (or every red gate has a baselined or
  justified entry — see "Burndown burndown policy" in the SDK's
  CONTRIBUTING.md).
- A changelog entry under `[Unreleased]` describing any wire-
  visible field add, rename, or removal. Phrase it from the
  caller's perspective (what they read), not the implementation
  (which transformer was edited).
- Tests covering the new field path. For new fields the test
  should assert the value flows through, not just that the type
  compiles. The bug class we catch with these passes is "type
  says X, runtime returns undefined" — a test that only asserts
  the type compiles cannot catch it.

## What the gates catch automatically vs. what this runbook adds

| Bug class | Caught by gate | Caught by runbook |
|---|---|---|
| Type drifts from spec | wire-shape contract gate | Pass 1 confirms |
| Transformer drops a typed field (object literal) | TS AST `transformer-coverage` | Pass 2 confirms + extends to dynamic constructions |
| Falsey-clobber on a wire field | TS `prefer-nullish-coalescing`, Python `no-falsey-clobber` | Pass 4 confirms + extends to lint-tolerated cases |
| Sync facade lags async signature | _no gate_ | Pass 3 catches |
| Helper transformer (`mapFoo`) builds partial | _no gate_ | Pass 2 catches via recursion |
| Cross-spec schema duplication | wire-shape contract gate | — |
| Server emits a field the spec doesn't declare | _no gate_ (server is authoritative; spec is the artefact that drifts) | Pass 1 catches if you're reading server code |

The runbook plus the gates is where we sit today. Phase 2 work in
ADR-047 closes most of the "no gate" rows above.

## When you find a bug

Fix it in the same PR. Do not file a follow-up "we'll fix it later"
issue — the same shape of bug shows up at every review round when
deferred. If the fix is genuinely out of scope, the burndown-or-
justify policy in the SDK's CONTRIBUTING.md applies: justify in the
PR description with one line of context.

## Reference

- ADR-047: SDK rigor gates — language-targeted CI for wire-shape and transformer drift
- Wire-shape contract gate: `tests/fixtures/wire-shape-baseline.json` in each SDK repo
- TS AST `transformer-coverage`: `scripts/transformer-coverage/check.js`
  in `axonflow-sdk-typescript`
- Python `no-falsey-clobber`: `scripts/lint_no_falsey_clobber.py` in
  `axonflow-sdk-python`
- TS lint: `eslint.config.js` rule `@typescript-eslint/prefer-nullish-coalescing`
  in `axonflow-sdk-typescript`
