# ADR-065 conformance corpus and source-case disposition ledger

This directory is the executable specification for ADR-065 Phase 0. It carries
three artifacts that are checked against each other on every run:

1. **The fixture world** (`world.go`, `scenario.go`), which is the Grants and
   Ceilings draft's fixture set translated into ADR-065's four policy
   authorities.
2. **The disposition ledger** (`disposition_ledger.tsv`), one row per source
   case, recording what happened to it.
3. **The case corpus** (`cases_test.go`, `cases_corrective_test.go`), which
   executes every case against a `contract.Decider`.

The ledger guard fails if the three disagree. That is the point: the failure
mode worth designing against is a row that still claims coverage after the case
behind it stopped running.

## How to read the ledger

`disposition_ledger.tsv` is tab separated with a fixed header and exactly 47
data rows, one per source case, permanently. ADR-065 Phase 0 requires every
source case to carry exactly one disposition, so a forty-eighth row breaks the
gate rather than extending it.

| Column | Meaning |
|---|---|
| `source_case_id` | `EX-01` through `EX-47`, verbatim from the source draft |
| `source_title` | the case's own title |
| `source_family` | the section of the corpus it belongs to |
| `source_result` | what the source draft says the case produces |
| `disposition` | `kept`, `changed`, `replaced` or `dropped` |
| `adr065_result` | the operational state ADR-065 produces |
| `semantic_reason` | why, in enough detail to review |
| `replacement_case_ids` | new cases added because of the change, `-` when none |
| `coverage_case_ids` | every case that actually covers this row |
| `approving_reviewer` | the review authority the row was approved by |

A compound outcome is written with a semicolon, for example `ERROR;DENY`, so a
case with two arms names both rather than being summarised into an aggregate
category the source case cannot be read back out of.

### What the dispositions mean

- **kept**: ADR-065 produces the same operational outcome by the same rule and
  the case transcribes directly.
- **changed**: the case remains meaningful but ADR-065 produces a different
  outcome, a different determining rule, or both. The transcribed case is
  updated to assert the new result, so the case itself is still the coverage.
- **replaced**: the source case's mechanism does not exist in ADR-065. Other
  cases cover the property it protected, and they must be named.
- **dropped**: the case tests a construct ADR-065 removes. It still requires
  named replacement coverage, because ADR-065 gate 14 asks for executable
  replacement coverage for changed, replaced AND dropped cases. A drop is never
  a way to stop covering a property.

The committed ledger contains no `replaced` and no `dropped` row, and that is a
finding rather than an omission: the source proposal's decomposition survives
intact, and what ADR-065 changes is the algebra and the failure postures rather
than the decomposition. The guard's self-test exercises both unused
dispositions against synthetic rows, so the rules that would catch a bad
`replaced` or `dropped` row are executed on every run rather than lying dormant
until the first one is written.

### Approving authority

Every row whose disposition is not `kept` changes a fail-closed boundary, so it
carries `architecture+security` rather than `architecture` alone, and the guard
enforces that pairing. The approving ACT is the merge of the pull request that
introduces or edits the row: git records the actor and the timestamp, which is
a stronger record than a hand-typed name that goes stale the first time
somebody changes teams.

## Coverage across workstreams

Conformance case identifiers are namespaced `AXC-NNN`. This package owns
`AXC-001` through `AXC-199`; `AXC-200` through `AXC-299` belong to the identity
plane workstream, which cites its own cases into the `coverage_case_ids` cells
of the rows its corpus covers.

The guard is built for that. Per row it requires **at least one** coverage
identifier that resolves to a case executing in THIS package, and it accepts
identifiers that do not resolve here. What it refuses is a row whose only
coverage is an identifier nothing runs, which is the placeholder failure: a cell
that reads as green while pointing at nothing.

## The families of the corpus

| Family | What it exercises |
|---|---|
| A Baseline | permission coverage, default deny, union across groups |
| B Constraints | explicit denial, exception clauses, conjunctive selectors |
| C Approval | conjunction of threshold clauses, deduplication without pool flattening |
| D Closure | inherited scope, cyclic directories, truncated closures |
| E Indeterminacy | unknown permissions and constraints, Kleene short-circuit |
| F Obligations | per-leaf disclosure resolution, incomparable transforms, capability checks |
| G Reservation | reserve, commit, release, expiry, concurrent holds |
| H Delegation | chain meet, delegation depth |
| I Inspection | gating versus advisory controls, evidence-based obligations |
| J Binding | decision binding, break-glass, admission refusals |
| K Containment | named levels, recursive closures, multi-parent resources |
| L Realms | authoritative empty closure, non-interactive approver pools, undeclared realms |
| M to Y | the corrective cases ADR-065 adds |

## Why a case can fail

Three layers, in increasing strength:

- **Assertion counting.** The runner refuses a case that recorded zero
  assertions. A case that runs, does not error and checks nothing is not
  coverage, and this turns that from an invisible pass into a named failure.
- **Mutation proofs** (`mutation_test.go`). For at least one representative case
  per family, the property is asserted to HOLD on the clean policy world, the
  mutant is asserted to COMPILE (a mutant that fails to build is a broken
  mutant, not a kill), and the property is asserted to FAIL on the mutant.
- **The tri-state corpus** (`tristate_corpus_test.go`). For every attribute any
  policy references and every way that attribute can fail to be a resolved
  value, a policy that matched on healthy data may stay matched or become
  unknown, but may never become a clean non-match.

  Its floor counts the per-policy comparisons it PERFORMED, not the subtests it
  generated. The generated count is identically the product of two lengths and
  survives the deletion of every assertion it claims to guard; an earlier
  version of this corpus generated ninety-eight subtests and performed
  twenty-eight checks, and a planted fail-open in the helper passed the whole
  package. The gate now fails if any referenced attribute carries no evidence
  at all, and separately if the staleness family never produced an unknown,
  which is the one family whose perturbation the evaluator rather than the
  fixture applies.

- **A declared outcome per source case.** Each transcribed case states the
  operational outcome it shows ADR-065 reaching. The runner checks that
  declaration against what the case observed, and the ledger guard checks the
  `adr065_result` column against the declaration. Without that loop the column
  is unverified prose: three rows once claimed an outcome no assertion
  produced.

## Running it

```
cd platform/decision && go test ./...
```

The corpus, the ledger guard, the tri-state corpus, the mutation proofs, the
property tests and the schema validation all run under that one command, and
all of them run in the `Unit Tests: Decision Contracts` job on every pull
request.
