# The capability registry

`registry.json` is AxonFlow's one canonical capability registry (ADR-066
decision 1). It states, for every capability the platform ships, what edition a
deployment needs for it, how it is protected, what it exposes, and whether
`/health` advertises it.

Two things consume it:

- **both `/health` planes**, which project their capability list from it. That
  list used to be a hand-maintained Go literal on each plane, and four release
  trains shipped without an entry ([#3618]). There is nothing to forget to edit
  now.
- **the census**, `technical-docs/EDITION_CAPABILITY_CENSUS.md`, which is
  generated from this file and fails CI when the two disagree.

It is **not** an entitlement mechanism. Nothing here is read at request time to
decide what a caller may do; the runtime licence checks in
`platform/agent/license` and the build-tag / `ee/` source separation are the
enforcement, unchanged. ADR-066 puts it plainly: the registry "is configuration
and metadata; it does not contain policy truth or replace license signature
validation."

## Adding or changing a capability

1. Edit `registry.json`.
2. `cd platform && go test ./shared/capability/` - the validator runs there.
3. `UPDATE_CENSUS=1 go test ./shared/capability/ -run TestCensusIsUpToDate` to
   regenerate the census.

If you added a **route**, `TestEveryRegisteredRouteHasACapabilityEntry` will
have told you already: it derives every registered route from the source and
fails on one that belongs to no capability.

If you added a **`/health` entry**, `TestProjectionReproducesTheFrozenWire`
will fail, because `testdata/health_wire_freeze_*.json` records what the planes
served before the projection existed. That is intended friction: adding a name
to a discovery surface that clients already branch on should require deleting a
line that says "this is what we used to serve", and updating the freeze is how
you do it.

## The schema

Top level:

| Field | Meaning |
|---|---|
| `schema` | Schema version. Checked on load - a reader compiled against one schema refuses a file written for another rather than reading moved fields. |
| `platform_version` | The release the census was taken against. |
| `generated` | ISO date. |
| `scan_roots` | Repo-relative directories the route and build-tag derivation walks. Declared in the data so the SCOPE of the census is reviewable in the same diff as the census. |
| `capabilities` | The entries, sorted by `id`. |
| `route_exemptions` | Registration sites the derivation cannot resolve, each with a reason. |
| `matrix_sections_out_of_scope` | Headings of the living feature matrix that no capability models, each with a reason. |

Per capability:

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | Stable `family.name`, lower snake case. What ADR-066's enforcement response quotes. Do not change it once shipped. |
| `title`, `summary` | yes | Human-readable name and one sentence. |
| `family` | yes | The first ID segment. Band scoring groups by it. |
| `minimum_edition` | yes | `community` \| `evaluation` \| `enterprise`. **There is no encoding for "undecided"** - an unclassified capability fails. |
| `source_classification` | yes | ADR-066 decision 2: `community_core` \| `evaluation_preview` \| `enterprise_protocol` \| `enterprise_implementation`. Where the SOURCE may live, which is a different question from which edition may run it. |
| `build_tag` | yes | `none` \| `enterprise` \| `split`. Checked against the files `implementation` names. |
| `sync` | yes | `mirrored` \| `excluded` \| `stub` - disposition towards the community mirror. |
| `implementation` | yes | Repo-relative paths or directories holding the backing code. |
| `owner` | yes | The test that exercises it. ADR-066 conformance item 10 wants every capability EXERCISED rather than merely compiled. |
| `routes`, `planes` | when it serves HTTP | Path patterns in the gorilla/mux spelling, and the binaries that serve them. A prefix covers the paths beneath it, at a path boundary. |
| `license_gate` | optional | `TierLimits` field names or gate functions. Every name is checked against the struct. |
| `migrations` | optional | Migration LANES (`core`, `enterprise`, `industry`, `community-saas`, `internal`), not file numbers - the lane is the edition-relevant fact. |
| `portal`, `docs`, `matrix` | optional | Portal control, public documentation path, and the matrix headings that cover it. |
| `health` | one of the two | `{name, since, description, planes, order, description_overrides?}` - the wire entry, served verbatim. |
| `health_absent_reason` | one of the two | Why this capability is deliberately NOT advertised. Mandatory when `health` is absent: an omission from a discovery surface reads to an SDK as "not supported", so it has to be a recorded decision. |
| `health_gap` | optional | `true` when the absence is arguably wrong rather than settled. A FIELD, not a phrase in the reason: a census that found its own gaps by grepping its own prose would be satisfied by a sentence saying something is *not* one. |
| `score` | yes | `{community, evaluation, enterprise, basis, reason?}`. Availability is `full` (1.0), `limited` (0.5) or `none` (0.0); `basis` is `MEASURED`, `CHOSEN` or `UNSCORABLE`. A non-MEASURED figure must carry a reason. |
| `matrix_disagreement` | optional | Where the living feature matrix and the tree say different things. Recorded, never resolved: editing the matrix to match the code would launder the discrepancy, and changing the code would be an entitlement change. |
| `notes` | optional | Anything no other field holds. |

### Consistency rules the validator enforces

- Duplicate `id`s, duplicate `/health` names, and two entries claiming the same
  `/health` position.
- An empty or unknown `minimum_edition`, `source_classification`, `build_tag`,
  `sync`, `score.basis` or availability. `""`, `"unknown"` and `"tbd"` are all
  rejected.
- A classification that contradicts the edition, the build tag or the sync
  disposition - `enterprise_implementation` cannot be `build_tag: none`,
  `sync: mirrored`, or `minimum_edition: community`.
- A missing owner, or an owner that is not a test.
- A score that is not monotonic across editions, or that gives a lower edition
  more than `minimum_edition` allows.
- `limited` for Community with nothing naming the cap.
- An entry with neither a `health` block nor a `health_absent_reason`, or with
  both.
- Two entries claiming the identical route prefix. (NESTED prefixes are fine -
  the longest wins.)
- An unknown field name anywhere in the document.

### What is derived rather than declared

`derive.go` PARSES every non-test Go file under `scan_roots` with `go/ast` and
resolves the path argument of every `HandleFunc` / `Handle` / `PathPrefix` /
`Path` call, following package-local and cross-package string constants and
`PathPrefix(...).Subrouter()` chains.

A regex would not do, and this is the measurement rather than an opinion: **19
registration sites on `main` name a constant instead of a string literal, and
two of them are `POST /api/v1/decide` and `POST /api/v1/access/evaluation`** -
the platform's two most-called governance surfaces. A census built on
`grep '"/api/v1'` would report a clean sweep of a route set missing both.

The same parse yields each file's build-constraint classification, using the
community sync's own expression for enterprise-only source
(`tests/regression-test-required/enterprise_tag_regex_single_definition_test.sh`
keeps that expression byte-identical across every site that reads it).

### On the mirror

This package syncs to the public repository - the community build projects its
own `/health` from `registry.json`, so it has to. Two consequences:

- The tests here run in both lanes, under `Unit Tests: Platform Packages` in
  `test.yml` and its community twin.
- Checks whose subject the mirror legitimately strips (`ee/` paths, the
  enterprise half of a build-tag pair, `technical-docs/`) skip **only** when the
  whole excluded directory is absent, and fail when the directory is present and
  the file is not. A stripped file and a deleted one are different things.

Anything commercially sensitive should NOT go in `registry.json`, because it is
published. The derived percentage bands live in the census, under
`technical-docs/`, which the sync excludes.

[#3618]: https://github.com/getaxonflow/axonflow-enterprise/issues/3618
