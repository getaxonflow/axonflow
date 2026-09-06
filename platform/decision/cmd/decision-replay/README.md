# decision-replay

Reproduce a recorded policy decision offline, from normalized input against pinned bundles, with nothing running.

This is ADR-065 acceptance gate 16's artifact: *"replay reproduces sampled decisions from pinned inputs and bundles."* It is also the incident tool. When someone disputes a decision - "why was that refund held for approval?", "why did that export deny?" - you reproduce it on a laptop from two files and see the same operational state, the same safe reason code and the same decision identifier, months after the fact and with no database, no orchestrator and no network.

## Build and run

```
cd platform/decision
go build ./cmd/decision-replay

./decision-replay -environment ENV.json RECORD.json [RECORD.json ...]
./decision-replay -environment ENV.json -dir samples/
```

Against the fixture that ships with the module:

```
$ ./decision-replay -environment replay/testdata/environment.json -dir replay/testdata/samples -quiet
environment sha256:aedf17935e167c823dfd08dc3381d759565238f52ff0e20ffad1fba402b55363
  bundle organization   sha256:fafe6c63da63897b2af1afcb0f597e3fcb35a72f35dc1f4fa3f97a678eebf329
  bundle system         sha256:dff5063380cea338ed604a53fbdf17dbaa3cd9564e6d6df4f33fd5059c828c84
VERIFIED personal-data-egress-denied  DENY/explicit_constraint  dec_c307f0b7b1d06d2c
VERIFIED read-only-has-no-matching-permission  DENY/no_matching_permission  dec_2b055c85424d4896
VERIFIED spend-above-threshold  CHALLENGE/approval_required  dec_e12d504d6d55c655
VERIFIED spend-below-threshold  ALLOW/permitted  dec_f895af74d7e5bd37
VERIFIED unresolvable-attribute-is-indeterminate  ERROR/unknown_constraint  dec_e84e7c27bb583b2c
```

Drop `-quiet` and the full decision is written to **stdout** as JSON, one object per record; the verdict lines and every diagnostic go to **stderr**, so `decision-replay ... > decisions.json` gives you a clean artifact.

## Exit codes

| Code | Meaning | What to do |
|------|---------|------------|
| `0` | Every record replayed, and every record carrying an expectation reproduced it. | Nothing. The decision is what the record says it was. |
| `1` | The arguments, the files or the artifacts are unusable - including a run that named **no** records. | Fix the invocation. A run over zero records is a failure, not a pass. |
| `2` | A record does not match the environment it was replayed against. **No decision was produced.** | Find the environment the record was actually taken against. |
| `3` | The artifacts match, the input matches, and the answer **moved**. | This is either an evaluator regression or a record from a different build. Escalate. |

Codes 2 and 3 are deliberately different. "You are holding the wrong artifact" and "the evaluator no longer agrees with itself" send you to different places.

## The two files

### The environment

Everything outside the request that a decision depends on: the signed bundles and the source documents they were compiled from, the public keys those signatures verify against, the action registry, the enforcement point's advertised capability profile, the approval lifetime and the payload leaf schema.

It is deliberately **larger than "the bundles"**. The registry decides admission before any policy runs - an action's declared delegation depth and argument schema are decision inputs - and an enforcement point that advertises no capabilities turns a mandatory obligation into a DENY (ADR-065 invariant 8). Pin only the bundles and you can reproduce a decision that happens to be right.

### The record

One sampled decision: a `case_id`, the **normalized** `contract.Request`, the pins, and (optionally) the `expected` decision.

Normalized input, not the raw call, is the whole point of the gate's wording. A raw HTTP body would make replay depend on every resolver that turned it into attributes - the directory closure, the resource ancestry, the detector scores - and those are precisely the things an incident cannot reconstitute months later. The request that reaches the evaluator is the reproducible unit.

A record with no `expected` block still replays; the tool prints `EMITTED` instead of `VERIFIED` and asserts nothing. It is never reported as verified.

## Pins refuse; they never fall back

Every mismatch is a refusal and no decision comes back:

```
$ ./decision-replay -environment replay/testdata/environment.json /tmp/mispinned.json
REFUSED  spend-above-threshold-mispinned
  replay: record "spend-above-threshold-mispinned" does not match this environment and will not be replayed against it
    - root "organization": the record pins bundle sha256:0000…0000 and this environment holds sha256:fafe6c63…
  A replay against artifacts the record was not taken against reproduces a different question's answer, so it is refused rather than attempted.
$ echo $?
2
```

Four mismatch shapes are detected, and the last one is the one that would otherwise pass silently:

- a bundle digest naming a different policy set;
- a root the record pins that the environment does not hold;
- an **environment root the record never pinned** - everything the record names *is* present, and a third signed bundle is nonetheless participating in the union that the sampled decision never saw;
- an environment digest from a different environment, with matching bundles.

A tool that "did its best" against a nearly-matching artifact would put an authoritative-looking answer to a different question in front of whoever is on call. That is worse than no answer, so there is no `--force`.

## Producing a record

Today the committed fixture is generated from the ADR-065 conformance corpus by `platform/decision/replay/fixture_test.go`; regenerate it after a deliberate corpus change with:

```
cd platform/decision
AXONFLOW_UPDATE_FIXTURES=1 go test ./replay/
```

and review the diff - a moved bundle digest is a compatibility event for every stored artifact digest, exactly as `conformance/pins_test.go` says.

Capturing records from a live deployment (sampling real decisions into this format) is not wired yet; the types are `replay.Environment` and `replay.Record` and both are ordinary JSON.

## Where this runs in CI

`ADR-065 gate 16: offline replay from pinned inputs and bundles`, a named step in the `Unit Tests: Decision Contracts` job of both `test.yml` and its community twin. The step names each gate test and fails if any of them reports no `--- PASS:` line, because a `-run` pattern that matches nothing exits 0 - a renamed gate test would otherwise leave the step green having executed none of it.
