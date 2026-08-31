# platform/decision/authoring

The typed policy authoring control plane of ADR-065: the layer above the
deterministic PDP that owns how a policy comes into existence, how it is
refused, how it is published, and how it is rendered back.

ADR-065 makes one promise the whole first release rests on: *"no raw customer
Rego in the first release. The supported authoring API produces a typed,
versioned policy document compiled into a bundle and rendered back without
loss."* `platform/decision/pdp` owns the vocabulary, the compiler and the
evaluator; it has no notion of a document somebody saved, somebody else
reviewed, that was published under an authority root, pinned by digest, or
rolled back. Those are the operations an operator performs, and they are what
this package is.

## Where the vocabulary lives

`pdp.Document` **is** the policy vocabulary. This package does not restate it,
wrap each field, or maintain a parallel enum. `authoring.Document` carries a
`pdp.Document` verbatim in one field and adds only what `pdp` cannot know:
which registered actions, resource types and realms exist, and who authored the
thing.

A field added to `pdp.Policy` is therefore authorable, compilable, renderable
and diffable here with no change to this package, and the class of defect where
a server switch and a UI list drift apart cannot start, because there is no
second list. The diff walks `pdp.Policy` by reflection and
`TestDiffCoversEveryPolicyField` holds the walk to `reflect.NumField`, so the
two cannot drift either.

The one thing this package derives rather than re-declares is
`pdp.Document.InteractiveRealms`, which duplicates a fact the `Catalog` already
holds. It exists because a signed bundle has to be self contained: an evaluator
verifying offline cannot call back into a registry. `NewDocument` is its only
writer and `CATALOG_DISAGREEMENT` refuses a document whose copy says something
the registry does not.

## The four things this package guarantees

**1. Rendered back without loss is a theorem.** `Render`, `Parse` and `Publish`
are held to a property over *generated* documents, not to examples:

```
document -> render -> parse -> render  is byte-identical
                      parse -> compile is byte-identical to the published module
                      parse -> build   is byte-identical to the published bundle digest
```

The last two conjuncts are what make it a statement about policy rather than
about JSON. A render that dropped a field the compiler reads would satisfy the
first and fail these, and an operator reading the source in a portal would
otherwise have no way to detect that it is not the source being enforced.
`TestPropertyDocumentsRenderBackWithoutLoss` draws 400 documents;
`TestTheGeneratorReachesTheWholeVocabulary` is its anti-vacuity gate and names
any authority, condition kind, obligation type or feature the corpus never
reached.

**2. Document digests are byte-exact.** `Render` uses `contract.ExactJSON`, not
`contract.CanonicalJSON`. The two exist for opposite purposes: request agreement
normalizes Unicode, artifact integrity must not. A digest over an NFC-normalized
projection is satisfied by every byte sequence sharing that projection, and two
documents differing only in Unicode composition compile to different Rego and
match different values. `TestUnicodeNormalizationCannotCollideTwoDocuments`
asserts both directions, including the counterfactual that the *normalizing*
encoder does collide them, so the distinction cannot quietly stop being
load bearing.

**3. Rejections are the product.** Every refusal carries a declared code, a
severity, the policy it is about, and a sentence a portal renders verbatim.
`Findings` is ordered and complete rather than first-error: an author fixing one
rejection per publish attempt is how a rule set stops being enforced in
practice. The check set has three layers, decided by what each check needs to
see: the envelope, the relayed `pdp` rules, and the catalog-aware rules that
cannot live in `pdp` because a compiled bundle is evaluated offline against no
registry at all.

**4. There is exactly one path to a signed artifact.** `Artifact` carries only
unexported fields, so no struct literal anywhere produces one. `Publish`
validates, compiles, runs the gauntlet against *that* bundle rather than a
rebuild, signs, and pins. The gauntlet report is inside the signed view, so an
artifact cannot claim results it did not get, and `LoadArtifact` re-derives every
claim including recompiling the carried source and requiring a byte-identical
module.

## The check set

Twenty-seven declared checks. Thirteen are relayed from `pdp`'s own authoring
validator and are not reimplemented here; `TestRelayCoversEveryPDPRule` holds the
relay table to `pdp.AllRules`, so a rule added there cannot reach a portal as a
refusal whose explanation is missing. Fourteen are owned here because they need
the registry, the publication actors, or a cross-policy view.

Every check has a case proving it fires **and** a mutant proving that case can
fail. The mutants are real edits to the real source, compiled and run through
`go test -overlay`, so nothing on disk is modified and a harness killed mid-run
cannot leave the tree mutated. The harness demands the mutant *build* as its own
step, because `go test` exits non-zero for a compile error and a failing
assertion alike and a harness reading only the exit code reports a mutant that
never compiled as proof of a working guard. An inert control mutant must still
pass, which is what separates "these cases detect the check" from "this harness
reports failure".

Two mutants survived the first run, and both were the same defect in the cases
rather than in the checks: asserting only that a code appeared is satisfied by
the code appearing for the wrong reason. Every case now names the offending
value, and `detail` is a required field.

Five source-specification checks are recorded as retired with the reason each
was dropped, and `TestRetiredChecksAreGenuinelyRetired` makes the disposition
executable: a retired code that reappeared in the active set, or an active code
also listed as retired, fails there rather than in a review six months later.

## The publication gauntlet

Five gates, in order, each recording the number of assertions it actually
performed so that a gate degenerating to zero work is visible in the signed
report instead of reading as a pass: `compile`, `round_trip`, `fixtures`,
`tri_state`, `determinism`.

The `tri_state` gate is the executable form of ADR-065's *"synthetic missing,
absent, stale, malformed, and resolver-failure inputs are generated for every
referenced attribute during bundle validation"*. It degrades every referenced
attribute through every declared unknown reason plus authoritative absence and
requires that no degradation turns a `NO_MATCH` into a `MATCH`.
`TestGauntletTriStateGateRefusesAWideningDegradation` falsifies it by planting a
fail-open in the platform-owned tri-state helper; under that plant the author's
own fixtures still pass, which is the point, because every baseline attribute is
known and the defect is invisible to every case a person would write.

## What is not here

**No migration and no persistence.** A document is a content-addressed artifact
in the bundle store, not a row. `Store` is in-process. Persistence needs a
schema number that only the release owner allocates, and self-picking one is how
two branches collide on it.

**No HTTP surface.** `API` is in-process. A transport is a layer over these
calls rather than a second implementation of them, and every method delegates to
the package-level function that carries the guard, so a handler that forgets to
validate is not something anyone can write.

**No effect claim the source cannot support.** `DiffDocuments` returns
`EffectUndetermined` for an edited condition, and does so freely. Whether a new
condition admits more requests than the old one is a question about every
possible request, which two condition trees do not answer. An operator told a
change is undetermined goes and looks; an operator told it narrows does not.
