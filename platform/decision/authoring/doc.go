// Package authoring is the typed policy authoring control plane: the layer
// above the deterministic PDP that owns how a policy comes into existence,
// how it is rejected, how it is published, and how it is rendered back.
//
// ADR-065 makes one promise that the whole first release rests on: "no raw
// customer Rego in the first release. The supported authoring API produces a
// typed, versioned policy document compiled into a bundle and rendered back
// without loss." Nothing in platform/decision/pdp makes that promise real on
// its own. pdp owns the vocabulary, the compiler and the evaluator; it has no
// notion of a document that was saved by somebody, reviewed by somebody else,
// published under an authority root, pinned by digest, or rolled back. Those
// are the operations an operator actually performs, and they are what this
// package is.
//
// # The division of labour, and why the vocabulary lives in exactly one place
//
// pdp.Document IS the policy vocabulary. This package does not restate it,
// wrap each field, or maintain a parallel enum anywhere. authoring.Document
// carries a pdp.Document verbatim in one field and adds only what pdp cannot
// know: which registered actions, resource types and realms exist, and who
// authored the thing. A field added to pdp.Policy is therefore authorable,
// compilable, renderable and diffable here without one line changing, and the
// class of defect where a server switch and a UI list drift apart cannot start,
// because there is no second list.
//
// The one place this package derives rather than re-declares is
// pdp.Document.InteractiveRealms, which duplicates a fact the Catalog already
// holds. NewDocument fills it from the Catalog and CatalogAgreement refuses a
// document whose copy disagrees, so a hand-assembled document cannot claim a
// realm is interactive when the registry says otherwise.
//
// # Rendered back without loss is a theorem, not a feature
//
// Render, Parse and Publish are held to a round trip that is asserted over
// generated documents rather than over examples: the bytes a caller gets back
// from a published artifact are the bytes that were signed, they parse to a
// document that re-renders to the same bytes, and that document recompiles to
// a byte-identical Rego module under a byte-identical bundle digest. The last
// conjunct is what makes it load bearing rather than decorative. A round trip
// that only proves "the JSON survived" would still let a lossy render return
// a document that compiles to different policy from the one being enforced,
// which is the exact situation an operator reading the source in a portal
// would have no way to detect.
//
// # Rejections are the product
//
// A control plane whose validator says "invalid" is not a control plane. Every
// refusal here carries a declared code, a severity, the policy it is about and
// a sentence a portal can render verbatim, and Findings is ordered and
// complete rather than first-error: an author fixing one rejection per publish
// attempt is how a rule set stops being enforced in practice.
//
// # Where the guards live
//
// Validation lives in the document constructor and in Publish, not in each
// entry point of the API. A guard at the callers is not a guard: the next
// caller is the one that will not have it. Publish is the only function in
// this package that can produce a signed Artifact, and Artifact carries
// unexported fields so no other code, in this package or outside it, can build
// one by struct literal and skip the gauntlet.
package authoring
