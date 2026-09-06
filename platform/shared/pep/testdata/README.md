# `frozen_wire_origin_main_0a4b97119.json`

The exact request bytes `platform/shared/pep`'s encoder produced **before** #3704,
captured by running a capture test inside a worktree checked out at
`origin/main` commit `0a4b97119` — **not** regenerated from the changed tree.

That distinction is the whole point of the file. A fixture regenerated from the
new code proves the new code is self-consistent, which it would be whatever it
did; it cannot say whether the bytes a shipped SDK sends today still mean what
they meant. These bytes were produced by the code that shipped.

The fifth row is the evidence rather than the assertion: on `origin/main`,
`FulfillmentCapabilities: []string{}` encodes **byte-identically** to
`FulfillmentCapabilities: nil`. Measured, not argued.

**That is the ENCODER's collapse, not the wire's**, and the qualifier is load
bearing. A non-Go caller could always put `[]` on the wire — `caps or []` in
Python, `JSON.stringify([])`, a hand-built curl — and the server has always read
it as a legacy caller. It still does, deliberately: changing that reading would
widen a security control for a caller that changed nothing. So this fixture
proves the encoder never produced `[]`, and says nothing about what the decoder
made of it. `TestExplicitEmptyOnTheWireStillReadsAsALegacyCaller` in
`platform/agent` is what speaks for the decoder, and it starts from literal
bytes for exactly that reason.

`frozen_wire_test.go` asserts that rows 1-4 are unchanged after #3704 and that
row 5 is the ONLY one whose bytes moved.

Regenerate ONLY when deliberately re-baselining against a new pre-change commit,
and rename the file to that commit. Never regenerate to make a test pass.
