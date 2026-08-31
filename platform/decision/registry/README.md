# ADR-065 registry plane

The action, tool, resource-type and PEP registry: the catalog every governed
operation resolves against before a policy runs.

Tracking: [#3558](https://github.com/getaxonflow/axonflow-enterprise/issues/3558)
under epic [#3549](https://github.com/getaxonflow/axonflow-enterprise/issues/3549).

## What this package is for

Two things ADR-065 makes structural, which were previously inferred per plane:

1. **An operation with no registered action is refused at admission**, before any
   policy loads, and distinguishably from a registered action with no matching
   permission. The two need different fixes.
2. **The failure semantics of a registered action are declared, not defaulted.**
   Both posture axes are mandatory; there is no global default, no inference and
   no inheritance.

## Where this sits

`platform/decision/pdp` already carries the admission-time `Registry`: the map
the evaluator consults. This package does not replace it and does not restate
it. It is the registration and governance layer whose output **is** that map, via
`Catalog.PDPRegistry`.

A catalog that fails validation cannot be projected. That is the mechanism, not a
convenience: there is no path from a record with an undeclared posture to a
running evaluator, even for a catalog that was not assembled through
`RegisterAction`.

```
RegisterTag / RegisterResourceType / RegisterRealm
RegisterAction / RegisterTool / RegisterPEP        registration rules
RegisterCompatibilityException
        |
        v
     Catalog  --- Validate() ---> Findings (complete, ordered, stable)
        |
        +-- PDPRegistry()          -> pdp.Registry        (admission)
        +-- CompatibilityProfile() -> pdp.CompatibilityProfile
        +-- PEPRecord.Profile()    -> contract.PEPProfile  (obligation composition)
        +-- CheckAncestorLevel / CheckContainmentScope     (authoring save time)
        +-- SupportsObligation / CheckPublication          (capability)
```

## The three rules worth reading before changing anything

### Posture is two axes, both mandatory, and its legal values are narrow

`Unmatched` is `not_applicable` or `permit`. It is **not** `deny`: under the
four-valued outcome, deny means an explicit constraint matched, and seeding the
grant fold with deny would report a constraint that never fired. Both reach the
PEP state `DENY` through `contract.StateFor`, so preserving the distinction costs
nothing.

`OnError` is `indeterminate` or `permit`, by the same argument.

`permit` on either axis is the source proposal's fail-open, which ADR-065
reverses as an owned decision. `Unmatched=permit` is accepted only behind a
registered compatibility exception naming an owner, a metric, an expiry and a
removal issue, and never on a privileged, irreversible or data-egress action.
`OnError=permit` is refused outright, with no exception path.

### A governed tag is a policy channel, so registration is create-only

A policy selects actions by tag. Changing an action's tags moves it into and out
of the reach of policies nobody edited, so a tag change is `ApplyTagChange` with
an approval reference, not a field somebody overwrites. Registration is
create-only because an overwrite would be the bypass that makes the change path
advisory.

Both directions alarm. Removal disarms every constraint selecting on the tag;
addition arms every permission selecting on it. Neither shows up as an edit to
any policy document.

### Edition is a property of the enforcement point, not of this binary

A community gateway, an SDK interceptor or a plugin can enforce decisions taken
by an Enterprise PDP. Whether it can discharge an obligation is a fact about
*that* machine, so `Edition` is a field on the PEP record and an input to the
capability check, rather than a compile-time build tag.

`CapabilityNoRecord` and `CapabilityDeclaredNone` are separate answers. The
existing #2958 fulfillment handshake carries its capability list in an
`omitempty` field, so an enforcement point advertising an empty set is
byte-identical on the wire to one that advertised nothing and both read as
"legacy caller". Under ADR-065 invariant 8 both deny, and they deny with
different explanations.

## Conformance

`AXC-300` through `AXC-399` are this plane's identifiers; nothing outside this
package allocates in that range. The corpus is in `conformance.go` and is held to
the source tree by three mechanisms, in the form the identity plane established
in #3570: every case names a test that must exist, every test marks its case and
`TestMain` fails the package if one never ran, and the disposition ledger's
coverage cells are compared against the computed corpus.

`TestSourceMutationsAreKilled` compiles a mutated copy of this package through
`go test -overlay` for each of eighteen guards and requires the named test to go
red. The tree is never edited in place. `TestTheMutationGateCanReportASurvivor`
is the other half: an inert mutation must leave the test passing, or a runner
that always reported failure would produce the same green result.

## The authoring plane is derived, not parallel

`authoring.NewCatalogFromRegistry` builds the authoring-time catalog from this
one, so the actions, resource types and realms an author may reference are the
ones somebody registered rather than a second table. It inherits the refusal:
a registry that cannot be projected cannot become an authoring catalog either.

Realm ATTRIBUTES are supplied by the caller rather than read from here. The
registry declares which realm qualifiers are trusted, because that is its half
of the symmetric admission check; whether a realm is interactive and whether it
has a group graph belong to `platform/shared/identity`. The derivation refuses
when the two sets disagree in either direction.

`authoring` answers `SCOPE_REQUIRES_RECURSION` and `LEVEL_NOT_DECLARED` per
POLICY, naming the policy that would be inert; this package answers the same two
per RESOURCE TYPE, for a consumer holding a type and no policy.
`TestTheTwoContainmentChecksCannotDisagree` holds the two to the same answer on
every declared type and level, and a mutant proves it can fire.

## The legacy plane fixture

`legacy_plane_peps.tsv` is the registry view of the twelve legacy enforcement
planes, per edition, with the file and symbol behind every capability claim.
Under-advertising is the safe direction and is what this table does: a capability
is listed only where there is a named enforcement path behind it, and a plane is
absent from an edition only when its source carries that build constraint.

The plane vocabulary belongs to the shadow-diff harness
(`platform/decision/legacycompile`, [#3577](https://github.com/getaxonflow/axonflow-enterprise/pull/3577)).
`legacy_plane_census_test.go` holds this table to a reviewed literal list
unconditionally, and compares it against that package's own plane constants as
soon as they are in the tree.
