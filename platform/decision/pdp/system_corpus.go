// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package pdp

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"axonflow/platform/decision/contract"
)

// THE SHIPPED SYSTEM CORPUS AND ITS TRUST ANCHOR (#3884)
//
// The platform's own controls ship as a typed document. This file is where a
// deployment reads it, and where the one property that makes it trustworthy is
// enforced.
//
// # THE ANCHOR IS A DIGEST, NOT A PUBLIC KEY, AND THAT IS THE DESIGN
//
// The obvious shape is a vendor PKI: sign the corpus at release with a private
// key that never leaves our infrastructure, compile the public key into the
// binary, verify at activation. That is how licences work
// (`platform/agent/license/tier.go`), and it is the wrong shape here.
//
// A signature answers "who published this". A digest answers "is this the
// artifact this binary was built with". For content that ships INSIDE the
// binary, the second is the question with teeth: twenty of the corpus's
// hundred-odd controls are algorithmic detectors whose behaviour IS a Go symbol
// in this binary, so an attacker who can replace the corpus source can replace
// `ValidateSSN` alongside it and a signature over the corpus would not have
// noticed. It would be a second, weaker supply chain beside the one already
// delivering the code the content names.
//
// It is also the only shape with no fail-open. A PKI needs an answer for "the
// signature is absent", which a contributor's machine and CI both produce, and
// both available answers are bad: a tree that does not build outside the
// release job, or a checked-in development private key that can sign a
// platform ceiling. The second is #1541's actual incident, where a private
// licence seed embedded in a script forced a key rotation and a re-signing of
// every active licence.
//
// `HelperDigest` above is the same mechanism for the same reason, one file
// over: the helper module is embedded "so that a deployed binary evaluates the
// helpers it was built with rather than whatever happens to be on disk".
//
// # REVISIT WHEN
//
// The first shipped detector whose content must change WITHOUT a binary
// release - a pattern issued as a content feed between releases. On that day
// the corpus is no longer release-scoped, a digest fixed at build time cannot
// express it, and a vendor PKI with real key custody becomes necessary; the
// custody precedent to copy is `platform/agent/license/tier.go:142-163`.
// Nothing in the v11 corpus has that property: every pattern is seeded by
// `migrations/core` and every algorithmic implementation is a Go symbol.

// SystemCorpusSource is the checked-in shipped corpus, embedded so a deployment
// activates the corpus its binary was built with.
//
//go:embed system_corpus.json
var SystemCorpusSource []byte

// shippedCorpus is the parsed corpus, memoised. Parsing is deterministic and
// the source never changes at runtime, so a second parse could only produce a
// second answer if something had mutated the embedded bytes, which is not
// reachable.
var shippedCorpus struct {
	once     sync.Once
	system   *Document
	org      *Document
	bindings map[string][]string
	digest   string
	// orgDigest is the organization template's digest, computed as digest is.
	orgDigest string
	err       error
}

// shippedCorpusFile is the artifact's shape. It is a private mirror of
// `legacycompile.Corpus` and NOT an import of it: `pdp` is the layer the
// decision core is built on, and a dependency from it on the migration tool
// that produced the artifact would outlive the migration by years.
//
// `shapeEqualityTest` below names the test that holds the two shapes equal, in
// the resolvable `path::Symbol` form, and `TestTheShapeEqualityCitationResolves`
// checks that it exists. An earlier version of this comment named a test that
// had never been written - the exact defect the same branch built
// `crossModuleEqualityTest` to prevent, one file over.
// shapeEqualityTest names the test that holds `shippedCorpusFile` equal to
// `legacycompile.Corpus`. It is a constant so the citation can be resolved.
const shapeEqualityTest = "platform/decision/legacycompile/system_corpus_test.go::TestTheArtifactShapeMatchesWhatPDPParses"

type shippedCorpusFile struct {
	System               *Document `json:"system"`
	OrganizationTemplate *Document `json:"organization_template"`
	// ScopeBindings names, for a shipped control whose legacy action differs
	// by enforcement scope, the scopes it binds on (SystemCorpusScopeBindings).
	ScopeBindings map[string][]string `json:"scope_bindings"`
	Divergences   json.RawMessage     `json:"divergences"`
}

func loadShippedCorpus() {
	system, org, bindings, digest, err := parseShippedCorpus(SystemCorpusSource)
	if err != nil {
		shippedCorpus.err = err
		return
	}
	orgDigest, err := contract.ExactDigest(org)
	if err != nil {
		shippedCorpus.err = fmt.Errorf("pdp: digesting the shipped organization template: %w", err)
		return
	}
	shippedCorpus.system, shippedCorpus.org, shippedCorpus.bindings, shippedCorpus.digest, shippedCorpus.orgDigest = system, org, bindings, digest, orgDigest
}

// parseShippedCorpus is the loader over arbitrary bytes, so what it refuses can
// be driven with an artifact that is not the embedded one.
func parseShippedCorpus(src []byte) (system, org *Document, bindings map[string][]string, digest string, err error) {
	var f shippedCorpusFile
	dec := json.NewDecoder(bytes.NewReader(src))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, nil, nil, "", fmt.Errorf("pdp: the shipped system corpus could not be parsed: %w", err)
	}
	if f.System == nil || f.OrganizationTemplate == nil {
		return nil, nil, nil, "", fmt.Errorf("pdp: the shipped system corpus carries no %s document",
			map[bool]string{true: "system", false: "organization template"}[f.System == nil])
	}
	if f.System.Root != RootSystem {
		return nil, nil, nil, "", fmt.Errorf("pdp: the shipped corpus's system document declares root %q", f.System.Root)
	}
	if f.OrganizationTemplate.Root != RootOrganization {
		return nil, nil, nil, "", fmt.Errorf("pdp: the shipped corpus's organization template declares root %q", f.OrganizationTemplate.Root)
	}
	if len(f.System.Policies) == 0 {
		// An empty system document is the failure mode this whole anchor
		// exists to make impossible: it would activate, verify, and enforce
		// none of the platform's own controls, with every count reconciling
		// against itself.
		return nil, nil, nil, "", fmt.Errorf("pdp: the shipped corpus's system document carries no policy; a deployment activating it would enforce none of the platform's own controls")
	}
	// EVERY SHIPPED CONTROL DECLARES ITS ASSURANCE CLASS, and a corpus in which
	// one does not is refused here rather than defaulted downstream: a portal
	// rendering "advisory" for a control nobody classified would be a statement
	// about its failure behaviour that nothing established.
	for _, d := range []*Document{f.System, f.OrganizationTemplate} {
		if err := RequireDeclaredAssurance(d); err != nil {
			return nil, nil, nil, "", fmt.Errorf("pdp: the shipped system corpus: %w", err)
		}
	}
	if err := validateScopeBindings(f.System, f.OrganizationTemplate, f.ScopeBindings); err != nil {
		return nil, nil, nil, "", fmt.Errorf("pdp: the shipped system corpus: %w", err)
	}
	digest, err = contract.ExactDigest(f.System)
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("pdp: digesting the shipped system corpus: %w", err)
	}
	return f.System, f.OrganizationTemplate, f.ScopeBindings, digest, nil
}

// validateScopeBindings refuses every binding shape that would leave a shipped
// control out of a scope without saying so (#4046).
//
//   - The section is REQUIRED, and empty when no control is split: an absent
//     section is indistinguishable from one a regeneration dropped.
//   - A binding names a policy of the system document or of the organization
//     template, whose redactions are bound by discharge (#4131). A binding for
//     a control the platform does not ship would bind nothing and describe
//     nothing.
//   - A bound control names at least one scope. One bound to none binds
//     nowhere, and every restriction would leave it out with no reason given.
//   - Its scopes are non-blank and strictly sorted, so a duplicate, a padded
//     name and an unstable order are refused rather than tolerated. Whether a
//     scope NAME is declared is not this package's to judge - pdp has no plane
//     vocabulary - and activation.RestrictToScope refuses an undeclared one.
func validateScopeBindings(system, template *Document, bindings map[string][]string) error {
	if bindings == nil {
		return fmt.Errorf("the artifact carries no scope_bindings section; an artifact whose controls bind on every scope carries an empty one, and an absent section is indistinguishable from one a regeneration dropped")
	}
	shipped := make(map[string]bool, len(system.Policies)+len(template.Policies))
	for _, doc := range []*Document{system, template} {
		for _, p := range doc.Policies {
			shipped[p.ID] = true
		}
	}
	var problems []string
	for id, scopes := range bindings {
		switch {
		case !shipped[id]:
			problems = append(problems, fmt.Sprintf("scope_bindings names %q, which is not a policy of the system document or the organization template", id))
		case len(scopes) == 0:
			problems = append(problems, fmt.Sprintf("%q is bound to no scope: it would bind nowhere, and every restriction would leave it out without saying why", id))
		}
		for i, scope := range scopes {
			if scope == "" || strings.TrimSpace(scope) != scope {
				problems = append(problems, fmt.Sprintf("%q is bound to a blank or padded scope %q", id, scope))
				continue
			}
			if i > 0 && scopes[i-1] >= scope {
				problems = append(problems, fmt.Sprintf("%q's scopes %v are not strictly sorted: a duplicate or an unstable order", id, scopes))
				break
			}
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("%d scope binding problem(s):\n  %s", len(problems), strings.Join(problems, "\n  "))
	}
	return nil
}

// SystemCorpusDocument returns the shipped system-root document.
//
// THE RETURNED POINTER IS THE MEMOISED ONE, and what protects it is a
// mechanism rather than a convention - but the mechanism is ACTIVATION-TIME
// and that bound is stated rather than left to be discovered.
//
// A caller that mutates this document BEFORE building a bundle from it does
// not get a mutated corpus activated: `NewEngine` binds every document to the
// bundle it claims to be the source of, and the anchor compares that bundle's
// source digest against `SystemCorpusDigest()`, which is computed once inside
// `once.Do` and cannot be moved by a caller. So a pre-activation mutation
// fails one or the other.
//
// A mutation AFTER activation is a different question and this does not answer
// it: `MetaIndex` copies obligation, pierceable-by and scope-group slices as
// HEADERS, so a running engine's combiner metadata aliases this document's
// backing arrays, and both checks fire once. Nothing recomputes a digest per
// decision.
//
// AN EARLIER VERSION OF THIS PARAGRAPH called the post-activation case safe
// because the one live construction it knew of - the decision shadow's world
// build - was `Unanchored(...)`, so `requireSystemBundle` and
// `checkSystemBundle` returned nil on their first line. v11 retired that
// observer (PRD v11 §1.1). The live constructions are now the anchored engines
// platform/decision/activation builds, where both checks run, so the
// post-activation question above is answered by what those callers do with the
// returned document, not by an exemption.
//
// Deep-copying a hundred policies on every call was the alternative, and for
// the SYSTEM side it is worse than it looks: the digest would then be a claim
// about bytes no caller holds, and two callers could hold two corpora that
// both claim to be the shipped one. The ORGANIZATION template makes the
// opposite trade, for a stated reason - see its own comment.
func SystemCorpusDocument() (*Document, error) {
	shippedCorpus.once.Do(loadShippedCorpus)
	if shippedCorpus.err != nil {
		return nil, shippedCorpus.err
	}
	return shippedCorpus.system, nil
}

// SystemCorpusOrganizationTemplate returns the shipped per-organization seed.
//
// IT RETURNS A COPY, AND THE SYSTEM DOCUMENT DOES NOT, BECAUSE THEY ARE
// DIFFERENT KINDS OF THING. The system document is a CEILING: a caller that
// mutates it before activation gets a refusal, because the anchor compares
// against the digest of the PARSED DOCUMENT - computed once at load, not from
// the file bytes - and `NewEngine` binds every document to its bundle. The organization template is a SEED whose documented use is "a
// deployment instantiates it per organization" - extending it in place is the
// expected shape of use - and organization bundles are not anchored, so
// nothing downstream would notice. R3 drove it: one caller appending a policy
// through the returned pointer made every later caller in the process see 23
// policies where the first saw 22.
func SystemCorpusOrganizationTemplate() (*Document, error) {
	shippedCorpus.once.Do(loadShippedCorpus)
	if shippedCorpus.err != nil {
		return nil, shippedCorpus.err
	}
	out := *shippedCorpus.org
	out.Attributes = append([]AttributeSchema(nil), shippedCorpus.org.Attributes...)
	// DEEP ENOUGH TO MATTER. Copying the policy slice alone protects
	// `Policies[i].ID` and leaves every slice INSIDE a policy shared -
	// obligations, pierceable-by, scope groups, condition operands. R3 drove
	// it: writing to a policy's obligation through the returned template was
	// visible to the next caller, and eight of these policies carry
	// obligations. A copy that protects the one field a test happens to poke
	// is not a copy.
	out.Policies = make([]Policy, len(shippedCorpus.org.Policies))
	for i, p := range shippedCorpus.org.Policies {
		out.Policies[i] = clonePolicyForTemplate(p)
	}
	if shippedCorpus.org.InteractiveRealms != nil {
		out.InteractiveRealms = make(map[string]bool, len(shippedCorpus.org.InteractiveRealms))
		for k, v := range shippedCorpus.org.InteractiveRealms {
			out.InteractiveRealms[k] = v
		}
	}
	return &out, nil
}

// SystemCorpusDigest is the trust anchor: the digest of the system document
// this binary shipped with.
//
// It is computed from the PARSED DOCUMENT, not from the embedded file bytes,
// and that is repeated here because a comment in this file once said the
// opposite. Digesting the bytes would make a re-indentation of the artifact
// look like a different corpus while a bundle built from it still verified.
//
// It is `contract.ExactDigest` over the DOCUMENT rather than over the file
// bytes, so it is directly comparable to a bundle's `Provenance.SourceDigest`,
// which `BuildBundle` computes the same way. Digesting the bytes instead would
// make a re-indentation of the artifact look like a different corpus while a
// bundle built from it still verified.
func SystemCorpusDigest() (string, error) {
	shippedCorpus.once.Do(loadShippedCorpus)
	if shippedCorpus.err != nil {
		return "", shippedCorpus.err
	}
	return shippedCorpus.digest, nil
}

// SystemCorpusOrganizationTemplateID names the shipped organization template as
// a document: what an organization's activation history records as active once
// it has withdrawn its own document (PRD v11 §1.15). The entry's kind, not this
// identifier, is what says the organization withdrew.
const SystemCorpusOrganizationTemplateID = "shipped-organization-template"

// SystemCorpusOrganizationTemplateDigest is the digest of the organization
// template this binary shipped with, computed as SystemCorpusDigest is: by
// contract.ExactDigest over the PARSED document.
//
// A withdrawal names it (PRD v11 §1.15). The implicit bundle an organization
// returns to is composed per scope, per vocabulary and per recorded override,
// so it has no single digest; the ledger names the document it is composed
// from instead. It is audit provenance, never a decision's snapshot: a
// decision names the bundle the engine actually composed (policy_bundle).
func SystemCorpusOrganizationTemplateDigest() (string, error) {
	shippedCorpus.once.Do(loadShippedCorpus)
	if shippedCorpus.err != nil {
		return "", shippedCorpus.err
	}
	return shippedCorpus.orgDigest, nil
}

// SystemCorpusScopeBindings returns, for every shipped control whose legacy
// action differs by enforcement scope, and every organization-template
// redaction bound by discharge (#4131), the scopes it binds on - as a copy. A
// control with no entry binds wherever a restriction's other arms keep it.
//
// NOT PART OF THE DIGEST, AND WHY THAT IS SAFE. The anchor digests the system
// DOCUMENT, and a restriction may only leave its controls out: every restricted
// policy is still held byte-identical to a shipped one
// (checkSystemRestriction). A binding decides WHICH controls a scope leaves out,
// exactly as the restriction's other arms do, and those arms are code. It ships
// inside the same binary as the document and that code, so it can narrow what a
// scope enforces and can never add or edit a control.
func SystemCorpusScopeBindings() (map[string][]string, error) {
	shippedCorpus.once.Do(loadShippedCorpus)
	if shippedCorpus.err != nil {
		return nil, shippedCorpus.err
	}
	out := make(map[string][]string, len(shippedCorpus.bindings))
	for id, scopes := range shippedCorpus.bindings {
		out[id] = append([]string(nil), scopes...)
	}
	return out, nil
}

// SystemCorpusAnchor states what a deployment's engine trusts as its
// system-root corpus.
//
// EXACTLY ONE OF THE TWO FIELDS IS SET, AND AN EMPTY ANCHOR IS REFUSED.
//
// The obvious alternative - an optional digest, unset meaning "no check" - is
// a fail-open with a field nobody filled in, and this package's own rule is
// that a guard at the callers is not a guard. So "this engine is not running
// the shipped corpus" is something somebody WROTE, with a reason that reaches
// the error message when a bundle is refused.
//
// The three legitimate unanchored callers today are the shadow harness, the
// replay environment and the conformance world: each compiles ad-hoc documents
// from recorded rows or fixtures, none of them activates the shipped corpus,
// and each says so in its own words.
type SystemCorpusAnchor struct {
	// Digest is the system-corpus digest this engine will activate, normally
	// SystemCorpusDigest().
	Digest string
	// UnanchoredReason says why this engine activates a system document that
	// is not the shipped corpus.
	UnanchoredReason string
	// RestrictionReason says why this engine activates a SUBSET of the shipped
	// corpus, and is set only alongside Digest. Empty with a Digest means the
	// engine activates the whole corpus and a bundle that is not byte-identical
	// to it is refused. See AnchorToShippedCorpusRestriction.
	RestrictionReason string
}

// AnchorToShippedCorpus is the production anchor for an engine that activates
// the WHOLE shipped corpus.
func AnchorToShippedCorpus() (SystemCorpusAnchor, error) {
	d, err := SystemCorpusDigest()
	if err != nil {
		return SystemCorpusAnchor{}, err
	}
	return SystemCorpusAnchor{Digest: d}, nil
}

// AnchorToShippedCorpusRestriction is the production anchor for an engine that
// activates a PLANE-SCOPED RESTRICTION of the shipped corpus (#3895).
//
// # WHY A RESTRICTION EXISTS AT ALL
//
// The shipped corpus is the UNION of the platform's controls across every
// enforcement plane, because ADR-065 removed execution location from policy
// identity. A single plane runs a SUBSET: `decide` runs the static substrate
// only, so the twenty-one controls compiled from dynamic_policies have no
// detector, no scorer and no resolver there.
//
// MEASURED, on a booted anchored engine with the whole corpus and a decide-plane
// request: the four dynamic-substrate CONSTRAINTS resolve UNKNOWN and the
// engine answers ERROR/unknown_constraint on every request; supplying the
// signals as authoritatively absent leaves `sys_dyn_gdpr` unknown on
// `principal.region` and the answer is still ERROR. A plane cannot enforce a
// control whose inputs it does not produce, and pretending the inputs resolved
// - a fabricated `false`, a fabricated empty region - is the fail-open the
// tri-state exists to forbid. So the honest move is to activate the controls
// that BIND on this plane and to say which those are.
//
// # WHY OMISSION IS THE ONLY PERMITTED EDIT, AND WHY THAT IS SOUND
//
// A restriction is verified as a SUBSET: every system-root policy in the
// bundle must appear, byte-identically, in the corpus this binary shipped. So
// a restriction cannot ADD a ceiling nobody authored and cannot MODIFY one -
// the two failures the whole-corpus anchor exists to prevent - and the only
// thing it can do is leave a control out. Against this anchor's stated threat,
// which is replacement of the corpus SOURCE (see the file header), that is no
// weaker: the source is still the embedded artifact and its digest is still
// checked, one policy at a time.
//
// What it does NOT defend against is an in-process caller choosing to omit
// everything, and that is stated rather than papered over: such a caller can
// already pass any document it likes to NewEngine. What makes the omission
// accountable instead of silent is that the restriction's own digest is
// recorded on the anchor and travels into the decision's policy-bundle
// identity, so "which controls decided this request" is answerable from the
// record. platform/decision/activation derives the restriction from the plane
// registry rather than accepting one as an argument.
func AnchorToShippedCorpusRestriction(reason string) (SystemCorpusAnchor, error) {
	if strings.TrimSpace(reason) == "" {
		return SystemCorpusAnchor{}, fmt.Errorf(
			"pdp: a restriction of the shipped system corpus must say in words which controls it leaves out and why; " +
				"an unexplained restriction is a platform ceiling somebody narrowed with no record of it")
	}
	d, err := SystemCorpusDigest()
	if err != nil {
		return SystemCorpusAnchor{}, err
	}
	return SystemCorpusAnchor{Digest: d, RestrictionReason: reason}, nil
}

// Unanchored declares an engine that activates a system document other than
// the shipped corpus, with the reason.
func Unanchored(reason string) SystemCorpusAnchor {
	return SystemCorpusAnchor{UnanchoredReason: reason}
}

// Validate refuses an anchor that is empty or that is both things at once.
func (a SystemCorpusAnchor) Validate() error {
	switch {
	case a.Digest == "" && a.UnanchoredReason == "":
		return fmt.Errorf("pdp: an engine declares no system-corpus anchor. Set SystemCorpus to AnchorToShippedCorpus() to " +
			"activate the corpus this binary shipped with, or to Unanchored(reason) to say in words why this engine " +
			"activates a system document that is not it. There is no default: a missing anchor would be a system root " +
			"nobody is checking, which is the whole thing the anchor exists to prevent")
	case a.Digest != "" && a.UnanchoredReason != "":
		return fmt.Errorf("pdp: the system-corpus anchor is both pinned to digest %s and declared unanchored (%q); "+
			"an anchor that is both cannot refuse anything", a.Digest, a.UnanchoredReason)
	case a.UnanchoredReason != "" && a.RestrictionReason != "":
		return fmt.Errorf("pdp: the system-corpus anchor is declared unanchored (%q) and also a restriction (%q); "+
			"a restriction is a subset of the SHIPPED corpus, so an engine that is not running the shipped corpus "+
			"cannot be restricting it", a.UnanchoredReason, a.RestrictionReason)
	}
	return nil
}

// requireSystemBundle refuses an ANCHORED engine that activates no system
// bundle at all.
//
// `checkSystemBundle` alone conflates two different states: "this is not the
// shipped corpus" and "there is no system corpus here". A deployment that
// simply omits the system bundle passes every per-bundle check, enforces zero
// platform ceilings, and looks identical to one that activated the corpus
// correctly. R3 drove exactly that configuration and the engine activated.
//
// So an anchor that names a digest requires the corpus it names to be present.
// An UNANCHORED engine is exempt by construction: the shadow harness, the
// replay environment and the conformance world each activate a system document
// that is not the shipped one, or none at all, and each says so in words.
func (a SystemCorpusAnchor) requireSystemBundle(bundles []*Bundle) error {
	if a.UnanchoredReason != "" {
		return nil
	}
	for _, b := range bundles {
		if b != nil && b.Root == RootSystem {
			return nil
		}
	}
	return fmt.Errorf("pdp: this engine is anchored to the shipped system corpus (%s) and activates no system-root bundle. "+
		"An engine with no system document enforces none of the platform's own ceilings, and every per-bundle check passes "+
		"while it does - which is why the anchor asks for the corpus to be PRESENT rather than only for it not to be a "+
		"different one. Declare Unanchored(reason) if this engine is deliberately not running the shipped corpus", a.Digest)
}

// RefusalBlanketPermission is the code an anchored engine refuses activation
// with when a document carries a BLANKET permission: every action, the whole
// organization, no condition, no resource scope. See ActivationRefusal.
const RefusalBlanketPermission = "BLANKET_PERMISSION_REFUSED"

// ActivationRefusal is a NewEngine refusal with a machine-readable code, so a
// transport can report WHICH production rule refused rather than parsing the
// message. It wraps the underlying detail and is matched with errors.As.
type ActivationRefusal struct {
	Code   string
	Detail string
}

func (e *ActivationRefusal) Error() string { return "pdp: " + e.Code + ": " + e.Detail }

// refuseBlanketPermission is the ANCHORED engine's half of the blanket rule.
//
// The other half is authoring.CodeBlanketPermission at publication, and both
// exist because they guard different doors. Publication guards what an author
// can SAVE through a transport; this guards what an engine will ENFORCE, which
// includes a document that reached the engine without passing through
// authoring at all - a shadow world's compiled baseline, a replay fixture, a
// migration's output. An UNANCHORED engine is exempt by construction: the
// shadow harness compiles exactly this permission on purpose, its own comment
// says it must not survive cutover, and this is the check that makes that
// sentence a mechanism. The exemption is the same first-line return as the
// two anchor checks above, for the same reason: the reader who anchors the
// shadow path is the reader who needs this to fire.
func (a SystemCorpusAnchor) refuseBlanketPermission(docs []*Document) error {
	if a.UnanchoredReason != "" {
		return nil
	}
	for _, d := range docs {
		if d == nil {
			continue
		}
		for _, p := range d.Policies {
			if IsBlanketPermission(p) {
				return &ActivationRefusal{
					Code: RefusalBlanketPermission,
					Detail: fmt.Sprintf("the %s document carries policy %q, a permission over every action for the whole "+
						"organization with no condition and no resource scope. An anchored engine will not enforce it: it "+
						"permits every action registered after it, silently, and the shadow harness's baseline of this "+
						"shape says in its own description that it must not survive cutover. Grant per action instead "+
						"(authoringcatalog.BaselinePermissionPack)", d.Root, p.ID),
				}
			}
		}
	}
	return nil
}

// IsBlanketPermission reports whether a policy is a permission over EVERY
// action, for the WHOLE organization, with NO condition and NO resource scope.
// All four are required; see authoring.IsBlanketPermission, which relays this
// one so the two doors judge one shape.
func IsBlanketPermission(p Policy) bool {
	if p.Authority != contract.AuthorityPermission {
		return false
	}
	if !p.Actions.Any || len(p.Actions.Actions) > 0 || len(p.Actions.RequiredTags) > 0 {
		return false
	}
	if !p.Scope.Organization || len(p.Scope.Groups) > 0 || len(p.Scope.Principals) > 0 {
		return false
	}
	if p.ResourceScope != nil && p.ResourceScope.Kind != CondTrue {
		return false
	}
	if p.Unless != nil {
		return false
	}
	return p.Where.Kind == CondTrue
}

// checkSystemBundle refuses a system-root bundle that is not the shipped
// corpus.
//
// It answers only "is this bundle the shipped corpus". "Is the shipped corpus
// here at all" is `requireSystemBundle`'s question, and the two are separate
// because a per-bundle check cannot see an absence.
func (a SystemCorpusAnchor) checkSystemBundle(b *Bundle) error {
	if a.UnanchoredReason != "" {
		return nil
	}
	if b.Provenance.SourceDigest == a.Digest {
		return nil
	}
	if a.RestrictionReason != "" {
		// A RESTRICTION IS CHECKED AGAINST THE DOCUMENT, NOT THE BUNDLE, and
		// every caller binds the document to this bundle before this runs:
		// NewEngine and CheckSystemPublication both call bindSourceDocument,
		// which compares ExactDigest(document) against the bundle's source
		// digest. So checking the document here is checking this bundle.
		// The check itself is checkSystemRestriction's; reaching this arm at
		// all means the bundle is not the whole corpus, which is what a
		// restriction is.
		return nil
	}
	return fmt.Errorf("pdp: refusing to activate a system-root bundle whose source digests to %s; this binary shipped the "+
		"system corpus digesting to %s. The system root is the platform's own authority - an organization policy can grant "+
		"only within system constraints and can never modify them - so a system document this binary did not ship is a "+
		"ceiling nobody here authored",
		b.Provenance.SourceDigest, a.Digest)
}

// checkSystemRestriction refuses a system document that is not a SUBSET of the
// shipped corpus.
//
// Every policy is compared by its EXACT DIGEST rather than by identifier, so a
// restriction that keeps a control's name and changes its condition, its
// obligations or its authority is refused exactly as an added one is. The
// shipped corpus's policies are indexed once per call; the corpus is a hundred
// policies and this runs at activation, not per decision.
//
// AN EMPTY RESTRICTION IS REFUSED. "This plane enforces none of the platform's
// controls" is a statement somebody must make deliberately - it is the state
// requireSystemBundle exists to make impossible for the whole-corpus case, and
// a restriction must not become the way around it.
func (a SystemCorpusAnchor) checkSystemRestriction(d *Document) error {
	if a.UnanchoredReason != "" || a.RestrictionReason == "" {
		return nil
	}
	shipped, err := SystemCorpusDocument()
	if err != nil {
		return err
	}
	index := make(map[string]struct{}, len(shipped.Policies))
	for _, p := range shipped.Policies {
		pd, err := contract.ExactDigest(p)
		if err != nil {
			return fmt.Errorf("pdp: digesting the shipped corpus policy %q: %w", p.ID, err)
		}
		index[pd] = struct{}{}
	}
	if len(d.Policies) == 0 {
		return &ActivationRefusal{
			Code: RefusalEmptyRestriction,
			Detail: fmt.Sprintf("the system document restricts the shipped corpus to NO policy at all (%q). A plane that "+
				"enforces none of the platform's own controls is a plane with no ceiling, and every per-policy check "+
				"below would pass having checked nothing", a.RestrictionReason),
		}
	}
	for _, p := range d.Policies {
		pd, err := contract.ExactDigest(p)
		if err != nil {
			return fmt.Errorf("pdp: digesting the restricted corpus policy %q: %w", p.ID, err)
		}
		if _, ok := index[pd]; !ok {
			return &ActivationRefusal{
				Code: RefusalNotARestriction,
				Detail: fmt.Sprintf("policy %q is not a policy of the corpus this binary shipped. A restriction may only "+
					"LEAVE CONTROLS OUT (%q); adding one, or keeping a control's name while changing its condition, its "+
					"obligations or its authority, is a system ceiling nobody here authored", p.ID, a.RestrictionReason),
			}
		}
	}

	// THE DOCUMENT IS MORE THAN ITS POLICY LIST, and checking only the list was
	// a real hole R3 found: `Document` carries Attributes, Version and
	// InteractiveRealms too, and AttributeSchema.Optional decides whether the
	// authoritative ABSENCE of a signal is a non-match or an unknown. Flipping
	// one control's signal to Optional turns its fail-closed unknown into a
	// silent NO_MATCH - the control stops applying - while every policy stays
	// byte-identical and a policies-only subset check passes.
	//
	// So every non-policy field is held EQUAL to the shipped document, except
	// that attributes may be OMITTED with the policies that read them, which is
	// what a restriction does. Same rule as the policy list, one field over:
	// leave out, never alter.
	schema := make(map[string]AttributeSchema, len(shipped.Attributes))
	for _, at := range shipped.Attributes {
		schema[at.Path] = at
	}
	for _, at := range d.Attributes {
		want, ok := schema[at.Path]
		if !ok {
			return &ActivationRefusal{
				Code: RefusalNotARestriction,
				Detail: fmt.Sprintf("the restricted system document declares attribute %q, which the shipped corpus "+
					"does not (%q). A restriction may omit an attribute with the controls that read it; it may not "+
					"introduce one", at.Path, a.RestrictionReason),
			}
		}
		if at != want {
			return &ActivationRefusal{
				Code: RefusalNotARestriction,
				Detail: fmt.Sprintf("the restricted system document redeclares attribute %q as %+v; the shipped corpus "+
					"declares %+v (%q). `Optional` decides whether an authoritative absence is a NON-MATCH or an "+
					"UNKNOWN, so editing it turns a fail-closed control into one that silently stops applying while "+
					"every policy stays byte-identical", at.Path, at, want, a.RestrictionReason),
			}
		}
	}
	if d.Version != shipped.Version {
		return &ActivationRefusal{
			Code: RefusalNotARestriction,
			Detail: fmt.Sprintf("the restricted system document declares version %d; the shipped corpus is version %d (%q)",
				d.Version, shipped.Version, a.RestrictionReason),
		}
	}
	if len(d.InteractiveRealms) != len(shipped.InteractiveRealms) {
		return &ActivationRefusal{
			Code: RefusalNotARestriction,
			Detail: fmt.Sprintf("the restricted system document declares %d interactive realm(s) and the shipped corpus "+
				"declares %d (%q); realm interactivity decides whether an approval can ever be answered",
				len(d.InteractiveRealms), len(shipped.InteractiveRealms), a.RestrictionReason),
		}
	}
	for realm, want := range shipped.InteractiveRealms {
		if got, ok := d.InteractiveRealms[realm]; !ok || got != want {
			return &ActivationRefusal{
				Code: RefusalNotARestriction,
				Detail: fmt.Sprintf("the restricted system document says realm %q has interactive=%t and the shipped "+
					"corpus says %t (%q)", realm, got, want, a.RestrictionReason),
			}
		}
	}
	return nil
}

// CheckSystemRestrictionForTest exposes the subset check so a test can ask the
// anchor DIRECTLY, rather than only through NewEngine.
//
// It exists because two earlier fences - the compiler's authoring validation
// and NewEngine's document-to-bundle binding - stand in front of this one, so a
// test driving only NewEngine cannot tell "the anchor refused it" from "the
// anchor was never reached". Asserting the ORDER of the fences would be
// asserting the wrong property; asking each one is asserting the right one.
// Intended for use in tests only.
func (a SystemCorpusAnchor) CheckSystemRestrictionForTest(d *Document) error {
	return a.checkSystemRestriction(d)
}

// CheckSystemPublication asks the anchor what NewEngine asks of a system-root
// bundle and the document it was built from, BY THE SAME CODE: the binding of
// the document to the bundle (bindSourceDocument), the subset check on the
// document (checkSystemRestriction) and the anchor check on the bundle
// (checkSystemBundle). There is no third expression of any of the three here.
//
// THE BINDING IS NOT OPTIONAL, ON EITHER ANCHOR. Under a restriction,
// checkSystemBundle accepts any bundle that is not the whole corpus and leaves
// the verdict to the document. Under the whole corpus, checkSystemRestriction
// does not run and checkSystemBundle judges only the bundle. Either way one of
// the pair goes unexamined, so without the binding a mismatched pair would be
// answered nil. No caller may rely on having related the two.
//
// The three checks are pure and the verdict is their conjunction, so their
// ORDER decides which refusal a caller reads, never whether a pair is accepted,
// and no test asserts it.
//
// It exists for authoring.SystemAuthority, the one signer of system-root
// policy, so that signer refuses what an anchored engine would refuse before
// any signature exists. NewEngine keeps asking all of it independently, because
// a system bundle can reach an engine without passing through the signer.
func (a SystemCorpusAnchor) CheckSystemPublication(d *Document, b *Bundle) error {
	if err := a.Validate(); err != nil {
		return err
	}
	if a.UnanchoredReason != "" {
		return fmt.Errorf("pdp: an unanchored declaration (%q) names no shipped corpus, so it cannot say whether a publication is one", a.UnanchoredReason)
	}
	if d == nil || b == nil {
		return fmt.Errorf("pdp: a system publication is a document and the bundle built from it, and one of the two is missing")
	}
	if d.Root != RootSystem || b.Root != RootSystem {
		return fmt.Errorf("pdp: a system publication declares root %q for its document and %q for its bundle; the shipped corpus is the %q document",
			d.Root, b.Root, RootSystem)
	}
	if err := bindSourceDocument(d, b); err != nil {
		return err
	}
	if err := a.checkSystemRestriction(d); err != nil {
		return err
	}
	return a.checkSystemBundle(b)
}

// RefusalEmptyRestriction and RefusalNotARestriction are the two ways a
// restriction of the shipped corpus is refused.
const (
	RefusalEmptyRestriction = "EMPTY_SYSTEM_RESTRICTION"
	RefusalNotARestriction  = "NOT_A_SHIPPED_CORPUS_RESTRICTION"
)

// clonePolicyForTemplate deep-copies the slices a caller extending the
// organization template would reach through.
//
// It copies what `Policy` actually owns: the obligation list and its own
// parameter maps, the break-glass list, the action and scope selectors, and
// the condition trees. `Condition` is a recursive value with an `Operands`
// slice, so a shallow copy of a policy leaves its whole condition tree shared.
func clonePolicyForTemplate(p Policy) Policy {
	out := p
	out.Obligations = make([]contract.Obligation, len(p.Obligations))
	for i, o := range p.Obligations {
		ob := o
		if o.Params != nil {
			ob.Params = make(map[string]string, len(o.Params))
			for k, v := range o.Params {
				ob.Params[k] = v
			}
		}
		out.Obligations[i] = ob
	}
	out.PierceableBy = append([]contract.ID(nil), p.PierceableBy...)
	out.Actions.Actions = append([]contract.ID(nil), p.Actions.Actions...)
	out.Actions.RequiredTags = append([]string(nil), p.Actions.RequiredTags...)
	out.Scope.Groups = append([]contract.ID(nil), p.Scope.Groups...)
	out.Scope.Principals = append([]contract.ID(nil), p.Scope.Principals...)
	out.Where = cloneCondition(p.Where)
	if p.Unless != nil {
		u := cloneCondition(*p.Unless)
		out.Unless = &u
	}
	if p.ResourceScope != nil {
		r := cloneCondition(*p.ResourceScope)
		out.ResourceScope = &r
	}
	return out
}

// cloneCondition deep-copies a condition tree.
func cloneCondition(c Condition) Condition {
	out := c
	if c.Operands != nil {
		out.Operands = make([]Condition, len(c.Operands))
		for i, sub := range c.Operands {
			out.Operands[i] = cloneCondition(sub)
		}
	}
	return out
}
