// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoringcatalog

import (
	"fmt"
	"sort"
	"strings"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/registry"
)

// THE DEPLOYMENT VOCABULARY (#3895)
//
// A fresh install has no connectors, no imported policy and no fixture world.
// What it DOES have, on the day the image starts, is:
//
//   - three governed operations, because those are the stages every decision
//     surface already recognises - `llm.completion`, `tool.call` and
//     `agent.invoke` are the exact action names the AuthZEN adapter maps and
//     the Decision API's stage vocabulary renders (platform/agent);
//   - the trust realms its identity plane mints principals in, which the
//     platform module hands in through Deployment.Realms because they are
//     identity-plane facts this module must not restate;
//   - the in-process enforcement planes of this build and the capability each
//     one discharges, from registry/legacy_plane_peps.tsv;
//   - the 101 shipped inspection controls from the detector census, and the
//     corpus they compile to, anchored by the digest this binary was built with
//     (#3967).
//
// Every one of those is DERIVED from a declaration that already exists in the
// tree. Nothing in this file is a second list of anything: the action names are
// welded to the adapter's table by a test in the platform module, the argument
// schema and the payload leaves are read out of the shipped corpus, the planes
// and the detectors are read out of their census files, and the realms come
// from the caller. A hand-kept list of any of them is one entry short the day a
// fourth stage or a fifth realm lands, which is #3877's shape.

// DeploymentCatalogVersion is the registry version the built-in deployment
// vocabulary carries on the wire (contract.Snapshot.RegistryVersion,
// proof.Binding.ToolRegistryVersion).
//
// It is an INTEGER because the wire contract carries one, and it is WELDED to
// the content digest by TestTheDeploymentCatalogVersionIsWeldedToItsDigest in
// platform/shared/authoringvocabulary - the package that resolves the REAL
// deployment, realms included, so the pin is over the catalog a deployment
// actually runs: a change to anything this file derives moves the digest, and
// the test then refuses until this constant moves with it. The version is therefore not a
// number somebody remembers to bump; it is a number the digest makes them bump.
//
// It starts at 1 and it is bumped by one per content change. It is never
// reset, because a decision recorded under version 3 must never be
// reproducible against a version-3 vocabulary that is not the one it was
// decided against.
const DeploymentCatalogVersion int64 = 2

// Stage action identifiers. THESE STRINGS ARE OWNED BY THE DECISION SURFACE:
// platform/agent/authzen_adapter.go maps exactly these three names onto the
// evaluator's stages, and TestTheDeploymentActionsAreTheAdaptersActions in
// that package fails the build if either side gains or loses one. They are
// restated here only because the decision module cannot import the agent.
const (
	ActionLLMCompletion = "llm.completion"
	ActionToolCall      = "tool.call"
	ActionAgentInvoke   = "agent.invoke"
)

// DeploymentActions lists the built-in action local names, sorted.
func DeploymentActions() []string {
	return []string{ActionAgentInvoke, ActionLLMCompletion, ActionToolCall}
}

// stageTag is the tag every stage action carries, so a policy can select "every
// governed operation of stage X" without naming the action.
func stageTag(stage string) string { return "stage:" + stage }

// ArgumentQuery is the one argument every stage requires: the content the
// policy engine inspects. The legacy evaluator refuses a request without it,
// and the AuthZEN adapter refuses its absence by name (authzenArgsQuery).
const ArgumentQuery = "query"

// deploymentAction is the declaration this file derives an ActionRecord from.
// The EFFECTS are declared conservatively: a stage governs an operation whose
// concrete tool is not registered yet, so the risk class is the worst case of
// the class, which keeps every stage ineligible for the compatibility posture
// (registry.Effects.CompatibilityIneligible) - the fail-closed direction.
type deploymentAction struct {
	local       string
	stage       string
	display     string
	description string
	effects     registry.Effects
}

func deploymentActions() []deploymentAction {
	yes, no := registry.DeclarationYes, registry.DeclarationNo
	return []deploymentAction{
		{
			local: ActionLLMCompletion, stage: "llm", display: "Model completion",
			description: "a completion request to a model provider; the prompt leaves the organization and tokens are paid for",
			effects:     registry.Effects{Irreversible: no, Spend: yes, DataEgress: yes, Privileged: no},
		},
		{
			local: ActionToolCall, stage: "tool", display: "Tool call",
			description: "an invocation of a tool on the caller's behalf; until the tool is registered its effects are the worst case of the class",
			effects:     registry.Effects{Irreversible: yes, Spend: no, DataEgress: yes, Privileged: no},
		},
		{
			local: ActionAgentInvoke, stage: "agent", display: "Agent invocation",
			description: "a delegation to an agent that may itself call models and tools; the worst case of both",
			effects:     registry.Effects{Irreversible: yes, Spend: yes, DataEgress: yes, Privileged: no},
		},
	}
}

// deploymentMaxDelegationDepth is the actor-chain bound. ADR-065's canonical
// request shows the three-hop chain a deployment must admit - a user, the
// agent acting for them, and the workload the agent runs as - and nothing
// longer is a shape any built-in surface produces.
const deploymentMaxDelegationDepth = 3

// PlatformRealmAttributes describes the two realms THIS MODULE declares: the
// one the in-process planes authenticate as and the one an external
// enforcement point is admitted under. Neither has a person in it and neither
// has a directory. They are described here rather than in the platform module
// because the registry package that declares them is this module's.
func PlatformRealmAttributes() map[string]authoring.RealmEntry {
	return map[string]authoring.RealmEntry{
		registry.LegacyPlaneRealm: {Interactive: false, HasGroupGraph: false},
		registry.ExternalPEPRealm: {Interactive: false, HasGroupGraph: false},
	}
}

// resolveDeployment builds the production snapshot.
func resolveDeployment(dep Deployment) (*Snapshot, error) {
	if !dep.Edition.IsValid() {
		return nil, fmt.Errorf("the deployment vocabulary needs the build edition to register its enforcement planes; got %v", dep.Edition)
	}
	if len(dep.Realms) == 0 {
		return nil, fmt.Errorf("the deployment vocabulary needs the identity plane's realm attributes and was given none; a vocabulary whose realms were invented here would let an author scope a policy to a realm no request can arrive from")
	}
	if dep.Now.IsZero() {
		return nil, fmt.Errorf("the deployment vocabulary needs an evaluation instant; a registry that silently read the wall clock could not be replayed")
	}
	corpus, err := pdp.SystemCorpusDocument()
	if err != nil {
		return nil, err
	}
	corpusDigest, err := pdp.SystemCorpusDigest()
	if err != nil {
		return nil, err
	}
	orgTemplate, err := pdp.SystemCorpusOrganizationTemplate()
	if err != nil {
		return nil, err
	}

	c := registry.NewCatalog(dep.Now)

	// The shipped inspection controls, from the census. A row that will not
	// register is a build-time failure naming the row.
	if err := registry.SeedShippedDetectors(c); err != nil {
		return nil, fmt.Errorf("deployment vocabulary: %w", err)
	}
	// The enforcement planes of this build, and the realm they authenticate
	// as. RegisterLegacyPlanes declares registry.LegacyPlaneRealm itself.
	if err := registry.RegisterLegacyPlanes(c, dep.Edition); err != nil {
		return nil, fmt.Errorf("deployment vocabulary: registering the enforcement planes: %w", err)
	}
	// The realm an external enforcement point is admitted under, the same
	// fence platform/agent/pep_handshake.go puts in front of the handshake.
	if err := registry.RegisterExternalPEPRealm(c); err != nil {
		return nil, fmt.Errorf("deployment vocabulary: %w", err)
	}
	// The identity plane's realms, handed in by the caller.
	realms := PlatformRealmAttributes()
	for _, q := range sortedKeys(dep.Realms) {
		if _, taken := realms[q]; taken {
			return nil, fmt.Errorf("deployment vocabulary: realm %q is declared by the decision module and cannot be redescribed by the identity plane", q)
		}
		if !c.RealmDeclared(q) {
			if err := c.RegisterRealm(q); err != nil {
				return nil, fmt.Errorf("deployment vocabulary: %w", err)
			}
		}
		realms[q] = dep.Realms[q]
	}

	// The argument schema is DERIVED from the corpus: every `args.*` attribute
	// a shipped control reads is an argument every stage declares, at the type
	// the corpus declares it, plus the one argument the evaluator requires.
	// ADR-065 admission refuses a request carrying an `args.*` attribute the
	// registry does not declare, so a corpus whose reads were not declared
	// here would refuse the very requests its controls inspect.
	args, err := corpusArguments(corpus, orgTemplate)
	if err != nil {
		return nil, err
	}
	// The payload leaves are likewise the corpus's own redaction targets:
	// field_redact is resolved PER PAYLOAD LEAF, and a mandatory transform
	// whose target covers no declared leaf is reported unplaced and NOT
	// APPLIED. A hand-written leaf list that missed one of the twelve would
	// silently drop that redaction. The fields of a redaction the corpus ships
	// as a warn stay leaves too (#4254): shipping a platform control as a warn
	// must not narrow what an organization's document may redact.
	retained, err := pdp.SystemCorpusRetainedPayloadLeaves()
	if err != nil {
		return nil, err
	}
	leaves := corpusPayloadLeaves(retained, corpus, orgTemplate)

	for _, a := range deploymentActions() {
		if err := c.RegisterTag(registry.TagRecord{
			Tag:         stageTag(a.stage),
			Governance:  registry.TagGovernanceUngoverned,
			Description: "every governed operation of the " + a.stage + " stage",
		}); err != nil {
			return nil, fmt.Errorf("deployment vocabulary: %w", err)
		}
		if err := c.RegisterAction(registry.ActionRecord{
			ID:                 contract.MustParseID(contract.KindAction, "Action::"+a.local),
			DisplayName:        a.display,
			Description:        a.description,
			Tags:               []string{stageTag(a.stage)},
			Posture:            registry.FailClosedPosture(),
			MaxDelegationDepth: deploymentMaxDelegationDepth,
			Arguments:          cloneArgs(args),
			RequiredArguments:  []string{ArgumentQuery},
			PayloadLeaves:      append([]string(nil), leaves...),
			Effects:            a.effects,
			// Every in-process plane discharges immutable_audit; an
			// enforcement point that cannot record a decision cannot enforce
			// one of these.
			RequiredCapabilities: []contract.Capability{{Type: contract.ObImmutableAudit, Version: 1}},
		}); err != nil {
			return nil, fmt.Errorf("deployment vocabulary: registering %s: %w", a.local, err)
		}
	}

	cat, err := authoring.NewCatalogFromRegistry(c, realms)
	if err != nil {
		return nil, fmt.Errorf("the deployment registry is not usable as an authoring catalog: %w", err)
	}
	return finish(SourceDeployment, false, c, cat, corpusDigest, DeploymentCatalogVersion, dep.Edition)
}

// corpusArguments derives the stage argument schema from the shipped corpus.
func corpusArguments(docs ...*pdp.Document) (map[string]pdp.ValueType, error) {
	out := map[string]pdp.ValueType{ArgumentQuery: pdp.TypeString}
	for _, d := range docs {
		for _, a := range d.Attributes {
			if !strings.HasPrefix(a.Path, "args.") {
				continue
			}
			name := strings.TrimPrefix(a.Path, "args.")
			if prev, ok := out[name]; ok && prev != a.Type {
				// Two shipped documents reading one argument at two types is
				// the compiler's TypeAny widening, and it is refused here
				// rather than widened again: an argument schema WITH UNITS
				// is the point of having one.
				return nil, fmt.Errorf("deployment vocabulary: the shipped corpus reads argument %q as both %s and %s", name, prev, a.Type)
			}
			out[name] = a.Type
		}
	}
	return out, nil
}

func cloneArgs(in map[string]pdp.ValueType) map[string]pdp.ValueType {
	out := make(map[string]pdp.ValueType, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// corpusPayloadLeaves is the sorted, deduplicated set of disclosure targets
// the shipped corpus names, together with retained: the fields of a redaction
// the corpus ships as something that masks nothing (#4254,
// pdp.SystemCorpusRetainedPayloadLeaves).
func corpusPayloadLeaves(retained []string, docs ...*pdp.Document) []string {
	set := map[string]struct{}{}
	for _, field := range retained {
		set[field] = struct{}{}
	}
	for _, d := range docs {
		for _, p := range d.Policies {
			for _, o := range p.Obligations {
				fam, err := contract.FamilyOf(o.Type)
				if err != nil || fam != contract.FamilyDisclosure || o.Target == "" {
					continue
				}
				set[o.Target] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// BaselinePermissionPackID is the document identity of the pack below.
const BaselinePermissionPackID = "baseline.permissions"

// BaselinePermissionPack is the EXPLICIT organization-root permission set a
// fresh install publishes first: one permission per registered stage action,
// each naming its action, none of them `Any`.
//
// ADR-065 denies what no permission grants, so a deployment that activates the
// shipped corpus alone permits nothing - which is correct, and is also not a
// deployment anybody can use. The legacy substrate answered this by having no
// gate at all, and the shadow harness reproduces that with a single blanket
// permission (shadow.BaselinePermissionID: every action, no condition). That
// shape is REFUSED in production - authoring.CodeBlanketPermission at
// publication, pdp.RefusalBlanketPermission at anchored activation - because a
// blanket grant auto-permits every action registered AFTER it, silently, which
// is the opposite of a registry.
//
// This pack is the replacement: explicit, per-action, authored under the
// organization root through the same publication path as every other customer
// document, so it is signed, attributed and activatable by digest, and it
// stops covering an action the day that action is removed from the catalog.
func BaselinePermissionPack(snap *Snapshot) (*pdp.Document, error) {
	if snap == nil || snap.Catalog == nil {
		return nil, fmt.Errorf("authoringcatalog: a baseline pack needs a resolved snapshot")
	}
	if snap.Fixture {
		return nil, fmt.Errorf("authoringcatalog: a baseline pack is derived from the deployment vocabulary, not from the %s fixture", snap.Source)
	}
	// Attributes is an EMPTY LIST rather than nil: the published schema wants
	// an array, and the pack reads no attribute - every permission is
	// unconditional over its one named action.
	doc := &pdp.Document{Root: pdp.RootOrganization, Version: 1, Attributes: []pdp.AttributeSchema{}}
	for _, key := range sortedKeys(snap.Catalog.Actions) {
		entry := snap.Catalog.Actions[key]
		doc.Policies = append(doc.Policies, pdp.Policy{
			ID:        "baseline.permit." + entry.ID.Local,
			Authority: contract.AuthorityPermission,
			Root:      pdp.RootOrganization,
			Scope:     pdp.Scope{Organization: true},
			Actions:   pdp.ActionSelector{Actions: []contract.ID{entry.ID}},
			Where:     pdp.True(),
			Description: "baseline permission for " + entry.ID.String() + ": every principal of the organization may perform it, " +
				"within the platform's system constraints and this organization's own. Narrow it by editing this document; " +
				"it names the action so that an action registered later is NOT permitted by it.",
		})
	}
	return doc, nil
}
