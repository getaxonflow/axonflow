// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/registry"
)

// THE SHIPPED-POSTURE TABLE (#4112, PRD §1.4 and acceptance §5 item 4).
//
// PRD §1.4 publishes the shipped set's posture as one table - policy, category,
// scope, action, reason - "so nobody discovers it by being blocked", and the
// acceptance says a test derives one from the other. This is that test. It
// writes platform/decision/pdp/shipped_posture.json, and the docs site renders
// that file and nothing else.
//
// EVERY COLUMN COMES FROM THE CODE THAT ENFORCES, never from a second model of
// it:
//
//   - scopes: activation.RestrictToScope, per legacycompile.AllScopes(), which
//     is what Activate calls. The corpus's scope_bindings are NOT the scopes a
//     control runs on: the binding arm runs after the substrate, detector,
//     phase and category arms, so a variant bound to a scope whose call sites
//     never admit its category is dropped there. A table read off the bindings
//     lists planes where the control never runs.
//   - action: the policy's authority and obligations, read back through the
//     one mapping that compiles a legacy action (legacycompile.ActionPolicy).
//     A shape that mapping cannot produce fails the derivation by name.
//   - the organization template: activation.OrganizationTemplateForScope, per
//     scope, which is what Activate composes while no document is active; a
//     published document's copy of a template policy binds only where the
//     template's does (unboundTemplateControls). So a template policy is listed
//     on the scopes where it binds. Until #4131 this said the template was
//     composed whole and listed it on every declared scope, which the implicit
//     bundle never did.
//   - reason: the corpus's own divergence facts plus a sentence generated from
//     them. There is no hand-written rationale anywhere to read.
//
// A STALE TABLE IS DETECTABLE. The artifact records the sha256 of every input
// the derivation reads, so a failure says WHICH input moved rather than only
// that the bytes differ.

// shippedPosturePath is the artifact, relative to this package.
var shippedPosturePath = filepath.Join("..", "pdp", "shipped_posture.json")

// legacyCallSitesPath is the call-site census the plane model's category
// admission is derived from at package init. It is embedded unexported, so its
// hash is taken from the file the embed reads.
var legacyCallSitesPath = filepath.Join("..", "legacycompile", "legacy_call_sites.tsv")

// operatorToolPlanes are the modelled planes that are operator tools rather
// than enforcement points (plane.go documents policy_simulation as one; the
// policy test surface is the per-policy dry run). No exported declaration
// carries this, so it is pinned here and TestEveryPlaneHasAPostureScopeKind
// holds the pin to the plane model.
var operatorToolPlanes = map[legacycompile.Plane]bool{
	legacycompile.PlanePolicySimulation: true,
	legacycompile.PlanePolicyTest:       true,
}

// classifiedPlanes is every plane this table classifies. A plane added to the
// model reds TestEveryPlaneHasAPostureScopeKind until it is classified here.
var classifiedPlanes = []legacycompile.Plane{
	legacycompile.PlaneCoworkIngest,
	legacycompile.PlaneDecide,
	legacycompile.PlaneGatewayRequest,
	legacycompile.PlaneMAP,
	legacycompile.PlaneMCP,
	legacycompile.PlaneOpenAICompatible,
	legacycompile.PlaneOrchestratorResponse,
	legacycompile.PlanePolicySimulation,
	legacycompile.PlanePolicyTest,
	legacycompile.PlaneProxyRequest,
	legacycompile.PlaneWCP,
}

type postureArtifact struct {
	SchemaVersion  int                    `json:"schema_version"`
	Provenance     postureProvenance      `json:"provenance"`
	Scopes         []postureScope         `json:"scopes"`
	System         []postureEntry         `json:"system"`
	Organization   []postureEntry         `json:"organization"`
	NotRepresented []postureUnrepresented `json:"not_represented"`
	// Packs is the installed policy packs' section (PRD §1.9). No pack
	// mechanism exists yet, so it is empty rather than absent.
	Packs []json.RawMessage `json:"packs"`
}

type postureProvenance struct {
	DerivedBy          string         `json:"derived_by"`
	SystemCorpusDigest string         `json:"system_corpus_digest"`
	Inputs             []postureInput `json:"inputs"`
	OrganizationScopes string         `json:"organization_scopes"`
}

type postureInput struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type postureScope struct {
	Scope string `json:"scope"`
	// Kind is enforcement, operator-tool or gated.
	Kind string `json:"kind"`
	// GatedBy names the gating condition of a gated scope: edition or
	// configuration (legacycompile.PlanesGatedByEdition and
	// PlanesGatedUnderDefaultPosture).
	GatedBy string `json:"gated_by,omitempty"`
}

type postureEntry struct {
	LegacyID    string              `json:"legacy_id"`
	SourceTable string              `json:"source_table"`
	Name        *string             `json:"name"`
	Category    *string             `json:"category"`
	Root        string              `json:"root"`
	Policies    []posturePolicy     `json:"policies"`
	Divergences []postureDivergence `json:"divergences"`
	Reason      string              `json:"reason"`
}

type posturePolicy struct {
	PolicyID string   `json:"policy_id"`
	Part     *int     `json:"part"`
	Action   string   `json:"action"`
	Scopes   []string `json:"scopes"`
}

type postureDivergence struct {
	Kind          string   `json:"kind"`
	LegacyActions []string `json:"legacy_actions,omitempty"`
	Chosen        string   `json:"chosen,omitempty"`
	FromRoot      string   `json:"from_root,omitempty"`
	ToRoot        string   `json:"to_root,omitempty"`
	ReasonCodes   []string `json:"reason_codes,omitempty"`
}

type postureUnrepresented struct {
	LegacyID    string              `json:"legacy_id"`
	SourceTable string              `json:"source_table"`
	Name        string              `json:"name"`
	Category    string              `json:"category"`
	Divergences []postureDivergence `json:"divergences"`
	Reason      string              `json:"reason"`
}

func TestTheShippedPostureArtifactIsDerivedFromTheCorpus(t *testing.T) {
	a, err := derivePosture()
	if err != nil {
		t.Fatal(err)
	}
	got, err := renderPosture(a)
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("AXONFLOW_WRITE_SHIPPED_POSTURE") == "1" {
		if err := os.WriteFile(shippedPosturePath, got, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s (%d bytes)", shippedPosturePath, len(got))
		return
	}
	want, err := os.ReadFile(shippedPosturePath)
	if err != nil {
		t.Fatalf("reading %s: %v. Derive it with AXONFLOW_WRITE_SHIPPED_POSTURE=1", shippedPosturePath, err)
	}
	if bytes.Equal(got, want) {
		return
	}
	if moved := movedInputs(want, a); len(moved) > 0 {
		t.Fatalf("%s is stale: these inputs of the derivation changed since it was derived, and the published posture table "+
			"no longer describes the corpus:\n  %s\nRe-derive it with AXONFLOW_WRITE_SHIPPED_POSTURE=1 and review the row diff.",
			shippedPosturePath, strings.Join(moved, "\n  "))
	}
	t.Fatalf("%s differs from the derivation although every input it records is unchanged, so the checked-in table was "+
		"edited by hand or the derivation changed. First difference: %s. Re-derive it with AXONFLOW_WRITE_SHIPPED_POSTURE=1.",
		shippedPosturePath, firstDifference(want, got))
}

// TestEveryPlaneHasAPostureScopeKind holds the pinned classification to the
// plane model: a plane added or removed reds here until the table says what
// kind of scope it is.
func TestEveryPlaneHasAPostureScopeKind(t *testing.T) {
	want := map[legacycompile.Plane]bool{}
	for _, p := range classifiedPlanes {
		want[p] = true
	}
	for _, p := range legacycompile.AllPlanes() {
		if !want[p] {
			t.Errorf("plane %q is in the plane model and the shipped-posture table does not classify it; add it to classifiedPlanes "+
				"and, if it is an operator tool rather than an enforcement point, to operatorToolPlanes", p)
		}
		delete(want, p)
	}
	for p := range want {
		t.Errorf("classifiedPlanes names %q, which the plane model no longer declares", p)
	}
	for p := range operatorToolPlanes {
		if _, err := legacycompile.SpecFor(p); err != nil {
			t.Errorf("operatorToolPlanes names %q: %v", p, err)
		}
	}
}

// TestNoPostureReasonClaimsWhatALegacyEngineDid holds the generated reason to
// what the corpus records. The plane-action divergence is how the compiler
// reads a stored legacy row whose action differs by plane. Rendered as "the
// legacy engines resolve ...", it claimed what a v10 engine ran, and for the
// organization template's rows no v10 engine decided anything on the request
// path (W3-K). The published page renders this sentence word for word.
func TestNoPostureReasonClaimsWhatALegacyEngineDid(t *testing.T) {
	a, err := derivePosture()
	if err != nil {
		t.Fatal(err)
	}
	collapsed := 0
	check := func(where, id, reason string, ds []postureDivergence) {
		if strings.Contains(strings.ToLower(reason), "legacy engine") {
			t.Errorf("%s row %s: the reason %q says what a legacy engine did; it may say only what the corpus records", where, id, reason)
		}
		for _, d := range ds {
			if d.Kind != string(legacycompile.DivergencePlaneActionCollapsed) {
				continue
			}
			collapsed++
			if !strings.Contains(reason, "its legacy row compiles to") {
				t.Errorf("%s row %s carries a plane-action divergence and its reason %q does not state it as the compiler's reading of the row", where, id, reason)
			}
		}
	}
	for _, e := range a.System {
		check("system", e.LegacyID, e.Reason, e.Divergences)
	}
	for _, e := range a.Organization {
		check("organization", e.LegacyID, e.Reason, e.Divergences)
	}
	for _, e := range a.NotRepresented {
		check("not-represented", e.LegacyID, e.Reason, e.Divergences)
	}
	// ANTI-VACUITY: the divergence this test is about must occur, or every
	// check above passes over an empty set.
	if collapsed == 0 {
		t.Fatal("no posture row carries a plane-action divergence, so this test checks nothing")
	}
}

func derivePosture() (*postureArtifact, error) {
	system, err := pdp.SystemCorpusDocument()
	if err != nil {
		return nil, err
	}
	org, err := pdp.SystemCorpusOrganizationTemplate()
	if err != nil {
		return nil, err
	}
	digest, err := pdp.SystemCorpusDigest()
	if err != nil {
		return nil, err
	}
	census, err := registry.ShippedCensus()
	if err != nil {
		return nil, err
	}
	callSites, err := os.ReadFile(legacyCallSitesPath)
	if err != nil {
		return nil, fmt.Errorf("reading the call-site census the plane model's admission is derived from: %w", err)
	}
	ledgerRaw, err := os.ReadFile(activation.DormantTemplateVariantsPath)
	if err != nil {
		return nil, fmt.Errorf("reading the ledger of dormant template variants: %w", err)
	}
	ledger, err := activation.ParseDormantTemplateVariants(ledgerRaw)
	if err != nil {
		return nil, err
	}
	var corpusFile struct {
		Divergences []legacycompile.Divergence `json:"divergences"`
	}
	if err := json.Unmarshal(pdp.SystemCorpusSource, &corpusFile); err != nil {
		return nil, fmt.Errorf("reading the corpus's divergences: %w", err)
	}

	a := &postureArtifact{
		SchemaVersion: 1,
		Provenance: postureProvenance{
			DerivedBy:          "platform/decision/activation TestTheShippedPostureArtifactIsDerivedFromTheCorpus",
			SystemCorpusDigest: digest,
			Inputs: []postureInput{
				{Path: "platform/decision/legacycompile/legacy_call_sites.tsv", SHA256: sha256Hex(callSites)},
				{Path: "platform/decision/pdp/system_corpus.json", SHA256: sha256Hex(pdp.SystemCorpusSource)},
				{Path: "platform/decision/registry/detectors_census.tsv", SHA256: sha256Hex([]byte(registry.DetectorCensusFile))},
				{Path: "platform/decision/activation/" + activation.DormantTemplateVariantsPath, SHA256: sha256Hex(ledgerRaw)},
			},
			OrganizationScopes: "restricted: activation.Activate composes the organization template restricted to the scope " +
				"(OrganizationTemplateForScope) while no document is active, and a published document's copy of a template policy " +
				"binds only where the template's does, so a template policy is listed on the scopes where it binds",
		},
		NotRepresented: []postureUnrepresented{},
		Packs:          []json.RawMessage{},
	}

	// kept is where each system policy binds, and templateKept where each
	// template policy does: the implicit bundle composes the template restricted
	// to the scope (OrganizationTemplateForScope, activation.go), and a published
	// document's copy of a template policy binds only where the template's does.
	kept, templateKept := map[string][]string{}, map[string][]string{}
	for _, s := range legacycompile.AllScopes() {
		doc, _, err := activation.RestrictToScope(s)
		if err != nil {
			return nil, err
		}
		for _, p := range doc.Policies {
			kept[p.ID] = append(kept[p.ID], s.String())
		}
		template, err := activation.OrganizationTemplateForScope(s)
		if err != nil {
			return nil, err
		}
		for _, p := range template.Policies {
			templateKept[p.ID] = append(templateKept[p.ID], s.String())
		}
		kind, gatedBy := scopeKind(s.Plane)
		a.Scopes = append(a.Scopes, postureScope{Scope: s.String(), Kind: kind, GatedBy: gatedBy})
	}

	censusByID := map[string]registry.CensusRow{}
	for _, r := range census {
		censusByID[r.PolicyID] = r
	}
	divergences := map[string][]legacycompile.Divergence{}
	for _, d := range corpusFile.Divergences {
		control := legacycompile.CorpusPolicyIDFor(d.Table, d.PolicyID)
		divergences[control] = append(divergences[control], d)
	}

	a.System, err = postureEntries(system.Policies, pdp.RootSystem, func(p pdp.Policy) []string { return kept[p.ID] }, censusByID, divergences)
	if err != nil {
		return nil, err
	}
	a.Organization, err = postureEntries(org.Policies, pdp.RootOrganization, func(p pdp.Policy) []string { return templateKept[p.ID] }, censusByID, divergences)
	if err != nil {
		return nil, err
	}
	seenDormant := map[string]bool{}
	if err := stateDormantVariants(a.System, "system", ledger, seenDormant); err != nil {
		return nil, err
	}
	if err := stateDormantVariants(a.Organization, "organization", ledger, seenDormant); err != nil {
		return nil, err
	}
	if err := staleDormantRows(ledger, seenDormant); err != nil {
		return nil, err
	}

	// NOT REPRESENTED: a censused row with no corpus policy in either document.
	// It is derived from the census and checked against the corpus's own
	// row_not_represented divergences in both directions, so a row cannot
	// vanish from the table without one of them saying why.
	represented := map[string]bool{}
	for _, e := range append(append([]postureEntry{}, a.System...), a.Organization...) {
		represented[legacycompile.CorpusPolicyIDFor(e.SourceTable, e.LegacyID)] = true
	}
	claimed := map[string]bool{}
	for control, ds := range divergences {
		for _, d := range ds {
			if d.Kind == legacycompile.DivergenceRowNotRepresented {
				claimed[control] = true
			}
		}
	}
	for _, r := range census {
		control := legacycompile.CorpusPolicyIDFor("static_policies", r.PolicyID)
		if represented[control] {
			continue
		}
		if !claimed[control] {
			return nil, fmt.Errorf("census row %s produces no corpus policy and the corpus records no row_not_represented divergence for it", r.PolicyID)
		}
		delete(claimed, control)
		ds := postureDivergences(divergences[control])
		a.NotRepresented = append(a.NotRepresented, postureUnrepresented{
			LegacyID: r.PolicyID, SourceTable: "static_policies", Name: r.Name, Category: r.Category,
			Divergences: ds, Reason: postureReason(ds, nil),
		})
	}
	for control := range claimed {
		return nil, fmt.Errorf("the corpus records %s as not represented, and no census row names it", control)
	}
	sort.Slice(a.NotRepresented, func(i, j int) bool { return a.NotRepresented[i].LegacyID < a.NotRepresented[j].LegacyID })
	return a, nil
}

// DORMANT TEMPLATE VARIANTS ARE NAMED, NOT LEFT BLANK (#4131). A template
// policy the restriction keeps on no scope is on the ledger or the derivation
// fails, and the row's reason - the sentence the docs site renders - says it is
// dormant and what makes it live. Since #4253 the system document's entries
// are stated the same way, and a ledger row no policy of either root matches is
// stale and also fails.
func stateDormantVariants(entries []postureEntry, root string, ledger map[string]activation.DormantTemplateVariant, seen map[string]bool) error {
	for i := range entries {
		e := &entries[i]
		var dormant []string
		for _, p := range e.Policies {
			if len(p.Scopes) != 0 {
				continue
			}
			row, listed := ledger[p.PolicyID]
			if !listed {
				return fmt.Errorf("%s policy %s binds on no scope and %s does not list it; a dormant variant is named or it is a defect", root, p.PolicyID, activation.DormantTemplateVariantsPath)
			}
			seen[p.PolicyID] = true
			if root == "organization" {
				dormant = append(dormant, fmt.Sprintf("its %s policy %s is dormant: admitted on no scope; becomes live if %s canonicalises the category", p.Action, p.PolicyID, row.Revisit))
			} else {
				dormant = append(dormant, fmt.Sprintf("its %s policy %s is dormant: admitted on no scope; %s", p.Action, p.PolicyID, row.Revisit))
			}
		}
		if len(dormant) > 0 {
			e.Reason = strings.TrimSuffix(e.Reason, ".") + "; " + strings.Join(dormant, "; ") + "."
		}
	}
	return nil
}

// staleDormantRows fails on a ledger row no policy of either root matched.
func staleDormantRows(ledger map[string]activation.DormantTemplateVariant, seen map[string]bool) error {
	for id := range ledger {
		if !seen[id] {
			return fmt.Errorf("%s lists %s, which is not a policy the restriction keeps on no scope; the row is stale", activation.DormantTemplateVariantsPath, id)
		}
	}
	return nil
}

// postureEntries groups a document's policies into one entry per legacy row,
// placing every policy exactly once.
func postureEntries(policies []pdp.Policy, root pdp.Root, scopesOf func(pdp.Policy) []string,
	census map[string]registry.CensusRow, divergences map[string][]legacycompile.Divergence) ([]postureEntry, error) {
	byControl := map[string]*postureEntry{}
	for _, p := range policies {
		control, _, ok := legacycompile.CorpusControlOf(p.ID)
		if !ok {
			return nil, fmt.Errorf("corpus policy %q is not a corpus policy identifier", p.ID)
		}
		e, seen := byControl[control]
		if !seen {
			table, encoded, _ := strings.Cut(strings.TrimPrefix(control, "corpus:"), ":")
			legacyID, ok := legacycompile.UnsanitizePolicyID(encoded)
			if !ok {
				return nil, fmt.Errorf("corpus control %q does not decode to a legacy row identifier", control)
			}
			e = &postureEntry{LegacyID: legacyID, SourceTable: table, Root: string(root),
				Divergences: postureDivergences(divergences[control])}
			if row, censused := census[legacyID]; censused && table == "static_policies" {
				name, category := row.Name, row.Category
				e.Name, e.Category = &name, &category
			}
			byControl[control] = e
		}
		action, err := postureAction(p)
		if err != nil {
			return nil, err
		}
		scopes := append([]string{}, scopesOf(p)...)
		sort.Strings(scopes)
		e.Policies = append(e.Policies, posturePolicy{PolicyID: p.ID, Part: posturePart(p.ID), Action: action, Scopes: scopes})
	}
	out := make([]postureEntry, 0, len(byControl))
	placed := 0
	for _, e := range byControl {
		sort.Slice(e.Policies, func(i, j int) bool { return e.Policies[i].PolicyID < e.Policies[j].PolicyID })
		placed += len(e.Policies)
		e.Reason = postureReason(e.Divergences, e.Policies)
		out = append(out, *e)
	}
	if placed != len(policies) {
		return nil, fmt.Errorf("placed %d of the %s document's %d policies", placed, root, len(policies))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SourceTable != out[j].SourceTable {
			return out[i].SourceTable < out[j].SourceTable
		}
		return out[i].LegacyID < out[j].LegacyID
	})
	return out, nil
}

// postureAction reads a compiled policy back to the legacy action that
// legacycompile.ActionPolicy compiles to that shape. A shape the mapping cannot
// produce is refused by name rather than rendered as a guess.
func postureAction(p pdp.Policy) (string, error) {
	types := map[contract.ObligationType]bool{}
	for _, o := range p.Obligations {
		types[o.Type] = true
	}
	switch {
	case p.Authority == contract.AuthorityConstraint && len(types) == 0:
		return "block", nil
	case p.Authority == contract.AuthorityInspection:
		return "allow", nil
	case p.Authority == contract.AuthorityRequirement && len(types) == 1 && types[contract.ObFieldRedact]:
		return "redact", nil
	case p.Authority == contract.AuthorityRequirement && len(types) == 1 && types[contract.ObNotification]:
		return "warn", nil
	case p.Authority == contract.AuthorityRequirement && len(types) == 1 && types[contract.ObImmutableAudit]:
		return "log", nil
	}
	return "", fmt.Errorf("corpus policy %s has authority %q and obligations %v, a shape legacycompile.ActionPolicy compiles from no legacy action",
		p.ID, p.Authority, p.Obligations)
}

// posturePart is the "#n" part of a row compiled into several policies, or
// nil.
func posturePart(id string) *int {
	_, suffix, ok := strings.Cut(id, "#")
	if !ok {
		return nil
	}
	n, err := strconv.Atoi(suffix)
	if err != nil {
		return nil
	}
	return &n
}

func scopeKind(p legacycompile.Plane) (kind, gatedBy string) {
	if _, gated := legacycompile.PlanesGatedByEdition[p]; gated {
		return "gated", "edition"
	}
	if _, gated := legacycompile.PlanesGatedUnderDefaultPosture[p]; gated {
		return "gated", "configuration"
	}
	if operatorToolPlanes[p] {
		return "operator-tool", ""
	}
	return "enforcement", ""
}

func postureDivergences(ds []legacycompile.Divergence) []postureDivergence {
	out := []postureDivergence{}
	for _, d := range ds {
		out = append(out, postureDivergence{
			Kind: string(d.Kind), LegacyActions: d.LegacyActions, Chosen: d.Chosen,
			FromRoot: d.FromRoot, ToRoot: d.ToRoot, ReasonCodes: reasonCodes(d.CompilerReasons),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Kind < out[j].Kind })
	return out
}

// reasonCodes are the compiler's reason codes: each carried reason's text up
// to its first colon, deduplicated.
func reasonCodes(reasons []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range reasons {
		code, _, _ := strings.Cut(r, ":")
		code = strings.TrimSpace(code)
		if code == "" || seen[code] {
			continue
		}
		seen[code] = true
		out = append(out, code)
	}
	sort.Strings(out)
	return out
}

// postureReason is the generated sentence beside the divergence facts. It says
// only what those facts and the policy shapes say.
func postureReason(ds []postureDivergence, policies []posturePolicy) string {
	var parts []string
	var variantActions []string
	for _, p := range policies {
		if _, action, _ := legacycompile.CorpusControlOf(p.PolicyID); action != "" {
			variantActions = append(variantActions, p.Action)
		}
	}
	if len(variantActions) > 1 {
		parts = append(parts, fmt.Sprintf("its action differs by scope, so it ships as one policy per action (%s), each kept only on the scopes listed",
			strings.Join(variantActions, ", ")))
	}
	for _, d := range ds {
		codes := ""
		if len(d.ReasonCodes) > 0 {
			codes = " (" + strings.Join(d.ReasonCodes, ", ") + ")"
		}
		switch d.Kind {
		case string(legacycompile.DivergencePlaneActionCollapsed):
			parts = append(parts, fmt.Sprintf("its legacy row compiles to %s on different planes and the corpus keeps %s",
				strings.Join(d.LegacyActions, " and "), d.Chosen))
		case string(legacycompile.DivergenceLegacyDefectReproduced):
			parts = append(parts, "its compilation reproduces a recorded legacy defect"+codes)
		case string(legacycompile.DivergenceRootDisagreesWithTier):
			parts = append(parts, fmt.Sprintf("it compiles on the %s root and its tier places it on the %s root", d.FromRoot, d.ToRoot))
		case string(legacycompile.DivergenceRowNotRepresented):
			parts = append(parts, "no corpus policy is compiled from it"+codes)
		case string(legacycompile.DivergenceRedactionBoundByDischarge):
			parts = append(parts, "it redacts on the scopes that can carry a redaction out and warns on the scopes that cannot, "+
				"where a mandatory redaction would refuse every request it matches")
		case string(legacycompile.DivergenceDynamicRedactionShipsAsWarn):
			parts = append(parts, "its legacy redaction ships as a warn under the same id, because no scope it binds on can carry a redaction out "+
				"and there a mandatory redaction would refuse every request it matches")
		default:
			parts = append(parts, strings.ReplaceAll(d.Kind, "_", " ")+codes)
		}
	}
	if len(parts) == 0 {
		return "Compiled with no recorded divergence."
	}
	s := strings.Join(parts, "; ")
	return strings.ToUpper(s[:1]) + s[1:] + "."
}

func renderPosture(a *postureArtifact) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(a); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// movedInputs names every input whose recorded hash differs from the one the
// derivation just took.
func movedInputs(checkedIn []byte, derived *postureArtifact) []string {
	var prior postureArtifact
	if err := json.Unmarshal(checkedIn, &prior); err != nil {
		return []string{fmt.Sprintf("the checked-in artifact does not parse (%v)", err)}
	}
	recorded := map[string]string{}
	for _, in := range prior.Provenance.Inputs {
		recorded[in.Path] = in.SHA256
	}
	var moved []string
	for _, in := range derived.Provenance.Inputs {
		switch was, ok := recorded[in.Path]; {
		case !ok:
			moved = append(moved, in.Path+": not recorded by the checked-in artifact")
		case was != in.SHA256:
			moved = append(moved, fmt.Sprintf("%s: sha256 %s when derived, %s now", in.Path, was, in.SHA256))
		}
	}
	if prior.Provenance.SystemCorpusDigest != derived.Provenance.SystemCorpusDigest {
		moved = append(moved, fmt.Sprintf("pdp.SystemCorpusDigest(): %s when derived, %s now",
			prior.Provenance.SystemCorpusDigest, derived.Provenance.SystemCorpusDigest))
	}
	return moved
}

// firstDifference renders the first differing line of two renderings.
func firstDifference(want, got []byte) string {
	w, g := strings.Split(string(want), "\n"), strings.Split(string(got), "\n")
	for i := 0; i < len(w) || i < len(g); i++ {
		var wl, gl string
		if i < len(w) {
			wl = w[i]
		}
		if i < len(g) {
			gl = g[i]
		}
		if wl != gl {
			return fmt.Sprintf("line %d, checked in %q, derived %q", i+1, wl, gl)
		}
	}
	return "none found line by line"
}
