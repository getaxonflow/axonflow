// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policypack_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/policypack"
)

func source() *policypack.Source {
	return &policypack.Source{
		ID: "testpack", Version: 1,
		Approval: &policypack.ApproverPool{Quorum: 1, Group: "testpack-approvers"},
		Detectors: []policypack.Detector{
			{ID: "tp_block", Name: "Block", Category: "testcat", Severity: "high", Phase: "request", Action: "block", Priority: 90, Pattern: `blockme`},
			{ID: "tp_step", Name: "Step", Category: "testcat", Severity: "medium", Phase: "request", Action: "require_approval", Priority: 80, Pattern: `stepme`},
			{ID: "tp_warn", Name: "Warn", Category: "testcat", Severity: "low", Phase: "request", Action: "warn", Priority: 70, Pattern: `warnme`},
		},
	}
}

// Every control reads its own detector and nothing else, and each action takes
// the shape the ONE mapping gives it - the assertion is on the policy the
// engine will read, not on a field this package set.
func TestEachDetectorCompilesThroughTheOneActionMapping(t *testing.T) {
	doc, err := policypack.Compile(source(), []string{"Group::r:testpack-approvers"})
	if err != nil {
		t.Fatal(err)
	}
	if doc.Root != pdp.RootOrganization || len(doc.Policies) != 3 || len(doc.Attributes) != 3 {
		t.Fatalf("root %q, %d policies, %d attributes", doc.Root, len(doc.Policies), len(doc.Attributes))
	}
	byID := map[string]pdp.Policy{}
	names := map[string]string{}
	for _, d := range source().Detectors {
		names[policypack.PolicyID("testpack", d.ID)] = d.Name
	}
	for _, p := range doc.Policies {
		byID[p.ID] = p
		if p.Name != names[p.ID] || p.Name == "" {
			t.Errorf("%s is named %q; a pack control carries its detector's name %q", p.ID, p.Name, names[p.ID])
		}
		if paths := p.ReferencedPaths(); len(paths) != 1 || !strings.HasPrefix(paths[0], "signal.detector.") {
			t.Errorf("%s reads %v; a pack control reads its own detector only", p.ID, paths)
		}
	}
	block := byID[policypack.PolicyID("testpack", "tp_block")]
	if block.Authority != contract.AuthorityConstraint || len(block.Obligations) != 0 || block.Assurance != pdp.AssuranceGatingRisk {
		t.Errorf("block: %+v", block)
	}
	step := byID[policypack.PolicyID("testpack", "tp_step")]
	if step.Authority != contract.AuthorityRequirement || !step.Mandatory || len(step.Obligations) != 1 ||
		step.Obligations[0].Type != contract.ObApprovalChallenge || step.Obligations[0].SourcePolicy != step.ID ||
		step.Obligations[0].Params["quorum"] != "1" || step.Obligations[0].Params["eligible"] != "Group::r:testpack-approvers" ||
		step.Assurance != pdp.AssuranceGatingRisk {
		t.Errorf("require_approval: %+v", step)
	}
	warn := byID[policypack.PolicyID("testpack", "tp_warn")]
	if warn.Authority != contract.AuthorityRequirement || warn.Mandatory || warn.Obligations[0].Type != contract.ObNotification || warn.Assurance != pdp.AssuranceAdvisory {
		t.Errorf("warn: %+v", warn)
	}
	// The mapping is legacycompile's, not a second spelling of it.
	base := block
	base.Authority, base.Assurance = "", ""
	want, _ := legacycompile.ActionPolicy(base, legacycompile.ActionBlock, "testcat", "high", legacycompile.DefaultContentTarget, "")
	if want.Authority != block.Authority {
		t.Errorf("block compiled to %s, legacycompile.ActionPolicy gives %s", block.Authority, want.Authority)
	}
}

func TestValidateRefusesWhatCouldNotBeEnforced(t *testing.T) {
	cases := map[string]struct {
		mutate func(*policypack.Source)
		want   string
	}{
		"a pack id with a colon":               {func(s *policypack.Source) { s.ID = "a:b" }, "one lowercase segment"},
		"version zero":                         {func(s *policypack.Source) { s.Version = 0 }, "version 0"},
		"no detector":                          {func(s *policypack.Source) { s.Detectors = nil }, "carries no detector"},
		"a duplicate detector":                 {func(s *policypack.Source) { s.Detectors[1].ID = "tp_block" }, "appears twice"},
		"a shipped detector's id":              {func(s *policypack.Source) { s.Detectors[0].ID = "drop_table_prevention" }, "shipped detector's id"},
		"a phase the detector layer lacks":     {func(s *policypack.Source) { s.Detectors[0].Phase = "either" }, "declares phase"},
		"a pattern RE2 cannot compile":         {func(s *policypack.Source) { s.Detectors[0].Pattern = `(?<=x)y` }, "does not compile under RE2"},
		"require_approval with no pool":        {func(s *policypack.Source) { s.Approval = nil }, "no approval_pool"},
		"a pool with no quorum":                {func(s *policypack.Source) { s.Approval.Quorum = 0 }, "not positive"},
		"a pool group that is not one segment": {func(s *policypack.Source) { s.Approval.Group = "r:g" }, "not one identifier segment"},
		"action_request on a response-only detector": {func(s *policypack.Source) {
			s.Detectors[0].Phase, s.Detectors[0].ActionRequest = "response", "warn"
		}, "scans only responses"},
		"action_response on a request-only detector": {func(s *policypack.Source) { s.Detectors[0].ActionResponse = "warn" }, "scans only requests"},
		"a per-phase require_approval with no pool": {func(s *policypack.Source) {
			s.Approval, s.Detectors[1].Action = nil, "block"
			s.Detectors[0].Phase, s.Detectors[0].ActionResponse = "both", "require_approval"
		}, "no approval_pool"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			s := source()
			c.mutate(s)
			err := s.Validate()
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Validate() = %v, want a refusal containing %q", err, c.want)
			}
		})
	}
	// Planted negative: the unmutated source validates, so each refusal above
	// is the mutation's.
	if err := source().Validate(); err != nil {
		t.Fatalf("the unmutated source is refused: %v", err)
	}
}

// A redact control targets the plane's content root, as a shipped redact
// control does, and says so: that is the one caveat a pack may state. An action
// with no mapping is still refused rather than shipped as something else.
func TestARedactControlTargetsTheContentRootAndSaysSo(t *testing.T) {
	s := source()
	s.Detectors[2].Action = "redact"
	doc, err := policypack.Compile(s, []string{"Group::r:g"})
	if err != nil {
		t.Fatalf("Compile() = %v, want the redact control", err)
	}
	var red pdp.Policy
	for _, p := range doc.Policies {
		if p.ID == policypack.PolicyID("testpack", "tp_warn") {
			red = p
		}
	}
	if red.Authority != contract.AuthorityRequirement || !red.Mandatory || len(red.Obligations) != 1 ||
		red.Obligations[0].Type != contract.ObFieldRedact || red.Obligations[0].Target != legacycompile.DefaultContentTarget {
		t.Fatalf("redact: %+v", red)
	}
	if !strings.Contains(red.Description, "content root") {
		t.Errorf("the redact control's description %q does not state that it redacts the content root", red.Description)
	}
	s.Detectors[2].Action = "explode"
	if _, err := policypack.Compile(s, []string{"Group::r:g"}); err == nil || !strings.Contains(err.Error(), "does not compile") {
		t.Fatalf("Compile(action with no mapping) = %v, want the refusal", err)
	}
}

// ONE detector, ONE control, unless its phases take different actions: then
// one control per phase, each suffixed with its action as the shipped corpus's
// split variants are, and each bound only on its own phase. This is the guard
// that a detector with one phase action is compiled exactly as before - the
// committed FinCrime document (TestEveryShippedPackDocumentIsWhatItsSourceCompilesTo)
// holds the same property byte for byte over a real pack.
func TestADetectorCompilesToOneControlPerDistinctPhaseAction(t *testing.T) {
	s := &policypack.Source{ID: "phasepack", Version: 1, Detectors: []policypack.Detector{
		// One phase, one action: one control, unsuffixed, bound on that phase.
		{ID: "pp_one", Name: "One", Category: "pii-india", Severity: "high", Phase: "request", Action: "warn", Pattern: "one"},
		// Both phases, an override equal to the default: still one control, bound on both.
		{ID: "pp_same", Name: "Same", Category: "pii-india", Severity: "high", Phase: "both", Action: "warn", ActionRequest: "warn", Pattern: "same"},
		// Both phases, two actions: one control per phase.
		{ID: "pp_split", Name: "Split", Category: "pii-india", Severity: "high", Phase: "both", Action: "warn", ActionResponse: "redact", Pattern: "split"},
	}}
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	pack, err := policypack.Load(raw, render(t, s))
	if err != nil {
		t.Fatal(err)
	}
	split := policypack.PolicyID("phasepack", "pp_split")
	want := []struct {
		id, phase string
		ob        contract.ObligationType
	}{
		{policypack.PolicyID("phasepack", "pp_one"), "request", contract.ObNotification},
		{policypack.PolicyID("phasepack", "pp_same"), "both", contract.ObNotification},
		{split + ":warn", "request", contract.ObNotification},
		{split + ":redact", "response", contract.ObFieldRedact},
	}
	doc := pack.Compiled
	if len(doc.Policies) != len(want) {
		t.Fatalf("%d controls, want %d: %v", len(doc.Policies), len(want), policyIDs(doc))
	}
	for i, w := range want {
		p := doc.Policies[i]
		phase, ok := pack.ControlPhase(p.ID)
		if p.ID != w.id || !ok || phase != w.phase || len(p.Obligations) != 1 || p.Obligations[0].Type != w.ob {
			t.Errorf("control %d = %s (phase %q, known %t, obligations %v), want %s bound on %s carrying %s",
				i, p.ID, phase, ok, p.Obligations, w.id, w.phase, w.ob)
		}
	}
	// One signal, two controls: both variants read the split detector, and the
	// schema declares each detector once.
	path := legacycompile.DetectorSignalPath("pp_split")
	for _, p := range doc.Policies[2:] {
		if paths := p.ReferencedPaths(); len(paths) != 1 || paths[0] != path {
			t.Errorf("%s reads %v, want only %s", p.ID, paths, path)
		}
	}
	if len(doc.Attributes) != 3 {
		t.Errorf("%d attributes, want one per detector (3)", len(doc.Attributes))
	}
	if _, ok := pack.ControlPhase(split); ok {
		t.Errorf("the unsuffixed id of a split detector is not one of the pack's controls")
	}
}

func policyIDs(doc *pdp.Document) []string {
	out := make([]string, 0, len(doc.Policies))
	for _, p := range doc.Policies {
		out = append(out, p.ID)
	}
	return out
}

func render(t *testing.T, s *policypack.Source) []byte {
	t.Helper()
	out, err := policypack.Render(s)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestLoadHoldsTheCommittedDocumentToTheSource(t *testing.T) {
	src, _ := json.Marshal(source())
	committed := render(t, source())
	if _, err := policypack.Load(src, committed); err != nil {
		t.Fatalf("the rendered form does not load: %v", err)
	}
	var doc pdp.Document
	if err := json.Unmarshal(committed, &doc); err != nil {
		t.Fatal(err)
	}
	doc.Policies[0].Authority = contract.AuthorityRequirement // a hand edit
	edited, _ := json.Marshal(&doc)
	if _, err := policypack.Load(src, edited); err == nil || !strings.Contains(err.Error(), "not what its source compiles to") {
		t.Fatalf("Load(edited) = %v, want the drift refusal", err)
	}
}

// The committed form and the instantiated form differ in the approval pool's
// eligible set and nowhere else, and only the instantiated one validates.
func TestInstantiationQualifiesThePoolPerRealmAndChangesNothingElse(t *testing.T) {
	src, _ := json.Marshal(source())
	pack, err := policypack.Load(src, render(t, source()))
	if err != nil {
		t.Fatal(err)
	}
	if errs := pack.Compiled.Validate(); len(errs) == 0 {
		t.Fatal("the committed form validates; its pool carries no realm, so it must not")
	}
	doc, digest, err := pack.Instantiate([]string{"zeta", "alpha"})
	if err != nil {
		t.Fatal(err)
	}
	if digest == "" {
		t.Fatal("no digest")
	}
	strip := func(d *pdp.Document) string {
		c := *d
		c.Policies = append([]pdp.Policy(nil), d.Policies...)
		for i := range c.Policies {
			for j := range c.Policies[i].Obligations {
				o := c.Policies[i].Obligations[j]
				if o.Type == contract.ObApprovalChallenge {
					params := map[string]string{}
					for k, v := range o.Params {
						params[k] = v
					}
					delete(params, "eligible")
					o.Params = params
					c.Policies[i].Obligations = append([]contract.Obligation(nil), c.Policies[i].Obligations...)
					c.Policies[i].Obligations[j] = o
				}
			}
		}
		out, _ := json.Marshal(&c)
		return string(out)
	}
	if strip(doc) != strip(pack.Compiled) {
		t.Fatal("the instantiated form differs from the committed form beyond the eligible set")
	}
	for _, p := range doc.Policies {
		for _, o := range p.Obligations {
			if o.Type == contract.ObApprovalChallenge && o.Params["eligible"] != "Group::alpha:testpack-approvers,Group::zeta:testpack-approvers" {
				t.Errorf("%s eligible = %q, want both realms in sorted order", p.ID, o.Params["eligible"])
			}
		}
	}
	if _, _, err := pack.Instantiate(nil); err == nil || !strings.Contains(err.Error(), "no realm a person can answer in") {
		t.Fatalf("Instantiate(no realm) = %v, want the refusal", err)
	}
}

// A detector's validator gates its signal, so the compiled document names it and
// a document whose detector names another validator is another document, under
// another digest. A detector that names none compiles exactly as before.
func TestAControlNamesTheValidatorItsDetectorNames(t *testing.T) {
	s := &policypack.Source{ID: "valpack", Version: 1, Detectors: []policypack.Detector{
		{ID: "vp_named", Name: "Named", Category: "pii-india", Severity: "high", Phase: "request", Action: "warn", Pattern: "n", Validator: "passport"},
		{ID: "vp_plain", Name: "Plain", Category: "pii-india", Severity: "high", Phase: "request", Action: "warn", Pattern: "p"},
	}}
	doc, err := policypack.Compile(s, []string{"Group::r:g"})
	if err != nil {
		t.Fatal(err)
	}
	if got := doc.Policies[0].Description; !strings.Contains(got, "action warn, validator passport).") {
		t.Errorf("vp_named's description %q does not name the validator its detector names", got)
	}
	if got := doc.Policies[1].Description; strings.Contains(got, "validator") {
		t.Errorf("vp_plain's description %q names a validator; its detector names none", got)
	}
	with := render(t, s)
	s.Detectors[0].Validator = ""
	if bytes.Equal(with, render(t, s)) {
		t.Error("the committed document is the same whether or not a detector names a validator: its digest would not cover what gates the match")
	}
}
