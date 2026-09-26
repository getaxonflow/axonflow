// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package policypack is an add-on policy pack: named pattern detectors a
// deployment installs, and the one typed organization-root document they
// compile into (PRD v11 §1.9).
//
// # WHAT A PACK IS, AND WHY IT IS NOT A SET OF ROWS
//
// Under PRD v11 §1.2 a seeded legacy row authors no verdict. A pack is
// therefore two things with separate lifecycles, the split the shipped corpus
// makes (legacycompile.DetectorSignalPath):
//
//   - DETECTORS, the patterns. ADR-065's condition language has no regex
//     operator, so a pattern runs in the detector layer and a typed policy
//     reads its verdict as `signal.detector.<id>`.
//   - A DOCUMENT, the controls. Each detector compiles into one policy through
//     the ONE action mapping the corpus uses: legacycompile.ApprovalPolicy for
//     require_approval, legacycompile.ActionPolicy for every other action.
//
// Nothing here is a static_policies row, and nothing here writes one.
//
// # THE COMMITTED FORM AND THE INSTANTIATED FORM
//
// A require_approval control names an approver pool, and a pool is a set of
// realm-qualified groups: pdp's document validation parses every eligible
// entry through contract.ParseID, which refuses a group with no realm. The
// realm is the deployment's, so it cannot be committed. The committed document
// is therefore Compile over the pool's UNQUALIFIED group name - reviewable and
// held to the source by Load, deliberately not a loadable document - and
// Instantiate compiles again with the realms the deployment mints principals
// in. The two differ in the approval_challenge `eligible` parameter and
// nowhere else.
//
// # COMMUNITY-VISIBLE, NO PACK CONTENT
//
// This is the mechanism. A pack's content lives with the pack - the FinCrime
// pack is under ee/policy-packs/fincrime - and nothing here names one.
package policypack

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/registry"
)

// PolicyIDPrefix is the prefix every pack policy id carries, `pack:<pack>:`.
// It is disjoint from the shipped corpus's `corpus:` and from an override
// replacement's prefix, so a pack policy is never read as either.
const PolicyIDPrefix = "pack:"

// Detector is one pattern a pack ships and the legacy action it compiles from.
type Detector struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	// Phase is the content phase the detector scans: request, response or
	// both, the vocabulary of the detector layer it runs in.
	Phase string `json:"phase"`
	// Action is the legacy action the control compiles from.
	Action string `json:"action"`
	// ActionRequest and ActionResponse override Action for one phase, as a
	// static_policies row's action_request and action_response do. A detector
	// whose phases resolve to two different actions compiles to one control per
	// phase (Controls); one whose phases resolve to one action compiles to one
	// control under the unsuffixed PolicyID.
	ActionRequest  string `json:"action_request,omitempty"`
	ActionResponse string `json:"action_response,omitempty"`
	// Priority orders the detector among the rows the detector layer loads.
	Priority int    `json:"priority"`
	Pattern  string `json:"pattern"`
	// Validator names the detector layer's validator that gates a match, a key
	// of its registry (passport, phone, ...). A detector that names none
	// matches its pattern as written: it takes no validator from its category
	// or its id, as a static_policies row does.
	Validator   string `json:"validator,omitempty"`
	Description string `json:"description"`
}

// ApproverPool is the pack's approval pool before a deployment's realms
// qualify it: the quorum and the approver group's local name.
type ApproverPool struct {
	Quorum int    `json:"quorum"`
	Group  string `json:"group"`
}

// ScoreThreshold is a pack control over an EXTERNAL SCORER's number (#3330,
// PRD v11 §1.2 ruling R2): the scorer is a fact producer whose score arrives
// as `signal.scorer.<signal>` (ScorerSignalPath), and this control is the
// typed constraint that reads it.
//
// IT ALWAYS COMPILES TO A HOLD, NEVER TO A BLOCK. There is no action field: a
// score at or above Threshold is a mandatory approval_challenge, so a score can
// hold a request for a person and can never refuse one. And a MISSING score is
// a non-match (on_absent no_match over an attribute the document declares
// optional), so a scorer that is down, unconfigured or misconfigured makes the
// control not apply rather than refuse every request: a probabilistic control
// must not be able to take the gateway down (pdp combine.go, Step 4). Why the
// score is absent is recorded beside the decision by the plane that asked.
//
// ThresholdRule is how Threshold was chosen, stated wherever the threshold is:
// the compiled control's description carries it, so a reviewer reading the
// control reads the rule and the corpus beside the number.
//
// AN ORGANIZATION MOVES THE THRESHOLD BY PUBLISHING THE CONTROL'S OWN ID: a
// policy its document carries under PolicyID(pack, id) replaces the pack's copy
// for that organization (activation.notCarried). A requirement under another id
// can only add a hold beside this one.
type ScoreThreshold struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	// Phase is the content phase the control binds on. Only request: a scorer
	// is consulted on a request pass, before anything runs.
	Phase string `json:"phase"`
	// Signal names the scorer's output the control reads (ScorerSignalPath).
	Signal        string  `json:"signal"`
	Threshold     float64 `json:"threshold"`
	ThresholdRule string  `json:"threshold_rule"`
	Description   string  `json:"description"`
}

// Source is a pack's source of truth.
type Source struct {
	ID       string        `json:"id"`
	Version  int           `json:"version"`
	Approval *ApproverPool `json:"approval_pool,omitempty"`
	// Detectors are in the pack's order, which is the compiled document's.
	Detectors []Detector `json:"detectors"`
	// Scores are the pack's controls over an external scorer's signal, compiled
	// after the detectors' controls, in this order (#3330).
	Scores []ScoreThreshold `json:"scores,omitempty"`
}

// ScorerSignalPath is the attribute path an external scorer's signal arrives
// at: `signal.scorer.<signal>`, the signal rendered as one path segment the way
// a detector id is. It is disjoint from `signal.detector.*`, so a score is
// never read as a detector's verdict, and from `signal.risk_score`, the
// platform's own content risk floor.
func ScorerSignalPath(signal string) string {
	return "signal.scorer." + legacycompile.SanitizePolicyID(signal)
}

// signalShape is a scorer signal name: one lowercase identifier.
var signalShape = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// Pack is a loaded pack: its source and the committed compiled form Load held
// to it.
type Pack struct {
	Source   Source
	Compiled *pdp.Document
}

// PolicyID is the typed policy id a pack detector compiles to.
func PolicyID(pack, detector string) string {
	return PolicyIDPrefix + pack + ":" + legacycompile.SanitizePolicyID(detector)
}

// ActionFor is the legacy action the detector takes on one phase, request or
// response: the phase's override when it sets one, Action otherwise.
func (d Detector) ActionFor(phase string) string {
	switch {
	case phase == "request" && d.ActionRequest != "":
		return d.ActionRequest
	case phase == "response" && d.ActionResponse != "":
		return d.ActionResponse
	}
	return d.Action
}

// phasesOf are the content phases a detector phase value scans.
func phasesOf(phase string) []string {
	switch phase {
	case "request", "response":
		return []string{phase}
	case "both":
		return []string{"request", "response"}
	}
	return nil
}

// Control is one control a pack detector compiles to: its policy id, the phase
// it binds on (request, response or both) and the legacy action it compiles from.
type Control struct {
	ID     string
	Phase  string
	Action string
}

// Controls are the controls one of a pack's detectors compiles to, in order.
//
// ONE action across the phases the detector scans is ONE control, under the
// unsuffixed PolicyID and bound on the detector's own phase: every pack control
// has that shape unless a per-phase action differs, so a pack that sets none
// compiles exactly as before.
//
// TWO different actions are one control per phase, each suffixed with its
// action. That is the shipped corpus's own split-variant naming
// (legacycompile.CorpusVariantIDFor: the control's identifier, ":", the action),
// so a pack control that mirrors a shipped posture reads like the shipped one.
// Both variants read the same detector: one signal, two controls.
func Controls(pack string, d Detector) []Control {
	phases := phasesOf(d.Phase)
	if len(phases) == 0 {
		return nil
	}
	if len(phases) == 2 && d.ActionFor("request") != d.ActionFor("response") {
		out := make([]Control, 0, len(phases))
		for _, ph := range phases {
			a := d.ActionFor(ph)
			out = append(out, Control{ID: PolicyID(pack, d.ID) + ":" + a, Phase: ph, Action: a})
		}
		return out
	}
	return []Control{{ID: PolicyID(pack, d.ID), Phase: d.Phase, Action: d.ActionFor(phases[0])}}
}

// ControlPhase is the phase one of this pack's controls binds on, and whether
// id is one of them. It is read from the source, which Load held the committed
// document to, so it cannot disagree with the controls the document carries.
func (p *Pack) ControlPhase(id string) (string, bool) {
	for _, d := range p.Source.Detectors {
		for _, c := range Controls(p.Source.ID, d) {
			if c.ID == id {
				return c.Phase, true
			}
		}
	}
	if s, ok := p.ScoreControl(id); ok {
		return s.Phase, true
	}
	return "", false
}

// ScoreControl is the score threshold one of this pack's controls compiles
// from, and whether id is one.
func (p *Pack) ScoreControl(id string) (ScoreThreshold, bool) {
	for _, s := range p.Source.Scores {
		if PolicyID(p.Source.ID, s.ID) == id {
			return s, true
		}
	}
	return ScoreThreshold{}, false
}

// packIDShape is a pack identifier: one lowercase segment, safe inside a
// policy id (`pack:<id>:...`) and inside `<id>@<digest>` on the wire.
var packIDShape = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// Validate refuses a source that cannot compile to a pack a deployment could
// enforce, naming every problem.
func (s *Source) Validate() error {
	var problems []string
	if !packIDShape.MatchString(s.ID) {
		problems = append(problems, fmt.Sprintf("pack id %q is not one lowercase segment", s.ID))
	}
	if s.Version < 1 {
		problems = append(problems, fmt.Sprintf("pack %q declares version %d; a shipped pack starts at 1", s.ID, s.Version))
	}
	if len(s.Detectors) == 0 && len(s.Scores) == 0 {
		problems = append(problems, fmt.Sprintf("pack %q carries no detector and no score control", s.ID))
	}
	shipped, err := shippedDetectorIDs()
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	needsPool := false
	for _, d := range s.Detectors {
		switch {
		case d.ID == "":
			problems = append(problems, "a detector has no id")
			continue
		case seen[d.ID]:
			problems = append(problems, fmt.Sprintf("detector %q appears twice", d.ID))
		case shipped[d.ID]:
			// ONE SIGNAL PATH, TWO DETECTORS. A pack detector named like a
			// shipped one would publish its verdict under the shipped
			// detector's path, and whichever ran last would decide both.
			problems = append(problems, fmt.Sprintf("detector %q is a shipped detector's id; its signal would be the shipped detector's", d.ID))
		}
		seen[d.ID] = true
		if d.Category == "" || d.Severity == "" || d.Name == "" {
			problems = append(problems, fmt.Sprintf("detector %q needs a name, a category and a severity", d.ID))
		}
		switch d.Phase {
		case "request", "response", "both":
		default:
			problems = append(problems, fmt.Sprintf("detector %q declares phase %q; the detector layer scans request, response or both", d.ID, d.Phase))
		}
		// The detector layer compiles patterns with regexp (RE2) and SKIPS one
		// that does not compile, so an invalid pattern would ship a control
		// whose signal is never produced.
		if _, err := regexp.Compile(d.Pattern); err != nil {
			problems = append(problems, fmt.Sprintf("detector %q: the pattern does not compile under RE2: %v", d.ID, err))
		}
		if d.ActionRequest != "" && d.Phase == "response" {
			problems = append(problems, fmt.Sprintf("detector %q sets action_request and scans only responses", d.ID))
		}
		if d.ActionResponse != "" && d.Phase == "request" {
			problems = append(problems, fmt.Sprintf("detector %q sets action_response and scans only requests", d.ID))
		}
		for _, a := range []string{d.Action, d.ActionRequest, d.ActionResponse} {
			if legacycompile.LegacyAction(a) == legacycompile.ActionRequireApproval {
				needsPool = true
			}
		}
	}
	signals := map[string]bool{}
	for _, sc := range s.Scores {
		switch {
		case sc.ID == "":
			problems = append(problems, "a score control has no id")
			continue
		case seen[sc.ID]:
			problems = append(problems, fmt.Sprintf("control %q appears twice", sc.ID))
		case shipped[sc.ID]:
			problems = append(problems, fmt.Sprintf("score control %q is a shipped detector's id", sc.ID))
		}
		seen[sc.ID] = true
		needsPool = true
		if sc.Category == "" || sc.Severity == "" || sc.Name == "" {
			problems = append(problems, fmt.Sprintf("score control %q needs a name, a category and a severity", sc.ID))
		}
		if sc.Phase != "request" {
			// A scorer is consulted on a request pass only, before anything
			// runs; a control bound elsewhere would read a score nobody asked for.
			problems = append(problems, fmt.Sprintf("score control %q declares phase %q; a scorer is consulted on the request phase only", sc.ID, sc.Phase))
		}
		if !signalShape.MatchString(sc.Signal) {
			problems = append(problems, fmt.Sprintf("score control %q reads signal %q, which is not one lowercase identifier", sc.ID, sc.Signal))
		} else if signals[sc.Signal] {
			problems = append(problems, fmt.Sprintf("signal %q is read by two score controls; one pack states one threshold per signal", sc.Signal))
		}
		signals[sc.Signal] = true
		if math.IsNaN(sc.Threshold) || sc.Threshold <= 0 || sc.Threshold >= 1 {
			// 0 would hold every scored request and 1 none; neither is a threshold.
			problems = append(problems, fmt.Sprintf("score control %q's threshold %v is not strictly between 0 and 1", sc.ID, sc.Threshold))
		}
		if strings.TrimSpace(sc.ThresholdRule) == "" {
			problems = append(problems, fmt.Sprintf("score control %q states no threshold_rule; a threshold ships with how it was chosen", sc.ID))
		}
	}
	if needsPool {
		switch {
		case s.Approval == nil:
			problems = append(problems, fmt.Sprintf("pack %q has require_approval detectors and no approval_pool", s.ID))
		case s.Approval.Quorum < 1:
			problems = append(problems, fmt.Sprintf("pack %q's approval_pool quorum %d is not positive", s.ID, s.Approval.Quorum))
		case s.Approval.Group == "" || strings.ContainsAny(s.Approval.Group, ":,"):
			problems = append(problems, fmt.Sprintf("pack %q's approval_pool group %q is not one identifier segment", s.ID, s.Approval.Group))
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("policypack: %s", strings.Join(problems, "; "))
	}
	return nil
}

// Compile compiles the source into its organization-root document, with the
// approval pool's eligible set as given: the unqualified group name for the
// committed form, the realm-qualified groups for an instantiated one.
func Compile(s *Source, eligible []string) (*pdp.Document, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	doc := &pdp.Document{Root: pdp.RootOrganization, Version: s.Version, Attributes: []pdp.AttributeSchema{}}
	for _, d := range s.Detectors {
		path := legacycompile.DetectorSignalPath(d.ID)
		controls := Controls(s.ID, d)
		for _, c := range controls {
			action := c.Action
			if len(controls) > 1 {
				action = fmt.Sprintf("%s on the %s phase", c.Action, c.Phase)
			}
			base := pdp.Policy{
				ID:      c.ID,
				Root:    pdp.RootOrganization,
				Scope:   pdp.Scope{Organization: true},
				Actions: pdp.ActionSelector{Any: true},
				Where:   pdp.Compare(path, pdp.OpEq, true),
				// The detector's name is the control's name, as a shipped control
				// carries the name of the legacy row it was compiled from.
				Name: d.Name,
				Description: fmt.Sprintf("%s Compiled from pack %s v%d, detector %s (%s).",
					d.Description, s.ID, s.Version, d.ID, provenance(d, action)),
			}
			var p *pdp.Policy
			if act := legacycompile.LegacyAction(c.Action); act == legacycompile.ActionRequireApproval {
				p = legacycompile.ApprovalPolicy(base, legacycompile.ApprovalPool{Quorum: s.Approval.Quorum, Eligible: eligible})
			} else {
				compiled, reasons := legacycompile.ActionPolicy(base, act, d.Category, d.Severity, legacycompile.DefaultContentTarget, "")
				if compiled == nil {
					return nil, fmt.Errorf("policypack: detector %q's action %q does not compile: %v", d.ID, c.Action, reasons)
				}
				for _, r := range reasons {
					// ONE caveat is a pack's to state, and only that one: a
					// redaction whose target no field path names. A pack detector
					// stores no field path, as the static row it mirrors did not,
					// so the redaction targets the plane's content root, exactly
					// as a shipped redact control's does - and the control says so.
					// Any other caveat is one the pack cannot state on the control,
					// so it is refused rather than shipped with the caveat dropped.
					if r.Code != legacycompile.ReasonRedactTargetNotStored {
						return nil, fmt.Errorf("policypack: detector %q's action %q compiles only with the caveat %s: %s", d.ID, c.Action, r.Code, r.Detail)
					}
					compiled.Description += fmt.Sprintf(" It redacts the plane's content root (%s): a pack detector stores no field path.", legacycompile.DefaultContentTarget)
				}
				p = compiled
			}
			class, _ := pdp.DeriveAssurance(*p)
			p.Assurance = class
			doc.Policies = append(doc.Policies, *p)
		}
		doc.Attributes = append(doc.Attributes, pdp.AttributeSchema{Path: path, Type: pdp.TypeBoolean})
	}
	for _, sc := range s.Scores {
		path := ScorerSignalPath(sc.Signal)
		base := pdp.Policy{
			ID:      PolicyID(s.ID, sc.ID),
			Root:    pdp.RootOrganization,
			Scope:   pdp.Scope{Organization: true},
			Actions: pdp.ActionSelector{Any: true},
			// A MISSING SCORE IS NO MATCH: the attribute is optional and the
			// condition says what its absence means, so the scorer's absence
			// never makes this mandatory requirement indeterminate.
			Where: pdp.Compare(path, pdp.OpGe, sc.Threshold).HandlingAbsence(pdp.AbsentIsNoMatch),
			Name:  sc.Name,
			Description: fmt.Sprintf("%s Holds for approval when %s is at least %s; the threshold was %s. A missing score does not apply this control: "+
				"the request continues and the reason no score was stated is recorded beside the decision. Compiled from pack %s v%d, score control %s "+
				"(category %s, severity %s, action require_approval).",
				sc.Description, path, strconv.FormatFloat(sc.Threshold, 'g', -1, 64), sc.ThresholdRule, s.ID, s.Version, sc.ID, sc.Category, sc.Severity),
		}
		p := legacycompile.ApprovalPolicy(base, legacycompile.ApprovalPool{Quorum: s.Approval.Quorum, Eligible: eligible})
		class, _ := pdp.DeriveAssurance(*p)
		p.Assurance = class
		doc.Policies = append(doc.Policies, *p)
		doc.Attributes = append(doc.Attributes, pdp.AttributeSchema{Path: path, Type: pdp.TypeNumber, Optional: true})
	}
	return doc, nil
}

// provenance closes a compiled control's description: the detector's category,
// severity and action, and the validator that gates its signal when it names
// one. The validator is part of what the document's digest names, so two
// installs under one digest gate a match alike (#4141).
func provenance(d Detector, action string) string {
	s := fmt.Sprintf("category %s, severity %s, action %s", d.Category, d.Severity, action)
	if d.Validator != "" {
		s += ", validator " + d.Validator
	}
	return s
}

// committedEligible is the eligible set the committed form is compiled with:
// the pool's unqualified group, or none when no control needs a pool.
func (s *Source) committedEligible() []string {
	if s.Approval == nil {
		return nil
	}
	return []string{s.Approval.Group}
}

// Load reads a pack's source and committed document and refuses a document
// that is not what the source compiles to, so the shipped controls cannot
// drift from the detectors they read.
func Load(source, committed []byte) (*Pack, error) {
	var s Source
	if err := strictDecode(source, &s); err != nil {
		return nil, fmt.Errorf("policypack: the pack source does not parse: %w", err)
	}
	var doc pdp.Document
	if err := strictDecode(committed, &doc); err != nil {
		return nil, fmt.Errorf("policypack: pack %q's committed document does not parse: %w", s.ID, err)
	}
	want, err := Compile(&s, s.committedEligible())
	if err != nil {
		return nil, err
	}
	wantDigest, err := contract.ExactDigest(want)
	if err != nil {
		return nil, err
	}
	gotDigest, err := contract.ExactDigest(&doc)
	if err != nil {
		return nil, err
	}
	if wantDigest != gotDigest {
		return nil, fmt.Errorf("policypack: pack %q's committed document is not what its source compiles to (%s against %s); regenerate it", s.ID, gotDigest, wantDigest)
	}
	return &Pack{Source: s, Compiled: &doc}, nil
}

// Render is the committed form's bytes: Compile over the unqualified pool,
// indented, newline-terminated. The regeneration test writes and compares it.
func Render(s *Source) ([]byte, error) {
	doc, err := Compile(s, s.committedEligible())
	if err != nil {
		return nil, err
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// Instantiate compiles the pack for a deployment whose identity plane mints
// principals in realms: the approval pool names the pack's group in each, in
// sorted order. The instantiated document is validated as the engine will
// read it. A pack whose controls need a pool cannot be instantiated for a
// deployment with no such realm: a pool naming nobody is not a document pdp
// accepts.
func (p *Pack) Instantiate(realms []string) (*pdp.Document, string, error) {
	var eligible []string
	if p.Source.Approval != nil {
		sorted := append([]string(nil), realms...)
		sort.Strings(sorted)
		for _, r := range sorted {
			eligible = append(eligible, "Group::"+r+":"+p.Source.Approval.Group)
		}
		if len(eligible) == 0 {
			return nil, "", fmt.Errorf("policypack: pack %q's require_approval controls name an approver pool, and the deployment declares no realm a person can answer in", p.Source.ID)
		}
	}
	doc, err := Compile(&p.Source, eligible)
	if err != nil {
		return nil, "", err
	}
	if errs := doc.Validate(); len(errs) > 0 {
		return nil, "", fmt.Errorf("policypack: pack %q does not validate as instantiated: %v", p.Source.ID, errs)
	}
	digest, err := contract.ExactDigest(doc)
	if err != nil {
		return nil, "", err
	}
	return doc, digest, nil
}

func strictDecode(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("trailing content after the JSON value")
	}
	return nil
}

// shippedDetectorIDs is the shipped detector census, by id.
func shippedDetectorIDs() (map[string]bool, error) {
	rows, err := registry.ShippedCensus()
	if err != nil {
		return nil, fmt.Errorf("policypack: reading the shipped detector census: %w", err)
	}
	out := make(map[string]bool, len(rows))
	for _, r := range rows {
		out[r.PolicyID] = true
	}
	return out, nil
}
