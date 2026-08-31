// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package assurance separates detector assurance from authorization
// (ADR-065 issue #3562, epic #3551).
//
// # The contradiction this resolves
//
// Detectors are today described as advisory and skippable on error while ALSO
// being allowed to deny or require approval. Both cannot be true. The
// combination is an implicit fail-open: a control that may deny is a control
// the decision depends on, and a dependency that is skipped on error is a
// dependency that disappears exactly when it is least reliable.
//
// ADR-065 splits the two. Every control declares an assurance CLASS, and the
// class decides what its timeout or error means:
//
//	Enforcement  required deterministic control   -> failure DENIES
//	Gating risk  required score or detector       -> failure DENIES
//	Advisory     audit, warning, tuning evidence  -> failure CONTINUES, recorded
//
// # Inspection cannot grant authorization
//
// That is structural here, not conventional: Verdict has no value meaning
// "permit". Its two outcomes are Proceed (deterministic authorization stands,
// nothing here contradicted it) and Deny. A detector can stop an action; it
// can never be the reason one is allowed.
//
// # Edition
//
// Community-visible, no build tag. The PII, SQL-injection, media and
// exfiltration controls this adapts are themselves community-visible, and a
// community deployment must be able to name the assurance class of the control
// it is running.
package assurance

import (
	"fmt"
	"sort"
	"strings"
)

// Class is a control's assurance class.
type Class string

const (
	// ClassEnforcement - a required deterministic control. Failure DENIES.
	ClassEnforcement Class = "enforcement"
	// ClassGatingRisk - a required score or detector. Failure DENIES.
	ClassGatingRisk Class = "gating_risk"
	// ClassAdvisory - audit, warning or tuning evidence. Failure CONTINUES and
	// is recorded. An advisory control CANNOT deny.
	ClassAdvisory Class = "advisory"
)

// Required reports whether a failure of this class denies.
func (c Class) Required() bool { return c == ClassEnforcement || c == ClassGatingRisk }

// Valid reports whether c is one of the three.
func (c Class) Valid() bool {
	return c == ClassEnforcement || c == ClassGatingRisk || c == ClassAdvisory
}

// Outcome is what a control reported.
type Outcome string

const (
	// OutcomeClear - the control ran and found nothing.
	OutcomeClear Outcome = "clear"
	// OutcomeFlagged - the control ran and found something.
	OutcomeFlagged Outcome = "flagged"
	// OutcomeUnavailable - the control did not run, or ran and errored. NOT
	// the same as clear, and the whole point of the class table is that this
	// value means different things for different classes.
	OutcomeUnavailable Outcome = "unavailable"
)

// Provenance records where a result came from.
//
// ADR-065: "Policy never trusts a detector name or result supplied by the
// caller." A caller-supplied result is not weighted lower, it is DISCARDED -
// a client that could report its own PII scan as clear would be a client that
// could disable PII controls by asserting it had already run them.
type Provenance string

const (
	// ProvenancePlatformInvoked - the platform ran the control itself.
	ProvenancePlatformInvoked Provenance = "platform_invoked"
	// ProvenanceCallerSupplied - the caller asserted it. Never trusted.
	ProvenanceCallerSupplied Provenance = "caller_supplied"
)

// Control is a registered inspection or risk control.
type Control struct {
	// ID and Version identify the control. Version is bound into decision
	// evidence, so a ruleset change is visible in the audit trail.
	ID      string
	Version string

	// DefaultClass is the class this control has where an action does NOT
	// explicitly configure it.
	//
	// ADR-065: "a control becomes enforcement-relevant only through explicit
	// action-scoped configuration". The registry therefore REFUSES a default
	// class that is not advisory - see Registry.Build. Enforcement relevance
	// is opt-in per action and cannot be a property a control brings with it.
	DefaultClass Class

	// MinCoverage is the fraction of the input this control must have actually
	// inspected for its result to be meaningful, in [0,1]. A REQUIRED control
	// reporting less than this cannot permit: a scanner that examined 10% of a
	// payload and found nothing has not established that the payload is clean.
	MinCoverage float64

	// ReportsConfidence says whether a confidence value is meaningful for this
	// control. A deterministic pattern matcher has no confidence; a model
	// does. Evidence for a control that does not report one must not carry a
	// fabricated 1.0.
	ReportsConfidence bool
}

// Validate checks a control at registration.
func (c Control) Validate() error {
	if c.ID == "" {
		return fmt.Errorf("assurance control: id is required")
	}
	if c.Version == "" {
		return fmt.Errorf("assurance control %s: version is required; decision evidence must name the ruleset version", c.ID)
	}
	if !c.DefaultClass.Valid() {
		return fmt.Errorf("assurance control %s: unknown default class %q", c.ID, c.DefaultClass)
	}
	if c.DefaultClass != ClassAdvisory {
		return fmt.Errorf("assurance control %s: default class is %q; ADR-065 requires a control to become enforcement-relevant only through explicit action-scoped configuration, so the default class must be %q and an ActionBinding must raise it",
			c.ID, c.DefaultClass, ClassAdvisory)
	}
	if c.MinCoverage < 0 || c.MinCoverage > 1 {
		return fmt.Errorf("assurance control %s: min_coverage %v is outside [0,1]", c.ID, c.MinCoverage)
	}
	return nil
}

// ActionBinding raises a control's class for one action. This is the
// "explicit action-scoped configuration" that makes a control
// enforcement-relevant.
type ActionBinding struct {
	ActionID  string
	ControlID string
	Class     Class
}

// Registry holds controls and their action-scoped bindings. Immutable after
// Build: a runtime registration would let a request change the meaning of the
// controls inspecting it.
type Registry struct {
	controls map[string]Control
	bindings map[string]Class // actionID + "\x00" + controlID -> class
	// selected maps an action to the controls configured for it, so a caller
	// cannot silently run a control the action never selected.
	selected map[string][]string
	version  string
}

// RegistryBuilder accumulates controls and bindings.
type RegistryBuilder struct {
	version  string
	controls []Control
	bindings []ActionBinding
}

// NewRegistryBuilder starts a builder. version is carried into evidence.
func NewRegistryBuilder(version string) *RegistryBuilder {
	return &RegistryBuilder{version: version}
}

// AddControl stages a control.
func (b *RegistryBuilder) AddControl(c Control) *RegistryBuilder {
	b.controls = append(b.controls, c)
	return b
}

// Bind stages an action-scoped class for a control.
func (b *RegistryBuilder) Bind(bind ActionBinding) *RegistryBuilder {
	b.bindings = append(b.bindings, bind)
	return b
}

// Build validates and seals the registry.
func (b *RegistryBuilder) Build() (*Registry, error) {
	if b.version == "" {
		return nil, fmt.Errorf("assurance registry: version is required")
	}
	r := &Registry{
		controls: make(map[string]Control, len(b.controls)),
		bindings: map[string]Class{},
		selected: map[string][]string{},
		version:  b.version,
	}
	for _, c := range b.controls {
		if err := c.Validate(); err != nil {
			return nil, err
		}
		if _, dup := r.controls[c.ID]; dup {
			return nil, fmt.Errorf("assurance registry: duplicate control %q", c.ID)
		}
		r.controls[c.ID] = c
	}
	for _, bind := range b.bindings {
		if bind.ActionID == "" {
			return nil, fmt.Errorf("assurance registry: binding for control %q has no action", bind.ControlID)
		}
		if _, ok := r.controls[bind.ControlID]; !ok {
			return nil, fmt.Errorf("assurance registry: binding names unregistered control %q", bind.ControlID)
		}
		if !bind.Class.Valid() {
			return nil, fmt.Errorf("assurance registry: binding %s/%s has unknown class %q", bind.ActionID, bind.ControlID, bind.Class)
		}
		k := bind.ActionID + "\x00" + bind.ControlID
		if existing, dup := r.bindings[k]; dup && existing != bind.Class {
			return nil, fmt.Errorf("assurance registry: control %q is bound to action %q as both %q and %q; which one applied would depend on iteration order",
				bind.ControlID, bind.ActionID, existing, bind.Class)
		}
		r.bindings[k] = bind.Class
		if !contains(r.selected[bind.ActionID], bind.ControlID) {
			r.selected[bind.ActionID] = append(r.selected[bind.ActionID], bind.ControlID)
		}
	}
	for a := range r.selected {
		sort.Strings(r.selected[a])
	}
	return r, nil
}

// Version reports the registry snapshot version.
func (r *Registry) Version() string { return r.version }

// ClassFor returns the class a control has for an action: the action-scoped
// binding if there is one, otherwise the control's default (always advisory).
func (r *Registry) ClassFor(actionID, controlID string) (Class, bool) {
	c, ok := r.controls[controlID]
	if !ok {
		return "", false
	}
	if cl, bound := r.bindings[actionID+"\x00"+controlID]; bound {
		return cl, true
	}
	return c.DefaultClass, true
}

// SelectedFor lists the controls explicitly configured for an action.
//
// ADR-065 puts inspection-policy selection AFTER deterministic authorization
// admission; this function is what a coordinator calls at that point. It
// returns only what the action configured, so a control nobody selected cannot
// contribute to the decision even if a result for it turns up.
func (r *Registry) SelectedFor(actionID string) []string {
	return append([]string(nil), r.selected[actionID]...)
}

// Control returns a registered control.
func (r *Registry) Control(id string) (Control, bool) {
	c, ok := r.controls[id]
	return c, ok
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// Result is one control's report.
type Result struct {
	ControlID string
	// Version is the control's ruleset or model version as it ran. Compared
	// against the registry: a result from a version the registry does not know
	// is evidence about something else.
	Version string
	Outcome Outcome
	// Coverage is the fraction of the input actually inspected, in [0,1].
	Coverage float64
	// Confidence is meaningful only where the control declares it is.
	Confidence *float64
	// InputDigest identifies what was inspected, so evidence can be tied to a
	// payload without storing the payload.
	InputDigest string
	// Provenance says who produced this. Anything other than
	// ProvenancePlatformInvoked is discarded.
	Provenance Provenance
	// Err is the failure detail when Outcome is unavailable.
	Err string
}

// Decision is the inspection plane's outcome.
//
// TWO VALUES, AND NEITHER OF THEM PERMITS. ADR-065: "Inspection policy selects
// content controls, but cannot grant authorization." Proceed means "nothing
// here contradicted the deterministic decision", not "allowed".
// TestInspectionCannotGrantAuthorization pins the absence of a third value.
type Decision string

const (
	// DecisionProceed - nothing in the inspection plane denies. The
	// deterministic authorization decision stands on its own merits.
	DecisionProceed Decision = "proceed"
	// DecisionDeny - a required control denied, failed, or could not cover
	// enough of the input to have established anything.
	DecisionDeny Decision = "deny"
)

// Reason codes. Closed set.
const (
	ReasonRequiredControlFlagged     = "required_control_flagged"
	ReasonRequiredControlUnavailable = "required_control_unavailable"
	ReasonRequiredControlMissing     = "required_control_produced_no_result"
	ReasonRequiredControlLowCoverage = "required_control_coverage_below_floor"
	ReasonRequiredControlVersionSkew = "required_control_version_not_registered"
	ReasonAdvisoryReturnedDeny       = "advisory_control_attempted_to_deny"
	ReasonCallerSuppliedResult       = "caller_supplied_result_discarded"
	ReasonUnregisteredControl        = "result_from_unregistered_control_discarded"
	ReasonUnselectedControl          = "result_from_control_not_selected_for_this_action_discarded"
)

// Evidence is one control's contribution to the decision record.
type Evidence struct {
	ControlID   string
	Version     string
	Class       Class
	Outcome     Outcome
	Coverage    float64
	Confidence  *float64
	InputDigest string
	// Determining says this control's result decided the outcome.
	Determining bool
	// Note carries the reason a result was discarded or a control was skipped.
	Note string
}

// Verdict is the inspection plane's answer plus its evidence.
type Verdict struct {
	Decision Decision
	Reasons  []string
	Details  []string
	Evidence []Evidence
	// Unavailable names controls that did not report. Split by class, because
	// ADR-065 requires an advisory outage and a required-control outage to
	// have DIFFERENT documented outcomes and an operator has to be able to see
	// which happened.
	UnavailableAdvisory []string
	UnavailableRequired []string
	// Discarded names results that were not counted at all.
	Discarded []string
}

// EvaluateInput is one inspection evaluation.
type EvaluateInput struct {
	Registry *Registry
	ActionID string
	// Results are the reports gathered for this action. A control the action
	// selected but that produced no result is treated as UNAVAILABLE, never as
	// clear.
	Results []Result
}

// Evaluate applies the assurance classes to a set of control results.
func Evaluate(in EvaluateInput) Verdict {
	var v Verdict
	if in.Registry == nil {
		v.Decision = DecisionDeny
		v.Reasons = []string{ReasonRequiredControlMissing}
		v.Details = []string{"no assurance registry is wired; with no way to know which controls are required, the safe answer is deny"}
		return v
	}

	selected := in.Registry.SelectedFor(in.ActionID)
	byControl := map[string]Result{}

	for _, res := range in.Results {
		// 1. Caller-supplied results are DISCARDED. Not down-weighted: a
		// client that could report its own PII scan as clear could disable PII
		// controls by asserting it had already run them.
		if res.Provenance != ProvenancePlatformInvoked {
			v.Discarded = append(v.Discarded, res.ControlID)
			v.Reasons = append(v.Reasons, ReasonCallerSuppliedResult)
			v.Details = append(v.Details, fmt.Sprintf(
				"result for %q has provenance %q and was discarded; a caller-supplied detector result is never trusted", res.ControlID, res.Provenance))
			v.Evidence = append(v.Evidence, Evidence{ControlID: res.ControlID, Outcome: OutcomeUnavailable, Note: ReasonCallerSuppliedResult})
			continue
		}
		// 2. A result for a control the registry does not know is evidence
		// about something else.
		if _, ok := in.Registry.Control(res.ControlID); !ok {
			v.Discarded = append(v.Discarded, res.ControlID)
			v.Reasons = append(v.Reasons, ReasonUnregisteredControl)
			v.Details = append(v.Details, fmt.Sprintf("result for unregistered control %q discarded", res.ControlID))
			continue
		}
		// 3. A result for a control this ACTION did not select does not
		// contribute. Otherwise a control could be smuggled into an action's
		// decision by whoever gathers results.
		if !contains(selected, res.ControlID) {
			v.Discarded = append(v.Discarded, res.ControlID)
			v.Reasons = append(v.Reasons, ReasonUnselectedControl)
			v.Details = append(v.Details, fmt.Sprintf(
				"control %q is not configured for action %q; its result does not contribute", res.ControlID, in.ActionID))
			continue
		}
		byControl[res.ControlID] = res
	}

	deny := false
	for _, id := range selected {
		ctrl, _ := in.Registry.Control(id)
		class, _ := in.Registry.ClassFor(in.ActionID, id)
		res, reported := byControl[id]

		ev := Evidence{ControlID: id, Class: class, Version: ctrl.Version}

		// A selected control that produced no result is UNAVAILABLE, never
		// clear. Treating silence as a clean result is the fail-open.
		if !reported {
			ev.Outcome = OutcomeUnavailable
			ev.Note = "no result was produced"
			if class.Required() {
				deny = true
				ev.Determining = true
				v.UnavailableRequired = append(v.UnavailableRequired, id)
				v.Reasons = append(v.Reasons, ReasonRequiredControlMissing)
				v.Details = append(v.Details, fmt.Sprintf("required %s control %q produced no result", class, id))
			} else {
				v.UnavailableAdvisory = append(v.UnavailableAdvisory, id)
			}
			v.Evidence = append(v.Evidence, ev)
			continue
		}

		ev.Outcome = res.Outcome
		ev.Coverage = res.Coverage
		ev.InputDigest = res.InputDigest
		// Confidence is carried ONLY where the control says it is meaningful.
		// A deterministic pattern matcher reporting 1.0 would put a fabricated
		// number into the audit record.
		if ctrl.ReportsConfidence {
			ev.Confidence = res.Confidence
		} else if res.Confidence != nil {
			ev.Note = "confidence discarded: this control does not report a meaningful one"
		}

		// Version skew on a REQUIRED control cannot permit: the result came
		// from a ruleset the registry does not describe, so its meaning is
		// unknown.
		if res.Version != ctrl.Version {
			if class.Required() {
				deny = true
				ev.Determining = true
				v.Reasons = append(v.Reasons, ReasonRequiredControlVersionSkew)
				v.Details = append(v.Details, fmt.Sprintf(
					"required %s control %q reported version %q, registry has %q", class, id, res.Version, ctrl.Version))
				v.Evidence = append(v.Evidence, ev)
				continue
			}
			ev.Note = fmt.Sprintf("version skew: reported %q, registry has %q", res.Version, ctrl.Version)
		}

		switch res.Outcome {
		case OutcomeFlagged:
			if class.Required() {
				deny = true
				ev.Determining = true
				v.Reasons = append(v.Reasons, ReasonRequiredControlFlagged)
				v.Details = append(v.Details, fmt.Sprintf("required %s control %q flagged the input", class, id))
			}
			// An ADVISORY control that flagged does NOT deny. That is the
			// whole class distinction, and it is the direction that would be
			// easiest to get wrong by treating "flagged" as authoritative
			// wherever it appears.

		case OutcomeUnavailable:
			if class.Required() {
				deny = true
				ev.Determining = true
				v.UnavailableRequired = append(v.UnavailableRequired, id)
				v.Reasons = append(v.Reasons, ReasonRequiredControlUnavailable)
				v.Details = append(v.Details, fmt.Sprintf("required %s control %q was unavailable: %s", class, id, res.Err))
			} else {
				// ADVISORY OUTAGE: continue, record unavailable. This is the
				// documented difference ADR-065 asks for.
				v.UnavailableAdvisory = append(v.UnavailableAdvisory, id)
			}

		case OutcomeClear:
			// A required control that inspected too little of the input has
			// not established that the input is clean.
			if class.Required() && res.Coverage < ctrl.MinCoverage {
				deny = true
				ev.Determining = true
				v.Reasons = append(v.Reasons, ReasonRequiredControlLowCoverage)
				v.Details = append(v.Details, fmt.Sprintf(
					"required %s control %q reported clear at coverage %.2f, below its floor of %.2f; a scan of part of the input has not established that the whole is clean",
					class, id, res.Coverage, ctrl.MinCoverage))
			}

		default:
			// An unrecognised outcome is version skew or a bug. For a required
			// control it cannot permit.
			if class.Required() {
				deny = true
				ev.Determining = true
				v.Reasons = append(v.Reasons, ReasonRequiredControlUnavailable)
				v.Details = append(v.Details, fmt.Sprintf("required %s control %q reported unrecognised outcome %q", class, id, res.Outcome))
			} else {
				v.UnavailableAdvisory = append(v.UnavailableAdvisory, id)
			}
		}
		v.Evidence = append(v.Evidence, ev)
	}

	v.Reasons = sortedUnique(v.Reasons)
	v.Details = sortedUnique(v.Details)
	v.Discarded = sortedUnique(v.Discarded)
	v.UnavailableAdvisory = sortedUnique(v.UnavailableAdvisory)
	v.UnavailableRequired = sortedUnique(v.UnavailableRequired)
	sort.Slice(v.Evidence, func(i, j int) bool { return v.Evidence[i].ControlID < v.Evidence[j].ControlID })

	if deny {
		v.Decision = DecisionDeny
		return v
	}
	v.Decision = DecisionProceed
	return v
}

func sortedUnique(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// LegacyControlIDs are the shipped controls this plane adapts, with the
// assurance class they have TODAY: advisory, because none of them is
// action-scoped yet.
//
// ADR-065 requires ADR-059's capability selection to stay behaviourally
// compatible until cutover, and that is what this list encodes: naming a
// control here changes nothing about how it runs. It becomes
// enforcement-relevant only when an ActionBinding says so for a specific
// action, which is a deliberate configuration act.
var LegacyControlIDs = []string{
	"pii_detector",
	"sql_injection_detector",
	"media_detector",
	"exfiltration_detector",
	"risk_scorer",
}

// NewLegacyRegistry registers the shipped controls, all advisory, with no
// action bindings. The starting posture for the shadow migration.
func NewLegacyRegistry(version string, versions map[string]string) (*Registry, error) {
	b := NewRegistryBuilder(version)
	for _, id := range LegacyControlIDs {
		v, ok := versions[id]
		if !ok {
			return nil, fmt.Errorf("assurance registry: no version supplied for shipped control %q; decision evidence must name the ruleset version and there is no safe default", id)
		}
		b.AddControl(Control{
			ID:      id,
			Version: v,
			// Advisory, and the registry would refuse anything else as a
			// default. Enforcement relevance is per action.
			DefaultClass: ClassAdvisory,
			// The risk scorer is the one that reports a meaningful
			// confidence; the pattern matchers do not.
			ReportsConfidence: id == "risk_scorer",
			// A required pattern matcher must have seen essentially all of the
			// input. Advisory today, so this floor binds nothing until an
			// action binds the control.
			MinCoverage: coverageFloor(id),
		})
	}
	return b.Build()
}

func coverageFloor(id string) float64 {
	if strings.HasSuffix(id, "_detector") {
		// A pattern matcher that saw 99% of a payload and found nothing has
		// not established that the payload is clean - the interesting 1% is
		// exactly where an attacker puts it.
		return 1.0
	}
	// A risk score is a judgement over what it saw; requiring total coverage
	// of a scorer would deny on every truncated input.
	return 0.8
}
