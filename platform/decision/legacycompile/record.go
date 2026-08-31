package legacycompile

import (
	"fmt"
	"sort"

	"axonflow/platform/decision/pdp"
)

// Status is the row-level compilation outcome. The three values are the whole
// vocabulary on purpose: a row either became policy, became policy while
// carrying a legacy defect forward, or became nothing. There is no fourth
// value meaning "skipped", because a skipped row is the failure this package
// exists to make impossible.
type Status string

const (
	// StatusCompiled means the row produced ADR-065 policy on at least one
	// plane with no legacy defect preserved.
	StatusCompiled Status = "compiled"
	// StatusPreservedDefect means the row produced policy, and the compilation
	// deliberately reproduces a known legacy defect rather than repairing it.
	// The Reasons name the defect and its issue.
	StatusPreservedDefect Status = "preserved_defect"
	// StatusUncompilable means the row produced no policy on any plane. The
	// Reasons say why. A row excluded by the legacy readers' own predicate
	// (disabled, soft-deleted) lands here too: it is a real row that compiles
	// to nothing, and saying so is more useful than pretending it was never
	// captured.
	StatusUncompilable Status = "uncompilable"
)

// ReasonCode names why a row is not a plain compile. Every one is stable and
// greppable, and the shadow classifier keys off them, so they are part of this
// package's contract rather than log text.
type ReasonCode string

const (
	// ReasonCaptureError is a capture-side failure carried through so it
	// cannot be lost. Uncompilable.
	ReasonCaptureError ReasonCode = "capture_error"
	// ReasonCaptureIncomplete means the capture did not select every column
	// the compiler needs. Uncompilable, and a defect in the capture rather
	// than in the data.
	ReasonCaptureIncomplete ReasonCode = "capture_incomplete"
	// ReasonExcludedByLegacyPredicate means the legacy readers' WHERE clause
	// excludes this row (enabled = false, or deleted_at IS NOT NULL).
	ReasonExcludedByLegacyPredicate ReasonCode = "row_excluded_by_legacy_predicate"

	// ReasonLegacyScanDrop reproduces #3397: the legacy positional scan reads
	// this row into typed destinations, a NULL column lands in a non-nullable
	// one, the scan errors, and the reader logs-and-continues (loader.go
	// loadFromDatabase) or continues silently (LoadSystemPolicies). The row is
	// not enforced and the load still reports success.
	ReasonLegacyScanDrop ReasonCode = "legacy_scan_drop"
	// ReasonLegacyCompileDrop reproduces the sibling drop: compilePolicy fails
	// to compile the regex and the row is skipped the same way.
	ReasonLegacyCompileDrop ReasonCode = "legacy_compile_drop"
	// ReasonLegacyDeadConditionField reproduces #3515: a dynamic condition
	// names a field the orchestrator resolver has no explicit case for, so it
	// falls through to the default arm's direct req.Context[field] lookup -
	// caller-forwarded context. The condition is live for exactly the
	// requests whose caller supplies that key and nil-resolving for the rest,
	// so a control the policy editor presents as a first-class field is
	// enforced from an untrusted, caller-suppliable input. The code keeps its
	// historical "dead" spelling because it is a stable, greppable contract;
	// the field is NOT dead, and the first version of this compiler that said
	// so had compiled a live block condition into nothing.
	ReasonLegacyDeadConditionField ReasonCode = "legacy_dead_condition_field"

	// ReasonReadPathActionDivergence is the migration's central finding: this
	// row's two disjoint read paths resolve to DIFFERENT actions, so what the
	// row does depends on which plane asked.
	ReasonReadPathActionDivergence ReasonCode = "read_path_action_divergence"
	// ReasonNoStoredActionForPhase means the phase column the plane reads is
	// NULL, so the legacy engine resolves through GetActionForPhase's
	// category/severity fallback. The action the operator sees in the row is
	// not the action that runs.
	ReasonNoStoredActionForPhase ReasonCode = "no_stored_action_for_phase"
	// ReasonPostureLeverDisplaces means the deployment detection posture
	// replaces this row's resolved action on lever-bearing planes.
	ReasonPostureLeverDisplaces ReasonCode = "posture_lever_displaces_stored_action"

	// ReasonPatternNotTypedCondition records that legacy content matching has
	// no ADR-065 typed-condition equivalent, so it compiles to a DETECTOR
	// reference: a static row's regex becomes a named detector the policy
	// reads (DetectorSignalPath), and a dynamic row's content conditions -
	// contains, not_contains, contains_any, regex - become one per-row
	// detector the same way (DynamicContentDetectorPath). This is a modelling
	// statement, not a defect, and it is recorded on every content policy so
	// the population is countable rather than assumed.
	ReasonPatternNotTypedCondition ReasonCode = "pattern_compiled_as_inspection_detector"
	// ReasonUnsupportedConditionOperator means a dynamic condition operator
	// has no typed equivalent.
	ReasonUnsupportedConditionOperator ReasonCode = "unsupported_condition_operator"
	// ReasonMalformedJSON means conditions or actions JSONB would not parse.
	ReasonMalformedJSON ReasonCode = "malformed_jsonb"
	// ReasonUnknownLegacyAction means the stored action is outside the set the
	// legacy engines understand.
	ReasonUnknownLegacyAction ReasonCode = "unknown_legacy_action"
	// ReasonNoActionableOutcome means the row parsed but names nothing to do.
	ReasonNoActionableOutcome ReasonCode = "no_actionable_outcome"
	// ReasonPhaseNotEvaluatedHere means the plane does not evaluate the phase
	// the row is stored for. It is NOT a defect and NOT a gap: the row is
	// simply not applicable here, which is a per-plane fact worth recording
	// and worth keeping out of the "unmeasurable" bucket, where it would
	// drown the rows that genuinely enforce something nothing can compare.
	ReasonPhaseNotEvaluatedHere ReasonCode = "phase_not_evaluated_on_this_plane"

	// ReasonApprovalPoolNotStored is the migration gap under a legacy
	// require_approval: ADR-065's approval obligation needs an eligible pool
	// and a quorum, and the legacy row stores neither - the approver set was
	// a deployment concern of the HITL queue, not a policy field. Without a
	// supplied pool the row is uncompilable, because inventing an approver
	// group would be a fabricated semantic rather than a migration.
	ReasonApprovalPoolNotStored ReasonCode = "approval_pool_not_stored"
	// ReasonRedactTargetNotStored records that a legacy redact names no field
	// path - the target was whatever span the detector matched at runtime - so
	// the disclosure obligation is emitted against the plane's declared
	// content root. It is a modelling statement, recorded so the population is
	// countable.
	ReasonRedactTargetNotStored ReasonCode = "redact_target_not_stored"
	// ReasonPriorityHasNoEquivalent records that legacy evaluation order
	// (priority DESC, created_at ASC) has no ADR-065 equivalent: combining is
	// by authority, not by rank. It cannot change a deny, because any matched
	// constraint denies; it can change WHICH policy is reported as
	// determining, which is why the shadow diff records determining policies
	// on both sides.
	ReasonPriorityHasNoEquivalent ReasonCode = "priority_has_no_equivalent"
	// ReasonRiskMutationHasNoObligation records a dynamic `modify_risk`
	// action. It adds to the in-flight risk score, which a later-evaluated
	// policy's own risk_score condition can then read, so it is an
	// order-dependent mutation of evaluation state rather than an instruction
	// to the enforcement point. ADR-065 has no obligation for that and does
	// not want one: risk is an inspection input, not an outcome.
	ReasonRiskMutationHasNoObligation ReasonCode = "risk_mutation_has_no_obligation"
	// ReasonInertLegacyAction records a dynamic action type that falls through
	// the orchestrator's action switch with no matching case and therefore
	// applies nothing at all. It is preserved as a no-op because that is what
	// the running system does; migration 036's downgraded
	// sys_dyn_high_risk_block sat in exactly this state until a `warn` arm was
	// added, believed to be warning and silently inert.
	ReasonInertLegacyAction ReasonCode = "inert_legacy_action"
	// ReasonVacuousConditionSet records a dynamic policy whose stored
	// conditions are NULL or absent: the engine treats that as vacuous truth
	// and the policy applies to everything.
	ReasonVacuousConditionSet ReasonCode = "vacuous_condition_set"
)

// defectReasons are the reason codes that mean "a legacy defect was preserved
// on purpose". Membership decides Status, and the shadow classifier consults
// the same set, so a new defect reason cannot be added to one and forgotten in
// the other.
var defectReasons = map[ReasonCode]string{
	ReasonLegacyScanDrop:           "#3397",
	ReasonLegacyCompileDrop:        "#3397",
	ReasonLegacyDeadConditionField: "#3515",
	ReasonReadPathActionDivergence: "#3563",
	ReasonNoStoredActionForPhase:   "#3563",
	ReasonPostureLeverDisplaces:    "#3360",
	ReasonInertLegacyAction:        "#3563",
	// Malformed conditions or actions JSONB is the SAME substrate behaviour as
	// an uncompilable regex on a static row: the engine logs, continues, and
	// the policy is loaded, counted and never enforced. Filing one as a
	// preserved defect and the other as uncompilable would put two identical
	// legacy behaviours in different buckets, and the migration report's
	// headline counts are built from those buckets.
	ReasonMalformedJSON: "#3397",
}

// compilerGapReasons are the reasons that mean THIS COMPILER could not express
// the row - as opposed to the row being faithfully reproduced as unenforced.
//
// The distinction decides the status of a row that produced no policy AND
// carries a preserved defect, which is reachable: a dead condition field
// (#3515, a defect) under an operator the typed language has no equivalent for
// (a gap). Without the split, a compiler gap wears a legacy-defect label,
// CountsByStatus reports uncompilable=0, and a reader sizing "how much can the
// compiler not express yet" is told nothing.
var compilerGapReasons = map[ReasonCode]bool{
	ReasonCaptureError:                 true,
	ReasonCaptureIncomplete:            true,
	ReasonUnsupportedConditionOperator: true,
	ReasonApprovalPoolNotStored:        true,
	ReasonUnknownLegacyAction:          true,
	ReasonRiskMutationHasNoObligation:  true,
}

// IsCompilerGapReason reports whether a reason marks something the compiler
// could not express, rather than a legacy behaviour it reproduced.
func IsCompilerGapReason(c ReasonCode) bool { return compilerGapReasons[c] }

// IsDefectReason reports whether a reason code marks a preserved legacy
// defect, and returns the issue that owns it.
func IsDefectReason(c ReasonCode) (string, bool) {
	ref, ok := defectReasons[c]
	return ref, ok
}

// DefectReasonCodes returns every preserved-defect reason code in a stable
// order. Exported so the shadow classifier enumerates the same set rather than
// carrying a second copy.
func DefectReasonCodes() []ReasonCode {
	out := make([]ReasonCode, 0, len(defectReasons))
	for c := range defectReasons {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Reason is one structured explanation attached to a Record.
type Reason struct {
	Code ReasonCode `json:"code"`
	// Issue is the tracking issue that owns the defect, empty for reasons that
	// are not defects.
	Issue string `json:"issue,omitempty"`
	// Plane scopes the reason when it is per-plane rather than per-row.
	Plane Plane `json:"plane,omitempty"`
	// Detail is human-readable specifics: which column, which field, which
	// two actions diverged.
	Detail string `json:"detail"`
}

// SourceRef traces a compiled policy back to the exact row it came from.
// ADR-065's acceptance criterion is that compiled policy is losslessly
// traceable to source row and version, so this travels with every record AND
// is stamped into each emitted policy's identifier.
type SourceRef struct {
	Table    string `json:"table"`
	OrgScope string `json:"org_scope"`
	ID       string `json:"id"`
	PolicyID string `json:"policy_id"`
	Version  int    `json:"version"`
	// RowDigest is a content digest over the captured columns, so a later
	// capture can prove a row did or did not change.
	RowDigest string `json:"row_digest"`
}

// PlaneResult is what one row compiled to on one plane.
type PlaneResult struct {
	Plane Plane `json:"plane"`
	// Phase is the legacy evaluation phase this result describes, for a
	// static read path. A plane evaluating two phases produces two results
	// for one row, and before this field existed nothing on the result said
	// which was which - so the shadow model applied BOTH phases' resolutions
	// to one case while the compiled engine saw one document, and every
	// two-phase plane conflated its phases into a single comparison. Empty
	// for the dynamic read path, which has no phase concept.
	Phase Phase `json:"phase,omitempty"`
	// ReadPath is which legacy column set this plane's compilation read.
	ReadPath ReadPath `json:"read_path"`
	// Policies are the emitted ADR-065 typed policies. Empty means the row
	// contributes nothing on this plane, and Reasons says why.
	Policies []pdp.Policy `json:"policies,omitempty"`
	// ResolvedAction is the legacy action this plane resolves for the row,
	// AFTER phase resolution and category fallback but BEFORE the posture
	// lever. Empty when the plane resolves nothing.
	ResolvedAction string `json:"resolved_action,omitempty"`
	// StoredAction is the explicit column value the plane's read path
	// supplies, empty when that column is NULL. The pair
	// (StoredAction, ResolvedAction) is what makes a category fallback
	// visible instead of leaving the action column an unexplained lie.
	StoredAction string   `json:"stored_action,omitempty"`
	Reasons      []Reason `json:"reasons,omitempty"`
	// AttributePaths are every ADR-065 attribute path this row READS on this
	// plane, whether or not it compiled to a policy.
	//
	// A row the compiler could not express still reads inputs, and a shadow
	// request has to be able to CARRY those inputs or the two sides cannot be
	// compared: the PDP refuses a request bearing an attribute its document
	// does not declare, so an undeclared path turns every case on the plane
	// into a schema violation. Declaring a path no policy reads costs nothing;
	// omitting one makes the plane unmeasurable.
	AttributePaths []string `json:"attribute_paths,omitempty"`
}

// Record is the compilation record for exactly one captured row.
type Record struct {
	Source  SourceRef     `json:"source"`
	Status  Status        `json:"status"`
	Reasons []Reason      `json:"reasons,omitempty"`
	Planes  []PlaneResult `json:"planes,omitempty"`
}

// PolicyCount returns how many ADR-065 policies this record emitted across
// every plane.
func (r Record) PolicyCount() int {
	n := 0
	for _, p := range r.Planes {
		n += len(p.Policies)
	}
	return n
}

// HasReason reports whether the record carries a reason code, at row level or
// on any plane.
func (r Record) HasReason(c ReasonCode) bool {
	for _, rs := range r.Reasons {
		if rs.Code == c {
			return true
		}
	}
	for _, p := range r.Planes {
		for _, rs := range p.Reasons {
			if rs.Code == c {
				return true
			}
		}
	}
	return false
}

// Limitation is a known, whole-population gap recorded once on the report
// rather than repeated on every row it applies to.
type Limitation struct {
	Issue  string `json:"issue"`
	Scope  string `json:"scope"`
	Detail string `json:"detail"`
}

// Report is the complete compilation result.
type Report struct {
	Records []Record `json:"records"`
	// InputRows is the number of raw rows handed to the compiler. The
	// exactly-one-Record invariant is len(Records) == InputRows and is
	// asserted, not assumed.
	InputRows int `json:"input_rows"`
	// KnownLimitations are population-wide gaps that are not per-row facts.
	KnownLimitations []Limitation `json:"known_limitations"`
}

// CountsByStatus returns the record count per status.
func (rep Report) CountsByStatus() map[Status]int {
	out := map[Status]int{StatusCompiled: 0, StatusPreservedDefect: 0, StatusUncompilable: 0}
	for _, r := range rep.Records {
		out[r.Status]++
	}
	return out
}

// CountsByTable returns the record count per source table.
func (rep Report) CountsByTable() map[string]int {
	out := map[string]int{}
	for _, r := range rep.Records {
		out[r.Source.Table]++
	}
	return out
}

// CountsByReason returns how many records carry each reason code.
func (rep Report) CountsByReason() map[ReasonCode]int {
	out := map[ReasonCode]int{}
	for _, r := range rep.Records {
		seen := map[ReasonCode]bool{}
		mark := func(rs []Reason) {
			for _, x := range rs {
				if !seen[x.Code] {
					seen[x.Code] = true
					out[x.Code]++
				}
			}
		}
		mark(r.Reasons)
		for _, p := range r.Planes {
			mark(p.Reasons)
		}
	}
	return out
}

// OrgScopes returns every org scope the capture carries, sorted.
//
// It is the second dimension of the compilation, alongside the plane: the
// runtime reads policy under strict per-org row-level security, so one
// document per plane per org is what the deployment actually has.
func (rep Report) OrgScopes() []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range rep.Records {
		if !seen[r.Source.OrgScope] {
			seen[r.Source.OrgScope] = true
			out = append(out, r.Source.OrgScope)
		}
	}
	sort.Strings(out)
	return out
}

// PoliciesFor returns every emitted policy for a plane and org scope, in a
// stable order.
func (rep Report) PoliciesFor(p Plane, orgScope string) []pdp.Policy {
	return rep.PoliciesForPhase(p, "", orgScope)
}

// PoliciesForPhase returns the emitted policies for one plane, one PHASE and
// one org scope. An empty phase means every phase, which is what a
// single-phase plane's callers pass.
//
// The phase dimension exists because a two-phase plane's engine evaluates one
// phase per pass in production: the mcp plane runs its input pass and its
// output pass separately, and a row storing phase='both' resolves an action in
// EACH pass. Building one document out of both phases' policies made every
// shadow comparison on that plane evaluate two passes as one.
func (rep Report) PoliciesForPhase(p Plane, ph Phase, orgScope string) []pdp.Policy {
	var out []pdp.Policy
	for _, r := range rep.Records {
		if r.Source.OrgScope != orgScope {
			continue
		}
		for _, pr := range r.Planes {
			if pr.Plane != p {
				continue
			}
			if ph != "" && pr.Phase != "" && pr.Phase != ph {
				continue
			}
			out = append(out, pr.Policies...)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ContributesTo reports whether the LEGACY ENGINE enforces this row on a
// plane - which is a different question from whether it compiled.
//
// The distinction decides what the shadow gate must cover. A row the compiler
// could not express still runs in production, so it has to appear in the
// coverage denominator and in the legacy side of the diff; otherwise the two
// sides agree by both being silent, and a cutover fail-open reads as a match.
// A row the legacy READER drops (#3397 scan drop) genuinely enforces nothing,
// so it does not contribute.
func (r Record) ContributesTo(p Plane) bool {
	return r.ContributesOnPhase(p, "")
}

// ContributesOnPhase is ContributesTo scoped to one legacy phase. An empty
// phase means any phase; a result with no phase (the dynamic read path)
// matches every phase, because the dynamic engine has no phase concept.
func (r Record) ContributesOnPhase(p Plane, ph Phase) bool {
	for _, pr := range r.Planes {
		if pr.Plane != p {
			continue
		}
		if ph != "" && pr.Phase != "" && pr.Phase != ph {
			continue
		}
		dropped := false
		for _, rs := range pr.Reasons {
			if rs.Code == ReasonLegacyScanDrop {
				dropped = true
			}
		}
		if dropped {
			continue
		}
		if pr.ResolvedAction != "" || len(pr.Policies) > 0 {
			return true
		}
	}
	return false
}

// RowsFor returns the source rows the legacy engine enforces on a plane. It is
// what makes per-policy-row coverage reportable: the shadow gate compares this
// against the rows the replay corpus actually exercised, and names the
// difference.
//
// It is keyed on ContributesTo rather than on "emitted a policy", because a
// coverage denominator built from what COMPILED would shrink by exactly the
// rows the migration has not solved.
func (rep Report) RowsFor(p Plane) []SourceRef {
	var out []SourceRef
	for _, r := range rep.Records {
		if r.ContributesTo(p) {
			out = append(out, r.Source)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Table != out[j].Table {
			return out[i].Table < out[j].Table
		}
		return out[i].PolicyID < out[j].PolicyID
	})
	return out
}

// Reconcile checks the record count against an independently obtained count
// per table - in practice `SELECT count(*)` run by the capture step.
//
// This is the anti-silent-drop assertion at report level. The compiler already
// guarantees one Record per input row; this guarantees the input itself was
// complete, which is the half a compiler cannot check on its own.
func (rep Report) Reconcile(dbCounts map[string]int) error {
	if len(rep.Records) != rep.InputRows {
		return fmt.Errorf(
			"legacycompile: %d records for %d input rows - the one-record-per-row invariant is broken, which is the #3397 silent-drop class",
			len(rep.Records), rep.InputRows)
	}
	got := rep.CountsByTable()
	var tables []string
	for t := range dbCounts {
		tables = append(tables, t)
	}
	for t := range got {
		if _, ok := dbCounts[t]; !ok {
			tables = append(tables, t)
		}
	}
	sort.Strings(tables)
	seen := map[string]bool{}
	for _, t := range tables {
		if seen[t] {
			continue
		}
		seen[t] = true
		if got[t] != dbCounts[t] {
			return fmt.Errorf(
				"legacycompile: table %q compiled %d record(s) but the database reports %d row(s); "+
					"a row that reaches neither a record nor the count is a row nobody is accountable for",
				t, got[t], dbCounts[t])
		}
	}
	return nil
}
