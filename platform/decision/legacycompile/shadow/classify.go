package shadow

import (
	"fmt"
	"sort"
	"strings"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
)

// Classification is the verdict on one comparison.
type Classification string

const (
	// ClassMatch means the two engines agreed on everything compared.
	ClassMatch Classification = "match"
	// ClassExpectedChange means the difference is an ADR-065 change the
	// architecture decided on purpose. It carries the rule that names it.
	ClassExpectedChange Classification = "expected_change"
	// There is deliberately no legacy_defect classification; see the note
	// below the constants.
	//
	// ClassUnexplained means nothing accounted for the difference. This is the
	// value ADR-065 acceptance gate 18 requires to be zero, and it is the
	// DEFAULT: a difference is unexplained until something proves otherwise,
	// never the other way round.
	ClassUnexplained Classification = "UNEXPLAINED"
)

// WHY THERE IS NO legacy_defect CLASSIFICATION.
//
// There was one. It was removed after independent review showed it can only
// ever fire on a difference the named defect did NOT cause, and that it
// silenced a real fail-open while doing so.
//
// The argument is structural, not a bug that can be patched. This package's
// governing rule is that a legacy defect is REPRODUCED, never repaired - so a
// faithfully preserved defect makes the two sides behave IDENTICALLY, and an
// identical pair is a match, not a difference. Walk the preserved-defect
// reason codes and every one of them is symmetric by construction: a scan drop
// or a compile drop or malformed JSONB removes the row from both sides; an
// inert action applies nothing on both; a category fallback, a read-path
// divergence and a posture displacement are per-plane resolutions the model
// and the compiler both perform. None can produce the asymmetry an evidence
// rule would need.
//
// So every firing of such a rule was, necessarily, a difference caused by
// something else - and the reviewer demonstrated exactly that: two rows
// differing only in whether action_request was NULL, against the same injected
// fail-open, classified UNEXPLAINED (gate red) and legacy_defect (gate green).
// On the real seed set 46 of 112 rows carry a preserved-defect reason, so 41%
// of the population would have carried an absorption licence.
//
// Preserved defects are still RECORDED - on the compilation record, and as
// context on every diff record via DiffRecord.PreservedDefects - because a
// triager looking at an unexplained difference wants to know the row has one.
// They no longer EXPLAIN anything, which means such a difference stays
// UNEXPLAINED and a human looks at it. That is the safe direction, and it is
// the honest one: this harness cannot establish that a preserved defect caused
// a difference, so it does not claim to.
//
// #3563 asks for three classes (legacy defect, migration defect, approved
// intentional change). This deviates from that vocabulary and the deviation is
// deliberate; it is recorded in the PR body and on the issue rather than
// resolved here.

// expectedObligations is the classifier's INDEPENDENT statement of what each
// legacy action should become under ADR-065.
//
// It duplicates a mapping the compiler also makes, and the duplication is the
// entire point. The compiler asserts "redact becomes field_redact"; this table
// asserts the same thing from the other side of the diff. If somebody changes
// the compiler's arm to emit a notification instead, nothing in the compiler's
// own tests need fail - but every case exercising a redact row starts
// reporting UNEXPLAINED here, which is what a differential harness is for.
//
// An action that produces no obligation maps to the empty list. block and deny
// are expressed as executability, not as an obligation, and the classifier
// checks executability separately.
var expectedObligations = map[legacycompile.LegacyAction][]contract.ObligationType{
	legacycompile.ActionBlock:           nil,
	legacycompile.ActionDeny:            nil,
	legacycompile.ActionRedact:          {contract.ObFieldRedact},
	legacycompile.ActionLog:             {contract.ObImmutableAudit},
	legacycompile.ActionLogOnly:         {contract.ObImmutableAudit},
	legacycompile.ActionWarn:            {contract.ObNotification},
	legacycompile.ActionAllow:           {contract.ObImmutableAudit},
	legacycompile.ActionRequireApproval: {contract.ObApprovalChallenge},
	legacycompile.ActionRoute:           {contract.ObRouteRestriction},
	legacycompile.ActionAlert:           {contract.ObNotification},
}

// ExpectedObligationsFor returns the obligation types a legacy action should
// produce, and whether the action is one the table knows about.
func ExpectedObligationsFor(a legacycompile.LegacyAction) ([]contract.ObligationType, bool) {
	types, ok := expectedObligations[a]
	return types, ok
}

// ExpectedChangeRule names one intended ADR-065 semantic change.
//
// Each rule carries a PREDICATE, not a description. A classification reachable
// by matching prose is a classification reachable by accident, and "expected
// change" is the label a real regression would hide under most comfortably.
type ExpectedChangeRule struct {
	// ID is the stable rule identifier quoted in diff records.
	ID string
	// ADRSection is the section of ADR-065 that decided it.
	ADRSection string
	// Detail explains the change in one sentence.
	Detail string
	// Applies is the predicate.
	Applies func(in ClassifyInput) bool
	// ExplainsEffects declares that this rule accounts for a difference in the
	// obligation set. A rule that does not must leave one unexplained rather
	// than absorbing it.
	ExplainsEffects bool
	// ExplainsDetermining declares the same for the determining set.
	ExplainsDetermining bool
}

// ClassifyInput is everything the classifier may consider. It is a struct
// rather than a parameter list so that widening what a classification depends
// on is a visible change.
type ClassifyInput struct {
	Case   Case
	Legacy Verdict
	New    Verdict
	// Decision is the full ADR-065 decision, needed for reason codes and the
	// unknown-policy diagnostics.
	Decision *contract.Decision
	// Report is the compilation report. It supplies the preserved-defect
	// CONTEXT recorded on each record; it never justifies a classification.
	Report *legacycompile.Report
}

// expectedChangeRules is the CLOSED set of intended ADR-065 changes.
//
// Closed is the operative word. A difference no rule's predicate matches is
// UNEXPLAINED, and adding a rule is a deliberate, reviewable act that says
// "the architecture decided this". There is no catch-all and no rule whose
// predicate is true of every difference; the classifier's own tests assert,
// per rule, that it is false on a verdict pair the rule is not about.
func expectedChangeRules() []ExpectedChangeRule {
	return []ExpectedChangeRule{
		{
			ID:         "EC1_DEFAULT_DENY",
			ADRSection: "Default deny and availability ownership",
			Detail: "the legacy engines permit a request no policy matched; ADR-065 returns NotApplicable, which maps to deny in the production profile. " +
				"A read-only label is not a reason to fail open. This is the difference a plane sees at cutover before its permissions are authored.",
			Applies: func(in ClassifyInput) bool {
				return in.Legacy.Executable && !in.New.Executable &&
					in.Decision != nil &&
					in.Decision.Authorization == contract.AuthzNotApplicable &&
					in.Decision.Reason == contract.ReasonNoMatchingPermission
			},
			// NotApplicable carries no obligations and no determining set.
			ExplainsEffects: true, ExplainsDetermining: true,
		},
		{
			ID:         "EC2_UNKNOWN_IS_NOT_FALSE",
			ADRSection: "Explicit tri-state compilation model",
			Detail: "a policy-visible attribute the Policy Information Point could not establish makes the decision Indeterminate. " +
				"The legacy engines had no third truth value: an unresolvable input was compared as a value and the request proceeded.",
			Applies: func(in ClassifyInput) bool {
				if in.Decision == nil || in.Decision.Authorization != contract.AuthzIndeterminate {
					return false
				}
				// EVIDENCE: the decision must actually name an unknown policy.
				// Without this the rule would absorb every Indeterminate,
				// including an evaluation error, which is not an expected
				// change at all.
				if len(in.Decision.Determining.Unknown) == 0 {
					return false
				}
				switch in.Decision.Reason {
				case contract.ReasonUnknownConstraint, contract.ReasonUnknownPermission, contract.ReasonUnknownRequirement:
					return in.Legacy.Executable && !in.New.Executable
				}
				return false
			},
			// An Indeterminate decision carries no obligations and no
			// determining set by construction, so the rule genuinely accounts
			// for both dimensions rather than skipping past them.
			ExplainsEffects: true, ExplainsDetermining: true,
		},
		{
			ID:         "EC3_APPROVAL_IS_A_CHALLENGE_NOT_A_DENY",
			ADRSection: "Operational decision contract",
			Detail: "the legacy engines have no CHALLENGE state: require_approval sets Allowed=false, so an approvable request is indistinguishable from a refused one. " +
				"ADR-065 returns CHALLENGE with the outstanding clauses; neither state executes, so the enforcement outcome is unchanged.",
			Applies: func(in ClassifyInput) bool {
				// Both refuse execution. This rule may never explain a
				// difference in whether the request runs.
				if in.Legacy.Executable || in.New.Executable {
					return false
				}
				// EVIDENCE: the new side must actually carry an outstanding
				// approval, and the legacy side must have resolved a
				// require_approval on some row.
				if in.New.State != contract.StateChallenge || in.New.ApprovalClauses == 0 {
					return false
				}
				return in.Legacy.State == contract.StateDeny && legacyDemandedApproval(in.Legacy)
			},
			// This rule is about the STATE only. If an obligation also went
			// missing, or a different policy determined the outcome, that is a
			// separate difference and stays unexplained.
			ExplainsEffects: false, ExplainsDetermining: false,
		},
		{
			ID:         "EC6_PROXY_TIER_FIRST_MATCH_SHADOWING",
			ADRSection: "Combining by authority, not by rank",
			Detail: "the legacy proxy tier engine is first-match-wins: evaluateFirstMatch RETURNS on the first matching row in tier/priority/name " +
				"order, so a non-blocking row can shadow a matched block entirely and the request proceeds. ADR-065 combines every matched policy " +
				"by authority - any matched constraint denies, whatever else matched - so the shadowed block now refuses the request. Enforcement " +
				"is strictly tightened on this plane, never loosened, and only on the one plane whose legacy evaluation was ordered.",
			Applies: func(in ClassifyInput) bool {
				if in.Case.Plane != legacycompile.PlaneProxyTier {
					return false
				}
				// Legacy permitted, ADR-065 denied by an EXPLICIT constraint.
				// The safe direction; the rule may never explain the reverse.
				if !in.Legacy.Executable || in.New.Executable {
					return false
				}
				if in.Decision == nil || in.Decision.Authorization != contract.AuthzDeny ||
					in.Decision.Reason != contract.ReasonExplicitConstraint {
					return false
				}
				// The tier engine picked a NON-BLOCKING winner. An empty legacy
				// determining set is a different difference (nothing matched at
				// all), and a deny-side winner would mean the outcomes agree.
				if len(in.Legacy.Determining) == 0 {
					return false
				}
				// EVIDENCE: every denying constraint must be a row whose
				// detector FIRED in this very case - a row the legacy engine
				// matched and then discarded by order. A constraint the legacy
				// side never matched denying here is not first-match shadowing;
				// it is a difference this rule knows nothing about.
				cons := in.Decision.Determining.MatchedConstraints
				if len(cons) == 0 {
					return false
				}
				for _, id := range cons {
					rowKey := SourcePolicyOf(id)
					parts := strings.SplitN(rowKey, "|", 2)
					if len(parts) != 2 || !in.Case.DetectorVerdicts[parts[1]] {
						return false
					}
				}
				// A deny composes no requirements, so the new side must carry
				// nothing; anything it does carry is a separate difference.
				return len(in.New.Effects) == 0 && in.New.ApprovalClauses == 0
			},
			// The rule is about the plane's whole evaluation shape: the deny
			// reports the shadowed constraints instead of the legacy winner
			// (determining), and a deny composes no requirement obligations
			// while the legacy winner applied its one action (effects). Both
			// dimensions are consequences of the same architectural decision.
			ExplainsEffects: true, ExplainsDetermining: true,
		},
		{
			ID:         "EC5_A_DENY_CARRIES_NO_OBLIGATIONS",
			ADRSection: "Obligations",
			Detail: "ADR-065 carries obligations only on a permit: an explicit constraint determines Deny and the requirement policies are never " +
				"composed, so a denied request emits no redaction, no audit instruction and no approval, and reports only the constraint that " +
				"denied it. The legacy engines applied EVERY matched policy's action regardless of whether another policy blocked, so a blocked " +
				"request still redacted and still logged.",
			Applies: func(in ClassifyInput) bool {
				// Both sides refuse. This rule may never explain a difference
				// in whether the request runs.
				if in.Legacy.Executable || in.New.Executable {
					return false
				}
				// EVIDENCE: the new side must actually be a non-permit carrying
				// nothing, and the legacy side must carry something. Without
				// the first half the rule would absorb any deny-side obligation
				// difference, including a compiler that dropped an obligation
				// it should have emitted.
				if in.Decision == nil || in.Decision.Authorization == contract.AuthzPermit {
					return false
				}
				if len(in.New.Effects) > 0 || in.New.ApprovalClauses > 0 {
					return false
				}
				return len(in.Legacy.Effects) > 0
			},
			// A deny reports the matched constraints and composes no
			// requirements, so one fact accounts for both the effect set and
			// the determining set.
			ExplainsEffects: true, ExplainsDetermining: true,
		},
	}
}

// EC4 WAS HERE, AND WAS REMOVED BECAUSE ITS PREMISE IS FALSE.
//
// It read: "legacy evaluation reports policies in priority order and stops
// caring after the first blocking match, so the determining sets differ while
// the outcome does not." The first half is true - sortedDynamicPolicyEntries
// and the static loader both order by priority DESC - but the second is not.
// EvaluateDynamicPolicies appends EVERY applicable policy to AppliedPolicies
// and keeps going; nothing stops at the first block. The rule was therefore
// unreachable, and an unreachable rule is worse than a missing one: it reads
// as coverage. If a real determining-set difference ever appears it must be
// UNEXPLAINED until somebody looks at it.

func legacyDemandedApproval(v Verdict) bool {
	want := "legacy_action:" + string(legacycompile.ActionRequireApproval)
	for _, e := range v.Effects {
		if _, kind := SplitEffect(e); kind == want {
			return true
		}
	}
	return false
}

// ExpectedChangeRuleIDs returns every rule id, sorted.
func ExpectedChangeRuleIDs() []string {
	rules := expectedChangeRules()
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.ID)
	}
	sort.Strings(out)
	return out
}

// effectsCorrespond checks that every legacy action produced the obligations
// the correspondence table predicts, and that the new side produced no
// obligation no legacy action predicts. It returns nil when they correspond,
// and otherwise the disagreement, rendered.
func effectsCorrespond(legacy, nw Verdict) error {
	// Both sides are reduced to a multiset of (source row, obligation type,
	// target). The TYPE alone does not say what the enforcement point does -
	// two field_redact instructions against two different fields are two
	// different instructions - and the COUNT is what stops two of three
	// dropping silently.
	type key struct {
		src    string
		typ    contract.ObligationType
		target string
	}
	want := map[key]int{}
	wantApprovalActions := 0
	for _, e := range legacy.Effects {
		src, kind := SplitEffect(e)
		action, target := SplitKind(kind)
		types, known := ExpectedObligationsFor(legacycompile.LegacyAction(action))
		if !known {
			return fmt.Errorf("legacy action %q on row %s has no entry in the correspondence table, so what it should become under ADR-065 has never been decided", action, src)
		}
		for _, ty := range types {
			if ty == contract.ObApprovalChallenge {
				// Approval obligations are composed into the decision's
				// ApprovalRequirement and lose their source attribution, so
				// they are counted rather than attributed.
				wantApprovalActions++
				continue
			}
			want[key{src, ty, target}]++
		}
	}
	got := map[key]int{}
	for _, e := range nw.Effects {
		src, kind := SplitEffect(e)
		typ, target := SplitKind(kind)
		ty := contract.ObligationType(typ)
		if ty == contract.ObApprovalChallenge {
			// Carried BOTH on Decision.Obligations and, composed, on
			// Decision.Approval. Counting it here as well would double-count.
			continue
		}
		got[key{src, ty, target}]++
	}

	var problems []string
	for k, n := range want {
		if got[k] < n {
			problems = append(problems, fmt.Sprintf("row %s should have produced %d %s obligation(s)%s, ADR-065 produced %d",
				k.src, n, k.typ, targetSuffix(k.target), got[k]))
		}
	}
	for k, n := range got {
		if want[k] < n {
			problems = append(problems, fmt.Sprintf("ADR-065 produced %d %s obligation(s)%s from row %s that no legacy action predicts",
				n, k.typ, targetSuffix(k.target), k.src))
		}
	}
	// The COUNT of outstanding approvals has to match, not just the
	// zero/non-zero boundary. One caveat, stated rather than assumed:
	// composition DEDUPLICATES identical clauses, so N legacy require_approval
	// actions resolving to the SAME pool compose to one clause. Every row in
	// one compilation shares one pool today (Options.ApprovalPool falls back to
	// "*"), so the expected clause count is 1 whenever any row demanded an
	// approval - and the moment pools vary per org this comparison has to
	// become pool-aware or it will under-count.
	wantApprovalClauses := 0
	if wantApprovalActions > 0 {
		wantApprovalClauses = 1
	}
	if wantApprovalClauses != nw.ApprovalClauses {
		problems = append(problems, fmt.Sprintf(
			"%d legacy require_approval action(s) resolving to %d approver pool(s), but ADR-065 raised %d approval clause(s)",
			wantApprovalActions, wantApprovalClauses, nw.ApprovalClauses))
	}
	if len(problems) == 0 {
		return nil
	}
	sort.Strings(problems)
	return fmt.Errorf("%s", strings.Join(problems, "; "))
}

func targetSuffix(target string) string {
	if target == "" {
		return ""
	}
	return " targeting " + target
}

// FailOpenDirection says which way an executability difference runs.
type FailOpenDirection string

const (
	// FailOpenNone means the two sides agree on executability.
	FailOpenNone FailOpenDirection = "none"
	// FailOpenLegacyPermitted means legacy executed and ADR-065 did not. This
	// is the SAFE direction: the new engine is stricter.
	FailOpenLegacyPermitted FailOpenDirection = "legacy_permitted_new_denied"
	// FailOpenNewPermitted means ADR-065 executed and legacy did not. This is
	// the dangerous direction, and gate 18 blocks cutover on any unexplained
	// instance of it.
	FailOpenNewPermitted FailOpenDirection = "new_permitted_legacy_denied"
)

func directionOf(legacy, nw Verdict) FailOpenDirection {
	switch {
	case legacy.Executable == nw.Executable:
		return FailOpenNone
	case legacy.Executable:
		return FailOpenLegacyPermitted
	default:
		return FailOpenNewPermitted
	}
}

// DiffRecord is one classified comparison.
type DiffRecord struct {
	CaseID string              `json:"case_id"`
	Plane  legacycompile.Plane `json:"plane"`
	Legacy Verdict             `json:"legacy"`
	New    Verdict             `json:"new"`
	Class  Classification      `json:"classification"`
	// RuleID is the expected-change rule that explains the difference.
	RuleID string `json:"rule_id,omitempty"`
	// PreservedDefects names the rows PARTICIPATING in this comparison that
	// carry a preserved legacy defect, with the issue that owns each.
	//
	// It is CONTEXT, not an explanation. A triager looking at an unexplained
	// difference wants to know whether a row in play is already known to be
	// broken; what they must not be told is that the defect accounts for the
	// difference, because this harness cannot establish that. See the note on
	// the classification constants.
	PreservedDefects []string `json:"preserved_defects,omitempty"`
	// Detail is the human-readable explanation.
	Detail string `json:"detail"`
	// FailOpen records which way an executability difference runs. It is a
	// field rather than something to read off the prose because gate 18 is
	// specifically about fail-open differences, and a gate that reads its own
	// operand out of a sentence stops measuring what it names.
	FailOpen FailOpenDirection `json:"fail_open"`
}

// Classify compares one pair of verdicts and classifies the difference.
//
// The order is deliberate and is the safety property:
//
//  1. agreement on outcome, effects and determining set is a match;
//  2. otherwise, a preserved legacy defect on a row that PARTICIPATES in the
//     difference explains it - participation is checked, not assumed;
//  3. otherwise, an expected-change rule whose predicate holds explains it;
//  4. otherwise it is UNEXPLAINED.
//
// Step 2 precedes step 3 because a legacy defect is a fact about the rows in
// play while an expected change is a fact about the architecture, and
// attributing a real legacy defect to an architectural decision would retire
// the defect by relabelling it.
func Classify(in ClassifyInput) DiffRecord {
	rec := DiffRecord{
		CaseID: in.Case.ID, Plane: in.Case.Plane,
		Legacy: in.Legacy.Canonical(), New: in.New.Canonical(),
		FailOpen:         directionOf(in.Legacy, in.New),
		PreservedDefects: preservedDefectContext(in),
	}
	outcomeAgrees := in.Legacy.Executable == in.New.Executable && in.Legacy.State == in.New.State
	corrErr := effectsCorrespond(in.Legacy, in.New)
	detAgrees := equalStrings(SourceDetermining(in.Legacy), SourceDetermining(in.New))

	if outcomeAgrees && corrErr == nil && detAgrees {
		rec.Class = ClassMatch
		rec.Detail = "both engines refused or permitted identically, every legacy action produced the obligation the correspondence table predicts, and the determining sets agree"
		return rec
	}

	for _, r := range expectedChangeRules() {
		if !r.Applies(in) {
			continue
		}
		// A rule explains the dimension it is ABOUT. Anything it leaves
		// disagreeing is still unexplained, and returning on the first
		// matching predicate without checking the rest let one architectural
		// difference launder a real compiler defect riding along in the same
		// record - an obligation silently dropped while the outcome changed
		// for a reason the architecture had decided.
		var residual []string
		if !r.ExplainsEffects && corrErr != nil {
			residual = append(residual, "effects do not correspond: "+corrErr.Error())
		}
		if !r.ExplainsDetermining && !detAgrees {
			residual = append(residual, fmt.Sprintf("determining sets differ: legacy %v, ADR-065 %v",
				SourceDetermining(in.Legacy), SourceDetermining(in.New)))
		}
		if len(residual) > 0 {
			rec.Class = ClassUnexplained
			rec.Detail = fmt.Sprintf(
				"rule %s explains the outcome difference, but %s; a rule explains the dimension it is about and nothing else",
				r.ID, strings.Join(residual, "; "))
			return rec
		}
		rec.Class = ClassExpectedChange
		rec.RuleID = r.ID
		rec.Detail = fmt.Sprintf("ADR-065 %s: %s", r.ADRSection, r.Detail)
		return rec
	}

	rec.Class = ClassUnexplained
	corr := "effects correspond"
	if corrErr != nil {
		corr = "effects do not correspond: " + corrErr.Error()
	}
	rec.Detail = fmt.Sprintf(
		"legacy executable=%t state=%s effects=%v determining=%v; ADR-065 executable=%t state=%s effects=%v approval_clauses=%d determining=%v; %s; "+
			"no preserved legacy defect names a participating row and no expected-change rule's predicate holds",
		in.Legacy.Executable, in.Legacy.State, in.Legacy.Effects, SourceDetermining(in.Legacy),
		in.New.Executable, in.New.State, in.New.Effects, in.New.ApprovalClauses, SourceDetermining(in.New), corr)
	return rec
}

// preservedDefectContext names the participating rows that carry a preserved
// legacy defect. Context for a human, never an input to the classification.
func preservedDefectContext(in ClassifyInput) []string {
	if in.Report == nil {
		return nil
	}
	participating := map[string]bool{}
	for _, id := range SourceDetermining(in.Legacy) {
		participating[id] = true
	}
	for _, id := range SourceDetermining(in.New) {
		participating[id] = true
	}
	if len(participating) == 0 {
		return nil
	}
	var out []string
	for _, r := range in.Report.Records {
		if !participating[RowKeyFor(r.Source.Table, r.Source.PolicyID)] {
			continue
		}
		if !r.ContributesTo(in.Case.Plane) {
			continue
		}
		for _, code := range legacycompile.DefectReasonCodes() {
			if !r.HasReason(code) {
				continue
			}
			ref, _ := legacycompile.IsDefectReason(code)
			out = append(out, fmt.Sprintf("%s carries %s (%s)", r.Source.PolicyID, code, ref))
			break
		}
	}
	sort.Strings(out)
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
