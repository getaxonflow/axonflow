package shadow

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
)

// LegacyEvaluator produces the legacy side of a shadow diff.
//
// It is an interface with exactly one production purpose: to let a
// production-capture adapter that wraps the RUNNING engines drop into the same
// runner as the model below. The model is what CI can execute, because the
// decision module carries no database and no orchestrator; the adapter is what
// a live shadow deployment will use. Both must produce the same Verdict shape,
// which is the contract that makes the swap safe.
type LegacyEvaluator interface {
	Evaluate(ctx context.Context, c Case) (Verdict, error)
}

// ModelEvaluator reproduces the legacy decision procedure over a compiled
// report.
//
// It is a MODEL and says so. It reproduces:
//
//   - per-plane read path selection, so the proxy tier engine resolves the
//     action column and every other plane resolves the phase columns;
//   - GetActionForPhase's category and severity fallback;
//   - the detection-posture lever, on the planes that pass an override map;
//   - priority-ordered evaluation, DESC, which decides which policy is
//     REPORTED first even where it cannot change the verdict;
//   - the ADR-060 segment applicability rule, including its fail-closed empty
//     side;
//   - the dynamic engine's condition semantics, including sprintValue's
//     stringification and the context-fallthrough resolution (#3515): a field
//     outside getFieldValue's explicit cases reads the caller-forwarded
//     req.Context[field], so its value is caller-controlled and an unsupplied
//     key makes a not_equals fire on every request;
//   - the rows the legacy readers silently drop, which contribute nothing.
//
// It does NOT reproduce: the risk-score accumulation across policies
// (modify_risk), overrides, or the HITL queue. Each of those is recorded as a
// known limitation on the run rather than silently approximated, because an
// approximation in the legacy side of a differential harness is
// indistinguishable from a real difference.
type ModelEvaluator struct {
	// Report is the compiled policy set both sides evaluate.
	Report *legacycompile.Report
	// Rows carries the per-row legacy facts the model reads, keyed by
	// RowKey(table, policy_id). It is a field rather than package state so two
	// corpora cannot leak into each other, which matters because a leaked row
	// is a policy one side enforces and the other has never heard of.
	Rows map[string]RowFacts
	// ContentTarget is the field path a STATIC redaction targets, matching
	// legacycompile.Options.ContentTarget. static_policies stores none, so
	// both sides have to be told the same one or a correspondence over
	// redaction targets compares a value against a default.
	ContentTarget string
}

// RowFacts is the slice of a captured legacy row the model needs beyond what
// the compilation record already carries.
type RowFacts struct {
	// Priority is the stored priority. Legacy evaluation is priority DESC.
	Priority int
	// Tier is the stored tier. On the PROXY TIER plane it outranks priority:
	// GetEffective orders system before organization before tenant, and
	// evaluateFirstMatch returns on the first match in that order, so a
	// system-tier log at priority 1 beats a tenant-tier block at priority 999.
	// A model that sorted on priority alone reported the opposite verdict.
	Tier string
	// Name is the stored name, the final tie-break in GetEffective's ordering.
	Name string
	// Actions is the raw dynamic_policies.actions JSONB. The model reads the
	// redaction TARGETS out of it, so the legacy side of an effect comparison
	// carries the field paths independently of what the compiler emitted.
	Actions json.RawMessage
	// Category selects the detection-posture lever.
	Category string
	// SegmentID is the ADR-060 targeting key, empty when not segment-scoped.
	SegmentID string
	// Conditions is the raw dynamic_policies.conditions JSONB, nil for a
	// static row.
	Conditions json.RawMessage
}

var _ LegacyEvaluator = (*ModelEvaluator)(nil)

// ModelLimitations names what the model does not reproduce.
//
// The runner copies it onto every Run and the gate prints it, so it is the
// reader's only protection against mistaking this harness for a complete one.
// That makes UNDERSTATING it the dangerous direction, and the first version
// did: it named three items where an independent census of the enforcement
// paths found roughly thirty-five verdict-affecting behaviours outside the
// model. The list below is that census, and the first entry is the one that
// turns a deny into an allow for an entire deployment mode.
//
// A limitation belongs here when it can change a VERDICT and the model does
// not reproduce it. Anything that only changes reporting belongs on the
// compilation report's KnownLimitations instead.
func ModelLimitations() []string {
	return []string{
		"DEPLOYMENT_MODE=community turns require_approval into ALLOW. decision_handler.go's verdict arm is " +
			"`if result.RequiresApproval && !communityMode`, so on a community deployment an approvable request falls " +
			"through to the allow arm; gateway_handlers.go's preCheckRequiresHITL is false in community mode for the " +
			"same reason. The model reports require_approval as a deny, which is what an ENTERPRISE deployment does. " +
			"For an entire deployment mode it is wrong in the fail-open direction, and a shadow run taken on a " +
			"community stack cannot be read as measuring it.",
		"An outstanding approval GRANT clears RequiresApproval before the verdict is formed (decision_handler.go, " +
			"run.go, gateway_handlers.go). That is queue state feeding back INTO the verdict, so the next limitation's " +
			"\"queue state is out of scope\" does not cover it.",
		"The HITL queue itself: whether an approval is subsequently granted is queue state, not policy.",
		"policy_overrides. The ADR-044 break-glass allow-flip IS enforced on the dynamic plane - FindActiveOverride " +
			"carries no policy_type predicate and ApplyOverrideToResult flips a deny to allow - and an action-override " +
			"resolves on the static plane through EffectiveOverride. Neither is captured and neither is modelled, so a " +
			"shadow run says nothing about a request an operator has broken glass on.",
		"modify_risk accumulation. A matched dynamic policy can raise the in-flight risk score, which a " +
			"later-evaluated policy's risk_score condition then reads. The model evaluates each policy against the " +
			"case's own field values, so an order-dependent escalation is not reproduced.",
		"Obligation-capability fallback. applySeamCapabilityObligations rewrites allow to deny when the enforcement " +
			"point cannot discharge an obligation and the org's fallback posture is block. That is a verdict change " +
			"driven by PEP capability, which this harness does not vary.",
		"Administrative-role category suppression. RoleIsAdministrative drops the whole admin-access category before " +
			"evaluation on the proxy planes, so an admin-access row is inert for those callers and the model applies it.",
		"Proxy Phase 2 MUTATES the Phase-1 result in place, overwriting Severity and setting Blocked/RequiresApproval. " +
			"The model treats proxy_request and proxy_tier as two independent planes, which is how they are cut over " +
			"but not how their results combine.",
		"Deliberate fail-open paths. hitl_execution.go proceeds on a policy-check error by explicit design decision, " +
			"and five enforcement sites treat a nil engine as allow (gateway_handlers, run.go, openai_compat_handler, " +
			"wcp_policy_adapter, map_hitl_adapter). The model has no notion of an unavailable engine, so it reports the " +
			"policy verdict where production would report the availability one.",
		"Segment-resolution failure. Every plane denies with a fail-closed guard when resolveUserSegments errors " +
			"(#3482, still an open decision). The model resolves segments from the case and never fails.",
		"Enterprise-only escalations that alter a verdict without consulting the legacy substrate: HITL " +
			"AutoApproveLowRisk, a WCP GateOverride bypassing EvaluateStepGate, MAP confirm-mode returning " +
			"require_approval with no policy consulted, and the fincrime external scorer escalating allow to " +
			"needs_approval.",
		"dynamic_policies.risk_threshold, policy_type and category are captured and read by nothing in this compiler.",
	}
}

// Evaluate returns the legacy verdict for a case.
func (m *ModelEvaluator) Evaluate(_ context.Context, c Case) (Verdict, error) {
	if m.Report == nil {
		return Verdict{}, fmt.Errorf("shadow: the legacy model has no compiled report; an evaluator with no policy set would report permit for everything, which is the fail-open shape this harness exists to detect")
	}
	spec, err := legacycompile.SpecFor(c.Plane)
	if err != nil {
		return Verdict{}, err
	}

	var hits []appliedRow

	for _, rec := range m.Report.Records {
		// One org's policies never reach another org's requests: the runtime
		// reads with `WHERE org_id = $1` under strict-equality RLS. Modelling
		// this on the legacy side is half of what makes the compiled per-org
		// documents comparable at all.
		if rec.Source.OrgScope != c.Org {
			continue
		}
		row, known := m.rowFacts(rec)
		if !known {
			// A record with no registered row facts is a corpus defect, not a
			// policy that does not apply. Silently skipping it would shrink
			// the legacy side and make the diff look clean.
			return Verdict{}, fmt.Errorf(
				"shadow: no row facts registered for %s; the legacy model would silently enforce nothing for that row",
				RowKeyFor(rec.Source.Table, rec.Source.PolicyID))
		}
		if !segmentApplies(row.SegmentID, c.Groups) {
			continue
		}
		for _, pr := range rec.Planes {
			if pr.Plane != c.Plane {
				continue
			}
			// A phase-scoped case evaluates ONE phase, the way production
			// does: the mcp plane runs its input pass and its output pass
			// separately, and each resolves its own action column. Before
			// this filter existed the model applied BOTH phases' resolutions
			// to one case - a phase='both' row contributed [log, log] to a
			// single verdict - while the engine on the other side evaluated
			// one phase-scoped document, so every two-phase plane conflated
			// its phases into one comparison. A result with no phase (the
			// dynamic read path) matches every phase.
			if c.Phase != "" && pr.Phase != "" && pr.Phase != c.Phase {
				continue
			}
			// A row the legacy READER drops contributes nothing, and that is
			// the point of preserving the drop rather than repairing it.
			if hasReason(pr.Reasons, legacycompile.ReasonLegacyScanDrop) {
				continue
			}
			// Everything else is evaluated, INCLUDING a row that compiled to
			// no policy. That is the whole reason this side exists: a row the
			// typed language cannot express, or one whose approval pool is not
			// stored, is still enforced in production, and skipping it here
			// would make the two sides agree by both being silent. A cutover
			// fail-open would then read as a match.
			//
			// Whether the row FIRES is decided by rowMatches against the
			// legacy semantics, so an unsatisfiable condition set contributes
			// nothing without needing a special case here.
			matched, err := m.rowMatches(rec, row, c)
			if err != nil {
				return Verdict{}, err
			}
			if !matched {
				continue
			}
			acts := legacyActionsOf(pr)
			if spec.PostureLever && rec.Source.Table == "static_policies" {
				for i, a := range acts {
					if displaced, did := c.Posture.Apply(row.Category, a); did {
						acts[i] = displaced
					}
				}
			}
			// A plane-level coercion outranks both the stored action and the
			// posture, exactly as it does in compileStaticForPlane: the cowork
			// ingest plane builds its own override map forcing redact for the
			// enabled PII categories, so a warn or log deployment still masks
			// before it persists. The compiler modelled this and the model did
			// not, so the two sides of the diff disagreed about the cowork
			// plane's action for every PII row - an asymmetry in the harness,
			// not a finding about the migration.
			if rec.Source.Table == "static_policies" {
				if forced, does := spec.Forces(row.Category); does {
					for i := range acts {
						acts[i] = forced
					}
				}
			}
			hits = append(hits, appliedRow{
				priority: row.Priority, policyID: rec.Source.PolicyID,
				table: rec.Source.Table, segmentID: row.SegmentID,
				tier: row.Tier, name: row.Name,
				actions: acts,
				effects: effectsForRow(RowKeyFor(rec.Source.Table, rec.Source.PolicyID), acts, row, m.ContentTarget),
			})
		}
	}

	// Legacy evaluation order: priority DESC, then a stable tie-break. On most
	// planes it cannot change WHETHER a block wins - the shared engine applies
	// every matched policy - so it decides only which policy is reported
	// first. On the proxy tier it decides the whole answer.
	if c.Plane == legacycompile.PlaneProxyTier {
		// GetEffective's order: tier ASC (system, organization, tenant), then
		// priority DESC, then name ASC.
		sort.SliceStable(hits, func(i, j int) bool {
			ti, tj := tierRank(hits[i].tier), tierRank(hits[j].tier)
			if ti != tj {
				return ti < tj
			}
			if hits[i].priority != hits[j].priority {
				return hits[i].priority > hits[j].priority
			}
			return hits[i].name < hits[j].name
		})
	} else {
		sort.SliceStable(hits, func(i, j int) bool {
			if hits[i].priority != hits[j].priority {
				return hits[i].priority > hits[j].priority
			}
			return hits[i].policyID < hits[j].policyID
		})
	}

	// THE PROXY TIER IS FIRST-MATCH-WINS, and it is the only plane that is.
	//
	// TierAwarePolicyEngine.EvaluatePolicy splits the effective set by segment
	// and runs two DIFFERENT algorithms: evaluateFirstMatch over the
	// non-segment rows, which RETURNS inside the loop on the first pattern
	// match, and evaluateStrictestMatch over the segment-scoped ones, which
	// takes the single most restrictive. The two are then combined,
	// restriction-only. At most TWO rows determine a proxy-tier verdict, where
	// every other plane accumulates all of them.
	//
	// Modelling it as "apply everything" reported a determining set the
	// running system does not produce.
	if c.Plane == legacycompile.PlaneProxyTier {
		hits = proxyTierWinners(hits)
	}

	v := Verdict{Executable: true, State: contract.StateAllow}
	for _, h := range hits {
		v.Determining = append(v.Determining, RowKeyFor(h.table, h.policyID))
		v.Effects = append(v.Effects, h.effects...)
		for _, a := range h.actions {
			switch a {
			case legacycompile.ActionBlock, legacycompile.ActionDeny,
				legacycompile.ActionRequireApproval:
				// The legacy engines have no CHALLENGE state: require_approval
				// sets Allowed=false and appends a RequiredActions marker, so
				// the request does not execute and is indistinguishable from a
				// refusal. Reported as DENY, which is what the running system
				// does - not as CHALLENGE, which would flatter it.
				v.Executable = false
				v.State = contract.StateDeny
			}
		}
	}
	return v.Canonical(), nil
}

// rowMatches decides whether one legacy row fires for a case.
func (m *ModelEvaluator) rowMatches(rec legacycompile.Record, row RowFacts, c Case) (bool, error) {
	if rec.Source.Table == "static_policies" {
		// A static policy fires when its detector matched. A detector that did
		// not run is, for the LEGACY engine, simply a pattern that did not
		// match: the engine runs every pattern it loaded, and content that
		// does not match is a non-match. There is no third state.
		return c.DetectorVerdicts[rec.Source.PolicyID], nil
	}
	conds, err := row.conditions()
	if err != nil {
		// The engine logs and continues, so the policy is loaded, counted and
		// never enforced.
		return false, nil
	}
	if conds == nil {
		// NULL or absent conditions is vacuous truth.
		return true, nil
	}
	if len(conds) == 0 {
		// An explicitly empty array is excluded from enforcement (#3384).
		return false, nil
	}
	for _, cond := range conds {
		if !legacyConditionMatches(cond, c) {
			return false, nil
		}
	}
	return true, nil
}

func (f RowFacts) conditions() ([]legacyCond, error) {
	if len(f.Conditions) == 0 || string(f.Conditions) == "null" {
		return nil, nil
	}
	var out []legacyCond
	if err := json.Unmarshal(f.Conditions, &out); err != nil {
		return nil, err
	}
	if out == nil {
		out = []legacyCond{}
	}
	return out, nil
}

type legacyCond struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    any    `json:"value"`
}

// RowKey is the key RowFacts are stored under.
func RowKey(table, policyID string) string { return table + "|" + policyID }

func (m *ModelEvaluator) rowFacts(rec legacycompile.Record) (RowFacts, bool) {
	f, ok := m.Rows[RowKeyFor(rec.Source.Table, rec.Source.PolicyID)]
	return f, ok
}

// segmentApplies reproduces CompiledPolicy.AppliesToSegments: a policy with no
// segment applies to everyone; a segment-scoped policy applies only to a
// caller whose resolved membership contains it, so a nil or empty membership
// excludes every segment-scoped policy.
func segmentApplies(segmentID string, groups []string) bool {
	if segmentID == "" {
		return true
	}
	for _, g := range groups {
		if g == segmentID {
			return true
		}
	}
	return false
}

func hasReason(rs []legacycompile.Reason, code legacycompile.ReasonCode) bool {
	for _, r := range rs {
		if r.Code == code {
			return true
		}
	}
	return false
}

// legacyActionsOf returns the legacy actions one plane result applies.
//
// A static row resolves exactly one action for the phase; a dynamic row
// applies every action in its actions array, so the plane result carries a
// comma-separated list. Splitting here rather than storing a slice keeps the
// compilation record plain JSON, and an empty string yields no actions rather
// than one empty one - which matters, because an empty action would look up as
// an unknown entry in the correspondence table and turn a row that applies
// nothing into an unexplained difference.
func legacyActionsOf(pr legacycompile.PlaneResult) []legacycompile.LegacyAction {
	if pr.ResolvedAction == "" {
		return nil
	}
	parts := strings.Split(pr.ResolvedAction, ",")
	out := make([]legacycompile.LegacyAction, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, legacycompile.LegacyAction(p))
	}
	return out
}

// effectsForRow renders the non-authorization outcomes a legacy match
// produces, in the LEGACY vocabulary.
//
// It deliberately does NOT read the compiled policies' obligations. Doing so
// would make the legacy side of the diff a projection of the compiler's own
// output, and the two sides would then agree by construction on exactly the
// mapping the harness exists to test. The classifier reconciles the two
// vocabularies through its own correspondence table.
func effectsForRow(rowKey string, actions []legacycompile.LegacyAction, facts RowFacts, contentTarget string) []string {
	out := make([]string, 0, len(actions))
	for _, a := range actions {
		if a != legacycompile.ActionRedact {
			out = append(out, LegacyEffect(rowKey, string(a), ""))
			continue
		}
		// A redaction names FIELDS, and the fields are what the enforcement
		// point is told to do. One legacy redact action over three fields is
		// three instructions, and comparing it as one let a compiler that
		// redacted the wrong field - or one field instead of three -
		// correspond cleanly.
		//
		// The targets are read from the ROW's own actions JSONB, not from the
		// compiled obligations: the compiler's mapping is the thing under
		// test, and taking its answer here would collapse the two sides.
		targets := redactTargets(facts.Actions)
		if len(targets) == 0 {
			// static_policies stores no field path for a redaction, so the
			// target is the plane's content root - the same value the compiler
			// is configured with, which is supplied rather than derived.
			targets = []string{contentTarget}
		}
		for _, t := range targets {
			out = append(out, LegacyEffect(rowKey, string(a), t))
		}
	}
	return out
}

// redactTargets reads the field paths out of a dynamic row's actions JSONB.
func redactTargets(raw json.RawMessage) []string {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var acts []struct {
		Type   string         `json:"type"`
		Config map[string]any `json:"config"`
	}
	if err := json.Unmarshal(raw, &acts); err != nil {
		return nil
	}
	var out []string
	for _, a := range acts {
		if a.Type != "redact" || a.Config == nil {
			continue
		}
		switch v := a.Config["fields"].(type) {
		case []any:
			for _, f := range v {
				if s, ok := f.(string); ok {
					out = append(out, s)
				}
			}
		case []string:
			out = append(out, v...)
		}
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------------------
// The legacy condition evaluator, reproduced.
//
// Every arm below is the behaviour of platform/shared/policy's
// ConditionEvaluator.Match, including the parts that are defects: sprintValue
// renders a nil field value as the string "<nil>" and compares it, rather than
// treating an unestablished field as a condition that cannot be evaluated.
// That is what makes `user.department not_equals compliance` fire on every
// request whose caller did not forward that context key (#3515), and
// reproducing it is the only way the shadow diff can attribute that
// difference to the legacy side rather than to the compiler.
// ---------------------------------------------------------------------------

func legacyConditionMatches(cond legacyCond, c Case) bool {
	var fieldValue any
	// EVERY field reads from the case, whatever its name. getFieldValue has
	// explicit cases for some fields, prefix handling for media.* and
	// context.*, and a default arm that is a direct req.Context[field] lookup
	// over caller-forwarded context - so there is no field production cannot
	// resolve, only fields whose value the CALLER controls (#3515). An earlier
	// version of this function refused to read a field outside the explicit
	// cases, asserting it "resolves to nil no matter what the request
	// carries"; that predicate is false, and honouring it here made the model
	// report a caller-triggerable block as a row production cannot fire.
	// Case.Fields carries the value getFieldValue would return; a field absent
	// from the map resolves to nil, exactly as a context key the caller did
	// not supply does.
	if v, present := c.Fields[cond.Field]; present {
		fieldValue = v
	}
	switch cond.Operator {
	case "equals":
		return sprintValue(fieldValue) == sprintValue(cond.Value)
	case "not_equals":
		return sprintValue(fieldValue) != sprintValue(cond.Value)
	case "contains":
		return legacyContains(fieldValue, cond.Value)
	case "not_contains":
		return !legacyContains(fieldValue, cond.Value)
	case "contains_any":
		items, ok := toAnyList(cond.Value)
		if !ok {
			return false
		}
		f := strings.ToLower(sprintValue(fieldValue))
		for _, it := range items {
			if strings.Contains(f, strings.ToLower(sprintValue(it))) {
				return true
			}
		}
		return false
	case "greater_than", "less_than":
		fv, fok := toFloat(fieldValue)
		cv, cok := toFloat(cond.Value)
		if !fok || !cok {
			return false
		}
		if cond.Operator == "greater_than" {
			return fv > cv
		}
		return fv < cv
	case "in":
		return inList(fieldValue, cond.Value)
	case "not_in":
		return !inList(fieldValue, cond.Value)
	case "regex":
		// The pattern must be a Go string; a non-string value is an immediate
		// non-match rather than a compile attempt.
		pattern, ok := cond.Value.(string)
		if !ok {
			return false
		}
		// A regex condition has no typed equivalent and the compiler refuses
		// to emit a policy for it, so a row carrying one contributes nothing
		// on the ADR-065 side. A legacy match here with no compiled
		// counterpart produces a difference the classifier cannot explain,
		// which is CORRECT: it is unexplained until somebody deals with the
		// row. The corpus carries such rows deliberately so the gate sees them
		// rather than the migration discovering them in production.
		matched, err := regexp.MatchString(pattern, sprintValue(fieldValue))
		if err != nil {
			// A pattern that does not compile is a non-match, never a panic.
			// Every legacy implementation discards this error; only whether
			// they logged it differed.
			return false
		}
		return matched
	default:
		return false
	}
}

func sprintValue(v any) string { return fmt.Sprintf("%v", v) }

func legacyContains(fieldValue, condValue any) bool {
	return strings.Contains(strings.ToLower(sprintValue(fieldValue)), strings.ToLower(sprintValue(condValue)))
}

func toAnyList(v any) ([]any, bool) {
	switch vv := v.(type) {
	case []any:
		return vv, true
	case []string:
		out := make([]any, len(vv))
		for i, s := range vv {
			out[i] = s
		}
		return out, true
	default:
		return nil, false
	}
}

// inList reproduces matchInList: a Value that is neither []any nor []string
// matches nothing, which makes `in` false and `not_in` true.
func inList(fieldValue, listValue any) bool {
	items, ok := toAnyList(listValue)
	if !ok {
		return false
	}
	f := sprintValue(fieldValue)
	for _, it := range items {
		if sprintValue(it) == f {
			return true
		}
	}
	return false
}

// toFloat reproduces the converged toFloat64: an unparseable operand is NOT
// COMPARABLE rather than silently zero. The silent zero was the live false
// positive the convergence fixed, and reproducing the FIXED behaviour is
// correct because the fixed behaviour is what runs.
func toFloat(v any) (float64, bool) {
	switch vv := v.(type) {
	case float64:
		return vv, true
	case float32:
		return float64(vv), true
	case int:
		return float64(vv), true
	case int64:
		return float64(vv), true
	case json.Number:
		f, err := vv.Float64()
		return f, err == nil
	case string:
		f, err := strconv.ParseFloat(vv, 64)
		return f, err == nil
	default:
		return 0, false
	}
}

// appliedRow is one legacy row that matched, with what it applies.
type appliedRow struct {
	priority  int
	policyID  string
	table     string
	segmentID string
	tier      string
	name      string
	actions   []legacycompile.LegacyAction
	effects   []string
}

// tierRank orders the tier column the way GetEffective does: system first,
// then organization, then tenant. An unrecognised tier sorts LAST rather than
// first, because a tier nobody declared must not pre-empt a system policy.
func tierRank(tier string) int {
	switch tier {
	case "system":
		return 0
	case "organization":
		return 1
	case "tenant":
		return 2
	default:
		return 3
	}
}

// restrictiveness mirrors agent.ActionRestrictiveness EXACTLY:
// block(5) > require_approval(4) > redact(3) > warn(2) > log(1), and ZERO for
// everything else - including deny, alert and log_only, which are declared
// LegacyActions and which that function does not rank.
//
// Mirroring the zero rather than "improving" on it is the point. The model's
// job is to reproduce the engine, and an engine that ranks `deny` at zero will
// let a `log` win a combine that this model would give to the deny. Pinned by
// TestRestrictivenessMirrorsTheEngine.
func restrictiveness(a legacycompile.LegacyAction) int {
	switch a {
	case legacycompile.ActionBlock:
		return 5
	case legacycompile.ActionRequireApproval:
		return 4
	case legacycompile.ActionRedact:
		return 3
	case legacycompile.ActionWarn:
		return 2
	case legacycompile.ActionLog:
		return 1
	default:
		return 0
	}
}

// proxyTierWinners reduces a hit list to what
// TierAwarePolicyEngine.EvaluatePolicy actually returns: ONE result.
//
// The engine splits the effective set by segment, takes the FIRST matching
// non-segment row (evaluateFirstMatch returns inside its loop), takes the MOST
// RESTRICTIVE matching segment row, and then combines the two into a single
// PolicyEvaluationResult carrying a single action - strictest wins, ties go to
// the tier result (combineTierAndSegmentResults). An earlier version of this
// function returned both, so the model named two determining policies and
// applied two actions where the engine names one and applies one.
//
// hits must already be in the engine's evaluation order.
func proxyTierWinners(hits []appliedRow) []appliedRow {
	var tierWinner, segWinner *appliedRow
	for i := range hits {
		if hits[i].segmentID == "" {
			if tierWinner == nil {
				tierWinner = &hits[i]
			}
			continue
		}
		if segWinner == nil || maxRestrictiveness(hits[i].actions) > maxRestrictiveness(segWinner.actions) {
			segWinner = &hits[i]
		}
	}
	switch {
	case tierWinner == nil && segWinner == nil:
		return nil
	case tierWinner == nil:
		return []appliedRow{*segWinner}
	case segWinner == nil:
		return []appliedRow{*tierWinner}
	}
	// Strictly greater, so a tie goes to the tier result - which is what
	// combineTierAndSegmentResults does, and it matters: ADR-060 Decision 1
	// makes a segment additive-restriction-only, never a way to displace an
	// equally restrictive tier policy.
	if maxRestrictiveness(segWinner.actions) > maxRestrictiveness(tierWinner.actions) {
		return []appliedRow{*segWinner}
	}
	return []appliedRow{*tierWinner}
}

func maxRestrictiveness(actions []legacycompile.LegacyAction) int {
	best := 0
	for _, a := range actions {
		if r := restrictiveness(a); r > best {
			best = r
		}
	}
	return best
}
