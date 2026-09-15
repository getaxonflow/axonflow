// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package legacycompile

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/registry"
)

// DetectorSignalPath is the attribute path a compiled static policy reads.
//
// A legacy static policy is a REGEX over content, and ADR-065's typed
// condition language has no regex operator - deliberately, because a condition
// language that can run arbitrary patterns over payloads is an inspection
// subsystem wearing a policy's clothes. So the pattern does not become a
// condition. It becomes a named DETECTOR, and the compiled policy reads that
// detector's verdict as an ordinary tri-state attribute.
//
// The consequence is load bearing and is an intended ADR-065 change rather
// than a compiler artifact: when the detector did not run, its signal is
// UNKNOWN, and an unknown constraint makes the decision Indeterminate. Under
// the legacy engine the same situation - the pattern never evaluated - was
// simply no match, which permits. The shadow diff will report this as an
// expected change, which is exactly where it belongs.
// IT DELEGATES (#3884). `registry.DetectorID.SignalPath` is the one derivation
// of this path and this function is its caller, not a second spelling of it.
// The registry keys detector records on the same identifier, so two spellings
// would be two answers that agree until one changes - and the failure would be
// a policy reading an attribute path no enforcement point ever populates, which
// is a permanently UNKNOWN detector and therefore an Indeterminate decision.
// The dependency direction is the safe one: this package is the migration tool
// and the registry is permanent.
func DetectorSignalPath(policyID string) string {
	return registry.DetectorID(policyID).SignalPath()
}

// sanitizePathSegment renders a policy id as one attribute-path segment,
// BIJECTIVELY.
//
// The first version hex-escaped anything outside the permitted alphabet as
// "x"+hex, which is not self-delimiting against that same alphabet:
// "a.b" and the literal id "ax2eb" both produced "ax2eb". Two rows then shared
// one detector signal path, one overwrote the other's verdict in map order, and
// the same pinned inputs classified differently between runs - which breaks
// replay reproducibility as well as the diff.
//
// The encoding here is injective: "_" is doubled, every other non-permitted
// rune becomes "_<hex>_", and an id that would otherwise be ambiguous cannot
// arise because "_" is the only escape introducer and it is always escaped.
// IT DELEGATES (#3884). The encoding lives in `platform/decision/registry`,
// which keys detector records on the identifier this produces. Two
// implementations of one bijection are two answers that agree until one
// changes, and here the disagreement would be silent: a policy would read an
// attribute path no enforcement point populates. `UnsanitizePolicyID` below is
// the INVERSE and stays here, held to this by TestSanitizeRoundTripsAndMatches
// TheRegistrysEncoding.
func sanitizePathSegment(in string) string {
	return registry.EncodePathSegment(in)
}

// PolicyIDFor renders the ADR-065 policy identifier for one compiled output.
// It carries the source table, row policy_id, plane and phase so a compiled
// policy is losslessly traceable to its source row, which is one of #3563's
// acceptance criteria.
//
// `table` is the FULL table name, matching SourceRef.Table. An abbreviated
// token here and the full name on the record would make the two sides of the
// shadow diff key the same row differently, so nothing would ever match.
//
// The policy id is SANITISED into the identifier. policy_id is VARCHAR(100)
// with no character constraint, so it can contain the ':' this format
// separates on - and an unsanitised id then fails to round-trip: a row named
// "acme:ssn" parsed back as "acme", which is also the key a row genuinely
// named "acme" produces. Two distinct rows, one key. RawPolicyID recovers the
// original, and SourceRef carries it unmodified.
func PolicyIDFor(table, policyID string, plane Plane, phase Phase) string {
	safe := sanitizePathSegment(policyID)
	if phase == "" {
		return fmt.Sprintf("legacy:%s:%s:%s", table, safe, plane)
	}
	return fmt.Sprintf("legacy:%s:%s:%s:%s", table, safe, plane, phase)
}

// SanitizePolicyID renders a policy id the way PolicyIDFor and
// DetectorSignalPath embed it.
func SanitizePolicyID(policyID string) string { return sanitizePathSegment(policyID) }

// UnsanitizePolicyID is SanitizePolicyID's inverse.
//
// It exists so that a compiled policy identifier can be read back to the
// ORIGINAL policy_id rather than to its encoded form. Carrying the encoded
// form outward would work but would put "sys__pii__ssn" in every operator-
// facing diff record for a row called "sys_pii_ssn", and a report whose
// identifiers do not match the database is a report people stop trusting.
//
// The second return value is false for a string the encoding cannot have
// produced - a trailing lone "_", or a "_...._" group that is not hex. That is
// reported rather than guessed, because a silent best-effort decode would
// invent a policy id.
func UnsanitizePolicyID(s string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(s); {
		c := s[i]
		if c != '_' {
			b.WriteByte(c)
			i++
			continue
		}
		if i+1 < len(s) && s[i+1] == '_' {
			b.WriteByte('_')
			i += 2
			continue
		}
		j := strings.IndexByte(s[i+1:], '_')
		if j < 0 {
			return "", false
		}
		hex := s[i+1 : i+1+j]
		if hex == "" {
			return "", false
		}
		r, err := strconv.ParseInt(hex, 16, 32)
		if err != nil {
			return "", false
		}
		b.WriteRune(rune(r))
		i += 1 + j + 1
	}
	return b.String(), true
}

// legacyScanDestinationsRuntime lists the columns the RUNTIME read path scans
// into a destination that cannot hold NULL, with the Go type it scans into.
//
// This is the #3397 model. `loadFromDatabase` scans positionally into a
// policyRow whose ID, PolicyID, Name, Category, Tier, Pattern, Severity and
// TenantID are `string`, Enabled is `bool`, Priority is `int`, Metadata is
// `json.RawMessage` and CreatedAt is `time.Time`. A NULL arriving in any of
// them fails the scan and the reader moves to the next row, logging once; the
// load still reports success, so the policy is simply not enforced.
// json.RawMessage belongs on the list: it is neither a pointer nor a Scanner,
// and database/sql takes a NULL only into *any, *[]byte, *sql.RawBytes, a
// pointer or a Scanner, so a NULL metadata (JSONB with no NOT NULL, core/010)
// fails the scan like the rest. The list missed it until #4078's
// guard read the reader instead of trusting a hand-kept list.
//
// `LoadSystemPolicies` scans the same shape MINUS created_at (16 destinations,
// not 17) and does not log at all. Modelling the union is the conservative
// direction for this list: a NULL created_at drops the row on the reader that
// selects it, and the compiler reports the drop for the whole
// runtime_phase_columns path rather than splitting one read path in two. The
// over-report is recorded here rather than left for a reader to discover.
var legacyScanDestinationsRuntime = []struct {
	Column string
	GoType string
}{
	{"id", "string"}, {"policy_id", "string"}, {"name", "string"},
	{"category", "string"}, {"tier", "string"}, {"pattern", "string"},
	{"severity", "string"}, {"enabled", "bool"}, {"priority", "int"},
	{"tenant_id", "string"}, {"metadata", "json.RawMessage"},
	{"created_at", "time.Time"},
}

// legacyScanDestinationsDynamic is the same model for the DYNAMIC substrate.
//
// #3397 is not a static-only defect and modelling it on one substrate of two
// would leave an undisclosed hole in this package's headline claim.
// RefreshDynamicPolicies (platform/shared/policy/loader.go) scans positionally
// into a DynamicPolicyRow and, on a scan error, logs and continues, exactly
// like its static sibling.
//
// Like the two static models, this lists every column the reader SELECTs
// WITHOUT a COALESCE and scans into a destination that cannot hold NULL: id,
// name, conditions, actions and policy_id (all NOT NULL, core/010) and
// priority (a default but no NOT NULL, core/010). dynamicScanDropColumns
// reports the ones whose NULL the capture can carry, which is priority alone.
//
// It used to list description and category, reasoning from the SCHEMA (both
// columns are nullable) and never from the QUERY, which COALESCEs both - and
// policy_type, risk_level and allow_override - in the SQL itself, so a NULL in
// any of them reaches the scan as a value and cannot fail it (#4078). That
// declared a loaded row enforced nowhere. TestScanDropModelsMatchTheLoaderQueries
// now derives all three models from the loader's queries and scans, and fails
// when a model and its reader part.
var legacyScanDestinationsDynamic = []struct {
	Column string
	GoType string
}{
	{"id", "string"}, {"name", "string"}, {"conditions", "string"},
	{"actions", "string"}, {"priority", "int"}, {"policy_id", "string"},
}

// dynamicScanDropColumns returns the columns whose NULL would fail the dynamic
// refresh's scan, in a stable order.
func dynamicScanDropColumns(row DynamicRow) []string {
	return nullScanDestinations(row.raw, legacyScanDestinationsDynamic)
}

// nullScanDestinations returns each modelled column the raw row carries as
// NULL or does not carry at all, as "column (type)", in a stable order. It is
// the one judge of a scan drop: the models are the list, and the row is the
// evidence, so a column a model gains is checked with no second list to keep.
func nullScanDestinations(raw RawRow, model []struct {
	Column string
	GoType string
}) []string {
	var out []string
	for _, d := range model {
		if raw.isNull(d.Column) || !raw.has(d.Column) {
			out = append(out, d.Column+" ("+d.GoType+")")
		}
	}
	sort.Strings(out)
	return out
}

// scanDropColumns returns the columns whose NULL would fail the legacy scan on
// the runtime read path, in a stable order.
func scanDropColumns(row StaticRow) []string {
	return nullScanDestinations(row.raw, legacyScanDestinationsRuntime)
}

// compileStatic compiles one static_policies row into a Record.
//
// Every exit from this function produces a Record. There is no branch that
// returns nothing, which is the whole point.
func compileStatic(raw RawRow, row StaticRow, opts Options) Record {
	rec := Record{
		Source: SourceRef{
			Table: raw.Table, OrgScope: raw.OrgScope, ID: row.ID,
			PolicyID: row.PolicyID, Name: row.Name, Version: row.Version, RowDigest: digestRow(raw),
		},
	}

	// The legacy readers' own WHERE clause. A row it excludes is a real row
	// that compiles to nothing, and saying so is what makes the count
	// reconcile against an unfiltered SELECT count(*).
	if row.EnabledNull || !row.Enabled {
		rec.Reasons = append(rec.Reasons, Reason{
			Code: ReasonExcludedByLegacyPredicate,
			Detail: "every static_policies reader filters `enabled = true`; this row is " +
				describeBool(row.Enabled, row.EnabledNull) + " and is loaded by nothing",
		})
	}
	if row.DeletedAt != "" {
		rec.Reasons = append(rec.Reasons, Reason{
			Code:   ReasonExcludedByLegacyPredicate,
			Detail: "loadFromDatabase and GetEffective both filter `deleted_at IS NULL`; this row is soft-deleted at " + row.DeletedAt,
		})
	}
	if len(rec.Reasons) > 0 {
		rec.Status = StatusUncompilable
		return rec
	}

	if _, err := regexp.Compile(row.Pattern); err != nil {
		// compilePolicy returns an error, and both callers `continue`. The row
		// vanishes and the load still reports success.
		rec.Status = StatusPreservedDefect
		rec.Reasons = append(rec.Reasons, Reason{
			Code: ReasonLegacyCompileDrop, Issue: "#3397",
			Detail: fmt.Sprintf("pattern %q does not compile (%v); compilePolicy errors and every caller skips the row without failing the load", row.Pattern, err),
		})
		return rec
	}

	for _, plane := range PlanesFor(SubstrateStatic) {
		spec := MustSpecFor(plane)
		pr := compileStaticForPlane(row, spec, opts)
		rec.Planes = append(rec.Planes, pr...)
	}

	// #3899: the tenant column, read and deliberately not translated. Emitted
	// at ROW level rather than per plane or per policy because it is a fact
	// about the row's column, and repeating it once per emitted policy would
	// make the proposal's reason counts describe the fan-out rather than the
	// input.
	if r := tenantColumnReason(row.TenantID, row.Tier, staticRootFor(row)); r != nil {
		rec.Reasons = append(rec.Reasons, *r)
	}
	rec.Reasons = append(rec.Reasons, Reason{
		Code: ReasonPatternNotTypedCondition,
		Detail: fmt.Sprintf("the content regex %q is carried as detector %q rather than a typed condition; "+
			"an unrun detector is UNKNOWN, where the legacy engine had no match", row.Pattern, DetectorSignalPath(row.PolicyID)),
	})

	rec.Status = statusFrom(rec)
	return rec
}

func describeBool(v, isNull bool) string {
	if isNull {
		return "NULL"
	}
	return strconv.FormatBool(v)
}

// compileStaticForPlane produces the per-plane results for one row. A plane
// evaluating two phases produces two results, because the row can resolve a
// different action in each and collapsing them would hide exactly that.
func compileStaticForPlane(row StaticRow, spec PlaneSpec, opts Options) []PlaneResult {
	var out []PlaneResult

	// Runtime phase-column path.
	rowPhase := row.Phase
	if row.PhaseNull || rowPhase == "" {
		// compilePolicy defaults a NULL phase to PhaseBoth.
		rowPhase = PhaseBoth
	}
	drops := scanDropColumns(row)

	for _, ph := range spec.Phases {
		if rowPhase != PhaseBoth && rowPhase != ph {
			// A phase the row does not carry produces a RESULT saying so, not
			// silence. PlaneResult's contract is "empty means the row
			// contributes nothing here, and Reasons says why", and a plane
			// that is simply absent from the record cannot carry a reason - so
			// a reader cannot tell "not applicable by phase" from "not
			// modelled".
			out = append(out, PlaneResult{
				Plane: spec.Plane, Phase: ph, ReadPath: spec.StaticReadPath,
				Reasons: []Reason{{
					Code: ReasonPhaseNotEvaluatedHere, Plane: spec.Plane,
					Detail: fmt.Sprintf("the row stores phase %q, so the %s phase this plane evaluates never reaches it", rowPhase, ph),
				}},
			})
			continue
		}
		pr := PlaneResult{Plane: spec.Plane, Phase: ph, ReadPath: spec.StaticReadPath,
			AttributePaths: []string{DetectorSignalPath(row.PolicyID)}}
		if len(drops) > 0 {
			pr.Reasons = append(pr.Reasons, Reason{
				Code: ReasonLegacyScanDrop, Issue: "#3397", Plane: spec.Plane,
				Detail: "NULL in non-nullable scan destination(s): " + strings.Join(drops, ", ") +
					" - the scan errors and the reader continues, so this row is silently unenforced while the load reports success",
			})
			out = append(out, pr)
			continue
		}

		stored, storedPresent := row.ActionRequest, !row.ActionRequestNull
		if ph == PhaseResponse {
			stored, storedPresent = row.ActionResponse, !row.ActionResponseNull
		}
		resolved := ResolveActionForPhase(row.Category, row.Severity, stored)
		if !storedPresent || stored == "" {
			pr.Reasons = append(pr.Reasons, Reason{
				Code: ReasonNoStoredActionForPhase, Issue: "#3563", Plane: spec.Plane,
				Detail: fmt.Sprintf("the %s-phase action column is %s, so GetActionForPhase resolves %q from category %q / severity %q; the row's own action column (%q) is read by nothing on this plane",
					ph, nullOrEmpty(storedPresent), resolved, row.Category, row.Severity, row.Action),
			})
		}
		pr.StoredAction = stored
		pr.ResolvedAction = string(resolved)

		enforced := resolved
		if arm := retiredTierPassArm(spec, row, resolved); arm != "" {
			// What /api/request's retired second pass read (#4253): the row's
			// STORED action column, which no surviving plane reads. PRD v11 §1 item
			// 1 evaluates every control that named that pass here, so where an arm
			// applies, the stored action, not the phase column, is what this plane
			// enforces. It is a stated divergence from the phase resolution, never
			// a silent one; an organization's category action below may still
			// displace it, as it may any resolved action.
			stored := LegacyAction(row.Action)
			pr.Reasons = append(pr.Reasons, Reason{
				Code: ReasonRetiredTierPassAction, Issue: "#4253", Plane: spec.Plane,
				Detail: fmt.Sprintf("%s: the %s-phase column resolves %q and the row's stored action column is %q; /api/request's retired second pass read the stored column, so this plane enforces %q",
					arm, ph, resolved, row.Action, stored),
			})
			enforced = stored
			// The retired pass RESOLVED the stored column, and the corpus collapses
			// an organization row by ranking each plane's resolution, so this
			// plane's resolution is the stored action, as the tier plane's was.
			// The phase column's resolution stays stated in the reason above.
			pr.ResolvedAction = string(stored)
		}
		if spec.PassesOrgOverrides {
			if displaced, did := opts.CategoryActions.Apply(row.Category, resolved); did {
				// What is displaced is what this plane would otherwise enforce:
				// the stored action where a retired-pass arm applied, the phase
				// resolution everywhere else.
				before := enforced
				enforced = displaced
				pr.Reasons = append(pr.Reasons, Reason{
					Code: ReasonOrgOverrideDisplaces, Issue: "#3961", Plane: spec.Plane,
					Detail: fmt.Sprintf("the action assigned to category %q displaces the enforced action %q with %q on this plane",
						row.Category, before, displaced),
				})
			}
		}
		if forced, does := spec.Forces(row.Category); does {
			// A plane-level coercion, not a posture. It applies whatever the
			// deployment is configured to do, which is the whole point of the
			// cowork storage plane: a warn or log deployment still masks
			// before it persists.
			if forced != enforced {
				pr.Reasons = append(pr.Reasons, Reason{
					Code: ReasonPlaneCoercesAction, Issue: "#3360", Plane: spec.Plane,
					Detail: fmt.Sprintf("this plane COERCES %q for category %q regardless of the deployment posture, replacing the resolved action %q",
						forced, row.Category, enforced),
				})
			}
			enforced = forced
		}

		// RECORDED AT THE ONE SITE WHERE `enforced` IS FINALLY KNOWN - after the
		// category action above and after the plane coercion above it, and on the
		// same value handed to policyFor. Setting it anywhere earlier would
		// publish an action the compiled policy does not carry.
		pr.EnforcedAction = string(enforced)

		pol, reasons := policyFor(row, spec, ph, enforced, opts)
		pr.Reasons = append(pr.Reasons, reasons...)
		if pol != nil {
			pr.Policies = append(pr.Policies, *pol)
		}
		out = append(out, pr)
	}
	return out
}

func nullOrEmpty(present bool) string {
	if present {
		return "an empty string"
	}
	return "NULL"
}

// policyFor maps one resolved legacy action to one ADR-065 typed policy.
//
// The mapping is the substance of the migration, so each arm says what it
// claims. ADR-065 is explicit that there is no action ranking such as
// block > redact > warn > log: redaction, logging, warning and approval are
// different obligations, not points on one scale. That is why block becomes a
// constraint and everything else becomes a requirement or an inspection,
// rather than all of them becoming one policy with a severity field.
func policyFor(row StaticRow, spec PlaneSpec, ph Phase, act LegacyAction, opts Options) (*pdp.Policy, []Reason) {
	if !isKnownAction(act) {
		return nil, unknownActionReasons(spec.Plane, act)
	}

	id := PolicyIDFor("static_policies", row.PolicyID, spec.Plane, ph)
	root := staticRootFor(row)
	scope := pdp.Scope{Organization: true}
	if !row.SegmentIDNull && row.SegmentID != "" {
		// ADR-060 segment targeting becomes group scope, which is the
		// ADR-065 equivalent: membership resolved through principal.groups,
		// participating in three-valued logic, so an unresolvable closure
		// makes a segment-scoped constraint UNKNOWN rather than silently
		// inapplicable - which is what AppliesToSegments' nil-callerSegments
		// arm did.
		gid, err := contract.ParseID(contract.KindGroup, opts.GroupIDFor(row.SegmentID))
		if err != nil {
			return nil, []Reason{{
				Code: ReasonNoActionableOutcome, Plane: spec.Plane,
				Detail: fmt.Sprintf("segment_id %q does not render a canonical group id: %v", row.SegmentID, err),
			}}
		}
		scope = pdp.Scope{Groups: []contract.ID{gid}}
	}

	where := pdp.Compare(DetectorSignalPath(row.PolicyID), pdp.OpEq, true)
	base := pdp.Policy{
		ID: id, Root: root, Scope: scope,
		Actions: pdp.ActionSelector{Any: true},
		Where:   where,
		Description: fmt.Sprintf("compiled from static_policies %s (category %s, severity %s, pattern %q) for plane %s",
			row.PolicyID, row.Category, row.Severity, row.Pattern, spec.Plane),
	}

	if act == ActionRequireApproval {
		pool, ok := opts.ApprovalPool(row.OrgID, row.TenantID)
		if !ok {
			return nil, []Reason{{
				Code: ReasonApprovalPoolNotStored, Plane: spec.Plane,
				Detail: "require_approval resolves for this row, but ADR-065's approval obligation needs an eligible pool and a quorum and static_policies stores neither; " +
					"supply Options.ApprovalPools for this org to compile it",
			}}
		}
		return ApprovalPolicy(base, pool), nil
	}
	return ActionPolicy(base, act, row.Category, row.Severity, opts.ContentTarget, spec.Plane)
}

// unknownActionReasons is the refusal of an action outside KnownActions.
func unknownActionReasons(plane Plane, act LegacyAction) []Reason {
	return []Reason{{
		Code: ReasonUnknownLegacyAction, Plane: plane,
		Detail: fmt.Sprintf("action %q is outside the set the legacy engines understand (%v); it is not coerced to a neighbour", act, KnownActions()),
	}}
}

// ActionPolicy shapes base - a policy whose id, root, scope, action selector
// and condition are already set - into the control one legacy action means.
//
// IT IS THE ONE ACTION MAPPING. policyFor applies it to the action a static row
// resolves to, and an organization's recorded detection override applies it to
// the control the override displaces (#4045), so one action cannot compile to
// two shapes depending on which of the two asked. category and severity are the
// censused row's, carried into the obligations that record them, and
// contentTarget is the field path a redaction targets.
//
// require_approval is not mapped here: its obligation needs an approval pool,
// which each caller resolves for itself, and no override can record one. It is
// ApprovalPolicy's.
func ActionPolicy(base pdp.Policy, act LegacyAction, category, severity, contentTarget string, plane Plane) (*pdp.Policy, []Reason) {
	if !isKnownAction(act) {
		return nil, unknownActionReasons(plane, act)
	}
	var reasons []Reason
	id := base.ID
	switch act {
	case ActionBlock, ActionDeny:
		base.Authority = contract.AuthorityConstraint
		return &base, reasons

	case ActionRedact:
		base.Authority = contract.AuthorityRequirement
		base.Mandatory = true
		base.Obligations = []contract.Obligation{{
			Type:          contract.ObFieldRedact,
			Target:        contentTarget,
			Mandatory:     true,
			SourcePolicy:  id,
			SchemaVersion: 1,
		}}
		reasons = append(reasons, Reason{
			Code: ReasonRedactTargetNotStored, Plane: plane,
			Detail: fmt.Sprintf("static_policies stores no field path for a redaction - the target was the span the detector matched at runtime - so the obligation targets the plane's content root %q", contentTarget),
		})
		return &base, reasons

	case ActionWarn:
		base.Authority = contract.AuthorityRequirement
		base.Obligations = []contract.Obligation{{
			Type:          contract.ObNotification,
			Params:        map[string]string{"severity": severity, "category": category},
			SourcePolicy:  id,
			SchemaVersion: 1,
		}}
		return &base, reasons

	case ActionLog, ActionLogOnly:
		base.Authority = contract.AuthorityRequirement
		base.Obligations = []contract.Obligation{{
			Type:          contract.ObImmutableAudit,
			Params:        map[string]string{"category": category, "severity": severity},
			SourcePolicy:  id,
			SchemaVersion: 1,
		}}
		return &base, reasons

	case ActionAllow:
		// A legacy `allow` on a MATCHED detector means the match does nothing.
		// It is emphatically NOT an ADR-065 permission: a detector cannot
		// attest that a request is legitimate, only that something was seen.
		// It compiles to an inspection policy that records the observation and
		// grants nothing, which is what the ADR reserves inspection for.
		base.Authority = contract.AuthorityInspection
		base.Obligations = []contract.Obligation{{
			Type:          contract.ObImmutableAudit,
			Params:        map[string]string{"category": category, "observed": "allow"},
			SourcePolicy:  id,
			SchemaVersion: 1,
		}}
		return &base, reasons
	}
	return nil, []Reason{{
		Code: ReasonNoActionableOutcome, Plane: plane,
		Detail: fmt.Sprintf("action %q has no mapping arm here; require_approval is compiled by ApprovalPolicy, over a pool its caller resolves", act),
	}}
}

// ApprovalPolicy shapes base - a policy whose id, root, scope, action selector
// and condition are already set - into the control require_approval means: a
// mandatory requirement carrying one approval_challenge that names pool's quorum
// and eligible set, attributed to base.ID.
//
// IT IS THE ONE APPROVAL MAPPING, as ActionPolicy is the one mapping of every
// other action. policyFor applies it to a static row, dynamicPolicyFor to a
// dynamic action and a policy pack (platform/decision/policypack) to a pack
// detector, so require_approval cannot compile to two shapes depending on which
// source asked.
//
// It takes an ALREADY-RESOLVED pool. Where the pool comes from differs by caller
// - Options.ApprovalPool per row for the two substrates, the deployment's realms
// for a pack - and so does the refusal when there is none
// (ReasonApprovalPoolNotStored carries a different detail per substrate), which
// is why the refusal stays at each call site.
//
// The obligation's SourcePolicy is base.ID rather than an argument, so it cannot
// be attributed to a policy other than the one it is attached to.
// TestApprovalPolicyIsTheOneMappingForBothSubstrates pins both halves: every
// source's approval control is this shape, and this is the only place an
// approval_challenge is constructed.
func ApprovalPolicy(base pdp.Policy, pool ApprovalPool) *pdp.Policy {
	base.Authority = contract.AuthorityRequirement
	base.Mandatory = true
	base.Obligations = []contract.Obligation{{
		Type:          contract.ObApprovalChallenge,
		Params:        map[string]string{"quorum": strconv.Itoa(pool.Quorum), "eligible": strings.Join(pool.Eligible, ",")},
		Mandatory:     true,
		SourcePolicy:  base.ID,
		SchemaVersion: 1,
	}}
	return &base
}

// The two arms of PlaneSpec.EnforcesRetiredTierPassRead, as the reason names them.
const (
	retiredTierPassSystemBlock    = "system stored block"
	retiredTierPassTemplateAction = "template stored action outranks the phase resolution"
)

// retiredTierPassArm names the arm of PlaneSpec.EnforcesRetiredTierPassRead that
// applies to a row whose phase column resolved `resolved` on a plane, or "" when
// none does (#4253).
//
// The asymmetry is the corpus's, not this rule's. A system row compiles to one
// policy PER SCOPE (#4046), so the retired pass's read of a system row was its
// own proxy_tier-only variant: the stored block it refused on is kept, and a
// lesser read leaves the corpus with the plane. A non-system row - the
// organization template in the shipped corpus, an organization's own row in the
// legacy import - compiles to ONE policy, its most restrictive plane compilation
// (corpusRestrictiveness), and until #4253 that was the retired pass's read of
// its stored column wherever the read outranked the phase resolution. So for such
// a row the stored action is kept wherever it outranks, ranked as the corpus
// ranks it - save a stored hold (require_approval), whose successor is the
// orchestrator's typed approval challenge (#4254), not a refusal here.
func retiredTierPassArm(spec PlaneSpec, row StaticRow, resolved LegacyAction) string {
	if !spec.EnforcesRetiredTierPassRead {
		return ""
	}
	stored := LegacyAction(row.Action)
	if row.Tier == "system" {
		if stored == ActionBlock && resolved != ActionBlock {
			return retiredTierPassSystemBlock
		}
		return ""
	}
	if stored == ActionRequireApproval {
		// A stored hold is not kept. The route's hold exit retired with the pass
		// (#4253), and holds return with the orchestrator's typed approval
		// challenge (#4254); keeping one here would make /api/request REFUSE what
		// the pass held.
		return ""
	}
	storedRank, _, storedOK := corpusRestrictiveness(string(stored))
	resolvedRank, _, resolvedOK := corpusRestrictiveness(string(resolved))
	if storedOK && resolvedOK && storedRank > resolvedRank {
		return retiredTierPassTemplateAction
	}
	return ""
}

// statusFrom derives the row status from what the compilation produced. It is
// derived rather than assigned at each site so that a new reason code cannot
// be added without landing in exactly one of the three buckets.
//
// A preserved defect OUTRANKS a zero policy count, and the ordering is the
// whole point. A row the legacy scan drops (#3397) compiles to nothing on the
// planes that drop it - but calling that "uncompilable" would file it beside a
// row the compiler could not handle, and lose the fact that matters: this row
// exists, an operator believes it is enforced, and production silently is not
// enforcing it. `uncompilable` means the COMPILER could not express the row;
// `preserved_defect` means the row was reproduced faithfully, defect included.
func statusFrom(rec Record) Status {
	// A COMPILER GAP outranks everything when nothing was emitted. A row can
	// carry a preserved defect AND fail to compile because the typed language
	// has no equivalent for one of its operators; filing that as
	// preserved_defect would report the row as faithfully reproduced when in
	// fact this package could not express it, and would leave
	// CountsByStatus reporting uncompilable=0 while the migration backlog is
	// non-empty.
	if rec.PolicyCount() == 0 {
		for _, rs := range rec.Reasons {
			if IsCompilerGapReason(rs.Code) {
				return StatusUncompilable
			}
		}
		for _, pr := range rec.Planes {
			for _, rs := range pr.Reasons {
				if IsCompilerGapReason(rs.Code) {
					return StatusUncompilable
				}
			}
		}
	}
	for _, c := range DefectReasonCodes() {
		if rec.HasReason(c) {
			return StatusPreservedDefect
		}
	}
	if rec.PolicyCount() == 0 {
		return StatusUncompilable
	}
	return StatusCompiled
}

// staticRootFor is the ONE derivation of a static row's authority root.
//
// It was inline in policyFor until #3899 needed the same answer at row level to
// decide whether a tenant column is worth reporting. Two copies of "is this
// row the platform's own" would be two chances to disagree about it, and the
// disagreement would be invisible: the reason would describe a row the
// compiled policy had classified the other way.
func staticRootFor(row StaticRow) pdp.Root {
	if row.Tier == "system" || row.TenantID == "global" {
		return pdp.RootSystem
	}
	return pdp.RootOrganization
}
