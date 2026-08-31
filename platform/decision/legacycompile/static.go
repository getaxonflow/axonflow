package legacycompile

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
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
func DetectorSignalPath(policyID string) string {
	return "signal.detector." + sanitizePathSegment(policyID)
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
func sanitizePathSegment(in string) string {
	var b strings.Builder
	for _, r := range in {
		switch {
		case r == '_':
			b.WriteString("__")
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
		default:
			b.WriteString("_" + strconv.FormatInt(int64(r), 16) + "_")
		}
	}
	return b.String()
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
// TenantID are `string`, Enabled is `bool`, Priority is `int` and CreatedAt is
// `time.Time`. A NULL arriving in any of them fails the scan and the reader
// moves to the next row, logging once; the load still reports success, so the
// policy is simply not enforced.
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
	{"tenant_id", "string"}, {"created_at", "time.Time"},
}

// legacyScanDestinationsEffective lists the same for the EFFECTIVE read path.
//
// EffectivePolicyRow (loader.go) makes Description, OrgID, SegmentID, Tags,
// Metadata, CreatedBy and UpdatedBy nullable, and keeps Action, Tier, Priority,
// Enabled, TenantID, Version, CreatedAt and UpdatedAt non-nullable.
//
// The two TIMESTAMP columns are easy to miss and they matter: both are
// `time.Time`, not `sql.NullTime`, and both are `DEFAULT NOW()` without NOT
// NULL in migrations/core/010, so a NULL in either fails the scan and
// ScanEffectivePolicyRows logs-and-continues. Omitting them made the compiler
// emit an ADR-065 constraint on the proxy tier for a row GetEffective never
// returns - a deny with no legacy counterpart, on the one plane the operator is
// least likely to check.
var legacyScanDestinationsEffective = []struct {
	Column string
	GoType string
}{
	{"id", "string"}, {"policy_id", "string"}, {"name", "string"},
	{"category", "string"}, {"pattern", "string"}, {"severity", "string"},
	{"action", "string"}, {"tier", "string"}, {"priority", "int"},
	{"enabled", "bool"}, {"tenant_id", "string"}, {"version", "int"},
	{"created_at", "time.Time"}, {"updated_at", "time.Time"},
}

// legacyScanDestinationsDynamic is the same model for the DYNAMIC substrate.
//
// #3397 is not a static-only defect and modelling it on one substrate of two
// would leave an undisclosed hole in this package's headline claim.
// RefreshDynamicPolicies (platform/shared/policy/loader.go) scans positionally
// into a DynamicPolicyRow whose Name, Description, Conditions, Actions,
// PolicyID, PolicyType, Category and RiskLevel are `string`, Priority is `int`
// and AllowOverride is `bool` - and on a scan error it logs and continues,
// exactly like its static sibling.
//
// Three of those destinations take a NULLable column: description (TEXT, no
// NOT NULL, core/010), priority (DEFAULT 50, core/030) and category
// (VARCHAR(50), core/030). TenantID, OrgID, SegmentID and CreatedAt are
// nullable TYPES and cannot drop the row.
var legacyScanDestinationsDynamic = []struct {
	Column string
	GoType string
}{
	{"description", "string"}, {"priority", "int"}, {"category", "string"},
}

// dynamicScanDropColumns returns the columns whose NULL would fail the dynamic
// refresh's scan, in a stable order.
func dynamicScanDropColumns(row DynamicRow) []string {
	nulls := map[string]bool{
		"description": row.DescriptionNull,
		"priority":    row.PriorityNull,
		"category":    row.CategoryNull,
	}
	var out []string
	for _, d := range legacyScanDestinationsDynamic {
		if nulls[d.Column] {
			out = append(out, d.Column+" ("+d.GoType+")")
		}
	}
	sort.Strings(out)
	return out
}

// scanDropColumns returns the columns whose NULL would fail the legacy scan on
// a read path, in a stable order.
func scanDropColumns(row StaticRow, path ReadPath) []string {
	dest := legacyScanDestinationsRuntime
	if path == ReadPathEffectiveAction {
		dest = legacyScanDestinationsEffective
	}
	nulls := map[string]bool{
		"tier": row.TierNull, "tenant_id": row.TenantIDNull,
		"priority": row.PriorityNull, "enabled": row.EnabledNull,
		"created_at": row.CreatedAtNull, "updated_at": row.UpdatedAtNull,
		"version": row.VersionNull, "action": row.ActionNull,
	}
	var out []string
	for _, d := range dest {
		if nulls[d.Column] {
			out = append(out, d.Column+" ("+d.GoType+")")
		}
	}
	sort.Strings(out)
	return out
}

// compileStatic compiles one static_policies row into a Record.
//
// Every exit from this function produces a Record. There is no branch that
// returns nothing, which is the whole point.
func compileStatic(raw RawRow, row StaticRow, opts Options) Record {
	rec := Record{
		Source: SourceRef{
			Table: raw.Table, OrgScope: raw.OrgScope, ID: row.ID,
			PolicyID: row.PolicyID, Version: row.Version, RowDigest: digestRow(raw),
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

	// The central migration finding: do the two read paths agree? This is a
	// ROW-level fact, computed across planes rather than inside one, because
	// no single plane can see it.
	if d := readPathDivergence(rec.Planes); d != "" {
		rec.Reasons = append(rec.Reasons, Reason{
			Code: ReasonReadPathActionDivergence, Issue: "#3563", Detail: d,
		})
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

	if spec.StaticReadPath == ReadPathEffectiveAction {
		// The effective read path evaluates exactly one phase (the tier engine
		// runs on the request), so its one result carries that phase.
		pr := PlaneResult{Plane: spec.Plane, Phase: spec.Phases[0], ReadPath: spec.StaticReadPath,
			AttributePaths: []string{DetectorSignalPath(row.PolicyID)}}
		if drops := scanDropColumns(row, spec.StaticReadPath); len(drops) > 0 {
			pr.Reasons = append(pr.Reasons, Reason{
				Code: ReasonLegacyScanDrop, Issue: "#3397", Plane: spec.Plane,
				Detail: "NULL in non-nullable scan destination(s): " + strings.Join(drops, ", ") +
					" - GetEffective's scan errors and the row is not enforced on this plane",
			})
			out = append(out, pr)
			return out
		}
		pr.StoredAction = row.Action
		pr.ResolvedAction = string(LegacyAction(row.Action))
		// The tier engine reads the action column verbatim. No phase
		// resolution, no category fallback, and no posture lever: it never
		// sees EvalOptions.ActionOverrides.
		pol, reasons := policyFor(row, spec, "", LegacyAction(row.Action), opts)
		pr.Reasons = append(pr.Reasons, reasons...)
		if pol != nil {
			pr.Policies = append(pr.Policies, *pol)
		}
		out = append(out, pr)
		return out
	}

	// Runtime phase-column path.
	rowPhase := row.Phase
	if row.PhaseNull || rowPhase == "" {
		// compilePolicy defaults a NULL phase to PhaseBoth.
		rowPhase = PhaseBoth
	}
	drops := scanDropColumns(row, spec.StaticReadPath)

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
		if spec.PostureLever {
			if displaced, did := opts.Posture.Apply(row.Category, resolved); did {
				enforced = displaced
				pr.Reasons = append(pr.Reasons, Reason{
					Code: ReasonPostureLeverDisplaces, Issue: "#3360", Plane: spec.Plane,
					Detail: fmt.Sprintf("%s displaces the resolved action %q with %q on this plane",
						PostureLeverFor(row.Category), resolved, displaced),
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
					Code: ReasonPostureLeverDisplaces, Issue: "#3360", Plane: spec.Plane,
					Detail: fmt.Sprintf("this plane COERCES %q for category %q regardless of the deployment posture, replacing the resolved action %q",
						forced, row.Category, enforced),
				})
			}
			enforced = forced
		}

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
	var reasons []Reason
	if !isKnownAction(act) {
		return nil, []Reason{{
			Code: ReasonUnknownLegacyAction, Plane: spec.Plane,
			Detail: fmt.Sprintf("action %q is outside the set the legacy engines understand (%v); it is not coerced to a neighbour", act, KnownActions()),
		}}
	}

	id := PolicyIDFor("static_policies", row.PolicyID, spec.Plane, ph)
	root := pdp.RootOrganization
	if row.Tier == "system" || row.TenantID == "global" {
		root = pdp.RootSystem
	}
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

	switch act {
	case ActionBlock, ActionDeny:
		base.Authority = contract.AuthorityConstraint
		return &base, reasons

	case ActionRequireApproval:
		pool, ok := opts.ApprovalPool(row.OrgID, row.TenantID)
		if !ok {
			return nil, []Reason{{
				Code: ReasonApprovalPoolNotStored, Plane: spec.Plane,
				Detail: "require_approval resolves for this row, but ADR-065's approval obligation needs an eligible pool and a quorum and static_policies stores neither; " +
					"supply Options.ApprovalPools for this org to compile it",
			}}
		}
		base.Authority = contract.AuthorityRequirement
		base.Mandatory = true
		base.Obligations = []contract.Obligation{{
			Type:          contract.ObApprovalChallenge,
			Params:        map[string]string{"quorum": strconv.Itoa(pool.Quorum), "eligible": strings.Join(pool.Eligible, ",")},
			Mandatory:     true,
			SourcePolicy:  id,
			SchemaVersion: 1,
		}}
		return &base, reasons

	case ActionRedact:
		base.Authority = contract.AuthorityRequirement
		base.Mandatory = true
		base.Obligations = []contract.Obligation{{
			Type:          contract.ObFieldRedact,
			Target:        opts.ContentTarget,
			Mandatory:     true,
			SourcePolicy:  id,
			SchemaVersion: 1,
		}}
		reasons = append(reasons, Reason{
			Code: ReasonRedactTargetNotStored, Plane: spec.Plane,
			Detail: fmt.Sprintf("static_policies stores no field path for a redaction - the target was the span the detector matched at runtime - so the obligation targets the plane's content root %q", opts.ContentTarget),
		})
		return &base, reasons

	case ActionWarn:
		base.Authority = contract.AuthorityRequirement
		base.Obligations = []contract.Obligation{{
			Type:          contract.ObNotification,
			Params:        map[string]string{"severity": row.Severity, "category": row.Category},
			SourcePolicy:  id,
			SchemaVersion: 1,
		}}
		return &base, reasons

	case ActionLog, ActionLogOnly:
		base.Authority = contract.AuthorityRequirement
		base.Obligations = []contract.Obligation{{
			Type:          contract.ObImmutableAudit,
			Params:        map[string]string{"category": row.Category, "severity": row.Severity},
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
			Params:        map[string]string{"category": row.Category, "observed": "allow"},
			SourcePolicy:  id,
			SchemaVersion: 1,
		}}
		return &base, reasons
	}
	return nil, []Reason{{
		Code: ReasonNoActionableOutcome, Plane: spec.Plane,
		Detail: fmt.Sprintf("action %q has no mapping arm", act),
	}}
}

// readPathDivergence renders the disagreement between the two read paths, or
// "" when they agree.
func readPathDivergence(planes []PlaneResult) string {
	runtime := map[string]bool{}
	effective := map[string]bool{}
	for _, p := range planes {
		switch p.ReadPath {
		case ReadPathRuntimePhase:
			if p.ResolvedAction != "" {
				runtime[p.ResolvedAction] = true
			}
		case ReadPathEffectiveAction:
			if p.ResolvedAction != "" {
				effective[p.ResolvedAction] = true
			}
		}
	}
	if len(runtime) == 0 && len(effective) == 0 {
		// Neither path resolves anything: the row is unenforced everywhere and
		// there is no divergence to report.
		return ""
	}
	if len(runtime) == 0 || len(effective) == 0 {
		// One side resolves and the other does not. Reading that as agreement
		// is how the package's central finding fails closed to SILENCE: a row
		// with a NULL version or updated_at scan-drops on the effective path
		// while every runtime plane still enforces it, so it does nothing on
		// the proxy tier and acts everywhere else - which is the most
		// divergent a row can be.
		return fmt.Sprintf(
			"the runtime read path (phase columns) resolves %v and the effective read path (action column) resolves %v; "+
				"one path enforces this row and the other does not reach it at all",
			sortedKeys(runtime), sortedKeys(effective))
	}
	same := true
	for a := range runtime {
		if !effective[a] {
			same = false
			break
		}
	}
	if same && len(runtime) == len(effective) {
		return ""
	}
	return fmt.Sprintf(
		"the runtime read path (phase columns) resolves %v and the effective read path (action column) resolves %v; "+
			"what this row does depends on which plane asked, which is the split ADR-065 Phase 5 removes",
		sortedKeys(runtime), sortedKeys(effective))
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
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
