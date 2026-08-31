package legacycompile

import (
	"fmt"
	"sort"
	"strings"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// ApprovalPool is the eligible approver set and quorum for one org. Legacy
// policy rows store neither, so it is supplied to the compiler rather than
// invented by it.
type ApprovalPool struct {
	Quorum   int
	Eligible []string
}

// Options configure a compilation run.
type Options struct {
	// Posture is the deployment detection posture in force. An empty Posture
	// means no lever is configured, which is NOT the same as a lever set to
	// the stored action.
	Posture Posture
	// ApprovalPools maps an org id (or tenant id, or "*") to the approver pool
	// a require_approval row compiles against. Absent means such a row is
	// uncompilable, and saying so is the point.
	ApprovalPools map[string]ApprovalPool
	// ContentTarget is the field path a legacy static redaction targets. The
	// legacy row stores none.
	ContentTarget string
	// FieldPaths overrides the legacy-field to ADR-065-attribute-path mapping.
	FieldPaths map[string]string
	// Realm qualifies the canonical group identifiers an ADR-060 segment
	// compiles into. A legacy segment_id is a scim_groups.id scoped under
	// org_id and carries no realm, while an ADR-065 group identifier is
	// (realm, local) - so the realm has to come from configuration. It is NOT
	// defaulted silently to something that looks plausible: two orgs whose
	// segments collide across realms would then compile to one identifier.
	Realm string
}

// DefaultRealm is the realm compiled segment groups are qualified with when
// Options.Realm is empty. It names the migration explicitly rather than
// borrowing a production realm name.
const DefaultRealm = "legacy_segment"

// DefaultContentTarget is the field path a legacy static redaction targets
// when the caller names none. static_policies stores no field path - the
// target was whatever span the detector matched at runtime - so it has to come
// from configuration, and BOTH sides of the shadow diff must be given the same
// one.
const DefaultContentTarget = "response.content"

func (o Options) withDefaults() Options {
	if o.ContentTarget == "" {
		o.ContentTarget = DefaultContentTarget
	}
	if o.Realm == "" {
		o.Realm = DefaultRealm
	}
	return o
}

// GroupIDFor renders the canonical group identifier for an ADR-060 segment.
func (o Options) GroupIDFor(segmentID string) string {
	realm := o.Realm
	if realm == "" {
		realm = DefaultRealm
	}
	return "Group::" + realm + ":" + segmentID
}

// ApprovalPool resolves the approver pool for an org, falling back to the
// tenant key and then to the "*" default.
func (o Options) ApprovalPool(orgID, tenantID string) (ApprovalPool, bool) {
	for _, k := range []string{orgID, tenantID, "*"} {
		if k == "" {
			continue
		}
		if p, ok := o.ApprovalPools[k]; ok && p.Quorum > 0 && len(p.Eligible) > 0 {
			return p, true
		}
	}
	return ApprovalPool{}, false
}

// defaultFieldPaths maps each legacy dynamic-policy condition field onto an
// ADR-065 attribute path.
//
// The namespace is the interesting part, and it is not cosmetic: ADR-065
// declares which provenance classes may populate each namespace and forbids an
// untrusted namespace from establishing authority. `query`, `request_type` and
// the whole `context.*` family arrive in the request BODY, so they belong in
// `args`, the untrusted namespace - which is the correct home and also the
// reason #3152 existed, when `user.role` was read straight off the body and a
// caller could assert `{"user":{"role":"admin"}}` past a HIPAA template. The
// user.* fields map into `principal` because #3152 bound them to
// authentication-derived headers; mapping them anywhere else would restate the
// vulnerability in the new model.
var defaultFieldPaths = map[string]string{
	"query":            "args.query",
	"request_type":     "args.request_type",
	"request_id":       "args.request_id",
	"user.id":          "principal.id",
	"user_id":          "principal.id",
	"user.email":       "principal.email",
	"user_email":       "principal.email",
	"user.role":        "principal.role",
	"user_role":        "principal.role",
	"user.region":      "principal.region",
	"user_region":      "principal.region",
	"region":           "principal.region",
	"user.tenant_id":   "principal.tenant_id",
	"client.id":        "agent.id",
	"client_id":        "agent.id",
	"agent_id":         "agent.id",
	"client.org_id":    "agent.org_id",
	"org_id":           "agent.org_id",
	"client.tenant_id": "agent.tenant_id",
	"tenant_id":        "agent.tenant_id",
	"environment":      "env.environment",
	"env":              "env.environment",
	"risk_score":       "signal.risk_score",
	"cost_estimate":    "signal.cost_estimate",
}

// AttributePathFor maps a legacy condition field onto an ADR-065 attribute
// path.
func (o Options) AttributePathFor(field string) string {
	if p, ok := o.FieldPaths[field]; ok {
		return p
	}
	if p, ok := defaultFieldPaths[field]; ok {
		return p
	}
	if rest, ok := strings.CutPrefix(field, "media."); ok {
		return "signal.media." + sanitizePathSegment(rest)
	}
	if rest, ok := strings.CutPrefix(field, "context."); ok {
		return "args.context." + sanitizePathSegment(rest)
	}
	// A field with no explicit mapping resolves through getFieldValue's
	// default arm: a DIRECT req.Context[field] lookup, keyed by the FULL field
	// name. That is the same map the spelling "context.<field>" reads after
	// its prefix is stripped, so the two spellings of one context key must
	// compile to ONE path - "connector" and "context.connector" both read
	// req.Context["connector"] in production, and giving them two attribute
	// paths would let the two compile into policies that can disagree about a
	// single stored value. The args namespace is also the correct trust home:
	// caller-forwarded context is the untrusted surface, and a compiled policy
	// over it can never establish authority.
	return "args.context." + sanitizePathSegment(field)
}

// digestRow returns a content digest over a captured row's columns, so a later
// capture can prove a row did or did not change.
func digestRow(raw RawRow) string {
	d, err := contract.Digest(map[string]any{
		"table": raw.Table, "org_scope": raw.OrgScope, "columns": raw.Columns,
	})
	if err != nil {
		return "sha256:undigestible"
	}
	return d
}

// knownLimitations are population-wide gaps recorded once per report. They are
// facts about the legacy substrate that are true of every row of a class, so
// repeating them per row would drown the per-row signal without adding
// information - but omitting them entirely would leave the migration report
// claiming a completeness it does not have.
func knownLimitations() []Limitation {
	return []Limitation{
		{
			Issue: "#3401", Scope: "action_override and enabled_override on every dynamic_policies row",
			Detail: "an override's ACTION is never resolved for a dynamic policy: EffectiveOverride has one production call site and it builds an " +
				"EffectiveStaticPolicy, so action_override and enabled_override are inert on the dynamic planes. " +
				"The ADR-044 break-glass allow-flip is a DIFFERENT mechanism and it IS enforced there - FindActiveOverride carries no policy_type " +
				"predicate and ApplyOverrideToResult flips a deny to allow for any row with an active session override. " +
				"Neither mechanism is captured or modelled here, so a shadow run says nothing about a request an operator has broken glass on.",
		},
		{
			Issue: "#3515", Scope: "the policy editor's Priority helper text",
			Detail: "the dialog says \"Lower = higher priority\" while every ENFORCEMENT consumer sorts priority DESC. " +
				"The orderings are not uniform beyond that: the static loader breaks ties on created_at ASC and the dynamic reads on created_at DESC, " +
				"GetEffective orders tier ASC before priority, and two admin LIST surfaces sort priority ASC. " +
				"None of it changes a compiled output, but a captured corpus may contain rows an operator ranked backwards.",
		},
		{
			Issue: "#3399", Scope: "every dynamic evaluation result",
			Detail: "PolicyEvaluationResult.DatabaseAccessed is hardcoded true, including when the engine is serving built-in fallback defaults. " +
				"A shadow corpus captured from a defaults-mode deployment cannot be told apart from a database-backed one by that field.",
		},
		{
			Issue: "#3398", Scope: "the dynamic engine's cache_age_seconds gauge",
			Detail: "0 means both \"just loaded\" and \"never loaded\", so freshness of the captured policy set cannot be established from that metric alone.",
		},
		{
			Issue: "#3563", Scope: "static_policies rows on planes with no posture lever entry",
			Detail: "categories outside " + strings.Join(PostureLeverCategories(), ", ") +
				" have no lever, so their resolved action is the stored one on every plane. " +
				"HighRiskAction and DangerousQueryAction are populated from the environment and read by no ENFORCEMENT path " +
				"(both reach the profile banner, and DangerousQueryAction is a ModeDetectionConfig field, but neither is mapped into an override).",
		},
	}
}

// Compile turns captured legacy rows into a Report.
//
// The invariant: len(report.Records) == len(rows), always, with no exception
// for a row that fails to decode, fails to compile, or would have been dropped
// by the legacy reader. That is asserted at the end of this function rather
// than left to the reader's confidence, because "the compiler cannot drop a
// row" is precisely the claim a reader has no way to check.
func Compile(rows []RawRow, opts Options) (*Report, error) {
	opts = opts.withDefaults()
	rep := &Report{InputRows: len(rows), KnownLimitations: knownLimitations()}
	// Duplicate detection is a REAL check, not bookkeeping. row.go's contract
	// allows the same physical row to be captured once per org scope, and two
	// records for one (table, policy_id, org_scope) would compile two policies
	// with the SAME identifier - which pdp rejects as DUPLICATE_POLICY_ID at
	// world construction, i.e. late, loudly and without naming the capture as
	// the cause. An earlier version counted these into a map and never read it.
	seen := map[string]int{}
	for _, raw := range rows {
		rec := compileOne(raw, opts)
		// Only rows that HAVE an identity are checked. A capture error or a
		// capture missing the policy_id column produces a record with an empty
		// id, and two such records are two unidentifiable rows rather than one
		// row captured twice - reporting them as duplicates would refuse the
		// whole compilation for a reason that is not true.
		if rec.Source.PolicyID != "" {
			seen[rec.Source.Table+"|"+rec.Source.PolicyID+"|"+rec.Source.OrgScope]++
		}
		rep.Records = append(rep.Records, rec)
	}
	var dups []string
	for k, n := range seen {
		if n > 1 {
			dups = append(dups, fmt.Sprintf("%s appears %d times", k, n))
		}
	}
	if len(dups) > 0 {
		sort.Strings(dups)
		return nil, fmt.Errorf(
			"legacycompile: the capture contains duplicate rows, which compile to duplicate policy identifiers: %s",
			strings.Join(dups, "; "))
	}

	if len(rep.Records) != rep.InputRows {
		return nil, fmt.Errorf(
			"legacycompile: produced %d records for %d rows; the one-record-per-row invariant is the #3397 defect class and it must never be broken silently",
			len(rep.Records), rep.InputRows)
	}
	return rep, nil
}

func compileOne(raw RawRow, opts Options) Record {
	base := Record{Source: SourceRef{
		Table: raw.Table, OrgScope: raw.OrgScope,
		ID: raw.stringOr("id", ""), PolicyID: raw.stringOr("policy_id", ""),
		RowDigest: digestRow(raw),
	}}

	if raw.CaptureError != "" {
		base.Status = StatusUncompilable
		base.Reasons = []Reason{{Code: ReasonCaptureError, Detail: raw.CaptureError}}
		return base
	}
	if _, err := RequiredColumns(raw.Table); err != nil {
		base.Status = StatusUncompilable
		base.Reasons = []Reason{{Code: ReasonCaptureIncomplete, Detail: err.Error()}}
		return base
	}
	if missing := missingColumns(raw); len(missing) > 0 {
		base.Status = StatusUncompilable
		base.Reasons = []Reason{{
			Code:   ReasonCaptureIncomplete,
			Detail: "the capture did not select: " + strings.Join(missing, ", "),
		}}
		return base
	}

	switch raw.Table {
	case "static_policies":
		return compileStatic(raw, decodeStatic(raw), opts)
	case "dynamic_policies":
		return compileDynamicRow(raw, decodeDynamic(raw), opts)
	}
	base.Status = StatusUncompilable
	base.Reasons = []Reason{{Code: ReasonCaptureIncomplete, Detail: "unreachable: table validated above"}}
	return base
}

// Documents assembles the compiled policies for one plane AND ONE ORG SCOPE
// into the two signed authority roots ADR-065 requires, with an attribute
// schema derived from the policies themselves.
//
// Per org, not per plane alone. The runtime reads static_policies with
// `WHERE org_id = $1` under row-level security that is strict equality
// (migrations/core/018), so one org's policies never reach another org's
// requests. An earlier version of this compiled every captured row into ONE
// organization document with `Scope{Organization: true}`, which compiles to
// an unconditional match - so at cutover every org's policies would have
// applied to every org's requests, and the harness could not see it because
// both sides were equally org-blind. ADR-065 invariant 1 makes org_id the
// isolation boundary; a migration tool that erases it is worse than no tool.
//
// Deriving the schema rather than declaring it is what makes it complete by
// construction: a policy referencing an attribute nobody declared is an
// authoring rejection, so a hand-maintained schema turns a compiler change
// into a mysterious FIELD_NOT_IN_SCHEMA rather than into working policy.
func (rep Report) Documents(plane Plane, orgScope string) (system, org *pdp.Document, err error) {
	return rep.DocumentsForPhase(plane, "", orgScope)
}

// DocumentsForPhase is Documents scoped to one legacy phase, which is how a
// two-phase plane's worlds are built: one engine per phase, because that is
// how production evaluates them. An empty phase means every phase.
func (rep Report) DocumentsForPhase(plane Plane, ph Phase, orgScope string) (system, org *pdp.Document, err error) {
	policies := rep.PoliciesForPhase(plane, ph, orgScope)
	// The schema is the union of what the compiled policies read AND what
	// every contributing row reads. The second half matters: a row the
	// compiler could not express still reads inputs, and a request carrying an
	// undeclared attribute is refused by admission, so omitting those paths
	// would turn every case on the plane into a schema violation and make the
	// plane unmeasurable rather than merely unmigrated.
	var extra []string
	for _, r := range rep.Records {
		if r.Source.OrgScope != orgScope || !r.ContributesOnPhase(plane, ph) {
			continue
		}
		for _, pr := range r.Planes {
			if pr.Plane != plane {
				continue
			}
			if ph != "" && pr.Phase != "" && pr.Phase != ph {
				continue
			}
			extra = append(extra, pr.AttributePaths...)
		}
	}
	schema := deriveSchema(policies, extra)
	// Two documents, two slices. Handing both the same backing array means an
	// append to one silently mutates the other, and the two roots exist
	// precisely so that an organization document cannot reach into the system
	// one.
	system = &pdp.Document{Root: pdp.RootSystem, Version: 1, Attributes: append([]pdp.AttributeSchema(nil), schema...)}
	org = &pdp.Document{Root: pdp.RootOrganization, Version: 1, Attributes: append([]pdp.AttributeSchema(nil), schema...)}
	for _, p := range policies {
		switch p.Root {
		case pdp.RootSystem:
			system.Policies = append(system.Policies, p)
		case pdp.RootOrganization:
			org.Policies = append(org.Policies, p)
		default:
			return nil, nil, fmt.Errorf("legacycompile: policy %q declares root %q", p.ID, p.Root)
		}
	}
	return system, org, nil
}

// deriveSchema builds the attribute schema every compiled policy needs.
//
// Every attribute is declared REQUIRED. That is a deliberate ADR-065 posture
// and not an oversight: a required attribute that is absent is a data defect
// and resolves to unknown, an unknown constraint makes the decision
// Indeterminate, and Indeterminate does not execute. The legacy alternative -
// an unestablished field silently comparing against nil - is exactly the
// #3515 shape, and reproducing it in the TARGET model would carry the defect
// across the migration instead of ending it. Where the legacy behaviour must
// be preserved for diffing, it is preserved in the compiler's and the model's
// context-fallthrough treatment, not in the emitted schema.
func deriveSchema(policies []pdp.Policy, extraPaths []string) []pdp.AttributeSchema {
	types := map[string]pdp.ValueType{}
	note := func(path string, t pdp.ValueType) {
		if path == "" {
			return
		}
		cur, seen := types[path]
		switch {
		case !seen:
			types[path] = t
		case cur != t:
			types[path] = pdp.TypeAny
		}
	}
	var walk func(c pdp.Condition)
	walk = func(c pdp.Condition) {
		switch c.Kind {
		case pdp.CondCompare:
			note(c.Path, typeOfLiteral(c.Literal))
		case pdp.CondMember, pdp.CondSuperset, pdp.CondIntersects:
			note(c.Path, pdp.TypeArray)
		case pdp.CondAttrCompare:
			note(c.Path, pdp.TypeAny)
			note(c.RightPath, pdp.TypeAny)
		}
		for _, o := range c.Operands {
			walk(o)
		}
	}
	for _, p := range extraPaths {
		if _, seen := types[p]; !seen && p != "" {
			types[p] = pdp.TypeAny
		}
	}
	for _, p := range policies {
		walk(p.Where)
		if p.Unless != nil {
			walk(*p.Unless)
		}
		if p.ResourceScope != nil {
			walk(*p.ResourceScope)
		}
		if len(p.Scope.Groups) > 0 {
			note("principal.groups", pdp.TypeArray)
		}
		if len(p.Scope.Principals) > 0 {
			note("principal.id", pdp.TypeString)
		}
		if len(p.Actions.Actions) > 0 {
			note("action.id", pdp.TypeString)
		}
		if len(p.Actions.RequiredTags) > 0 {
			note("action.tags", pdp.TypeArray)
		}
	}
	paths := make([]string, 0, len(types))
	for p := range types {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	out := make([]pdp.AttributeSchema, 0, len(paths))
	for _, p := range paths {
		out = append(out, pdp.AttributeSchema{Path: p, Type: types[p]})
	}
	return out
}

func typeOfLiteral(v any) pdp.ValueType {
	switch v.(type) {
	case bool:
		return pdp.TypeBoolean
	case string:
		return pdp.TypeString
	case float64, float32, int, int64, int32:
		return pdp.TypeNumber
	case []any, []string:
		return pdp.TypeArray
	default:
		return pdp.TypeAny
	}
}
