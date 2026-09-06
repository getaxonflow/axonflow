package contract

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ObligationFamily is the composition algebra an obligation type belongs to.
//
// ADR-065 "Obligations": schemas do not invent pairwise precedence. Obligations
// normalize to canonical atomic targets and then compose through one algebra
// per family. A schema can validate its own parameters but cannot redefine its
// family's algebra, which is what stops the composition rules becoming an
// expanding matrix of schema-to-schema exceptions.
type ObligationFamily string

const (
	// FamilyDisclosure covers field and response disclosure transforms.
	FamilyDisclosure ObligationFamily = "disclosure"
	// FamilyApproval covers approval challenges.
	FamilyApproval ObligationFamily = "approval"
	// FamilyRouting covers route restriction.
	FamilyRouting ObligationFamily = "routing"
	// FamilyStepUp covers step-up authentication.
	FamilyStepUp ObligationFamily = "step_up"
	// FamilyBudget covers quota and budget reservation.
	FamilyBudget ObligationFamily = "budget"
	// FamilyAuditNotify covers immutable audit and notification.
	FamilyAuditNotify ObligationFamily = "audit_notify"
)

// AllObligationFamilies returns every family in a stable order. Composition
// enumerates it so a family added without an algebra denies rather than being
// silently dropped from the composed set.
func AllObligationFamilies() []ObligationFamily {
	return []ObligationFamily{
		FamilyApproval, FamilyAuditNotify, FamilyBudget,
		FamilyDisclosure, FamilyRouting, FamilyStepUp,
	}
}

// ObligationType is a typed instruction owned by a named enforcement component.
type ObligationType string

const (
	ObApprovalChallenge ObligationType = "approval_challenge"
	ObFieldRemove       ObligationType = "field_remove"
	ObFieldRedact       ObligationType = "field_redact"
	ObFieldHash         ObligationType = "field_hash"
	ObFieldMask         ObligationType = "field_mask"
	ObFieldAnnotate     ObligationType = "field_annotate"
	ObFieldTokenize     ObligationType = "field_tokenize"
	ObSchemaTransform   ObligationType = "schema_transform"
	ObResponseFilter    ObligationType = "response_filter"
	ObRouteRestriction  ObligationType = "route_restriction"
	ObStepUpAuth        ObligationType = "step_up_authentication"
	ObQuotaReservation  ObligationType = "quota_reservation"
	ObImmutableAudit    ObligationType = "immutable_audit"
	ObNotification      ObligationType = "notification"
)

// disclosureRank orders comparable disclosure transforms from least disclosing
// to most disclosing. ADR-065: "The fixed order is remove < constant-redact <
// one-way-derived < partial-reveal < unchanged", where "<" means reveals no
// more information than. It is not an action or severity ranking, and there is
// deliberately no "block > redact > warn > log" scale anywhere in this package:
// redaction, logging, warning, routing and approval are different obligations,
// not points on one axis.
var disclosureRank = map[ObligationType]int{
	ObFieldRemove:   0,
	ObFieldRedact:   1,
	ObFieldHash:     2,
	ObFieldMask:     3,
	ObFieldAnnotate: 4,
}

// incomparableDisclosure lists disclosure transforms that are NOT on the chain
// above. A reversible surrogate, an arbitrary schema transform, or a row filter
// cannot be ordered against a redaction without a reviewed subsumption rule,
// and ADR-065 says incomparable results deny. Tokenization sat between hash and
// mask in the source proposal's rank table; that placement is wrong, because a
// value recoverable from a vault does not reveal less than a one-way digest.
var incomparableDisclosure = map[ObligationType]bool{
	ObFieldTokenize:   true,
	ObSchemaTransform: true,
	ObResponseFilter:  true,
}

var obligationFamilies = map[ObligationType]ObligationFamily{
	ObApprovalChallenge: FamilyApproval,
	ObFieldRemove:       FamilyDisclosure,
	ObFieldRedact:       FamilyDisclosure,
	ObFieldHash:         FamilyDisclosure,
	ObFieldMask:         FamilyDisclosure,
	ObFieldAnnotate:     FamilyDisclosure,
	ObFieldTokenize:     FamilyDisclosure,
	ObSchemaTransform:   FamilyDisclosure,
	ObResponseFilter:    FamilyDisclosure,
	ObRouteRestriction:  FamilyRouting,
	ObStepUpAuth:        FamilyStepUp,
	ObQuotaReservation:  FamilyBudget,
	ObImmutableAudit:    FamilyAuditNotify,
	ObNotification:      FamilyAuditNotify,
}

// AllObligationTypes returns every declared type in a stable order.
func AllObligationTypes() []ObligationType {
	out := make([]ObligationType, 0, len(obligationFamilies))
	for t := range obligationFamilies {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// FamilyOf returns the composition family of an obligation type.
func FamilyOf(t ObligationType) (ObligationFamily, error) {
	f, ok := obligationFamilies[t]
	if !ok {
		return "", fmt.Errorf("obligation type %q is not registered", t)
	}
	return f, nil
}

// Assurance is the required authentication assurance level of a step-up
// obligation. It is a declared ORDER rather than a string, because the merge of
// two step-up requirements takes the maximum and a lexicographic comparison of
// arbitrary labels is not that order: "high" sorts below "low", so composing a
// requirement for high assurance with one for low would yield low, and the
// conjunction would be weaker than one of its own inputs.
type Assurance string

const (
	AssuranceLevel1 Assurance = "aal1"
	AssuranceLevel2 Assurance = "aal2"
	AssuranceLevel3 Assurance = "aal3"
)

var assuranceStrength = map[Assurance]int{
	AssuranceLevel1: 1,
	AssuranceLevel2: 2,
	AssuranceLevel3: 3,
}

// AllAssurances returns every declared level, weakest first.
func AllAssurances() []Assurance {
	return []Assurance{AssuranceLevel1, AssuranceLevel2, AssuranceLevel3}
}

// Delivery is the required delivery guarantee for an audit or notification
// obligation, ordered from weakest to strongest.
type Delivery string

const (
	DeliveryBestEffort  Delivery = "best_effort"
	DeliveryAtLeastOnce Delivery = "at_least_once"
	DeliveryDurable     Delivery = "durable"
)

// deliveryStrength orders the declared guarantees. It is read with the
// two-value idiom EVERYWHERE, never bare.
//
// A bare read returns the zero rank for a value outside the map, which is the
// rank of the WEAKEST declared guarantee. In a comparison whose entire job is
// to keep the strongest, that silently demotes any guarantee this build does
// not recognise to the bottom of the order, and ties it with best_effort so
// that whichever obligation arrived first wins. One value over the range
// reinstates the permissive default the ordering exists to prevent.
var deliveryStrength = map[Delivery]int{
	DeliveryBestEffort:  0,
	DeliveryAtLeastOnce: 1,
	DeliveryDurable:     2,
}

// AllDeliveries returns every declared guarantee, weakest first.
func AllDeliveries() []Delivery {
	return []Delivery{DeliveryBestEffort, DeliveryAtLeastOnce, DeliveryDurable}
}

// Strength returns the guarantee's rank and whether it is declared. Callers
// must consult the second value: see deliveryStrength.
func (d Delivery) Strength() (int, bool) {
	s, ok := deliveryStrength[d]
	return s, ok
}

// Validate rejects an undeclared guarantee.
func (d Delivery) Validate() error {
	if _, ok := deliveryStrength[d]; !ok {
		return fmt.Errorf("delivery guarantee %q is not declared; the declared guarantees are %v", d, AllDeliveries())
	}
	return nil
}

// Obligation is one typed instruction attached to a permit.
type Obligation struct {
	Type ObligationType `json:"type"`
	// Target is the canonical field path for a disclosure transform and is
	// empty for every other family.
	Target string `json:"target,omitempty"`
	// Params are the type's own parameters. Two obligations of the same type
	// and target with different params are incomparable.
	Params map[string]string `json:"params,omitempty"`
	// Mandatory obligations deny when they cannot be discharged. An advisory
	// obligation is recorded and dropped.
	Mandatory bool `json:"mandatory"`
	// SourcePolicy is the policy that attached this obligation.
	SourcePolicy string `json:"source_policy"`
	// SchemaVersion is the obligation schema version the PEP must support.
	SchemaVersion int `json:"schema_version"`

	// absent records required members that were missing from the document this
	// obligation was DECODED from. It is never set by construction in Go, so a
	// hand-built obligation is unaffected; see presence.go for why the presence
	// question is answered once, here, rather than at the reads of Mandatory.
	absent wireAbsence
}

// Family returns the obligation's composition family.
func (o Obligation) Family() (ObligationFamily, error) { return FamilyOf(o.Type) }

// Validate rejects a structurally invalid obligation.
func (o Obligation) Validate() error {
	// Presence first. A document that omitted a required member is refused
	// before anything reads the value it did not carry - and `mandatory` is
	// read by the family checks below only indirectly, so a later position
	// would let an incomplete document get part-way through validation and
	// report the second-order complaint instead of the actual defect.
	if refusal, missing := o.absent.firstMissing(SchemaObligation); missing {
		return refusal
	}
	fam, err := FamilyOf(o.Type)
	if err != nil {
		return err
	}
	if o.SchemaVersion <= 0 {
		return fmt.Errorf("obligation %q: schema_version must be positive", o.Type)
	}
	if o.SourcePolicy == "" {
		return fmt.Errorf("obligation %q: source_policy is required", o.Type)
	}
	if fam == FamilyDisclosure {
		if o.Target == "" {
			return fmt.Errorf("obligation %q: a disclosure transform requires a target field path", o.Type)
		}
	} else if o.Target != "" {
		return fmt.Errorf("obligation %q: family %q must not carry a target, got %q", o.Type, fam, o.Target)
	}
	// The delivery guarantee is checked HERE, at the boundary, so that no
	// undeclared value ever reaches the ordering below. An enum whose only
	// enforcement is the comparison that reads it is not enforced: the
	// comparison has to do something with an out-of-range value, and the
	// cheapest something is to rank it zero.
	if raw, carried := o.Params["delivery"]; carried {
		if fam != FamilyAuditNotify {
			return fmt.Errorf("obligation %q: family %q declares no delivery guarantee, so the %q parameter would be read by nothing",
				o.Type, fam, "delivery")
		}
		if err := Delivery(raw).Validate(); err != nil {
			return fmt.Errorf("obligation %q from policy %q: %w", o.Type, o.SourcePolicy, err)
		}
	}
	// separation_of_duties is checked here for the same reason, and it is the
	// LIVE half of the class #3630 names.
	//
	// ApprovalRequirement.SeparationOfDuties is a wire boolean, and the presence
	// boundary in presence.go covers it as one. But nothing in this product
	// decodes that shape: the value that actually reaches a composed approval
	// requirement comes from HERE, out of a map[string]string, through
	// decodeApprovalParams' `o.Params["separation_of_duties"] == "true"`. In a
	// string-typed parameter every spelling that is not exactly "true" -
	// "TRUE", "1", "yes", a typo, a trailing space - read as FALSE, which is
	// "no separation required": the permissive reading of a control whose
	// entire purpose is to be restrictive, arriving through the one path a
	// policy author can actually reach.
	//
	// ABSENCE STAYS LEGAL and means false. That is the authored default and
	// always has been, exactly as an audit obligation carrying no delivery
	// guarantee demands none; refusing it would refuse every approval policy
	// written to date. What is refused is a value that is CARRIED and is not a
	// declared spelling - the case where an author stated an intention and the
	// evaluator read the opposite one.
	//
	// TWO REFUSALS, NOT ONE, and the second is worth naming: the parameter on a
	// NON-APPROVAL family is refused as well, because nothing would read it
	// there. That mirrors the delivery guarantee's family check above verbatim
	// and is a widening of what Validate refuses; it is stated here and in the
	// changelog rather than left to be discovered, since a widening is exactly
	// what this change declines to do elsewhere. Nothing in the tree emits the
	// key on any family - the obligation Params producers in legacycompile and
	// in the AuthZEN adapter each write a fixed key set that does not include
	// it - so no committed policy, pack, fixture or corpus is affected.
	if raw, carried := o.Params["separation_of_duties"]; carried {
		if fam != FamilyApproval {
			return fmt.Errorf("obligation %q: family %q declares no separation of duties, so the %q parameter would be read by nothing",
				o.Type, fam, "separation_of_duties")
		}
		if _, declared := parseObligationBool(raw); !declared {
			return fmt.Errorf("obligation %q from policy %q: separation_of_duties is %q, which is not a declared boolean spelling; "+
				"the declared spellings are %q and %q, and every other value reads as %q - the permissive answer for a restrictive control",
				o.Type, o.SourcePolicy, raw, "true", "false", "false")
		}
	}
	return nil
}

// parseObligationBool reads a boolean-valued obligation parameter.
//
// Two-value, never bare. A parameter map is string-typed, so the ONLY thing
// standing between an author's "TRUE" and the evaluator's "false" is a
// comparison that says so; a bare `== "true"` answers "false" for every input
// it does not recognise, and for a restrictive control that is the permissive
// answer. The declared set is exactly the two JSON boolean literals, because
// this parameter is the wire form of a member the schema types `boolean` and
// admitting a second spelling here would make the two forms disagree.
func parseObligationBool(raw string) (value bool, declared bool) {
	switch raw {
	case "true":
		return true, true
	case "false":
		return false, true
	default:
		return false, false
	}
}

// paramsKey renders the parameter map canonically so that two obligations can
// be compared for parameter identity without depending on map order.
func (o Obligation) paramsKey() string {
	if len(o.Params) == 0 {
		return ""
	}
	keys := make([]string, 0, len(o.Params))
	for k := range o.Params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte('\x1f')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(o.Params[k])
	}
	return b.String()
}

// transformKey identifies the INSTRUCTION: what to do, to what, with which
// parameters. Two obligations sharing it are the same instruction however they
// were attached, which is the comparison the disclosure algebra needs.
func (o Obligation) transformKey() string {
	return string(o.Type) + "\x1e" + o.Target + "\x1e" + o.paramsKey()
}

// paramsKeyExcept renders the parameter map canonically, omitting one key.
func (o Obligation) paramsKeyExcept(omit string) string {
	if len(o.Params) == 0 {
		return ""
	}
	keys := make([]string, 0, len(o.Params))
	for k := range o.Params {
		if k == omit {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte('\x1f')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(o.Params[k])
	}
	return b.String()
}

// identity adds the two fields that change what an ENFORCEMENT POINT must do:
// whether the obligation is mandatory, and which schema version it speaks.
//
// Leaving them out of the deduplication key is a fail-open, not an
// inefficiency. Two byte-identical obligations attached by two policies, one
// advisory and one mandatory, would collapse to whichever sorted first; if that
// was the advisory one, the mandatory twin disappears, the enforcement point
// capability check never runs on it, and adding an ADVISORY policy turns a deny
// into an allow. The schema version half is the same defect against
// PEPProfile.Supports, which requires exact version equality precisely so that
// a plane claiming v1 is not assumed to implement v2.
func (o Obligation) identity() string {
	mandatory := "advisory"
	if o.Mandatory {
		mandatory = "mandatory"
	}
	return o.transformKey() + "\x1e" + mandatory + "\x1e" + strconv.Itoa(o.SchemaVersion)
}

// ApprovalClause is one immutable threshold clause.
type ApprovalClause struct {
	// Quorum is the number of distinct eligible approvers required.
	Quorum int `json:"quorum"`
	// Eligible is the set of group identifiers whose members may approve.
	Eligible []ID `json:"eligible"`
}

func (c ApprovalClause) canonical() ApprovalClause {
	e := append([]ID(nil), c.Eligible...)
	sort.Slice(e, func(i, j int) bool { return e[i].String() < e[j].String() })
	out := e[:0]
	var prev string
	for i, v := range e {
		if i > 0 && v.String() == prev {
			continue
		}
		out = append(out, v)
		prev = v.String()
	}
	return ApprovalClause{Quorum: c.Quorum, Eligible: out}
}

func (c ApprovalClause) key() string {
	cc := c.canonical()
	parts := make([]string, 0, len(cc.Eligible))
	for _, e := range cc.Eligible {
		parts = append(parts, e.String())
	}
	return fmt.Sprintf("%d|%s", cc.Quorum, strings.Join(parts, ","))
}

// Validate rejects a clause that can never be discharged.
func (c ApprovalClause) Validate() error {
	if c.Quorum < 1 {
		return fmt.Errorf("approval clause: quorum must be at least 1, got %d", c.Quorum)
	}
	if len(c.Eligible) == 0 {
		return fmt.Errorf("approval clause: eligible set must not be empty")
	}
	for i, e := range c.Eligible {
		if e.Kind != KindGroup {
			return fmt.Errorf("approval clause: eligible[%d] must be a group identifier, got kind %q", i, e.Kind)
		}
		if err := e.Validate(); err != nil {
			return fmt.Errorf("approval clause: eligible[%d]: %w", i, err)
		}
	}
	return nil
}

// ApprovalRequirement is a conjunction of immutable threshold clauses.
//
// It is NOT a lattice element and it is not collapsed by pool intersection or
// union. The conjunction of "2 of {A,B}" and "2 of {B,C}" is satisfiable by
// approvals from A, B and C; reducing it to "2 of intersection({A,B},{B,C})"
// produces a deny that the policy set does not require. Duplicate clauses
// deduplicate; pools never flatten.
type ApprovalRequirement struct {
	AllOf []ApprovalClause `json:"all_of"`
	// SeparationOfDuties requires that no principal discharges more than one
	// clause and that no member of the actor chain discharges any.
	SeparationOfDuties bool `json:"separation_of_duties"`
	// ExpiresAt is the challenge expiry. Timeout is always deny: a
	// non-response never proves approval, and permitting after timeout also
	// admits execution against a released budget reservation.
	ExpiresAt time.Time `json:"expires_at"`

	// absent records required members that were missing from the document this
	// requirement was DECODED from. See presence.go.
	absent wireAbsence
}

// Validate rejects a structurally invalid requirement.
func (a *ApprovalRequirement) Validate() error {
	if a == nil {
		return fmt.Errorf("approval requirement: is nil")
	}
	// Presence first; see Obligation.Validate.
	if refusal, missing := a.absent.firstMissing(SchemaApproval); missing {
		return refusal
	}
	if len(a.AllOf) == 0 {
		return fmt.Errorf("approval requirement: at least one clause is required")
	}
	if a.ExpiresAt.IsZero() {
		return fmt.Errorf("approval requirement: expires_at is required, because timeout is the only safe default")
	}
	seen := map[string]struct{}{}
	for i, c := range a.AllOf {
		if err := c.Validate(); err != nil {
			return fmt.Errorf("approval requirement: all_of[%d]: %w", i, err)
		}
		k := c.key()
		if _, dup := seen[k]; dup {
			return fmt.Errorf("approval requirement: all_of[%d] duplicates an earlier clause; compose deduplicates, so a duplicate here is a construction defect", i)
		}
		seen[k] = struct{}{}
	}
	return nil
}

// Capability is one obligation type and version a PEP advertises.
type Capability struct {
	Type    ObligationType `json:"type"`
	Version int            `json:"version"`
}

// PEPProfile is what an enforcement point advertises about itself.
//
// A nil profile is not "no obligations needed"; it is an enforcement point that
// has not advertised the decision profile at all, and ADR-065 invariant 12 says
// such a plane refuses the request rather than interpreting it partially.
type PEPProfile struct {
	ID           string       `json:"id"`
	Capabilities []Capability `json:"capabilities"`
}

// Supports reports whether the profile advertises this exact obligation type at
// this exact schema version. Version equality rather than "at least" is
// deliberate: a rolling deploy that introduces a new transform must not
// silently fail open on enforcement points that have not caught up, and a PEP
// claiming v1 cannot be assumed to implement v2 semantics.
func (p *PEPProfile) Supports(o Obligation) bool {
	if p == nil {
		return false
	}
	for _, c := range p.Capabilities {
		if c.Type == o.Type && c.Version == o.SchemaVersion {
			return true
		}
	}
	return false
}

// ObligationOutcome is the result of composing an obligation set.
type ObligationOutcome struct {
	// Obligations is the composed, conflict-free set, canonically ordered.
	Obligations []Obligation
	// Approval is the composed approval requirement, or nil.
	Approval *ApprovalRequirement
	// Denied is true when composition itself denies.
	Denied bool
	// Reason is set when Denied.
	Reason ReasonCode
	// Detail explains the denial for the operator audience.
	Detail string
	// Err is the TYPED cause, when the denial has one.
	//
	// Detail is prose and is what an operator reads; Err is what an adapter
	// rendering a wire refusal reads. Without it the JSON Pointer that makes a
	// MissingMemberError actionable would be recoverable only by parsing
	// Detail, which is the thing typing the error was supposed to stop.
	// Deliberately absent on some denials rather than universal: a composition
	// CONFLICT is a property of a SET and has no single offending member to
	// point at, so there is nothing typed to carry. Callers must treat it as
	// optional - `errors.As(out.Err, &target)` on a nil error is false, which is
	// the correct answer, where `out.Err.Error()` would panic.
	Err error
	// DroppedAdvisory names the advisory obligations that could not be
	// composed alongside the required set. They are recorded rather than
	// promoted into a denial, because an advisory control that can deny is an
	// enforcement control that was never declared as one.
	DroppedAdvisory []Obligation
	// DropDetail explains why they were dropped.
	DropDetail string
	// Unplaced names mandatory disclosure transforms whose target covers no
	// leaf of the declared payload. See composeDisclosure for why this is
	// reported rather than denied.
	Unplaced []Obligation
	// UnplacedDetail explains them.
	UnplacedDetail string
}

// ComposeInput carries everything composition needs. Keeping it in one struct
// means a new input cannot be added at one call site and forgotten at another.
type ComposeInput struct {
	// Obligations is every obligation contributed by a matched policy,
	// mandatory and advisory together. The split is made HERE rather than by
	// the caller: an advisory control cannot return deny, and an invariant
	// that lives in one of several call sites is an invariant the next call
	// site will not have.
	Obligations []Obligation
	// Leaves is the complete set of canonical leaf field paths of the payload
	// the disclosure family transforms. A broad target expands over these.
	Leaves []string
	// PEP is the advertised enforcement profile.
	PEP *PEPProfile
	// ApprovalExpiry is the challenge expiry to stamp on a composed approval
	// requirement.
	ApprovalExpiry time.Time
}

// ComposeObligations applies one algebra per family and returns either a
// composed set or a denial.
//
// Every path out of this function that is not an explicit composed set is a
// denial. There is no path that drops an obligation it could not place, which
// is the structural form of "obligation failure is propagated into the final
// verdict" rather than something a caller has to remember to check.
func ComposeObligations(in ComposeInput) ObligationOutcome {
	// AN OBLIGATION WHOSE `mandatory` MEMBER WAS NEVER SUPPLIED CANNOT BE SPLIT,
	// SO IT IS REFUSED BEFORE THE SPLIT IS ATTEMPTED.
	//
	// The split below reads o.Mandatory to decide which obligations may be
	// dropped - and Mandatory is exactly the member a document can omit. An
	// obligation missing it therefore sorted itself into the ADVISORY bucket,
	// composeSet's refusal of it was reclassified by the advisory rule below as
	// "the advisory contribution does not compose alongside what policy
	// requires", and it was DROPPED with the request allowed to proceed.
	// Measured, not reasoned: an obligation document omitting `mandatory`
	// reached ObligationOutcome{Denied:false} with the refusal parked in
	// DropDetail, where nothing reads it.
	//
	// THE GUARD IS DELIBERATELY NARROWER THAN `o.Validate()`. Running the full
	// validator here would also convert every OTHER validation failure on an
	// advisory obligation - an undeclared delivery guarantee, an empty
	// source_policy, an unregistered type - from "dropped and recorded" into
	// "the whole decision denies", which is an allow-to-deny change for any
	// deployment carrying a bundle compiled before the rule that refuses it
	// (combine.go says exactly that case is reachable). The advisory-drop rule
	// is a deliberate design decision - a detector's contribution must not be
	// able to refuse a request - and it is not this change's to reverse.
	//
	// What it CANNOT survive is an obligation whose advisory-ness is unknown.
	// That is not a control the rule can decline to enforce; it is a document
	// the evaluator cannot classify, and ADR-065 invariant 4 says unknown or
	// malformed input never becomes a permit.
	for _, o := range in.Obligations {
		if refusal, missing := o.absent.firstMissing(SchemaObligation); missing {
			return ObligationOutcome{
				Denied: true,
				// SchemaViolation, not UnsupportedObligation: the document does
				// not satisfy the shape the contract declares, which is a
				// different fact from an instruction this build cannot carry
				// out, and an operator triaging one should not be shown the
				// other.
				Reason: ReasonSchemaViolation,
				Detail: refusal.Error(),
				Err:    refusal,
			}
		}
	}

	// The required set composes first and alone. If it denies, the decision
	// denies; nothing an advisory control contributed can rescue it.
	var required, advisory []Obligation
	for _, o := range in.Obligations {
		if o.Mandatory {
			required = append(required, o)
			continue
		}
		advisory = append(advisory, o)
	}
	if len(advisory) == 0 {
		return composeSet(in, in.Obligations)
	}
	base := composeSet(in, required)
	if base.Denied {
		return base
	}
	combined := composeSet(in, in.Obligations)
	if !combined.Denied {
		return combined
	}
	// The advisory contribution does not compose alongside what policy
	// requires. It is dropped and recorded. Returning the denial instead would
	// let a detector refuse a request, which is the failure ADR-065 forbids and
	// which every call site would otherwise have to remember to prevent.
	base.DroppedAdvisory = advisory
	base.DropDetail = combined.Detail
	return base
}

func composeSet(in ComposeInput, obligations []Obligation) ObligationOutcome {
	byFamily := map[ObligationFamily][]Obligation{}
	for _, o := range obligations {
		if err := o.Validate(); err != nil {
			// The typed cause is carried here too, not only at the pre-split
			// guard. The two sites are one refusal reported from two places,
			// and having one of them lose the cause is how "the pointer is
			// recoverable" becomes true only on the path someone happened to
			// test.
			return ObligationOutcome{Denied: true, Reason: ReasonUnsupportedObligation, Detail: err.Error(), Err: err}
		}
		fam, err := FamilyOf(o.Type)
		if err != nil {
			return ObligationOutcome{Denied: true, Reason: ReasonUnsupportedObligation, Detail: err.Error()}
		}
		byFamily[fam] = append(byFamily[fam], o)
	}

	var composed []Obligation
	var approval *ApprovalRequirement
	var unplaced []Obligation
	var unplacedDetail []string

	for _, fam := range AllObligationFamilies() {
		set := byFamily[fam]
		if len(set) == 0 {
			continue
		}
		switch fam {
		case FamilyDisclosure:
			out, outcome := composeDisclosure(set, in.Leaves)
			if outcome.Denied {
				return outcome
			}
			unplaced = append(unplaced, outcome.Unplaced...)
			unplacedDetail = append(unplacedDetail, outcome.UnplacedDetail)
			composed = append(composed, out...)
		case FamilyApproval:
			req, outcome := composeApproval(set, in.ApprovalExpiry)
			if outcome.Denied {
				return outcome
			}
			approval = req
			// The contributing approval_challenge obligations stay in the
			// composed set alongside the merged requirement. That is
			// deliberate redundancy: the PEP capability check below runs per
			// obligation and per schema version, so collapsing them into one
			// synthetic obligation would decide on the PEP's behalf which
			// version it needed to support.
			composed = append(composed, dedupeObligations(set)...)
		case FamilyAuditNotify:
			out, outcome := composeAuditNotify(set)
			if outcome.Denied {
				return outcome
			}
			composed = append(composed, out...)
		case FamilyRouting:
			out, outcome := composeRouting(set)
			if outcome.Denied {
				return outcome
			}
			composed = append(composed, out...)
		case FamilyStepUp:
			out, outcome := composeStepUp(set)
			if outcome.Denied {
				return outcome
			}
			composed = append(composed, out...)
		case FamilyBudget:
			composed = append(composed, composeBudget(set)...)
		default:
			// A family with no algebra denies. Reaching this branch means a
			// family was declared in AllObligationFamilies without a
			// composition rule, and dropping its obligations would be the
			// exact silent fail-open this switch exists to prevent.
			return ObligationOutcome{
				Denied: true, Reason: ReasonUnsupportedObligation,
				Detail: fmt.Sprintf("obligation family %q has no declared composition algebra", fam),
			}
		}
	}

	// PEP capability check runs after composition, because composition can
	// remove an obligation that a broader one subsumes, and denying on a
	// capability the composed set does not actually require would be wrong.
	for _, o := range composed {
		if !o.Mandatory {
			continue
		}
		if !in.PEP.Supports(o) {
			who := "the enforcement point advertised no profile"
			if in.PEP != nil {
				who = fmt.Sprintf("enforcement point %q advertises no %s at schema version %d", in.PEP.ID, o.Type, o.SchemaVersion)
			}
			return ObligationOutcome{
				Denied: true, Reason: ReasonUnsupportedObligation,
				Detail: fmt.Sprintf("mandatory obligation %q from policy %q cannot be discharged: %s", o.Type, o.SourcePolicy, who),
			}
		}
	}

	sortObligations(composed)
	out := ObligationOutcome{Obligations: composed, Approval: approval, Unplaced: unplaced}
	for _, d := range unplacedDetail {
		if d != "" {
			out.UnplacedDetail = d
		}
	}
	return out
}

// composeDisclosure resolves per leaf field, not per policy.
//
// Per-leaf resolution is what makes subsumption correct in both directions. A
// broad annotate plus a narrow redact yields redact on the narrow leaf and
// annotate elsewhere; the mirror case, a broad redact plus a narrow hash, must
// not downgrade the redaction to a hash. A per-policy "most specific target
// wins" rule gets the second case backwards and fails open.
func composeDisclosure(set []Obligation, leaves []string) ([]Obligation, ObligationOutcome) {
	if len(leaves) == 0 {
		return nil, ObligationOutcome{
			Denied: true, Reason: ReasonObligationConflict,
			Detail: "disclosure obligations were attached but the payload leaf schema is empty, so no target can be resolved",
		}
	}
	// A mandatory transform whose target covers no leaf of THIS action's
	// declared payload is reported rather than dropped in silence.
	//
	// It is not a denial, and that is a judgement worth stating. An
	// organization-wide requirement to redact a date of birth is vacuously
	// satisfied by an action whose response has no such field, and denying
	// would make any cross-action data policy refuse every action missing one
	// of its fields. But the vacuous case and the DRIFT case, where the
	// declared leaf schema has fallen behind the real response and the
	// redaction is being deleted rather than satisfied, are indistinguishable
	// from the leaf list alone. The evaluator cannot tell them apart, so it
	// makes the fact visible instead of choosing. Deciding it belongs to the
	// authoring path, which has the action registry and can ask whether the
	// target names a field any reachable action actually returns.
	var unplaced []Obligation
	for _, o := range set {
		if !o.Mandatory {
			continue
		}
		placed := false
		for _, leaf := range leaves {
			if targetCovers(o.Target, leaf) {
				placed = true
				break
			}
		}
		if !placed {
			unplaced = append(unplaced, o)
		}
	}
	var out []Obligation
	for _, leaf := range sortStrings(leaves) {
		var cov []Obligation
		for _, o := range set {
			if targetCovers(o.Target, leaf) {
				cov = append(cov, o)
			}
		}
		if len(cov) == 0 {
			continue
		}
		chosen, outcome := chooseLeastDisclosing(cov, leaf)
		if outcome.Denied {
			return nil, outcome
		}
		applied := chosen
		applied.Target = leaf
		// The winning transform inherits the mandatory flag of EVERY
		// obligation covering this leaf, not only of the ones sharing its
		// instruction. A policy that required SOME transform on this leaf still
		// requires one after a lower-ranked transform outranked it; carrying
		// only the winner's own flag lets an advisory transform that happens to
		// disclose less displace a mandatory requirement, take the leaf, and
		// skip the enforcement point capability check with it. That is the same
		// "adding an advisory policy turns a deny into an allow" failure
		// arriving through the rank comparison instead of through
		// deduplication.
		for _, o := range cov {
			if o.Mandatory {
				applied.Mandatory = true
				applied.SourcePolicy = joinSources(cov)
				break
			}
		}
		out = append(out, applied)
	}
	outcome := ObligationOutcome{}
	if len(unplaced) > 0 {
		names := make([]string, 0, len(unplaced))
		for _, o := range unplaced {
			names = append(names, fmt.Sprintf("%s(%s) from %s", o.Type, o.Target, o.SourcePolicy))
		}
		outcome.Unplaced = unplaced
		outcome.UnplacedDetail = fmt.Sprintf(
			"%d mandatory transforms target no leaf of the declared payload schema %v and were not applied: %s",
			len(unplaced), sortStrings(leaves), strings.Join(dedupeSorted(names), ", "))
	}
	return dedupeObligations(out), outcome
}

// targetCovers reports whether an obligation target is a prefix of, or equal
// to, a leaf path. Prefix matching is segment-wise so that "response.name" does
// not cover "response.name_suffix".
func targetCovers(target, leaf string) bool {
	if target == leaf {
		return true
	}
	return strings.HasPrefix(leaf, target+".")
}

// TargetCovers reports whether a disclosure transform's target expands over a
// declared payload leaf.
//
// It is exported so the authoring plane can answer, at save time, the question
// composeDisclosure deliberately refuses to decide at runtime: whether a
// mandatory transform names a field any reachable action actually returns. The
// two must use ONE expansion rule. A second implementation there would let a
// target be accepted by the authoring check and then go unplaced at
// enforcement, which is the redaction-deleted-rather-than-satisfied case that
// the runtime reports rather than denies precisely because it cannot tell it
// apart from a vacuous match.
func TargetCovers(target, leaf string) bool { return targetCovers(target, leaf) }

func chooseLeastDisclosing(cov []Obligation, leaf string) (Obligation, ObligationOutcome) {
	// Comparison is by INSTRUCTION. Two policies attaching the same transform
	// with the same parameters are not in conflict because one of them marked
	// it mandatory, so the mandatory flag is merged rather than compared.
	distinct := map[string]Obligation{}
	versions := map[string]map[int]struct{}{}
	for _, o := range cov {
		k := o.transformKey()
		if cur, seen := distinct[k]; seen {
			cur.Mandatory = cur.Mandatory || o.Mandatory
			cur.SourcePolicy = strings.Join(dedupeSorted([]string{cur.SourcePolicy, o.SourcePolicy}), ",")
			distinct[k] = cur
		} else {
			distinct[k] = o
			versions[k] = map[int]struct{}{}
		}
		versions[k][o.SchemaVersion] = struct{}{}
	}
	for k, vs := range versions {
		if len(vs) > 1 {
			return Obligation{}, ObligationOutcome{
				Denied: true, Reason: ReasonObligationConflict,
				Detail: fmt.Sprintf("leaf %q is covered by transform %q at %d different schema versions; an enforcement point advertising one version cannot be assumed to implement another",
					leaf, distinct[k].Type, len(vs)),
			}
		}
	}
	if len(distinct) == 1 {
		// Nothing to compare. An incomparable transform standing alone is the
		// only transform on this leaf and applies as authored.
		for _, o := range distinct {
			return o, ObligationOutcome{}
		}
	}
	var best Obligation
	bestRank := -1
	var tied []Obligation
	for _, o := range sortedDistinct(distinct) {
		if incomparableDisclosure[o.Type] {
			return Obligation{}, ObligationOutcome{
				Denied: true, Reason: ReasonObligationConflict,
				Detail: fmt.Sprintf("leaf %q is covered by %d transforms including %q, which is not comparable with the disclosure order and has no reviewed subsumption rule", leaf, len(distinct), o.Type),
			}
		}
		r, ranked := disclosureRank[o.Type]
		if !ranked {
			return Obligation{}, ObligationOutcome{
				Denied: true, Reason: ReasonObligationConflict,
				Detail: fmt.Sprintf("leaf %q is covered by transform %q, which carries no declared disclosure rank and is not listed as incomparable; "+
					"a transform with no place in the order cannot be composed", leaf, o.Type),
			}
		}
		switch {
		case bestRank < 0 || r < bestRank:
			best, bestRank, tied = o, r, []Obligation{o}
		case r == bestRank:
			tied = append(tied, o)
		}
	}
	if len(tied) > 1 {
		params := make([]string, 0, len(tied))
		for _, t := range tied {
			params = append(params, t.paramsKey())
		}
		return Obligation{}, ObligationOutcome{
			Denied: true, Reason: ReasonObligationConflict,
			Detail: fmt.Sprintf("leaf %q is covered by %d transforms of type %q with differing parameters (%s); equal rank with different parameters is incomparable", leaf, len(tied), tied[0].Type, strings.Join(params, " vs ")),
		}
	}
	return best, ObligationOutcome{}
}

// composeApproval takes the conjunction of every approval clause contributed by
// every matched policy, deduplicating identical clauses without flattening
// pools, and stamps the earliest expiry.
func composeApproval(set []Obligation, expiry time.Time) (*ApprovalRequirement, ObligationOutcome) {
	req := &ApprovalRequirement{ExpiresAt: expiry}
	seen := map[string]struct{}{}
	for _, o := range set {
		clause, sod, err := decodeApprovalParams(o)
		if err != nil {
			return nil, ObligationOutcome{Denied: true, Reason: ReasonUnsupportedObligation, Detail: err.Error()}
		}
		if sod {
			req.SeparationOfDuties = true
		}
		k := clause.key()
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		req.AllOf = append(req.AllOf, clause.canonical())
	}
	sort.Slice(req.AllOf, func(i, j int) bool { return req.AllOf[i].key() < req.AllOf[j].key() })
	if err := req.Validate(); err != nil {
		return nil, ObligationOutcome{Denied: true, Reason: ReasonApprovalUnsatisfiable, Detail: err.Error()}
	}
	return req, ObligationOutcome{}
}

// decodeApprovalParams reads a clause out of an approval_challenge obligation.
// The wire form keeps the clause in params so that the obligation type stays a
// flat, schema-validatable object.
func decodeApprovalParams(o Obligation) (ApprovalClause, bool, error) {
	quorum := o.Params["quorum"]
	eligible := o.Params["eligible"]
	if quorum == "" || eligible == "" {
		return ApprovalClause{}, false, fmt.Errorf("obligation %q from policy %q requires params quorum and eligible", o.Type, o.SourcePolicy)
	}
	var q int
	if _, err := fmt.Sscanf(quorum, "%d", &q); err != nil {
		return ApprovalClause{}, false, fmt.Errorf("obligation %q from policy %q has a non-integer quorum %q", o.Type, o.SourcePolicy, quorum)
	}
	clause := ApprovalClause{Quorum: q}
	for _, raw := range strings.Split(eligible, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		id, err := ParseID(KindGroup, raw)
		if err != nil {
			return ApprovalClause{}, false, fmt.Errorf("obligation %q from policy %q: %w", o.Type, o.SourcePolicy, err)
		}
		clause.Eligible = append(clause.Eligible, id)
	}
	if err := clause.Validate(); err != nil {
		return ApprovalClause{}, false, fmt.Errorf("obligation %q from policy %q: %w", o.Type, o.SourcePolicy, err)
	}
	// Read with the two-value idiom even though Obligation.Validate has already
	// refused an undeclared spelling, for the same reason deliveryRank is:
	// depending on the order of two checks in different functions for a
	// fail-closed property is how the property stops holding the next time one
	// of them moves. Absent is legal and means false; carried-and-undeclared is
	// refused rather than silently read as the permissive answer.
	raw, carried := o.Params["separation_of_duties"]
	if !carried {
		return clause, false, nil
	}
	sod, declared := parseObligationBool(raw)
	if !declared {
		return ApprovalClause{}, false, fmt.Errorf("obligation %q from policy %q: separation_of_duties is %q, which is not a declared boolean spelling",
			o.Type, o.SourcePolicy, raw)
	}
	return clause, sod, nil
}

// deliveryRank returns the rank of an obligation's delivery guarantee.
//
// ABSENT and UNDECLARED are different states and conflating them broke the
// merge: Obligation.Validate admits an audit that carries no delivery
// parameter at all - it validates the value only `if carried` - so absence is
// a legitimate authored state, and reading it through Params["delivery"] as
// the empty string made Strength() refuse it as undeclared. Two identical
// no-delivery audits then could not merge: mandatory ones denied the request
// and advisory ones were silently dropped as non-composing. An obligation
// that carries no guarantee demands none, which is the weakest declared rank;
// only a value that is CARRIED and undeclared is unrankable.
func deliveryRank(o Obligation) (int, bool) {
	raw, carried := o.Params["delivery"]
	if !carried {
		return DeliveryBestEffort.Strength()
	}
	return Delivery(raw).Strength()
}

// composeAuditNotify unions the set with stable deduplication and keeps the
// strongest required delivery guarantee per distinct target.
func composeAuditNotify(set []Obligation) ([]Obligation, ObligationOutcome) {
	strongest := map[string]Obligation{}
	for _, o := range set {
		// The schema version is part of the key: two audit obligations at
		// different versions are two instructions, and merging them would hide
		// one from the capability check.
		// Keyed on the FULL parameter set minus the delivery guarantee, which
		// is the one field this family merges. A key naming only a few
		// parameters silently discards the rest of a mandatory obligation's
		// instruction and makes the surviving one depend on input order.
		key := string(o.Type) + "\x1e" + strconv.Itoa(o.SchemaVersion) + "\x1e" + o.paramsKeyExcept("delivery")
		cur, ok := strongest[key]
		if !ok {
			strongest[key] = o
			continue
		}
		mandatory := cur.Mandatory || o.Mandatory
		// The merged instruction keeps EVERY demanding policy in its source,
		// exactly as dedupeObligations and chooseLeastDisclosing do. This
		// merge point was the one of three that silently kept a single
		// source, so which policy a merged audit was attributed to depended
		// on delivery strength and input order - and a consumer comparing
		// obligations per source policy read every other demanding policy's
		// instruction as missing.
		sources := strings.Join(dedupeSorted([]string{cur.SourcePolicy, o.SourcePolicy}), ",")
		// Both ranks are read with the two-value idiom even though
		// Obligation.Validate has already refused an undeclared guarantee.
		// Depending on the order of two checks in different functions for a
		// fail-closed property is how the property stops holding the next time
		// one of them moves.
		next, nextOK := deliveryRank(o)
		held, heldOK := deliveryRank(cur)
		if !nextOK || !heldOK {
			return nil, ObligationOutcome{
				Denied: true, Reason: ReasonUnsupportedObligation,
				Detail: fmt.Sprintf("obligations from %q and %q carry delivery guarantees %q and %q, and one is not declared, so the strongest cannot be identified",
					cur.SourcePolicy, o.SourcePolicy, cur.Params["delivery"], o.Params["delivery"]),
			}
		}
		if next > held {
			cur = o
		}
		cur.Mandatory = mandatory
		cur.SourcePolicy = sources
		strongest[key] = cur
	}
	return dedupeObligations(sortedDistinct(strongest)), ObligationOutcome{}
}

// composeRouting intersects allowed destinations. An empty intersection denies.
func composeRouting(set []Obligation) ([]Obligation, ObligationOutcome) {
	var current map[string]struct{}
	for _, o := range set {
		allowed := splitSet(o.Params["allowed_destinations"])
		if len(allowed) == 0 {
			return nil, ObligationOutcome{
				Denied: true, Reason: ReasonUnsupportedObligation,
				Detail: fmt.Sprintf("route restriction from policy %q declares no allowed destinations", o.SourcePolicy),
			}
		}
		if current == nil {
			current = allowed
			continue
		}
		current = intersect(current, allowed)
	}
	if len(current) == 0 {
		return nil, ObligationOutcome{
			Denied: true, Reason: ReasonObligationConflict,
			Detail: "route restrictions intersect to an empty destination set",
		}
	}
	merged, outcome := mergedShell(set, "route restriction")
	if outcome.Denied {
		return nil, outcome
	}
	merged.Params = map[string]string{"allowed_destinations": joinSet(current)}
	return []Obligation{merged}, ObligationOutcome{}
}

// composeStepUp takes the maximum required assurance and intersects permitted
// methods. An empty method set denies.
func composeStepUp(set []Obligation) ([]Obligation, ObligationOutcome) {
	maxAssurance := Assurance("")
	maxStrength := 0
	var methods map[string]struct{}
	for _, o := range set {
		a := Assurance(o.Params["assurance"])
		strength, declared := assuranceStrength[a]
		if !declared {
			return nil, ObligationOutcome{
				Denied: true, Reason: ReasonUnsupportedObligation,
				Detail: fmt.Sprintf("step-up requirement from policy %q declares assurance %q, which is not one of %v",
					o.SourcePolicy, o.Params["assurance"], AllAssurances()),
			}
		}
		if strength > maxStrength {
			maxStrength, maxAssurance = strength, a
		}
		m := splitSet(o.Params["methods"])
		if len(m) == 0 {
			return nil, ObligationOutcome{
				Denied: true, Reason: ReasonUnsupportedObligation,
				Detail: fmt.Sprintf("step-up requirement from policy %q declares no permitted methods", o.SourcePolicy),
			}
		}
		if methods == nil {
			methods = m
			continue
		}
		methods = intersect(methods, m)
	}
	if len(methods) == 0 {
		return nil, ObligationOutcome{
			Denied: true, Reason: ReasonObligationConflict,
			Detail: "step-up requirements intersect to an empty authentication method set",
		}
	}
	merged, outcome := mergedShell(set, "step-up requirement")
	if outcome.Denied {
		return nil, outcome
	}
	merged.Params = map[string]string{"assurance": string(maxAssurance), "methods": joinSet(methods)}
	return []Obligation{merged}, ObligationOutcome{}
}

// composeBudget takes the conjunction: every distinct reservation must succeed.
// Reservations are not merged, because two budgets with different scopes are
// two independent atomic operations.
func composeBudget(set []Obligation) []Obligation {
	return dedupeObligations(set)
}

// mergedShell builds the carrier for an intersected family result.
//
// The merged obligation is a CONJUNCTION of its inputs, so it must be mandatory
// if any input was. Copying the first contributor's struct instead, which is
// what an unordered set makes arbitrary, hands the enforcement point a
// requirement marked advisory that a policy declared mandatory, and the
// capability check then skips it. Mixed schema versions refuse outright: a
// merged instruction can only speak one version, and silently picking one would
// discard a requirement rather than compose it.
func mergedShell(set []Obligation, what string) (Obligation, ObligationOutcome) {
	out := set[0]
	out.Mandatory = false
	versions := map[int]struct{}{}
	for _, o := range set {
		out.Mandatory = out.Mandatory || o.Mandatory
		versions[o.SchemaVersion] = struct{}{}
	}
	if len(versions) > 1 {
		return Obligation{}, ObligationOutcome{
			Denied: true, Reason: ReasonUnsupportedObligation,
			Detail: fmt.Sprintf("%ss from %s span %d schema versions and cannot be merged into one instruction",
				what, joinSources(set), len(versions)),
		}
	}
	out.SourcePolicy = joinSources(set)
	return out, ObligationOutcome{}
}

func splitSet(csv string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, v := range strings.Split(csv, ",") {
		v = strings.TrimSpace(v)
		if v != "" {
			out[v] = struct{}{}
		}
	}
	return out
}

func joinSet(s map[string]struct{}) string {
	out := make([]string, 0, len(s))
	for v := range s {
		out = append(out, v)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func intersect(a, b map[string]struct{}) map[string]struct{} {
	out := map[string]struct{}{}
	for v := range a {
		if _, ok := b[v]; ok {
			out[v] = struct{}{}
		}
	}
	return out
}

func joinSources(set []Obligation) string {
	s := make([]string, 0, len(set))
	for _, o := range set {
		s = append(s, o.SourcePolicy)
	}
	return strings.Join(dedupeSorted(s), ",")
}

func sortedDistinct(m map[string]Obligation) []Obligation {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]Obligation, 0, len(keys))
	for _, k := range keys {
		out = append(out, m[k])
	}
	return out
}

// dedupeObligations collapses obligations that are the same INSTRUCTION at the
// same schema version, taking the strictest mandatory flag rather than the
// first one seen.
//
// It merges rather than drops. Two policies attaching the same instruction, one
// advisory and one mandatory, describe one instruction that IS mandatory,
// because a policy that requires it does not stop requiring it because another
// policy would have settled for advice.
func dedupeObligations(in []Obligation) []Obligation {
	order := []string{}
	merged := map[string]Obligation{}
	sources := map[string][]string{}
	for _, o := range in {
		k := o.transformKey() + "\x1e" + strconv.Itoa(o.SchemaVersion)
		cur, seen := merged[k]
		if !seen {
			order = append(order, k)
			merged[k] = o
			sources[k] = []string{o.SourcePolicy}
			continue
		}
		cur.Mandatory = cur.Mandatory || o.Mandatory
		merged[k] = cur
		sources[k] = append(sources[k], o.SourcePolicy)
	}
	out := make([]Obligation, 0, len(order))
	for _, k := range order {
		o := merged[k]
		o.SourcePolicy = strings.Join(dedupeSorted(sources[k]), ",")
		out = append(out, o)
	}
	return out
}

func sortObligations(in []Obligation) {
	sort.Slice(in, func(i, j int) bool { return in[i].identity() < in[j].identity() })
}
