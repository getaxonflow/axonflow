package contract

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// AuthZENProfile is the versioned AxonFlow context profile a PEP must
// negotiate before it receives anything beyond the boolean decision.
//
// AuthZEN 1.0's decision field is a boolean. AxonFlow's internal lattice is
// four-valued and carries obligations, a challenge and safe reason codes, all
// of which ride in the response context. A PEP that did not negotiate the
// profile sees only the boolean, because handing a partial interpretation to a
// plane that cannot act on it is the failure ADR-065 invariant 12 forbids.
type AuthZENProfile string

// AuthZENProfileV1 is the only profile version this contract emits.
const AuthZENProfileV1 AuthZENProfile = "axonflow-authzen-profile-2026-08-29"

// AuthZENSubject is the AuthZEN subject object.
type AuthZENSubject struct {
	Type       string         `json:"type"`
	ID         string         `json:"id"`
	Properties map[string]any `json:"properties,omitempty"`
}

// AuthZENAction is the AuthZEN action object.
type AuthZENAction struct {
	Name       string         `json:"name"`
	Properties map[string]any `json:"properties,omitempty"`
}

// AuthZENResource is the AuthZEN resource object.
type AuthZENResource struct {
	Type       string         `json:"type"`
	ID         string         `json:"id"`
	Properties map[string]any `json:"properties,omitempty"`
}

// AuthZENRequest is one AuthZEN subject-action-resource-context request.
type AuthZENRequest struct {
	Subject  *AuthZENSubject  `json:"subject,omitempty"`
	Action   *AuthZENAction   `json:"action,omitempty"`
	Resource *AuthZENResource `json:"resource,omitempty"`
	Context  map[string]any   `json:"context,omitempty"`
}

// AuthZENBulk is the plural envelope: shared subject, action and context at the
// top level, with one entry per decision.
//
// The number of decisions is fixed by the mapping, never by the arguments. COAZ
// is explicit that returning a list must not cause the request to fan out,
// because that would let runtime argument data decide how many authorization
// checks happen.
type AuthZENBulk struct {
	Subject     *AuthZENSubject  `json:"subject,omitempty"`
	Action      *AuthZENAction   `json:"action,omitempty"`
	Resource    *AuthZENResource `json:"resource,omitempty"`
	Context     map[string]any   `json:"context,omitempty"`
	Evaluations []AuthZENRequest `json:"evaluations"`
}

// AuthZENEnvelope is the top level. Exactly two keys are defined and exactly
// one may be present; any other top-level key is malformed.
type AuthZENEnvelope struct {
	Evaluation  *AuthZENRequest `json:"evaluation,omitempty"`
	Evaluations *AuthZENBulk    `json:"evaluations,omitempty"`
}

// DecodeAuthZENEnvelope decodes strictly.
//
// Strict decoding is the whole point of the boundary: unknown required fields,
// mappings, profiles or obligations fail closed. A tolerant decoder that
// ignores an unrecognized top-level key would silently accept a request built
// for a different profile version and evaluate it as if it were this one.
func DecodeAuthZENEnvelope(raw []byte) (*AuthZENEnvelope, error) {
	// Duplicate members are refused before anything else. DisallowUnknownFields
	// does not cover them, and encoding/json silently keeps the LAST, so a
	// request carrying two "evaluation" members is one request to this decoder
	// and a different one to any layer that read the first: a gateway, an audit
	// log, a rate limiter. That is the same class the unknown-key rule exists
	// for, arriving through a member name the schema does declare.
	if err := rejectDuplicateKeys(json.NewDecoder(bytes.NewReader(raw)), "$"); err != nil {
		return nil, fmt.Errorf("authzen: envelope is malformed: %w", err)
	}

	// Top-level presence is decided on the KEY SET, not on the decoded
	// pointers. {"evaluation":{...},"evaluations":null} carries both declared
	// members, and reading the pointers would see only one.
	var present map[string]json.RawMessage
	if err := json.Unmarshal(raw, &present); err != nil {
		return nil, fmt.Errorf("authzen: envelope is not an object: %w", err)
	}
	_, hasSingular := present["evaluation"]
	_, hasPlural := present["evaluations"]
	switch {
	case !hasSingular && !hasPlural:
		return nil, fmt.Errorf("authzen: envelope must carry exactly one of \"evaluation\" or \"evaluations\", got neither")
	case hasSingular && hasPlural:
		return nil, fmt.Errorf("authzen: envelope must carry exactly one of \"evaluation\" or \"evaluations\", got both")
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var env AuthZENEnvelope
	if err := dec.Decode(&env); err != nil {
		return nil, fmt.Errorf("authzen: envelope is malformed: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("authzen: envelope carries trailing content")
	}
	if env.Evaluation == nil && env.Evaluations == nil {
		return nil, fmt.Errorf("authzen: the declared envelope member is null")
	}
	if env.Evaluations != nil && len(env.Evaluations.Evaluations) == 0 {
		return nil, fmt.Errorf("authzen: plural envelope carries an empty evaluations array; the decision count is fixed by the mapping and zero is not a mapping")
	}
	return &env, nil
}

// rejectDuplicateKeys walks the token stream and refuses any object with a
// repeated member name, at any depth.
func rejectDuplicateKeys(dec *json.Decoder, path string) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	switch d := tok.(type) {
	case json.Delim:
		switch d {
		case '{':
			seen := map[string]struct{}{}
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return err
				}
				key, ok := keyTok.(string)
				if !ok {
					return fmt.Errorf("object member name at %s is not a string", path)
				}
				if _, dup := seen[key]; dup {
					return fmt.Errorf("object at %s carries the member %q more than once", path, key)
				}
				seen[key] = struct{}{}
				if err := rejectDuplicateKeys(dec, path+"."+key); err != nil {
					return err
				}
			}
			if _, err := dec.Token(); err != nil {
				return err
			}
		case '[':
			i := 0
			for dec.More() {
				if err := rejectDuplicateKeys(dec, fmt.Sprintf("%s[%d]", path, i)); err != nil {
					return err
				}
				i++
			}
			if _, err := dec.Token(); err != nil {
				return err
			}
		}
	}
	return nil
}

// ProjectedRequest is the output of the pure projection step: identifiers taken
// from the request as it arrived, plus caller-supplied argument data, and
// nothing that required a lookup.
//
// The separation from Request is not bookkeeping. A projection can say the
// resource is ticket SUP-42; it cannot say SUP-42 sits in a restricted project.
// Containment and attributes are authority facts, and an authority fact
// established from caller input is not an authority fact.
type ProjectedRequest struct {
	SubjectType  string
	SubjectID    string
	ActionName   string
	ResourceType string
	ResourceID   string
	// CallerAttributes are the caller-supplied values, already namespaced
	// under args. Nothing else may be produced here.
	CallerAttributes AttributeSet
	// EnvelopeIndex is the zero-based index of this entry in the envelope.
	EnvelopeIndex int
}

// Project turns a decoded envelope into one projected request per decision.
func (e *AuthZENEnvelope) Project(observedAt time.Time) ([]ProjectedRequest, error) {
	if e == nil {
		return nil, fmt.Errorf("authzen: envelope is nil")
	}
	if e.Evaluation != nil {
		p, err := projectOne(*e.Evaluation, nil, 0, observedAt)
		if err != nil {
			return nil, err
		}
		return []ProjectedRequest{p}, nil
	}
	base := AuthZENRequest{
		Subject:  e.Evaluations.Subject,
		Action:   e.Evaluations.Action,
		Resource: e.Evaluations.Resource,
		Context:  e.Evaluations.Context,
	}
	out := make([]ProjectedRequest, 0, len(e.Evaluations.Evaluations))
	for i, entry := range e.Evaluations.Evaluations {
		p, err := projectOne(entry, &base, i, observedAt)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func projectOne(entry AuthZENRequest, base *AuthZENRequest, index int, observedAt time.Time) (ProjectedRequest, error) {
	merged := entry
	if base != nil {
		if merged.Subject == nil {
			merged.Subject = base.Subject
		}
		if merged.Action == nil {
			merged.Action = base.Action
		}
		if merged.Resource == nil {
			merged.Resource = base.Resource
		}
		if merged.Context == nil {
			merged.Context = base.Context
		}
	}
	if merged.Subject == nil || merged.Subject.ID == "" || merged.Subject.Type == "" {
		return ProjectedRequest{}, fmt.Errorf("authzen: evaluation %d has no subject type and id", index)
	}
	if merged.Action == nil || merged.Action.Name == "" {
		return ProjectedRequest{}, fmt.Errorf("authzen: evaluation %d has no action name", index)
	}
	if merged.Resource == nil || merged.Resource.ID == "" || merged.Resource.Type == "" {
		return ProjectedRequest{}, fmt.Errorf("authzen: evaluation %d has no resource type and id", index)
	}
	attrs, err := projectCallerProperties(merged, observedAt)
	if err != nil {
		return ProjectedRequest{}, fmt.Errorf("authzen: evaluation %d: %w", index, err)
	}
	return ProjectedRequest{
		SubjectType:      merged.Subject.Type,
		SubjectID:        merged.Subject.ID,
		ActionName:       merged.Action.Name,
		ResourceType:     merged.Resource.Type,
		ResourceID:       merged.Resource.ID,
		CallerAttributes: attrs,
		EnvelopeIndex:    index,
	}, nil
}

// projectCallerProperties writes caller-supplied data into the args namespace
// and refuses to write anywhere else.
//
// This is the structural form of "adapters never copy arbitrary caller JSON
// into trusted context". A mapping may route caller data into any AuthZEN
// field, so the rule cannot be about which field a value lands in; it is about
// provenance, and the only namespace whose declared provenance is caller is
// args.
func projectCallerProperties(r AuthZENRequest, observedAt time.Time) (AttributeSet, error) {
	out := AttributeSet{}
	sources := []struct {
		prefix string
		values map[string]any
	}{
		{"args", asMap(r.Context["args"])},
		{"args.subject_properties", r.Subject.Properties},
		{"args.action_properties", r.Action.Properties},
		{"args.resource_properties", r.Resource.Properties},
	}
	for _, s := range sources {
		for _, k := range sortedKeys(s.values) {
			path := s.prefix + "." + k
			if NamespaceOf(path) != NsArgs {
				return nil, fmt.Errorf("caller-supplied property %q would land outside the args namespace", path)
			}
			if err := ValidateAttributePath(path); err != nil {
				return nil, fmt.Errorf("caller-supplied property: %w", err)
			}
			// Two caller inputs that project onto one path are refused rather
			// than resolved last-wins. Silently discarding one of them means
			// the evaluated request is not the request that arrived, and the
			// caller has no way to know which half was read.
			if _, dup := out[path]; dup {
				return nil, fmt.Errorf("two caller-supplied properties project onto the attribute path %q", path)
			}
			out[path] = Known(s.values[k], ProvCaller, 0, observedAt)
		}
	}
	return out, nil
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// AuthZENResponseContext is the versioned AxonFlow profile payload.
type AuthZENResponseContext struct {
	Profile       AuthZENProfile       `json:"profile"`
	State         OperationalState     `json:"state"`
	Category      Category             `json:"category"`
	Reason        ReasonCode           `json:"reason,omitempty"`
	Obligations   []Obligation         `json:"obligations,omitempty"`
	Approval      *ApprovalRequirement `json:"approval,omitempty"`
	DecisionID    string               `json:"decision_id"`
	SchemaVersion string               `json:"schema_version"`
}

// AuthZENResponse is the AuthZEN reply.
type AuthZENResponse struct {
	Decision bool                    `json:"decision"`
	Context  *AuthZENResponseContext `json:"context,omitempty"`
}

// AuthZENErrorCode names why a request was refused rather than evaluated.
//
// The set is closed for the same reason the unknown reasons are: a code
// invented at a call site is invisible to the clients that have to branch on
// it, and a client that cannot distinguish "you sent something I cannot
// evaluate" from "the evaluator is unavailable" cannot decide whether retrying
// is sensible.
type AuthZENErrorCode string

const (
	// ErrMalformedEnvelope is a body that is not a well-formed envelope:
	// unknown keys, duplicate members, neither or both top-level members, an
	// empty plural array. It is ALSO the code on the two size refusals (413):
	// a body over the byte cap and a plural envelope over the entry cap.
	// Those envelopes may be well-formed; the code is reused because the
	// enumeration is closed on the wire, both are non-retryable in the same
	// way (an identical resend gets an identical answer), and the status plus
	// the pointer carry the actual diagnosis.
	ErrMalformedEnvelope AuthZENErrorCode = "malformed_envelope"
	// ErrIncompleteEvaluation is an entry that, after inheriting from the
	// shared base, still has no subject, action or resource.
	ErrIncompleteEvaluation AuthZENErrorCode = "incomplete_evaluation"
	// ErrUnsupportedSubject is a subject the caller is not authenticated as.
	ErrUnsupportedSubject AuthZENErrorCode = "unsupported_subject"
	// ErrUnsupportedAction is an action name outside the evaluable set.
	ErrUnsupportedAction AuthZENErrorCode = "unsupported_action"
	// ErrUnsupportedResource is a resource shape the evaluator cannot target.
	ErrUnsupportedResource AuthZENErrorCode = "unsupported_resource"
	// ErrUnevaluableAttribute is caller-supplied data the evaluator would not
	// consider.
	//
	// This is the code that exists to prevent a fail-open: accepting an
	// attribute the decision never read tells the caller a fact was weighed
	// when it was not, and every subsequent audit of that decision inherits
	// the lie. Refusing is the only honest answer while the evaluator behind
	// this surface cannot read the attribute.
	ErrUnevaluableAttribute AuthZENErrorCode = "unevaluable_attribute"
	// ErrMissingEvaluableContent is a request carrying nothing to evaluate.
	ErrMissingEvaluableContent AuthZENErrorCode = "missing_evaluable_content"
	// ErrEvaluationUnavailable is a dependency failure: the evaluator could
	// not answer. It is the only code for which retrying is meaningful.
	ErrEvaluationUnavailable AuthZENErrorCode = "evaluation_unavailable"
)

// AllAuthZENErrorCodes returns every declared code in a stable order.
func AllAuthZENErrorCodes() []AuthZENErrorCode {
	return []AuthZENErrorCode{
		ErrMalformedEnvelope, ErrIncompleteEvaluation, ErrUnsupportedSubject,
		ErrUnsupportedAction, ErrUnsupportedResource, ErrUnevaluableAttribute,
		ErrMissingEvaluableContent, ErrEvaluationUnavailable,
	}
}

// Retryable reports whether the caller could get a different answer by sending
// the same request again. Only a dependency failure is.
func (c AuthZENErrorCode) Retryable() bool { return c == ErrEvaluationUnavailable }

// AuthZENError is the structured refusal body.
//
// It is a SEPARATE shape from AuthZENResponse rather than an extra member on
// it, because a refusal is not a decision: a response carrying decision=false
// says the request was evaluated and denied, and returning that for a request
// that was never evaluated would make "denied" and "unevaluable" the same event
// in every audit and every client branch.
type AuthZENError struct {
	Code AuthZENErrorCode `json:"code"`
	// Pointer is a JSON Pointer (RFC 6901) into the request, naming the exact
	// member that could not be evaluated. It is what makes a refusal
	// actionable rather than a puzzle: "unevaluable_attribute" alone does not
	// tell an SDK author which of forty context keys to drop.
	Pointer string `json:"pointer,omitempty"`
	Message string `json:"message"`
	// Supported lists what would have been accepted at Pointer, when the set is
	// closed and small enough to state. An error that names the offending value
	// without naming the alternatives sends the caller to the documentation.
	Supported []string `json:"supported,omitempty"`
	// RequestID correlates the refusal with the server's own records. A
	// refusal is audited like any other terminal outcome.
	RequestID string `json:"request_id,omitempty"`
}

func (e *AuthZENError) Error() string {
	if e == nil {
		return "<nil authzen error>"
	}
	if e.Pointer != "" {
		return fmt.Sprintf("authzen: %s at %s: %s", e.Code, e.Pointer, e.Message)
	}
	return fmt.Sprintf("authzen: %s: %s", e.Code, e.Message)
}

// Validate rejects a refusal that would not be actionable.
func (e *AuthZENError) Validate() error {
	if e == nil {
		return fmt.Errorf("authzen error: is nil")
	}
	declared := false
	for _, c := range AllAuthZENErrorCodes() {
		if c == e.Code {
			declared = true
			break
		}
	}
	if !declared {
		return fmt.Errorf("authzen error: %q is not a declared code", e.Code)
	}
	if e.Message == "" {
		return fmt.Errorf("authzen error: a refusal must carry a message")
	}
	return nil
}

// MandatoryObligationWithheld reports whether rendering this decision to a
// caller that negotiated `negotiated` would silently drop an instruction the
// PEP is not permitted to ignore.
//
// # Why this predicate exists at all
//
// Everything AxonFlow adds to AuthZEN 1.0 - the four-valued state, the
// obligations, the approval challenge - rides in the response context, which is
// returned ONLY to a caller that negotiated the profile. That gating is
// correct for anything ADVISORY: a bare AuthZEN 1.0 PEP cannot act on it, and a
// partial interpretation it will ignore is worse than the boolean it
// understands.
//
// It is NOT correct for a MANDATORY obligation. A mandatory obligation is a
// precondition of the allow, not a decoration on it, so gating it turns
// "allowed once you have redacted this" into a bare "allowed" - and the caller
// proceeds with the unredacted content believing it was permitted to. ADR-065
// invariant 8 prescribes DENY for a mandatory obligation the PEP cannot
// enforce, and a PEP that cannot even RECEIVE the obligation is the limiting
// case of one that cannot enforce it.
//
// # Why the predicate is on Mandatory rather than on len(obligations) > 0
//
// The property that decides the answer is enforceability, not presence. Every
// obligation this build renders onto the AuthZEN surface today happens to be
// mandatory (the legacy Decision API has no advisory obligations, so
// mapObligations stamps Mandatory unconditionally), which would make a
// len(obligations) > 0 test observationally identical right now. It would stop
// being identical the first time an advisory obligation is emitted, and it
// would then deny an operation that a bare PEP was entitled to perform. The
// emission side is expected to change; the invariant is not.
//
// # Why the STATE is a parameter rather than a guard at each call site
//
// The rule has three terms, and the state is one of them: nothing is withheld
// from a decision that was not going to permit execution anyway. That term used
// to live at ONE of the two call sites - the serving adapter tested
// `state == StateAllow && MandatoryObligationWithheld(...)` while ToAuthZEN
// applied the predicate with no state term at all - and the two agreed only
// because Executable() happens to be `s == StateAllow` today. Two call sites
// spelling one rule differently is the drift this function was extracted to
// prevent, so the whole rule is here and neither caller restates any part of
// it.
//
// The term is `state.Executable()` rather than an equality against StateAllow
// on purpose: the boolean this rule OVERRIDES is exactly `state.Executable()`,
// so deriving the override from the same function means the two cannot come
// apart if a further state ever becomes executable.
//
// It matters beyond tidiness because it decides the METRIC label, not the
// boolean. A DENY that happens to carry an obligation - which a plural envelope
// can assemble, since obligations accumulate across entries while the meet
// takes the worst state - must count as a policy denial, not as a caller that
// needs to send a header. A CHALLENGE is the sharper case: it is a PERMIT with
// an approval outstanding, so Decision.Validate positively ALLOWS it to carry
// obligations, and without this term every challenge carrying a mandatory
// obligation would be reported as a withheld-obligation deny.
//
// It is declared HERE, beside the profile it gates, so the serving adapter and
// the decision renderer below apply one rule rather than two copies that drift.
func MandatoryObligationWithheld(state OperationalState, negotiated AuthZENProfile, obligations []Obligation) bool {
	if !state.Executable() {
		// Nothing is withheld from a decision that permits no execution: the
		// boolean is already false and the PEP has nothing to discharge.
		return false
	}
	if negotiated == AuthZENProfileV1 {
		// The caller receives the obligations, so nothing is withheld.
		return false
	}
	for _, o := range obligations {
		if o.Mandatory {
			return true
		}
	}
	return false
}

// ToAuthZEN collapses a decision at the edge.
//
// ALLOW maps to decision true; every other state maps to false. The boolean is
// not allowed to leak inward, which is why this is the only function in the
// package that produces one.
//
// AN ALLOW WHOSE MANDATORY OBLIGATIONS CANNOT BE DELIVERED IS RENDERED FALSE.
// See MandatoryObligationWithheld: withholding the obligation and keeping the
// true is the fail-open, and deny is both what invariant 8 prescribes and the
// only answer a bare AuthZEN 1.0 caller can read.
func (d *Decision) ToAuthZEN(negotiated AuthZENProfile) (*AuthZENResponse, error) {
	if d == nil {
		return nil, fmt.Errorf("authzen: decision is nil")
	}
	if err := d.Validate(); err != nil {
		return nil, err
	}
	resp := &AuthZENResponse{Decision: d.State.Executable()}
	if negotiated != AuthZENProfileV1 {
		// Not negotiated, or negotiated at a version this build does not
		// emit. The PEP sees only the boolean - and the boolean must not say
		// "go ahead" when the conditions attached to the allow travelled no
		// further than this function.
		if MandatoryObligationWithheld(d.State, negotiated, d.Obligations) {
			resp.Decision = false
		}
		return resp, nil
	}
	resp.Context = &AuthZENResponseContext{
		Profile:       AuthZENProfileV1,
		State:         d.State,
		Category:      CategoryFor(d.Reason),
		Reason:        d.Reason,
		Obligations:   d.Obligations,
		Approval:      d.Approval,
		DecisionID:    d.DecisionID,
		SchemaVersion: d.Snapshot.SchemaVersion,
	}
	return resp, nil
}

// precedence orders the four outcomes from least to most permissive for the
// meet across entries.
//
// It is not a second lattice. It is the single-request combining order of
// ADR-065 read across entries: a matched constraint determines Deny without
// waiting for unrelated unknowns; constraint uncertainty outranks permission
// coverage; and an absent permission outranks a permit. It is declared once,
// at package level, so the order is a statement rather than a local rebuilt on
// every call, and so a test can hold it to the enumeration it ranks.
var precedence = map[Authorization]int{
	AuthzDeny:          0,
	AuthzIndeterminate: 1,
	AuthzNotApplicable: 2,
	AuthzPermit:        3,
}

// MeetOptions carry what recomposing an obligation set across entries needs.
//
// They are required rather than optional: composing without the payload leaf
// schema cannot resolve a disclosure transform to a leaf, and composing without
// the enforcement profile cannot check that a mandatory obligation is
// supported. A meet that skipped either would be the place a requirement got
// lost.
type MeetOptions struct {
	PayloadLeaves []string
	PEP           *PEPProfile
}

// MeetDecisions combines the per-entry decisions of a plural envelope into the
// effective decision for the operation.
//
// The combination is a meet, never a union, and it is sound because a mapping's
// entries are always preconditions of one operation rather than independent
// queries: moving a ticket must be authorized against the destination project
// as well as against the ticket, or an agent could relocate anything into a
// restricted project or out of one.
//
// The precedence below is not a second lattice. It is the single-request
// combining order of ADR-065 read across entries: a matched constraint
// determines Deny without waiting for unrelated unknowns; constraint
// uncertainty outranks permission coverage; and an absent permission outranks a
// permit.
func MeetDecisions(in []*Decision, opts MeetOptions) (*Decision, error) {
	if len(in) == 0 {
		return nil, fmt.Errorf("authzen: cannot meet an empty decision set")
	}
	// A single entry is still validated. Returning it untouched would make this
	// the one path by which a malformed decision, for example deny carried with
	// an ALLOW state, reaches a caller as executable, and a rule that holds for
	// two entries and not for one is not a rule.
	for i, d := range in {
		if d == nil {
			return nil, fmt.Errorf("authzen: decision set contains a nil entry at %d", i)
		}
		if err := d.Validate(); err != nil {
			return nil, err
		}
		// Every entry of one envelope, and every hop of one chain, is
		// evaluated against ONE request and ONE bundle. Entries that disagree
		// about what they were computed against cannot be combined into a
		// decision that names a snapshot, and a combined decision that names
		// the wrong snapshot is not replayable.
		if in[i].Snapshot != in[0].Snapshot {
			return nil, fmt.Errorf("authzen: decision %d was evaluated against a different snapshot than decision 0", i)
		}
		if in[i].RequestID != in[0].RequestID {
			return nil, fmt.Errorf("authzen: decision %d belongs to request %q, decision 0 to %q", i, in[i].RequestID, in[0].RequestID)
		}
	}
	if len(in) == 1 {
		return in[0], nil
	}
	worst := in[0]
	for _, d := range in {
		// Read with the two-value idiom, not bare. Every entry has already
		// passed Validate, which refuses an undeclared authorization, so an
		// unranked value cannot arrive today; a bare read would make that
		// safety depend on the order of two checks in one function, and the
		// zero rank here is the MOST restrictive, so a future reordering would
		// fail in the safe direction silently rather than loudly.
		got, gotOK := precedence[d.Authorization]
		held, heldOK := precedence[worst.Authorization]
		if !gotOK || !heldOK {
			return nil, fmt.Errorf("authzen: cannot order authorization %q against %q; one of them is not a declared outcome",
				d.Authorization, worst.Authorization)
		}
		if got < held {
			worst = d
		}
	}
	if worst.Authorization != AuthzPermit {
		out := *worst
		out.Determining = mergeDetermining(in)
		retrace(&out, in)
		return &out, nil
	}

	// Every entry permitted. The obligations of all entries apply, and the
	// approval clauses conjoin: an operation is not approved because one of
	// its preconditions was.
	out := *in[0]
	out.Determining = mergeDetermining(in)
	var obligations []Obligation
	var clauses []ApprovalClause
	var expiry time.Time
	sod := false
	for _, d := range in {
		obligations = append(obligations, d.Obligations...)
		if d.Approval == nil {
			continue
		}
		clauses = append(clauses, d.Approval.AllOf...)
		sod = sod || d.Approval.SeparationOfDuties
		if expiry.IsZero() || d.Approval.ExpiresAt.Before(expiry) {
			expiry = d.Approval.ExpiresAt
		}
	}
	// The union is RECOMPOSED rather than concatenated. Each entry's set was
	// already resolved per leaf against its own policies; concatenating two
	// resolved sets can put two transforms back on one leaf, and the weaker of
	// the two would then reach the enforcement point alongside the stronger.
	// That is strictly more permissive than the least permissive entry, which
	// is the one thing a meet may never be.
	recomposed := ComposeObligations(ComposeInput{
		Obligations:    obligations,
		Leaves:         opts.PayloadLeaves,
		PEP:            opts.PEP,
		ApprovalExpiry: expiry,
	})
	if recomposed.Denied {
		denied := *worst
		denied.Authorization = AuthzDeny
		denied.State = StateDeny
		denied.Reason = recomposed.Reason
		denied.Obligations = nil
		denied.Approval = nil
		denied.Determining = mergeDetermining(in)
		// This exit is reached only when EVERY entry permitted, so the entry
		// this copies from is a permit and its trace says so. Without
		// rebuilding, the combined denial would explain itself to every
		// audience as an allow, and would do it through a pointer shared with
		// the entry it came from.
		retrace(&denied, in)
		if err := denied.Validate(); err != nil {
			return nil, err
		}
		return &denied, nil
	}
	var dropped []string
	if len(recomposed.DroppedAdvisory) > 0 {
		// The same rule as inside one evaluation: an advisory contribution
		// that does not compose across the meet is dropped and recorded rather
		// than promoted into a denial.
		dropped = append(dropped, "advisory obligations were dropped across the meet because they do not compose with the required set: "+recomposed.DropDetail)
	}
	out.Obligations = recomposed.Obligations
	sortObligations(out.Obligations)
	if len(clauses) > 0 {
		req := &ApprovalRequirement{SeparationOfDuties: sod, ExpiresAt: expiry}
		seen := map[string]struct{}{}
		for _, c := range clauses {
			k := c.key()
			if _, dup := seen[k]; dup {
				continue
			}
			seen[k] = struct{}{}
			req.AllOf = append(req.AllOf, c.canonical())
		}
		sort.Slice(req.AllOf, func(i, j int) bool { return req.AllOf[i].key() < req.AllOf[j].key() })
		out.Approval = req
		out.Reason = ReasonApprovalRequired
	} else {
		out.Approval = nil
	}
	state, err := StateFor(out.Authorization, out.Approval != nil)
	if err != nil {
		return nil, err
	}
	out.State = state
	retrace(&out, in, dropped...)
	if err := out.Validate(); err != nil {
		return nil, err
	}
	return &out, nil
}

// retrace rebuilds the combined decision's trace from the combined decision.
//
// Copying the struct of the first entry carries its TRACE POINTER with it, so
// the combined decision would explain itself with the first hop's state,
// reason, obligations and expiry while carrying its own. Every audience reads
// the trace and nothing else, so the divergence is not cosmetic: an operator
// would be shown a permit for a challenge, and the obligation list of one hop
// for the obligations of all of them. Sharing the pointer also means mutating
// one mutates the other.
func retrace(out *Decision, in []*Decision, extraWarnings ...string) {
	var warnings []string
	var witnesses []Witness
	for _, d := range in {
		if d.Trace == nil {
			continue
		}
		warnings = append(warnings, d.Trace.Warnings...)
		witnesses = append(witnesses, d.Trace.Witnesses...)
	}
	t := &Trace{
		State:       out.State,
		Category:    CategoryFor(out.Reason),
		Reason:      out.Reason,
		Obligations: out.Obligations,
		Warnings:    dedupeSorted(append(warnings, extraWarnings...)),
	}
	determining := out.Determining
	t.Determining = &determining
	snapshot := out.Snapshot
	t.Snapshot = &snapshot
	if out.Approval != nil {
		expiry := out.Approval.ExpiresAt
		t.ApprovalExpiresAt = &expiry
	}
	if len(witnesses) > 0 {
		SortWitnesses(witnesses)
		t.Witnesses = witnesses
	}
	// The binding policy and the remediation are the WORST entry's, because
	// that is the entry that determined the combined outcome.
	for _, d := range in {
		if d.Authorization == out.Authorization && d.Reason == out.Reason && d.Trace != nil {
			t.BindingPolicy = d.Trace.BindingPolicy
			t.Remediation = d.Trace.Remediation
			t.NextBound = d.Trace.NextBound
			break
		}
	}
	out.Trace = t
}

func mergeDetermining(in []*Decision) Determining {
	var d Determining
	for _, e := range in {
		d.MatchedPermissions = append(d.MatchedPermissions, e.Determining.MatchedPermissions...)
		d.MatchedConstraints = append(d.MatchedConstraints, e.Determining.MatchedConstraints...)
		d.MatchedRequirement = append(d.MatchedRequirement, e.Determining.MatchedRequirement...)
		d.MatchedInspections = append(d.MatchedInspections, e.Determining.MatchedInspections...)
		d.Unknown = append(d.Unknown, e.Determining.Unknown...)
	}
	return d.Canonical()
}
