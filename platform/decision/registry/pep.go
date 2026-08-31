package registry

import (
	"fmt"
	"sort"

	"axonflow/platform/decision/contract"
)

// enterpriseOnlyFamilies are the obligation families a community enforcement
// point cannot discharge.
//
// Approval is the one the feature matrix settles: workflow approval gates are
// Enterprise, the community hitl.Service.CreateApprovalRequest is a stub that
// returns ErrHITLApprovalDisabledByTier, and every agent-plane call site is
// guarded on the deployment mode besides. Disclosure, audit and notification
// are universal ("Security is universal" in the matrix), and routing, step-up
// and budget have no community-versus-Enterprise split declared anywhere this
// package can cite.
//
// The brief's rule for an ambiguous family is Enterprise plus a flag. Nothing
// here is ambiguous in the direction that would need it: a family absent from
// this map is one where a community enforcement point may advertise the
// capability, and advertising is not the same as being believed, because a
// capability still has to be declared on the record before it counts.
var enterpriseOnlyFamilies = map[contract.ObligationFamily]bool{
	contract.FamilyApproval: true,
}

// EnterpriseOnlyFamilies returns the Enterprise-only families in a stable
// order.
func EnterpriseOnlyFamilies() []contract.ObligationFamily {
	var out []contract.ObligationFamily
	for _, f := range contract.AllObligationFamilies() {
		if enterpriseOnlyFamilies[f] {
			out = append(out, f)
		}
	}
	return out
}

// PEPRecord is one registered Policy Enforcement Point.
//
// The record exists so that "does this enforcement point understand this
// obligation" has an answer BEFORE a decision is issued. ADR-065 invariant 8
// makes an unsupported mandatory obligation a deny, and a deny nobody can
// compute is an aspiration.
type PEPRecord struct {
	// ID is the enforcement point identifier a decision names.
	ID string `json:"id"`
	// Realm is the trust realm this enforcement point authenticates as. It
	// must be a realm the catalog declares: an enforcement point resolving in
	// an undeclared realm is the same unknown-surface condition as a principal
	// from one, and admitting it would let a plane authenticate as a realm no
	// policy can be scoped to.
	Realm string `json:"realm"`
	// Edition is the build and licence class of this enforcement point.
	Edition Edition `json:"edition"`
	// Capabilities is the exact set of obligation types and versions this
	// enforcement point can discharge.
	//
	// An EMPTY set is a legitimate, meaningful declaration: a dry-run
	// simulation surface enforces nothing and discharges nothing. It is not
	// the same as no record at all, and the two must not share a
	// representation. See CapabilityStatus for why that distinction is the
	// correction rather than a nicety.
	Capabilities []contract.Capability `json:"capabilities"`
	// Description is what this enforcement point is, for the operator reading
	// a capability refusal.
	Description string `json:"description,omitempty"`
}

// Validate checks one enforcement point record.
func (p PEPRecord) Validate() Findings {
	var out Findings
	subject := p.ID
	if p.ID == "" {
		subject = "(empty pep id)"
		out = out.errorf(CodeIdentifierInvalid, subject, "an enforcement point record carries an empty identifier")
	}
	if !p.Edition.IsValid() {
		out = out.errorf(CodeEditionNotDeclared, subject,
			"edition is %s; whether this enforcement point carries the Enterprise-only obligation families is a fact about it, not about the process holding this registry",
			p.Edition)
	}
	out = append(out, validateCapabilities(subject, "advertised capability", p.Capabilities)...)
	if p.Edition == EditionCommunity {
		for _, c := range sortedCapabilities(p.Capabilities) {
			family, err := contract.FamilyOf(c.Type)
			if err != nil {
				// The undeclared type is already reported by
				// validateCapabilities; reporting it twice would make one
				// typo look like two defects.
				continue
			}
			if enterpriseOnlyFamilies[family] {
				out = out.errorf(CodeCapabilityMissing, subject,
					"a community enforcement point advertises %q, whose family %q is Enterprise-only; over-advertising is the dangerous direction, because the decision is issued on the strength of the claim",
					c.Type, family)
			}
		}
	}
	return out
}

// CapabilityStatus is why a capability check answered as it did.
//
// The zero value is invalid and every non-Supported member refuses, so a status
// this package has not declared yet cannot admit an obligation.
//
// NoRecord and DeclaredNone are separate members on purpose, and separating
// them is a correction rather than a refinement. The existing #2958 fulfillment
// handshake in platform/shared/pep carries its capability list in an omitempty
// field, so an enforcement point advertising an empty set is byte-identical on
// the wire to one that advertised nothing, and the contract reads both as
// "legacy caller" and emits the obligation anyway. That is defensible for
// redaction, where the enforcement point fails closed on an obligation it
// cannot fulfil, and it is not defensible for audit or notification, where
// failing to discharge is silent. Under ADR-065 both must deny, and they must
// deny with different explanations: one enforcement point never told us
// anything, the other told us it can do nothing.
type CapabilityStatus int

const (
	// CapabilityStatusUnspecified is the zero value and is never valid.
	CapabilityStatusUnspecified CapabilityStatus = iota
	// CapabilitySupported means this exact type at this exact version is
	// advertised.
	CapabilitySupported
	// CapabilityNoRecord means no enforcement point is registered under that
	// identifier. It never advertised anything, which is not the same as
	// advertising nothing.
	CapabilityNoRecord
	// CapabilityDeclaredNone means the enforcement point is registered and
	// declares an empty capability set.
	CapabilityDeclaredNone
	// CapabilityTypeUnsupported means the enforcement point advertises other
	// obligation types but not this one.
	CapabilityTypeUnsupported
	// CapabilityVersionUnsupported means it advertises this type at other
	// versions only. Matching is exact: an enforcement point claiming v1
	// cannot be assumed to implement v2 semantics, and a rolling deploy that
	// introduces a new transform must not fail open on the half that has not
	// caught up.
	CapabilityVersionUnsupported
	// CapabilityObligationUnversioned means the obligation itself declares a
	// non-positive schema version, so there is nothing to match against.
	CapabilityObligationUnversioned
)

// String renders the status.
func (c CapabilityStatus) String() string {
	switch c {
	case CapabilitySupported:
		return "supported"
	case CapabilityNoRecord:
		return "no_record"
	case CapabilityDeclaredNone:
		return "declared_none"
	case CapabilityTypeUnsupported:
		return "type_unsupported"
	case CapabilityVersionUnsupported:
		return "version_unsupported"
	case CapabilityObligationUnversioned:
		return "obligation_unversioned"
	case CapabilityStatusUnspecified:
		return "unspecified"
	default:
		return fmt.Sprintf("CapabilityStatus(%d)", int(c))
	}
}

// IsValid reports whether the status is one of the declared members.
func (c CapabilityStatus) IsValid() bool {
	switch c {
	case CapabilitySupported, CapabilityNoRecord, CapabilityDeclaredNone,
		CapabilityTypeUnsupported, CapabilityVersionUnsupported, CapabilityObligationUnversioned:
		return true
	case CapabilityStatusUnspecified:
		return false
	default:
		return false
	}
}

// AllCapabilityStatuses returns every declared status in a stable order.
func AllCapabilityStatuses() []CapabilityStatus {
	return []CapabilityStatus{
		CapabilitySupported, CapabilityNoRecord, CapabilityDeclaredNone,
		CapabilityTypeUnsupported, CapabilityVersionUnsupported, CapabilityObligationUnversioned,
	}
}

// CapabilityCheck is the result of asking whether an enforcement point can
// discharge one obligation.
type CapabilityCheck struct {
	Status CapabilityStatus `json:"status"`
	// PEP is the enforcement point that was asked.
	PEP string `json:"pep"`
	// Obligation is the type that was asked about.
	Obligation contract.ObligationType `json:"obligation"`
	// Version is the version that was asked about.
	Version int `json:"version"`
	// Detail explains the answer for the operator audience.
	Detail string `json:"detail"`
}

// Supported reports whether the obligation may be issued to this enforcement
// point.
//
// Membership against the single admitting member, not a comparison against a
// refusal. A status added later without a decision about it therefore refuses,
// which is the direction that does not turn a new enumeration member into a
// silent permit.
func (c CapabilityCheck) Supported() bool { return c.Status == CapabilitySupported }

// checkCapability answers for one record, or for a missing one.
//
// found is passed rather than inferred from a nil record, because a nil record
// and a record with no capabilities are exactly the two states this function
// exists to tell apart.
func checkCapability(pepID string, rec PEPRecord, found bool, o contract.Obligation) CapabilityCheck {
	out := CapabilityCheck{PEP: pepID, Obligation: o.Type, Version: o.SchemaVersion}
	if !found {
		out.Status = CapabilityNoRecord
		out.Detail = fmt.Sprintf(
			"no enforcement point is registered as %q, so nothing has advertised the decision profile; ADR-065 invariant 12 refuses the request rather than interpreting it partially",
			pepID)
		return out
	}
	if o.SchemaVersion <= 0 {
		out.Status = CapabilityObligationUnversioned
		out.Detail = fmt.Sprintf(
			"obligation %q declares schema version %d; capability matching is exact, so an unset version would be satisfied only by an unset capability",
			o.Type, o.SchemaVersion)
		return out
	}
	if len(rec.Capabilities) == 0 {
		out.Status = CapabilityDeclaredNone
		out.Detail = fmt.Sprintf(
			"enforcement point %q advertises an empty capability set, which is a declaration that it discharges nothing; it is registered, so this is not a missing record",
			pepID)
		return out
	}
	var versions []int
	for _, c := range rec.Capabilities {
		if c.Type != o.Type {
			continue
		}
		if c.Version == o.SchemaVersion {
			out.Status = CapabilitySupported
			out.Detail = fmt.Sprintf("enforcement point %q advertises %q at version %d", pepID, o.Type, o.SchemaVersion)
			return out
		}
		versions = append(versions, c.Version)
	}
	if len(versions) > 0 {
		sort.Ints(versions)
		out.Status = CapabilityVersionUnsupported
		out.Detail = fmt.Sprintf(
			"enforcement point %q advertises %q at version(s) %v, not at %d; version matching is exact, because a build claiming one version cannot be assumed to implement another's semantics",
			pepID, o.Type, versions, o.SchemaVersion)
		return out
	}
	out.Status = CapabilityTypeUnsupported
	out.Detail = fmt.Sprintf("enforcement point %q advertises %d capability type(s), none of them %q",
		pepID, len(distinctTypes(rec.Capabilities)), o.Type)
	return out
}

func distinctTypes(caps []contract.Capability) []contract.ObligationType {
	seen := map[contract.ObligationType]bool{}
	var out []contract.ObligationType
	for _, c := range caps {
		if seen[c.Type] {
			continue
		}
		seen[c.Type] = true
		out = append(out, c.Type)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func sortedCapabilities(caps []contract.Capability) []contract.Capability {
	out := append([]contract.Capability(nil), caps...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].Version < out[j].Version
	})
	return out
}

// clone returns a deep copy of the record. See ActionRecord.clone.
//
// The capability slice is copied even when it is empty, and it stays non-nil in
// that case: a declared-empty set that came back as nil would round-trip through
// JSON as an absent field, which is precisely the collapse CapabilityStatus
// exists to prevent.
func (p PEPRecord) clone() PEPRecord {
	out := p
	out.Capabilities = make([]contract.Capability, len(p.Capabilities))
	copy(out.Capabilities, p.Capabilities)
	return out
}

// Profile projects the record into the enforcement profile the merged engine
// consults, so the set a decision is composed against and the set the registry
// governs are one table rendered twice.
func (p PEPRecord) Profile() *contract.PEPProfile {
	return &contract.PEPProfile{ID: p.ID, Capabilities: sortedCapabilities(p.Capabilities)}
}
