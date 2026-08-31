package registry

import (
	"fmt"
	"sort"
	"strings"
)

// Code is a stable machine identifier for a registration or query refusal.
//
// The two containment codes are spelled exactly as the source specification
// spells them, because they are the codes an author sees in the portal and the
// codes the authoring validator relays. A synonym here would be a second
// vocabulary for one condition.
type Code string

const (
	// CodePostureNotDeclared is a registration missing either posture axis.
	CodePostureNotDeclared Code = "POSTURE_NOT_DECLARED"
	// CodePostureNotPermitted is a posture axis carrying a value the
	// production profile refuses.
	CodePostureNotPermitted Code = "POSTURE_NOT_PERMITTED"
	// CodePostureCompatibilityRequired is a permissive Unmatched posture with
	// no live compatibility exception behind it.
	CodePostureCompatibilityRequired Code = "POSTURE_COMPATIBILITY_REQUIRED"
	// CodePostureCompatibilityIneligible is a permissive Unmatched posture on
	// an action whose risk classes make the exception unavailable.
	CodePostureCompatibilityIneligible Code = "POSTURE_COMPATIBILITY_INELIGIBLE"
	// CodeEffectNotDeclared is a risk class nobody filled in.
	CodeEffectNotDeclared Code = "EFFECT_NOT_DECLARED"
	// CodeIdentifierInvalid is a malformed or wrongly kinded identifier.
	CodeIdentifierInvalid Code = "IDENTIFIER_INVALID"
	// CodeAlreadyRegistered is a re-registration of an existing record.
	CodeAlreadyRegistered Code = "ALREADY_REGISTERED"
	// CodeDelegationDepthNotDeclared is an action with no positive maximum
	// delegation depth.
	CodeDelegationDepthNotDeclared Code = "DELEGATION_DEPTH_NOT_DECLARED"
	// CodeArgumentNotDeclared is a required argument absent from the schema.
	CodeArgumentNotDeclared Code = "ARGUMENT_NOT_DECLARED"
	// CodeTagNotDeclared is an action tag absent from the tag vocabulary.
	CodeTagNotDeclared Code = "TAG_NOT_DECLARED"
	// CodeTagGovernanceNotDeclared is a tag whose governance class is unset.
	CodeTagGovernanceNotDeclared Code = "TAG_GOVERNANCE_NOT_DECLARED"
	// CodeTagOwnerRequired is a governed tag with no owner.
	CodeTagOwnerRequired Code = "TAG_OWNER_REQUIRED"
	// CodeTagChangeUnapproved is a governed-tag change with no approval
	// reference or no reason.
	CodeTagChangeUnapproved Code = "TAG_CHANGE_UNAPPROVED"
	// CodeUnknownAction names an action identifier the catalog does not hold.
	CodeUnknownAction Code = "UNKNOWN_ACTION"
	// CodeUnknownTool names a tool identifier the catalog does not hold. This
	// is the source specification's UNKNOWN_TOOL.
	CodeUnknownTool Code = "UNKNOWN_TOOL"
	// CodeUnknownResourceType names a resource type the catalog does not hold.
	CodeUnknownResourceType Code = "UNKNOWN_RESOURCE_TYPE"
	// CodeUnknownRealm names a realm the catalog does not hold.
	CodeUnknownRealm Code = "UNKNOWN_REALM"
	// CodeToolSchemaDrift is a tool call whose registry version is not the
	// version the mapping was registered against.
	CodeToolSchemaDrift Code = "TOOL_SCHEMA_DRIFT"
	// CodeMappingProfileUnsupported is an unknown mapping profile or version.
	CodeMappingProfileUnsupported Code = "MAPPING_PROFILE_UNSUPPORTED"
	// CodeAliasCollision is one alias claimed by two actions or tools.
	CodeAliasCollision Code = "ALIAS_COLLISION"
	// CodeLevelNotDeclared is the source specification's LEVEL_NOT_DECLARED: a
	// policy reads an ancestor level the resource type does not declare.
	CodeLevelNotDeclared Code = "LEVEL_NOT_DECLARED"
	// CodeScopeRequiresRecursion is the source specification's
	// SCOPE_REQUIRES_RECURSION: a containment scope over a type whose
	// hierarchy admits no transitive closure.
	CodeScopeRequiresRecursion Code = "SCOPE_REQUIRES_RECURSION"
	// CodeRecursionNotDeclared is a resource type whose recursion flag is
	// unset.
	CodeRecursionNotDeclared Code = "RECURSION_NOT_DECLARED"
	// CodeMaxDepthInvalid is a recursive type with no positive maximum depth,
	// or a non-recursive type carrying one.
	CodeMaxDepthInvalid Code = "MAX_DEPTH_INVALID"
	// CodeCapabilityVersionInvalid is an advertised or required capability
	// with a non-positive version.
	CodeCapabilityVersionInvalid Code = "CAPABILITY_VERSION_INVALID"
	// CodeCapabilityMissing is a mandatory obligation no named enforcement
	// point advertises at the required type and version.
	CodeCapabilityMissing Code = "PEP_CAPABILITY_MISSING"
	// CodeEditionNotDeclared is a PEP record whose edition is unset.
	CodeEditionNotDeclared Code = "EDITION_NOT_DECLARED"
	// CodeCompatibilityIncomplete is a compatibility exception missing an
	// owner, a metric, a removal issue or an expiry.
	CodeCompatibilityIncomplete Code = "COMPATIBILITY_INCOMPLETE"
	// CodeCompatibilityExpired is an exception whose expiry has passed.
	CodeCompatibilityExpired Code = "COMPATIBILITY_EXPIRED"
	// CodeObligationTypeUndeclared is a capability or requirement naming an
	// obligation type the contract does not declare.
	CodeObligationTypeUndeclared Code = "OBLIGATION_TYPE_UNDECLARED"
)

// Finding is one reason a registration, a validation or a query refused.
//
// Findings are returned as a complete, ordered list rather than as a first
// error. An operator fixing a registry entry needs every reason it is being
// refused, and a first-error interface turns one fix into a queue of them.
type Finding struct {
	// Code is the stable machine identifier.
	Code Code `json:"code"`
	// Severity decides whether the finding blocks.
	Severity Severity `json:"severity"`
	// Subject names the record the finding is about.
	Subject string `json:"subject"`
	// Message is the sentence a portal renders verbatim.
	Message string `json:"message"`
}

// String renders the finding for a test failure or a log line.
func (f Finding) String() string {
	return fmt.Sprintf("%s [%s] %s: %s", f.Code, f.Severity, f.Subject, f.Message)
}

// Findings is an ordered finding list.
type Findings []Finding

// Sorted returns the findings in a stable order: subject, then code, then
// message. Registration walks maps, and an unordered list would make two runs
// over the same catalog produce two different reports.
func (f Findings) Sorted() Findings {
	out := append(Findings(nil), f...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Subject != out[j].Subject {
			return out[i].Subject < out[j].Subject
		}
		if out[i].Code != out[j].Code {
			return out[i].Code < out[j].Code
		}
		return out[i].Message < out[j].Message
	})
	return out
}

// Blocking reports whether any finding is at or above SeverityError.
//
// An undeclared severity on a finding makes this return true. That is the only
// safe reading: the alternative is a finding whose severity nobody can order
// being treated as advisory, which is a refusal that silently became a warning.
func (f Findings) Blocking() bool {
	for _, one := range f {
		atLeast, err := one.Severity.AtLeast(SeverityError)
		if err != nil {
			return true
		}
		if atLeast {
			return true
		}
	}
	return false
}

// Err returns an error naming every blocking finding, or nil.
func (f Findings) Err() error {
	if !f.Blocking() {
		return nil
	}
	lines := make([]string, 0, len(f))
	for _, one := range f.Sorted() {
		lines = append(lines, "  "+one.String())
	}
	return fmt.Errorf("registry: %d finding(s):\n%s", len(f), strings.Join(lines, "\n"))
}

// Has reports whether the list carries a finding with this code.
func (f Findings) Has(c Code) bool {
	for _, one := range f {
		if one.Code == c {
			return true
		}
	}
	return false
}

// errorf appends a blocking finding.
func (f Findings) errorf(c Code, subject, format string, args ...any) Findings {
	return append(f, Finding{Code: c, Severity: SeverityError, Subject: subject,
		Message: fmt.Sprintf(format, args...)})
}
