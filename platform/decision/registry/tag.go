package registry

import (
	"fmt"
	"sort"
	"time"

	"axonflow/platform/decision/contract"
)

// TagGovernance is whether a tag is part of the governed vocabulary.
//
// It is three-valued for the reason the source specification names in section
// 17.2: tags are an ungoverned policy channel BY DEFAULT, and a default is
// exactly what a zero-valued bool would reinstate. A tag whose governance
// nobody declared would register as ungoverned and could then be edited without
// review while a constraint selected on it.
type TagGovernance int

const (
	// TagGovernanceUnspecified is the zero value and is never valid.
	TagGovernanceUnspecified TagGovernance = iota
	// TagGovernanceUngoverned is a descriptive tag no policy selects on.
	TagGovernanceUngoverned
	// TagGovernanceGoverned is a tag policies select on. Changing it is a
	// policy edit and goes through the policy-change path.
	TagGovernanceGoverned
)

// String renders the governance class.
func (g TagGovernance) String() string {
	switch g {
	case TagGovernanceUngoverned:
		return "ungoverned"
	case TagGovernanceGoverned:
		return "governed"
	case TagGovernanceUnspecified:
		return "unspecified"
	default:
		return fmt.Sprintf("TagGovernance(%d)", int(g))
	}
}

// IsValid reports whether the class is one of the declared members.
func (g TagGovernance) IsValid() bool {
	switch g {
	case TagGovernanceUngoverned, TagGovernanceGoverned:
		return true
	case TagGovernanceUnspecified:
		return false
	default:
		return false
	}
}

// Governed reports whether the class is an explicit governed.
func (g TagGovernance) Governed() bool { return g == TagGovernanceGoverned }

// TagRecord is one entry in the tag vocabulary.
type TagRecord struct {
	// Tag is the literal a policy's action selector carries.
	Tag string `json:"tag"`
	// Governance decides whether a change to this tag needs the policy-change
	// path.
	Governance TagGovernance `json:"governance"`
	// Owner is the team a governed-tag alarm pages. It is required for a
	// governed tag: an alarm with no owner is a log line.
	Owner string `json:"owner,omitempty"`
	// Description is what the tag means, for the author choosing whether to
	// select on it.
	Description string `json:"description"`
}

// Validate checks one vocabulary entry.
func (t TagRecord) Validate() Findings {
	var out Findings
	if t.Tag == "" {
		out = out.errorf(CodeTagNotDeclared, "(empty tag)", "a tag vocabulary entry carries an empty tag")
	}
	if !t.Governance.IsValid() {
		out = out.errorf(CodeTagGovernanceNotDeclared, t.Tag,
			"governance class is %s; a tag is an ungoverned policy channel by default, so the class is declared rather than defaulted",
			t.Governance)
	}
	if t.Governance.Governed() && t.Owner == "" {
		out = out.errorf(CodeTagOwnerRequired, t.Tag,
			"a governed tag names an owner, because a governed-tag change raises an alarm and an alarm with nobody to page is a log line")
	}
	return out
}

// TagChange is one edit to an action's governed vocabulary.
//
// A tag change is modelled as an operation with its own review evidence rather
// than as a field somebody overwrites, because a policy selects actions by tag:
// changing an action's tags moves it into and out of the reach of policies
// nobody edited. The source specification's section 17.2 makes the same point
// and requires the policy-change path.
type TagChange struct {
	// Action is the action whose vocabulary changes.
	Action contract.ID `json:"action"`
	// Add and Remove are the tags entering and leaving. Both must already be
	// declared in the vocabulary: a change cannot invent a tag.
	Add    []string `json:"add,omitempty"`
	Remove []string `json:"remove,omitempty"`
	// Actor is who made the change.
	Actor string `json:"actor"`
	// Reason is why.
	Reason string `json:"reason"`
	// ApprovalRef is the approval record for the policy-change path. It is
	// required whenever a GOVERNED tag is added or removed, and refused as
	// unnecessary for nothing: an ungoverned change may carry one.
	ApprovalRef string `json:"approval_ref,omitempty"`
	// At is when the change was applied.
	At time.Time `json:"at"`
}

// EventCode names a registry event.
type EventCode string

const (
	// EventActionRegistered records a new action.
	EventActionRegistered EventCode = "ACTION_REGISTERED"
	// EventToolRegistered records a new tool.
	EventToolRegistered EventCode = "TOOL_REGISTERED"
	// EventPEPRegistered records a new enforcement point.
	EventPEPRegistered EventCode = "PEP_REGISTERED"
	// EventGovernedTagAdded records a governed tag entering an action's
	// vocabulary. It is an alarm: every permission selecting on that tag now
	// reaches an action it did not reach, with no policy document edited.
	EventGovernedTagAdded EventCode = "GOVERNED_TAG_ADDED"
	// EventGovernedTagRemoved records a governed tag leaving an action's
	// vocabulary. It is an alarm for the mirror-image reason, and it is the
	// more dangerous of the two: every constraint selecting on that tag stops
	// matching, silently and with nothing to see in any policy.
	EventGovernedTagRemoved EventCode = "GOVERNED_TAG_REMOVED"
	// EventTagChanged records an ungoverned tag change.
	EventTagChanged EventCode = "TAG_CHANGED"
	// EventCompatibilityRegistered records a temporary compatibility
	// exception. It is an alarm because it is the only sanctioned deviation
	// from default deny.
	EventCompatibilityRegistered EventCode = "COMPATIBILITY_REGISTERED"
)

// Event is one recorded registry change.
type Event struct {
	Code     EventCode `json:"code"`
	Severity Severity  `json:"severity"`
	Subject  string    `json:"subject"`
	Detail   string    `json:"detail"`
	At       time.Time `json:"at"`
}

// String renders the event.
func (e Event) String() string {
	return fmt.Sprintf("%s [%s] %s: %s", e.Code, e.Severity, e.Subject, e.Detail)
}

// Events is an ordered event log.
type Events []Event

// Alarms returns the events at or above SeverityAlarm, in order.
//
// An event whose severity is not a declared member is INCLUDED, for the same
// reason Findings.Blocking treats one as blocking: an alarm that cannot be
// ordered must not be filtered out of the list somebody pages from.
func (e Events) Alarms() Events {
	var out Events
	for _, one := range e {
		atLeast, err := one.Severity.AtLeast(SeverityAlarm)
		if err != nil || atLeast {
			out = append(out, one)
		}
	}
	return out
}

// Has reports whether the log carries an event with this code and subject.
func (e Events) Has(code EventCode, subject string) bool {
	for _, one := range e {
		if one.Code == code && one.Subject == subject {
			return true
		}
	}
	return false
}

// tagDelta is the resolved effect of a change on one action, computed against
// the action's CURRENT tags so that removing a tag the action never carried is
// not reported as a removal.
type tagDelta struct {
	added   []string
	removed []string
}

func computeTagDelta(current, add, remove []string) tagDelta {
	have := map[string]bool{}
	for _, t := range current {
		have[t] = true
	}
	var d tagDelta
	for _, t := range sortedStrings(add) {
		if !have[t] {
			d.added = append(d.added, t)
		}
	}
	// A tag both added and removed by one change is a contradiction rather
	// than a no-op, and the catalog refuses it before this is reached. Removal
	// is computed from the same current set so the two lists cannot overlap by
	// accident.
	for _, t := range sortedStrings(remove) {
		if have[t] {
			d.removed = append(d.removed, t)
		}
	}
	return d
}

// applyTagDelta returns the new tag set.
func applyTagDelta(current []string, d tagDelta) []string {
	set := map[string]bool{}
	for _, t := range current {
		set[t] = true
	}
	for _, t := range d.added {
		set[t] = true
	}
	for _, t := range d.removed {
		delete(set, t)
	}
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}
