package registry

import (
	"fmt"
	"sort"

	"axonflow/platform/decision/contract"
)

// MappingProfile is the versioned adapter that projects a raw invocation into
// the canonical authorization request.
//
// ADR-065's standards position: COAZ Draft 1 and COAZ-MCP Draft 1 are versioned
// adapters behind capability negotiation, and unknown profile fields, mappings,
// obligations or response contexts fail closed. A profile is therefore a
// declared name at a declared version, not a free string.
type MappingProfile struct {
	Name    string `json:"name"`
	Version int    `json:"version"`
}

// String renders the profile.
func (m MappingProfile) String() string { return fmt.Sprintf("%s/v%d", m.Name, m.Version) }

// Mapping profile names, spelled as ADR-065's standards table spells them.
const (
	// MappingAuthZEN is the OpenID AuthZEN Authorization API profile.
	MappingAuthZEN = "authzen"
	// MappingCOAZ is the COAZ profile for connector and HTTP surfaces.
	MappingCOAZ = "coaz"
	// MappingCOAZMCP is the COAZ-MCP profile for Model Context Protocol tools.
	MappingCOAZMCP = "coaz-mcp"
)

// supportedMappingProfiles is the accepted set. A caller selecting a profile
// outside it is refused rather than defaulted onto the nearest one: ADR-065
// accepts a COAZ profile "only when a caller selects a supported profile
// version", and picking a neighbour on the caller's behalf is precisely the
// partial interpretation invariant 12 forbids.
var supportedMappingProfiles = map[string]map[int]bool{
	MappingAuthZEN: {1: true},
	MappingCOAZ:    {1: true},
	MappingCOAZMCP: {1: true},
}

// SupportedMappingProfiles returns every accepted profile in a stable order.
//
// The versions are collected and sorted rather than counted up from one. A loop
// bounded by len() enumerates 1..n and would silently omit a profile supported
// at versions 1 and 3, which is the shape a deprecated middle version takes.
func SupportedMappingProfiles() []MappingProfile {
	var out []MappingProfile
	for _, name := range []string{MappingAuthZEN, MappingCOAZ, MappingCOAZMCP} {
		versions := make([]int, 0, len(supportedMappingProfiles[name]))
		for v, ok := range supportedMappingProfiles[name] {
			if ok {
				versions = append(versions, v)
			}
		}
		sort.Ints(versions)
		for _, v := range versions {
			out = append(out, MappingProfile{Name: name, Version: v})
		}
	}
	return out
}

// ToolRecord is one concrete callable surface: a connector operation or an MCP
// tool, at one schema version, mapped onto exactly one canonical action.
type ToolRecord struct {
	// ID is the tool identifier a request's ToolCall carries.
	ID contract.ID `json:"id"`
	// Action is the canonical action this tool resolves to. It is mandatory:
	// a tool that resolves to nothing is an ungoverned surface, and ADR-065
	// requires every governed operation to resolve to one registered action or
	// fail closed.
	Action contract.ID `json:"action"`
	// Connector names the connector or server the tool belongs to.
	Connector string `json:"connector"`
	// SchemaVersion is the tool input-schema version the mapping was
	// registered against. A call declaring a different version is schema drift.
	SchemaVersion int64 `json:"schema_version"`
	// Mapping is the versioned adapter profile.
	Mapping MappingProfile `json:"mapping"`
	// Aliases are prior names for this surface. They resolve to the same tool,
	// and the catalog refuses a collision.
	Aliases []string `json:"aliases,omitempty"`
}

// Validate checks the record in isolation.
func (t ToolRecord) Validate() Findings {
	subject := t.ID.String()
	var out Findings
	if t.ID.Kind != contract.KindTool {
		out = out.errorf(CodeIdentifierInvalid, subject,
			"a tool record carries a tool identifier, got kind %q", t.ID.Kind)
	}
	if err := t.ID.Validate(); err != nil {
		out = out.errorf(CodeIdentifierInvalid, subject, "%v", err)
	}
	if t.Action.Kind != contract.KindAction {
		out = out.errorf(CodeIdentifierInvalid, subject,
			"a tool resolves to an action identifier, got kind %q", t.Action.Kind)
	} else if err := t.Action.Validate(); err != nil {
		out = out.errorf(CodeIdentifierInvalid, subject, "the action it resolves to: %v", err)
	}
	if t.SchemaVersion <= 0 {
		out = out.errorf(CodeToolSchemaDrift, subject,
			"schema version is %d; a non-positive version cannot be compared against a call, so drift would be undetectable", t.SchemaVersion)
	}
	if !supportedMappingProfiles[t.Mapping.Name][t.Mapping.Version] {
		out = out.errorf(CodeMappingProfileUnsupported, subject,
			"mapping profile %s is not supported; the accepted profiles are %v and an unsupported one fails closed rather than falling back to a neighbour",
			t.Mapping, SupportedMappingProfiles())
	}
	return out
}

// clone returns a deep copy of the record. See ActionRecord.clone.
func (t ToolRecord) clone() ToolRecord {
	out := t
	out.Aliases = append([]string(nil), t.Aliases...)
	return out
}

// ResolutionStatus is the outcome of resolving a tool call against the catalog.
//
// The zero value is invalid, so a resolution nobody filled in cannot read as a
// success. Resolved is the ONLY member that admits the call.
type ResolutionStatus int

const (
	// ResolutionUnspecified is the zero value and is never valid.
	ResolutionUnspecified ResolutionStatus = iota
	// ResolutionResolved means the tool is registered at the called version.
	ResolutionResolved
	// ResolutionUnknownTool means no record. This is the source
	// specification's Phase 0.2 Deny(UNKNOWN_TOOL).
	ResolutionUnknownTool
	// ResolutionSchemaDrift means the tool is registered at a different schema
	// version than the call declares, so the registered mapping does not
	// describe the call's arguments.
	ResolutionSchemaDrift
	// ResolutionActionMissing means the tool resolves to an action the catalog
	// does not hold. It is separated from UnknownTool because the two need
	// different fixes: one is an unregistered surface, the other is a registry
	// whose own binding is broken.
	ResolutionActionMissing
)

// String renders the status.
func (s ResolutionStatus) String() string {
	switch s {
	case ResolutionResolved:
		return "resolved"
	case ResolutionUnknownTool:
		return "unknown_tool"
	case ResolutionSchemaDrift:
		return "schema_drift"
	case ResolutionActionMissing:
		return "action_missing"
	case ResolutionUnspecified:
		return "unspecified"
	default:
		return fmt.Sprintf("ResolutionStatus(%d)", int(s))
	}
}

// IsValid reports whether the status is one of the declared members.
func (s ResolutionStatus) IsValid() bool {
	switch s {
	case ResolutionResolved, ResolutionUnknownTool, ResolutionSchemaDrift, ResolutionActionMissing:
		return true
	case ResolutionUnspecified:
		return false
	default:
		return false
	}
}

// Resolution is the result of resolving one tool call.
type Resolution struct {
	Status ResolutionStatus `json:"status"`
	// Action is the canonical action, set only when Status is Resolved.
	Action contract.ID `json:"action,omitempty"`
	// Reason is the decision reason code a refusal maps to. It is one of the
	// codes contract already declares: a registry-specific reason code would
	// fork the normalized vocabulary that ADR-065 gate 15 requires every plane
	// to share.
	Reason contract.ReasonCode `json:"reason,omitempty"`
	// Detail explains the refusal for the operator audience.
	Detail string `json:"detail,omitempty"`
}

// Admits reports whether the call may proceed.
//
// It is membership against the one admitting member rather than a comparison
// against a refusal, so a status this package has not declared yet refuses.
func (r Resolution) Admits() bool { return r.Status == ResolutionResolved }
