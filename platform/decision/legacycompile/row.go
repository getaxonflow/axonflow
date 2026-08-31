package legacycompile

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// RawRow is one captured legacy row, LOSSLESSLY.
//
// Every column arrives as raw JSON keyed by column name, never as a positional
// list. That is deliberate: the legacy readers scan positionally into typed
// destinations, which is what makes a NULL in a non-nullable destination drop
// the row (#3397), and a compiler that inherited the same positional scan
// would inherit the same blindness. Capturing by name means the compiler can
// MODEL the legacy scan - and report which rows it would have eaten - instead
// of being subject to it.
type RawRow struct {
	// Table is "static_policies" or "dynamic_policies".
	Table string `json:"table"`
	// OrgScope is the org_id the capture read this row under.
	//
	// It is part of the row's identity: the compiler builds one document set
	// per plane per org, because the runtime reads under strict-equality RLS
	// and one org's policies never reach another org's requests.
	//
	// Under core/018's `org_id = get_current_org_id()` a row is visible in
	// exactly ONE scoped pass, so a capture built from `SELECT DISTINCT
	// org_id` cannot legitimately contain the same physical row twice. If one
	// ever does, Compile REFUSES it by name rather than letting two identical
	// policy identifiers reach the bundle, where pdp would reject them late
	// and without naming the capture as the cause.
	OrgScope string `json:"org_scope"`
	// Columns are the row's columns by name. A NULL column is present with a
	// JSON null value; an ABSENT key means the capture did not select the
	// column, which is a capture defect and is reported as one.
	Columns map[string]json.RawMessage `json:"columns"`
	// CaptureError is set when the capture itself could not read the row. It
	// is carried rather than dropped so that a capture-side failure produces a
	// Record like everything else.
	CaptureError string `json:"capture_error,omitempty"`
}

func (r RawRow) has(col string) bool {
	_, ok := r.Columns[col]
	return ok
}

// isNull reports whether a PRESENT column holds SQL NULL. An absent column is
// not null, it is missing, and the two are never conflated.
func (r RawRow) isNull(col string) bool {
	raw, ok := r.Columns[col]
	if !ok {
		return false
	}
	return string(raw) == "null"
}

func (r RawRow) stringOr(col, def string) string {
	raw, ok := r.Columns[col]
	if !ok || string(raw) == "null" {
		return def
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	// A non-string JSON value still has a faithful text rendering; returning
	// it keeps a malformed capture visible instead of turning it into "".
	return strings.Trim(string(raw), `"`)
}

func (r RawRow) intOr(col string, def int) (int, bool) {
	raw, ok := r.Columns[col]
	if !ok || string(raw) == "null" {
		return def, false
	}
	var n json.Number
	if err := json.Unmarshal(raw, &n); err == nil {
		if v, err := strconv.Atoi(n.String()); err == nil {
			return v, true
		}
	}
	return def, false
}

func (r RawRow) boolOr(col string, def bool) (bool, bool) {
	raw, ok := r.Columns[col]
	if !ok || string(raw) == "null" {
		return def, false
	}
	var b bool
	if err := json.Unmarshal(raw, &b); err == nil {
		return b, true
	}
	return def, false
}

// jsonOr returns a column's raw JSON, or nil when absent or NULL.
func (r RawRow) jsonOr(col string) json.RawMessage {
	raw, ok := r.Columns[col]
	if !ok || string(raw) == "null" {
		return nil
	}
	return raw
}

// StaticRow is one static_policies row, carrying BOTH read paths' columns.
//
// Presence is tracked separately from value for every column whose NULLability
// changes what the legacy readers do. `ActionRequest == ""` and
// `action_request IS NULL` are different facts: the first is a stored empty
// string, the second is what makes GetActionForPhase fall through to its
// category/severity table. Collapsing them would make the compiler agree with
// the legacy engine by accident on the rows where it matters most.
type StaticRow struct {
	ID       string
	PolicyID string
	Name     string
	Category string
	Pattern  string
	Severity string

	// Tier, TenantID, Priority, Enabled are DEFAULTed but NULLable in
	// migrations/core/010 and 030. Their NULLability is what the legacy scan
	// model turns into a dropped row.
	Tier         string
	TierNull     bool
	TenantID     string
	TenantIDNull bool
	OrgID        string
	OrgIDNull    bool
	Priority     int
	PriorityNull bool
	Enabled      bool
	EnabledNull  bool

	// Runtime read path columns.
	Phase              Phase
	PhaseNull          bool
	ActionRequest      string
	ActionRequestNull  bool
	ActionResponse     string
	ActionResponseNull bool

	// Effective read path column. NOT NULL in the schema, so an absence here
	// is a capture defect rather than a data state.
	Action     string
	ActionNull bool

	SegmentID     string
	SegmentIDNull bool
	Version       int
	VersionNull   bool
	Metadata      json.RawMessage
	DeletedAt     string
	CreatedAt     string
	CreatedAtNull bool
	UpdatedAt     string
	UpdatedAtNull bool
}

// DynamicRow is one dynamic_policies row.
type DynamicRow struct {
	ID           string
	PolicyID     string
	Name         string
	PolicyType   string
	Category     string
	CategoryNull bool

	Tier         string
	TierNull     bool
	TenantID     string
	TenantIDNull bool
	OrgID        string
	OrgIDNull    bool
	Priority     int
	PriorityNull bool
	Enabled      bool
	EnabledNull  bool

	RiskThreshold     float64
	RiskThresholdNull bool
	Version           int
	VersionNull       bool
	Description       string
	DescriptionNull   bool

	// Conditions and Actions are JSONB and NOT NULL. They are kept as raw
	// JSON so that a malformed document is a compilation reason rather than a
	// decode panic - and, critically, so that a row whose JSONB will not parse
	// still produces a Record.
	Conditions json.RawMessage
	Actions    json.RawMessage

	SegmentID     string
	SegmentIDNull bool
	Metadata      json.RawMessage
	CreatedAt     string
	CreatedAtNull bool
}

// staticColumns is every column the compiler needs to see for a
// static_policies row, across BOTH read paths.
//
// It is exported through RequiredColumns, and the capture is verified against
// it rather than generated from it: the script selects `row_to_json(t)`, so a
// column added by a later migration arrives without anybody remembering to add
// it, and a capture that is nonetheless missing something the compiler needs is
// reported as capture_incomplete rather than compiled around.
var staticColumns = []string{
	"id", "policy_id", "name", "category", "pattern", "severity",
	"tier", "tenant_id", "org_id", "priority", "enabled",
	"phase", "action_request", "action_response", "action",
	"segment_id", "version", "metadata", "deleted_at", "created_at", "updated_at",
}

var dynamicColumns = []string{
	"id", "policy_id", "name", "policy_type", "category",
	"tier", "tenant_id", "org_id", "priority", "enabled",
	"risk_threshold", "conditions", "actions",
	"segment_id", "metadata", "created_at", "version", "description",
}

// RequiredColumns returns the columns a complete capture must select for a
// table, in a stable order.
func RequiredColumns(table string) ([]string, error) {
	switch table {
	case "static_policies":
		return append([]string(nil), staticColumns...), nil
	case "dynamic_policies":
		return append([]string(nil), dynamicColumns...), nil
	default:
		return nil, fmt.Errorf("legacycompile: %q is not a legacy policy table", table)
	}
}

// missingColumns returns the required columns a raw row does not carry.
func missingColumns(r RawRow) []string {
	want, err := RequiredColumns(r.Table)
	if err != nil {
		return nil
	}
	var out []string
	for _, c := range want {
		if !r.has(c) {
			out = append(out, c)
		}
	}
	sort.Strings(out)
	return out
}

func decodeStatic(r RawRow) StaticRow {
	pr, prOK := r.intOr("priority", 0)
	en, enOK := r.boolOr("enabled", false)
	ver, verOK := r.intOr("version", 0)
	row := StaticRow{
		ID:       r.stringOr("id", ""),
		PolicyID: r.stringOr("policy_id", ""),
		Name:     r.stringOr("name", ""),
		Category: r.stringOr("category", ""),
		Pattern:  r.stringOr("pattern", ""),
		Severity: r.stringOr("severity", ""),

		Tier:         r.stringOr("tier", ""),
		TierNull:     r.isNull("tier") || !r.has("tier"),
		TenantID:     r.stringOr("tenant_id", ""),
		TenantIDNull: r.isNull("tenant_id") || !r.has("tenant_id"),
		OrgID:        r.stringOr("org_id", ""),
		OrgIDNull:    r.isNull("org_id") || !r.has("org_id"),
		Priority:     pr,
		PriorityNull: !prOK,
		Enabled:      en,
		EnabledNull:  !enOK,

		Phase:              Phase(r.stringOr("phase", "")),
		PhaseNull:          r.isNull("phase") || !r.has("phase"),
		ActionRequest:      r.stringOr("action_request", ""),
		ActionRequestNull:  r.isNull("action_request") || !r.has("action_request"),
		ActionResponse:     r.stringOr("action_response", ""),
		ActionResponseNull: r.isNull("action_response") || !r.has("action_response"),

		Action:     r.stringOr("action", ""),
		ActionNull: r.isNull("action") || !r.has("action"),

		SegmentID:     r.stringOr("segment_id", ""),
		SegmentIDNull: r.isNull("segment_id") || !r.has("segment_id"),
		Version:       ver,
		VersionNull:   !verOK,
		Metadata:      r.jsonOr("metadata"),
		DeletedAt:     r.stringOr("deleted_at", ""),
		CreatedAt:     r.stringOr("created_at", ""),
		CreatedAtNull: r.isNull("created_at") || !r.has("created_at"),
		UpdatedAt:     r.stringOr("updated_at", ""),
		UpdatedAtNull: r.isNull("updated_at") || !r.has("updated_at"),
	}
	return row
}

func decodeDynamic(r RawRow) DynamicRow {
	pr, prOK := r.intOr("priority", 0)
	en, enOK := r.boolOr("enabled", false)
	var rt float64
	rtOK := false
	if raw := r.jsonOr("risk_threshold"); raw != nil {
		var n json.Number
		if err := json.Unmarshal(raw, &n); err == nil {
			if f, err := n.Float64(); err == nil {
				rt, rtOK = f, true
			}
		}
	}
	ver, verOK := r.intOr("version", 0)
	return DynamicRow{
		Version:         ver,
		VersionNull:     !verOK,
		Description:     r.stringOr("description", ""),
		DescriptionNull: r.isNull("description") || !r.has("description"),
		ID:              r.stringOr("id", ""),
		PolicyID:        r.stringOr("policy_id", ""),
		Name:            r.stringOr("name", ""),
		PolicyType:      r.stringOr("policy_type", ""),
		Category:        r.stringOr("category", ""),
		CategoryNull:    r.isNull("category") || !r.has("category"),

		Tier:         r.stringOr("tier", ""),
		TierNull:     r.isNull("tier") || !r.has("tier"),
		TenantID:     r.stringOr("tenant_id", ""),
		TenantIDNull: r.isNull("tenant_id") || !r.has("tenant_id"),
		OrgID:        r.stringOr("org_id", ""),
		OrgIDNull:    r.isNull("org_id") || !r.has("org_id"),
		Priority:     pr,
		PriorityNull: !prOK,
		Enabled:      en,
		EnabledNull:  !enOK,

		RiskThreshold:     rt,
		RiskThresholdNull: !rtOK,

		Conditions: r.jsonOr("conditions"),
		Actions:    r.jsonOr("actions"),

		SegmentID:     r.stringOr("segment_id", ""),
		SegmentIDNull: r.isNull("segment_id") || !r.has("segment_id"),
		Metadata:      r.jsonOr("metadata"),
		CreatedAt:     r.stringOr("created_at", ""),
		CreatedAtNull: r.isNull("created_at") || !r.has("created_at"),
	}
}
