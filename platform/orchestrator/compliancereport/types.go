// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build enterprise

package compliancereport

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"axonflow/platform/orchestrator/compliancereport/renderer"
)

// -----------------------------------------------------------------------------
// Regulator / framework / format vocabulary
// -----------------------------------------------------------------------------

// Regulator identifies the regulatory module a report is generated from.
type Regulator string

const (
	RegulatorEUAIAct Regulator = "euaiact"
	RegulatorSEBI    Regulator = "sebi"
	RegulatorRBI     Regulator = "rbi"
	RegulatorMASFEAT Regulator = "masfeat"
	RegulatorOJK     Regulator = "ojk"
)

// AllRegulators is the canonical ordered list. Ordered (not a map range) so
// every enumeration in an error message, a response body and a rendered
// artifact is stable.
func AllRegulators() []Regulator {
	return []Regulator{RegulatorEUAIAct, RegulatorSEBI, RegulatorRBI, RegulatorMASFEAT, RegulatorOJK}
}

// Valid reports whether r is a known regulator.
func (r Regulator) Valid() bool {
	for _, k := range AllRegulators() {
		if k == r {
			return true
		}
	}
	return false
}

// DisplayName is the human-readable regulator name used in report headers.
func (r Regulator) DisplayName() string {
	switch r {
	case RegulatorEUAIAct:
		return "EU AI Act"
	case RegulatorSEBI:
		return "SEBI (India)"
	case RegulatorRBI:
		return "RBI FREE-AI (India)"
	case RegulatorMASFEAT:
		return "MAS FEAT (Singapore)"
	case RegulatorOJK:
		return "OJK / BI / UU PDP (Indonesia)"
	default:
		return string(r)
	}
}

// Framework identifies the specific compliance framework within a regulator.
// OJK carries sub-frameworks because a single Indonesian deployment reports
// against AI governance, personal-data protection and payment-system rules
// under three different instruments.
type Framework string

const (
	FrameworkEUAIAct   Framework = "EU_AI_ACT"
	FrameworkSEBIAIML  Framework = "SEBI_AI_ML"
	FrameworkRBIFreeAI Framework = "RBI_FREE_AI"
	FrameworkMASFEAT   Framework = "MAS_FEAT"

	// OJK sub-frameworks.
	FrameworkOJKAIGovernance Framework = "OJK_AI_GOVERNANCE"
	FrameworkUUPDP           Framework = "UU_PDP"
	FrameworkBIPJP           Framework = "BI_PJP"
	FrameworkOJKBICombined   Framework = "OJK_BI_COMBINED"
)

// AllFrameworks is every Framework constant, in declaration order.
//
// Exists so the database's framework CHECK and this vocabulary can be pinned
// against each other by a test that ENUMERATES rather than by a hand-copied
// list (migration 136,
// TestRealPG_VocabularyConstraintsMatchTheGoEnums). A framework added here
// without the matching CHECK value fails that test instead of failing later, in
// the async processor, as a mysteriously rejected job.
func AllFrameworks() []Framework {
	return []Framework{
		FrameworkEUAIAct,
		FrameworkSEBIAIML,
		FrameworkRBIFreeAI,
		FrameworkMASFEAT,
		FrameworkOJKAIGovernance,
		FrameworkUUPDP,
		FrameworkBIPJP,
		FrameworkOJKBICombined,
	}
}

// Format is a rendered artifact format.
type Format string

const (
	FormatPDF  Format = "pdf"
	FormatCSV  Format = "csv"
	FormatXLSX Format = "xlsx"
	FormatJSON Format = "json"
)

// Valid reports whether f is a known format. It says nothing about whether the
// format is offered for a given regulator — see FormatsFor.
func (f Format) Valid() bool {
	switch f {
	case FormatPDF, FormatCSV, FormatXLSX, FormatJSON:
		return true
	}
	return false
}

// Status is the async job lifecycle state. Same vocabulary as the EU AI Act
// export precedent (euaiact/types.go) so a portal that already polls one
// contract does not learn a second one.
type Status string

const (
	StatusPending    Status = "pending"
	StatusProcessing Status = "processing"
	StatusCompleted  Status = "completed"
	StatusFailed     Status = "failed"
)

// Valid reports whether s is a known job status.
func (s Status) Valid() bool {
	switch s {
	case StatusPending, StatusProcessing, StatusCompleted, StatusFailed:
		return true
	}
	return false
}

// ReportState is the THREE-STATE data-availability answer (epic #2892 D3).
//
// It exists because "an empty 200" is ambiguous on every existing compliance
// surface: the portal cannot tell "this regulatory module is not enabled for
// your deployment" from "it is enabled and there was genuinely no activity in
// the period you asked for". Those need different UI and different customer
// conversations, and inferring one from the other is the null-collapse class
// recorded on #2892. Every create and every poll response carries this field,
// and it is derived from an explicit probe of the underlying module, never
// from the emptiness of a payload.
type ReportState string

const (
	// ReportStateUndetermined is the value while a job is still `pending` or
	// `processing`: the data state is genuinely not known yet.
	//
	// The JSON key is ALWAYS present (no omitempty on ReportJob.ReportState),
	// so a client never has to tell "absent" from "null" - the null-collapse
	// class this whole field exists to kill. Empty means exactly one thing:
	// "ask again when the job is terminal". Writing one of the three real
	// values here would be a guess, and a guess about whether a regulator has
	// data is precisely what must never be guessed.
	//
	// It is NOT one of the three states the design record enumerates, and it
	// can never be the state of a `completed` report - asserted by
	// TestTerminalJobNeverCarriesUndeterminedState.
	ReportStateUndetermined ReportState = ""

	// ReportStateNotAvailable: the regulator's module is not wired in this
	// deployment (community build, or the module failed to initialize). No
	// report can be produced. This is a DEPLOYMENT fact, not a data fact.
	ReportStateNotAvailable ReportState = "not_available"

	// ReportStateEnabledEmpty: the module is enabled and was queried, and the
	// org has no rows in the requested period. A truthful "no governed
	// activity in range" attestation — a valid regulatory artifact, not a
	// failure.
	ReportStateEnabledEmpty ReportState = "enabled_empty"

	// ReportStatePopulated: the module is enabled and returned at least one row.
	ReportStatePopulated ReportState = "populated"
)

// Valid reports whether rs is one of the three TERMINAL states. The
// undetermined value is deliberately NOT valid here: this predicate guards the
// state a finished report carries, and an in-flight job's blank is checked
// against ReportStateUndetermined explicitly at the two places it is legal.
func (rs ReportState) Valid() bool {
	switch rs {
	case ReportStateNotAvailable, ReportStateEnabledEmpty, ReportStatePopulated:
		return true
	}
	return false
}

// Terminal reports whether a job status is a final state.
func (s Status) Terminal() bool {
	return s == StatusCompleted || s == StatusFailed
}

// -----------------------------------------------------------------------------
// Per-regulator capability matrix
// -----------------------------------------------------------------------------

// regulatorCapability is the per-regulator contract: which frameworks it
// accepts, which artifact formats it offers, and the retention statement that
// belongs on the face of the artifact.
//
// The format matrix is DELIBERATELY not "all four everywhere". XLSX is offered
// only where the regulator's own submission practice is spreadsheet-shaped
// (SEBI and RBI); offering it elsewhere would be a capability we do not have a
// regulator-appropriate layout for. The matrix is published in the docs page
// and asserted by TestFormatMatrixMatchesDesignRecord.
type regulatorCapability struct {
	frameworks    []Framework
	formats       []Format
	retentionNote string
}

var regulatorCapabilities = map[Regulator]regulatorCapability{
	RegulatorEUAIAct: {
		frameworks:    []Framework{FrameworkEUAIAct},
		formats:       []Format{FormatPDF, FormatCSV, FormatJSON},
		retentionNote: "EU AI Act: automatically generated logs retained at least 6 months (Art. 12/19); technical documentation retained 10 years (Art. 18).",
	},
	RegulatorSEBI: {
		frameworks:    []Framework{FrameworkSEBIAIML},
		formats:       []Format{FormatPDF, FormatCSV, FormatXLSX, FormatJSON},
		retentionNote: "SEBI: records retained 5 years.",
	},
	RegulatorRBI: {
		frameworks:    []Framework{FrameworkRBIFreeAI},
		formats:       []Format{FormatPDF, FormatCSV, FormatXLSX, FormatJSON},
		retentionNote: "RBI FREE-AI: retention per the FREE-AI framework and the institution's board-approved policy.",
	},
	RegulatorMASFEAT: {
		frameworks:    []Framework{FrameworkMASFEAT},
		formats:       []Format{FormatPDF, FormatCSV, FormatJSON},
		retentionNote: "MAS FEAT: records retained 7 years.",
	},
	RegulatorOJK: {
		frameworks: []Framework{
			FrameworkOJKAIGovernance,
			FrameworkUUPDP,
			FrameworkBIPJP,
			FrameworkOJKBICombined,
		},
		formats:       []Format{FormatPDF, FormatCSV, FormatJSON},
		retentionNote: "OJK / UU PDP: records retained 5 years.",
	},
}

// FrameworksFor returns the frameworks a regulator accepts, in a stable order.
func FrameworksFor(r Regulator) []Framework {
	cap, ok := regulatorCapabilities[r]
	if !ok {
		return nil
	}
	out := make([]Framework, len(cap.frameworks))
	copy(out, cap.frameworks)
	return out
}

// FormatsFor returns the artifact formats a regulator offers, in a stable order.
func FormatsFor(r Regulator) []Format {
	cap, ok := regulatorCapabilities[r]
	if !ok {
		return nil
	}
	out := make([]Format, len(cap.formats))
	copy(out, cap.formats)
	return out
}

// RetentionNoteFor returns the retention statement rendered on the artifact.
func RetentionNoteFor(r Regulator) string {
	return regulatorCapabilities[r].retentionNote
}

// DefaultFramework is the framework used when a request omits one. Only
// regulators with exactly one framework have a default; OJK does not, because
// silently picking one of its four would put a report under the wrong
// instrument.
func DefaultFramework(r Regulator) (Framework, bool) {
	fws := FrameworksFor(r)
	if len(fws) == 1 {
		return fws[0], true
	}
	return "", false
}

// -----------------------------------------------------------------------------
// Request / job
// -----------------------------------------------------------------------------

// ReportRequest is the client-supplied report specification.
//
// It deliberately carries NO org/tenant field: the scope is derived from the
// authenticated request headers by the handler and can never be named by the
// caller. That is the #3066 lesson — a client-supplied scope parameter is a
// tenant boundary the caller chooses.
type ReportRequest struct {
	Regulator   Regulator `json:"regulator"`
	Framework   Framework `json:"framework,omitempty"`
	PeriodStart time.Time `json:"period_start"`
	PeriodEnd   time.Time `json:"period_end"`
	Format      Format    `json:"format"`
}

// maxPeriodDays bounds the requested reporting window. A regulator report is a
// periodic artifact (monthly/quarterly/annual); an unbounded window turns one
// HTTP call into a full-table scan of audit_logs. 3 years covers every
// published per-regulator reporting cycle with headroom.
const maxPeriodDays = 1096

// Validate checks the request in isolation (vocabulary + window), returning a
// *RequestError so the handler can map it to a stable error code. It does NOT
// check deployment state — that is Probe's job.
func (req *ReportRequest) Validate() error {
	if !req.Regulator.Valid() {
		return &RequestError{
			Code: ErrCodeUnknownRegulator,
			Message: fmt.Sprintf("unknown regulator %q; supported: %s",
				req.Regulator, joinRegulators(AllRegulators())),
		}
	}
	if req.Framework == "" {
		fw, ok := DefaultFramework(req.Regulator)
		if !ok {
			return &RequestError{
				Code: ErrCodeUnknownFramework,
				Message: fmt.Sprintf("framework is required for regulator %q; supported: %s",
					req.Regulator, joinFrameworks(FrameworksFor(req.Regulator))),
			}
		}
		req.Framework = fw
	}
	if !frameworkAllowed(req.Regulator, req.Framework) {
		return &RequestError{
			Code: ErrCodeUnknownFramework,
			Message: fmt.Sprintf("framework %q is not defined for regulator %q; supported: %s",
				req.Framework, req.Regulator, joinFrameworks(FrameworksFor(req.Regulator))),
		}
	}
	if req.Format == "" {
		return &RequestError{Code: ErrCodeUnsupportedFormat, Message: "format is required"}
	}
	if !req.Format.Valid() {
		return &RequestError{
			Code:    ErrCodeUnsupportedFormat,
			Message: fmt.Sprintf("unknown format %q; supported: pdf, csv, xlsx, json", req.Format),
		}
	}
	if !formatAllowed(req.Regulator, req.Format) {
		return &RequestError{
			Code: ErrCodeUnsupportedFormat,
			Message: fmt.Sprintf("format %q is not offered for regulator %q; supported: %s",
				req.Format, req.Regulator, joinFormats(FormatsFor(req.Regulator))),
		}
	}
	if req.PeriodStart.IsZero() || req.PeriodEnd.IsZero() {
		return &RequestError{Code: ErrCodeInvalidPeriod, Message: "period_start and period_end are required (RFC3339)"}
	}
	if !req.PeriodEnd.After(req.PeriodStart) {
		return &RequestError{Code: ErrCodeInvalidPeriod, Message: "period_end must be after period_start"}
	}
	if req.PeriodEnd.Sub(req.PeriodStart) > time.Duration(maxPeriodDays)*24*time.Hour {
		return &RequestError{
			Code:    ErrCodeInvalidPeriod,
			Message: fmt.Sprintf("reporting period must not exceed %d days", maxPeriodDays),
		}
	}
	return nil
}

func frameworkAllowed(r Regulator, fw Framework) bool {
	for _, k := range FrameworksFor(r) {
		if k == fw {
			return true
		}
	}
	return false
}

func formatAllowed(r Regulator, f Format) bool {
	for _, k := range FormatsFor(r) {
		if k == f {
			return true
		}
	}
	return false
}

func joinRegulators(rs []Regulator) string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, string(r))
	}
	return strings.Join(out, ", ")
}

func joinFrameworks(fs []Framework) string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, string(f))
	}
	return strings.Join(out, ", ")
}

func joinFormats(fs []Format) string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, string(f))
	}
	return strings.Join(out, ", ")
}

// ReportJob is a persisted report-generation job. It is the wire shape of both
// the create (202) and the poll (200) response.
//
// OrgID/TenantID are NOT serialized: they are the caller's own scope, echoing
// them back adds nothing and a response body is a place people copy strings
// out of. StorageKey is likewise internal — the download route mints a
// presigned URL from it.
type ReportJob struct {
	ID          string      `json:"id"`
	OrgID       string      `json:"-"`
	TenantID    string      `json:"-"`
	Regulator   Regulator   `json:"regulator"`
	Framework   Framework   `json:"framework"`
	Format      Format      `json:"format"`
	PeriodStart time.Time   `json:"period_start"`
	PeriodEnd   time.Time   `json:"period_end"`
	Status      Status      `json:"status"`
	ReportState ReportState `json:"report_state"`
	Progress    int         `json:"progress"`
	RecordCount int         `json:"record_count"`
	SizeBytes   int64       `json:"size_bytes"`
	StorageKey  string      `json:"-"`
	Checksum    string      `json:"checksum,omitempty"`
	Error       string      `json:"error,omitempty"`
	RequestedBy string      `json:"requested_by"`
	CreatedAt   time.Time   `json:"created_at"`
	StartedAt   *time.Time  `json:"started_at,omitempty"`
	CompletedAt *time.Time  `json:"completed_at,omitempty"`
}

// Clone returns a deep-enough copy for handing across the async boundary.
// ReportJob holds only value fields plus two *time.Time; those are copied by
// value so a mutation on one side cannot be observed on the other.
func (j *ReportJob) Clone() *ReportJob {
	if j == nil {
		return nil
	}
	out := *j
	if j.StartedAt != nil {
		t := *j.StartedAt
		out.StartedAt = &t
	}
	if j.CompletedAt != nil {
		t := *j.CompletedAt
		out.CompletedAt = &t
	}
	return &out
}

// -----------------------------------------------------------------------------
// Report model handed to the renderers
// -----------------------------------------------------------------------------

// The renderer-facing document model lives in the child renderer package, not
// here: the parent imports the renderer, so the model has to sit on the side
// that has no import back. These aliases (not wrapper types) let providers
// build Sections in the vocabulary of this package while the renderers keep a
// dependency-free model. The enum-ish fields on renderer.Report are plain
// strings for the same reason; the service converts at the seam.
type (
	// Report is the renderer-facing model: regulator-agnostic and fully
	// ORDERED - no maps anywhere in the reachable graph - because every
	// renderer walks it in declaration order and two renders of the same job
	// must be byte-identical.
	Report = renderer.Report
	// Section is one report section: a titled table plus optional narrative
	// notes and key/value summary lines. A section is emitted even when empty,
	// carrying its empty-state sentence in Notes, so "no rows" is never
	// confused with "not covered by this report".
	Section = renderer.Section
	// KV is an ordered key/value summary line.
	KV = renderer.KV
)

// SortedKV converts an unordered map into ordered KV lines. Every provider that
// reads a map out of an upstream module MUST funnel it through here: ranging a
// Go map directly is the single easiest way to make a renderer nondeterministic.
func SortedKV(m map[string]int) []KV {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]KV, 0, len(keys))
	for _, k := range keys {
		out = append(out, KV{Key: k, Value: fmt.Sprintf("%d", m[k])})
	}
	return out
}

// -----------------------------------------------------------------------------
// Error codes
// -----------------------------------------------------------------------------

// Error codes are stable strings the portal switches on. Each names a DISTINCT
// cause: an operator reading a 403 must be able to tell "your license does not
// include this" from "you are not an administrator" without reading prose.
const (
	ErrCodeUnknownRegulator    = "UNKNOWN_REGULATOR"
	ErrCodeUnknownFramework    = "UNKNOWN_FRAMEWORK"
	ErrCodeUnsupportedFormat   = "UNSUPPORTED_FORMAT"
	ErrCodeInvalidPeriod       = "INVALID_PERIOD"
	ErrCodeInvalidBody         = "INVALID_BODY"
	ErrCodeScopeRequired       = "SCOPE_REQUIRED"
	ErrCodeNotFound            = "REPORT_NOT_FOUND"
	ErrCodeNotAvailable        = "REGULATOR_NOT_AVAILABLE"
	ErrCodeLicenseRequired     = "COMPLIANCE_REPORT_REQUIRES_EVALUATION_LICENSE"
	ErrCodeRateLimitExceeded   = "COMPLIANCE_REPORT_LIMIT_EXCEEDED"
	ErrCodeNotCompleted        = "REPORT_NOT_COMPLETED"
	ErrCodeArtifactUnavailable = "REPORT_ARTIFACT_UNAVAILABLE"
	ErrCodeInternal            = "INTERNAL_ERROR"
)

// RequestError is a validation failure carrying the stable code the handler
// puts on the wire. Returning a bare error and string-matching it in the
// handler is how error codes drift away from their messages.
type RequestError struct {
	Code    string
	Message string
}

func (e *RequestError) Error() string { return e.Message }

// ErrorResponse is the JSON error envelope.
//
// report_state is `omitempty` HERE, unlike ReportJob.ReportState. The
// difference is deliberate and is the one place the two envelopes diverge on
// this key: on a JOB the key must always be present because blank is a
// meaningful value ("not determined yet"), whereas most refusals - a malformed
// period, a missing header - say nothing about the module's data state at all,
// and emitting a blank there would invite a client to read it as "determined,
// and empty". The one refusal that DOES know the state,
// REGULATOR_NOT_AVAILABLE, carries it.
type ErrorResponse struct {
	Error       string      `json:"error"`
	ErrorCode   string      `json:"error_code"`
	ReportState ReportState `json:"report_state,omitempty"`
}
