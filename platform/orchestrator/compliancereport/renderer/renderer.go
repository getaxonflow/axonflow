// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build enterprise

// Package renderer turns a regulator-agnostic report model into a downloadable
// artifact (PDF, CSV, XLSX, JSON).
//
// # Determinism is a contract, not a nicety
//
// A compliance artifact is checksummed, stored, and later re-derived to prove
// it was not altered. Two renders of the SAME job on the same host MUST be
// byte-identical, so every renderer here obeys three rules:
//
//  1. No wall-clock reads. The only timestamp on the page is Report.GeneratedAt,
//     which the service copies off the persisted job record.
//  2. No map iteration. The model is fully ordered (slices everywhere); a
//     provider holding a map converts it through compliancereport.SortedKV.
//  3. No emoji and no non-cp1252 glyphs in the PDF. The PDF uses the standard
//     14 core fonts, so nothing is embedded, nothing is downloaded, and there
//     is no font file to license or ship — which also makes an air-gapped
//     in-VPC build produce the same bytes as CI.
//
// fpdf additionally needs SetCatalogSort(true): its font resource dictionary is
// written by ranging a Go map, so without it two renders of the same document
// differ in the /Font entry order. That was MEASURED, not assumed — see
// TestPDFRendererIsDeterministic.
//
// This package deliberately does NOT import the parent compliancereport
// package: the parent imports it, and the model below is the seam. Enum-ish
// fields are plain strings for the same reason.
package renderer

import (
	"fmt"
	"time"
)

// Report is the renderer-facing document model. Fully ordered; no maps.
type Report struct {
	JobID         string    `json:"job_id"`
	Regulator     string    `json:"regulator"`
	RegulatorName string    `json:"regulator_name"`
	Framework     string    `json:"framework"`
	OrgID         string    `json:"org_id"`
	PeriodStart   time.Time `json:"period_start"`
	PeriodEnd     time.Time `json:"period_end"`
	// GeneratedAt is the JOB's creation timestamp, never time.Now(). It is what
	// makes a re-render reproduce the original bytes.
	GeneratedAt   time.Time `json:"generated_at"`
	ReportState   string    `json:"report_state"`
	RetentionNote string    `json:"retention_note"`
	RecordCount   int       `json:"record_count"`
	Sections      []Section `json:"sections"`
}

// Section is one titled table plus optional narrative notes and summary lines.
type Section struct {
	Key         string     `json:"key"`
	Title       string     `json:"title"`
	Description string     `json:"description,omitempty"`
	Columns     []string   `json:"columns,omitempty"`
	Rows        [][]string `json:"rows,omitempty"`
	Summary     []KV       `json:"summary,omitempty"`
	Notes       []string   `json:"notes,omitempty"`
}

// KV is an ordered key/value summary line.
type KV struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Renderer converts a Report into artifact bytes.
type Renderer interface {
	// Render returns the artifact bytes. It must be a pure function of the
	// Report: same input, same bytes, every time, on this host.
	Render(rep *Report) ([]byte, error)
	// ContentType is the MIME type stored alongside the artifact.
	ContentType() string
	// Extension is the file extension WITHOUT a leading dot.
	Extension() string
}

// brandName is the product name on the face of every artifact.
const brandName = "AxonFlow"

// documentTitle is the artifact's title line, shared by every renderer so the
// PDF header, the CSV preamble, the XLSX cover sheet and the JSON envelope all
// name the same document.
func documentTitle(rep *Report) string {
	return fmt.Sprintf("%s Compliance Report - %s", brandName, rep.RegulatorName)
}

// headerLines are the identity block every renderer prints before the sections.
// One function, so the four formats cannot drift apart on what a report claims
// about itself.
func headerLines(rep *Report) []KV {
	return []KV{
		{Key: "Report ID", Value: rep.JobID},
		{Key: "Regulator", Value: rep.RegulatorName},
		{Key: "Framework", Value: rep.Framework},
		{Key: "Organization", Value: rep.OrgID},
		{Key: "Reporting period", Value: fmt.Sprintf("%s to %s", fmtDay(rep.PeriodStart), fmtDay(rep.PeriodEnd))},
		{Key: "Generated at", Value: fmtStamp(rep.GeneratedAt)},
		{Key: "Data state", Value: stateSentence(rep.ReportState)},
		{Key: "Records", Value: fmt.Sprintf("%d", rep.RecordCount)},
		{Key: "Retention", Value: rep.RetentionNote},
	}
}

// stateSentence turns the three-state machine value into the sentence a human
// reads on the artifact. The raw token is also carried in the JSON render, so a
// machine consumer never has to parse this prose.
func stateSentence(state string) string {
	switch state {
	case "populated":
		return "populated - the period contains governed activity"
	case "enabled_empty":
		return "enabled, no data - the module is active and the period contains no governed activity"
	case "not_available":
		return "not available - the regulatory module is not enabled in this deployment"
	default:
		return state
	}
}

func fmtDay(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02")
}

func fmtStamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
