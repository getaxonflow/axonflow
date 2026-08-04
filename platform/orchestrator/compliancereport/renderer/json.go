// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build enterprise

package renderer

import (
	"bytes"
	"encoding/json"
)

// JSONRenderer emits the machine-readable form of the report.
//
// It marshals the Report model directly. Because the model contains no maps,
// encoding/json's field order is the struct declaration order and the output is
// deterministic without any extra sorting step.
type JSONRenderer struct{}

// NewJSON returns a JSON renderer.
func NewJSON() *JSONRenderer { return &JSONRenderer{} }

// ContentType implements Renderer.
func (JSONRenderer) ContentType() string { return "application/json" }

// Extension implements Renderer.
func (JSONRenderer) Extension() string { return "json" }

// jsonEnvelope wraps the report with a schema marker so a consumer can tell
// this artifact apart from the legacy per-module export payloads, which are
// also JSON and also carry an org and a date range.
type jsonEnvelope struct {
	Schema string  `json:"schema"`
	Title  string  `json:"title"`
	Report *Report `json:"report"`
}

// jsonSchemaID versions the artifact envelope. Bump it when the report model
// changes shape in a way a consumer must notice.
const jsonSchemaID = "axonflow.compliance-report/v1"

// Render implements Renderer.
func (r JSONRenderer) Render(rep *Report) ([]byte, error) {
	if err := validateReport(rep); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	// SetEscapeHTML(false) keeps `&`, `<` and `>` readable in policy names and
	// descriptions; the artifact is a downloaded file, never inlined into a
	// page, so HTML escaping buys nothing and makes the bytes harder to diff.
	enc.SetEscapeHTML(false)
	if err := enc.Encode(jsonEnvelope{
		Schema: jsonSchemaID,
		Title:  documentTitle(rep),
		Report: rep,
	}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
