// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// The content types the MCP request pass can redact (ADR-056 / #2563 addendum).
//
// check-input and the redact_pii obligation contract are content-type agnostic
// on purpose: a redaction request carries a content_type, and the obligation
// names the content types the endpoint can redact
// (requestRedactionContentTypes). What performs the redaction is the anchored
// decision's own masking - the detectors behind its redaction requirements,
// through the platform's redactor (maskMCPStatement) - and it works over text.
// A caller submitting any other content type is refused at entry, so an
// enforcement point never believes it discharged a redaction nobody performed.
//
// Media is not a hypothetical build: the orchestrator ships a media-governance
// subsystem (platform/orchestrator/media/, /api/v1/media-governance/*).
// Redacting image/* or application/pdf through it is a tracked #2563 follow-up;
// it adds a content type here and a masking path beside maskMCPStatement, never
// an endpoint or wire-contract redesign.

import "sort"

// redactableRequestContentTypes is every content type check-input can redact.
var redactableRequestContentTypes = map[string]bool{contentTypeText: true}

// canRedactRequestContentType reports whether check-input can redact content of
// a type. An empty content type is text/plain, for callers that predate the
// field.
func canRedactRequestContentType(contentType string) bool {
	if contentType == "" {
		contentType = contentTypeText
	}
	return redactableRequestContentTypes[contentType]
}

// requestRedactionContentTypes returns the redactable content types, sorted, for
// the redact_pii obligation's content_types, so an enforcement point knows which
// modalities the endpoint can redact and fails closed on the rest.
func requestRedactionContentTypes() []string {
	out := make([]string, 0, len(redactableRequestContentTypes))
	for ct := range redactableRequestContentTypes {
		out = append(out, ct)
	}
	sort.Strings(out)
	return out
}
