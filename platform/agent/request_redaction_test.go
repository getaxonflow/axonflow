// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Unit tests for the content types the MCP request pass can redact (ADR-056 /
// #2563). The masking itself is the anchored decision's (maskMCPStatement) and
// is exercised through the real check-input handler in
// mcp_request_enforcing_seam_test.go.

import (
	"strings"
	"testing"

	sharedpolicy "axonflow/platform/shared/policy"
)

func TestCanRedactRequestContentType(t *testing.T) {
	if !canRedactRequestContentType("") {
		t.Fatal("an empty content type is text/plain, which the request pass redacts")
	}
	if !canRedactRequestContentType(contentTypeText) {
		t.Fatalf("%s must be redactable", contentTypeText)
	}
	// Media is a future modality: check-input refuses it at entry, so an
	// enforcement point never believes a redaction nobody performed happened.
	if canRedactRequestContentType("image/png") {
		t.Fatal("image/png must not be redactable yet")
	}
}

func TestRequestRedactionContentTypes_AdvertisesText(t *testing.T) {
	cts := requestRedactionContentTypes()
	found := false
	for _, c := range cts {
		if c == contentTypeText {
			found = true
		}
	}
	if !found {
		t.Fatalf("content types %v must advertise %s", cts, contentTypeText)
	}
}

// TestIndonesiaFollowsPIIConvention guards the core #2563 finding: the request
// pass's detector pass scopes PII through EnabledPIICategories (#2565,
// evaluateInputPolicies), which keys on the `pii-*` naming convention. So the
// Indonesia rows are evaluated, and their detector facts reach the anchored
// engine, only while pii-indonesia follows that convention.
func TestIndonesiaFollowsPIIConvention(t *testing.T) {
	if !strings.HasPrefix(string(sharedpolicy.CategoryPIIIndonesia), "pii-") {
		t.Fatalf("CategoryPIIIndonesia=%q breaks the pii-* convention EnabledPIICategories keys on; the request pass would never evaluate the Indonesia rows (#2563)", sharedpolicy.CategoryPIIIndonesia)
	}
}
