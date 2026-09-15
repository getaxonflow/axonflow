// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build !enterprise

package rbi

import (
	"reflect"
	"testing"
)

// The Community build's UPI detector on the payloads #4225 measured on the
// Enterprise agent. Community detects by pattern alone, with no validator and
// no context analysis, so the contract here differs from Enterprise's in one
// place and the cases say so: an @ inside a secret and a user@host token have
// an alphanumeric handle and still read as UPI ids. What #4225 fixes here is
// the edition-independent half, the email: the pattern carries the whole
// domain, and a dot or a hyphen after the @ is a mail domain.
func TestCommunityUPIDetectorOnTheMeasuredPayloads_4225(t *testing.T) {
	d := NewIndiaPIIDetector(DefaultIndiaPIIDetectorConfig())
	cases := []struct {
		name  string
		input string
		want  []string
	}{
		{"measured 1: an @ inside a secret still reads as a UPI id (pattern-only, no context analysis)",
			"database password = SuperSecretP@ssw0rd123", []string{"SuperSecretP@ssw0rd123"}},
		{"measured 2: a gmail address is not a UPI id",
			"please forward the statement to john.doe@gmail.com today", nil},
		{"measured 3: a corporate email beside a payment word is not a UPI id",
			"please send the statement to jane.doe@acme.com today", nil},
		{"measured 4: a corporate email with no payment word is not a UPI id",
			"reach jane.doe@acme.com about the refund", nil},
		{"measured 5: a bank-handle VPA is a UPI id",
			"pay 500 to rahul@okicici for the order", []string{"rahul@okicici"}},
		{"measured 6: a benign string holds none",
			"show me the weather forecast for tomorrow", nil},
		{"measured 7: the declared corporate email is not a UPI id either",
			"reach jane.doe@acme.com about the refund", nil},

		{"a user@host token still reads as a UPI id (pattern-only)",
			"ssh deploy@buildhost and restart the agent", []string{"deploy@buildhost"}},
		{"a hyphenated corporate domain is not a UPI id",
			"send the invoice to accounts@acme-corp.com", nil},
		{"a two-label country domain is not a UPI id",
			"transfer the file to jane@acme.co.uk", nil},
		{"a bare mail-provider name is not a handle",
			"send it to billing@gmail now", nil},
		{"a hyphenated handle with no dot is not a UPI id",
			"send 200 to ops@build-host now", nil},
		{"a VPA before a sentence full stop keeps its match",
			"pay rahul@okicici. Thanks", []string{"rahul@okicici"}},
		{"a VPA before a comma keeps its match",
			"pay rahul@okicici, then confirm", []string{"rahul@okicici"}},
		{"a VPA in a upi:// deep link is a UPI id",
			"upi://pay?pa=rahul@okicici&pn=Rahul&am=500", []string{"rahul@okicici"}},
		// A KNOWN FALSE NEGATIVE, pinned so that changing it is a decision: a
		// VPA glued to the next word by a dot reads as a domain.
		{"a VPA glued to the next word by a full stop is not detected (known false negative)",
			"pay rahul@okicici.Thanks", nil},
		{"a VPA glued to the next word by a hyphen is not detected (known false negative)",
			"pay rahul@okicici-Thanks", nil},
		{"a dotted username keeps its match",
			"My VPA is first.last@okhdfcbank", []string{"first.last@okhdfcbank"}},
	}
	values := func(results []IndiaPIIDetectionResult) []string {
		var out []string
		for _, r := range results {
			if r.Type == IndiaPIITypeUPI {
				out = append(out, r.Value)
			}
		}
		return out
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := values(d.DetectUPIIDs(tc.input)); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("DetectUPIIDs(%q) = %v, want %v", tc.input, got, tc.want)
			}
			if got := values(d.DetectAll(tc.input)); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("DetectAll(%q) UPI values = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}
