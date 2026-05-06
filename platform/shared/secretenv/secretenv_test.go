// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package secretenv

import (
	"testing"
)

func TestGet(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{"unset returns empty", "", ""},
		{"plain value preserved", "whsec_abc", "whsec_abc"},
		{"single trailing newline trimmed", "whsec_abc\n", "whsec_abc"},
		{"double trailing newline trimmed (AWS SM CLI quirk)", "whsec_abc\n\n", "whsec_abc"},
		{"leading whitespace trimmed", "  whsec_abc", "whsec_abc"},
		{"surrounding whitespace trimmed", "  whsec_abc  \n", "whsec_abc"},
		{"CRLF trimmed", "whsec_abc\r\n", "whsec_abc"},
		{"tab trimmed", "whsec_abc\t", "whsec_abc"},
		{"interior whitespace preserved", "AxonFlow <hello@x.com>", "AxonFlow <hello@x.com>"},
		{"all-whitespace returns empty", "  \n\t ", ""},
	}

	const key = "AXONFLOW_SECRETENV_TEST"
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value == "" {
				t.Setenv(key, "")
			} else {
				t.Setenv(key, tt.value)
			}
			if got := Get(key); got != tt.want {
				t.Errorf("Get(%q value=%q) = %q, want %q", key, tt.value, got, tt.want)
			}
		})
	}
}

// TestGet_RejectsControlCharsInHeader is a smoke check that catches the
// concrete failure mode this helper exists to prevent: a trailing newline
// turning into an http.Header.Set rejection. We don't actually call the
// http stack here — just assert the trim removes the offending byte.
func TestGet_RejectsControlCharsInHeader(t *testing.T) {
	t.Setenv("AXONFLOW_SECRETENV_HEADER_TEST", "Bearer key\n")
	got := Get("AXONFLOW_SECRETENV_HEADER_TEST")
	for _, r := range got {
		if r == '\r' || r == '\n' || r == '\t' {
			t.Errorf("Get() returned control character %q in %q — defeats the purpose of this helper", r, got)
		}
	}
}
