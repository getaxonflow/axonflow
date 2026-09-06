// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package secretenv

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// fixtureSeed is 32 bytes whose STANDARD base64 encoding contains both '+' and
// '/', so the URL-safe cases below are genuinely different strings rather than
// duplicates of the standard ones. TestFixtureSeedDistinguishesTheAlphabets is
// the control that keeps that true.
func fixtureSeed() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte((i*7 + 251) % 256)
	}
	return b
}

func TestFixtureSeedDistinguishesTheAlphabets(t *testing.T) {
	std := base64.StdEncoding.EncodeToString(fixtureSeed())
	url := base64.URLEncoding.EncodeToString(fixtureSeed())
	if !strings.ContainsAny(std, "+/") {
		t.Fatalf("standard encoding %q has no '+' or '/': the URL-safe cases are vacuous", std)
	}
	if std == url {
		t.Fatalf("standard and URL-safe encodings are identical (%q): the URL-safe cases are vacuous", std)
	}
}

// pasteForms is every spelling of the same bytes that reaches an environment
// variable in practice: four base64 dialects crossed with the whitespace a
// secrets store, a heredoc or a CI runner leaves behind.
func pasteForms(seed []byte) map[string]string {
	dialects := map[string]string{
		"std-padded": base64.StdEncoding.EncodeToString(seed),
		"std-raw":    base64.RawStdEncoding.EncodeToString(seed),
		"url-padded": base64.URLEncoding.EncodeToString(seed),
		"url-raw":    base64.RawURLEncoding.EncodeToString(seed),
	}
	wraps := map[string][2]string{
		"bare":           {"", ""},
		"trailing-lf":    {"", "\n"},
		"trailing-crlf":  {"", "\r\n"},
		"trailing-lf-lf": {"", "\n\n"},
		"trailing-tab":   {"", "\t"},
		"leading-spaces": {"  ", ""},
		"surrounded":     {"  ", "  \n"},
	}
	out := make(map[string]string, len(dialects)*len(wraps))
	for dn, d := range dialects {
		for wn, w := range wraps {
			out[dn+"/"+wn] = w[0] + d + w[1]
		}
	}
	return out
}

func TestGetBase64SeedAcceptsEveryPasteForm(t *testing.T) {
	seed := fixtureSeed()
	const key = "AXONFLOW_SECRETENV_SEED_TEST"
	for name, value := range pasteForms(seed) {
		t.Run(name, func(t *testing.T) {
			t.Setenv(key, value)
			got, err := GetBase64Seed(key)
			if err != nil {
				t.Fatalf("GetBase64Seed rejected %s: %v", name, err)
			}
			if !bytes.Equal(got, seed) {
				t.Fatalf("GetBase64Seed(%s) decoded %x, want %x", name, got, seed)
			}
		})
	}
}

func TestDecodeBase64TolerantAcceptsEveryPasteForm(t *testing.T) {
	seed := fixtureSeed()
	for name, value := range pasteForms(seed) {
		t.Run(name, func(t *testing.T) {
			got, err := DecodeBase64Tolerant(value)
			if err != nil {
				t.Fatalf("DecodeBase64Tolerant rejected %s: %v", name, err)
			}
			if !bytes.Equal(got, seed) {
				t.Fatalf("DecodeBase64Tolerant(%s) decoded %x, want %x", name, got, seed)
			}
		})
	}
}

// TestGetBase64SeedReportsUnsetSeparately pins the distinction the callers
// depend on: an unset variable is a configuration gap with its own operator
// message, not an undecodable value. The empty string decodes cleanly to zero
// bytes, so without the explicit check this returns (nil-length, nil).
func TestGetBase64SeedReportsUnsetSeparately(t *testing.T) {
	const key = "AXONFLOW_SECRETENV_SEED_UNSET_TEST"
	for _, tc := range []struct{ name, value string }{
		{"unset", ""},
		{"whitespace-only", " \n\t "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(key, tc.value)
			got, err := GetBase64Seed(key)
			if !errors.Is(err, ErrNotSet) {
				t.Fatalf("GetBase64Seed on %s returned (%x, %v), want ErrNotSet", tc.name, got, err)
			}
			if got != nil {
				t.Fatalf("GetBase64Seed on %s returned %x, want nil bytes", tc.name, got)
			}
		})
	}
}

// TestGetBase64SeedRejectsUndecodableValue keeps tolerance scoped to dialect,
// not to validity, and pins WHICH error comes back: the standard-encoding one,
// whose byte offset refers to the padded form operators are documented to use.
func TestGetBase64SeedRejectsUndecodableValue(t *testing.T) {
	const key = "AXONFLOW_SECRETENV_SEED_BAD_TEST"
	t.Setenv(key, "this is not base64 at all !!!")
	_, err := GetBase64Seed(key)
	if err == nil {
		t.Fatal("expected an error for a value that is not base64 in any dialect")
	}
	if errors.Is(err, ErrNotSet) {
		t.Fatalf("a present-but-invalid value must not report ErrNotSet, got: %v", err)
	}
	if !strings.Contains(err.Error(), "illegal base64 data") {
		t.Fatalf("expected the standard-encoding decode error, got: %v", err)
	}
}
