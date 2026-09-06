// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
)

// The audit signing key was the third copy of the tolerant base64 decoder
// consolidated in #3710 — its own comment described itself as mirroring the
// one in platform/agent/license/keygen.go. TestLoadAuditSigningKeyFromEnv
// already covered "unset", "standard", "raw-url" and "wrong length"; it
// covered neither of the two dialects in between nor any whitespace, which is
// what an operator's heredoc or secrets-manager fetch actually delivers.

// auditSeedPasteFixture is 32 bytes whose standard base64 contains both '+'
// and '/', so the URL-safe legs below are different strings from the standard
// ones rather than duplicates of them.
func auditSeedPasteFixture() []byte {
	b := make([]byte, ed25519.SeedSize)
	for i := range b {
		b[i] = byte((i*7 + 251) % 256)
	}
	return b
}

func TestAuditSigningKeyAcceptsEveryPasteForm(t *testing.T) {
	seed := auditSeedPasteFixture()
	std := base64.StdEncoding.EncodeToString(seed)
	url := base64.URLEncoding.EncodeToString(seed)
	if !strings.ContainsAny(std, "+/") || std == url {
		t.Fatalf("fixture cannot distinguish the base64 alphabets (std=%q url=%q); the URL-safe legs would be vacuous", std, url)
	}

	dialects := []struct{ name, enc string }{
		{"std-padded", std},
		{"std-raw", base64.RawStdEncoding.EncodeToString(seed)},
		{"url-padded", url},
		{"url-raw", base64.RawURLEncoding.EncodeToString(seed)},
	}
	wraps := []struct{ name, prefix, suffix string }{
		{"bare", "", ""},
		{"trailing-lf", "", "\n"},
		{"trailing-crlf", "", "\r\n"},
		{"trailing-lf-lf", "", "\n\n"},
		{"trailing-tab", "", "\t"},
		{"leading-spaces", "  ", ""},
		{"surrounded", "  ", "  \n"},
	}

	want := ed25519.NewKeyFromSeed(seed)
	for _, d := range dialects {
		for _, w := range wraps {
			t.Run(d.name+"/"+w.name, func(t *testing.T) {
				t.Setenv(auditSigningKeyEnvVar, w.prefix+d.enc+w.suffix)
				key, keyID, err := LoadAuditSigningKeyFromEnv()
				if err != nil {
					t.Fatalf("LoadAuditSigningKeyFromEnv rejected a seed pasted as %s/%s: %v", d.name, w.name, err)
				}
				if !bytes.Equal(key, want) {
					t.Fatalf("loaded a different key for %s/%s", d.name, w.name)
				}
				if keyID == "" {
					t.Fatalf("no key id derived for %s/%s", d.name, w.name)
				}
			})
		}
	}
}

// TestAuditSigningKeyWhitespaceOnlyIsUnsigned pins the "hash-chain but do not
// sign" mode against the change of decoder. A whitespace-only value used to
// reach the "" branch through an explicit TrimSpace at the call site; it now
// reaches it through secretenv.ErrNotSet, and either way it must be silence,
// not an error — a value that is nothing but a stray newline is an unset
// variable, and an error here would refuse to boot.
func TestAuditSigningKeyWhitespaceOnlyIsUnsigned(t *testing.T) {
	for _, v := range []string{"", "\n", "   ", " \n\t "} {
		t.Setenv(auditSigningKeyEnvVar, v)
		key, keyID, err := LoadAuditSigningKeyFromEnv()
		if err != nil || key != nil || keyID != "" {
			t.Fatalf("value %q: got key=%v id=%q err=%v, want nil/empty/nil", v, key, keyID, err)
		}
	}
}
