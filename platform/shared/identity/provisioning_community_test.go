//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"errors"
	"testing"
)

// TestCommunityStubs_AllEnterpriseOnly pins the community contract: every
// provisioning constructor refuses with ErrEnterpriseOnly and returns no
// usable implementation — a community binary can never validate (or appear
// to validate) per-user tokens.
func TestCommunityStubs_AllEnterpriseOnly(t *testing.T) {
	if v, err := NewHS256Validator([]byte("secret"), nil); v != nil || !errors.Is(err, ErrEnterpriseOnly) {
		t.Fatalf("NewHS256Validator = (%v, %v), want (nil, ErrEnterpriseOnly)", v, err)
	}
	if v, err := NewOIDCVerifier(nil, nil); v != nil || !errors.Is(err, ErrEnterpriseOnly) {
		t.Fatalf("NewOIDCVerifier = (%v, %v), want (nil, ErrEnterpriseOnly)", v, err)
	}
	if s, err := NewDBRevocationStore(nil); s != nil || !errors.Is(err, ErrEnterpriseOnly) {
		t.Fatalf("NewDBRevocationStore = (%v, %v), want (nil, ErrEnterpriseOnly)", s, err)
	}
	if p, err := NewDBOIDCConfigProvider(nil); p != nil || !errors.Is(err, ErrEnterpriseOnly) {
		t.Fatalf("NewDBOIDCConfigProvider = (%v, %v), want (nil, ErrEnterpriseOnly)", p, err)
	}
	if r, err := NewSCIMRoleResolver(nil); r != nil || !errors.Is(err, ErrEnterpriseOnly) {
		t.Fatalf("NewSCIMRoleResolver = (%v, %v), want (nil, ErrEnterpriseOnly)", r, err)
	}
}
