// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"context"
	"errors"
	"testing"
)

// tableValidator is a table-driven TokenValidator for the resolver contract
// tests: it returns id/err for the tokens it "owns" and ErrNotConfigured
// otherwise (so the resolver moves on), without real crypto.
type tableValidator struct {
	name   string
	owns   map[string]*ValidatedIdentity // token -> identity to return on success
	reject map[string]error              // token -> error (recognized-but-invalid)
}

func (f *tableValidator) Name() string { return f.name }

func (f *tableValidator) Validate(_ context.Context, _, token string) (*ValidatedIdentity, error) {
	if err, ok := f.reject[token]; ok {
		return nil, err
	}
	if id, ok := f.owns[token]; ok {
		cp := *id
		return &cp, nil
	}
	return nil, ErrNotConfigured // not this validator's token
}

func TestResolveToken_NoTokenReturnsNilNil(t *testing.T) {
	ResetRegistryForTest()
	t.Cleanup(ResetRegistryForTest)
	_ = RegisterValidator(&tableValidator{name: "a"})
	id, err := ResolveToken(context.Background(), "org1", "   ")
	if id != nil || err != nil {
		t.Fatalf("no token → (nil,nil), got id=%+v err=%v", id, err)
	}
}

func TestResolveToken_EmptyRegistryIsLeastPrivilege(t *testing.T) {
	ResetRegistryForTest()
	t.Cleanup(ResetRegistryForTest)
	// A token presented with NO validators registered (community build) is
	// ignored — least-privilege, never rejected, never elevated.
	id, err := ResolveToken(context.Background(), "org1", "some-token")
	if id != nil || err != nil {
		t.Fatalf("empty registry → (nil,nil), got id=%+v err=%v", id, err)
	}
}

func TestResolveToken_ValidTokenSucceeds(t *testing.T) {
	ResetRegistryForTest()
	t.Cleanup(ResetRegistryForTest)
	_ = RegisterValidator(&tableValidator{name: "hs256", owns: map[string]*ValidatedIdentity{
		"good": {Email: "dev@corp.com", Role: "admin", OrgID: "org1", Validated: true, Source: "hs256"},
	}})
	id, err := ResolveToken(context.Background(), "org1", "good")
	if err != nil || id == nil {
		t.Fatalf("expected success, got id=%+v err=%v", id, err)
	}
	if id.Email != "dev@corp.com" || id.Role != "admin" {
		t.Errorf("unexpected identity: %+v", id)
	}
}

func TestResolveToken_TamperedRejected(t *testing.T) {
	ResetRegistryForTest()
	t.Cleanup(ResetRegistryForTest)
	_ = RegisterValidator(&tableValidator{name: "hs256", reject: map[string]error{
		"tampered": ErrTokenInvalid,
	}})
	id, err := ResolveToken(context.Background(), "org1", "tampered")
	if id != nil {
		t.Fatalf("tampered token must not resolve, got %+v", id)
	}
	if !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("expected ErrTokenInvalid, got %v", err)
	}
}

func TestResolveToken_RevokedRejected(t *testing.T) {
	ResetRegistryForTest()
	t.Cleanup(ResetRegistryForTest)
	_ = RegisterValidator(&tableValidator{name: "hs256", reject: map[string]error{
		"revoked": ErrTokenRevoked,
	}})
	_, err := ResolveToken(context.Background(), "org1", "revoked")
	if !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("expected ErrTokenRevoked surfaced, got %v", err)
	}
}

func TestResolveToken_FallsThroughToSecondValidator(t *testing.T) {
	ResetRegistryForTest()
	t.Cleanup(ResetRegistryForTest)
	// HS256 rejects the token (e.g. wrong alg/iss — an OIDC token); OIDC owns
	// it. HS256's reject must NOT be terminal.
	_ = RegisterValidator(&tableValidator{name: "hs256", reject: map[string]error{"oidc-tok": ErrTokenInvalid}})
	_ = RegisterValidator(&tableValidator{name: "oidc", owns: map[string]*ValidatedIdentity{
		"oidc-tok": {Email: "u@corp.com", Role: "member", OrgID: "org1", Validated: true, Source: "oidc"},
	}})
	id, err := ResolveToken(context.Background(), "org1", "oidc-tok")
	if err != nil || id == nil {
		t.Fatalf("OIDC should accept after HS256 rejects, got id=%+v err=%v", id, err)
	}
	if id.Source != "oidc" {
		t.Errorf("source = %q, want oidc", id.Source)
	}
}

func TestResolveToken_FirstSuccessWins(t *testing.T) {
	ResetRegistryForTest()
	t.Cleanup(ResetRegistryForTest)
	_ = RegisterValidator(&tableValidator{name: "hs256", owns: map[string]*ValidatedIdentity{
		"tok": {Email: "a@corp.com", Role: "admin", OrgID: "org1", Validated: true, Source: "hs256"},
	}})
	_ = RegisterValidator(&tableValidator{name: "oidc", owns: map[string]*ValidatedIdentity{
		"tok": {Email: "b@corp.com", Role: "viewer", OrgID: "org1", Validated: true, Source: "oidc"},
	}})
	id, _ := ResolveToken(context.Background(), "org1", "tok")
	if id.Source != "hs256" {
		t.Errorf("first registered success should win, got source %q", id.Source)
	}
}

func TestResolveToken_AllSkippedStillRejects(t *testing.T) {
	ResetRegistryForTest()
	t.Cleanup(ResetRegistryForTest)
	// Only a not-configured validator is registered → a presented token that
	// nothing can handle is still a rejected access attempt (fail-closed).
	_ = RegisterValidator(&tableValidator{name: "oidc"}) // owns nothing → ErrNotConfigured
	id, err := ResolveToken(context.Background(), "org1", "some-token")
	if id != nil {
		t.Fatalf("unhandleable token must not resolve, got %+v", id)
	}
	if !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("all-skipped presented token should reject with ErrTokenInvalid, got %v", err)
	}
}
