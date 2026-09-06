// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// --- test doubles ---

// captureRecorder remembers every counterfactual.
type captureRecorder struct{ records []Counterfactual }

func (r *captureRecorder) RecordCounterfactual(_ context.Context, rec Counterfactual) {
	r.records = append(r.records, rec)
}

func (r *captureRecorder) last(t *testing.T) Counterfactual {
	t.Helper()
	if len(r.records) == 0 {
		t.Fatalf("no counterfactual was recorded")
	}
	return r.records[len(r.records)-1]
}

// panicRecorder fails the test if it is ever called. It is how "mode off runs
// nothing" is proved as an absence of work rather than as an absence of
// output.
type panicRecorder struct{ t *testing.T }

func (r *panicRecorder) RecordCounterfactual(context.Context, Counterfactual) {
	r.t.Fatalf("the recorder was called with the adapter switched off")
}

// panicRealmSource fails the test if the adapter touches realms at all.
type panicRealmSource struct{ t *testing.T }

func (s *panicRealmSource) EnsureRealms(context.Context, string) error {
	s.t.Fatalf("the realm source was consulted with the adapter switched off")
	return nil
}

// failingRealmSource reports an outage.
type failingRealmSource struct{ err error }

func (s failingRealmSource) EnsureRealms(context.Context, string) error { return s.err }

// countingRealmSource records how many times it was asked.
type countingRealmSource struct {
	inner CompatRealmSource
	calls int
}

func (s *countingRealmSource) EnsureRealms(ctx context.Context, orgID string) error {
	s.calls++
	return s.inner.EnsureRealms(ctx, orgID)
}

// staticRevocations answers from a fixed set of revoked keys.
type staticRevocations struct {
	revoked map[string]bool
	err     error
}

func (s staticRevocations) IsRevoked(_ string, _ RealmID, key string) (bool, error) {
	if s.err != nil {
		return false, s.err
	}
	return s.revoked[key], nil
}

// compatFixture builds an adapter over the built-in realms for fixtureOrg.
func compatFixture(t *testing.T, mode CompatMode, dep BuiltinRealmDeployment, opts ...CompatAdapterOption) (*CompatAdapter, *captureRecorder, *RealmRegistry) {
	t.Helper()
	reg := NewRealmRegistry()
	src, err := NewBuiltinRealmSource(reg, dep)
	if err != nil {
		t.Fatalf("NewBuiltinRealmSource: %v", err)
	}
	rec := &captureRecorder{}
	opts = append([]CompatAdapterOption{
		WithCompatClock(func() time.Time { return fixtureNow }),
		// A realistic component, so the plumbing from adapter to record is
		// exercised rather than defaulted away.
		WithCompatComponent("agent"),
	}, opts...)
	a, err := NewCompatAdapter(mode, reg, src, rec, opts...)
	if err != nil {
		t.Fatalf("NewCompatAdapter: %v", err)
	}
	return a, rec, reg
}

// mintedClaims builds a well-formed AxonFlow-minted HS256 claim set: the happy
// path every unhappy case below is one field away from.
func mintedClaims() map[string]any {
	return map[string]any{
		"iss":    UserTokenIssuer,
		"sub":    "user-1138",
		"email":  "dev@corp.example",
		"jti":    "jti-1",
		"org_id": fixtureOrg,
		"iat":    float64(fixtureNow.Add(-time.Minute).Unix()),
		"exp":    float64(fixtureNow.Add(time.Hour).Unix()),
	}
}

// --- mode ---

func TestParseCompatMode(t *testing.T) {
	for _, tc := range []struct {
		raw     string
		want    CompatMode
		wantErr bool
	}{
		{"", CompatModeOff, false},
		{"off", CompatModeOff, false},
		{"OFF", CompatModeOff, false},
		{"  shadow  ", CompatModeShadow, false},
		{"Enforce", CompatModeEnforce, false},
		{"enfore", CompatModeUnspecified, true},
		{"true", CompatModeUnspecified, true},
		{"on", CompatModeUnspecified, true},
	} {
		got, err := ParseCompatMode(tc.raw)
		if (err != nil) != tc.wantErr {
			t.Fatalf("ParseCompatMode(%q) error = %v, wantErr %v", tc.raw, err, tc.wantErr)
		}
		if got != tc.want {
			t.Fatalf("ParseCompatMode(%q) = %s, want %s", tc.raw, got, tc.want)
		}
	}
}

// TestCompatModeMembershipRefusesOutOfRange pins the reason every tri-state in
// this plane is validated by membership: an out-of-range value must not
// evaluate and must not enforce. Inequality against the zero value would let
// CompatMode(99) do both.
func TestCompatModeMembershipRefusesOutOfRange(t *testing.T) {
	rogue := CompatMode(99)
	if rogue.IsValid() {
		t.Fatalf("CompatMode(99).IsValid() = true")
	}
	if rogue.evaluates() {
		t.Fatalf("CompatMode(99) evaluates; an undeclared mode must not run the identity plane")
	}
	if rogue.enforces() {
		t.Fatalf("CompatMode(99) enforces; an undeclared mode must never refuse a request")
	}
	if _, err := NewCompatAdapter(rogue, NewRealmRegistry(), failingRealmSource{}, &captureRecorder{}); err == nil {
		t.Fatalf("NewCompatAdapter accepted an undeclared mode")
	}
}

func TestNewCompatAdapterRefusesMissingCollaborators(t *testing.T) {
	reg := NewRealmRegistry()
	src := failingRealmSource{}
	rec := &captureRecorder{}
	if _, err := NewCompatAdapter(CompatModeShadow, nil, src, rec); err == nil {
		t.Fatalf("accepted a nil registry")
	}
	if _, err := NewCompatAdapter(CompatModeShadow, reg, nil, rec); err == nil {
		t.Fatalf("accepted a nil realm source")
	}
	if _, err := NewCompatAdapter(CompatModeShadow, reg, src, nil); err == nil {
		t.Fatalf("accepted a nil recorder; a shadow phase that records nothing has not run")
	}
}

// --- off means off ---

// TestCompatOffTouchesNothing is the "flag off is byte-identical" guarantee
// expressed as an absence of work: the recorder and the realm source both fail
// the test if they are reached, and the clock panics if it is read.
func TestCompatOffTouchesNothing(t *testing.T) {
	a, err := NewCompatAdapter(CompatModeOff, NewRealmRegistry(), &panicRealmSource{t: t}, &panicRecorder{t: t},
		WithCompatClock(func() time.Time {
			t.Fatalf("the clock was read with the adapter switched off")
			return time.Time{}
		}))
	if err != nil {
		t.Fatalf("NewCompatAdapter: %v", err)
	}
	out := a.Resolve(context.Background(), HS256LegacyAuth(fixtureOrg, mintedClaims(), true, "", ""))
	if out.Refusal() != nil {
		t.Fatalf("mode off produced a refusal")
	}
	if out.Evaluated {
		t.Fatalf("mode off reported Evaluated")
	}
	if out.Divergence != DivergenceNotEvaluated {
		t.Fatalf("mode off divergence = %s, want %s", out.Divergence, DivergenceNotEvaluated)
	}
}

// TestNilCompatAdapterIsOff means an unwired deployment needs no nil check at
// any call site.
func TestNilCompatAdapterIsOff(t *testing.T) {
	var a *CompatAdapter
	out := a.Resolve(context.Background(), HS256LegacyAuth(fixtureOrg, mintedClaims(), true, "", ""))
	if out.Refusal() != nil || out.Evaluated {
		t.Fatalf("a nil adapter was not off: %+v", out)
	}
	if a.Mode() != CompatModeOff {
		t.Fatalf("a nil adapter reports mode %s", a.Mode())
	}
}

// --- the happy path ---

func TestCompatHS256HappyPathAgrees(t *testing.T) {
	a, rec, _ := compatFixture(t, CompatModeEnforce, BuiltinRealmDeployment{})
	out := a.Resolve(context.Background(), HS256LegacyAuth(fixtureOrg, mintedClaims(), true, "", ""))

	if out.Refusal() != nil {
		t.Fatalf("a well-formed minted token was refused: %v", out.Refusal())
	}
	if !out.Subject.Admission.State.IsAdmitted() {
		t.Fatalf("admission = %s %s (%s)", out.Subject.Admission.State, out.Subject.Admission.Reason, out.Subject.Admission.Detail)
	}
	if out.Divergence != DivergenceNone {
		t.Fatalf("divergence = %s, want none", out.Divergence)
	}
	want := "User::" + string(BuiltinRealmMinted) + ":user-1138"
	if got := out.Subject.Admission.Principal.String(); got != want {
		t.Fatalf("principal = %q, want %q", got, want)
	}
	if r := rec.last(t); r.Principal != want || r.RealmID != BuiltinRealmMinted {
		t.Fatalf("recorded principal/realm = %q/%q", r.Principal, r.RealmID)
	}
}

// TestCompatSubjectComesFromTheClaimMapping is ADR-065 invariant 3 at the
// adapter boundary: the canonical subject is the claim the REALM named, and an
// email is not substituted for it.
func TestCompatSubjectComesFromTheClaimMapping(t *testing.T) {
	a, _, _ := compatFixture(t, CompatModeShadow, BuiltinRealmDeployment{})
	claims := mintedClaims()
	delete(claims, "sub")

	out := a.Resolve(context.Background(), HS256LegacyAuth(fixtureOrg, claims, true, "", ""))
	if out.Subject.Admission.Reason != ReasonSubjectMissing {
		t.Fatalf("a token with no subject claim: reason = %s, want %s", out.Subject.Admission.Reason, ReasonSubjectMissing)
	}
	if strings.Contains(out.Subject.Admission.Detail, "dev@corp.example") {
		t.Fatalf("the refusal detail leaked the email that was NOT substituted for the subject")
	}
}

// TestCompatRefusesACallerSuppliedSubject: the one route by which an alias
// could become an identifier is a caller pre-setting Credential.Subject.
func TestCompatRefusesACallerSuppliedSubject(t *testing.T) {
	a, rec, _ := compatFixture(t, CompatModeEnforce, BuiltinRealmDeployment{})
	in := HS256LegacyAuth(fixtureOrg, mintedClaims(), true, "", "")
	in.Credential.Subject = "dev@corp.example"

	out := a.Resolve(context.Background(), in)
	if out.Divergence != DivergenceAdapterDefect {
		t.Fatalf("divergence = %s, want %s", out.Divergence, DivergenceAdapterDefect)
	}
	if out.Refusal() != nil {
		t.Fatalf("an adapter-side defect enforced; a defect in this package must not deny a caller's request")
	}
	if rec.last(t).Divergence != DivergenceAdapterDefect {
		t.Fatalf("the defect was not recorded")
	}
}

// --- the four expected divergences ---

// TestCompatUndeclaredIssuerIsUnknownRealm is EX-47.
func TestCompatUndeclaredIssuerIsUnknownRealm(t *testing.T) {
	for name, iss := range map[string]any{
		"an issuer no realm declares": issuerAcquired,
		"no issuer claim at all":      nil,
	} {
		t.Run(name, func(t *testing.T) {
			a, _, _ := compatFixture(t, CompatModeShadow, BuiltinRealmDeployment{})
			claims := mintedClaims()
			if iss == nil {
				delete(claims, "iss")
			} else {
				claims["iss"] = iss
			}
			out := a.Resolve(context.Background(), HS256LegacyAuth(fixtureOrg, claims, true, "", ""))
			if out.Subject.Admission.Reason != ReasonUnknownRealm {
				t.Fatalf("reason = %s, want %s", out.Subject.Admission.Reason, ReasonUnknownRealm)
			}
			if out.Divergence != DivergenceIdentityRefused {
				t.Fatalf("divergence = %s, want %s", out.Divergence, DivergenceIdentityRefused)
			}
		})
	}
}

// TestCompatWrongOrgClaimIsRefused is #3488 / #3556: the org claim is bound to
// the credential that authenticated, and a disagreement is refused rather than
// narrowed to an organization-only evaluation.
//
// The three cases are the three shapes an org claim can take, and the last two
// are the ones a happy-path-only test misses.
func TestCompatWrongOrgClaimIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name       string
		mutate     func(map[string]any)
		wantReason AdmissionReason
		wantAdmit  bool
	}{
		{
			name:       "an org claim naming another organization",
			mutate:     func(c map[string]any) { c["org_id"] = fixtureOtherOrg },
			wantReason: ReasonOrgBindingMismatch,
		},
		{
			name:       "an org claim present but empty",
			mutate:     func(c map[string]any) { c["org_id"] = "" },
			wantReason: ReasonOrgBindingMismatch,
		},
		{
			name:       "an org claim delivered as a number, which is not a string this plane can key on",
			mutate:     func(c map[string]any) { c["org_id"] = float64(42) },
			wantReason: ReasonOrgBindingMismatch,
		},
		{
			name:      "NO org claim at all is bound by construction and admitted",
			mutate:    func(c map[string]any) { delete(c, "org_id") },
			wantAdmit: true,
		},
		{
			name:      "the matching org claim is admitted",
			mutate:    func(c map[string]any) { c["org_id"] = fixtureOrg },
			wantAdmit: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _, _ := compatFixture(t, CompatModeEnforce, BuiltinRealmDeployment{})
			claims := mintedClaims()
			tc.mutate(claims)

			out := a.Resolve(context.Background(), HS256LegacyAuth(fixtureOrg, claims, true, "", ""))
			if tc.wantAdmit {
				if !out.Subject.Admission.State.IsAdmitted() {
					t.Fatalf("admission = %s %s", out.Subject.Admission.State, out.Subject.Admission.Reason)
				}
				if out.Refusal() != nil {
					t.Fatalf("refused: %v", out.Refusal())
				}
				return
			}
			if out.Subject.Admission.Reason != tc.wantReason {
				t.Fatalf("reason = %s, want %s", out.Subject.Admission.Reason, tc.wantReason)
			}
			if out.Refusal() == nil {
				t.Fatalf("enforce mode did not refuse a legacy-accepted credential the identity plane denied")
			}
		})
	}
}

// TestCompatUnrevocableTokenIsIndeterminate: a realm that declares a
// revocation source and a credential that carries no revocation key cannot be
// checked, and "cannot be checked" is not "not revoked".
func TestCompatUnrevocableTokenIsIndeterminate(t *testing.T) {
	a, _, _ := compatFixture(t, CompatModeShadow, BuiltinRealmDeployment{HasRevocation: true},
		WithCompatRevocations(staticRevocations{}))
	claims := mintedClaims()
	delete(claims, "jti")

	out := a.Resolve(context.Background(), HS256LegacyAuth(fixtureOrg, claims, true, "", ""))
	if out.Subject.Admission.State != AdmissionIndeterminate {
		t.Fatalf("state = %s, want INDETERMINATE", out.Subject.Admission.State)
	}
	if out.Subject.Admission.Reason != ReasonRevocationUnavailable {
		t.Fatalf("reason = %s, want %s", out.Subject.Admission.Reason, ReasonRevocationUnavailable)
	}
	if out.Divergence != DivergenceIdentityIndeterminate {
		t.Fatalf("divergence = %s, want %s", out.Divergence, DivergenceIdentityIndeterminate)
	}
}

// TestCompatRevokedTokenIsDenied confirms the oracle is actually consulted,
// which the indeterminate case above cannot show.
func TestCompatRevokedTokenIsDenied(t *testing.T) {
	a, _, _ := compatFixture(t, CompatModeShadow, BuiltinRealmDeployment{HasRevocation: true},
		WithCompatRevocations(staticRevocations{revoked: map[string]bool{"jti-1": true}}))

	out := a.Resolve(context.Background(), HS256LegacyAuth(fixtureOrg, mintedClaims(), true, "", ""))
	if out.Subject.Admission.Reason != ReasonCredentialRevoked {
		t.Fatalf("reason = %s, want %s", out.Subject.Admission.Reason, ReasonCredentialRevoked)
	}
}

// TestCompatRevocationOutageIsIndeterminateNotClear pins the direction: an
// oracle that errors must never read as "not revoked".
func TestCompatRevocationOutageIsIndeterminateNotClear(t *testing.T) {
	a, _, _ := compatFixture(t, CompatModeShadow, BuiltinRealmDeployment{HasRevocation: true},
		WithCompatRevocations(staticRevocations{err: errors.New("deny-list unreachable")}))

	out := a.Resolve(context.Background(), HS256LegacyAuth(fixtureOrg, mintedClaims(), true, "", ""))
	if out.Subject.Admission.State != AdmissionIndeterminate {
		t.Fatalf("a revocation outage produced %s, want INDETERMINATE", out.Subject.Admission.State)
	}
}

// TestCompatTrustedHeaderNeedsASubjectNotAnAlias is the fourth expected
// divergence: an upstream asserting only an address has asserted an alias.
func TestCompatTrustedHeaderNeedsASubjectNotAnAlias(t *testing.T) {
	t.Run("email only is SUBJECT_MISSING", func(t *testing.T) {
		a, _, _ := compatFixture(t, CompatModeShadow, BuiltinRealmDeployment{})
		out := a.Resolve(context.Background(),
			TrustedHeaderLegacyAuth(fixtureOrg, "", "dev@corp.example", true, "", fixtureNow))
		if out.Subject.Admission.Reason != ReasonSubjectMissing {
			t.Fatalf("reason = %s, want %s", out.Subject.Admission.Reason, ReasonSubjectMissing)
		}
	})

	t.Run("a stable user id is admitted, with the email as an alias", func(t *testing.T) {
		a, _, _ := compatFixture(t, CompatModeShadow, BuiltinRealmDeployment{})
		out := a.Resolve(context.Background(),
			TrustedHeaderLegacyAuth(fixtureOrg, "u-42", "dev@corp.example", true, "", fixtureNow))
		if !out.Subject.Admission.State.IsAdmitted() {
			t.Fatalf("admission = %s %s (%s)", out.Subject.Admission.State, out.Subject.Admission.Reason, out.Subject.Admission.Detail)
		}
		if got := out.Subject.Admission.Principal.Subject; got != "u-42" {
			t.Fatalf("canonical subject = %q, want the asserted user id", got)
		}
		if len(out.Subject.Aliases) != 1 || out.Subject.Aliases[0].Kind != AliasEmail ||
			out.Subject.Aliases[0].Value != "dev@corp.example" {
			t.Fatalf("aliases = %+v, want the email recorded as an alias", out.Subject.Aliases)
		}
	})

	t.Run("nothing asserted at all is SUBJECT_MISSING, not admitted", func(t *testing.T) {
		a, _, _ := compatFixture(t, CompatModeShadow, BuiltinRealmDeployment{})
		out := a.Resolve(context.Background(),
			TrustedHeaderLegacyAuth(fixtureOrg, "", "", false, "the identity-trust gate is off", fixtureNow))
		if out.Subject.Admission.State.IsAdmitted() {
			t.Fatalf("an empty header assertion was admitted")
		}
		if out.Divergence != DivergenceNone {
			t.Fatalf("divergence = %s: legacy also declined, so the two agree", out.Divergence)
		}
	})
}

// --- enforcement ---

// TestCompatShadowNeverRefuses is the split, stated once for every path: the
// SAME inputs that enforce under enforce record and return nothing under
// shadow.
func TestCompatShadowNeverRefuses(t *testing.T) {
	claims := mintedClaims()
	claims["org_id"] = fixtureOtherOrg

	for _, path := range []struct {
		name string
		in   LegacyAuth
	}{
		{"hs256", HS256LegacyAuth(fixtureOrg, claims, true, "", "")},
		{"oidc", OIDCLegacyAuth(fixtureOrg, map[string]any{"iss": issuerAcquired, "sub": "s", "exp": float64(fixtureNow.Add(time.Hour).Unix())}, true, "", "")},
		{"api_credential", APICredentialLegacyAuth(fixtureOrg, "", VerificationAPICredential, true, "", fixtureNow)},
		{"trusted_header", TrustedHeaderLegacyAuth(fixtureOrg, "", "dev@corp.example", true, "", fixtureNow)},
	} {
		t.Run(path.name, func(t *testing.T) {
			shadow, shadowRec, _ := compatFixture(t, CompatModeShadow, BuiltinRealmDeployment{})
			shadowOut := shadow.Resolve(context.Background(), path.in)
			if shadowOut.Refusal() != nil {
				t.Fatalf("shadow refused: %v", shadowOut.Refusal())
			}
			if shadowOut.Subject.Admission.State.IsAdmitted() {
				t.Fatalf("this case is meant to be one the identity plane refuses; it admitted")
			}
			if r := shadowRec.last(t); r.Enforced {
				t.Fatalf("a shadow record was marked enforced")
			}

			enforce, enforceRec, _ := compatFixture(t, CompatModeEnforce, BuiltinRealmDeployment{})
			enforceOut := enforce.Resolve(context.Background(), path.in)
			if enforceOut.Refusal() == nil {
				t.Fatalf("enforce did not refuse the same input shadow declined to")
			}
			// The POSITIVE half. Without it, Enforced could be hardcoded false
			// and both this assertion and the runtime suite's enforced= grep
			// would pass, which is two mutually vacuous checks over one field.
			if r := enforceRec.last(t); !r.Enforced {
				t.Fatalf("an ENFORCED refusal was recorded with Enforced=false")
			}
			if enforceOut.Subject.Admission.Reason != shadowOut.Subject.Admission.Reason {
				t.Fatalf("shadow and enforce reached different reasons: %s vs %s",
					shadowOut.Subject.Admission.Reason, enforceOut.Subject.Admission.Reason)
			}
		})
	}
}

// TestCompatNeverAdmitsWhatLegacyRejected is the one-direction invariant: the
// adapter has no route by which a legacy rejection becomes an acceptance, in
// any mode, for any path.
func TestCompatNeverAdmitsWhatLegacyRejected(t *testing.T) {
	for _, mode := range []CompatMode{CompatModeShadow, CompatModeEnforce} {
		a, rec, _ := compatFixture(t, mode, BuiltinRealmDeployment{})
		// A claim set that would otherwise pass every realm check.
		out := a.Resolve(context.Background(), HS256LegacyAuth(fixtureOrg, mintedClaims(), false, "signature mismatch", ""))

		if out.Subject.Admission.State.IsAdmitted() {
			t.Fatalf("mode %s: the identity plane ADMITTED a credential the legacy path rejected", mode)
		}
		if out.Subject.Admission.Reason != ReasonSignatureNotVerified {
			t.Fatalf("mode %s: reason = %s, want %s", mode, out.Subject.Admission.Reason, ReasonSignatureNotVerified)
		}
		if out.Refusal() != nil {
			t.Fatalf("mode %s: a legacy rejection produced a refusal of its own; there is nothing left to refuse", mode)
		}
		if out.Divergence != DivergenceNone {
			t.Fatalf("mode %s: divergence = %s, want none", mode, out.Divergence)
		}
		if rec.last(t).Divergence == DivergenceIdentityAdmittedLegacyRejected {
			t.Fatalf("mode %s: the unreachable alarm fired", mode)
		}
	}
}

// --- adapter-side defects ---

func TestCompatAdapterDefectsNeverEnforce(t *testing.T) {
	base := func() LegacyAuth { return HS256LegacyAuth(fixtureOrg, mintedClaims(), true, "", "") }
	for _, tc := range []struct {
		name   string
		mutate func(*LegacyAuth)
	}{
		{"an undeclared legacy path", func(in *LegacyAuth) { in.Path = LegacyPath("smtp") }},
		{"a legacy decision left at its zero value", func(in *LegacyAuth) { in.Decision = LegacyDecisionUnspecified }},
		{"an out-of-range legacy decision", func(in *LegacyAuth) { in.Decision = LegacyDecision(99) }},
		{"no authenticated organization", func(in *LegacyAuth) { in.AuthenticatedOrgID = " " }},
		{"a nil claim set", func(in *LegacyAuth) { in.Claims = nil }},
		{"a caller-supplied canonical subject", func(in *LegacyAuth) { in.Credential.Subject = "smuggled" }},
		{"an unverifiable reason outside the allow-list", func(in *LegacyAuth) {
			in.Decision = LegacyDecisionRejected
			in.UnverifiableReason = ReasonUnknownRealm
		}},
		{"an unverifiable reason on an ACCEPTED credential", func(in *LegacyAuth) {
			in.UnverifiableReason = ReasonKeyMaterialUnavailable
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, rec, _ := compatFixture(t, CompatModeEnforce, BuiltinRealmDeployment{})
			in := base()
			tc.mutate(&in)

			out := a.Resolve(context.Background(), in)
			if out.Divergence != DivergenceAdapterDefect {
				t.Fatalf("divergence = %s, want %s", out.Divergence, DivergenceAdapterDefect)
			}
			if out.Refusal() != nil {
				t.Fatalf("an adapter-side defect refused a caller's request")
			}
			if out.Evaluated {
				t.Fatalf("an adapter-side defect reported Evaluated")
			}
			if r := rec.last(t); r.IdentityReason != ReasonIdentityInternalError {
				t.Fatalf("recorded reason = %s, want %s", r.IdentityReason, ReasonIdentityInternalError)
			}
		})
	}
}

// --- unverifiable causes ---

func TestCompatUnverifiableReasonShortCircuits(t *testing.T) {
	for _, reason := range []AdmissionReason{ReasonKeyMaterialUnavailable, ReasonRevocationUnavailable} {
		t.Run(string(reason), func(t *testing.T) {
			a, rec, _ := compatFixture(t, CompatModeEnforce, BuiltinRealmDeployment{})
			out := a.Resolve(context.Background(),
				OIDCLegacyAuth(fixtureOrg, nil, false, "the IdP could not be reached", reason))

			if out.Subject.Admission.State != AdmissionIndeterminate {
				t.Fatalf("state = %s, want INDETERMINATE", out.Subject.Admission.State)
			}
			if out.Subject.Admission.Reason != reason {
				t.Fatalf("reason = %s, want %s", out.Subject.Admission.Reason, reason)
			}
			if out.Subject.Admission.Reason == ReasonSignatureNotVerified {
				t.Fatalf("an outage was reported as a forgery")
			}
			if out.Refusal() != nil {
				t.Fatalf("a legacy rejection produced a refusal")
			}
			if rec.last(t).IdentityReason != reason {
				t.Fatalf("the outage was not recorded under its own reason")
			}
		})
	}
}

func TestClassifyTokenError(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want AdmissionReason
	}{
		{"no error", nil, ""},
		{"an invalid token is determinate", fmt.Errorf("wrapped: %w", ErrTokenInvalid), ""},
		{"a revoked token is determinate", ErrTokenRevoked, ""},
		{"an unconfigured backend is determinate", ErrNotConfigured, ""},
		{"unavailable key material", fmt.Errorf("wrapped: %w", ErrJWKSUnavailable), ReasonKeyMaterialUnavailable},
		{"an unreachable deny-list", fmt.Errorf("wrapped: %w", ErrRevocationUnavailable), ReasonRevocationUnavailable},
	} {
		if got := ClassifyTokenError(tc.err); got != tc.want {
			t.Fatalf("%s: ClassifyTokenError = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// --- realm-source outages ---

// TestCompatRealmOutageIsIndeterminateNotUnknownRealm: a realm source that
// cannot answer must not present as an organization with no realms, which
// would send an operator to declare a realm that already exists.
func TestCompatRealmOutageIsIndeterminateNotUnknownRealm(t *testing.T) {
	rec := &captureRecorder{}
	a, err := NewCompatAdapter(CompatModeEnforce, NewRealmRegistry(),
		failingRealmSource{err: errors.New("realm store unreachable")}, rec,
		WithCompatClock(func() time.Time { return fixtureNow }))
	if err != nil {
		t.Fatalf("NewCompatAdapter: %v", err)
	}

	out := a.Resolve(context.Background(), HS256LegacyAuth(fixtureOrg, mintedClaims(), true, "", ""))
	if out.Subject.Admission.State != AdmissionIndeterminate {
		t.Fatalf("state = %s, want INDETERMINATE", out.Subject.Admission.State)
	}
	if out.Subject.Admission.Reason == ReasonUnknownRealm {
		t.Fatalf("a realm-source outage was reported as UNKNOWN_REALM")
	}
	if out.Refusal() == nil {
		t.Fatalf("enforce mode admitted a credential the identity plane could not verify")
	}
}

// TestBuiltinRealmsAreRegisteredOnce pins the memoization: the version-must-
// advance rule in the registry means a second registration of the same
// built-ins would fail, so the source must not attempt one.
func TestBuiltinRealmsAreRegisteredOnce(t *testing.T) {
	reg := NewRealmRegistry()
	inner, err := NewBuiltinRealmSource(reg, BuiltinRealmDeployment{})
	if err != nil {
		t.Fatalf("NewBuiltinRealmSource: %v", err)
	}
	src := &countingRealmSource{inner: inner}
	rec := &captureRecorder{}
	a, err := NewCompatAdapter(CompatModeShadow, reg, src, rec, WithCompatClock(func() time.Time { return fixtureNow }))
	if err != nil {
		t.Fatalf("NewCompatAdapter: %v", err)
	}

	for i := 0; i < 3; i++ {
		out := a.Resolve(context.Background(), HS256LegacyAuth(fixtureOrg, mintedClaims(), true, "", ""))
		if !out.Subject.Admission.State.IsAdmitted() {
			t.Fatalf("call %d: %s %s (%s)", i, out.Subject.Admission.State,
				out.Subject.Admission.Reason, out.Subject.Admission.Detail)
		}
	}
	if src.calls != 3 {
		t.Fatalf("the realm source was consulted %d times, want once per request", src.calls)
	}
	epoch := reg.Epoch()
	if _, ok := reg.Lookup(fixtureOrg, BuiltinRealmMinted); !ok {
		t.Fatalf("the minted realm was not registered")
	}
	// A fourth request must not mutate the registry.
	a.Resolve(context.Background(), HS256LegacyAuth(fixtureOrg, mintedClaims(), true, "", ""))
	if reg.Epoch() != epoch {
		t.Fatalf("the registry epoch advanced on a repeat request: realms are being re-registered")
	}
}

// TestBuiltinRealmsAreOrgScoped: one organization's built-ins never answer for
// another's.
func TestBuiltinRealmsAreOrgScoped(t *testing.T) {
	a, _, reg := compatFixture(t, CompatModeShadow, BuiltinRealmDeployment{})
	a.Resolve(context.Background(), HS256LegacyAuth(fixtureOrg, mintedClaims(), true, "", ""))

	if _, ok := reg.LookupByIssuer(fixtureOtherOrg, UserTokenIssuer); ok {
		t.Fatalf("one organization's built-in realm resolved for another")
	}
}

// --- built-in realm declarations ---

func TestBuiltinRealmsValidate(t *testing.T) {
	for _, dep := range []BuiltinRealmDeployment{
		{},
		{HasDirectory: true, HasRevocation: true},
		{HasDirectory: true, HasRevocation: true, HasCAEP: true},
	} {
		realms := BuiltinRealms(fixtureOrg, dep)
		if len(realms) == 0 {
			t.Fatalf("no built-in realms for %+v", dep)
		}
		seenID := map[RealmID]bool{}
		seenIssuer := map[string]bool{}
		for _, r := range realms {
			if err := r.Validate(); err != nil {
				t.Fatalf("built-in realm %q (%+v) is invalid: %v", r.RealmID, dep, err)
			}
			if seenID[r.RealmID] {
				t.Fatalf("duplicate built-in realm id %q", r.RealmID)
			}
			seenID[r.RealmID] = true
			if seenIssuer[r.CanonicalIssuer] {
				t.Fatalf("two built-in realms claim issuer %q; the registry refuses that", r.CanonicalIssuer)
			}
			seenIssuer[r.CanonicalIssuer] = true
			if r.OrgID != fixtureOrg {
				t.Fatalf("built-in realm %q carries org %q", r.RealmID, r.OrgID)
			}
		}
	}
}

// TestBuiltinDirectoryAndRevocationArePositiveDeclarations: the two deployment
// booleans decide facts that EX-45 turns on, so they must actually move.
func TestBuiltinDirectoryAndRevocationArePositiveDeclarations(t *testing.T) {
	bare := realmByID(t, BuiltinRealms(fixtureOrg, BuiltinRealmDeployment{}), BuiltinRealmMinted)
	if bare.Directory != DirectorySourceNone {
		t.Fatalf("a deployment with no directory declared %s", bare.Directory)
	}
	if bare.Revocation != RevocationSourceNone {
		t.Fatalf("a deployment with no deny-list declared %s", bare.Revocation)
	}
	if bare.HasGroupGraph() {
		t.Fatalf("a no-directory realm reports a group graph")
	}

	wired := realmByID(t, BuiltinRealms(fixtureOrg, BuiltinRealmDeployment{HasDirectory: true, HasRevocation: true}), BuiltinRealmMinted)
	if wired.Directory != DirectorySourceSCIM {
		t.Fatalf("a deployment WITH a directory declared %s", wired.Directory)
	}
	if wired.Revocation != RevocationSourceLocalStore {
		t.Fatalf("a deployment WITH a deny-list declared %s", wired.Revocation)
	}
}

// TestBuiltinAPICredentialAssertsAClientNotAUser is ADR-065 invariant 2: a
// client credential authenticates an application, and a Client principal is
// attribution rather than authority.
func TestBuiltinAPICredentialAssertsAClientNotAUser(t *testing.T) {
	realms := BuiltinRealms(fixtureOrg, BuiltinRealmDeployment{})
	api := realmByID(t, realms, BuiltinRealmAPICredential)
	if api.ClaimMapping.SubjectType != SubjectClient {
		t.Fatalf("the api-credential realm asserts %s", api.ClaimMapping.SubjectType)
	}
	if api.AcceptsSubjectType(SubjectUser) {
		t.Fatalf("the api-credential realm accepts a User subject; an API key is not a person")
	}
	svc := realmByID(t, realms, BuiltinRealmInternalService)
	if svc.ClaimMapping.SubjectType != SubjectService {
		t.Fatalf("the internal-service realm asserts %s", svc.ClaimMapping.SubjectType)
	}
	if api.Interactive.CanAnswer() || svc.Interactive.CanAnswer() {
		t.Fatalf("a non-human realm reports that it can answer an approval (EX-46)")
	}
}

// TestBuiltinTrustedHeaderCannotClaimHighAssurance: TrustRealm.Validate caps a
// trusted-header realm at AssuranceLow, and the community realm is declared as
// one precisely so it inherits that ceiling.
func TestBuiltinTrustedHeaderCannotClaimHighAssurance(t *testing.T) {
	realms := BuiltinRealms(fixtureOrg, BuiltinRealmDeployment{})
	for _, id := range []RealmID{BuiltinRealmTrustedHeader, BuiltinRealmCommunity} {
		r := realmByID(t, realms, id)
		if r.Kind != RealmKindTrustedHeader {
			t.Fatalf("realm %q kind = %s", id, r.Kind)
		}
		if r.MinimumAssurance > AssuranceLow {
			t.Fatalf("realm %q declares assurance %s above the trusted-header ceiling", id, r.MinimumAssurance)
		}
		r.MinimumAssurance = AssuranceHigh
		if err := r.Validate(); err == nil {
			t.Fatalf("realm %q accepted an assurance above the trusted-header ceiling", id)
		}
	}
}

// TestVerificationNoneIsNotSpelledNone: TrustRealm.Validate refuses the literal
// "none" case-insensitively because in a JWT header it means an unsigned
// token, and "this deployment requires no credential" is a different fact.
func TestVerificationNoneIsNotSpelledNone(t *testing.T) {
	if strings.EqualFold(VerificationCommunityUnauthenticated, "none") {
		t.Fatalf("the community verification method is spelled %q, which Validate refuses", VerificationCommunityUnauthenticated)
	}
	for _, v := range []string{VerificationAPICredential, VerificationHMACInternalService, VerificationUpstreamAsserted, VerificationCommunityUnauthenticated} {
		if strings.TrimSpace(v) == "" {
			t.Fatalf("an empty verification method")
		}
	}
}

func realmByID(t *testing.T, realms []TrustRealm, id RealmID) TrustRealm {
	t.Helper()
	for _, r := range realms {
		if r.RealmID == id {
			return r
		}
	}
	t.Fatalf("no built-in realm %q", id)
	return TrustRealm{}
}

// --- the live-verification window ---

// TestLiveVerifiedCredentialsExpire: an API credential has no expiry of its
// own, and the synthesized window can only ever NARROW what is admissible.
func TestLiveVerifiedCredentialsExpire(t *testing.T) {
	verifiedAt := fixtureNow.Add(-2 * LiveVerificationWindow)
	a, _, _ := compatFixture(t, CompatModeShadow, BuiltinRealmDeployment{})

	stale := a.Resolve(context.Background(),
		APICredentialLegacyAuth(fixtureOrg, "client-1", VerificationAPICredential, true, "", verifiedAt))
	if stale.Subject.Admission.Reason != ReasonCredentialExpired {
		t.Fatalf("a verification two windows old: reason = %s, want %s", stale.Subject.Admission.Reason, ReasonCredentialExpired)
	}

	fresh := a.Resolve(context.Background(),
		APICredentialLegacyAuth(fixtureOrg, "client-1", VerificationAPICredential, true, "", fixtureNow))
	if !fresh.Subject.Admission.State.IsAdmitted() {
		t.Fatalf("a fresh verification was refused: %s %s", fresh.Subject.Admission.Reason, fresh.Subject.Admission.Detail)
	}
	if got := fresh.Subject.Admission.Principal.Type; got != SubjectClient {
		t.Fatalf("an API credential produced a %s principal", got)
	}
}

// TestInternalServiceIsCoveredByTheAPICredentialAdapter: the fifth auth entry
// point a four-adapter census misses.
func TestInternalServiceIsCoveredByTheAPICredentialAdapter(t *testing.T) {
	a, _, _ := compatFixture(t, CompatModeShadow, BuiltinRealmDeployment{})
	out := a.Resolve(context.Background(),
		InternalServiceLegacyAuth(fixtureOrg, "orchestrator", true, "", fixtureNow))
	if !out.Subject.Admission.State.IsAdmitted() {
		t.Fatalf("admission = %s %s (%s)", out.Subject.Admission.State, out.Subject.Admission.Reason, out.Subject.Admission.Detail)
	}
	if out.Subject.Admission.Principal.Type != SubjectService {
		t.Fatalf("the internal-service hop produced a %s principal", out.Subject.Admission.Principal.Type)
	}
	if out.Subject.Realm.RealmID != BuiltinRealmInternalService {
		t.Fatalf("realm = %q", out.Subject.Realm.RealmID)
	}
}

// TestCommunityModeIsAnAssertionNotAnAbsence: community mode declares that it
// accepts an unverified assertion, which is a fact worth naming in an audit
// trail rather than an absence of identity.
func TestCommunityModeIsAnAssertionNotAnAbsence(t *testing.T) {
	a, _, _ := compatFixture(t, CompatModeShadow, BuiltinRealmDeployment{})
	out := a.Resolve(context.Background(), CommunityLegacyAuth(fixtureOrg, "community", fixtureNow))
	if !out.Subject.Admission.State.IsAdmitted() {
		t.Fatalf("admission = %s %s (%s)", out.Subject.Admission.State, out.Subject.Admission.Reason, out.Subject.Admission.Detail)
	}
	if out.Subject.Realm.Kind != RealmKindTrustedHeader {
		t.Fatalf("the community realm kind = %s", out.Subject.Realm.Kind)
	}
	if out.Subject.Assurance != AssuranceLow {
		t.Fatalf("community mode attested assurance %s", out.Subject.Assurance)
	}
}

// --- claim readers ---

func TestAudienceClaimShapes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		claims map[string]any
		want   []string
	}{
		{"absent yields the deployment audience", map[string]any{}, []string{AudienceDeployment}},
		{"a single string", map[string]any{"aud": "a"}, []string{"a"}},
		{"a []string", map[string]any{"aud": []string{"a", "b"}}, []string{"a", "b"}},
		{"a []any of strings", map[string]any{"aud": []any{"a", "b"}}, []string{"a", "b"}},
		{"a []any with a non-string member drops it", map[string]any{"aud": []any{"a", 7}}, []string{"a"}},
		{"a shape that is not an audience yields NOTHING, which intersects nothing", map[string]any{"aud": 7}, nil},
	} {
		got := audienceClaim(tc.claims)
		if len(got) != len(tc.want) {
			t.Fatalf("%s: audienceClaim = %v, want %v", tc.name, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("%s: audienceClaim = %v, want %v", tc.name, got, tc.want)
			}
		}
	}
}

// TestMalformedAudienceIsRefusedNotDefaulted pins the direction of the last
// case above: a malformed aud must not fall back to the deployment audience,
// which would admit it.
func TestMalformedAudienceIsRefusedNotDefaulted(t *testing.T) {
	a, _, _ := compatFixture(t, CompatModeShadow, BuiltinRealmDeployment{})
	claims := mintedClaims()
	claims["aud"] = 7

	out := a.Resolve(context.Background(), HS256LegacyAuth(fixtureOrg, claims, true, "", ""))
	if out.Subject.Admission.Reason != ReasonAudienceRejected {
		t.Fatalf("reason = %s, want %s", out.Subject.Admission.Reason, ReasonAudienceRejected)
	}
}

func TestTimeClaimShapes(t *testing.T) {
	ts := int64(1788000000)
	for _, tc := range []struct {
		name  string
		value any
		want  time.Time
	}{
		{"float64", float64(ts), time.Unix(ts, 0).UTC()},
		{"int64", ts, time.Unix(ts, 0).UTC()},
		{"int", int(ts), time.Unix(ts, 0).UTC()},
		{"json.Number", json.Number("1788000000"), time.Unix(ts, 0).UTC()},
		{"a string is not a NumericDate", "1788000000", time.Time{}},
		{"a bool is not a NumericDate", true, time.Time{}},
	} {
		got := timeClaim(map[string]any{"exp": tc.value}, "exp")
		if !got.Equal(tc.want) {
			t.Fatalf("%s: timeClaim = %v, want %v", tc.name, got, tc.want)
		}
	}
	if got := timeClaim(map[string]any{}, "exp"); !got.IsZero() {
		t.Fatalf("an absent claim yielded %v", got)
	}
	// Sub-second precision survives: a truncated exp would expire a credential
	// up to a second early, and a truncated nbf would admit one early.
	frac := timeClaim(map[string]any{"exp": float64(ts) + 0.5}, "exp")
	if frac.Nanosecond() == 0 {
		t.Fatalf("a fractional NumericDate was truncated to whole seconds")
	}
}

func TestClaimPresence(t *testing.T) {
	for _, tc := range []struct {
		name        string
		claims      map[string]any
		wantValue   string
		wantPresent bool
	}{
		{"absent", map[string]any{}, "", false},
		{"present and empty", map[string]any{"org_id": ""}, "", true},
		{"present with a value", map[string]any{"org_id": "o"}, "o", true},
		{"present as a non-string is PRESENT, not absent", map[string]any{"org_id": 7}, "", true},
	} {
		v, present := claimPresence(tc.claims, "org_id")
		if v != tc.wantValue || present != tc.wantPresent {
			t.Fatalf("%s: claimPresence = (%q, %v), want (%q, %v)", tc.name, v, present, tc.wantValue, tc.wantPresent)
		}
	}
}

// --- recorder ---

func TestLogRecorderCountsAndSamples(t *testing.T) {
	r := NewLogCounterfactualRecorder(0)
	for i := 0; i < 5; i++ {
		r.RecordCounterfactual(context.Background(), Counterfactual{Divergence: DivergenceNone, Path: LegacyPathHS256})
	}
	r.RecordCounterfactual(context.Background(), Counterfactual{Divergence: DivergenceIdentityRefused, Path: LegacyPathHS256})
	r.RecordCounterfactual(context.Background(), Counterfactual{Divergence: DivergenceIdentityRefused, Path: LegacyPathOIDC})

	snap := r.Snapshot()
	if snap.ByDivergence[DivergenceNone] != 5 {
		t.Fatalf("agreements = %d, want 5", snap.ByDivergence[DivergenceNone])
	}
	if snap.ByDivergence[DivergenceIdentityRefused] != 2 {
		t.Fatalf("refusals = %d, want 2", snap.ByDivergence[DivergenceIdentityRefused])
	}
	if snap.ByPath[LegacyPathHS256][DivergenceIdentityRefused] != 1 ||
		snap.ByPath[LegacyPathOIDC][DivergenceIdentityRefused] != 1 {
		t.Fatalf("per-path divergences = %+v", snap.ByPath)
	}
	if _, ok := snap.ByPath[LegacyPathHS256][DivergenceNone]; ok {
		t.Fatalf("agreements were counted per path; that is one counter per request and answers nothing")
	}
	// The snapshot is a copy.
	snap.ByDivergence[DivergenceNone] = 999
	if r.Snapshot().ByDivergence[DivergenceNone] != 5 {
		t.Fatalf("Snapshot handed out a live map")
	}
}

// TestOutageIsLoggedEvenThoughThePlanesAgree: a legacy rejection and an
// identity-plane Indeterminate AGREE on the outcome, so the divergence is
// none. Sampling that away hides the operationally sharpest record this plane
// produces, which is that the IdP or the deny-list is down. The runtime suite
// found this by asserting on a KEY_MATERIAL_UNAVAILABLE record that was never
// being logged.
func TestOutageIsLoggedEvenThoughThePlanesAgree(t *testing.T) {
	for _, tc := range []struct {
		name string
		rec  Counterfactual
		want bool
	}{
		{
			name: "an outage both planes refused is logged",
			rec:  Counterfactual{Divergence: DivergenceNone, IdentityState: AdmissionIndeterminate, IdentityReason: ReasonKeyMaterialUnavailable},
			want: true,
		},
		{
			name: "an ordinary agreement is sampled",
			rec:  Counterfactual{Divergence: DivergenceNone, IdentityState: AdmissionAccept},
			want: false,
		},
		{
			name: "a determinate refusal both planes reached is sampled, not logged one line per expired token",
			rec:  Counterfactual{Divergence: DivergenceNone, IdentityState: AdmissionDeny, IdentityReason: ReasonSignatureNotVerified},
			want: false,
		},
		{
			name: "a divergence is always logged",
			rec:  Counterfactual{Divergence: DivergenceIdentityRefused, IdentityState: AdmissionDeny},
			want: true,
		},
		{
			name: "an indeterminate divergence is logged",
			rec:  Counterfactual{Divergence: DivergenceIdentityIndeterminate, IdentityState: AdmissionIndeterminate},
			want: true,
		},
	} {
		if got := logsIndividually(tc.rec); got != tc.want {
			t.Fatalf("%s: logsIndividually = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestMultiRecorderSkipsNilMembers(t *testing.T) {
	a := &captureRecorder{}
	b := &captureRecorder{}
	m := MultiCounterfactualRecorder{a, nil, b}
	m.RecordCounterfactual(context.Background(), Counterfactual{Divergence: DivergenceNone})
	if len(a.records) != 1 || len(b.records) != 1 {
		t.Fatalf("a nil member stopped the fan-out")
	}
}

// --- process adapter ---

func TestProcessCompatAdapterRoundTrip(t *testing.T) {
	prior := ProcessCompatAdapter()
	t.Cleanup(func() { SetProcessCompatAdapter(prior) })

	SetProcessCompatAdapter(nil)
	if out := CompatResolve(context.Background(), HS256LegacyAuth(fixtureOrg, mintedClaims(), true, "", "")); out.Refusal() != nil {
		t.Fatalf("an uninstalled process adapter refused a request")
	}

	a, _, _ := compatFixture(t, CompatModeEnforce, BuiltinRealmDeployment{})
	SetProcessCompatAdapter(a)
	claims := mintedClaims()
	claims["iss"] = issuerAcquired
	if out := CompatResolve(context.Background(), HS256LegacyAuth(fixtureOrg, claims, true, "", "")); out.Refusal() == nil {
		t.Fatalf("the installed process adapter did not enforce")
	}
}

// --- bootstrap ---

func TestBootstrapCompatRefusesABadMode(t *testing.T) {
	if _, err := BootstrapCompat(CompatBootstrapConfig{RawMode: "enfore"}); err == nil {
		t.Fatalf("BootstrapCompat accepted an unrecognized mode; a deployment that believes it enforces must not boot silently off")
	}
	b, err := BootstrapCompat(CompatBootstrapConfig{RawMode: "shadow"})
	if err != nil {
		t.Fatalf("BootstrapCompat: %v", err)
	}
	if b.Mode != CompatModeShadow || b.Adapter == nil || b.Registry == nil || b.Recorder == nil {
		t.Fatalf("BootstrapCompat returned %+v", b)
	}
}

func TestBootstrapCompatPropagatesAnExtraSourceFailure(t *testing.T) {
	boom := errors.New("no OIDC provider")
	_, err := BootstrapCompat(CompatBootstrapConfig{
		RawMode: "shadow",
		ExtraRealmSources: func(*RealmRegistry) ([]CompatRealmSource, error) {
			return nil, boom
		},
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the extra source's failure", err)
	}
}

// TestCompatRealmSourceFailureDoesNotRefuseADeclaredIssuer: a realm source is a
// CHAIN. The built-ins register once and never fail again; the tenant OIDC
// source reads a database row and can fail for reasons that have nothing to do
// with the credential in hand. One unreadable sso_configurations row must not
// refuse the client credential, the internal-service hop and the HS256 token,
// none of which involves OIDC.
func TestCompatRealmSourceFailureDoesNotRefuseADeclaredIssuer(t *testing.T) {
	reg := NewRealmRegistry()
	builtins, err := NewBuiltinRealmSource(reg, BuiltinRealmDeployment{},
		failingRealmSource{err: errors.New("the tenant OIDC row will not parse")})
	if err != nil {
		t.Fatalf("NewBuiltinRealmSource: %v", err)
	}
	rec := &captureRecorder{}
	a, err := NewCompatAdapter(CompatModeEnforce, reg, builtins, rec,
		WithCompatClock(func() time.Time { return fixtureNow }))
	if err != nil {
		t.Fatalf("NewCompatAdapter: %v", err)
	}

	// The built-in minted realm IS registered (the extras run after them), so
	// this credential's issuer resolves even though the chain reported a
	// failure.
	out := a.Resolve(context.Background(), HS256LegacyAuth(fixtureOrg, mintedClaims(), true, "", ""))
	if !out.Subject.Admission.State.IsAdmitted() {
		t.Fatalf("a credential whose realm IS declared was refused because another source in the chain failed: %s %s (%s)",
			out.Subject.Admission.State, out.Subject.Admission.Reason, out.Subject.Admission.Detail)
	}
	if out.Refusal() != nil {
		t.Fatalf("enforce refused: %v", out.Refusal())
	}

	// The control: a credential whose issuer does NOT resolve stays
	// Indeterminate, because a failed source and an undeclared issuer cannot
	// be told apart.
	claims := mintedClaims()
	claims["iss"] = issuerAcquired
	miss := a.Resolve(context.Background(), HS256LegacyAuth(fixtureOrg, claims, true, "", ""))
	if miss.Subject.Admission.State != AdmissionIndeterminate {
		t.Fatalf("an undeclared issuer under a failed realm source: state = %s, want INDETERMINATE", miss.Subject.Admission.State)
	}
	if miss.Subject.Admission.Reason == ReasonUnknownRealm {
		t.Fatalf("a realm-source outage was reported as UNKNOWN_REALM")
	}
}

// TestBuiltinRealmSourceMemoizesAFailure: the remedy for an invalid built-in
// realm is a fixed build, not a validation spent on every request forever, and
// a partially registered organization must not read as a successful one.
func TestBuiltinRealmSourceMemoizesAFailure(t *testing.T) {
	reg := NewRealmRegistry()
	src, err := NewBuiltinRealmSource(reg, BuiltinRealmDeployment{})
	if err != nil {
		t.Fatalf("NewBuiltinRealmSource: %v", err)
	}
	// Claim the minted realm's issuer for a DIFFERENT realm first, so the
	// built-in registration collides and fails.
	blocker := workspaceRealm()
	blocker.RealmID = "blocker"
	blocker.CanonicalIssuer = UserTokenIssuer
	if regErr := reg.Register(blocker); regErr != nil {
		t.Fatalf("register blocker: %v", regErr)
	}

	first := src.EnsureRealms(context.Background(), fixtureOrg)
	if first == nil {
		t.Fatalf("a colliding built-in registration was reported as success")
	}
	// THE DECISIVE STEP. Remove the obstacle. A source that memoized its
	// failure still reports it; a source that retries would now SUCCEED, and
	// nothing else in this test could tell the two apart - an epoch check
	// cannot, because a retry that fails again also leaves the epoch alone.
	reg.Remove(fixtureOrg, "blocker")
	second := src.EnsureRealms(context.Background(), fixtureOrg)
	if second == nil {
		t.Fatalf("the failure was not memoized: the source retried once the obstacle was removed, so an invalid built-in realm would cost a validation on every request forever")
	}
	if second.Error() != first.Error() {
		t.Fatalf("the memoized failure changed between calls: %v then %v", first, second)
	}
}

// TestResolveTokenKeepsTheOutageNotTheLastRejection: both validators are tried
// for every token and each rejects the other's credential class by SHAPE, so
// the LAST error is routinely from the validator that never had a chance.
func TestResolveTokenKeepsTheOutageNotTheLastRejection(t *testing.T) {
	ResetRegistryForTest()
	t.Cleanup(ResetRegistryForTest)
	prior := ProcessCompatAdapter()
	t.Cleanup(func() { SetProcessCompatAdapter(prior) })

	// Registration order mirrors production: HS256 first, OIDC second.
	if err := RegisterValidator(&fixedValidator{name: ValidatorNameHS256,
		err: fmt.Errorf("%w: revocation check failed", ErrRevocationUnavailable)}); err != nil {
		t.Fatalf("register hs256: %v", err)
	}
	if err := RegisterValidator(&fixedValidator{name: ValidatorNameOIDC,
		err: fmt.Errorf("%w: unexpected signing method", ErrTokenInvalid)}); err != nil {
		t.Fatalf("register oidc: %v", err)
	}

	a, rec, _ := compatFixture(t, CompatModeShadow, BuiltinRealmDeployment{})
	SetProcessCompatAdapter(a)

	if _, err := ResolveToken(context.Background(), fixtureOrg, "some-token"); err == nil {
		t.Fatalf("a token no validator accepted must be rejected")
	}
	r := rec.last(t)
	if r.IdentityReason != ReasonRevocationUnavailable {
		t.Fatalf("recorded reason = %s, want %s: the outage from the validator that examined the credential was lost to the shape rejection that followed it",
			r.IdentityReason, ReasonRevocationUnavailable)
	}
	if r.Path != LegacyPathHS256 {
		t.Fatalf("recorded path = %s, want hs256: the counterfactual was attributed to the validator that rejected by shape", r.Path)
	}
}

// fixedValidator always returns the same error.
type fixedValidator struct {
	name string
	err  error
}

func (v *fixedValidator) Name() string { return v.name }
func (v *fixedValidator) Validate(context.Context, string, string) (*ValidatedIdentity, error) {
	return nil, v.err
}

// TestARefusalNeverCarriesItsDetailToACaller is the guard on round one's
// sharpest finding, which shipped with no test at any level.
//
// CompatRefusal still implements error and Error() still renders Detail, so one
// future `return fmt.Errorf("...: %w", ref)` reopens the channel. The detail
// names the realm's declared subject claim, its accepted algorithms and
// audiences, the presented issuer, and - on the realm-chain branch - a wrapped
// DATABASE error. This asserts the property at the shared choke point, which is
// the site that had it wrong.
func TestARefusalNeverCarriesItsDetailToACaller(t *testing.T) {
	ResetRegistryForTest()
	t.Cleanup(ResetRegistryForTest)
	prior := ProcessCompatAdapter()
	t.Cleanup(func() { SetProcessCompatAdapter(prior) })

	a, rec, _ := compatFixture(t, CompatModeEnforce, BuiltinRealmDeployment{})
	SetProcessCompatAdapter(a)
	if err := RegisterValidator(&fixedIdentityValidator{
		name: ValidatorNameHS256,
		id: &ValidatedIdentity{
			Email: "dev@corp.example", OrgID: fixtureOrg, Validated: true,
			Source: ValidatorNameHS256,
			// An issuer no realm declares, so the identity plane refuses and
			// the detail quotes the issuer verbatim.
			Claims: map[string]any{
				"iss": issuerAcquired, "sub": "user-1138", "email": "dev@corp.example",
				"exp": float64(fixtureNow.Add(time.Hour).Unix()),
			},
		},
	}); err != nil {
		t.Fatalf("register: %v", err)
	}

	_, err := ResolveToken(context.Background(), fixtureOrg, "a-token")
	if err == nil {
		t.Fatalf("enforce did not refuse a credential from an undeclared issuer")
	}
	msg := err.Error()
	if !strings.Contains(msg, string(ReasonUnknownRealm)) {
		t.Fatalf("the refusal does not carry its reason CODE, which is what an operator correlates on: %q", msg)
	}
	// The detail exists and is recorded; it must not be in the error a caller
	// sees. Asserting on the RECORDED detail rather than on a literal keeps
	// this honest if the wording changes.
	detail := rec.last(t).IdentityDetail
	if detail == "" {
		t.Fatalf("no detail was recorded, so this test cannot tell suppression from absence")
	}
	if strings.Contains(msg, detail) {
		t.Fatalf("the refusal leaked its detail to the caller.\ndetail: %s\nerror:  %s", detail, msg)
	}
	if strings.Contains(msg, issuerAcquired) {
		t.Fatalf("the refusal leaked the presented issuer to the caller: %s", msg)
	}
}

// fixedIdentityValidator always returns the same validated identity.
type fixedIdentityValidator struct {
	name string
	id   *ValidatedIdentity
}

func (v *fixedIdentityValidator) Name() string { return v.name }
func (v *fixedIdentityValidator) Validate(context.Context, string, string) (*ValidatedIdentity, error) {
	return v.id, nil
}

// TestTheCounterfactualCarriesTheDetail: two call-site comments justify keeping
// the detail off a 401 by saying it is "in the counterfactual record, which is
// where an operator looks". It has to actually be there.
func TestTheCounterfactualCarriesTheDetail(t *testing.T) {
	a, rec, _ := compatFixture(t, CompatModeShadow, BuiltinRealmDeployment{})
	claims := mintedClaims()
	claims["iss"] = issuerAcquired

	a.Resolve(context.Background(), HS256LegacyAuth(fixtureOrg, claims, true, "", ""))
	r := rec.last(t)
	if r.IdentityDetail == "" {
		t.Fatalf("the record carries no detail, so UNKNOWN_REALM says some issuer is undeclared and not WHICH")
	}
	if !strings.Contains(r.IdentityDetail, issuerAcquired) {
		t.Fatalf("the detail does not name the undeclared issuer: %q", r.IdentityDetail)
	}
	if r.Component == "" {
		t.Fatalf("the record names no component; two processes log under one prefix")
	}
}

// TestRecorderGuardRefusesWhatCannotRecordAndAcceptsWhatCan. The reflect-based
// version of this guard was wrong in BOTH directions: it accepted
// MultiCounterfactualRecorder{} (an empty NON-NIL slice, which is the spelling
// anyone writing a fan-out types) and refused a legitimate stateless recorder
// implemented as a zero-width value type.
func TestRecorderGuardRefusesWhatCannotRecordAndAcceptsWhatCan(t *testing.T) {
	var typedNil *LogCounterfactualRecorder
	for _, tc := range []struct {
		name     string
		recorder CounterfactualRecorder
		wantOK   bool
	}{
		{"a plain nil", nil, false},
		{"a TYPED nil, whose method returns immediately", typedNil, false},
		{"a nil fan-out", MultiCounterfactualRecorder(nil), false},
		{"an EMPTY fan-out, which is what a fan-out is actually spelled", MultiCounterfactualRecorder{}, false},
		{"a fan-out of nothing but nils", MultiCounterfactualRecorder{nil, nil}, false},
		{"a fan-out of nothing but typed nils", MultiCounterfactualRecorder{typedNil}, false},
		{"a real recorder", NewLogCounterfactualRecorder(0), true},
		{"a fan-out with one real member", MultiCounterfactualRecorder{nil, NewLogCounterfactualRecorder(0)}, true},
		{"a STATELESS recorder implemented as a zero-width value type", statelessRecorder{}, true},
	} {
		_, err := NewCompatAdapter(CompatModeShadow, NewRealmRegistry(), failingRealmSource{}, tc.recorder)
		if tc.wantOK && err != nil {
			t.Fatalf("%s: refused a recorder that records: %v", tc.name, err)
		}
		if !tc.wantOK && err == nil {
			t.Fatalf("%s: accepted a recorder that records nothing", tc.name)
		}
	}
}

// statelessRecorder is a legitimate recorder with no state, which is what a
// Prometheus adapter looks like.
type statelessRecorder struct{}

func (statelessRecorder) RecordCounterfactual(context.Context, Counterfactual) {}

// TestEnforceReasonsNarrowsAndOnlyNarrows: an operator who has driven their
// undeclared issuers to zero in shadow must be able to enforce THAT without
// also enforcing SUBJECT_MISSING across a plugin fleet on the same day. The
// list can only ever narrow.
func TestEnforceReasonsNarrowsAndOnlyNarrows(t *testing.T) {
	undeclared := mintedClaims()
	undeclared["iss"] = issuerAcquired

	t.Run("a listed reason enforces", func(t *testing.T) {
		a, _, _ := compatFixture(t, CompatModeEnforce, BuiltinRealmDeployment{},
			WithCompatEnforceReasons([]AdmissionReason{ReasonUnknownRealm}))
		out := a.Resolve(context.Background(), HS256LegacyAuth(fixtureOrg, undeclared, true, "", ""))
		if out.Refusal() == nil {
			t.Fatalf("a listed reason did not enforce")
		}
	})

	t.Run("an UNlisted reason is recorded and not applied", func(t *testing.T) {
		a, rec, _ := compatFixture(t, CompatModeEnforce, BuiltinRealmDeployment{},
			WithCompatEnforceReasons([]AdmissionReason{ReasonOrgBindingMismatch}))
		out := a.Resolve(context.Background(), HS256LegacyAuth(fixtureOrg, undeclared, true, "", ""))
		if out.Refusal() != nil {
			t.Fatalf("an unlisted reason enforced: %v", out.Refusal())
		}
		// It must still be RECORDED, exactly as in shadow, or narrowing the
		// enforcement would also narrow the evidence.
		r := rec.last(t)
		if r.Divergence != DivergenceIdentityRefused || r.IdentityReason != ReasonUnknownRealm {
			t.Fatalf("an unlisted reason was not recorded: %+v", r)
		}
		if r.Enforced {
			t.Fatalf("an unlisted reason was recorded as enforced")
		}
	})

	t.Run("an empty list is every reason", func(t *testing.T) {
		a, _, _ := compatFixture(t, CompatModeEnforce, BuiltinRealmDeployment{},
			WithCompatEnforceReasons(nil))
		if out := a.Resolve(context.Background(), HS256LegacyAuth(fixtureOrg, undeclared, true, "", "")); out.Refusal() == nil {
			t.Fatalf("an empty allow-list narrowed enforcement instead of meaning every reason")
		}
	})
}

func TestParseEnforceReasons(t *testing.T) {
	got, err := ParseEnforceReasons(" unknown_realm , ORG_BINDING_MISMATCH ")
	if err != nil {
		t.Fatalf("ParseEnforceReasons: %v", err)
	}
	if len(got) != 2 || got[0] != ReasonUnknownRealm || got[1] != ReasonOrgBindingMismatch {
		t.Fatalf("got %v", got)
	}
	if got, err := ParseEnforceReasons(""); err != nil || got != nil {
		t.Fatalf("an empty list must mean every reason: %v %v", got, err)
	}
	// A TYPO IS AN ERROR, not a silently dropped entry: an operator who typed
	// ORG_BINDING_MISMATH believes they are enforcing it, and a list that
	// ignored the typo would enforce nothing while reading as though it
	// enforced one thing.
	if _, err := ParseEnforceReasons("ORG_BINDING_MISMATH"); err == nil {
		t.Fatalf("a misspelled reason was silently dropped")
	}
	// A reason this plane cannot produce for a legacy-ACCEPTED credential is
	// equally an error: listing it would enforce nothing.
	if _, err := ParseEnforceReasons("CHAIN_CYCLE"); err == nil {
		t.Fatalf("a reason the adapter cannot enforce on was accepted")
	}
}

// TestBootstrapCompatRefusesEnforceAtBoot pins the asymmetry #3633 closes.
//
// The decision axis has always refused its process-wide enforce at parse
// (ParseDecisionShadowMode); the identity axis accepted it in ONE
// unconditioned call, so `AXONFLOW_IDENTITY_COMPAT_MODE=enforce` began
// refusing requests at boot with no shadow phase behind it, no observed
// denominator, and nothing recorded about why it was safe - across every
// organization at once, since the process-wide mode has no per-org dimension.
//
// This asserts BOTH directions, because a refusal that also refuses shadow
// would pass a one-sided test while breaking every deployment in the fleet
// (prod-US and community-SaaS both sit on shadow).
func TestBootstrapCompatRefusesEnforceAtBoot(t *testing.T) {
	_, err := BootstrapCompat(CompatBootstrapConfig{RawMode: "enforce"})
	if err == nil {
		t.Fatal("BootstrapCompat accepted enforce at boot. Process-wide enforcement refuses requests before any " +
			"shadow phase has measured what it would refuse, on every organization at once; enforcement is granted " +
			"per organization through the settings surface, against an observed denominator.")
	}
	// The message must send the operator to the route that DOES exist. A bare
	// "not available" leaves them believing enforcement is unreachable and
	// hunting for a build flag.
	for _, want := range []string{"per organization", EnvEnforceReasons, "shadow"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q, so it does not tell the operator what to do instead.\ngot: %v", want, err)
		}
	}

	// EVERY OTHER MODE STILL BOOTS. This is the half that matters for the
	// fleet: a refusal keyed on anything broader than the single enforcing
	// value would take down every deployment on shadow.
	for _, raw := range []string{"", "off", "false", "0", "disabled", "shadow"} {
		b, err := BootstrapCompat(CompatBootstrapConfig{RawMode: raw})
		if err != nil {
			t.Errorf("BootstrapCompat(%q) = %v; only enforce is refused at boot", raw, err)
			continue
		}
		if b.Mode == CompatModeEnforce {
			t.Errorf("BootstrapCompat(%q) produced enforce, which this path must never yield", raw)
		}
	}

	// AND THE PER-ORG PARSER IS UNTOUCHED. The refusal lives on the boot path,
	// not in ParseCompatMode, precisely so the per-organization route through
	// the settings surface still has a mode to store. If this ever fails, the
	// refusal has been pushed down into the shared parser and there is no
	// route to enforcement at all.
	if m, err := ParseCompatMode("enforce"); err != nil || m != CompatModeEnforce {
		t.Errorf("ParseCompatMode(\"enforce\") = %v, %v; the shared parser must stay three-valued so the per-org "+
			"surface can still store an enforcing mode", m, err)
	}
}
