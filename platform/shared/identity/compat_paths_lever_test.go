// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"bytes"
	"context"
	"log"
	"strings"
	"testing"
)

// TestParseCompatPathsIsFatalOnAnUnrecognizedPath mirrors
// planeshadow.ParsePlanes, and the contrast with ParseCompatMode is the point.
//
// That parser accepts `false`, `0` and `disabled` as spellings of off, because
// a MODE is a posture written by hand and the synonyms are kind. A path list is
// a set of IDENTIFIERS, and kindness there is how a typo becomes a silent
// narrowing: "trusted-header" for "trusted_header" would leave an operator
// believing four paths are measured while three are.
func TestParseCompatPathsIsFatalOnAnUnrecognizedPath(t *testing.T) {
	for _, raw := range []string{
		"trusted-header",       // the plausible typo: hyphen for underscore
		"hs256,trusted-header", // one good entry does not rescue the list
		"gateway",              // a plane name, not a path name
		"api_credentials",      // pluralised
		"false",                // ParseCompatMode accepts this; this must not
		"0",                    // likewise
		"disabled",             // likewise
	} {
		got, err := ParseCompatPaths(raw)
		if err == nil {
			t.Errorf("ParseCompatPaths(%q) = %v, nil; an unrecognized path must be FATAL, or the deployment "+
				"evaluates fewer paths than its own configuration says", raw, got)
			continue
		}
		if !strings.Contains(err.Error(), EnvCompatPaths) {
			t.Errorf("the refusal for %q does not name %s, so an operator cannot tell which variable to fix: %v",
				raw, EnvCompatPaths, err)
		}
		for _, want := range CompatPathNames() {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the refusal for %q does not list the declared path %q: %v", raw, want, err)
			}
		}
	}
}

// TestParseCompatPathsNormalisesButDoesNotGuess separates canonicalisation
// from leniency. `Trusted_Header ` names a declared path unambiguously;
// `trusted-header` names nothing, and accepting it would be a guess.
func TestParseCompatPathsNormalisesButDoesNotGuess(t *testing.T) {
	got, err := ParseCompatPaths("  HS256 , Trusted_Header ")
	if err != nil {
		t.Fatalf("ParseCompatPaths on a case- and space-varied list: %v", err)
	}
	if !got[LegacyPathHS256] || !got[LegacyPathTrustedHeader] {
		t.Errorf("normalised parse = %v, want hs256 and trusted_header", got)
	}
	if got[LegacyPathOIDC] || got[LegacyPathAPICredential] {
		t.Errorf("parse admitted a path that was not named: %v", got)
	}
}

// TestParseCompatPathsDistinguishesAbsentFromEmpty is the trap this design
// turns on.
//
// Unset means EVERY path - the complete window, and the state of almost every
// deployment. A list that names nothing means nothing evaluates. Those are
// opposite postures, and an operator can produce the second by accident (a
// trailing comma, a variable expanded from an empty shell var), so the second
// is REFUSED rather than honoured.
func TestParseCompatPathsDistinguishesAbsentFromEmpty(t *testing.T) {
	// ALL FOUR MEASURED CASES, pinned as a table so the boundary is legible
	// rather than inferred from two separate loops.
	//
	// The empty and whitespace-only cases MUST NOT refuse, and the reason is a
	// deployment fact rather than a taste: the sibling parameter
	// DecisionShadowPlanes ships `Default: ''` in the CloudFormation templates
	// and is emitted unconditionally, so every deployment on defaults already
	// sends an empty string for its equivalent. Refusing empty here would fail
	// every default deployment the day this parameter is offered a template of
	// the same shape.
	for _, tc := range []struct {
		raw       string
		wantError bool
		why       string
	}{
		{"", false, "absent: every path, the default posture"},
		{"   ", false, "whitespace-only is absent too - a templating expansion that produced spaces"},
		{",", true, "separators but no names: evaluates nothing while reading as configured"},
		{",,", true, "same, and the shape a trailing comma or an unexpanded variable produces"},
	} {
		set, err := ParseCompatPaths(tc.raw)
		if tc.wantError {
			if err == nil {
				t.Errorf("ParseCompatPaths(%q) was accepted (%s); it names no path, which is the opposite "+
					"posture from unset and is reachable by accident", tc.raw, tc.why)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseCompatPaths(%q) refused (%s): %v", tc.raw, tc.why, err)
		}
		if set != nil {
			t.Errorf("ParseCompatPaths(%q) produced %v, want nil - nil is read as EVERY path (%s)", tc.raw, set, tc.why)
		}
	}
	// A TRAILING COMMA ON A REAL LIST IS ACCEPTED, and the refusal message
	// above says so in as many words. That sentence is a claim about behaviour,
	// so it is pinned here: an earlier wording blamed the names-nothing refusal
	// on "a trailing comma", which cannot produce it - the empty field is
	// skipped - and an operator reading it would have gone looking for a comma
	// that was never the problem.
	set, err := ParseCompatPaths("hs256,")
	if err != nil {
		t.Errorf("ParseCompatPaths(%q) refused: %v. A trailing comma on a list that names a path is not the "+
			"separators-only case, and the refusal message tells operators exactly that", "hs256,", err)
	} else if !set[LegacyPathHS256] || len(set) != 1 {
		t.Errorf("ParseCompatPaths(%q) = %v, want exactly {hs256}", "hs256,", set)
	}

	for _, p := range legacyPaths {
		if !CompatPathEvaluates(nil, p) {
			t.Errorf("CompatPathEvaluates(nil, %q) = false; an unconfigured deployment must evaluate every path, "+
				"not none - reading nil as 'no paths' would silently stop the window on every deployment that "+
				"configured nothing", p)
		}
	}
}

// TestResolveTreatsAnExcludedPathExactlyAsOff drives the ADAPTER, not the
// parser. The parser can be perfect while the set is never consulted.
func TestResolveTreatsAnExcludedPathExactlyAsOff(t *testing.T) {
	adapter, _, _ := compatFixture(t, CompatModeShadow, BuiltinRealmDeployment{},
		WithCompatPaths(map[LegacyPath]bool{LegacyPathHS256: true}))

	included := adapter.Resolve(context.Background(), LegacyAuth{
		Path: LegacyPathHS256, AuthenticatedOrgID: "org", Decision: LegacyDecisionAccepted,
	})
	if included.Divergence == DivergenceNotEvaluated {
		t.Fatalf("the INCLUDED path did not evaluate (%+v); the lever must narrow, not disable - a test where "+
			"nothing evaluates would pass the exclusion assertion below for the wrong reason", included)
	}

	excluded := adapter.Resolve(context.Background(), LegacyAuth{
		Path: LegacyPathOIDC, AuthenticatedOrgID: "org", Decision: LegacyDecisionAccepted,
	})
	if excluded.Divergence != DivergenceNotEvaluated {
		t.Errorf("excluded path divergence = %q, want %q; a path taken out must evaluate as off FOR THAT PATH",
			excluded.Divergence, DivergenceNotEvaluated)
	}
	if excluded.Mode != CompatModeOff {
		t.Errorf("excluded path mode = %q, want off; 'off for this path' must mean exactly what off means, or the "+
			"lever is a third posture with its own behaviour to reason about", excluded.Mode)
	}
	if excluded.Path != LegacyPathOIDC {
		t.Errorf("excluded outcome lost its path (%q); the caller still needs to know which path was skipped", excluded.Path)
	}
}

// TestResolveEvaluatesEveryPathWhenTheLeverIsUnset is the case that matters
// most: almost every deployment sets nothing.
func TestResolveEvaluatesEveryPathWhenTheLeverIsUnset(t *testing.T) {
	adapter, _, _ := compatFixture(t, CompatModeShadow, BuiltinRealmDeployment{})
	for _, p := range legacyPaths {
		out := adapter.Resolve(context.Background(), LegacyAuth{
			Path: p, AuthenticatedOrgID: "org", Decision: LegacyDecisionAccepted,
		})
		if out.Divergence == DivergenceNotEvaluated {
			t.Errorf("path %q did not evaluate with the lever unset; an unconfigured deployment must measure "+
				"every path, and a silent narrowing here would empty the window with no error anywhere", p)
		}
	}
}

// countingOrgModes records how many times the per-organization settings source
// was consulted. It exists for one assertion, below, and that assertion is the
// only way the lever's PLACEMENT is observable at all.
type countingOrgModes struct {
	calls int
	mode  CompatMode
}

func (c *countingOrgModes) OrgCompatMode(context.Context, string) (CompatMode, bool, error) {
	c.calls++
	return c.mode, true, nil
}

// TestAnExcludedPathNeverReadsTheOrganizationsMode pins WHERE the lever is
// checked, which no other test in this file can see.
//
// Every assertion about the lever so far compares OUTCOMES, and the outcome is
// identical whether the check sits above or below `mode := a.effectiveMode(…)`:
// both orders return an off, not-evaluated outcome for an excluded path. Moving
// the block below the mode read therefore survives the whole suite while
// changing the property the placement exists for - an excluded path would start
// depending on a per-organization settings read, which on a real deployment is
// a database lookup that can be slow, can fail, and can fall back. A path an
// operator switched off during an incident must not be able to fail on a lookup
// it was excluded from.
//
// TWO-SIDED, because "zero calls" is also what a fixture that never reaches the
// adapter produces: the INCLUDED path must consult the source in the same test.
func TestAnExcludedPathNeverReadsTheOrganizationsMode(t *testing.T) {
	src := &countingOrgModes{mode: CompatModeShadow}
	adapter, _, _ := compatFixture(t, CompatModeShadow, BuiltinRealmDeployment{},
		WithCompatPaths(map[LegacyPath]bool{LegacyPathHS256: true}),
		WithCompatOrgModes(src))

	adapter.Resolve(context.Background(), LegacyAuth{
		Path: LegacyPathOIDC, AuthenticatedOrgID: "org", Decision: LegacyDecisionAccepted,
	})
	if src.calls != 0 {
		t.Errorf("an EXCLUDED path consulted the per-organization mode source %d time(s); the lever is read below "+
			"the mode rather than above it, so a path taken out of compat can still fail on a settings lookup it "+
			"was excluded from", src.calls)
	}

	// The positive half. Without it, an adapter that never evaluated anything -
	// a broken fixture, a realm source that refused - would satisfy the check
	// above perfectly.
	adapter.Resolve(context.Background(), LegacyAuth{
		Path: LegacyPathHS256, AuthenticatedOrgID: "org", Decision: LegacyDecisionAccepted,
	})
	if src.calls == 0 {
		t.Error("the INCLUDED path did not consult the per-organization mode source either, so the zero above is " +
			"evidence about this fixture rather than about the lever")
	}
}

// TestLegacyPathIsValidMatchesExactlyAndNotByPrefix pins the comparison inside
// IsValid, which every other test exercises only through names that are either
// exactly right or nothing like a declared path.
//
// A prefix or substring match survives all of them - "trusted-header" is not a
// prefix of "trusted_header", "gateway" is not a substring of anything - while
// admitting "hs" and "oidc_issuer" as path names. Both are the shape of a real
// mistake: a truncated variable and a half-remembered spelling.
func TestLegacyPathIsValidMatchesExactlyAndNotByPrefix(t *testing.T) {
	for _, p := range legacyPaths {
		full := string(p)
		if !p.IsValid() {
			t.Fatalf("the declared path %q is not valid; this test's negatives would then prove nothing", full)
		}
		// A strict prefix, and a strict extension, of every declared name.
		for _, near := range []string{full[:len(full)-1], full + "_v2", strings.ToUpper(full[:1]) + full[1:len(full)-1]} {
			if LegacyPath(near).IsValid() {
				t.Errorf("IsValid admitted %q, which is not the declared path %q; a prefix or substring match here "+
					"would let a truncated or half-remembered name configure a path that does not exist, and the "+
					"parser's fatal refusal would never fire", near, full)
			}
		}
	}
}

// TestBootstrapCompatRefusesAnUnrecognizedPathList pins the CALL SITE, not the
// parser.
//
// ParseCompatPaths returning an error is worth nothing if BootstrapCompat logs
// it and carries on with a nil set: the deployment would boot, evaluate every
// path, and the operator who narrowed to a misspelt name would read their own
// configuration as honoured. Turning the `return nil, err` into a warning is
// the one-line mutant that survives every parser test in this file.
func TestBootstrapCompatRefusesAnUnrecognizedPathList(t *testing.T) {
	boot, err := BootstrapCompat(CompatBootstrapConfig{
		RawMode:   "shadow",
		RawPaths:  "hs256,trusted-header",
		Component: "agent",
	})
	if err == nil {
		t.Fatalf("BootstrapCompat accepted a misspelt path list and returned %+v; the caller's contract is to "+
			"refuse to boot, and a deployment that started here would measure fewer paths than its operator reads", boot)
	}
	if !strings.Contains(err.Error(), EnvCompatPaths) {
		t.Errorf("the boot refusal does not name %s, so an operator reading it off a container log cannot tell "+
			"which variable to fix: %v", EnvCompatPaths, err)
	}

	// THE CONTROL. Without it a BootstrapCompat that refused EVERY configuration
	// - a broken realm deployment, a missing component - would satisfy the
	// assertion above, and the test would be about nothing.
	if _, err := BootstrapCompat(CompatBootstrapConfig{
		RawMode:   "shadow",
		RawPaths:  "hs256,trusted_header",
		Component: "agent",
	}); err != nil {
		t.Fatalf("BootstrapCompat refused a WELL-FORMED path list (%v); the refusal above is then evidence about "+
			"this fixture rather than about the path list", err)
	}
}

// TestNarrowedPathsAreSaidOutLoudAtStartup pins the startup line, and pins the
// half of it that is easy to leave out.
//
// A narrowed deployment is one an operator set during an incident and will
// come back to days later, and the question then is not what is being measured
// but what has STOPPED being measured: a path recording nothing looks exactly
// like a path that never diverges, and those are opposite conclusions. So the
// line must name the OMITTED paths, not only the kept ones.
//
// It is asserted through the standard logger because that is where it goes;
// the output is restored with t.Cleanup so a failure cannot silence every
// later test in the package.
func TestNarrowedPathsAreSaidOutLoudAtStartup(t *testing.T) {
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	boot, err := BootstrapCompat(CompatBootstrapConfig{
		RawMode: "shadow", RawPaths: "hs256", Component: "agent",
	})
	if err != nil {
		t.Fatalf("BootstrapCompat: %v", err)
	}
	boot.InstallProcessCompat("agent")
	line := buf.String()

	if !strings.Contains(line, EnvCompatPaths) {
		t.Errorf("the startup log does not name %s, so an operator reading a container log cannot tell that "+
			"compat was narrowed at all:\n%s", EnvCompatPaths, line)
	}
	for _, kept := range []string{"hs256"} {
		if !strings.Contains(line, kept) {
			t.Errorf("the startup log does not name the KEPT path %q:\n%s", kept, line)
		}
	}
	for _, omitted := range []string{"oidc", "trusted_header", "api_credential"} {
		if !strings.Contains(line, omitted) {
			t.Errorf("the startup log does not name the OMITTED path %q. Naming only what is kept leaves the "+
				"reader to work out the complement from memory, and the omitted set is the one that explains why "+
				"a path shows no divergences:\n%s", omitted, line)
		}
	}

	// THE UNNARROWED CONTROL. The line is deliberately absent when every path
	// evaluates - a line on every boot saying "every path, as usual" teaches a
	// reader to skip it - and without this half, a build that logged the same
	// sentence unconditionally would satisfy every assertion above while
	// telling an operator nothing about which deployment they are looking at.
	buf.Reset()
	full, err := BootstrapCompat(CompatBootstrapConfig{
		RawMode: "shadow", RawPaths: "", Component: "agent",
	})
	if err != nil {
		t.Fatalf("BootstrapCompat with the lever unset: %v", err)
	}
	full.InstallProcessCompat("agent")
	if strings.Contains(buf.String(), EnvCompatPaths) {
		t.Errorf("the narrowing line was logged on an UNNARROWED deployment, so its presence says nothing about "+
			"whether the lever is set:\n%s", buf.String())
	}
}
