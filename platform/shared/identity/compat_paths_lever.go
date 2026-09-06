// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"fmt"
	"sort"
	"strings"
)

// EnvCompatPaths names the per-path rollback lever (#3634).
//
// # WHY A PER-PATH LEVER EXISTS AT ALL
//
// The rollout axes are supposed to be symmetric, and the decision axis has had
// this since v10.3.0: AXONFLOW_DECISION_SHADOW_PLANES narrows which planes
// dual-evaluate, so a plane producing noise can be taken out without taking the
// whole window down. The identity axis had only two widths - the process flag
// and the per-organization record - and neither is the right shape for the
// failure that actually happens.
//
// The failure that happens is ONE PATH going wrong for EVERYONE: a fleet
// asserting only an email on the trusted-header path, an IdP whose JWKS
// endpoint starts timing out on the OIDC path. Without this lever the only
// remedies are to lower an organization (which loses the other three paths for
// that tenant) or to lower the deployment (which loses the window entirely).
// Neither is proportionate to "one credential path is noisy", and both discard
// measurements that were fine.
//
// # ABSENT MEANS EVERY PATH, WHICH IS THE ONLY COMPLETE WINDOW
//
// Empty or unset evaluates every declared path, exactly as the decision axis
// treats an absent plane list. A narrowed list is a deliberate, temporary
// posture: the paths it omits evaluate as `off`, so they record nothing and
// refuse nothing, and gate 18's coverage for those paths stops accruing.
const EnvCompatPaths = "AXONFLOW_IDENTITY_COMPAT_PATHS"

// ParseCompatPaths maps the configured list to the set of paths that evaluate.
//
// A nil map means EVERY path, and it is the unset case rather than a special
// value: callers ask through CompatPathEvaluates, which reads nil as "all".
// Returning an empty non-nil map for "" would make the two states differ by a
// property no caller looks at, and one of them would silently evaluate nothing.
//
// # AN UNRECOGNIZED PATH IS FATAL, MIRRORING planeshadow.ParsePlanes
//
// It is NOT ParseCompatMode's shape, and the difference is deliberate. That
// parser accepts `false`, `0` and `disabled` as spellings of off, because a
// mode is a posture an operator writes by hand and the synonyms are kind. A
// path list is a set of IDENTIFIERS, and kindness there is how a typo becomes
// a silent narrowing: an operator who writes "trusted-header" for
// "trusted_header" believes that path is being measured, and a list that
// dropped the entry would measure three paths while reading as four. Refusing
// to boot is the one failure an operator sees immediately.
//
// Case and surrounding whitespace ARE normalised, which is not the same thing.
// `Trusted_Header ` names a declared path unambiguously; `trusted-header` names
// nothing. Normalising the first is canonicalisation, and accepting the second
// would be guessing.
func ParseCompatPaths(raw string) (map[LegacyPath]bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	out := map[LegacyPath]bool{}
	for _, field := range strings.Split(raw, ",") {
		name := LegacyPath(strings.ToLower(strings.TrimSpace(field)))
		if name == "" {
			continue
		}
		if !name.IsValid() {
			return nil, fmt.Errorf(
				"identity: %s names path %q, which is not a declared legacy credential path; the declared paths are %v. "+
					"Refusing to boot rather than dropping the entry: a list that silently omitted it would evaluate "+
					"fewer paths than the operator believes are being measured",
				EnvCompatPaths, name, CompatPathNames())
		}
		out[name] = true
	}
	if len(out) == 0 {
		// ONE LINE THAT NAMES BOTH POSTURES AND THE FIX. This is read off a
		// container log by someone who has just been paged, and the two
		// postures are opposite: absent means EVERY path, this value means
		// none. Saying only "invalid" would leave them guessing which way to
		// go, and guessing wrong stops the window silently.
		return nil, fmt.Errorf(
			"identity: %s=%q lists no path. UNSET it to keep every path in compat (the default), or list the "+
				"paths to keep (%v) - those are opposite postures, and a value that names nothing would evaluate "+
				"nothing while reading as configured. Note an EMPTY value is fine and means unset, and so is a "+
				"TRAILING comma on a real list (%q keeps that path); this is a value that is separators alone, "+
				"which an unexpanded or empty-expanded variable produces",
			EnvCompatPaths, raw, CompatPathNames(), "hs256,")
	}
	return out, nil
}

// CompatPathNames returns the declared path spellings, sorted, for an error
// message. Derived from the same legacyPaths slice IsValid reads, so a path
// added there appears here without anyone remembering.
func CompatPathNames() []string {
	out := make([]string, 0, len(legacyPaths))
	for _, p := range legacyPaths {
		out = append(out, string(p))
	}
	sort.Strings(out)
	return out
}

// CompatPathEvaluates reports whether path is in the configured set.
//
// A NIL SET IS EVERY PATH, not none. That is the unset deployment - the
// overwhelmingly common one - and reading nil as "evaluate nothing" would turn
// an unconfigured deployment into one that silently stopped measuring, which is
// the exact failure the fatal parse above exists to prevent, arriving by the
// one route that produces no error at all.
func CompatPathEvaluates(set map[LegacyPath]bool, path LegacyPath) bool {
	if set == nil {
		return true
	}
	return set[path]
}
