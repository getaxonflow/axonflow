// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package replay

import (
	"errors"
	"fmt"
	"sort"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// RecordSchemaVersion is the record artifact's own version.
const RecordSchemaVersion = 1

// Pin binds one signing root to the exact bundle digest a decision was made
// against.
type Pin struct {
	Root   pdp.Root `json:"root"`
	Digest string   `json:"digest"`
}

// Record is one sampled decision: the normalized request, the artifacts it was
// decided against, and - when the sample was taken from a live evaluation -
// the decision that came out.
//
// The request is stored as the NORMALIZED contract.Request rather than as
// whatever the enforcement point received. Gate 16's sentence is about
// normalized input for a reason: a raw HTTP body would make replay depend on
// every resolver that turned it into attributes, which is precisely the part
// an incident cannot reconstitute months later.
type Record struct {
	SchemaVersion int    `json:"schema_version"`
	CaseID        string `json:"case_id"`
	Description   string `json:"description,omitempty"`
	// EnvironmentDigest pins the whole evaluation environment.
	EnvironmentDigest string `json:"environment_digest"`
	// BundlePins pins each signing root's bundle by digest. Redundant with
	// EnvironmentDigest only when nothing is wrong; when something IS wrong
	// the two say different things (see the package doc).
	BundlePins []Pin `json:"bundle_pins"`
	// Request is the normalized input.
	Request *contract.Request `json:"request"`
	// Expected is the decision recorded when the sample was taken. Absent on a
	// record captured for reproduction rather than for verification, in which
	// case replay emits a decision and asserts nothing about it.
	Expected *contract.Decision `json:"expected,omitempty"`
}

// Validate refuses a structurally unusable record.
func (r *Record) Validate() error {
	if r == nil {
		return fmt.Errorf("replay: record is nil")
	}
	if r.SchemaVersion != RecordSchemaVersion {
		return fmt.Errorf(
			"replay: record declares schema version %d, this build understands %d",
			r.SchemaVersion, RecordSchemaVersion)
	}
	if r.CaseID == "" {
		return fmt.Errorf("replay: record carries no case id; a reproduction nobody can name is not evidence about anything")
	}
	if r.Request == nil {
		return fmt.Errorf("replay: record %q carries no request", r.CaseID)
	}
	if r.EnvironmentDigest == "" {
		return fmt.Errorf("replay: record %q pins no environment; an unpinned replay reproduces whatever happens to be on disk", r.CaseID)
	}
	if len(r.BundlePins) == 0 {
		return fmt.Errorf("replay: record %q pins no bundle", r.CaseID)
	}
	seen := map[pdp.Root]bool{}
	for _, p := range r.BundlePins {
		if p.Root == "" || p.Digest == "" {
			return fmt.Errorf("replay: record %q carries an incomplete bundle pin %+v", r.CaseID, p)
		}
		if seen[p.Root] {
			return fmt.Errorf("replay: record %q pins root %q twice", r.CaseID, p.Root)
		}
		seen[p.Root] = true
	}
	return nil
}

// PinMismatch is one way a record and an environment disagree.
type PinMismatch struct {
	// Kind is "environment", "bundle", "unpinned_root", "missing_root" or
	// "unverifiable_bundle".
	Kind string
	// Root names the authority root the mismatch is about. It is EMPTY only
	// for "environment", which is about the whole environment.
	Root pdp.Root
	// Want is the digest the record pins, or - for "unverifiable_bundle" - the
	// digest the bundle ADVERTISES, which is the value that turned out not to
	// describe its content.
	Want string
	// Got is the observed value: for "unverifiable_bundle", the digest the
	// bundle's content actually hashes to.
	Got string
	// Note carries an observation the mismatch itself cannot establish.
	//
	// It exists because the unverifiable_bundle message used to assert
	// unconditionally that the artifact "may well be the one the record was
	// taken against". That is the COMMON case and it is not always true: a
	// bundle whose content also differs from what the record pins is a
	// different artifact wearing a wrong label, and telling that operator they
	// probably have the right one sends them the wrong way. The comparison
	// costs one string equality, so the reassurance is now earned rather than
	// assumed.
	Note string
}

func (m PinMismatch) String() string {
	switch m.Kind {
	case "environment":
		return fmt.Sprintf("the record was taken against environment %s and this environment digests to %s", m.Want, m.Got)
	case "bundle":
		return fmt.Sprintf("root %q: the record pins bundle %s and this environment holds %s", m.Root, m.Want, m.Got)
	case "missing_root":
		return fmt.Sprintf("root %q: the record pins bundle %s and this environment holds no bundle for that root", m.Root, m.Want)
	case "unpinned_root":
		return fmt.Sprintf("root %q: this environment holds bundle %s, which the record does not pin", m.Root, m.Got)
	case "unverifiable_bundle":
		// The canonical wording ("advertised digest X does not match content
		// digest Y") is kept verbatim, because it is the same sentence
		// TrustStore.Verify and VerifiedDigest produce and an operator should
		// meet one phrasing of this fact rather than three. What is added is
		// the part a pin refusal needs and the raw error could not carry: the
		// root, and the statement that the environment HOLDS this bundle.
		out := fmt.Sprintf("root %q: this environment HOLDS a bundle for that root, but its advertised digest %s does not match content digest %s, so it cannot be pinned", m.Root, m.Want, m.Got)
		if m.Note != "" {
			out += " - " + m.Note
		}
		return out
	default:
		return fmt.Sprintf("%s: root %q want %s got %s", m.Kind, m.Root, m.Want, m.Got)
	}
}

// PinError is the refusal returned when a record and an environment do not
// describe the same artifacts. It carries every mismatch rather than the first,
// because an operator holding the wrong artifact wants to see the whole
// disagreement at once.
type PinError struct {
	CaseID     string
	Mismatches []PinMismatch
}

func (e *PinError) Error() string {
	out := fmt.Sprintf("replay: record %q does not match this environment and will not be replayed against it", e.CaseID)
	for _, m := range e.Mismatches {
		out += "\n  - " + m.String()
	}
	out += "\nA replay against artifacts the record was not taken against reproduces a different question's answer, so it is refused rather than attempted."
	return out
}

// CheckPins compares a record's pins against an environment.
//
// Both directions are checked. A pinned root the environment does not hold is
// obviously wrong; an environment root the record does NOT pin is wrong too,
// and is the direction that would otherwise go unnoticed - a third signed
// bundle participating in the union that the sampled decision never saw.
func CheckPins(env *Environment, rec *Record) error {
	if env == nil || rec == nil {
		return fmt.Errorf("replay: cannot check pins without both an environment and a record")
	}
	digest, err := env.Digest()
	if err != nil {
		return err
	}
	var out []PinMismatch
	if digest != rec.EnvironmentDigest {
		out = append(out, PinMismatch{Kind: "environment", Want: rec.EnvironmentDigest, Got: digest})
	}

	// A bundle whose content does not hash to its advertised digest is a PIN
	// problem, not a usage error (#3700), so it is RECORDED as a mismatch and
	// the comparison CONTINUES. Two things go wrong if it returns here
	// instead. Every other mismatch is dropped - the environment row already
	// accumulated above, and any missing or unpinned root among the bundles
	// that ARE pinnable - in a function whose doc says it checks both
	// directions. And cmd/decision-replay is downgraded from exitPin to
	// exitUsage, because that CLI chooses its exit code with errors.As on
	// *PinError, so the refusal this whole path exists to produce would have
	// exited "you called me wrong".
	pins, err := env.BundleDigests()
	// UNPINNABLE IS NOT MISSING, and telling an operator otherwise is worse
	// than telling them nothing. The returned slice is short by exactly the
	// unpinnable roots, so a root whose label is corrupted falls out of `have`
	// and, left alone, takes the !ok branch below and is reported as a root
	// this environment does not hold - about the one root it demonstrably
	// does. Worse, the record's pin for that root is usually the CONTENT
	// digest, so the two values agree perfectly and only the label is wrong;
	// the true sentence is "these are your artifacts, with a corrupted label".
	// Each affected root is therefore reported ONCE, as unverifiable, and the
	// missing/unpinned branches are skipped for it.
	unpinnable := map[pdp.Root]bool{}
	var unpin *UnpinnableBundlesError
	switch {
	case errors.As(err, &unpin):
		for _, u := range unpin.Roots {
			unpinnable[u.Root] = true
			m := PinMismatch{Kind: "unverifiable_bundle", Root: u.Root, Want: u.Advertised, Got: u.Content}
			// EARNED, not assumed. Only say the artifact is probably the right
			// one when the content is what the record actually pins.
			for _, p := range rec.BundlePins {
				if p.Root == u.Root {
					if p.Digest == u.Content {
						m.Note = "the content IS the digest your record pins, so this is very likely the right artifact wearing a corrupted label"
					} else {
						m.Note = fmt.Sprintf("and the content does not match what your record pins for this root (%s) either, so this is a DIFFERENT artifact and not merely a mislabelled one", p.Digest)
					}
					// FIRST match wins, and there can only be one: Record.Validate
					// refuses a record that pins a root twice, and Replay
					// validates before it checks pins. The break is here so the
					// loop does not depend on that being true somewhere else -
					// without it a duplicate would silently be last-wins, which
					// is a rule nobody chose.
					break
				}
			}
			out = append(out, m)
		}
	case err != nil:
		out = append(out, PinMismatch{Kind: "unverifiable_bundle", Got: err.Error()})
	}
	have := map[pdp.Root]string{}
	for _, p := range pins {
		have[p.Root] = p.Digest
	}
	pinned := map[pdp.Root]bool{}
	for _, p := range rec.BundlePins {
		pinned[p.Root] = true
		got, ok := have[p.Root]
		switch {
		case unpinnable[p.Root]:
			// Already reported above, with both digests. It is neither
			// missing nor mismatched: it is unverifiable.
		case !ok:
			out = append(out, PinMismatch{Kind: "missing_root", Root: p.Root, Want: p.Digest})
		case got != p.Digest:
			out = append(out, PinMismatch{Kind: "bundle", Root: p.Root, Want: p.Digest, Got: got})
		}
	}
	for root, got := range have {
		if !pinned[root] {
			out = append(out, PinMismatch{Kind: "unpinned_root", Root: root, Got: got})
		}
	}
	if len(out) == 0 {
		return nil
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Root < out[j].Root
	})
	return &PinError{CaseID: rec.CaseID, Mismatches: out}
}
