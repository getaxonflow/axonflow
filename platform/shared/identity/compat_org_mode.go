// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Per-organization compatibility mode (#3550, session ADR65-I).
//
// # WHAT THIS ADDS AND WHAT IT DOES NOT
//
// #3582 shipped the adapters behind ONE process-wide mode with a reason
// allow-list, and named per-organization enablement as the gap: the release
// plan promises shadow "enabled per org", because shadowing our own stacks
// and one design partner must not mean shadowing every tenant on the
// deployment at once. This file adds that axis.
//
// It does NOT add a second place where the mode is consulted. compat.go's
// structural invariant - the mode is read in exactly one function - is the
// whole safety argument for "the flag is honored on every plane or on none",
// and a per-organization override bolted on at the call sites would break it
// in the most ordinary way: one plane consults the record and the others do
// not. So the organization's record is an INPUT to the one existing read, not
// a reader of its own:
//
//	effectiveMode(process, record) = record.mode  if the organization has a record
//	                               = process      otherwise
//
// # THE COMPOSITION RULE, STATED SO IT CAN BE ARGUED WITH
//
// A record WINS, in both directions. An organization with a record runs in
// the record's mode whether that is above or below the process flag; an
// organization without one runs in the process flag's mode.
//
//   - Raising (process off, record shadow/enforce) is the release plan's
//     case: shadow one organization on a deployment that is otherwise off.
//   - Lowering (process enforce, record off/shadow) is the incident case: an
//     organization whose divergences are not yet cleared is exempted without
//     turning enforcement off for everyone else.
//   - Absent record: the process flag. This is every existing deployment, and
//     it is byte-identical to #3582 - the runtime suite's absent-record leg
//     measures exactly that.
//
// The reason allow-list (EnvEnforceReasons) stays process-wide and applies
// whenever the RESOLVED mode is enforce, whichever input produced it. It can
// only narrow, so a per-organization enforce is still bounded by it.
//
// # WHY A RECORD THAT CANNOT BE READ IS THE PROCESS MODE, AND WHY THAT IS SAID
//
// The source is consulted on the authentication path. If it fails, the
// request still has to be authenticated, and the only mode that can be
// asserted about an organization whose record is unreadable is the one the
// deployment declared for everyone. That is a fall-back and it is not silent:
// the adapter counts every fall-back (OrgModeFailures) and the Enterprise
// store logs the failure once per TTL window and serves its last
// successfully-read record for the organization while the failure persists,
// so a transient outage does not flip an organization's mode mid-incident.
// The direction of the fall-back is towards the DEPLOYMENT'S declaration,
// never towards a guess about the organization's.
//
// # WHY THE RECORD IS KEYED ON THE AUTHENTICATED ORGANIZATION
//
// The lookup key is LegacyAuth.AuthenticatedOrgID, which every call site
// establishes from the credential that authenticated (the #3488-class
// acceptance carried by #3556). It is never a claim out of the credential
// under verification and never a caller-supplied header, so a caller cannot
// select a more permissive organization's mode by asserting its id.
package identity

import (
	"context"
	"fmt"
	"log"
	"strings"

	logutil "axonflow/platform/shared/logger"
)

// CompatOrgModeSource answers "does this organization have a recorded
// compatibility mode, and what is it".
//
// It is consulted on the authentication path, so an implementation must be
// cheap after the first call for an organization: the Enterprise store is a
// TTL-memoized read of one row. It must be safe for concurrent use.
type CompatOrgModeSource interface {
	// OrgCompatMode returns the organization's recorded mode.
	//
	// found=false with a nil error means the organization has NO record and
	// the process mode applies; that is the ordinary answer for almost every
	// organization and is not an error. A non-nil error means the record
	// could not be read; the adapter then falls back to the process mode and
	// counts the fall-back. A returned mode must be a declared one
	// (CompatMode.IsValid); the adapter refuses anything else as a read
	// failure rather than acting on it.
	OrgCompatMode(ctx context.Context, orgID string) (mode CompatMode, found bool, err error)
}

// WithCompatOrgModes wires the per-organization mode source. Nil (the
// default, and every community build) means the process mode is the whole
// answer for every organization.
func WithCompatOrgModes(src CompatOrgModeSource) CompatAdapterOption {
	return func(a *CompatAdapter) { a.orgModes = src }
}

// OrgModeFailures reports how many times an organization's record could not
// be read and the process mode was used instead. It is a diagnostic: a
// deployment expecting a per-organization enforce that sees this climbing is
// running that organization in the process mode.
func (a *CompatAdapter) OrgModeFailures() uint64 {
	if a == nil {
		return 0
	}
	return a.orgModeFailures.Load()
}

// effectiveMode is THE ONE FUNCTION THAT READS THE MODE. It composes the
// process-wide flag with the organization's record, and every decision the
// adapter makes reads the value it returns rather than either input.
//
// It is the only reader of a.processMode and of a.orgModes in this package;
// TestCompatModeIsConsultedAtExactlyOneSite enumerates every selector on
// those two fields across every file and fails on any other reader.
func (a *CompatAdapter) effectiveMode(ctx context.Context, orgID string) CompatMode {
	process := a.processMode
	if a.orgModes == nil || orgID == "" {
		// No source, or no organization to key on. An empty organization is
		// refused later as an adapter defect when the mode evaluates; here it
		// simply has no record to look up.
		return process
	}
	// The same bound the realm source runs under, for the same reason: a
	// caller with no request context at all (adaptedValidateUserToken has
	// none, deliberately) would otherwise consult storage unbounded.
	octx, cancel := boundedRealmContext(ctx)
	defer cancel()
	record, found, err := a.orgModes.OrgCompatMode(octx, orgID)
	if err != nil {
		a.noteOrgModeFailure(orgID, err)
		return process
	}
	if !found {
		return process
	}
	if !record.IsValid() {
		// A source that answers with an undeclared value has not answered.
		// Acting on it would be the tri-state-by-inequality defect one level
		// up: CompatMode(99) is neither off nor a mode anyone declared, and
		// the safe reading of "the record is unreadable" is the same as any
		// other read failure.
		a.noteOrgModeFailure(orgID, fmt.Errorf("the recorded mode %s is not a declared mode", record))
		return process
	}
	return record
}

// noteOrgModeFailure counts a fall-back and logs it. The log line is
// deliberately terse and names the organization; the Enterprise store logs
// the underlying cause once per TTL window with the detail, so this line
// does not repeat it on every request of an outage.
func (a *CompatAdapter) noteOrgModeFailure(orgID string, err error) {
	a.orgModeFailures.Add(1)
	log.Printf("[IDENTITY-COMPAT] component=%s org=%s per-org mode unavailable, using the process mode (%s): %s",
		logutil.Sanitize(a.component), logutil.Sanitize(orgID), a.processModeForLog(), logutil.Sanitize(err.Error()))
}

// processModeForLog renders the process mode for the fall-back line. It is a
// separate one-line function rather than an inline a.processMode read so the
// AST guard's "exactly one reader" statement stays literally true: this is
// the diagnostics accessor, Mode, under another name, and reads through it.
func (a *CompatAdapter) processModeForLog() string {
	return strings.ToLower(a.Mode().String())
}
