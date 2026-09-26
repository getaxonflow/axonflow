// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoringstore

import (
	"errors"

	"axonflow/platform/decision/authoring"
)

// StoreFailure is which kind of failure a typed-authoring store error is, for
// an error already known to be the store's rather than a refusal of what the
// caller asked for.
//
// ONE RULE, READ BY EVERY TRANSPORT (#4283, #4249). The portal and the
// orchestrator's typed route each carried their own copy of the sentinel
// switch that turns a store error into an answer, and the order of that
// switch is the rule: ErrStoreUnavailable wraps its cause, so an error can be
// both an outage and a key that is not loaded, and the more specific
// sentinel has to win. Two copies of that order are two chances for it to
// drift. Both surfaces now read this one.
//
// A CLASSIFICATION, NOT A STATUS. Which HTTP status and which reason word each
// kind is answered with is the transport's vocabulary, and this package is a
// store: it names what went wrong and leaves the wire to its callers.
type StoreFailure int

const (
	// StoreOutage: the store could not be read or written. A retry once the
	// database is reachable can succeed.
	StoreOutage StoreFailure = iota
	// StoreKeyNotLoaded: an artifact's signing key is not loaded on this
	// process (ErrSigningKeyNotLoaded). A retry in a few seconds usually
	// settles it.
	StoreKeyNotLoaded
	// StoreUnverifiable: a stored artifact was read and does not verify
	// (ErrArtifactUnverifiable). A retry cannot change it.
	StoreUnverifiable
	// StoreLedgerInconsistent: the ledger names an active digest the store
	// does not hold (authoring.ErrLedgerInconsistent). A retry cannot change
	// it: the store is reachable and disagrees with itself.
	StoreLedgerInconsistent
)

// ClassifyStoreFailure names which kind of store failure err is. It is asked
// only of an error the caller already treats as the store's; anything it does
// not recognise is an outage, which is how every transport answered an
// unrecognised store error before it existed.
func ClassifyStoreFailure(err error) StoreFailure {
	switch {
	case errors.Is(err, ErrSigningKeyNotLoaded):
		return StoreKeyNotLoaded
	case errors.Is(err, ErrArtifactUnverifiable):
		return StoreUnverifiable
	case errors.Is(err, authoring.ErrLedgerInconsistent):
		return StoreLedgerInconsistent
	default:
		return StoreOutage
	}
}

// String is the kind's name for a log line or a test message, and NEVER a
// reason on the wire: "unverifiable" and "outage" are this package's words, no
// spec carries them, and each transport maps the kind to its own reason word
// (the portal in typedStoreRefusalReason, the orchestrator in its writers). No
// production code formats a StoreFailure (master R3 round 2 on #4439).
func (f StoreFailure) String() string {
	switch f {
	case StoreKeyNotLoaded:
		return "key_not_loaded"
	case StoreUnverifiable:
		return "unverifiable"
	case StoreLedgerInconsistent:
		return "ledger_inconsistent"
	default:
		return "outage"
	}
}
