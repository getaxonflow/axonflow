// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package contract

// UndischargedObligationError is the typed cause of an ADR-065 invariant-8
// refusal: the mandatory obligation the enforcement point cannot discharge.
//
// composeSet's capability check carries it on ObligationOutcome.Err, so an
// adapter that renders the refusal can name the capability gap without parsing
// Detail - the reason MissingMemberError is typed. Its Error is the outcome's
// Detail, byte for byte.
type UndischargedObligationError struct {
	// Obligation is the composed mandatory obligation the profile does not support.
	Obligation Obligation
	// Detail is the operator-facing explanation.
	Detail string
}

func (e *UndischargedObligationError) Error() string {
	if e == nil {
		return "<nil undischarged obligation error>"
	}
	return e.Detail
}
