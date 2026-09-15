// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package fincrime names the request-context keys of the Fraud & Risk Add-on's
// documented integration surface (ADR-061, ee/docs/fincrime/CONTEXT_SCHEMA.md).
// The decide handler lifts them into the parameters the detector pass evaluates
// (finCrimeParametersFromContext). The FinCrime policy pack itself is a typed
// document the agent installs and the anchored engine decides (PRD v11 §1.9);
// its document and pattern tests live beside this file.
//
// The package no longer carries an engine: the legacy in-process Engine A and
// its Engine B scorer client were deleted once the MCP request pass moved to
// the anchored engine and left them without a caller (PRD v11 §5.8).
package fincrime

// Context keys of the documented integration surface. Callers place these in
// DecideRequest.Context (the /decide plane) or in the request parameters map
// (the MCP planes). Untagged, so both builds route the keys.
const (
	TransactionContextKey = "fincrime_transaction"
	CohortContextKey      = "fincrime_cohort"
)
