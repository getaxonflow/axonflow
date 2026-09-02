// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package reservation is the ADR-065 atomic quota and budget reservation
// service: contract, lifecycle, an in-memory reference implementation, and the
// durable PostgreSQL store the reference is a reference FOR (issues #3561 and
// #3604, epic #3551).
//
// # Edition
//
// Every file except this one carries `//go:build enterprise`. That placement
// was FLAGGED as an open question when this package shipped and it is now
// SETTLED: ADR-066's acceptance puts the reservation service at
// `enterprise_implementation` ("Approval discharge, separation of duties,
// reservations ... are enterprise_implementation"), and Evaluation cannot
// reserve budgets. The unconditional registration of the shipped cost API in
// the community repo - the fact that made this look ambiguous - is a census
// item for #3590 rather than a reason to reclassify. Nothing here touches a
// licence tier; the edition is expressed entirely by the build tag, so the
// community mirror ships neither the store nor its migration.
//
// # Why this cannot be a counter
//
// Budget policy is stateful and cannot be made correct through a parameter
// hash or an eventually consistent counter. Two concurrent approvals against
// one budget both passed in the current system - that is a MEASURED result,
// not a theoretical one - because the check and the charge were two
// operations. Admission here is ONE linearizable conditional transaction
// across every required counter, and TestConcurrentReservationsAdmitExactlyOne
// runs the race.
//
// # The reservation key, and what is deliberately absent from it
//
// ADR-065: "Hashing tool arguments alone is prohibited as an idempotency or
// reservation key." That line encodes the #3483 replay finding, where a
// user-blind cache key replayed a non-member's allow for a segment member.
//
// So Key has NO arguments-digest field at all. An arguments-only key is not
// rejected at runtime, it is UNREPRESENTABLE, and
// TestKeyCannotBeBuiltFromArgumentsAlone pins the absence. Organization,
// actor scope and decision id are required, so a key can never be less
// specific than the principal it is charging.
//
// # Store selection: DECIDED
//
// PostgreSQL, in the existing platform database, with FORCE'd row-level
// security on both tables. Ruled by the operator on 2026-08-31 (#3551) from
// the written recommendation in
// technical-docs/RESERVATION_STORE_SELECTION.md, which also records what Redis
// and DynamoDB were rejected for. The schema is migration enterprise/148; the
// implementation is PostgresStore.
//
// MemoryStore remains, and remains a REFERENCE rather than a deployment. It is
// correct for one process and wrong for more than one: two processes each hold
// their own counters, so a budget of 100 admits 200, and both the agent and
// the orchestrator run multi-replica. NewStore will not hand it back unless a
// caller declares a single-process deployment explicitly, so a missing
// connection string cannot quietly become an unenforced budget.
//
// Both stores are driven by the SAME semantic suite (see
// store_conformance_test.go): every assertion about idempotency, fencing,
// atomicity, expiry, reconciliation and conversion runs against each, so a
// divergence is a test failure rather than a discovery in production. The
// three properties the reference cannot demonstrate at all - durability across
// a restart, cross-process linearizability, and storage-enforced isolation -
// are proven against a real PostgreSQL in postgres_realpg_test.go.
package reservation
