// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package fincrimeadmission implements the durable Model 1 quota/admission
// rail. It does not resolve authentication, issue grants, or call a scorer.
package fincrimeadmission

import (
	"context"
	"database/sql"
	"errors"

	"axonflow/platform/shared/capabilityresolution"
)

const (
	ModuleID            = capabilityresolution.FinCrimeModuleID
	CapabilityID        = capabilityresolution.FinCrimeRiskScoringCapabilityID
	CapabilityVersion   = "1.0"
	ScoreRequestsLimit  = capabilityresolution.FinCrimeScoreRequestsLimitID
	maximumInvocationID = 128
)

var ErrAdmissionUnavailable = errors.New("fincrime score admission unavailable")

// Request binds one admission to the invocation and canonical v2 request
// digest. The v2 wire is deliberately outside this PR.
type Request struct {
	InvocationID  string
	RequestSHA256 string
}

type Admission struct {
	ID        string
	Remaining int64
}

// Admitter is implemented by the Enterprise PostgreSQL rail and the
// Community refusal twin.
type Admitter interface {
	Admit(context.Context, Grant, Request) (Admission, capabilityresolution.Reason, error)
	Consume(context.Context, Grant, string, string) (bool, error)
}

// New returns the build-appropriate implementation. Neither build seeds a
// grant or limit; an absent database row remains safe-off.
func New(db *sql.DB) Admitter { return newAdmitter(db) }
