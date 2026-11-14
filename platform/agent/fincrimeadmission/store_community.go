//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package fincrimeadmission

import (
	"context"
	"database/sql"

	"axonflow/platform/shared/capabilityresolution"
)

// Grant carries no authority in Community. The refusal implementation accepts
// the opaque zero value only so the shared Admitter contract stays wire-stable.
type Grant struct{}

type communityRefusal struct{}

func newAdmitter(*sql.DB) Admitter { return communityRefusal{} }

func (communityRefusal) Admit(context.Context, Grant, Request) (Admission, capabilityresolution.Reason, error) {
	return Admission{}, capabilityresolution.ReasonEditionRequired, nil
}

func (communityRefusal) Consume(context.Context, Grant, string, string) (bool, error) {
	return false, ErrAdmissionUnavailable
}
