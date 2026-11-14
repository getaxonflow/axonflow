//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package fincrimeadmission

import (
	"context"
	"errors"
	"testing"

	"axonflow/platform/shared/capabilityresolution"
)

func TestCommunityBuildCannotAdmitOrConsumeFinCrimeScores(t *testing.T) {
	store := New(nil)
	if admission, reason, err := store.Admit(context.Background(), Grant{}, Request{}); err != nil ||
		reason != capabilityresolution.ReasonEditionRequired || admission.ID != "" {
		t.Fatalf("Community admission = %+v reason=%q err=%v", admission, reason, err)
	}
	if consumed, err := store.Consume(context.Background(), Grant{}, "", ""); consumed ||
		!errors.Is(err, ErrAdmissionUnavailable) {
		t.Fatalf("Community consume = %t err=%v", consumed, err)
	}
}
