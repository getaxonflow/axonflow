// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"net/http/httptest"
	"testing"
)

// TestInternalServiceHintsReadTheWireHeaderNames pins what the agent lifts off
// an internal-service request, by the header names on the wire rather than by
// the constants the code reads them through: a constant that drifted would
// agree with itself and fail here.
func TestInternalServiceHintsReadTheWireHeaderNames(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Internal-Service-ID", "orchestrator-internal")
	r.Header.Set("X-Internal-Service-Token", "AXON-INTERNAL-1-abc")
	r.Header.Set("X-Tenant-ID", "tenant-a")
	h := internalServiceHints(r)
	if h == nil || h.ClientID != "orchestrator-internal" || h.UserToken != "AXON-INTERNAL-1-abc" || h.TenantID != "tenant-a" {
		t.Fatalf("hints = %+v, want the service id, the token and the tenant from the wire headers", h)
	}

	// No service id is no internal-service request, whatever else is sent.
	bare := httptest.NewRequest("GET", "/", nil)
	bare.Header.Set("X-Internal-Service-Token", "AXON-INTERNAL-1-abc")
	if h := internalServiceHints(bare); h != nil {
		t.Fatalf("hints = %+v for a request with a token and no service id, want nil", h)
	}
}
