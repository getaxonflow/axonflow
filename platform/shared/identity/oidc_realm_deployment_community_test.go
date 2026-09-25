//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"errors"
	"testing"
)

// TestOIDCRealmSourceWiringIsFalseOnCommunity: a community build federates no
// IdP, so even with a database it wires no OIDC realm source and declares none.
func TestOIDCRealmSourceWiringIsFalseOnCommunity(t *testing.T) {
	configs, wired, err := OIDCRealmSourceWiring(noIODB(t))
	if wired || configs != nil || !errors.Is(err, ErrEnterpriseOnly) {
		t.Fatalf("community build with a database: configs=%v wired=%v err=%v; want nil, false, ErrEnterpriseOnly", configs, wired, err)
	}
}
