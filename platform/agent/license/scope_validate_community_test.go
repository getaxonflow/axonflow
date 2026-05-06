//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package license

import (
	"strings"
	"testing"
)

func TestParseAndVerifyServiceToken_CommunityRejects(t *testing.T) {
	_, err := ParseAndVerifyServiceToken("AXON-anything.signature")
	if err == nil {
		t.Fatal("expected error in community build, got nil")
	}
	if !strings.Contains(err.Error(), "enterprise build") {
		t.Errorf("error message should mention enterprise build, got: %v", err)
	}
}
