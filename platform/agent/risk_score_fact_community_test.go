//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"strings"
	"testing"
)

// The Community build carries no Engine B scorer (#3330): nothing is asked,
// /health is unchanged, and a process configuring one refuses to boot.
func TestTheCommunityBuildHasNoRiskScorer(t *testing.T) {
	if currentRiskScorer() != nil {
		t.Fatal("the Community build returned a scorer")
	}
	if h := riskScoreFactHealth(); h != nil {
		t.Fatalf("the Community /health gained a member: %v", h)
	}
	for _, name := range []string{envRiskFactURL, envRiskFactTimeoutMS} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(envRiskFactURL, "")
			t.Setenv(envRiskFactTimeoutMS, "")
			if err := wireRiskScoreFact(); err != nil {
				t.Fatalf("nothing set refused boot: %v", err)
			}
			t.Setenv(name, "http://scorer:8090")
			err := wireRiskScoreFact()
			if err == nil || !strings.Contains(err.Error(), name) || !strings.Contains(err.Error(), "Enterprise") {
				t.Fatalf("err %v; want a refusal naming %s and the edition", err, name)
			}
		})
	}
}
