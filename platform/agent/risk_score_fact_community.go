//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"fmt"
	"os"
	"strings"

	"axonflow/platform/shared/edition"
)

// The Community build carries no Engine B scorer (#3330): the FinCrime pack is
// an Enterprise add-on that a Community build refuses to install
// (policy_packs.go), so no control here reads the score and nothing is asked.

// currentRiskScorer is always nil on the Community build.
func currentRiskScorer() riskScorer { return nil }

// wireRiskScoreFact refuses a Community process that configures a scorer: it
// would believe transactions are scored, and nothing here calls one.
func wireRiskScoreFact() error {
	var set []string
	for _, name := range []string{envRiskFactURL, envRiskFactTimeoutMS} {
		if v := strings.TrimSpace(os.Getenv(name)); v != "" {
			set = append(set, fmt.Sprintf("%s=%q", name, v))
		}
	}
	if len(set) == 0 {
		return nil
	}
	return fmt.Errorf("%s: the Engine B risk-score fact is an Enterprise add-on and this is a %s build, which carries none; unset it",
		strings.Join(set, ", "), edition.Current)
}

// riskScoreFactHealth is nil on the Community build, so /health carries no
// member for a scorer the build cannot have.
func riskScoreFactHealth() map[string]interface{} { return nil }
