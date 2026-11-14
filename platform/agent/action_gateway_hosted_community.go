//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"database/sql"
	"errors"
	"os"

	"github.com/gorilla/mux"
)

// RegisterHostedActionGatewayRoutes deliberately exposes no Community route.
func RegisterHostedActionGatewayRoutes(_ *mux.Router, _ *sql.DB) error {
	if os.Getenv("AXONFLOW_SQUARE_SANDBOX_PROVIDER_SEND") == "enabled" {
		return errors.New("square sandbox action gateway is unavailable in Community")
	}
	return nil
}
