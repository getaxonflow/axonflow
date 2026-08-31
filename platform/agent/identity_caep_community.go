//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"database/sql"

	"github.com/gorilla/mux"
)

// RegisterCAEPReceiver is Enterprise-only. A community build federates no IdP,
// declares no OIDC realm and holds no per-organization settings, so there is
// no realm a Shared Signals stream could act on; the symbol exists so run.go
// can call it unconditionally. Nothing is registered and nothing is logged:
// a community deployment has no capability to report missing.
func RegisterCAEPReceiver(_ *mux.Router, _ *sql.DB) {}
