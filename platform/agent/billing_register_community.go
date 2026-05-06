//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"database/sql"

	"github.com/gorilla/mux"
)

// RegisterBillingWebhook is a community-edition no-op. Stripe-driven license
// issuance is a paid feature; community self-hosted deployments don't
// receive Stripe webhooks. The symbol exists so platform/agent/run.go can
// call it unconditionally regardless of build tag.
func RegisterBillingWebhook(_ *mux.Router, _ *sql.DB) {}
