//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import "github.com/gorilla/mux"

// RegisterEnforcePrecondition is a no-op on the community build.
//
// The route serves the per-organization identity settings surface, which is
// Enterprise: the row it gates lives behind migration enterprise/146 and the
// customer-portal that writes it does not ship here. Registering it would
// advertise a capability this edition does not have, and the community binary
// has no per-organization enforce to grant.
func RegisterEnforcePrecondition(_ *mux.Router) {}
