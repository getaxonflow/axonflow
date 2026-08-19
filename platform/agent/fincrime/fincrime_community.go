//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Community Edition stub for the fincrime package (ADR-061 / #3329). The
// Fraud & Risk Add-on is an Enterprise add-on: on a community build the
// engine constructor returns nil, the seam consult returns nil, and every
// request proceeds bit-identically to a build that never heard of the
// add-on. The symbols exist so the untagged agent handlers and boot wiring
// compile unconditionally regardless of build tag (cf.
// billing_register_community.go).
package fincrime

import "context"

// Engine is the community no-op stand-in for the enterprise fincrime engine.
type Engine struct{}

// NewEngineFromEnv returns nil on community builds: the add-on is not
// present, and a nil *Engine is the "not consulted" state everywhere.
func NewEngineFromEnv() *Engine { return nil }

// Evaluate always reports "nothing to say" on community builds.
func (e *Engine) Evaluate(_ context.Context, _ Input) *Result { return nil }

// ScorerConfigured is always false on community builds.
func (e *Engine) ScorerConfigured() bool { return false }
