// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package edition names, once, which BUILD of AxonFlow a binary is.
//
// # WHY A PACKAGE AND NOT A BOOLEAN AT EACH CALL SITE
//
// The answer is a compile-time constant — the `enterprise` build tag is on or
// it is off — and until now no production code could ask it. Every consumer
// that needed it either inferred it from something else (DEPLOYMENT_MODE, the
// licence tier, whether a table existed) or split into two files of its own.
// Inference is what this package exists to stop: all three of those signals
// are configuration, and configuration disagrees with the build. The
// community-SaaS fleet runs the ENTERPRISE binary against the `community-saas`
// schema, so "which schema" cannot answer "which build"; a licence tier is
// issued, not compiled.
//
// # WHAT IT DOES NOT ANSWER
//
//   - Which SCHEMA a deployment applied — platform/shared/deploymode.
//   - Which runtime POSTURE it enforces — isCommunityMode() in
//     platform/agent/run.go, which fails closed on an unset value.
//   - What a customer is ENTITLED to — the licence, never this constant.
//
// It answers exactly one question: which set of source files was compiled in.
// Use it for telemetry, /health disclosure and log lines. It must never gate
// an entitlement: a build tag is not a purchase.
//
// # THE ONE BINARY THIS CONSTANT IS WRONG FOR
//
// The standalone axonflow-gateway-adapters image is built WITHOUT `-tags
// enterprise` (see its Dockerfile) even though it is an Enterprise-only
// component with no community edition. `Current` therefore reads `community`
// inside it, which is true of its compilation and false of the artifact. That
// binary states its edition as a property of the artifact instead. THAT BINDING
// LANDS WITH PR C of this lane (#3660) — it does not exist on this branch, so
// do not go looking for it here. Nothing else in the tree has that split.
package edition

// Community / Enterprise are the two edition values. They are the wire
// vocabulary the checkpoint contract accepts (telemetry.EditionCommunity /
// EditionEnterprise). The two copies are pinned across the module boundary by
// TestEditionVocabularyMatchesTheContract in platform/shared/heartbeat, which
// compares All() against the contract doc's vocab block — a block that
// TestDocsVocabularyTablesMatchTheGoSource holds equal to the checkpoint Go.
const (
	Community  = "community"
	Enterprise = "enterprise"
)

// All returns both edition values, sorted. Used by the vocabulary parity pin.
func All() []string { return []string{Community, Enterprise} }
