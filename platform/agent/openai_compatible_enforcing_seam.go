// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// THE OPENAI-COMPATIBLE ROUTE'S ENFORCING SEAM (#4092, #3564).
//
// The anchored engine authors the policy verdict of POST /v1/chat/completions
// (handleOpenAICompat, legacycompile.PlaneOpenAICompatible). The route has
// decide's shape - one request phase, the organization's overrides passed - so
// it runs through decide's request path, enforceRequestPass, and projects the
// answer onto the StaticPolicyResult the rest of the handler reads
// (requestPassEnforcement.staticPolicyResult).
//
// # WHY IT CAN BE CUT OVER
//
//   - THE RESTRICTION. activation.RestrictToScope(openai_compatible) keeps the
//     shipped controls whose rows load in the request phase and whose
//     categories the route admits, and TestEveryEnforcingSeamActivatesOnBothEditions
//     activates the scope in both editions.
//   - THE DISCHARGE. The route forwards the request to the provider or refuses
//     it with an OpenAI error, and tells its caller no obligation, so the seam
//     delivers nothing and an obligation the decision attaches refuses the
//     request.
//   - THE SUBJECT, which is what held it back (#4092). The route carries no
//     per-user identity on any deployment: it mirrors OpenAI's wire, and
//     OpenAI's `user` member is free text for abuse monitoring that nothing
//     verifies, so it is NOT honoured as a user token. Every request is
//     therefore evaluated for its authenticated client credential - the
//     credential principal (ADR-065 invariant 2 as amended 2026-09-11 (third),
//     PRD v11 §1.6).
//   - THE ACTION. Every request is a chat completion, recorded under the llm
//     stage, so it is evaluated as that stage's registered action.
//
// # WHERE THE ENGINE, SUBJECT TYPE AND POLICY BUNDLE ARE CARRIED
//
// The response body is OpenAI's, which a client parses with OpenAI's SDK, so
// they ride response HEADERS beside the decision and trace ids the route
// already sets, and the decision's audit row.

import "axonflow/platform/decision/legacycompile"

// openaiCompatibleSeamScope is the scope this seam cuts over: the whole plane,
// which evaluates one phase.
var openaiCompatibleSeamScope = legacycompile.MustScopeFor(legacycompile.PlaneOpenAICompatible, "")

// openaiCompatibleWire names this route in a refusal its wire cannot express.
const openaiCompatibleWire = "the OpenAI-compatible route"

// Headers the route carries the decision's authorship on.
const (
	openaiCompatibleEngineHeader       = "X-AxonFlow-Engine"
	openaiCompatibleSubjectTypeHeader  = "X-AxonFlow-Subject-Type"
	openaiCompatiblePolicyBundleHeader = "X-AxonFlow-Policy-Bundle"
)
