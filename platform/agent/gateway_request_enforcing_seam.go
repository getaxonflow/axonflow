// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// THE GATEWAY PRE-CHECK'S ENFORCING SEAM (#3564, wave two).
//
// The third scope the anchored engine authors a verdict on, after decide and the
// MCP response pass: the POLICY verdict of POST /api/policy/pre-check, which
// handlePolicyPreCheck's shared-engine evaluation (legacycompile.
// PlaneGatewayRequest) used to give alone. The pre-check has decide's shape -
// one request phase read from the runtime phase columns, the organization's
// overrides passed, a per-user token in the body - so it runs through decide's
// request path, enforceRequestPass, and supplies only its wire: how an anchored
// answer becomes the StaticPolicyResult the rest of the handler reads.
//
// # WHY IT CAN BE CUT OVER
//
// Three facts, each derived rather than assumed:
//
//   - THE RESTRICTION. activation.RestrictToScope(gateway_request) keeps the
//     shipped controls whose rows load in the request phase and whose categories
//     the pre-check's call site admits. On the shipped corpus none of them
//     carries a mandatory obligation, and
//     TestEveryEnforcingSeamActivatesOnBothEditions activates the scope in both
//     editions.
//   - THE DISCHARGE. The pre-check never redacts. It answers requires_redaction
//     and the calling SDK obtains the engine-masked content, the one sanctioned
//     discharge (ADR-056). That instruction is the request-phase redact_pii the
//     Decision API renders, told as a boolean, so the seam delivers exactly the
//     Decision wire's capability; a redaction fulfilled after the call has no
//     representation here and refuses the request (staticPolicyResult).
//   - THE SUBJECT. The pre-check resolves the body's user_token before any
//     policy runs and refuses one that does not verify. A request with no
//     per-user identity is evaluated for its client credential (the credential
//     principal, PRD v11 §1.6), as on decide.
//
// # WHAT DIFFERS FROM THE LEGACY ENGINE, STATED
//
//   - The organization pii=redact override behind the India and Indonesia
//     redaction flags: under the anchored engine requires_redaction is the
//     decision's alone. Their pii=block refusals run BEFORE the seam and are
//     unchanged.
//   - A policy that asks for approval: approval execution is not wired on this
//     seam, so an anchored CHALLENGE is a refusal (mapAnchoredDecision). No queue
//     entry is raised and no approval grant is spent on a request the legacy
//     engine did not decide.
//   - Detection narrowed for the process refuses to boot (#4032): with detection
//     off the anchored engine would have no detector inputs and every
//     detector-reading control would be UNKNOWN.
//
// The kill switch, the circuit breaker, segment resolution, the India and
// Indonesia validators' refusals and the budget check are not policy-engine
// verdicts, and they run exactly as before.

import "axonflow/platform/decision/legacycompile"

// gatewayRequestSeamScope is the scope this seam cuts over: the whole plane,
// which evaluates one phase.
var gatewayRequestSeamScope = legacycompile.MustScopeFor(legacycompile.PlaneGatewayRequest, "")

// gatewayPreCheckWire names this pass in a refusal its wire cannot express.
const gatewayPreCheckWire = "the gateway pre-check"
