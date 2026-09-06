// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package gatewayadapters implements the agentgateway-native PEP adapters
// (#2886): three gRPC policy-server surfaces that let an agentgateway
// (agentgateway.dev) data plane call AxonFlow as its Policy Decision Point.
//
// The three seams (all fail-closed on the gateway side by default) and the
// AxonFlow contracts they translate to:
//
//   - ExtMcp (agentgateway.dev.ext_mcp.ExtMcp, bespoke gRPC): MCP-layer
//     gating + mutation. CheckRequest gates/mutates JSON-RPC params via
//     decide + engine request-redaction; CheckResponse gates/mutates the
//     result via the engine's response-governance endpoint.
//   - Envoy ext_authz (envoy.service.auth.v3.Authorization): HTTP-layer
//     allow/deny + header mutation over POST /api/v1/decide. Headers-only —
//     it cannot rewrite a body, so it declares that (see "Seam capabilities"
//     below) and the PDP never asks it to redact one.
//   - Envoy ext_proc (envoy.service.ext_proc.v3.ExternalProcessor):
//     streaming request+response BODY governance — decide + engine
//     redaction on the request body, engine response-governance on the
//     response body.
//
// Seam capabilities (#2958): every decide call declares what the CALLING PATH
// can actually discharge (pep.Capability*), so the PDP only emits obligations
// this adapter can carry out. Capability is a property of the path, not the
// adapter: ext_proc is body-capable when it has a body to rewrite, and
// headers-only on a BODYLESS request, where the only content is the request
// line and ext_proc cannot rewrite :path/:method.
//
// What happens to content a policy wanted masked on a path that cannot mask is
// the PDP's decision, NOT this package's: it applies the org's
// obligation-fallback posture (log => allow + audit the suppressed redaction;
// block => deny). This adapter enforces the verdict it is handed.
//
// Until 9.11.0 ext_authz answered that question locally, converting the PDP's
// `allow` into a client-facing 403 whenever the verdict carried an obligation
// it could not fulfill. That was a policy decision made in the PEP — the one
// thing the structural guarantee below forbids — and it took a design partner's
// LLM chat offline for every PII-bearing prompt. Do not reintroduce it: if a
// seam cannot do something, DECLARE that and let the PDP decide.
//
// Structural guarantee (ADR-056 / #2563): this package contains ZERO policy
// or redaction logic — no regex, no pattern table, no masking branch. Every
// allow/deny/redact outcome is an engine round-trip through the blessed
// platform/shared/pep client. Mutated payloads carry engine-returned bytes,
// never locally computed masks.
//
// Failure posture: the REQUEST plane honors a configurable fail-open /
// fail-closed posture (default fail-closed) for PDP-unavailable only; a PDP
// 4xx rejection always blocks, as does an obligation that arrives DESPITE this
// seam declaring it cannot fulfill it — a never-fires backstop for one case, a
// >=9.11.0 adapter against a <=9.10.0 PDP that predates fulfillment_capabilities
// and ignores the declaration (it blocks + ERROR-logs the version mismatch;
// forwarding would leak exactly what the obligation exists to mask, so posture
// does not apply). A conforming PDP never puts this adapter in that position —
// it suppresses the obligation and applies the org posture instead. The RESPONSE
// plane is UNCONDITIONALLY fail-closed — a response that cannot be proven
// scanned (engine unreachable, redaction_evaluated=false, unparseable
// redaction) is withheld even under request-plane fail-open.
//
// That fail-closed doctrine governs RUNTIME failures of a response plane that
// exists. Whether an ext_proc leg HAS a response plane is a separate, static
// question, and the answer is deliberately not the gateway's to give: a leg
// advertising responseBodyMode: none is rejected unless this adapter was
// started with AXONFLOW_EXTPROC_RESPONSE_GOVERNANCE=off (#2959). Under that
// opt-in the leg forwards the upstream response unscanned — which is what
// makes streaming (SSE) completions governable at all, since the request plane
// still decides and redacts the prompt in full — and every such stream says so
// in the log. Nothing about it weakens the doctrine above: a governed leg that
// cannot reach the engine still withholds the response.
//
// The Envoy protos come from the canonical published module
// github.com/envoyproxy/go-control-plane/envoy. agentgateway vendors trimmed
// copies of the same protos (crates/protos/proto/{ext_authz,ext_proc,
// shared_envoy}.proto at the pinned tag) that keep the canonical package
// names, service/method names, and field numbers, so the canonical stubs are
// wire-compatible; the ExtMcp stubs are vendored from the pinned agentgateway
// tag (see agentgateway/api/README.md).
//
// This package is Enterprise-only (it lives in the ee module and ships as
// the standalone axonflow-gateway-adapters binary; no community HTTP surface
// is registered anywhere).
package gatewayadapters
