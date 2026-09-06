// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Command axonflow-gateway-adapters serves the agentgateway-native PEP
// adapters (#2886): the ExtMcp, Envoy ext_authz, and Envoy ext_proc gRPC
// policy services, all translating to the AxonFlow Decision Mode engine.
// Enterprise-only.
//
// Configuration is via environment variables (see gatewayadapters.ConfigFromEnv):
//
//	AXONFLOW_ENDPOINT          PDP base URL (required)
//	AXONFLOW_ORG_ID            HTTP Basic org (with AXONFLOW_LICENSE_KEY)
//	                           ALSO the org_id on this binary's telemetry ping:
//	                           an `axonflow-` org classifies the row as an
//	                           internal deployment rather than as external
//	                           adoption (ADR-054, #2259).
//	DEPLOYMENT_MODE            not read by this binary's own configuration, but
//	                           READ BY ITS TELEMETRY, where it decides ONE of
//	                           the ping's two mode fields and not the other:
//	                             platform_deployment_mode - this value,
//	                               normalised; OMITTED when unset, which is the
//	                               honest answer rather than a default.
//	                             deployment_mode (topology) - `self_hosted` on
//	                               every row this binary emits, whatever this
//	                               variable says, because the only other value
//	                               is community_saas and Community-SaaS does not
//	                               deploy gateway adapters. Right by
//	                               CONSTRUCTION, not by measurement: read it as
//	                               "this component only ships self-hosted", not
//	                               as evidence about the deployment.
//	                           Inherited from the task definition the adapters
//	                           share with the agent.
//	AXONFLOW_LICENSE_KEY       HTTP Basic license key
//	AXONFLOW_TENANT_ID         tenant scope
//	AXONFLOW_GATEWAY_ID        caller_identity.gateway_id (default "agentgateway")
//	AXONFLOW_DEFAULT_STAGE     decide stage for HTTP seams: llm|tool|agent (default "llm")
//	AXONFLOW_FAIL_MODE         request-plane posture: closed|open (default "closed")
//	AXONFLOW_REQUEST_TIMEOUT   engine call timeout (default "10s")
//	AXONFLOW_MAX_BODY_BYTES    scannable-payload bound (default 8388608)
//	AXONFLOW_BREAKER_THRESHOLD / AXONFLOW_BREAKER_COOLDOWN
//	                           circuit posture (defaults 5 / "30s")
//	AXONFLOW_TRUST_IDENTITY_HEADERS
//	                           forward client X-User-Email/X-Session-Id on
//	                           check-output (default "false"; see Config)
//	AXONFLOW_EXTPROC_RESPONSE_GOVERNANCE
//	                           which ext_proc response body modes are accepted:
//	                           "buffered" (default) requires every leg to hand
//	                           the adapter the whole response body, so every
//	                           response is scanned; "off" ALSO accepts a leg
//	                           advertising responseBodyMode: none, which runs
//	                           that leg with the RESPONSE UNGOVERNED (no
//	                           check-output scan, no response redaction) while
//	                           the request is still decided and redacted — the
//	                           seam for streaming/SSE completions (#2959). It is
//	                           process-wide: with it set, any ext_proc route on
//	                           this adapter may drop response governance by
//	                           advertising none. Any other value refuses to boot.
//	GATEWAY_ADAPTERS_LISTEN    gRPC listen address (default ":9090")
//	GATEWAY_ADAPTERS_METRICS_LISTEN
//	                           optional HTTP address for /metrics (e.g. ":9091").
//	                           UNSET starts no listener, keeping the
//	                           single-listener shape this binary has always had.
//	                           Deliberately a separate address from the gRPC
//	                           port: that one carries governed traffic and must
//	                           not also answer unauthenticated HTTP.
//	AXONFLOW_TELEMETRY         set to "off" to disable the anonymous 7-day
//	                           startup heartbeat (the same lever the SDKs honor)
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	gatewayadapters "axonflow/platform/gateway-adapters"
)

func main() {
	cfg := gatewayadapters.ConfigFromEnv()
	srv, err := gatewayadapters.NewServer(cfg)
	if err != nil {
		log.Fatalf("[gateway-adapters] %v", err)
	}

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		log.Printf("[gateway-adapters] shutting down")
		srv.GracefulStop()
	}()

	// Anonymous platform startup telemetry (#3660). Fire-and-forget through the
	// ONE shared emitter the agent and orchestrator use; AXONFLOW_TELEMETRY=off
	// short-circuits inside it, as does the CI auto-suppress. Before this the
	// adapters emitted nothing at all, so a deployment running them was
	// indistinguishable from one that had never installed them.
	gatewayadapters.StartTelemetry(context.Background(), cfg)

	// Prometheus scrape surface (#3660). The adapter is a gRPC service with no
	// HTTP listener of its own, so the per-surface decision counters had
	// nowhere to be read from. This is a SEPARATE, opt-in address rather than a
	// port on the gRPC listener: the gRPC listener carries governed traffic and
	// must not also answer unauthenticated HTTP.
	//
	// It serves /metrics and nothing else. Unset (the default) starts no
	// listener at all, so an operator who does not want a second port keeps the
	// single-listener shape the adapter has always had.
	if addr := os.Getenv("GATEWAY_ADAPTERS_METRICS_LISTEN"); addr != "" {
		go func() {
			mux := http.NewServeMux()
			mux.Handle("/metrics", promhttp.Handler())
			log.Printf("[gateway-adapters] serving Prometheus metrics on %s/metrics", addr)
			// A wedged metrics listener must never take the adapter down: log
			// and carry on governing.
			srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
			if err := srv.ListenAndServe(); err != nil {
				log.Printf("[gateway-adapters] metrics listener stopped: %v", err)
			}
		}()
	}

	log.Printf("[gateway-adapters] serving ExtMcp + ext_authz + ext_proc on %s (PDP %s, fail_mode=%s, extproc_response_governance=%s)",
		cfg.ListenAddr, cfg.AxonFlowEndpoint, cfg.FailMode, cfg.ExtProcResponseGovernance)
	// An ungoverned response plane is opt-in, so it is an operator decision —
	// and an operator decision that is not visible at startup is one nobody
	// reviews. Say it once, loudly, naming exactly what is and is not covered.
	if cfg.ExtProcResponseGovernance == gatewayadapters.ExtProcResponseGovernanceOff {
		log.Printf("[gateway-adapters] WARNING: AXONFLOW_EXTPROC_RESPONSE_GOVERNANCE=%s — ext_proc legs whose gateway advertises responseBodyMode: none will run with the RESPONSE BODY UNGOVERNED: no check-output scan, no response redaction, no response-plane block. The REQUEST plane is unaffected (prompts are still decided and engine-redacted). Each such stream is logged individually.",
			gatewayadapters.ExtProcResponseGovernanceOff)
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("[gateway-adapters] %v", err)
	}
}
