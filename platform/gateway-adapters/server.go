// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package gatewayadapters

import (
	"fmt"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"

	agwapi "axonflow/platform/gateway-adapters/agentgateway/api"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
)

// Server hosts the three PEP adapter services on one gRPC listener.
type Server struct {
	cfg  Config
	grpc *grpc.Server
}

// NewServer validates cfg, builds the shared PDP facade, and registers the
// ExtMcp, ext_authz, and ext_proc services plus standard gRPC health.
func NewServer(cfg Config) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("gateway-adapters config: %w", err)
	}
	pdp, err := NewPDP(cfg)
	if err != nil {
		return nil, fmt.Errorf("gateway-adapters PDP client: %w", err)
	}

	gs := grpc.NewServer(
		// Governed payloads are capped at MaxBodyBytes; leave generous framing
		// headroom for proto envelope overhead.
		grpc.MaxRecvMsgSize(cfg.MaxBodyBytes + (1 << 20)),
	)
	agwapi.RegisterExtMcpServer(gs, NewExtMcpServer(pdp, cfg))
	authv3.RegisterAuthorizationServer(gs, NewExtAuthzServer(pdp, cfg))
	extprocv3.RegisterExternalProcessorServer(gs, NewExtProcServer(pdp, cfg))

	h := health.NewServer()
	h.SetServingStatus("", healthv1.HealthCheckResponse_SERVING)
	healthv1.RegisterHealthServer(gs, h)

	return &Server{cfg: cfg, grpc: gs}, nil
}

// ListenAndServe blocks serving gRPC on cfg.ListenAddr.
func (s *Server) ListenAndServe() error {
	lis, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("gateway-adapters listen %s: %w", s.cfg.ListenAddr, err)
	}
	return s.Serve(lis)
}

// Serve blocks serving gRPC on lis (split out for tests).
func (s *Server) Serve(lis net.Listener) error {
	return s.grpc.Serve(lis)
}

// GracefulStop drains in-flight RPCs and stops the server.
func (s *Server) GracefulStop() { s.grpc.GracefulStop() }
