// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Guards runtime-e2e/3067_cross_tenant_cache_isolation against #3104.
//
// That suite is the only executing cross-tenant connector proof. It stands its
// sentinel backend on a throwaway Docker network carved out of 198.18.0.0/15
// (test.sh:91-92) and installs an http connector whose base_url points at it
// (test.sh:300-308). It works because ConnectorEgress exempts the RFC 2544
// benchmarking range — the ONE deliberate divergence in the shared table.
//
// If a future change collapses ConnectorEgress into CallbackEgress, or drops
// the RangeBenchmarking exemption, that suite starts failing at fixture setup
// with "SSRF protection" and the failure will look like a stack problem rather
// than a policy change. This test fails first, in unit time, and says so.
//
// It drives the REAL Connect() path with the suite's literal SENTINEL_IP and
// SENTINEL_PORT. It opens no sockets to that address: the SSRF guard runs
// before any dial, so the assertion is on the guard's verdict alone.

package http

import (
	"context"
	"net"
	"testing"

	"axonflow/platform/connectors/base"
	"axonflow/platform/shared/egress"
)

// These MUST match runtime-e2e/3067_cross_tenant_cache_isolation/test.sh.
const (
	sentinelIP     = "198.18.67.10" // test.sh:92  SENTINEL_IP
	sentinelPort   = "18967"        // test.sh:59  SENTINEL_PORT
	sentinelSubnet = "198.18.67.0"  // test.sh:91  SENTINEL_SUBNET (network address)
)

// TestRuntimeE2E3067_SentinelBaseURLPassesTheEgressGuard drives the connector
// configuration the suite installs, with allow_private_ips UNSET — the suite
// does not set it, so the guard genuinely runs.
func TestRuntimeE2E3067_SentinelBaseURLPassesTheEgressGuard(t *testing.T) {
	c := NewHTTPConnector()
	err := c.Connect(context.Background(), &base.ConnectorConfig{
		Name:    "victim-api",
		Options: map[string]interface{}{"base_url": "http://" + sentinelIP + ":" + sentinelPort},
	})
	if err != nil {
		t.Fatalf("Connect to the runtime-e2e/3067 sentinel base_url failed: %v\n\n"+
			"runtime-e2e/3067_cross_tenant_cache_isolation stands its sentinel on %s and installs a connector "+
			"pointed at it with no allow_private_ips. If this is an SSRF refusal, the RangeBenchmarking exemption "+
			"on egress.ConnectorEgress has been removed or narrowed and that suite will fail at fixture setup.", err, sentinelIP)
	}
}

func sentinelIPValue(t *testing.T, s string) net.IP {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil {
		t.Fatalf("unparseable address %q", s)
	}
	return ip
}

// TestRuntimeE2E3067_SentinelSubnetBoundaries pins the whole range the suite's
// README offers as fallbacks (198.19.x.0/24, test.sh:236), not just the one
// address it uses by default.
func TestRuntimeE2E3067_SentinelSubnetBoundaries(t *testing.T) {
	for _, addr := range []string{
		"198.18.0.0", sentinelSubnet, sentinelIP, "198.18.67.255", "198.19.0.1", "198.19.255.255",
	} {
		t.Run(addr, func(t *testing.T) {
			c := NewHTTPConnector()
			if err := c.Connect(context.Background(), &base.ConnectorConfig{
				Name:    "sentinel-boundary",
				Options: map[string]interface{}{"base_url": "http://" + addr + ":" + sentinelPort},
			}); err != nil {
				t.Fatalf("Connect(%s) = %v; the whole of 198.18.0.0/15 must stay dialable for runtime-e2e/3067", addr, err)
			}
		})
	}
}

// TestRuntimeE2E3067_TheExemptionIsConnectorOnly states the other half of the
// contract. The suite's dependency justifies the exemption for CONNECTOR
// egress only; a callback surface must still refuse the range, or #3104's
// central finding would have been resolved by weakening the webhook guard.
func TestRuntimeE2E3067_TheExemptionIsConnectorOnly(t *testing.T) {
	ip := sentinelIPValue(t, sentinelIP)
	if egress.ConnectorEgress.Blocks(ip) {
		t.Error("ConnectorEgress blocks the sentinel address; runtime-e2e/3067 cannot run")
	}
	if !egress.CallbackEgress.Blocks(ip) {
		t.Error("CallbackEgress permits the sentinel address; the benchmarking exemption must NOT leak to callback surfaces — " +
			"that would be resolving #3104 by weakening the webhook guard, which is exactly what the issue says not to do")
	}
	if !egress.ConnectorEgress.Exempts(egress.RangeBenchmarking) {
		t.Error("ConnectorEgress no longer exempts RangeBenchmarking by name")
	}
}

// TestRuntimeE2E3067_TheAddressesTheSuiteRejects re-states the README's table:
// the reason the suite cannot simply use a sibling container name or
// host.docker.internal is that those resolve into RFC 1918.
func TestRuntimeE2E3067_TheAddressesTheSuiteRejects(t *testing.T) {
	for _, c := range []struct{ addr, why string }{
		{"172.18.0.5", "sibling container on the compose network — RFC 1918"},
		{"192.168.65.2", "host.docker.internal on Docker Desktop — RFC 1918"},
		{"127.0.0.1", "loopback"},
		{"203.0.113.10", "TEST-NET-3 — the README notes this would have worked only via the weaker pre-#3101 classifier"},
	} {
		t.Run(c.addr, func(t *testing.T) {
			conn := NewHTTPConnector()
			err := conn.Connect(context.Background(), &base.ConnectorConfig{
				Name:    "rejected",
				Options: map[string]interface{}{"base_url": "http://" + c.addr + ":" + sentinelPort},
			})
			if err == nil {
				t.Fatalf("Connect(%s) succeeded; the suite's choice of 198.18.0.0/15 depends on this being refused (%s)", c.addr, c.why)
			}
		})
	}
}
