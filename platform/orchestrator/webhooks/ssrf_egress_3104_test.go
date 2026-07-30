// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// #3104 — this surface had NO SSRF test before this file. Its classifier and
// validateWebhookURL were entirely unpinned, which is how it kept a
// permissive eight-CIDR list while platform/agent/hitl hardened.
//
// Every test here drives the REAL entry point (Service.Create / Service.Update),
// not the isPrivateIP predicate, so it fails if the surface ever stops
// consulting the shared policy.

package webhooks

import (
	"context"
	"net"
	"strings"
	"testing"

	"axonflow/platform/shared/egress"
)

func mustParse(t *testing.T, s string) net.IP {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil {
		t.Fatalf("unparseable test address %q", s)
	}
	return ip
}

func newTestService(t *testing.T) *Service {
	t.Helper()
	return NewService(newMockRepository(), nil)
}

func createURL(t *testing.T, svc *Service, rawURL string) error {
	t.Helper()
	_, err := svc.Create(context.Background(), &CreateSubscriptionRequest{
		URL:    rawURL,
		Events: []string{string(AllEvents[0])},
		Active: true,
	}, "tenant-1", "org-1")
	return err
}

// newlyBlocked is every range this surface accepted before #3104 and now
// refuses. Each entry is an IP literal so Create resolves it without network
// I/O — these tests are hermetic.
var newlyBlocked = []struct {
	url string
	why string
}{
	{"http://0.0.0.0:8080/hook", "unspecified — dial-routed to loopback on Linux and macOS"},
	{"http://0.1.2.3/hook", "this-network 0.0.0.0/8"},
	{"http://100.64.0.1/hook", "CGNAT 100.64.0.0/10 (also Tailscale)"},
	{"http://100.127.255.255/hook", "CGNAT last address"},
	{"http://192.0.0.1/hook", "IETF protocol assignments 192.0.0.0/24"},
	{"http://192.0.2.1/hook", "TEST-NET-1"},
	{"http://198.51.100.1/hook", "TEST-NET-2"},
	{"http://203.0.113.1/hook", "TEST-NET-3"},
	{"http://198.18.67.10/hook", "RFC 2544 benchmarking — permitted for connectors, not callbacks"},
	{"http://239.255.255.255/hook", "multicast"},
	{"http://240.0.0.1/hook", "reserved 240.0.0.0/4"},
	{"http://255.255.255.255/hook", "limited broadcast"},
	{"http://[2001:db8::1]/hook", "IPv6 documentation"},
	{"http://[64:ff9b::7f00:1]/hook", "NAT64 wrapping 127.0.0.1"},
	{"http://[2002:7f00:1::]/hook", "6to4 wrapping 127.0.0.1"},
	{"http://[ff02::1]/hook", "IPv6 link-local multicast"},
}

// alreadyBlocked is the pre-#3104 posture. It must not regress.
var alreadyBlocked = []struct {
	url string
	why string
}{
	{"http://127.0.0.1/hook", "loopback"},
	{"http://localhost/hook", "localhost by name"},
	{"http://10.0.0.1/hook", "RFC1918"},
	{"http://172.16.0.1/hook", "RFC1918"},
	{"http://192.168.1.1/hook", "RFC1918"},
	{"http://169.254.169.254/hook", "cloud instance metadata"},
	{"http://[::1]/hook", "IPv6 loopback"},
	{"http://[fc00::1]/hook", "IPv6 ULA"},
	{"http://[fe80::1]/hook", "IPv6 link-local"},
}

func TestCreate_BlocksNewlyRefusedRanges(t *testing.T) {
	svc := newTestService(t)
	for _, c := range newlyBlocked {
		t.Run(c.url, func(t *testing.T) {
			if err := createURL(t, svc, c.url); err == nil {
				t.Fatalf("Create(%s) succeeded; must be refused (%s)", c.url, c.why)
			}
		})
	}
}

func TestCreate_StillBlocksPreExistingRanges(t *testing.T) {
	svc := newTestService(t)
	for _, c := range alreadyBlocked {
		t.Run(c.url, func(t *testing.T) {
			if err := createURL(t, svc, c.url); err == nil {
				t.Fatalf("Create(%s) succeeded; this was blocked before #3104 too (%s)", c.url, c.why)
			}
		})
	}
}

// TestCreate_PublicTargetsStillAccepted is the vacuity control. Without it a
// guard that refused every URL would pass both tests above.
func TestCreate_PublicTargetsStillAccepted(t *testing.T) {
	svc := newTestService(t)
	for _, u := range []string{
		"https://8.8.4.4/hook",
		"http://8.8.8.8/hook",
		"http://198.17.255.255/hook", // immediately below the benchmarking range
		"http://198.20.0.0/hook",     // immediately above it
		"http://100.128.0.0/hook",    // immediately above CGNAT
		"http://[2001:db9::1]/hook",  // immediately above the IPv6 doc range
		"http://[64:ff9b::808:808]/hook",
	} {
		t.Run(u, func(t *testing.T) {
			if err := createURL(t, svc, u); err != nil {
				t.Fatalf("Create(%s) = %v; a public target must stay accepted", u, err)
			}
		})
	}
}

func TestUpdate_AppliesTheSamePolicyAsCreate(t *testing.T) {
	svc := newTestService(t)
	sub, err := svc.Create(context.Background(), &CreateSubscriptionRequest{
		URL: "https://8.8.4.4/hook", Events: []string{string(AllEvents[0])}, Active: true,
	}, "tenant-1", "org-1")
	if err != nil {
		t.Fatalf("setup Create failed: %v", err)
	}
	bad := "http://100.64.0.1/hook"
	if _, err := svc.Update(context.Background(), sub.ID, &UpdateSubscriptionRequest{URL: &bad}, "tenant-1", "org-1"); err == nil {
		t.Fatal("Update to a CGNAT URL succeeded; Update must apply the same policy as Create")
	}
}

// TestValidateWebhookURL_FailsClosedOnUnparseableResolvedAddress pins the
// contract change. The old classifier returned false for a nil net.IP, so an
// address that net.ParseIP could not read was treated as public.
func TestValidateWebhookURL_FailsClosedOnUnparseableResolvedAddress(t *testing.T) {
	if !egress.CallbackEgress.Blocks(nil) {
		t.Fatal("CallbackEgress permits a nil IP; validateWebhookURL's resolved-address loop would fail open")
	}
	if !isPrivateIP(nil) {
		t.Fatal("isPrivateIP(nil) = false; the pre-#3104 classifier's fail-open is still present")
	}
}

func TestErrorNamesTheRangeAndTheEscapeHatch(t *testing.T) {
	svc := newTestService(t)
	err := createURL(t, svc, "http://100.64.0.1/hook")
	if err == nil {
		t.Fatal("expected an error")
	}
	// The operator has to be able to act on this without reading the source.
	for _, want := range []string{"100.64.0.1", string(egress.RangeCGNAT), WebhookAllowPrivateEnv} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

// TestEscapeHatch pins both directions of WebhookAllowPrivateEnv, at Create
// (validation) as well as construction. A hatch that only relaxed the dialer
// would leave the subscription un-creatable and therefore be useless.
func TestEscapeHatch(t *testing.T) {
	orig := allowPrivateRanges
	t.Cleanup(func() { allowPrivateRanges = orig })

	t.Run("off by default", func(t *testing.T) {
		allowPrivateRanges = func() bool { return false }
		if err := createURL(t, newTestService(t), "http://100.64.0.1/hook"); err == nil {
			t.Fatal("CGNAT accepted with the hatch off")
		}
	})

	t.Run("on permits the previously-accepted range", func(t *testing.T) {
		allowPrivateRanges = func() bool { return true }
		if err := createURL(t, newTestService(t), "http://100.64.0.1/hook"); err != nil {
			t.Fatalf("hatch on but Create still refused CGNAT: %v", err)
		}
	})

	// The hatch relaxes the IP posture and ONLY the IP posture. An earlier
	// revision returned nil before the localhost and DNS-resolvability checks,
	// so it silently accepted `http://localhost/hook` and an unresolvable host
	// while its own comment claimed otherwise (#3104 R3 F4).
	t.Run("on relaxes the IP posture ONLY", func(t *testing.T) {
		allowPrivateRanges = func() bool { return true }
		for _, c := range []struct{ url, why string }{
			{"file:///etc/passwd", "scheme check"},
			{"http://localhost/hook", "explicit localhost target — a misconfiguration in every deployment shape"},
			{"http://LocalHost./hook", "localhost, case- and trailing-dot-insensitive"},
			{"http://no-such-host-3104.invalid/hook", "a host that cannot resolve can never deliver"},
		} {
			if err := createURL(t, newTestService(t), c.url); err == nil {
				t.Errorf("hatch on accepted %s; it must not relax the %s", c.url, c.why)
			}
		}
	})

	t.Run("env parsing is exact-true", func(t *testing.T) {
		allowPrivateRanges = orig
		for _, v := range []string{"1", "yes", "false", ""} {
			t.Setenv(WebhookAllowPrivateEnv, v)
			if allowPrivateRanges() {
				t.Errorf("%s=%q engaged the hatch; only exact \"true\" may", WebhookAllowPrivateEnv, v)
			}
		}
		t.Setenv(WebhookAllowPrivateEnv, "true")
		if !allowPrivateRanges() {
			t.Errorf("%s=true did not engage the hatch", WebhookAllowPrivateEnv)
		}
	})
}

// TestSurfaceUsesCallbackEgress pins WHICH policy this surface consumes.
// Swapping it to ConnectorEgress would silently re-permit the benchmarking
// range on an operator-supplied callback.
func TestSurfaceUsesCallbackEgress(t *testing.T) {
	probe := mustParse(t, "198.18.67.10")
	if !isPrivateIP(probe) {
		t.Error("this surface permits 198.18.0.0/15; a callback surface must use egress.CallbackEgress, not ConnectorEgress")
	}
	if egress.ConnectorEgress.Blocks(probe) {
		t.Error("ConnectorEgress now blocks the benchmarking range; runtime-e2e/3067 depends on it being permitted")
	}
}
