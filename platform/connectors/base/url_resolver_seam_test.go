// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package base

import (
	"errors"
	"net"
	"strings"
	"testing"
)

// THE RESOLVER SEAM IS TESTED ON THE MIRRORED SIDE (#3699).
//
// URLValidationOptions.LookupIP ships in the community mirror; the caller it
// was added for, ee/platform/connectors/amadeus, does not. A seam whose only
// exercise lives in the stripped half is a seam the community build carries
// untested, which is the same shape of hole as the by-name package list this
// change removed - so its behaviour is pinned here, where it is mirrored.
//
// The seam exists because a connector whose hosts are HARD-CODED cannot pass
// AllowPrivateIPs the way this package's own tests do without switching the
// SSRF check off entirely. It moves the resolver, never the check.

func TestTheResolverSeamMovesTheResolverAndNotTheCheck(t *testing.T) {
	const host = "https://api.example.com/v1"

	t.Run("a supplied resolver is used, and a public answer passes", func(t *testing.T) {
		called := 0
		err := ValidateURL(host, URLValidationOptions{
			AllowedSchemes: []string{"https"},
			AllowedHosts:   []string{"api.example.com"},
			LookupIP: func(h string) ([]net.IP, error) {
				called++
				if h != "api.example.com" {
					t.Errorf("the seam was asked to resolve %q, not the URL's host", h)
				}
				return []net.IP{net.ParseIP("8.8.8.8")}, nil
			},
		})
		if err != nil {
			t.Fatalf("a public answer was refused: %v", err)
		}
		if called != 1 {
			t.Fatalf("the supplied resolver was called %d times, want 1; the seam is not on the path", called)
		}
	})

	t.Run("THE CHECK STILL RUNS: a private answer is refused", func(t *testing.T) {
		// The whole point. If the seam had replaced the check rather than the
		// resolver, this would pass and every caller using it would have SSRF
		// protection in name only.
		for _, ip := range []string{"10.0.0.7", "127.0.0.1", "192.168.1.1", "169.254.169.254"} {
			err := ValidateURL(host, URLValidationOptions{
				AllowedSchemes: []string{"https"},
				AllowedHosts:   []string{"api.example.com"},
				LookupIP:       func(string) ([]net.IP, error) { return []net.IP{net.ParseIP(ip)}, nil },
			})
			if err == nil {
				t.Errorf("a resolver answer of %s was accepted; the private-IP check did not run over the seam's answer", ip)
			}
		}
	})

	t.Run("a resolver error is reported, not swallowed", func(t *testing.T) {
		sentinel := errors.New("no such host")
		err := ValidateURL(host, URLValidationOptions{
			AllowedSchemes: []string{"https"},
			AllowedHosts:   []string{"api.example.com"},
			LookupIP:       func(string) ([]net.IP, error) { return nil, sentinel },
		})
		if err == nil {
			t.Fatal("a resolution failure was accepted; an unresolvable host must not pass the SSRF check")
		}
		if !strings.Contains(err.Error(), "failed to resolve hostname") {
			t.Errorf("the refusal does not report a resolution failure: %v", err)
		}
	})

	t.Run("nil means the real resolver, and production is unchanged", func(t *testing.T) {
		// A nil seam must take net.LookupIP.
		//
		// Asserted WITHOUT REACHING A DNS SERVER, which matters more here than
		// anywhere: this test ships in a required lane on the community mirror,
		// and the change it guards exists precisely to stop unit tests doing
		// live DNS. An earlier draft resolved a `.invalid` name and called the
		// resulting failure proof - that is a live lookup, and it inverts under
		// a resolver that wildcards NXDOMAIN.
		//
		// "localhost" is answered from the hosts file, so it needs no DNS
		// server and lands in the loopback range the private-IP check refuses.
		// A DEPENDENCY RATHER THAN A GUARANTEE, stated as one: under the cgo
		// resolver (darwin by default) the lookup goes through getaddrinfo,
		// which may consult mDNS, and on a host with no localhost entry at all
		// Go falls through to DNS and the lookup errors.
		//
		// So the pinned property is the FIRST assertion, and only that one: a
		// nil seam must refuse. That is the outcome that distinguishes "nil
		// means net.LookupIP" from "nil means skip the check", and it holds
		// however localhost resolves, because both a loopback answer and a
		// resolution failure are refusals. The second assertion says which
		// refusal, and accepts either shape rather than making this test's
		// verdict depend on the resolver the runner happens to use.
		err := ValidateURL("https://localhost/v1", URLValidationOptions{
			AllowedSchemes: []string{"https"},
			AllowedHosts:   []string{"localhost"},
		})
		if err == nil {
			t.Fatal("a nil seam accepted a loopback host; nil must mean net.LookupIP, not 'skip the check'")
		}
		if !strings.Contains(err.Error(), "private/internal IP") &&
			!strings.Contains(err.Error(), "failed to resolve hostname") {
			t.Errorf("a nil seam refused, but for neither reason a real lookup produces (want the private-IP refusal, or a resolution failure on a host with no localhost entry): %v", err)
		}
	})

	t.Run("AllowPrivateIPs still skips resolution entirely", func(t *testing.T) {
		// The pre-existing escape hatch is unchanged: when the private-IP check
		// is off there is nothing to resolve, so the seam must not be called.
		err := ValidateURL(host, URLValidationOptions{
			AllowPrivateIPs: true,
			AllowedSchemes:  []string{"https"},
			AllowedHosts:    []string{"api.example.com"},
			LookupIP: func(string) ([]net.IP, error) {
				t.Error("the resolver was called although AllowPrivateIPs is set; resolution is the check's own step")
				return nil, nil
			},
		})
		if err != nil {
			t.Fatalf("AllowPrivateIPs no longer skips the check: %v", err)
		}
	})
}
