// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	sharedidentity "axonflow/platform/shared/identity"
)

var credentialPrincipalNow = time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)

// credentialHeaders sets each name/value pair as given, blank values included;
// a header not named is absent.
func credentialHeaders(pairs ...string) http.Header {
	h := http.Header{}
	for i := 0; i+1 < len(pairs); i += 2 {
		h.Set(pairs[i], pairs[i+1])
	}
	return h
}

// The community posture builds the community principal from the forwarded
// organization and client.
func TestTheCommunityPostureBuildsTheCommunityPrincipal(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	got, err := credentialPrincipal("org-a", "client-a", credentialPrincipalNow)
	if err != nil {
		t.Fatal(err)
	}
	if want := sharedidentity.CommunityPrincipal("org-a", "client-a", credentialPrincipalNow); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v; want the community principal %+v", got, want)
	}
}

// Every mode other than the exact community token builds the API-credential
// principal: community-saas and enterprise, which the agent maps to it, and an
// unset or misspelled mode, which never selects the posture that accepts an
// unverified assertion.
func TestEveryOtherModeBuildsTheAPICredentialPrincipal(t *testing.T) {
	want := sharedidentity.APICredentialPrincipal("org-a", "client-a", sharedidentity.VerificationAPICredential, true, credentialPrincipalNow)
	if reflect.DeepEqual(want, sharedidentity.CommunityPrincipal("org-a", "client-a", credentialPrincipalNow)) {
		t.Fatal("PREMISE: the API-credential and community principals are indistinguishable, so this test proves nothing")
	}
	for _, mode := range []string{"community-saas", "enterprise", "", " community", "Community", "comunity"} {
		t.Run(fmt.Sprintf("%q", mode), func(t *testing.T) {
			t.Setenv("DEPLOYMENT_MODE", mode)
			got, err := credentialPrincipal("org-a", "client-a", credentialPrincipalNow)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("got %+v; want the API-credential principal %+v", got, want)
			}
		})
	}
}

// A request without an organization or a client builds no principal, in either
// posture, and the error names the header that did not arrive.
func TestAMissingOrBlankOrganizationOrClientBuildsNoPrincipal(t *testing.T) {
	cases := []struct {
		name            string
		orgID, clientID string
		missing         string
	}{
		{"no organization", "", "client-a", "no X-Org-ID"},
		{"no client", "org-a", "", "no X-Client-ID"},
		{"blank organization", "  ", "client-a", "no X-Org-ID"},
		{"blank client", "org-a", "   ", "no X-Client-ID"},
		{"neither", "", "", "no X-Org-ID and no X-Client-ID"},
	}
	for _, mode := range []string{"community", "enterprise"} {
		for _, tc := range cases {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				t.Setenv("DEPLOYMENT_MODE", mode)
				got, err := credentialPrincipal(tc.orgID, tc.clientID, credentialPrincipalNow)
				if !errors.Is(err, errNoCredentialSubject) || !strings.Contains(err.Error(), tc.missing) {
					t.Fatalf("err %v; want errNoCredentialSubject naming %q", err, tc.missing)
				}
				if !reflect.DeepEqual(got, sharedidentity.CredentialPrincipal{}) {
					t.Fatalf("a principal was built without the value: %+v", got)
				}
			})
		}
	}
}

// The header wrapper reads exactly the two headers the agent sets, and nothing
// else. A seam that holds the request calls it; a seam whose plane threads the
// values through its own context calls the core. Pinning the two names here is
// what keeps the header spellings from drifting once the mapping itself lives
// one function down.
func TestTheHeaderWrapperReadsExactlyTheTwoAgentHeaders(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	want, err := credentialPrincipal("org-a", "client-a", credentialPrincipalNow)
	if err != nil {
		t.Fatal(err)
	}

	got, err := headerCredentialPrincipal(credentialHeaders(
		"X-Org-ID", "org-a",
		"X-Client-ID", "client-a",
		// Headers the wrapper must NOT read in place of the two above.
		"X-Tenant-ID", "tenant-a",
		"X-User-ID", "user-a",
		"X-Org-Id-Legacy", "org-b",
	), credentialPrincipalNow)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("the wrapper built %+v; want what the core builds from the same two values, %+v", got, want)
	}

	// Each header, absent on its own, is refused by name: neither is read from
	// any other header, and neither is optional.
	for _, tc := range []struct{ name, absent, missing string }{
		{"the organization header is absent", "X-Org-ID", "no X-Org-ID"},
		{"the client header is absent", "X-Client-ID", "no X-Client-ID"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pairs := []string{"X-Org-ID", "org-a", "X-Client-ID", "client-a", "X-Tenant-ID", "tenant-a"}
			h := credentialHeaders(pairs...)
			h.Del(tc.absent)
			if _, err := headerCredentialPrincipal(h, credentialPrincipalNow); !errors.Is(err, errNoCredentialSubject) || !strings.Contains(err.Error(), tc.missing) {
				t.Fatalf("err %v; want errNoCredentialSubject naming %q", err, tc.missing)
			}
		})
	}
}
