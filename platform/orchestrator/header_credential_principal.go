// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"axonflow/platform/shared/deploymode"
	sharedidentity "axonflow/platform/shared/identity"
)

// errNoCredentialSubject is a request whose credential subject cannot be built:
// the agent forwarded no organization or no client. An enforcing plane refuses
// it as subject_unverifiable; it never decides for an organization or a client
// it was not told (#4254).
var errNoCredentialSubject = errors.New("the request carries no credential subject")

// credentialPrincipal builds the credential principal an enforcing plane of this
// process admits (sharedidentity.SubjectAdmitter.AdmitCredentialSubject) for one
// request, from the organization and the client the agent authenticated.
//
// THE VALUES ARE THE AGENT'S, NOT THE CALLER'S. Every non-exempt request reaches
// this process over the internal-service hop (requireInternalProxyAuth), and the
// agent sets X-Org-ID and X-Client-ID on that hop from its own authentication of
// the caller. Those two headers are this process's ONLY source for these two
// values - headerCredentialPrincipal reads them - which is why the refusal below
// names the headers: an empty value means the agent forwarded no header.
//
// So the mapping is the agent's authResultPrincipal, one hop on:
//   - the community posture (deploymode.CurrentIsCommunityPosture: exactly the
//     token "community") builds sharedidentity.CommunityPrincipal, the
//     deployment's declared acceptance of an unverified client assertion;
//   - every other mode builds sharedidentity.APICredentialPrincipal, verified as
//     an API credential. That is community-saas and enterprise, which the agent
//     maps to the same principal, and an unset or unrecognised mode too: the
//     agent admits no caller there without checking a credential, so a posture
//     that accepts an unverified assertion is never inferred from a missing or
//     misspelled mode (#3096).
//
// A missing or blank value builds nothing and returns errNoCredentialSubject,
// naming the header that carries it.
func credentialPrincipal(orgID, clientID string, now time.Time) (sharedidentity.CredentialPrincipal, error) {
	var missing []string
	if strings.TrimSpace(orgID) == "" {
		missing = append(missing, "X-Org-ID")
	}
	if strings.TrimSpace(clientID) == "" {
		missing = append(missing, "X-Client-ID")
	}
	if len(missing) > 0 {
		return sharedidentity.CredentialPrincipal{}, fmt.Errorf("%w: the agent forwarded no %s", errNoCredentialSubject, strings.Join(missing, " and no "))
	}
	if deploymode.CurrentIsCommunityPosture() {
		return sharedidentity.CommunityPrincipal(orgID, clientID, now), nil
	}
	return sharedidentity.APICredentialPrincipal(orgID, clientID, sharedidentity.VerificationAPICredential, true, now), nil
}

// headerCredentialPrincipal is credentialPrincipal for a seam that holds the
// request itself: it reads the two headers the agent sets and nothing else.
//
// The multi-agent plane and the workflow step gate read it through the subject
// their HTTP boundary installs on the request context (withMAPPlaneSubject,
// withWCPPlaneSubject); the route seams read the request directly.
func headerCredentialPrincipal(h http.Header, now time.Time) (sharedidentity.CredentialPrincipal, error) {
	return credentialPrincipal(h.Get("X-Org-ID"), h.Get("X-Client-ID"), now)
}
