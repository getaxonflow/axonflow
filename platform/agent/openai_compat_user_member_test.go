// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"net/http"
	"net/http/httptest"
	"testing"

	sharedidentity "axonflow/platform/shared/identity"
)

// THE OPENAI-COMPATIBLE ROUTE DOES NOT HONOUR OPENAI'S `user` MEMBER (#4092).
//
// OpenAI's wire lets a caller name an end user in the request body. Nothing
// verifies that name, so it is not an identity: every request on this route is
// decided for its client credential (PRD v11 §1.6). The member is sent naming
// a user a verifying deployment would admit, and the subject is still the
// credential. The control sends no member and must get the same subject, which
// also proves this world sets one at all.
func TestOpenAICompat_TheUserMemberIsNotAnIdentity(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	t.Setenv("ENVIRONMENT", "development")
	installSharedEngineForOpenAITest(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-user-member","object":"chat.completion","choices":[]}`))
	}))
	t.Cleanup(upstream.Close)
	oldEndpoints := providerEndpoints
	providerEndpoints = map[string]string{"gpt-": upstream.URL}
	t.Cleanup(func() { providerEndpoints = oldEndpoints })

	for _, c := range []struct {
		name   string
		extras map[string]interface{}
	}{
		{"a request naming a user in OpenAI's user member is decided for the client credential", map[string]interface{}{"user": enfUser}},
		{"CONTROL, a request naming no user is decided for the client credential", nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			body := makeChatBody("gpt-4o", simpleMessages("What is 2+2?"), c.extras)
			rr := openaiCompatForTest(t, body, map[string]string{"X-Provider-Key": "test-provider-key"})
			if got := rr.Header().Get(openaiCompatibleSubjectTypeHeader); got != string(sharedidentity.SubjectClient) {
				t.Fatalf("%s = %q; want %q, the client credential (HTTP %d, body=%s)",
					openaiCompatibleSubjectTypeHeader, got, sharedidentity.SubjectClient, rr.Code, rr.Body.String())
			}
		})
	}
}
