// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"net/http"
	"net/http/httptest"
	"testing"

	sharedpolicy "axonflow/platform/shared/policy"
)

// THE OPENAI-COMPATIBLE ROUTE COUNTS A DISPLACED STORED ACTION (#3360).
//
// The anchored engine authors this route's verdict, so nothing on it converts
// the shared engine's result into a StaticPolicyResult, and the conversion was
// where every other plane records a downward displacement. The route records
// it from its own evaluation instead. The world is the NIK row, stored as
// block, under a recorded pii=warn: a weakening the organization chose, which
// the counter exists to show.
func TestOpenAICompat_ADownwardDisplacementIsCounted(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	t.Setenv("ENVIRONMENT", "development")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-displaced","object":"chat.completion","choices":[]}`))
	}))
	t.Cleanup(upstream.Close)
	oldEndpoints := providerEndpoints
	providerEndpoints = map[string]string{"gpt-": upstream.URL}
	t.Cleanup(func() { providerEndpoints = oldEndpoints })

	send := func() {
		body := makeChatBody("gpt-4o", simpleMessages("Customer NIK is "+fixtureNIK), nil)
		openaiCompatForTest(t, body, map[string]string{"X-Provider-Key": "test-provider-key"})
	}

	t.Run("a recorded pii=warn weakens the stored block, and the route counts it", func(t *testing.T) {
		installNIKWorld(t, getDeploymentOrgID(), DetectionActionWarn)
		before := displacedCount(sharedpolicy.ActionBlock, sharedpolicy.ActionWarn)
		send()
		if after := displacedCount(sharedpolicy.ActionBlock, sharedpolicy.ActionWarn); after != before+1 {
			t.Fatalf("the displacement must be counted once: %v -> %v", before, after)
		}
	})
	t.Run("CONTROL, no override recorded: nothing is weakened and nothing is counted", func(t *testing.T) {
		installNIKWorld(t, getDeploymentOrgID(), "")
		before := displacedCount(sharedpolicy.ActionBlock, sharedpolicy.ActionWarn)
		send()
		if after := displacedCount(sharedpolicy.ActionBlock, sharedpolicy.ActionWarn); after != before {
			t.Fatalf("no override is recorded, yet a displacement was counted: %v -> %v", before, after)
		}
	})
}
