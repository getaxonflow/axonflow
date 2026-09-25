// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/shared/activationinputs"
	"axonflow/platform/shared/serviceauth"
)

// unreachableSummaryAgent is the package tests' default read of the agent's
// summary: it fails at once, as an unreachable agent does.
func unreachableSummaryAgent() activationinputs.AgentSummaryReader {
	return activationinputs.AgentSummaryReader{
		AgentURL: "http://agent.invalid",
		Client:   &http.Client{Transport: failingTransport{}},
	}
}

type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("the agent is not reachable in this test")
}

// withSummaryAgent points the production read of the agent's summary at
// agent for the test: its credential and headers are production's, only the
// address is the fake agent's.
func withSummaryAgent(t *testing.T, agent *httptest.Server) {
	t.Helper()
	previous := typedAuthoringAgentSummary
	typedAuthoringAgentSummary = func() activationinputs.AgentSummaryReader {
		r := productionTypedAuthoringAgentSummary()
		r.AgentURL, r.Client = agent.URL, agent.Client()
		return r
	}
	t.Cleanup(func() { typedAuthoringAgentSummary = previous })
}

// agentCountedSummary is what a fake agent answers: a counted summary of the
// decide scope whose counts differ from any the orchestrator computes, so a
// route answering it is visibly answering the agent's.
func agentCountedSummary() activationinputs.Summary {
	pack := 7
	return activationinputs.Summary{Scope: "decide", Shipped: 40, Organization: 3, Pack: &pack, PacksCounted: true, Total: 50}
}

func summaryMembers(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// THE POLICY SUMMARY COUNTS THE INSTALLED PACKS BY READING THE AGENT (#4249).
// Only the agent loads a deployment's packs, so the orchestrator's summary
// answers the agent's count when it can read it, and otherwise its own, with
// the packs uncounted and the reason named, in one shape either way.
func TestTheSummaryRouteCountsTheInstalledPacksThroughTheAgent(t *testing.T) {
	var seen *http.Request
	agentAnswer := func(status int, body string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seen = r.Clone(r.Context())
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		}))
	}
	counted, err := json.Marshal(struct {
		Success bool `json:"success"`
		activationinputs.Summary
	}{true, agentCountedSummary()})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("the agent answers: the route answers the agent's counted summary", func(t *testing.T) {
		agent := agentAnswer(http.StatusOK, string(counted))
		defer agent.Close()
		withSummaryAgent(t, agent)
		got := summaryOf(t, newRouteHandler(t, authoring.EditionCommunity))
		if got["packs_counted"] != true || countOf(t, got, "pack") != 7 || countOf(t, got, "total") != 50 ||
			countOf(t, got, "shipped") != 40 || countOf(t, got, "organization") != 3 {
			t.Fatalf("summary %v; want the agent's: pack 7, total 50, shipped 40, organization 3, packs_counted true", got)
		}
		if _, present := got["packs_uncounted_reason"]; present {
			t.Fatalf("summary %v carries packs_uncounted_reason; it is omitted when the packs were counted", got)
		}
		// The read carried the internal-service credential and the caller's
		// organization, and nothing of the caller's own credential.
		if seen == nil || seen.URL.Path != activationinputs.AgentSummaryPath || seen.Method != http.MethodGet {
			t.Fatalf("the agent saw %v; want GET %s", seen, activationinputs.AgentSummaryPath)
		}
		if seen.Header.Get(serviceauth.ServiceIDHeader) != serviceauth.ClientID || seen.Header.Get(serviceauth.ServiceTokenHeader) == "" {
			t.Errorf("the read's internal-service pair: id %q token %q", seen.Header.Get(serviceauth.ServiceIDHeader), seen.Header.Get(serviceauth.ServiceTokenHeader))
		}
		if seen.Header.Get("X-Org-ID") != testOrg {
			t.Errorf("the read named organization %q, want %q", seen.Header.Get("X-Org-ID"), testOrg)
		}
		for _, h := range []string{"Authorization", "X-Client-ID", "X-Tenant-ID", "X-User-Token"} {
			if seen.Header.Get(h) != "" {
				t.Errorf("the read forwarded the caller's %s: %q", h, seen.Header.Get(h))
			}
		}
	})

	// Every way the read can fail answers the local summary in the same shape,
	// with packs_counted false, pack null and the reason named.
	local := summaryOf(t, newRouteHandler(t, authoring.EditionCommunity))
	for _, c := range []struct {
		name, reason string
		agent        func() *httptest.Server
	}{
		{"the agent is down", activationinputs.PacksUncountedAgentUnreachable, func() *httptest.Server {
			s := agentAnswer(http.StatusOK, string(counted))
			s.Close()
			return s
		}},
		{"the agent refuses", activationinputs.PacksUncountedAgentRefused, func() *httptest.Server {
			return agentAnswer(http.StatusInternalServerError, `{"success":false}`)
		}},
		{"the agent answers what is not a summary", activationinputs.PacksUncountedAgentAnswerUnreadable, func() *httptest.Server {
			return agentAnswer(http.StatusOK, `not json`)
		}},
		{"the agent answers another scope", activationinputs.PacksUncountedAgentAnswerUnreadable, func() *httptest.Server {
			return agentAnswer(http.StatusOK, `{"success":true,"scope":"mcp","shipped":1,"organization":0,"pack":0,"packs_counted":true,"disabled":0,"total":1}`)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			agent := c.agent()
			defer agent.Close()
			withSummaryAgent(t, agent)
			got := summaryOf(t, newRouteHandler(t, authoring.EditionCommunity))
			if got["packs_counted"] != false || got["pack"] != nil || got["packs_uncounted_reason"] != c.reason {
				t.Fatalf("summary %v; want packs_counted false, pack null and packs_uncounted_reason %q", got, c.reason)
			}
			for _, field := range []string{"shipped", "organization", "total", "disabled"} {
				if countOf(t, got, field) != countOf(t, local, field) {
					t.Errorf("%s = %d, want the local count %d", field, countOf(t, got, field), countOf(t, local, field))
				}
			}
			// One shape: the fallback carries every member the counted answer
			// does, and packs_uncounted_reason besides.
			want := append(summaryMembers(map[string]any{"success": 0, "scope": 0, "shipped": 0, "organization": 0, "pack": 0, "packs_counted": 0, "disabled": 0, "total": 0}), "packs_uncounted_reason")
			sort.Strings(want)
			if gotKeys := summaryMembers(got); !equalStrings(gotKeys, want) {
				t.Errorf("members %v, want %v", gotKeys, want)
			}
		})
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
