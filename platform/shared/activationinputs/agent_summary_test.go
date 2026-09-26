// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activationinputs

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Each answer the agent can give that is not a counted summary of the scope
// asked for is unreadable, and never read as a count.
func TestTheAgentSummaryReadAcceptsOnlyACountedSummaryOfTheScope(t *testing.T) {
	for _, c := range []struct {
		name, body, reason string
		status             int
	}{
		{"a counted summary", `{"success":true,"scope":"decide","shipped":2,"organization":1,"pack":4,"packs_counted":true,"disabled":0,"total":7}`, "", http.StatusOK},
		{"a counted zero", `{"success":true,"scope":"decide","shipped":2,"organization":0,"pack":0,"packs_counted":true,"disabled":0,"total":2}`, "", http.StatusOK},
		{"success false", `{"success":false,"scope":"decide","pack":4,"packs_counted":true}`, PacksUncountedAgentAnswerUnreadable, http.StatusOK},
		{"packs not counted", `{"success":true,"scope":"decide","pack":null,"packs_counted":false}`, PacksUncountedAgentAnswerUnreadable, http.StatusOK},
		// A pack number beside packs_counted false is still not a counted
		// summary: only the flag says the packs were counted, so this row reds
		// a read that trusts the number alone.
		{"a pack number the agent says it did not count", `{"success":true,"scope":"decide","pack":3,"packs_counted":false}`, PacksUncountedAgentAnswerUnreadable, http.StatusOK},
		{"pack absent", `{"success":true,"scope":"decide","packs_counted":true}`, PacksUncountedAgentAnswerUnreadable, http.StatusOK},
		{"another scope", `{"success":true,"scope":"mcp","pack":0,"packs_counted":true}`, PacksUncountedAgentAnswerUnreadable, http.StatusOK},
		{"not json", `<html>`, PacksUncountedAgentAnswerUnreadable, http.StatusOK},
		{"401", `{}`, PacksUncountedAgentRefused, http.StatusUnauthorized},
		{"503", `{}`, PacksUncountedAgentRefused, http.StatusServiceUnavailable},
	} {
		t.Run(c.name, func(t *testing.T) {
			agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(c.status)
				_, _ = w.Write([]byte(c.body))
			}))
			defer agent.Close()
			s, reason := AgentSummaryReader{AgentURL: agent.URL, Client: agent.Client()}.Read(context.Background(), "org-a", "decide")
			if reason != c.reason {
				t.Fatalf("reason %q, want %q", reason, c.reason)
			}
			if reason == "" && (!s.PacksCounted || s.Pack == nil) {
				t.Fatalf("a read summary %+v is not counted", s)
			}
		})
	}
	t.Run("an agent that cannot be reached", func(t *testing.T) {
		agent := httptest.NewServer(http.NotFoundHandler())
		agent.Close()
		if _, reason := (AgentSummaryReader{AgentURL: agent.URL}).Read(context.Background(), "org-a", "decide"); reason != PacksUncountedAgentUnreachable {
			t.Fatalf("reason %q, want %q", reason, PacksUncountedAgentUnreachable)
		}
	})
}

// WithAgentPacks answers the local summary with the packs uncounted and the
// reason named when the read fails, and changes nothing else about it.
func TestWithAgentPacksKeepsTheLocalCountsAndNamesTheReason(t *testing.T) {
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) }))
	defer agent.Close()
	local := Summary{Scope: "decide", Shipped: 5, Organization: 2, Disabled: 1, Total: 7, NotBoundHere: []string{"x"}}
	got := WithAgentPacks(context.Background(), local, AgentSummaryReader{AgentURL: agent.URL, Client: agent.Client()}, "org-a")
	if got.PacksCounted || got.Pack != nil || got.PacksUncountedReason != PacksUncountedAgentRefused {
		t.Fatalf("got %+v; want the packs uncounted, agent_refused", got)
	}
	if got.Shipped != 5 || got.Organization != 2 || got.Disabled != 1 || got.Total != 7 || len(got.NotBoundHere) != 1 {
		t.Fatalf("got %+v; the local counts must be unchanged", got)
	}
}

// An agent slower than the read's bound is unreachable, not waited on: the
// summary answers with the packs uncounted rather than hang the dashboard.
// The reader's default client (Client nil, as every production reader passes)
// is the one bounded, so this drives that client.
func TestAnAgentSlowerThanTheBoundIsUnreachable(t *testing.T) {
	prev := agentSummaryTimeout
	agentSummaryTimeout = 50 * time.Millisecond
	t.Cleanup(func() { agentSummaryTimeout = prev })
	release := make(chan struct{})
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(agent.Close)
	t.Cleanup(func() { close(release) })

	start := time.Now()
	_, reason := AgentSummaryReader{AgentURL: agent.URL}.Read(context.Background(), "org-slow", "decide")
	if reason != PacksUncountedAgentUnreachable {
		t.Fatalf("a slow agent answered reason %q, want %q", reason, PacksUncountedAgentUnreachable)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("the read waited %s for a slow agent; the bound is %s", elapsed, agentSummaryTimeout)
	}
}
