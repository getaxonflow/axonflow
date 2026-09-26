// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activationinputs

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

// agentSummaryTimeout bounds the read of the agent's summary: a summary that
// cannot reach the agent in time answers with the packs uncounted rather than
// hang the dashboard. A variable only so a test can shorten it.
var agentSummaryTimeout = 5 * time.Second

// agentSummaryMaxBody bounds the body read from the agent.
const agentSummaryMaxBody = 1 << 20

// AgentSummaryReader reads the agent's summary (AgentSummaryPath) of what it
// enforces on an organization. Only the agent loads a deployment's installed
// policy packs, so a summary served by another binary counts them through
// this read and never by loading the packs itself.
type AgentSummaryReader struct {
	// AgentURL is the agent's base URL.
	AgentURL string
	// Sign sets the internal-service credential on the request
	// (serviceauth.ServiceIDHeader and ServiceTokenHeader).
	Sign func(*http.Request)
	// Client is the HTTP client; nil uses one bounded by agentSummaryTimeout.
	Client *http.Client
}

// agentSummaryResponse is the agent's answer: the summary, beside success.
type agentSummaryResponse struct {
	Success bool `json:"success"`
	Summary
}

// Read returns the agent's summary for orgID and "" when it read one of scope,
// or a zero Summary and the PacksUncounted* reason it could not.
func (a AgentSummaryReader) Read(ctx context.Context, orgID, scope string) (Summary, string) {
	client := a.Client
	if client == nil {
		client = &http.Client{Timeout: agentSummaryTimeout}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(a.AgentURL, "/")+AgentSummaryPath, nil)
	if err != nil {
		return Summary{}, PacksUncountedAgentUnreachable
	}
	// A fresh request: nothing of the caller's own credential rides on it,
	// only the internal-service pair and the organization it resolved.
	if a.Sign != nil {
		a.Sign(req)
	}
	req.Header.Set("X-Org-ID", orgID)
	resp, err := client.Do(req)
	if err != nil {
		return Summary{}, PacksUncountedAgentUnreachable
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return Summary{}, PacksUncountedAgentRefused
	}
	var out agentSummaryResponse
	body, err := io.ReadAll(io.LimitReader(resp.Body, agentSummaryMaxBody))
	if err != nil || json.Unmarshal(body, &out) != nil || !out.Success || out.Scope != scope || !out.PacksCounted || out.Pack == nil {
		return Summary{}, PacksUncountedAgentAnswerUnreadable
	}
	return out.Summary, ""
}

// WithAgentPacks is the summary a binary other than the agent answers. When
// the agent's could be read, it is answered WHOLE: every count in it (shipped,
// organization, pack, disabled, total, and the not-bound and detector lists)
// is of the activation the agent enforces, which can differ from the local
// view, so none is mixed with a local count. Otherwise the local summary is
// answered with the packs uncounted and the reason named. Both are one
// Summary, so a client reads one shape either way.
func WithAgentPacks(ctx context.Context, local Summary, reader AgentSummaryReader, orgID string) Summary {
	agent, reason := reader.Read(ctx, orgID, local.Scope)
	if reason == "" {
		return agent
	}
	local.Pack, local.PacksCounted, local.PacksUncountedReason = nil, false, reason
	return local
}
