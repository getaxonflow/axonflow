// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"context"
	"net/http"
	"strings"
)

// SyntheticProbeHeader is the request header AxonFlow's own canary sets to mark
// its requests.
//
// # ITS FORGERY DIRECTION IS SAFE, WHICH IS WHY A HEADER CAN CARRY IT
//
// The header is caller-assertable, and it decides nothing: no admission,
// verification or policy decision reads it. The mark exists so the canary's
// decisions can be told apart from a tenant's (#4120 labels enforcement
// decisions with it). A tenant that marked its own traffic synthetic would only
// relabel it, and would gain nothing any decision reads.
const SyntheticProbeHeader = "X-Axonflow-Synthetic-Probe"

// IsSyntheticProbeHeader reports whether a header value marks a synthetic
// probe.
//
// A POSITIVE membership test on the two spellings the canary sends, not
// "non-empty": a header echoed back by a proxy, or one a caller set to "0" or
// "false" meaning to turn it OFF, must not read as true.
func IsSyntheticProbeHeader(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true":
		return true
	default:
		return false
	}
}

// SyntheticProbeMiddleware stamps the request context with the synthetic-probe
// fact, ONCE, at the outermost edge of a binary's handler chain.
//
// # WHY IT IS ONE MIDDLEWARE RATHER THAN N CALL SITES
//
// The fact's readers sit several layers in, where a context arrives and a
// request does not, so it is stamped once here, at the root, rather than at
// each call site. Both binaries wrap their served handler in it, and
// TestTheAgentRootHandlerStampsTheSyntheticProbe and its orchestrator twin pin
// the wrap in each. Nothing reads the mark yet; #4120's enforcement counter is
// its consumer.
//
// # IT IS UNCONDITIONAL
//
// The stamp is applied to every request, including unauthenticated ones, and
// costs one header lookup and one context.WithValue. See SyntheticProbeHeader
// for why a caller-assertable header is safe for this one fact.
//
// A nil `next` is returned as nil rather than wrapped, so a caller that has not
// built its router yet fails at the mux rather than inside a middleware.
func SyntheticProbeMiddleware(next http.Handler) http.Handler {
	if next == nil {
		return nil
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(ContextWithSyntheticProbe(
			r.Context(), IsSyntheticProbeHeader(r.Header.Get(SyntheticProbeHeader)))))
	})
}

// syntheticProbeCtxKey is the key ContextWithSyntheticProbe stores under. It is
// an unexported struct type so no other package can collide with it or set the
// value without going through the constructor below.
type syntheticProbeCtxKey struct{}

// ContextWithSyntheticProbe marks a context as belonging to a request driven
// by AxonFlow's own canary. SyntheticProbeMiddleware is its caller; a reader
// with no request of its own reads the mark back with SyntheticProbeFromContext.
func ContextWithSyntheticProbe(ctx context.Context, synthetic bool) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, syntheticProbeCtxKey{}, synthetic)
}

// SyntheticProbeFromContext reports whether the context was marked.
//
// AN UNSTAMPED CONTEXT ANSWERS FALSE, so a request that was never stamped reads
// as a tenant's rather than as the canary's.
func SyntheticProbeFromContext(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	v, _ := ctx.Value(syntheticProbeCtxKey{}).(bool)
	return v
}
