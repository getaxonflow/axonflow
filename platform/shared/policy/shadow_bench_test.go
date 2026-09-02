package policy

import (
	"context"
	"testing"
	"time"

	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/shared/planeshadow"
)

// THE OVERHEAD MEASUREMENT, AND WHAT IT IS A MEASUREMENT OF.
//
// The shadow's expensive half - compiling legacy policy to Rego, signing a
// bundle, running OPA - is on a worker and no request waits for it. What a
// request DOES wait for is: one atomic load when the shadow is off, and
// additionally the row-fact slice plus a channel send when it is on.
//
// So these benchmarks measure the SYNCHRONOUS cost only, which is the number
// the rollout decision actually turns on. A benchmark that included the worker
// would report a figure no caller experiences and would make the default
// sampling rate look indefensible.
//
// Run:
//
//	go test ./shared/policy/ -run '^$' -bench 'BenchmarkShadow' -benchtime 2000x
//
// The PR that introduced this records the measured p50/p99 per plane. They are
// deliberately NOT asserted here: a latency assertion on a shared CI runner is
// a flake generator, and the figure that matters is measured on the fleet
// rather than on a build box.

// benchPlanes spans the three evaluator entry points' static planes, because
// the observation's cost scales with the loaded policy set and each plane
// loads a different one in production.
var benchPlanes = []legacycompile.Plane{
	legacycompile.PlaneGatewayRequest,
	legacycompile.PlaneDecide,
	legacycompile.PlaneMCP,
	legacycompile.PlaneProxyRequest,
	legacycompile.PlaneOpenAICompatible,
}

// BenchmarkShadowOffRequestPlane is the baseline: what a deployment that never
// turns the shadow on pays. It must be indistinguishable from pre-v10.3.0.
func BenchmarkShadowOffRequestPlane(b *testing.B) {
	prior := planeshadow.ProcessObserver()
	planeshadow.SetProcessObserver(nil)
	b.Cleanup(func() { planeshadow.SetProcessObserver(prior) })

	for _, plane := range benchPlanes {
		plane := plane
		b.Run(string(plane), func(b *testing.B) {
			e := createTestEngine(shadowNoninterferencePolicies())
			opts := EvalOptions{Plane: plane, TenantID: "test-tenant", OrgID: "test-tenant"}
			ctx := context.Background()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = e.EvaluateRequest(ctx, "SELECT name FROM customers", opts)
			}
		})
	}
}

// BenchmarkShadowOnRequestPlane is the same evaluation with the shadow
// observing. The delta against the benchmark above is the whole cost a caller
// pays.
func BenchmarkShadowOnRequestPlane(b *testing.B) {
	o := benchObserver(b)
	planeshadow.SetProcessObserver(o)

	for _, plane := range benchPlanes {
		plane := plane
		b.Run(string(plane), func(b *testing.B) {
			e := createTestEngine(shadowNoninterferencePolicies())
			opts := EvalOptions{Plane: plane, TenantID: "test-tenant", OrgID: "test-tenant"}
			ctx := context.Background()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = e.EvaluateRequest(ctx, "SELECT name FROM customers", opts)
			}
		})
	}
}

// BenchmarkShadowOnRequestPlaneMatching is the same with content that MATCHES,
// so the observation carries a matched row and the legacy verdict is built.
//
// The two are measured separately because the clean path is the common one and
// the matching path is the expensive one; reporting only the average of a
// mixed corpus would hide which.
func BenchmarkShadowOnRequestPlaneMatching(b *testing.B) {
	o := benchObserver(b)
	planeshadow.SetProcessObserver(o)

	e := createTestEngine(shadowNoninterferencePolicies())
	opts := EvalOptions{
		Plane: legacycompile.PlaneGatewayRequest, TenantID: "test-tenant", OrgID: "test-tenant",
	}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = e.EvaluateRequest(ctx, "DROP TABLE customers", opts)
	}
}

// BenchmarkShadowOffResponsePlane and its ON counterpart measure the response
// phase, which redacts content and is the more expensive evaluation of the two.
func BenchmarkShadowOffResponsePlane(b *testing.B) {
	prior := planeshadow.ProcessObserver()
	planeshadow.SetProcessObserver(nil)
	b.Cleanup(func() { planeshadow.SetProcessObserver(prior) })
	benchResponse(b)
}

func BenchmarkShadowOnResponsePlane(b *testing.B) {
	planeshadow.SetProcessObserver(benchObserver(b))
	benchResponse(b)
}

func benchResponse(b *testing.B) {
	b.Helper()
	e := createTestEngine(shadowNoninterferencePolicies())
	opts := EvalOptions{
		Plane: legacycompile.PlaneOrchestratorResponse, TenantID: "test-tenant", OrgID: "test-tenant",
	}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = e.EvaluateResponse(ctx, []map[string]interface{}{
			{"name": "alice", "ssn": "123-45-6789"},
		}, opts)
	}
}

// benchObserver builds an observer sized so the queue never becomes the
// bottleneck.
//
// A SHALLOW queue would turn this into a benchmark of backpressure: once it
// filled, every Observe would take the drop branch, which is CHEAPER than the
// send - so the measured overhead would fall as the shadow stopped working.
// That is the wrong direction to be wrong in, so the queue is deep and the
// pool is real.
// benchQueueDepth is the depth benchObserver builds with, named so the guard
// below can be derived from it rather than from a repeated literal.
const benchQueueDepth = 1 << 16

func benchObserver(b *testing.B) *planeshadow.Observer {
	b.Helper()
	// THE GUARD THE DOC ABOVE DESCRIBES AND DID NOT HAVE.
	//
	// A deep queue is not enough on its own: `go test -bench .` grows b.N until
	// the benchmark takes benchtime, and nothing tied b.N to the depth. Past
	// it, every Observe takes the `default:` DROP branch, which is cheaper than
	// the send - so the reported ns/op FALLS as the shadow stops working, in
	// the direction that flatters the "no request-path latency" claim these
	// numbers are cited for.
	//
	// Skipping is the right answer rather than growing the queue: a run that
	// needs more iterations than the queue can hold is a run whose numbers
	// would be about backpressure, and a skipped benchmark says so out loud
	// where a quietly-wrong one does not. Half the depth, so the drop branch is
	// never reached even with the pool briefly stalled.
	if b.N > benchQueueDepth/2 {
		b.Skipf("b.N=%d exceeds half the bench queue depth (%d); past the depth every Observe "+
			"takes the cheaper DROP branch and the reported ns/op would FALL as the shadow "+
			"stopped working. Re-run with a smaller -benchtime.", b.N, benchQueueDepth)
	}
	prior := planeshadow.ProcessObserver()
	b.Cleanup(func() { planeshadow.SetProcessObserver(prior) })

	mode := shadowOnMode()
	o, err := planeshadow.NewObserver(
		planeshadow.Config{Mode: mode, SampleRate: 1, QueueDepth: benchQueueDepth, Workers: 4},
		shadowTestRows{}, planeshadow.MetricsRecorder{},
		planeshadow.WithComponent("bench"),
	)
	if err != nil {
		b.Fatalf("building the observer: %v", err)
	}
	b.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = o.Shutdown(ctx)
	})
	return o
}
