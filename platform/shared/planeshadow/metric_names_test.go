package planeshadow

import "testing"

// TestShadowMetricNamesAreStable pins the exported metric names as LITERALS.
//
// This is the planeshadow counterpart of the identity axis's
// TestCompatMetricNamesAreStable, and it exists for the same reason:
// platform/monitoring/rules/decision-shadow.rules.yml, its promtool suite and
// the runtime-e2e greps all match on these strings, and none of them is a Go
// reference — so a rename compiles, every Go test that uses the constant stays
// green, and the recording rules silently match nothing, which is the same
// failure mode as having no rules at all. Before this test existed that was
// measured, not hypothesised: renaming two of these constants left
// `go test ./shared/planeshadow/` fully green, and the only thing that caught
// it was a 13-minute stack-booting runtime-e2e suite. This is the 0.7-second
// version of that catch.
//
// If this test is failing you are renaming a wire-visible metric: update the
// rules file, its promtool suite, the runtime-e2e greps and the CHANGELOG in
// the same commit, then update the literal here.
func TestShadowMetricNamesAreStable(t *testing.T) {
	for got, want := range map[string]string{
		MetricShadowObservations: "axonflow_decision_shadow_observations_total",
		MetricShadowComparisons:  "axonflow_decision_shadow_comparisons_total",
		MetricShadowFailOpen:     "axonflow_decision_shadow_fail_open_total",
		MetricShadowMode:         "axonflow_decision_shadow_mode",
	} {
		if got != want {
			t.Errorf("metric name %q, want %q — the Prometheus rules match on the literal, not the constant", got, want)
		}
	}
}
