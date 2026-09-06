// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"fmt"
	"sort"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// EnforcePrecondition is the answer to "may this organization be moved to
// enforce", with the reason attached either way.
//
// It is a VALUE rather than a bare bool because every refusal is audited and
// the audit needs the reason, not the verdict. A caller that logged only
// "denied" would leave an operator unable to tell "this org has never been
// measured" from "this org is measured and still diverging", which are
// opposite problems with opposite remedies.
type EnforcePrecondition struct {
	// OK reports whether every precondition holds.
	OK bool
	// Reason is a short, stable code for the audit log. Empty when OK.
	Reason string
	// Detail is the operator-facing sentence. Empty when OK.
	Detail string
	// Denominator is the organic comparison count that was read.
	Denominator float64
	// Divergences is the unexplained divergence count that was read.
	Divergences float64
}

// Enforce-precondition reason codes. Stable strings: they are audited, and an
// operator greps them.
const (
	EnforceReasonNotMeasured     = "org_not_measured"
	EnforceReasonDiverging       = "org_still_diverging"
	EnforceReasonNotInShadow     = "org_not_in_shadow"
	EnforceReasonNoReasonSet     = "enforce_reasons_unset"
	EnforceReasonUnnamedOrgLabel = "org_label_not_addressable"
)

// EvaluateEnforcePrecondition reports whether orgID may be moved to enforce.
//
// THE THREE READS, AND WHY EACH IS SHAPED THE WAY IT IS.
//
//  1. THE DENOMINATOR IS THE PROOF THE ORGANIZATION WAS MEASURED, and it is
//     read with synthetic="false". LegacyAuth.Synthetic is a LABEL rather than
//     a filter precisely so a canary's comparisons count towards COVERAGE
//     while staying excludable from a VOLUME floor (compat.go's note on the
//     one-direction invariant). This is a volume floor: a canary exists to
//     give the window a denominator, so letting it satisfy the denominator
//     would let the probe unlock enforcement for traffic nobody has served.
//
//  2. AN ABSENT DIVERGENCE SERIES IS ZERO ONLY WHEN THE DENOMINATOR IS
//     NON-ZERO. A CounterVec with no children exports no series at all, so
//     "no divergence series for this org" is equally consistent with "nothing
//     diverged" and "nothing ran". Ordering the reads so the denominator is
//     established FIRST is what makes the second read meaningful; reversed,
//     an unmeasured organization would look perfectly clean.
//
//  3. THE OVERFLOW AND UNATTRIBUTED BUCKETS NEVER SATISFY THE GATE. Those
//     labels are shared by every organization past the cap and by every record
//     with no organization at all, so a reading taken from them is a statement
//     about a crowd. An organization that lands in one is not refused because
//     it is dirty - it is refused because this axis cannot address it, and the
//     reason says so.
//
// The mode and the reason-set are checked by the caller, which holds them;
// this function owns only the observed half.
func EvaluateEnforcePrecondition(component, orgID string) EnforcePrecondition {
	label := orgLabel(orgID)
	if label == labelOverflowOrg || label == labelUnattributedOrg {
		return EnforcePrecondition{
			Reason: EnforceReasonUnnamedOrgLabel,
			Detail: fmt.Sprintf(
				"this organization is counted under %q on %s rather than under its own label, so its comparison "+
					"volume cannot be read separately from every other organization in that bucket; enforcement "+
					"cannot be granted from a reading that is not about this organization alone",
				label, MetricCompatOrgComparisons),
		}
	}

	denom := sumCounter(compatOrgComparisons, map[string]string{
		"component": component, "org": label, "synthetic": "false",
	})
	if denom <= 0 {
		return EnforcePrecondition{
			Reason: EnforceReasonNotMeasured,
			Detail: fmt.Sprintf(
				"%s{org=%q,synthetic=\"false\"} is zero: this organization has no organic comparisons on this "+
					"component, so there is no shadow window behind the request. A canary's comparisons are "+
					"deliberately not counted here - they exist to give the window a denominator, and letting "+
					"them satisfy it would unlock enforcement for traffic nobody has served",
				MetricCompatOrgComparisons, label),
			Denominator: denom,
		}
	}

	classes := counterChildren(compatOrgDivergences, map[string]string{
		"component": component, "org": label,
	})
	var total float64
	seen := make([]string, 0, len(classes))
	for class, v := range classes {
		total += v
		seen = append(seen, fmt.Sprintf("%s=%.0f", class, v))
	}
	if total > 0 {
		sort.Strings(seen)
		return EnforcePrecondition{
			Reason: EnforceReasonDiverging,
			Detail: fmt.Sprintf(
				"this organization is still diverging over %.0f organic comparison(s): %s. Enforcement would "+
					"refuse exactly this traffic. Drive the classes to zero in shadow, then re-request",
				denom, strings.Join(seen, " ")),
			Denominator: denom,
			Divergences: total,
		}
	}
	return EnforcePrecondition{OK: true, Denominator: denom}
}

// sumCounter sums every child of c whose labels match every pair in want.
func sumCounter(c *prometheus.CounterVec, want map[string]string) float64 {
	var total float64
	for _, m := range collect(c) {
		if labelsMatch(m, want) {
			total += m.GetCounter().GetValue()
		}
	}
	return total
}

// counterChildren returns divergence-class -> value for children matching want.
func counterChildren(c *prometheus.CounterVec, want map[string]string) map[string]float64 {
	out := map[string]float64{}
	for _, m := range collect(c) {
		if !labelsMatch(m, want) {
			continue
		}
		for _, lp := range m.GetLabel() {
			if lp.GetName() == "divergence" {
				out[lp.GetValue()] += m.GetCounter().GetValue()
			}
		}
	}
	return out
}

func collect(c prometheus.Collector) []*dto.Metric {
	ch := make(chan prometheus.Metric, 1024)
	go func() { c.Collect(ch); close(ch) }()
	var out []*dto.Metric
	for m := range ch {
		d := &dto.Metric{}
		if err := m.Write(d); err == nil {
			out = append(out, d)
		}
	}
	return out
}

func labelsMatch(m *dto.Metric, want map[string]string) bool {
	got := make(map[string]string, len(m.GetLabel()))
	for _, lp := range m.GetLabel() {
		got[lp.GetName()] = lp.GetValue()
	}
	for k, v := range want {
		if got[k] != v {
			return false
		}
	}
	return true
}
