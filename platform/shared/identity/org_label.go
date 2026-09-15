// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"strings"
	"sync"
)

// maxOrgLabelValues caps how many distinct organizations get their own series
// on a per-organization metric label.
//
// # WHY THERE IS A CAP AT ALL
//
// An uncapped org label would be unbounded BY CONSTRUCTION on this fleet: the
// community-SaaS register endpoint mints a fresh organization on every call,
// so the hourly canary alone adds ~8,760 organizations a year, and a load
// generator adds them as fast as it can POST. An unbounded label on a counter
// incremented on a request path is a memory lever on the scrape target and an
// outage in the monitoring stack - which is a strictly worse failure than the
// one a per-organization breakdown exists to prevent.
//
// So the axis exists, bounded. The first maxOrgLabelValues organizations seen
// by a process each get a series; every later one is counted under
// labelOverflowOrg, which is itself a reading: a non-zero overflow bucket says
// "this deployment has more organizations than the per-org view can name".
//
// # WHERE THIS AXIS IS USEFUL, AND WHERE IT IS NOT - SAID PLAINLY
//
// On production-us and on any single-tenant or handful-of-tenants deployment,
// every tenant that matters is named and stays named. On community-SaaS the
// same property that forces the cap - a fresh organization per register call -
// fills the 100 slots within hours, after which every later tenant lands in
// labelOverflowOrg and the per-org view says little beyond "there are many".
// That is a real limit of this axis on that stack, not a bug to be tuned away:
// raising the cap moves the hour it fills, and removing it takes the scrape
// target down.
const maxOrgLabelValues = 100

// labelOverflowOrg is the bucket every organization past the cap is counted
// under. It is deliberately not a truncation or a hash of the real value:
// either would look like a name and be unusable as one.
const labelOverflowOrg = "__over_cap__"

// labelUnattributedOrg is the bucket for a record carrying no organization. It
// is distinct from the overflow bucket because they mean different things: one
// is "we stopped naming organizations", the other is "this event had no
// organization to name", which on an organization-scoped path is a defect worth
// seeing.
const labelUnattributedOrg = "__none__"

// orgLabelState bounds the per-organization label to maxOrgLabelValues
// distinct values per process.
//
// An RWMutex, not a Mutex: this is consulted on a request path for every
// counted event, and after the first sighting of an organization the answer
// is a read. On a stack with a handful of tenants the write path is taken a
// handful of times in the process's whole life, and every subsequent request
// takes a shared lock instead of contending on an exclusive one.
var orgLabelState struct {
	mu   sync.RWMutex
	seen map[string]bool
}

// orgLabel returns the label value for an organization, admitting it to the
// bounded set if there is room.
//
// The set is FIRST-COME and never evicted. Eviction would be worse than the
// cap: an organization that lost its slot would have its series stop moving
// while its traffic continued, which reads on a dashboard exactly like a path
// that went silent.
func orgLabel(orgID string) string {
	orgID = strings.TrimSpace(orgID)
	if orgID == "" {
		return labelUnattributedOrg
	}
	// The steady-state path: a shared lock and a map read.
	orgLabelState.mu.RLock()
	admitted, full := orgLabelState.seen[orgID], len(orgLabelState.seen) >= maxOrgLabelValues
	orgLabelState.mu.RUnlock()
	if admitted {
		return orgID
	}
	if full {
		return labelOverflowOrg
	}

	orgLabelState.mu.Lock()
	defer orgLabelState.mu.Unlock()
	if orgLabelState.seen == nil {
		orgLabelState.seen = make(map[string]bool, maxOrgLabelValues)
	}
	// RE-CHECKED under the exclusive lock. Between the read and the write
	// another goroutine may have admitted this organization, or filled the last
	// slot; acting on the stale read would admit one past the cap, which is the
	// one thing this function exists to prevent.
	if orgLabelState.seen[orgID] {
		return orgID
	}
	if len(orgLabelState.seen) >= maxOrgLabelValues {
		return labelOverflowOrg
	}
	orgLabelState.seen[orgID] = true
	return orgID
}

// BoundedOrgLabel is orgLabel, exported, for the decision-proof refusal
// counters (#3614): a per-organization metric reuses this capped scheme rather
// than adding a raw label, because two implementations of one cap are two
// things that must not disagree.
//
// One admission set, shared across every per-organization metric in the
// process, is also the only reading of the cap that BOUNDS THE PROCESS rather
// than each metric separately: N metrics each with their own 100-slot set is a
// 100N-organization memory lever on the scrape target, which is what the cap
// exists to prevent.
func BoundedOrgLabel(orgID string) string { return orgLabel(orgID) }

// MaxOrgLabelValues is maxOrgLabelValues, exported so a consumer's Help text
// can state the cap it is subject to. Stating the number is not cosmetic: an
// operator reading a per-organization panel that has silently folded every
// tenant past the hundredth into one bucket needs to know that from the metric
// itself, not from a runbook it has not opened.
const MaxOrgLabelValues = maxOrgLabelValues
