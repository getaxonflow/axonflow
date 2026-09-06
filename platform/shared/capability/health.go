// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package capability

import "sort"

// The two planes that serve /health. The agent listens on 8080 and the
// orchestrator on 8081; a client probes whichever it can reach.
const (
	PlaneAgent        = "agent"
	PlaneOrchestrator = "orchestrator"
)

// Advertised is one entry of the /health capability list.
//
// It is the wire shape both planes already served, reproduced here so the
// projection has a type of its own: the plane packages keep their own
// PlatformCapability structs for JSON encoding, and converting at the boundary
// is what stops this package from having to know about either plane.
type Advertised struct {
	Name        string
	Since       string
	Description string
}

// Health returns the capability list for a plane, in served order.
//
// This is the whole point of the registry as far as #3618 is concerned. The
// list used to be a hand-maintained Go literal beside each plane's handler,
// and a hand-maintained list is a census bounded by whoever last remembered to
// edit it: four releases shipped without one. Projecting it from the registry
// does not, by itself, make anyone remember either — what makes the omission
// visible is that the registry's route derivation fails when a registered
// route has no entry, so the reminder arrives at the capability that was
// forgotten rather than at the list that forgot it.
func Advertise(plane string) []Advertised {
	return registry.Advertise(plane)
}

// Advertise is the projection for an arbitrary registry, so a test can project a
// document it built itself.
func (r *Registry) Advertise(plane string) []Advertised {
	type ordered struct {
		order int
		adv   Advertised
	}
	var rows []ordered
	for _, e := range r.Entries {
		if e.Health == nil {
			continue
		}
		if !contains(e.Health.Planes, plane) {
			continue
		}
		desc := e.Health.Description
		if over, ok := e.Health.DescriptionOverrides[plane]; ok {
			desc = over
		}
		rows = append(rows, ordered{
			order: e.Health.Order,
			adv: Advertised{
				Name:        e.Health.Name,
				Since:       e.Health.Since,
				Description: desc,
			},
		})
	}
	// Validate has already proven Order is total within a plane, so this sort
	// is deterministic without a tiebreak. The tiebreak is here regardless:
	// this function runs in a shipped binary, where the only thing standing
	// between a duplicate order and a non-deterministic /health response would
	// otherwise be a test that ran somewhere else.
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].order != rows[j].order {
			return rows[i].order < rows[j].order
		}
		return rows[i].adv.Name < rows[j].adv.Name
	})
	out := make([]Advertised, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.adv)
	}
	return out
}

func contains(hay []string, needle string) bool {
	for _, v := range hay {
		if v == needle {
			return true
		}
	}
	return false
}
