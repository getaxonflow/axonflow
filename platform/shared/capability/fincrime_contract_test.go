// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package capability

import (
	"slices"
	"strings"
	"testing"

	"axonflow/platform/shared/capabilityresolution"
)

func TestFinCrimeFamilySeparatesProtocolPackAndScorer(t *testing.T) {
	r := Load()
	protocol := r.ByID(capabilityresolution.FinCrimeProtocolCapabilityID)
	pack := r.ByID(capabilityresolution.FinCrimePolicyPackCapabilityID)
	scorer := r.ByID(capabilityresolution.FinCrimeRiskScoringCapabilityID)
	if protocol == nil || pack == nil || scorer == nil {
		t.Fatalf("FinCrime entries = protocol:%v pack:%v scorer:%v; want all three stable identities",
			protocol != nil, pack != nil, scorer != nil)
	}

	if protocol.MinimumEdition != EditionCommunity || protocol.Classification != ClassCommunityCore ||
		protocol.BuildTag != TagNone || protocol.Sync != SyncMirrored {
		t.Errorf("shared protocol classification = edition %q class %q tag %q sync %q; want Community-visible semantics only",
			protocol.MinimumEdition, protocol.Classification, protocol.BuildTag, protocol.Sync)
	}
	if len(protocol.RefusalReasons) != 0 || len(protocol.Limits) != 0 {
		t.Errorf("shared protocol declares commercial enforcement metadata: reasons=%v limits=%v",
			protocol.RefusalReasons, protocol.Limits)
	}

	for _, entry := range []*Entry{pack, scorer} {
		if entry.MinimumEdition != EditionEnterprise || entry.Classification != ClassEnterpriseImplementation {
			t.Errorf("%s = edition %q class %q; Enterprise artifact must not activate in Community or Evaluation",
				entry.ID, entry.MinimumEdition, entry.Classification)
		}
		if entry.Score.Community != AvailNone || entry.Score.Evaluation != AvailNone || entry.Score.Enterprise != AvailFull {
			t.Errorf("%s score = %s/%s/%s; want none/none/full",
				entry.ID, entry.Score.Community, entry.Score.Evaluation, entry.Score.Enterprise)
		}
		if entry.Health != nil || entry.HealthGap {
			t.Errorf("%s is statically advertised or counted as an edition-blind /health gap; tenant-effective readback is a later Gate 2 surface", entry.ID)
		}
		if !slices.Contains(entry.RefusalReasons, capabilityresolution.ReasonEditionRequired) ||
			!slices.Contains(entry.RefusalReasons, capabilityresolution.ReasonCapabilityNotGranted) {
			t.Errorf("%s refusal reasons = %v; edition and grant legs must remain distinct", entry.ID, entry.RefusalReasons)
		}
	}
	if !slices.Equal(pack.Topologies, []Topology{TopologySelfHosted, TopologyHosted}) {
		t.Errorf("%s topologies = %v, want self_hosted and hosted", pack.ID, pack.Topologies)
	}
	if !slices.Equal(scorer.Topologies, []Topology{TopologySelfHosted}) {
		t.Errorf("%s topologies = %v, want self_hosted only until Hosted v2 tenant-binding proof", scorer.ID, scorer.Topologies)
	}
}

func TestFinCrimeScoringDeclaresDurableQuotaVocabulary(t *testing.T) {
	scorer := Load().ByID(capabilityresolution.FinCrimeRiskScoringCapabilityID)
	if scorer == nil {
		t.Fatal("fincrime.risk_scoring is absent")
	}
	if len(scorer.Limits) != 1 {
		t.Fatalf("scoring limits = %v, want one stable score-request dimension", scorer.Limits)
	}
	limit := scorer.Limits[0]
	if limit.ID != capabilityresolution.FinCrimeScoreRequestsLimitID || limit.Kind != LimitQuota ||
		limit.Unit != "score_request" || limit.Scope != LimitScopeTenant ||
		limit.Window != LimitWindowCalendarMonth {
		t.Errorf("scoring limit = %+v, want tenant calendar-month score-request quota", limit)
	}
	wantReasons := []capabilityresolution.Reason{
		capabilityresolution.ReasonEditionRequired,
		capabilityresolution.ReasonCapabilityNotGranted,
		capabilityresolution.ReasonQuotaExhausted,
		capabilityresolution.ReasonDependencyUnreachable,
	}
	if !slices.Equal(scorer.RefusalReasons, wantReasons) {
		t.Errorf("scoring refusal reasons = %v, want %v", scorer.RefusalReasons, wantReasons)
	}
}

func TestFinCrimeEnterpriseArtifactsDeriveAsMirrorExcludedOrStubbed(t *testing.T) {
	root := repoRoot(t)
	if TreeIsCommunityMirror(root) {
		t.Skip("community mirror: the Enterprise implementation paths this test derives are " +
			"stripped by construction; the enterprise tree and staged-mirror gate prove their exclusion")
	}
	for _, id := range []string{
		capabilityresolution.FinCrimePolicyPackCapabilityID,
		capabilityresolution.FinCrimeRiskScoringCapabilityID,
	} {
		entry := Load().ByID(id)
		tag, sync, found, err := DeriveEditionFacts(root, entry.Implementation)
		if err != nil {
			t.Fatalf("DeriveEditionFacts(%s): %v", id, err)
		}
		if !found {
			t.Fatalf("DeriveEditionFacts(%s) found no implementation; absence would make the mirror-leak check vacuous", id)
		}
		if tag != entry.BuildTag || sync != entry.Sync {
			t.Errorf("%s tree derives tag=%q sync=%q, registry says tag=%q sync=%q",
				id, tag, sync, entry.BuildTag, entry.Sync)
		}
		if sync == SyncMirrored {
			t.Errorf("%s derives as mirrored; an Enterprise artifact would leak to Community", id)
		}
	}
}

func TestModuleContractVocabularyRejectsUnreviewedWidening(t *testing.T) {
	t.Run("unknown topology", func(t *testing.T) {
		err := mutate(t, func(doc map[string]any) {
			capByID(t, doc, "fincrime.risk_scoring")["topologies"] = []any{"self_hosted", "browser"}
		})
		requireProblem(t, err, "an unreviewed deployment topology", "unknown topology")
	})
	t.Run("unknown refusal reason", func(t *testing.T) {
		err := mutate(t, func(doc map[string]any) {
			capByID(t, doc, "fincrime.risk_scoring")["refusal_reasons"] = []any{"edition_required", "fail_open"}
		})
		requireProblem(t, err, "an unreviewed failure posture", "unknown refusal_reason")
	})
	t.Run("quota reason without dimension", func(t *testing.T) {
		err := mutate(t, func(doc map[string]any) {
			delete(capByID(t, doc, "fincrime.risk_scoring"), "limits")
		})
		requireProblem(t, err, "a quota refusal with no countable dimension", "declares no limit dimension")
	})
	t.Run("dimension without quota reason", func(t *testing.T) {
		err := mutate(t, func(doc map[string]any) {
			capByID(t, doc, "fincrime.risk_scoring")["refusal_reasons"] = []any{
				"edition_required", "capability_not_granted", "dependency_unreachable",
			}
		})
		requireProblem(t, err, "a quota with no stable refusal", "but not the stable")
	})
	t.Run("limit identity collides across entries", func(t *testing.T) {
		err := mutate(t, func(doc map[string]any) {
			pack := capByID(t, doc, "fincrime.policy_pack")
			pack["limits"] = []any{map[string]any{
				"id":          "fincrime.score_requests",
				"kind":        "quota",
				"unit":        "score_request",
				"scope":       "tenant",
				"window":      "calendar_month",
				"description": "A mutant reuse of another capability's stable limit identity.",
			}}
			pack["refusal_reasons"] = []any{
				"edition_required", "capability_not_granted", "quota_exhausted", "dependency_unreachable",
			}
		})
		requireProblem(t, err, "two entries reuse one registry-wide limit identity", "duplicate limit id", "entries")
	})
	t.Run("unit is not a lower snake token", func(t *testing.T) {
		err := mutate(t, func(doc map[string]any) {
			limits := capByID(t, doc, "fincrime.risk_scoring")["limits"].([]any)
			limits[0].(map[string]any)["unit"] = "Score Request"
		})
		requireProblem(t, err, "a display label replaces the stable machine unit", "not a lower_snake token")
	})
}

func TestCensusPublishesFinCrimeContractWithoutClaimingDeployment(t *testing.T) {
	doc := RenderCensus(Load(), Narratives{})
	for _, want := range []string{
		"## Declared module contracts",
		"`fincrime.policy_pack`",
		"`fincrime.risk_scoring`",
		"`fincrime.score_requests` (score_request/tenant/calendar_month)",
		"do not grant a capability",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("generated census does not contain %q", want)
		}
	}
}
