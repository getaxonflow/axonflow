// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package authoringedition is the ONE place a process resolves which authoring
// boundary its deployment is entitled to (#3956).
//
// # THE DEFECT THIS PACKAGE EXISTS TO END
//
// license.ReadCurrentTier reads AXONFLOW_LICENSE_KEY from the environment of
// the CALLING PROCESS, and an absent key resolves to TierCommunity. That fold
// is correct and deliberate. What it cannot do is tell "this deployment is
// Community" apart from "this process was never given the variable", because
// both look identical from inside the process: an empty string.
//
// On 2026-09-09 that difference became a security boundary. #3943 made
// separation of duties edition-conditional - correctly, because PRD 5.3 rules
// it None/None/Full and the unconditional rule was what stopped a single-admin
// Community deployment publishing at all. The same afternoon, the
// customer-portal's compose service and its CloudFormation task definition
// enumerated their environment and neither listed AXONFLOW_LICENSE_KEY. So on
// an Enterprise deployment the portal read Community, and the two-person rule
// it had enforced that morning was off by lunchtime: one author could publish
// a policy and activate it alone.
//
// TWO SURFACES RESOLVE AN AUTHORING EDITION - the portal and, since #3943, the
// orchestrator route - and each carried its own two-line copy of the read.
// Same code, two processes, one of them missing its input. A third surface
// would have carried a third copy. This package is that read, once.
//
// # WHAT IT ADDS OVER THE LICENCE READ
//
// The licence read answers "what tier does this process hold". This package
// answers the question a boundary actually needs, which is one step back:
// "could this process establish what tier the DEPLOYMENT holds at all". The
// answer is three-valued where the licence read is two-valued, and the third
// value is the one that was missing.
//
// See Resolve for the three signals and Establishment for what is deliberately
// NOT decidable here.
package authoringedition

import (
	"context"
	"log"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"axonflow/platform/agent/license"
	"axonflow/platform/decision/authoring"
	"axonflow/platform/shared/deploymode"
)

// EnvLicenseKey is the variable license.ReadCurrentTier reads, named here so a
// refusal message and a deployment guard can cite the same string this package
// depends on rather than a second spelling of it.
const EnvLicenseKey = "AXONFLOW_LICENSE_KEY"

// Establishment is why Resolve reached the answer it did.
//
// It is reported rather than folded into the Profile because the two
// unestablished causes have DIFFERENT operator remedies - re-issue a licence,
// versus plumb a variable into a container - and a single boolean would make
// the log line say only that something was wrong.
type Establishment string

const (
	// EstablishedByKey: a licence key was present and verified. The tier is
	// this deployment's tier, stated by a signature.
	EstablishedByKey Establishment = "established_by_key"
	// EstablishedByMode: no licence key, and the deployment mode is not one
	// that is entitled to Enterprise. This is a genuine Community or
	// Evaluation deployment saying so, and it is the case #3907 exists to
	// serve: a sole administrator publishes here, and must keep being able to.
	EstablishedByMode Establishment = "established_by_mode"
	// UnestablishedKeyRejected: a licence key was present and did NOT verify -
	// forged, malformed, or past its expiry. The deployment believes it holds
	// a tier; this process cannot confirm which. Remedy: re-issue the licence.
	UnestablishedKeyRejected Establishment = "unestablished_key_rejected"
	// UnestablishedKeyAbsent: no licence key reached this process, and the
	// deployment mode says this deployment IS entitled to Enterprise. Those
	// two cannot both be true of a correctly configured deployment. Remedy:
	// give this process AXONFLOW_LICENSE_KEY. This is the portal defect.
	UnestablishedKeyAbsent Establishment = "unestablished_key_absent"
	// EstablishedByTransition: no licence key, the deployment mode is not
	// entitled to Enterprise, AND the operator has DECLARED a licence
	// transition (deploymode.EnvLicenceTransition). The deployment held a
	// licence, it has ended, and the operator is deliberately keeping the
	// enforcement plane serving rather than letting it crash-loop.
	//
	// # THIS MEMBER IS ESTABLISHED, AND THAT IS A RULING RATHER THAN AN OMISSION
	//
	// Established below is written as an explicit set so that a new member is
	// UNESTABLISHED until somebody rules on it. This is that ruling, and the
	// reason is what the alternative would do: an unestablished outcome carries
	// ProfileForUnestablishedTier, whose duty rule requires a SECOND APPROVER.
	// Turning the two-person rule ON for an operator whose licence has just
	// lapsed would add a new obstacle during the wind-down that
	// LicenceTransitionMode exists to make survivable - a control arriving
	// exactly when the deployment has least ability to satisfy it.
	//
	// So the profile a transition resolves to is the one it resolves to today:
	// Community constructs, no second approver, unchanged behaviour at every
	// authoring surface. What the member adds is the ability of ONE consumer to
	// ask a question it cannot ask today - see EnforcesConstructBoundary.
	EstablishedByTransition Establishment = "established_by_transition"
)

// Established reports whether e is one of the two established outcomes.
//
// Written as an explicit two-member set rather than as "not one of the
// unestablished ones", so a fourth Establishment added later is UNestablished
// until somebody rules on it. The permissive direction has to be asked for by
// name; that is the same burden-of-proof inversion deploymode.IsCommunityPosture
// applies to the Community posture, for the same reason.
func (e Establishment) Established() bool {
	return e == EstablishedByKey || e == EstablishedByMode || e == EstablishedByTransition
}

// InTransition reports whether the deployment DECLARED that its licence has
// ended and it is being kept serving.
//
// It is a separate question from Established, and the separation is the point.
// A transition IS established - the deployment told this process what it is,
// and the authoring boundary it resolves to is unchanged. What a transition is
// not is a deployment whose posture can be read as a statement about what it is
// ENTITLED to author: it held a licence, and the documents it published under
// that licence are still active. A control that refuses such a document has to
// be able to ask this question, and only this question, rather than widening
// Established and changing the duty rule as a side effect.
func (e Establishment) InTransition() bool { return e == EstablishedByTransition }

// Resolution is one answer, with the evidence that produced it.
type Resolution struct {
	// Profile is the boundary to enforce. It is what a surface hands to
	// authoring.NewAPI, and it already carries the asymmetry: the CONSTRUCT
	// set folds an unestablished tier to Community, and the DUTY rule does not.
	Profile authoring.Profile
	// Establishment is why. See the constants.
	Establishment Establishment
	// Tier is the tier name the licence read produced, for a log line. It is
	// "Community" for every unestablished outcome and must not be read as an
	// entitlement in that case - which is exactly the misreading this package
	// exists to stop, so it is not used to build the Profile above.
	Tier string
}

// unresolvedTierObserved counts resolutions that could NOT establish the
// deployment's tier, by cause.
//
// It is a counter rather than a gauge because the read is per publication, not
// per process: a portal that has been misconfigured for a week shows a rising
// series, and one that was fixed shows a flat one, which a gauge sampled after
// a restart could not distinguish.
var unresolvedTierObserved = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "axonflow_authoring_tier_unestablished_total",
	Help: "Authoring edition resolutions that could not establish the deployment's licensed tier, by cause. " +
		"A non-zero unestablished_key_absent series means this process is authoring policy without ever " +
		"having seen " + EnvLicenseKey + ", on a deployment whose DEPLOYMENT_MODE says it is entitled to Enterprise.",
}, []string{"cause"})

// UnestablishedCollectorForTest exposes the counter so a test can assert the
// series is written, rather than asserting that a log line was formatted.
// Intended for use in tests only.
func UnestablishedCollectorForTest() prometheus.Collector { return unresolvedTierObserved }

// loggedCauses bounds the log to one line per distinct cause for the life of
// the process. The label set is the Establishment constants above, so it is
// bounded by that closed vocabulary rather than by anything a caller supplies.
var loggedCauses sync.Map

// Resolve returns the authoring boundary this process's deployment is entitled
// to, and why.
//
// # THE THREE SIGNALS, AND WHY IT TAKES ALL THREE
//
//	licence key present and VERIFIED        -> established, at its tier
//	licence key present and REJECTED        -> UNESTABLISHED (forged/expired)
//	licence key ABSENT, mode not entitled   -> established, Community
//	licence key ABSENT, mode IS entitled    -> UNESTABLISHED (never plumbed)
//
// The last two rows are the whole point, and neither signal alone separates
// them. The licence read cannot: an absent key is an empty string either way.
// DEPLOYMENT_MODE cannot either, and must never be allowed to try - it is
// configuration, it is not signed, and ee/platform/agent/license/tier_limits.go
// states the standing rule that mode "may narrow what a build registers, it
// never grants a limit". Nothing here grants anything from the mode: an
// entitled mode only ever ADDS the requirement for a second approver, and the
// construct set of an unestablished tier is Community exactly as before.
//
// # WHAT THIS DELIBERATELY CANNOT SEE
//
// A process with NO licence key and NO DEPLOYMENT_MODE at all resolves as an
// established Community deployment. deploymode.Resolve maps unset onto
// `community`, which is not enterprise-entitled, so the disagreement this
// function keys on does not exist there - there is nothing to disagree with.
// That is the honest answer rather than a hole papered over: with neither
// signal present the deployment has told this process nothing, and inventing a
// duty rule from an absence would refuse every sole administrator who simply
// runs the published image without setting either variable. The population
// this misses is a deployment that is entitled to Enterprise AND declares no
// mode, which every shipped compose file, the marketplace template and the
// community-SaaS template all set. It is named here rather than left for a
// reader to discover, because a limit nobody wrote down reads as coverage.
func Resolve(ctx context.Context) Resolution {
	return resolve(
		license.ReadCurrentTier(ctx),
		deploymode.CurrentIsEnterpriseEntitled(),
		deploymode.CurrentIsLicenceTransition(),
	)
}

// EnforcesConstructBoundary reports whether a control may refuse an ALREADY
// ACTIVE document for spending a construct outside this deployment's edition.
//
// It is deliberately narrower than Established, and it is the only place the
// two differ. An unestablished process does not know what the deployment is
// entitled to, so it must not refuse; a deployment in a declared licence
// transition knows exactly what it was entitled to, and refusing there would
// take a wind-down the operator is managing and turn it into an outage - an
// activation refusal at the enforcement seam is HTTP 503 on /api/v1/decide and
// a withheld MCP response, not a message to an author.
//
// Both remaining cases are ones where a document outside the edition could only
// have arrived through a door this boundary exists to close: an importer that
// supplied its own edition, or a row written straight into the store.
func (r Resolution) EnforcesConstructBoundary() bool {
	return r.Establishment.Established() && !r.Establishment.InTransition()
}

// resolve is Resolve with every signal as a parameter, so each of the five
// rows above can be driven without a process environment.
func resolve(read license.TierRead, modeIsEnterpriseEntitled, inLicenceTransition bool) Resolution {
	tier := string(read.Tier)
	cause := establishmentFor(read, modeIsEnterpriseEntitled, inLicenceTransition)
	if !cause.Established() {
		observeUnestablished(cause, read.Reason)
		return Resolution{
			Profile:       authoring.ProfileForUnestablishedTier(),
			Establishment: cause,
			Tier:          tier,
		}
	}
	// ProfileFor refuses only an edition outside the declared three, and
	// EditionFor cannot produce one - its default arm is Community. The error
	// is therefore unreachable, and it is handled rather than dropped because
	// "unreachable" is a claim about EditionFor that this function would
	// otherwise be silently relying on: if a fourth edition ever arrives
	// without a rank, this lands on the unestablished profile, which is the
	// fail-closed side of the asymmetry.
	profile, err := authoring.ProfileFor(authoring.EditionFor(tier))
	if err != nil {
		observeUnestablished(UnestablishedKeyRejected, err.Error())
		return Resolution{
			Profile:       authoring.ProfileForUnestablishedTier(),
			Establishment: UnestablishedKeyRejected,
			Tier:          tier,
		}
	}
	return Resolution{Profile: profile, Establishment: cause, Tier: tier}
}

// establishmentFor is the four-row table above, and nothing else. It is its own
// function so the table can be driven directly, without a Profile in the way.
func establishmentFor(read license.TierRead, modeIsEnterpriseEntitled, inLicenceTransition bool) Establishment {
	switch {
	case read.Rejected:
		return UnestablishedKeyRejected
	case read.KeyPresent:
		return EstablishedByKey
	case modeIsEnterpriseEntitled:
		return UnestablishedKeyAbsent
	case inLicenceTransition:
		// ORDER: after the three rows above, and the position is load bearing.
		//
		// A declaration is not evidence about a licence, so it must never
		// displace one. A key that VERIFIES states the tier (row 2), and a key
		// that does not (row 1) is a question for the operator either way -
		// answering "transition" there would let a forged key be laundered into
		// a softer boundary by setting one environment variable. Row 3 is the
		// portal defect and stays a defect: a deployment whose mode says it is
		// entitled to Enterprise has not ended anything.
		//
		// What is left is exactly the row this member is for: no key at all, a
		// mode that claims nothing, and an operator saying why.
		return EstablishedByTransition
	default:
		return EstablishedByMode
	}
}

func observeUnestablished(cause Establishment, reason string) {
	unresolvedTierObserved.WithLabelValues(string(cause)).Inc()
	if _, seen := loggedCauses.LoadOrStore(cause, struct{}{}); seen {
		return
	}
	switch cause {
	case UnestablishedKeyAbsent:
		log.Printf("[authoring] %s never reached this process and DEPLOYMENT_MODE=%q is entitled to Enterprise, "+
			"so this process CANNOT establish the deployment's licensed tier. Authoring runs on the Community "+
			"CONSTRUCT set and REQUIRES a second approver, which is the fail-closed direction for a duty rule. "+
			"Give this container %s to restore the Enterprise construct set.",
			EnvLicenseKey, deploymode.Current(), EnvLicenseKey)
	default:
		log.Printf("[authoring] the licence key in this process did not verify (%s), so this process cannot "+
			"establish the deployment's licensed tier. Authoring runs on the Community CONSTRUCT set and "+
			"REQUIRES a second approver. Re-issue the licence to restore the Enterprise construct set.", reason)
	}
}
