// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package orchestrator

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// #3319: DatabaseDynamicPolicyEngine is one engine whose policy set is
// either database-loaded or the built-in default fallback set. These four
// metrics are what makes that distinction observable from outside the
// process — the gap that let a boot-time database blip permanently degrade
// a process (and nothing outside it notice) in the pre-#3319 two-engine
// design. Registered here, in this engine's own init(), following the same
// manual prometheus.NewXxx + prometheus.MustRegister pattern run.go already
// uses for the orchestrator's other metrics (run.go's promXxx vars) rather
// than introducing promauto as a second pattern in this package.
var (
	// policySetSourceGauge backs axonflow_policy_set_source — the single
	// most important signal this file publishes: whether the engine is
	// currently enforcing a database-loaded policy set or only the
	// built-in defaults. Exactly one of the two label values is 1 at any
	// moment (setPolicySetSourceMetric always drives the other to 0 in the
	// same call), so `axonflow_policy_set_source{source="database"} == 0`
	// alone means "this process has never completed a successful load."
	// Label set is the closed two-value enum {"database","defaults"} —
	// never a tenant id, policy id, or anything unbounded.
	policySetSourceGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "axonflow_policy_set_source",
			Help: "Whether the dynamic policy engine is enforcing a database-loaded policy set (source=\"database\") or the built-in default fallback set (source=\"defaults\"). Exactly one label value is 1 at a time. #3319.",
		},
		[]string{"source"},
	)

	// policyCacheAgeSeconds backs axonflow_policy_cache_age_seconds —
	// seconds since the engine's last successful load, 0 before the first
	// one. Alertable on `> N`, the question an operator actually has
	// ("how stale is what's being enforced").
	policyCacheAgeSeconds = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "axonflow_policy_cache_age_seconds",
			Help: "Seconds since the dynamic policy engine's last successful database load. 0 before the first successful load. #3319.",
		},
	)

	// policyRefreshFailuresTotal backs axonflow_policy_refresh_failures_total
	// — loads that failed and left the policy set unchanged (per #3319 item
	// B, a failed refresh is always a no-op, never a downgrade). reason is
	// one of the reason* constants below: a closed, low-cardinality set,
	// never a raw error string, tenant id, or policy id — mirroring
	// promPolicyConditionUnevaluableTotal's reason contract (run.go).
	policyRefreshFailuresTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "axonflow_policy_refresh_failures_total",
			Help: "Count of dynamic policy loads that failed and left the last-good policy set in place (never a downgrade to defaults), labeled by reason. #3319.",
		},
		[]string{"reason"},
	)

	// policyZeroRowLoadsTotal is this file's answer to the #3039 class
	// named in #3319: a load that SUCCEEDED but returned zero rows must be
	// distinguishable from a load that failed. It is deliberately its own
	// counter rather than a policyRefreshFailuresTotal reason label — the
	// load did not fail, and counting it as a failure would make "this
	// deployment genuinely has zero policies configured" indistinguishable
	// from an actual query error. A sustained nonzero rate here on a
	// deployment known to have policies configured is the same symptom
	// #3039 named for an all-tenants read on the app-role pool with no org
	// GUC: the query succeeds and enforces nothing. No labels — a single
	// process-wide time series is all this needs, and adding one would
	// only invite a high-cardinality value (e.g. a table/tenant name)
	// creeping in later.
	policyZeroRowLoadsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "axonflow_policy_zero_row_loads_total",
			Help: "Count of dynamic policy loads that succeeded but returned zero rows, distinguishing a genuinely empty policy set from a failed load. A nonzero rate on a deployment known to have policies configured may indicate an RLS-blind read (#3039 class).",
		},
	)
)

// reason* values for policyRefreshFailuresTotal's "reason" label — a closed
// set matched exhaustively at every recordPolicyRefreshFailure call site in
// db_dynamic_policies.go, never a formatted error string.
const (
	// reasonDatabaseNotConfigured: DATABASE_URL was never set — the engine
	// has no DSN to even attempt a connection with. Distinct from
	// reasonDatabaseUnreachable so an operator can tell "nobody configured
	// a database for this deployment" (possibly intentional, community
	// mode) apart from "a database is configured but not answering."
	reasonDatabaseNotConfigured = "database_not_configured"
	// reasonDatabaseUnreachable: DATABASE_URL is set, but connectDB's
	// (re)connect attempt failed — network partition, credentials, or the
	// database process itself being down.
	reasonDatabaseUnreachable = "database_unreachable"
	// reasonQueryFailed: the refresh SELECT itself failed (including the
	// segment-less retry) against an otherwise-reachable connection.
	reasonQueryFailed = "query_failed"
	// reasonRowIterationFailed: rows.Err() after a successful Query — a
	// failure surfaced mid-stream rather than at the initial query.
	reasonRowIterationFailed = "row_iteration_failed"
	// reasonZeroRowRLSBlind (#3322 item 3): the query itself returned zero
	// rows with no error, but on a pool this engine knows is RLS-scoped
	// with no dedicated BYPASSRLS admin pool backing it
	// (refreshPoolIsRLSScoped) — the exact #3039 shape (a missing org GUC
	// makes org_id = NULL match nothing). Counted as a refresh FAILURE
	// (not axonflow_policy_zero_row_loads_total, which is reserved for a
	// zero-row result this engine actually trusts) because the promotion
	// is refused: the last-good policy set is kept instead.
	reasonZeroRowRLSBlind = "zero_row_rls_blind"
)

func init() {
	prometheus.MustRegister(policySetSourceGauge)
	prometheus.MustRegister(policyCacheAgeSeconds)
	prometheus.MustRegister(policyRefreshFailuresTotal)
	prometheus.MustRegister(policyZeroRowLoadsTotal)
}

// setPolicySetSourceMetric publishes source as the current value of
// axonflow_policy_set_source, driving the OTHER label value to 0 in the
// same call so a scrape can never observe both (or neither) label at 1.
// source is normally one of policySetSourceDefaults/policySetSourceDatabase
// (db_dynamic_policies.go); any other value is treated as "defaults" —
// fail toward the more visible, more conservative signal rather than a
// silently-unlabeled series.
func setPolicySetSourceMetric(source string) {
	if source == policySetSourceDatabase {
		policySetSourceGauge.WithLabelValues(policySourceLabelDatabase).Set(1)
		policySetSourceGauge.WithLabelValues(policySourceLabelDefaults).Set(0)
		return
	}
	policySetSourceGauge.WithLabelValues(policySourceLabelDefaults).Set(1)
	policySetSourceGauge.WithLabelValues(policySourceLabelDatabase).Set(0)
}

// policySourceLabel{Database,Defaults} are the label VALUES for
// axonflow_policy_set_source's "source" dimension — kept as named
// constants (rather than inlining "database"/"defaults" at each call site)
// purely so setPolicySetSourceMetric and its test cannot typo one half of
// the pair out of sync with the other.
const (
	policySourceLabelDatabase = policySetSourceDatabase
	policySourceLabelDefaults = policySetSourceDefaults
)

// setPolicyCacheAgeSeconds publishes age as axonflow_policy_cache_age_seconds.
func setPolicyCacheAgeSeconds(age time.Duration) {
	policyCacheAgeSeconds.Set(age.Seconds())
}

// recordPolicyRefreshFailure increments axonflow_policy_refresh_failures_total
// for reason (one of the reason* constants above).
func recordPolicyRefreshFailure(reason string) {
	policyRefreshFailuresTotal.WithLabelValues(reason).Inc()
}

// recordPolicyZeroRowLoad increments axonflow_policy_zero_row_loads_total.
func recordPolicyZeroRowLoad() {
	policyZeroRowLoadsTotal.Inc()
}
