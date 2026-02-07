// Copyright 2025 AxonFlow
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
	"sync"
	"time"
)

// MetricsCollector collects and aggregates metrics for the orchestrator
type MetricsCollector struct {
	metrics *Metrics
	mu      sync.RWMutex
}

// Metrics represents collected metrics
type Metrics struct {
	RequestMetrics    map[string]*RequestTypeMetrics `json:"request_metrics"`
	ProviderMetrics   map[string]*ProviderMetrics    `json:"provider_metrics"`
	PolicyMetrics     *PolicyMetrics                 `json:"policy_metrics"`
	SystemMetrics     *SystemMetrics                 `json:"system_metrics"`
	LastResetTime     time.Time                      `json:"last_reset_time"`
	CollectionStarted time.Time                      `json:"collection_started"`
}

// RequestTypeMetrics tracks metrics per request type
type RequestTypeMetrics struct {
	TotalRequests   int64         `json:"total_requests"`
	SuccessCount    int64         `json:"success_count"`
	BlockedCount    int64         `json:"blocked_count"`
	ErrorCount      int64         `json:"error_count"`
	AvgResponseTime time.Duration `json:"avg_response_time_ms"`
	P95ResponseTime time.Duration `json:"p95_response_time_ms"`
	P99ResponseTime time.Duration `json:"p99_response_time_ms"`
	responseTimes   []time.Duration
}

// ProviderMetrics tracks metrics per LLM provider
type ProviderMetrics struct {
	RequestCount    int64   `json:"request_count"`
	SuccessCount    int64   `json:"success_count"`
	ErrorCount      int64   `json:"error_count"`
	TotalTokens     int64   `json:"total_tokens"`
	TotalCost       float64 `json:"total_cost"`
	AvgResponseTime float64 `json:"avg_response_time_ms"`
	Availability    float64 `json:"availability_percentage"`
}

// PolicyMetrics tracks policy enforcement metrics
type PolicyMetrics struct {
	TotalEvaluations     int64                       `json:"total_evaluations"`
	BlockedByPolicy      int64                       `json:"blocked_by_policy"`
	RedactionCount       int64                       `json:"redaction_count"`
	PolicyHitRate        map[string]int64            `json:"policy_hit_rate"`
	AvgEvaluationTime    time.Duration               `json:"avg_evaluation_time_ms"`
	RiskScoreDistribution map[string]int64           `json:"risk_score_distribution"`
}

// SystemMetrics tracks system-level metrics
type SystemMetrics struct {
	UptimeSeconds      int64     `json:"uptime_seconds"`
	TotalRequests      int64     `json:"total_requests"`
	ActiveConnections  int64     `json:"active_connections"`
	QueueDepth         int64     `json:"queue_depth"`
	LastHealthCheck    time.Time `json:"last_health_check"`
	HealthCheckPassed  bool      `json:"health_check_passed"`
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector() *MetricsCollector {
	collector := &MetricsCollector{
		metrics: &Metrics{
			RequestMetrics:    make(map[string]*RequestTypeMetrics),
			ProviderMetrics:   make(map[string]*ProviderMetrics),
			PolicyMetrics:     &PolicyMetrics{
				PolicyHitRate:         make(map[string]int64),
				RiskScoreDistribution: make(map[string]int64),
			},
			SystemMetrics:     &SystemMetrics{},
			CollectionStarted: time.Now(),
			LastResetTime:     time.Now(),
		},
	}

	// Start background tasks
	go collector.systemMetricsUpdater()

	return collector
}

// RecordRequest records metrics for a request
func (c *MetricsCollector) RecordRequest(requestType, provider string, responseTime time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Update request type metrics
	if _, exists := c.metrics.RequestMetrics[requestType]; !exists {
		c.metrics.RequestMetrics[requestType] = &RequestTypeMetrics{
			responseTimes: make([]time.Duration, 0, 1000),
		}
	}

	rtMetrics := c.metrics.RequestMetrics[requestType]
	rtMetrics.TotalRequests++
	rtMetrics.SuccessCount++
	rtMetrics.responseTimes = append(rtMetrics.responseTimes, responseTime)

	// Keep only last 1000 response times for percentile calculation
	if len(rtMetrics.responseTimes) > 1000 {
		rtMetrics.responseTimes = rtMetrics.responseTimes[len(rtMetrics.responseTimes)-1000:]
	}

	// Update provider metrics
	if _, exists := c.metrics.ProviderMetrics[provider]; !exists {
		c.metrics.ProviderMetrics[provider] = &ProviderMetrics{}
	}

	provMetrics := c.metrics.ProviderMetrics[provider]
	provMetrics.RequestCount++
	provMetrics.SuccessCount++

	// Update system metrics
	c.metrics.SystemMetrics.TotalRequests++
}

// RecordBlockedRequest records a blocked request
func (c *MetricsCollector) RecordBlockedRequest(requestType string, policyName string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.metrics.RequestMetrics[requestType]; !exists {
		c.metrics.RequestMetrics[requestType] = &RequestTypeMetrics{
			responseTimes: make([]time.Duration, 0, 1000),
		}
	}

	c.metrics.RequestMetrics[requestType].BlockedCount++
	c.metrics.PolicyMetrics.BlockedByPolicy++
	c.metrics.PolicyMetrics.PolicyHitRate[policyName]++
}

// RecordPolicyEvaluation records policy evaluation metrics
func (c *MetricsCollector) RecordPolicyEvaluation(evaluationTime time.Duration, riskScore float64, policiesApplied []string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.metrics.PolicyMetrics.TotalEvaluations++
	
	// Update average evaluation time
	currentAvg := c.metrics.PolicyMetrics.AvgEvaluationTime
	newAvg := (currentAvg*time.Duration(c.metrics.PolicyMetrics.TotalEvaluations-1) + evaluationTime) / 
		time.Duration(c.metrics.PolicyMetrics.TotalEvaluations)
	c.metrics.PolicyMetrics.AvgEvaluationTime = newAvg

	// Update policy hit rate
	for _, policy := range policiesApplied {
		c.metrics.PolicyMetrics.PolicyHitRate[policy]++
	}

	// Update risk score distribution
	riskBucket := c.getRiskScoreBucket(riskScore)
	c.metrics.PolicyMetrics.RiskScoreDistribution[riskBucket]++
}

// RecordRedaction records PII redaction metrics
func (c *MetricsCollector) RecordRedaction(fieldCount int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.metrics.PolicyMetrics.RedactionCount += int64(fieldCount)
}

// RecordProviderUsage records provider usage metrics
func (c *MetricsCollector) RecordProviderUsage(provider string, tokens int, cost float64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.metrics.ProviderMetrics[provider]; !exists {
		c.metrics.ProviderMetrics[provider] = &ProviderMetrics{}
	}

	provMetrics := c.metrics.ProviderMetrics[provider]
	provMetrics.TotalTokens += int64(tokens)
	provMetrics.TotalCost += cost
}

// RecordProviderError records provider error
func (c *MetricsCollector) RecordProviderError(provider string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.metrics.ProviderMetrics[provider]; !exists {
		c.metrics.ProviderMetrics[provider] = &ProviderMetrics{}
	}

	c.metrics.ProviderMetrics[provider].ErrorCount++
}

// GetMetrics returns current metrics
func (c *MetricsCollector) GetMetrics() *Metrics {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Calculate derived metrics
	c.calculateDerivedMetrics()

	// Deep copy metrics to avoid race conditions
	metricsCopy := &Metrics{
		RequestMetrics:    make(map[string]*RequestTypeMetrics),
		ProviderMetrics:   make(map[string]*ProviderMetrics),
		PolicyMetrics:     c.copyPolicyMetrics(),
		SystemMetrics:     c.copySystemMetrics(),
		LastResetTime:     c.metrics.LastResetTime,
		CollectionStarted: c.metrics.CollectionStarted,
	}

	// Copy request metrics
	for k, v := range c.metrics.RequestMetrics {
		metricsCopy.RequestMetrics[k] = &RequestTypeMetrics{
			TotalRequests:   v.TotalRequests,
			SuccessCount:    v.SuccessCount,
			BlockedCount:    v.BlockedCount,
			ErrorCount:      v.ErrorCount,
			AvgResponseTime: v.AvgResponseTime,
			P95ResponseTime: v.P95ResponseTime,
			P99ResponseTime: v.P99ResponseTime,
		}
	}

	// Copy provider metrics
	for k, v := range c.metrics.ProviderMetrics {
		metricsCopy.ProviderMetrics[k] = &ProviderMetrics{
			RequestCount:    v.RequestCount,
			SuccessCount:    v.SuccessCount,
			ErrorCount:      v.ErrorCount,
			TotalTokens:     v.TotalTokens,
			TotalCost:       v.TotalCost,
			AvgResponseTime: v.AvgResponseTime,
			Availability:    v.Availability,
		}
	}

	return metricsCopy
}

// ResetMetrics resets all metrics
func (c *MetricsCollector) ResetMetrics() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.metrics = &Metrics{
		RequestMetrics:    make(map[string]*RequestTypeMetrics),
		ProviderMetrics:   make(map[string]*ProviderMetrics),
		PolicyMetrics:     &PolicyMetrics{
			PolicyHitRate:         make(map[string]int64),
			RiskScoreDistribution: make(map[string]int64),
		},
		SystemMetrics:     &SystemMetrics{},
		CollectionStarted: c.metrics.CollectionStarted,
		LastResetTime:     time.Now(),
	}
}

// calculateDerivedMetrics calculates derived metrics like percentiles and averages
func (c *MetricsCollector) calculateDerivedMetrics() {
	// Calculate request type metrics
	for _, rtMetrics := range c.metrics.RequestMetrics {
		if len(rtMetrics.responseTimes) > 0 {
			// Calculate average
			var total time.Duration
			for _, rt := range rtMetrics.responseTimes {
				total += rt
			}
			rtMetrics.AvgResponseTime = total / time.Duration(len(rtMetrics.responseTimes))

			// Calculate percentiles
			rtMetrics.P95ResponseTime = c.calculatePercentile(rtMetrics.responseTimes, 95)
			rtMetrics.P99ResponseTime = c.calculatePercentile(rtMetrics.responseTimes, 99)
		}
	}

	// Calculate provider availability
	for _, provMetrics := range c.metrics.ProviderMetrics {
		if provMetrics.RequestCount > 0 {
			provMetrics.Availability = float64(provMetrics.SuccessCount) / float64(provMetrics.RequestCount) * 100
			
			if provMetrics.SuccessCount > 0 {
				// This is a simplified calculation - in production, track actual response times
				provMetrics.AvgResponseTime = 100.0 // Mock value
			}
		}
	}

	// Calculate system uptime
	c.metrics.SystemMetrics.UptimeSeconds = int64(time.Since(c.metrics.CollectionStarted).Seconds())
}

// calculatePercentile calculates the nth percentile of response times
func (c *MetricsCollector) calculatePercentile(times []time.Duration, percentile int) time.Duration {
	if len(times) == 0 {
		return 0
	}

	// Simple percentile calculation - in production, use a more efficient algorithm
	index := (len(times) * percentile) / 100
	if index >= len(times) {
		index = len(times) - 1
	}

	return times[index]
}

// getRiskScoreBucket returns the risk score bucket for metrics
func (c *MetricsCollector) getRiskScoreBucket(score float64) string {
	switch {
	case score < 0.2:
		return "very_low"
	case score < 0.4:
		return "low"
	case score < 0.6:
		return "medium"
	case score < 0.8:
		return "high"
	default:
		return "very_high"
	}
}

// copyPolicyMetrics creates a deep copy of policy metrics
func (c *MetricsCollector) copyPolicyMetrics() *PolicyMetrics {
	pm := &PolicyMetrics{
		TotalEvaluations:      c.metrics.PolicyMetrics.TotalEvaluations,
		BlockedByPolicy:       c.metrics.PolicyMetrics.BlockedByPolicy,
		RedactionCount:        c.metrics.PolicyMetrics.RedactionCount,
		AvgEvaluationTime:     c.metrics.PolicyMetrics.AvgEvaluationTime,
		PolicyHitRate:         make(map[string]int64),
		RiskScoreDistribution: make(map[string]int64),
	}

	for k, v := range c.metrics.PolicyMetrics.PolicyHitRate {
		pm.PolicyHitRate[k] = v
	}

	for k, v := range c.metrics.PolicyMetrics.RiskScoreDistribution {
		pm.RiskScoreDistribution[k] = v
	}

	return pm
}

// copySystemMetrics creates a deep copy of system metrics
func (c *MetricsCollector) copySystemMetrics() *SystemMetrics {
	return &SystemMetrics{
		UptimeSeconds:     c.metrics.SystemMetrics.UptimeSeconds,
		TotalRequests:     c.metrics.SystemMetrics.TotalRequests,
		ActiveConnections: c.metrics.SystemMetrics.ActiveConnections,
		QueueDepth:        c.metrics.SystemMetrics.QueueDepth,
		LastHealthCheck:   c.metrics.SystemMetrics.LastHealthCheck,
		HealthCheckPassed: c.metrics.SystemMetrics.HealthCheckPassed,
	}
}

// systemMetricsUpdater updates system-level metrics
func (c *MetricsCollector) systemMetricsUpdater() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		c.metrics.SystemMetrics.LastHealthCheck = time.Now()
		// In production, perform actual health checks
		c.metrics.SystemMetrics.HealthCheckPassed = true
		c.mu.Unlock()
	}
}