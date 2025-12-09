import React from 'react';
import './PerformanceMonitor.css';

function PerformanceMonitor({ performanceMetrics, policyMetrics, onBack }) {
  // Show demo data if no real data yet
  const hasData = performanceMetrics.totalRequests > 0;
  // Calculate max height for visualization
  const maxTime = Math.max(...performanceMetrics.timeSeriesData.map(p => p.responseTime || 0), 1);

  return (
    <div className="performance-page">
      <div className="performance-header">
        <button onClick={onBack} className="back-button">← Back to Dashboard</button>
        <h1>📊 Performance & Policy Monitoring</h1>
        <p>Real-time metrics for AxonFlow services and policy enforcement</p>
      </div>
      
      <div style={{
        background: '#f7fafc',
        border: '1px solid #e2e8f0',
        borderRadius: '8px',
        padding: '16px 20px',
        margin: '0 0 20px 0',
        fontSize: '0.9rem',
        color: '#4a5568'
      }}>
        <strong>⏱️ Timespan Reference:</strong> Response Times show hourly trends • Throughput shows last hour averages • Policy Enforcement & Total Requests show today's activity • Service Health shows current status
      </div>

      {!hasData && (
        <div style={{
          background: '#ebf8ff',
          border: '2px dashed #90cdf4',
          borderRadius: '12px',
          padding: '40px',
          textAlign: 'center',
          marginBottom: '30px'
        }}>
          <h2 style={{color: '#2b6cb0', marginBottom: '15px'}}>📈 No Data Yet</h2>
          <p style={{color: '#4a5568', fontSize: '1.1rem', marginBottom: '20px'}}>
            Execute some queries on the dashboard to see real-time performance metrics!
          </p>
          <p style={{color: '#718096', fontSize: '0.95rem'}}>
            Try these actions to populate metrics:
          </p>
          <ul style={{
            listStyle: 'none',
            padding: 0,
            marginTop: '15px',
            color: '#4a5568',
            fontSize: '0.9rem',
            lineHeight: '1.8'
          }}>
            <li>🔍 Run SQL queries from the dashboard</li>
            <li>🧠 Execute natural language queries</li>
            <li>🛡️ Toggle the Live Monitor to see real-time updates</li>
          </ul>
        </div>
      )}

      <div className="metrics-grid">
        {/* Response Time Metrics */}
        <div className="metric-section">
          <h2>⏱️ Response Times</h2>
          <div className="response-time-cards">
            <div className="metric-card average">
              <div className="metric-value">{performanceMetrics.avgResponseTime}ms</div>
              <div className="metric-label">Average</div>
              <div className="metric-trend">↓ 12% vs last hour</div>
            </div>
            <div className="metric-card p95">
              <div className="metric-value">{performanceMetrics.p95ResponseTime}ms</div>
              <div className="metric-label">P95</div>
              <div className="metric-trend">→ Stable</div>
            </div>
            <div className="metric-card p99">
              <div className="metric-value">{performanceMetrics.p99ResponseTime}ms</div>
              <div className="metric-label">P99</div>
              <div className="metric-trend">↑ 3% vs last hour</div>
            </div>
          </div>
        </div>

        {/* Throughput & Reliability */}
        <div className="metric-section">
          <h2>📈 Throughput & Reliability</h2>
          <div className="throughput-cards">
            <div className="metric-card">
              <div className="metric-value">{performanceMetrics.requestsPerSecond}</div>
              <div className="metric-label">Requests/sec</div>
              <div className="metric-indicator good">Last Hour</div>
            </div>
            <div className="metric-card">
              <div className="metric-value">{performanceMetrics.errorRate}%</div>
              <div className="metric-label">Error Rate</div>
              <div className="metric-indicator good">Last Hour</div>
            </div>
            <div className="metric-card">
              <div className="metric-value">{performanceMetrics.totalRequests}</div>
              <div className="metric-label">Total Requests</div>
              <div className="metric-indicator">Today</div>
            </div>
          </div>
        </div>

        {/* Service Latency Breakdown */}
        <div className="metric-section full-width">
          <h2>🔍 Service Latency Breakdown</h2>
          <div className="latency-breakdown">
            <div className="service-latency">
              <div className="service-header">
                <h3>AxonFlow Agent</h3>
                <span className="latency-value">{performanceMetrics.agentLatency}ms</span>
              </div>
              <div className="latency-bar">
                <div 
                  className="latency-fill agent"
                  style={{
                    width: `${performanceMetrics.avgResponseTime > 0 
                      ? (performanceMetrics.agentLatency / performanceMetrics.avgResponseTime) * 100 
                      : 0}%`
                  }}
                />
              </div>
              <p className="service-description">Authentication & static policy checks</p>
            </div>
            
            <div className="service-latency">
              <div className="service-header">
                <h3>AxonFlow Orchestrator</h3>
                <span className="latency-value">{performanceMetrics.orchestratorLatency}ms</span>
              </div>
              <div className="latency-bar">
                <div 
                  className="latency-fill orchestrator"
                  style={{
                    width: `${performanceMetrics.avgResponseTime > 0 
                      ? (performanceMetrics.orchestratorLatency / performanceMetrics.avgResponseTime) * 100 
                      : 0}%`
                  }}
                />
              </div>
              <p className="service-description">LLM routing & dynamic policy evaluation</p>
            </div>
          </div>
        </div>

        {/* Response Time Trend */}
        <div className="metric-section">
          <h2>📊 Response Time Trend</h2>
          <div className="trend-chart">
            {performanceMetrics.timeSeriesData.length > 0 ? (
              <div className="chart-bars">
                {performanceMetrics.timeSeriesData.map((point, index) => {
                  const height = ((point.responseTime || 0) / maxTime) * 150;
                  return (
                    <div
                      key={index}
                      className="chart-bar"
                      style={{
                        height: `${height}px`,
                        opacity: 1 - (index * 0.04)
                      }}
                      title={`${point.responseTime || 0}ms at ${new Date(point.timestamp).toLocaleTimeString()} (${Intl.DateTimeFormat().resolvedOptions().timeZone})`}
                    />
                  );
                })}
              </div>
            ) : (
              <div className="no-data">No data yet - execute queries to see metrics</div>
            )}
          </div>
          <p className="chart-label">Last 20 requests</p>
        </div>

        {/* Policy Enforcement */}
        <div className="metric-section">
          <h2>🛡️ Policy Enforcement</h2>
          <div style={{
            background: '#f7fafc',
            border: '1px solid #e2e8f0',
            borderRadius: '6px',
            padding: '12px 16px',
            margin: '0 0 20px 0',
            fontSize: '0.85rem',
            color: '#4a5568',
            textAlign: 'center'
          }}>
            <strong>Today's Data</strong> ({new Date().toLocaleDateString()} • {Intl.DateTimeFormat().resolvedOptions().timeZone})
          </div>
          <div className="policy-cards">
            <div className="metric-card">
              <div className="metric-value">{policyMetrics.regionalBlocks || 0}</div>
              <div className="metric-label">Regional Blocks</div>
              <div className="metric-description">Cross-region access restrictions applied</div>
            </div>
            <div className="metric-card">
              <div className="metric-value">{policyMetrics.piiRedacted || 0}</div>
              <div className="metric-label">PII Redactions</div>
              <div className="metric-description">Sensitive data automatically redacted</div>
            </div>
            <div className="metric-card">
              <div className="metric-value">{policyMetrics.aiQueries || 0}</div>
              <div className="metric-label">Unauthorized Queries</div>
              <div className="metric-description">Blocked dangerous or malicious queries</div>
            </div>
          </div>
          
          <div className="service-health">
            <h3>Service Health</h3>
            <div className="health-status">
              <div className="health-item">
                <span className="service-name">Agent</span>
                <span className={`health-indicator ${policyMetrics.agentHealth}`}>
                  {policyMetrics.agentHealth === 'healthy' ? '✅ Healthy' : '❌ Unhealthy'}
                </span>
              </div>
              <div className="health-item">
                <span className="service-name">Orchestrator</span>
                <span className={`health-indicator ${policyMetrics.orchestratorHealth}`}>
                  {policyMetrics.orchestratorHealth === 'healthy' ? '✅ Healthy' : '❌ Unhealthy'}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Recent Activity */}
        <div className="metric-section full-width">
          <h2>🕐 Recent Policy Activity</h2>
          <div className="activity-list">
            {policyMetrics.recentActivity.length > 0 ? (
              policyMetrics.recentActivity.map((activity, index) => (
                <div key={index} className="activity-item">
                  <div className="activity-header">
                    <span className="activity-type">
                      {activity.type === 'natural_query' ? '🧠 Natural Language' : '🔍 SQL Query'}
                    </span>
                    <span className="activity-time">
                      {new Date(activity.timestamp).toLocaleTimeString()} ({Intl.DateTimeFormat().resolvedOptions().timeZone})
                    </span>
                  </div>
                  <div className="activity-query">
                    {activity.query?.substring(0, 100)}{activity.query?.length > 100 ? '...' : ''}
                  </div>
                  {activity.provider && (
                    <div className="activity-routing">
                      Routed to: <span className="provider-name">{activity.provider}</span>
                    </div>
                  )}
                </div>
              ))
            ) : (
              <div className="no-data">No queries yet - execute some queries to see activity</div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default PerformanceMonitor;