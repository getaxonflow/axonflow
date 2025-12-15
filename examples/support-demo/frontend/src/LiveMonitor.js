import React, { useState } from 'react';
import './LiveMonitor.css';

function LiveMonitor({ policyMetrics, onClose }) {
  const [position, setPosition] = useState({ x: 20, y: 20 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });

  const handleMouseDown = (e) => {
    setIsDragging(true);
    setDragStart({
      x: e.clientX - position.x,
      y: e.clientY - position.y
    });
  };

  const handleMouseMove = (e) => {
    if (isDragging) {
      setPosition({
        x: e.clientX - dragStart.x,
        y: e.clientY - dragStart.y
      });
    }
  };

  const handleMouseUp = () => {
    setIsDragging(false);
  };

  React.useEffect(() => {
    if (isDragging) {
      document.addEventListener('mousemove', handleMouseMove);
      document.addEventListener('mouseup', handleMouseUp);
      return () => {
        document.removeEventListener('mousemove', handleMouseMove);
        document.removeEventListener('mouseup', handleMouseUp);
      };
    }
  }, [isDragging, dragStart]);

  return (
    <div 
      className="live-monitor"
      style={{
        right: `${position.x}px`,
        top: `${position.y}px`,
        cursor: isDragging ? 'grabbing' : 'grab'
      }}
    >
      <div 
        className="monitor-header"
        onMouseDown={handleMouseDown}
      >
        <h3>🛡️ Live Policy Monitor</h3>
        <button className="close-btn" onClick={onClose}>✕</button>
      </div>
      
      <div style={{
        background: '#f7fafc',
        padding: '8px 12px',
        margin: '0 0 12px 0',
        borderRadius: '4px',
        fontSize: '0.8rem',
        color: '#4a5568',
        textAlign: 'center',
        borderBottom: '1px solid #e2e8f0'
      }}>
        <span style={{fontWeight: '600'}}>Today's Data</span> ({new Date().toLocaleDateString()} • {Intl.DateTimeFormat().resolvedOptions().timeZone})
      </div>

      <div className="monitor-content">
        {/* Row 1: Total Queries alone */}
        <div className="metric-grid" style={{gridTemplateColumns: '1fr', gap: '8px', marginBottom: '8px'}}>
          <div className="metric-box queries" style={{padding: '12px'}}>
            <div className="metric-value" style={{fontSize: '1.8rem'}}>{policyMetrics.totalPoliciesEnforced}</div>
            <div className="metric-label" style={{fontSize: '0.8rem'}}>Total Queries</div>
          </div>
        </div>

        {/* Row 2: All policy actions together */}
        <div className="metric-grid" style={{gridTemplateColumns: '1fr 1fr 1fr', gap: '6px', marginBottom: '12px'}}>
          <div className="metric-box" style={{background: '#ecfccb', borderColor: '#65a30d', padding: '8px'}}>
            <div className="metric-value" style={{fontSize: '1.4rem'}}>{policyMetrics.piiRedacted || 0}</div>
            <div className="metric-label" style={{fontSize: '0.7rem'}}>PII Redacted</div>
          </div>
          <div className="metric-box violations" style={{background: '#fef3c7', borderColor: '#f59e0b', padding: '8px'}}>
            <div className="metric-value" style={{fontSize: '1.4rem'}}>{policyMetrics.aiQueries || 0}</div>
            <div className="metric-label" style={{fontSize: '0.7rem'}}>Unauthorized</div>
          </div>
          <div className="metric-box" style={{background: '#fef2f2', borderColor: '#dc2626', padding: '8px'}}>
            <div className="metric-value" style={{fontSize: '1.4rem'}}>{policyMetrics.regionalBlocks || 0}</div>
            <div className="metric-label" style={{fontSize: '0.7rem'}}>Regional Blocks</div>
          </div>
        </div>

        <div className="service-status">
          <h4>Service Health</h4>
          <div className="status-grid">
            <div className="status-item">
              <span className={`status-dot ${policyMetrics.agentHealth}`}></span>
              <span>Agent</span>
            </div>
            <div className="status-item">
              <span className={`status-dot ${policyMetrics.orchestratorHealth}`}></span>
              <span>Orchestrator</span>
            </div>
          </div>
        </div>

        <div className="activity-feed">
          <h4>Recent Activity</h4>
          {policyMetrics.recentActivity.length > 0 ? (
            <div className="activity-list">
              {policyMetrics.recentActivity.slice(0, 3).map((activity, index) => (
                <div key={index} className="activity-item">
                  <div className="activity-icon">
                    {activity.type === 'natural_query' ? '🧠' : '🔍'}
                  </div>
                  <div className="activity-details">
                    <div className="activity-query">
                      {activity.query?.substring(0, 30)}{activity.query?.length > 30 ? '...' : ''}
                    </div>
                    <div className="activity-meta">
                      {activity.provider && <span className="provider">{activity.provider}</span>}
                      <span className="time">{new Date(activity.timestamp).toLocaleTimeString()} ({Intl.DateTimeFormat().resolvedOptions().timeZone})</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="no-activity">Execute queries to see live updates</div>
          )}
        </div>

        <div className="monitor-footer">
          <div className="pulse-indicator"></div>
          <span>Real-time monitoring active</span>
        </div>
      </div>
    </div>
  );
}

export default LiveMonitor;