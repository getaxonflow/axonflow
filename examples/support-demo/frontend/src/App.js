import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './App.css';
import PolicyConfig from './PolicyConfig';
import PerformanceMonitor from './PerformanceMonitor';
import LiveMonitor from './LiveMonitor';

// API calls use relative paths - nginx proxies /api/* to backend
const API_BASE = '';

function App() {
  const [user, setUser] = useState(() => {
    const savedUser = localStorage.getItem('user');
    return savedUser ? JSON.parse(savedUser) : null;
  });
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [dashboard, setDashboard] = useState(null);
  const [queryResult, setQueryResult] = useState(null);
  const [auditLogs, setAuditLogs] = useState([]);
  const [query, setQuery] = useState('');
  const [userAccess, setUserAccess] = useState(null);
  const [naturalQuery, setNaturalQuery] = useState('');
  const [chatMessage, setChatMessage] = useState('');
  const [chatHistory, setChatHistory] = useState([]);
  const [policyMetrics, setPolicyMetrics] = useState({
    totalPoliciesEnforced: 0, // Total queries today (all types)
    aiQueries: 0, // Natural language queries today
    activeViolations: 0, // Keep at 0 for clean demo unless real violations occur
    piiRedacted: 0, // Count of PII redaction events
    regionalBlocks: 0, // Count of regional access restrictions
    agentHealth: 'healthy',
    orchestratorHealth: 'healthy',
    lastPolicyCheck: null,
    recentActivity: []
  });
  // Initialize currentView from URL hash
  const getInitialView = () => {
    const hash = window.location.hash.slice(1);
    if (['policy-config', 'performance'].includes(hash)) {
      return hash;
    }
    return 'dashboard';
  };
  
  const [currentView, setCurrentView] = useState(getInitialView());
  
  const [showRealtimeMonitor, setShowRealtimeMonitor] = useState(false); // Floating overlay for live metrics
  const [performanceMetrics, setPerformanceMetrics] = useState({
    avgResponseTime: 145,
    p95ResponseTime: 220,
    p99ResponseTime: 380,
    requestsPerSecond: 0.1,
    errorRate: 0.2,
    agentLatency: 45,
    orchestratorLatency: 100,
    totalRequests: 1247,
    recentRequests: [],
    timeSeriesData: []
  });

  // Demo queries for different user types
  const demoQueries = {
    'john.doe@company.com': [
      'SELECT * FROM customers WHERE region = \'us-west\' LIMIT 10',
      'SELECT * FROM support_tickets WHERE status = \'open\' LIMIT 5',
      'SELECT name, email FROM customers WHERE support_tier = \'premium\''
    ],
    'sarah.manager@company.com': [
      'SELECT * FROM customers WHERE support_tier = \'enterprise\'',
      'SELECT * FROM support_tickets WHERE priority = \'high\'',
      'SELECT customer_id, title, description FROM support_tickets WHERE assigned_to LIKE \'%manager%\''
    ],
    'admin@company.com': [
      'SELECT * FROM customers LIMIT 10',
      'SELECT * FROM support_tickets WHERE created_at > CURRENT_DATE - INTERVAL \'7 days\'',
      'SELECT user_email, COUNT(*) as query_count FROM audit_log GROUP BY user_email'
    ]
  };

  // Demo natural language queries - EXACT from demo script
  const demoNaturalQueries = {
    'john.doe@company.com': [
      'Show ticket statistics by status',  // Regular (no PII) - routes to Local (agent role)
      'Show customer count by region',  // Regular (no PII) - routes to Local (agent role)
      'Find customer with SSN 123-45-6789',  // PII - routes to Local
      'Show customers with phone numbers',  // PII - routes to Local
      'Show confidential enterprise customer data'  // Confidential - routes to Anthropic
    ],
    'sarah.manager@company.com': [
      'Show ticket count by priority level',  // OpenAI (no PII)
      'Show customer statistics by support tier',  // OpenAI (no PII)
      'Find customer with SSN 123-45-6789',  // Demo Flow 2 (PII test) - Local
      'Show confidential enterprise customer data',  // Anthropic trigger
      'Find internal escalation tickets'  // Anthropic trigger
    ],
    'admin@company.com': [
      'Show me system usage statistics',
      'Find all customers across all regions',
      'Which users are querying the most data?'
    ],
    'eu.agent@company.com': [
      'Show all EU customers',  // GDPR - routes to Local
      'Find customer with phone number 555-0123',  // PII - routes to Local  
      'Show premium customers',  // Regular - routes to Local (EU region)
      'Show confidential enterprise customer data',  // Confidential - routes to Local (EU override)
      'Show me all open support tickets'  // Regular - routes to Local (EU region)
    ]
  };

  useEffect(() => {
    // Check if token is expired or invalid
    if (token && token !== 'null' && token.length > 10) {
      try {
        // Parse JWT payload
        const parts = token.split('.');
        if (parts.length !== 3) {
          throw new Error('Invalid JWT format - wrong number of parts');
        }
        
        const payload = JSON.parse(atob(parts[1]));
        const now = Date.now() / 1000;
        
        // Check expiration with 30 second buffer to account for clock skew
        if (payload.exp && (payload.exp - 30) < now) {
          localStorage.removeItem('token');
          localStorage.removeItem('user');
          setToken(null);
          setUser(null);
          return;
        }
        
        // Check if token is issued too far in the future (invalid)
        if (payload.iat && payload.iat > (now + 300)) {
          localStorage.removeItem('token');
          localStorage.removeItem('user');
          setToken(null);
          setUser(null);
          return;
        }
        
      } catch (err) {
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        setToken(null);
        setUser(null);
        return;
      }
    }
    
    if (token && user && token !== 'null' && token.length > 10) {
      // Only fetch data if we have both token and user, and token looks valid
      fetchDashboard();
      fetchAuditLogs();
      fetchUserAccess();
      fetchPolicyMetrics();
      fetchPerformanceMetrics();
    }
  }, [token, user]);


  // Disabled automatic policy metrics refresh to avoid 404 errors
  // useEffect(() => {
  //   if (token && user) {
  //     const interval = setInterval(fetchPolicyMetrics, 5000);
  //     return () => clearInterval(interval);
  //   }
  // }, [token, user]);


  const fetchDashboard = async () => {
    try {
      const response = await axios.get(`${API_BASE}/api/dashboard`, {
        headers: { Authorization: `Bearer ${localStorage.getItem('token') || token}` }
      });
      setDashboard(response.data);
    } catch (err) {
      console.error('Failed to fetch dashboard:', err);
    }
  };

  const fetchAuditLogs = async () => {
    try {
      const response = await axios.get(`${API_BASE}/api/audit`, {
        headers: { Authorization: `Bearer ${localStorage.getItem('token') || token}` }
      });
      setAuditLogs(response.data || []);
    } catch (err) {
      console.error('Failed to fetch audit logs:', err);
    }
  };


  const fetchPerformanceMetrics = async () => {
    try {
      const response = await axios.get(`${API_BASE}/api/performance/metrics`, {
        headers: { Authorization: `Bearer ${localStorage.getItem('token') || token}` }
      });
      setPerformanceMetrics(prev => ({
        ...prev,
        avgResponseTime: response.data.avg_response_time || prev.avgResponseTime,
        p95ResponseTime: response.data.p95_response_time || prev.p95ResponseTime,
        p99ResponseTime: response.data.p99_response_time || prev.p99ResponseTime,
        requestsPerSecond: response.data.requests_per_second || prev.requestsPerSecond,
        errorRate: response.data.error_rate || prev.errorRate,
        totalRequests: response.data.total_requests || prev.totalRequests,
        agentLatency: response.data.agent_latency || prev.agentLatency,
        orchestratorLatency: response.data.orchestrator_latency || prev.orchestratorLatency,
        timeSeriesData: response.data.time_series_data || prev.timeSeriesData
      }));
    } catch (err) {
      console.error('Failed to fetch performance metrics:', err);
      // Keep existing demo data on error
    }
  };

  const updatePolicyMetrics = async (incrementPolicies = false, incrementAi = false, piiCount = 0, regionalCount = 0, activityType = '', query = '', provider = '') => {
    try {
      await axios.post(`${API_BASE}/api/policy-metrics/update`, {
        increment_policies_enforced: incrementPolicies,
        increment_ai_queries: incrementAi,
        increment_pii_redacted: piiCount,
        increment_regional_blocks: regionalCount,
        activity_type: activityType,
        query: query.substring(0, 100), // Truncate for storage
        provider: provider
      }, {
        headers: { Authorization: `Bearer ${localStorage.getItem('token') || token}` }
      });
      
      // Refresh metrics after update
      fetchPolicyMetrics();
    } catch (err) {
      console.error('Failed to update policy metrics:', err);
    }
  };

  const fetchUserAccess = async () => {
    try {
      const response = await axios.get(`${API_BASE}/api/llm/user-access`, {
        headers: { Authorization: `Bearer ${localStorage.getItem('token') || token}` }
      });
      setUserAccess(response.data);
    } catch (err) {
      console.error('Failed to fetch user access:', err);
      // Don't auto-logout on 401 - let user handle authentication manually
    }
  };

  const fetchPolicyMetrics = async () => {
    try {
      // For this demo, AxonFlow services are external - check via backend status endpoint
      const agentHealth = { data: { status: 'unknown' } };
      const orchestratorHealth = { data: { status: 'unknown' } };
      
      // Fetch persistent policy metrics from database
      const metricsResponse = await axios.get(`${API_BASE}/api/policy-metrics`, {
        headers: { Authorization: `Bearer ${localStorage.getItem('token') || token}` }
      }).catch(() => ({ 
        data: {
          total_policies_enforced: policyMetrics.totalPoliciesEnforced,
          ai_queries: policyMetrics.aiQueries,
          pii_redacted: policyMetrics.piiRedacted,
          regional_blocks: policyMetrics.regionalBlocks,
          recent_activity: policyMetrics.recentActivity
        }
      }));
      
      setPolicyMetrics(prev => ({
        ...prev,
        totalPoliciesEnforced: metricsResponse.data.total_policies_enforced || prev.totalPoliciesEnforced,
        aiQueries: metricsResponse.data.ai_queries || prev.aiQueries,
        activeViolations: metricsResponse.data.active_violations || 0,
        piiRedacted: metricsResponse.data.pii_redacted || prev.piiRedacted,
        regionalBlocks: metricsResponse.data.regional_blocks || prev.regionalBlocks,
        agentHealth: agentHealth.data.status === 'healthy' ? 'healthy' : 'unhealthy',
        orchestratorHealth: orchestratorHealth.data.status === 'healthy' ? 'healthy' : 'unhealthy',
        lastPolicyCheck: new Date().toISOString(),
        recentActivity: metricsResponse.data.recent_activity || prev.recentActivity
      }));
    } catch (err) {
      console.error('Failed to fetch policy metrics:', err);
    }
  };

  const updatePerformanceMetrics = (responseTime, queryType, isError) => {
    setPerformanceMetrics(prev => {
      const newRequest = {
        responseTime,
        queryType,
        timestamp: new Date().toISOString(),
        isError
      };
      
      // Keep last 100 requests for statistics
      const updatedRequests = [newRequest, ...prev.recentRequests.slice(0, 99)];
      
      // Calculate statistics
      const responseTimes = updatedRequests.filter(r => !r.isError).map(r => r.responseTime);
      const avgResponseTime = responseTimes.length > 0 
        ? Math.round(responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length)
        : 0;
      
      // Calculate percentiles
      const sortedTimes = [...responseTimes].sort((a, b) => a - b);
      const p95Index = Math.floor(sortedTimes.length * 0.95);
      const p99Index = Math.floor(sortedTimes.length * 0.99);
      const p95ResponseTime = sortedTimes[p95Index] || 0;
      const p99ResponseTime = sortedTimes[p99Index] || 0;
      
      // Calculate error rate
      const errorCount = updatedRequests.filter(r => r.isError).length;
      const errorRate = updatedRequests.length > 0 
        ? Math.round((errorCount / updatedRequests.length) * 100)
        : 0;
      
      // Calculate requests per second (based on last minute)
      const oneMinuteAgo = new Date(Date.now() - 60000);
      const recentRequestsCount = updatedRequests.filter(
        r => new Date(r.timestamp) > oneMinuteAgo
      ).length;
      const requestsPerSecond = Math.round(recentRequestsCount / 60 * 10) / 10;
      
      // Add to time series data (keep last 20 points)
      const newTimeSeriesPoint = {
        timestamp: new Date().toISOString(),
        responseTime,
        requestsPerSecond
      };
      const timeSeriesData = [newTimeSeriesPoint, ...prev.timeSeriesData.slice(0, 19)];
      
      return {
        ...prev,
        avgResponseTime,
        p95ResponseTime,
        p99ResponseTime,
        requestsPerSecond,
        errorRate,
        totalRequests: prev.totalRequests + 1,
        recentRequests: updatedRequests,
        timeSeriesData,
        agentLatency: Math.round(responseTime * 0.3), // Simulated agent portion
        orchestratorLatency: Math.round(responseTime * 0.7) // Simulated orchestrator portion
      };
    });
  };


  const executeNaturalQuery = async () => {
    if (!naturalQuery.trim()) return;
    
    setLoading(true);
    setError('');
    
    const startTime = Date.now();
    
    try {
      const response = await axios.post(`${API_BASE}/api/llm/natural-query`, {
        query: naturalQuery.trim()
      }, {
        headers: { Authorization: `Bearer ${localStorage.getItem('token') || token}` }
      });
      
      const endTime = Date.now();
      const responseTime = endTime - startTime;
      
      console.log('Full API Response:', JSON.stringify(response.data, null, 2)); // Debug log
      setQueryResult(response.data);
      // Refresh audit logs, dashboard and policy metrics after natural language query
      fetchAuditLogs();
      fetchDashboard();
      fetchPolicyMetrics();
      
      // Update policy metrics in database
      const piiCount = response.data.pii_detected?.length || 0;
      
      // Calculate regional blocks based on user and query
      let regionalCount = 0;
      if (user.region === 'eu' && naturalQuery.toLowerCase().includes('customer')) {
        regionalCount = 1;
      }
      if (user.role !== 'admin' && (
        naturalQuery.toLowerCase().includes('all customers') || 
        naturalQuery.toLowerCase().includes('customers across') ||
        naturalQuery.toLowerCase().includes('all regions')
      )) {
        regionalCount = 1;
      }
      
      updatePolicyMetrics(
        true, // increment policies enforced
        true, // increment AI queries  
        piiCount,
        regionalCount,
        'natural_query',
        naturalQuery.trim(),
        response.data.llm_provider?.name || 'direct'
      );
      
      // Update performance metrics
      updatePerformanceMetrics(responseTime, 'natural_query', false);
    } catch (err) {
      setError('Natural language query failed: ' + (err.response?.data || err.message));
      console.error('Natural query error:', err);
    } finally {
      setLoading(false);
    }
  };

  const sendChatMessage = async () => {
    if (!chatMessage.trim()) return;
    
    const userMessage = { role: 'user', content: chatMessage };
    setChatHistory(prev => [...prev, userMessage]);
    setChatMessage('');
    setLoading(true);
    
    try {
      const response = await axios.post(`${API_BASE}/api/llm/chat`, {
        message: chatMessage.trim(),
        context: {
          user_role: user?.role || '',
          user_permissions: user?.permissions?.join(',') || '',
          timestamp: new Date().toISOString()
        }
      }, {
        headers: { Authorization: `Bearer ${localStorage.getItem('token') || token}` }
      });
      
      const assistantMessage = { 
        role: 'assistant', 
        content: response.data.content,
        provider: response.data.provider,
        tokens: response.data.tokens_used,
        duration: response.data.duration
      };
      setChatHistory(prev => [...prev, assistantMessage]);
      
    } catch (err) {
      const errorMessage = { 
        role: 'error', 
        content: 'Failed to send message: ' + (err.response?.data || err.message)
      };
      setChatHistory(prev => [...prev, errorMessage]);
    } finally {
      setLoading(false);
    }
  };

  const login = async (email, password) => {
    setLoading(true);
    setError('');
    
    try {
      const response = await axios.post(`${API_BASE}/api/login`, {
        email,
        password
      });
      
      const { token: newToken, user: userData } = response.data;
      setToken(newToken);
      setUser(userData);
      localStorage.setItem('token', newToken);
      localStorage.setItem('user', JSON.stringify(userData));
      
      // Fetch initial data
      await fetchDashboard();
      await fetchAuditLogs();
    } catch (err) {
      setError('Login failed. Please check your credentials.');
      console.error('Login error:', err);
    } finally {
      setLoading(false);
    }
  };

  const logout = () => {
    setUser(null);
    setToken(null);
    setDashboard(null);
    setQueryResult(null);
    setAuditLogs([]);
    setError('');
    localStorage.removeItem('token');
    localStorage.removeItem('user');
  };

  const executeQuery = async () => {
    if (!query.trim()) return;
    
    setLoading(true);
    setError('');
    
    const startTime = Date.now();
    
    try {
      const response = await axios.post(`${API_BASE}/api/query`, {
        query: query.trim()
      }, {
        headers: { Authorization: `Bearer ${localStorage.getItem('token') || token}` }
      });
      
      const endTime = Date.now();
      const responseTime = endTime - startTime;
      
      setQueryResult(response.data);
      // Refresh audit logs, dashboard and policy metrics after query
      fetchAuditLogs();
      fetchDashboard();
      fetchPolicyMetrics();
      
      // Update policy metrics in database for SQL query
      updatePolicyMetrics(
        true, // increment policies enforced
        false, // don't increment AI queries (SQL queries are not AI queries)
        0, // no PII detection for SQL queries in demo
        0, // no regional blocks for SQL queries in demo
        'sql_query',
        query.trim(),
        'direct'
      );
      
      // Update performance metrics
      updatePerformanceMetrics(responseTime, 'sql_query', false);
    } catch (err) {
      const errorMsg = err.response?.data?.block_reason || 
                      err.response?.data?.error || 
                      err.response?.data || 
                      err.message;
      setError('Query failed: ' + errorMsg);
      console.error('Query error:', err);
      
      // Create security audit trail for blocked queries
      setQueryResult({
        data: [],
        count: 0,
        block_reason: err.response?.data?.block_reason || 'security_violation',
        security_log: {
          user_email: user.email,
          query_executed: query.substring(0, 100) + (query.length > 100 ? '...' : ''),
          access_granted: false,
          pii_redacted: false,
          timestamp: new Date().toISOString()
        }
      });
      
      // Refresh audit logs after blocked query with small delay to ensure backend has logged it
      setTimeout(() => {
        fetchAuditLogs();
        fetchDashboard();
        fetchPolicyMetrics();
      }, 100);
    } finally {
      setLoading(false);
    }
  };

  if (!token || !user) {
    return <LoginForm onLogin={login} loading={loading} error={error} />;
  }

  // Show different views based on currentView state with RBAC
  if (currentView === 'policy-config') {
    // Restrict Policy Configuration to Admin and Security Analyst only
    if (user.role !== 'admin' && user.role !== 'security_analyst') {
      return (
        <div className="container">
          <div className="card" style={{textAlign: 'center', padding: '50px'}}>
            <h2 style={{color: '#e53e3e', marginBottom: '20px'}}>🔒 Access Denied</h2>
            <p style={{fontSize: '1.1rem', color: '#4a5568', marginBottom: '30px'}}>
              Policy Configuration is restricted to Security Analysts and System Administrators only.
            </p>
            <p style={{fontSize: '0.9rem', color: '#718096', marginBottom: '30px'}}>
              Your current role: <strong>{user.role}</strong><br/>
              Contact your system administrator if you need access to policy management features.
            </p>
            <button 
              onClick={() => {
                setCurrentView('dashboard');
                window.location.hash = '';
              }} 
              className="btn"
              style={{background: '#3182ce'}}
            >
              ← Return to Dashboard
            </button>
          </div>
        </div>
      );
    }
    // Render the integrated PolicyConfig React component
    return <PolicyConfig 
      user={user} 
      token={token}
      apiBase={API_BASE}
      onBack={() => {
        setCurrentView('dashboard');
        window.location.hash = '';
      }} 
    />;
  }

  if (currentView === 'performance') {
    // Restrict Performance Monitor to Admin, Manager, and Security Analyst
    if (user.role !== 'admin' && user.role !== 'manager' && user.role !== 'security_analyst') {
      return (
        <div className="container">
          <div className="card" style={{textAlign: 'center', padding: '50px'}}>
            <h2 style={{color: '#e53e3e', marginBottom: '20px'}}>🔒 Access Denied</h2>
            <p style={{fontSize: '1.1rem', color: '#4a5568', marginBottom: '30px'}}>
              Performance Monitor is restricted to Managers, Security Analysts, and System Administrators.
            </p>
            <p style={{fontSize: '0.9rem', color: '#718096', marginBottom: '30px'}}>
              Your current role: <strong>{user.role}</strong><br/>
              Contact your manager if you need access to performance monitoring features.
            </p>
            <button 
              onClick={() => {
                setCurrentView('dashboard');
                window.location.hash = '';
              }} 
              className="btn"
              style={{background: '#3182ce'}}
            >
              ← Return to Dashboard
            </button>
          </div>
        </div>
      );
    }
    return <PerformanceMonitor 
      performanceMetrics={performanceMetrics} 
      policyMetrics={policyMetrics}
      onBack={() => {
        setCurrentView('dashboard');
        window.location.hash = '';
      }} 
    />;
  }

  // Default dashboard view
  return (
    <div className="container">
      <div className="card">
        <div className="header">
          <h1>🔒 AxonFlow Demo</h1>
          <p>Secure Customer Support AI with Zero-Trust Data Access</p>
          <div style={{marginTop: '15px', display: 'flex', gap: '10px'}}>
            <button onClick={logout} className="btn" style={{width: 'auto'}}>
              Logout
            </button>
            {/* Policy Configuration - Admin Only */}
            {(user.role === 'admin' || user.role === 'security_analyst') && (
              <button 
                onClick={() => {
                  setCurrentView('policy-config');
                  window.location.hash = 'policy-config';
                }} 
                className="btn" 
                style={{
                  width: 'auto',
                  background: '#805ad5'
                }}
              >
                🔧 Policy Configuration
              </button>
            )}
            
            {/* Performance Monitor - Admin & Manager Only */}
            {(user.role === 'admin' || user.role === 'manager' || user.role === 'security_analyst') && (
              <button 
                onClick={() => {
                  setCurrentView('performance');
                  window.location.hash = 'performance';
                }} 
                className="btn" 
                style={{
                  width: 'auto',
                  background: '#38a169'
                }}
              >
                📊 Performance Monitor
              </button>
            )}
            <button 
              onClick={() => setShowRealtimeMonitor(!showRealtimeMonitor)} 
              className="btn" 
              style={{
                width: 'auto',
                background: showRealtimeMonitor ? '#e53e3e' : '#2b6cb0',
                position: 'relative'
              }}
            >
              {policyMetrics.activeViolations > 0 && !showRealtimeMonitor && (
                <span style={{
                  position: 'absolute',
                  top: '-8px',
                  right: '-8px',
                  background: '#e53e3e',
                  color: 'white',
                  borderRadius: '50%',
                  width: '20px',
                  height: '20px',
                  fontSize: '0.7rem',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontWeight: 'bold'
                }}>
                  {policyMetrics.activeViolations}
                </span>
              )}
              🛡️ Live Monitor {showRealtimeMonitor ? '✕' : ''}
            </button>
          </div>
        </div>

        {dashboard && (
          <>
            <div style={{
              background: '#f7fafc',
              border: '1px solid #e2e8f0',
              borderRadius: '8px',
              padding: '16px 20px',
              margin: '20px 0',
              fontSize: '0.9rem',
              color: '#4a5568'
            }}>
              <strong>📊 Dashboard Overview:</strong> All metrics below show historical data since system deployment. 
              For real-time activity, use the Live Monitor to view today's policy enforcement and current system health.
            </div>
            <div className="stats-grid">
            <div className="stat-card">
              <h3>{dashboard.total_queries}</h3>
              <p>Total Queries</p>
            </div>
            <div className="stat-card">
              <h3>{dashboard.total_pii_detections}</h3>
              <p>PII Detections</p>
            </div>
            <div className="stat-card">
              <h3>{dashboard.total_users}</h3>
              <p>Total Users</p>
            </div>
            <div className="stat-card">
              <h3>{dashboard.compliance_score?.toFixed(1)}%</h3>
              <p>Compliance Score</p>
            </div>
          </div>
          </>
        )}


        <div className="dashboard">
          <div className="sidebar">
            <div className="card">
              <div className="user-info">
                <h3>👤 User Profile</h3>
                <p><strong>Email:</strong> {user.email}</p>
                <p><strong>Name:</strong> {user.name}</p>
                <p><strong>Department:</strong> {user.department}</p>
                <p><strong>Role:</strong> {user.role}</p>
                <p><strong>Region:</strong> {user.region}</p>
                <div className="permissions">
                  {user.permissions?.map(perm => (
                    <span key={perm} className="permission-badge">{perm}</span>
                  ))}
                </div>
              </div>
            </div>

            <div className="card">
              <h3>🤖 Your AI Access Level</h3>
              {userAccess ? (
                <div style={{marginBottom: '20px'}}>
                  <h4 style={{color: '#2d3748', fontSize: '0.9rem', marginBottom: '10px'}}>
                    Based on your role ({userAccess.user_role}):
                  </h4>
                  
                  {/* Dynamic provider access based on backend logic */}
                  {Object.entries(userAccess.providers).map(([key, provider]) => {
                    const colorMap = {
                      'green': { bg: '#f0fff4', text: '#2f855a', icon: '✅' },
                      'red': { bg: '#fed7d7', text: '#c53030', icon: '❌' },
                      'orange': { bg: '#fff4e6', text: '#ed8936', icon: '⚠️' }
                    };
                    const colors = colorMap[provider.color] || colorMap['green'];
                    
                    return (
                      <div key={key} style={{
                        display: 'flex', 
                        justifyContent: 'space-between', 
                        alignItems: 'center',
                        padding: '8px 12px',
                        marginBottom: '5px',
                        background: colors.bg,
                        borderRadius: '6px',
                        fontSize: '0.8rem'
                      }}>
                        <span style={{fontWeight: 'bold'}}>{provider.name}</span>
                        <span style={{color: colors.text}}>
                          {colors.icon} {provider.status}
                        </span>
                      </div>
                    );
                  })}
                  
                  <div style={{
                    background: '#f7fafc',
                    border: '1px solid #e2e8f0',
                    borderRadius: '6px',
                    padding: '10px',
                    marginTop: '10px',
                    fontSize: '0.75rem',
                    color: '#4a5568'
                  }}>
                    <strong>💡 Routing Priority:</strong><br/>
                    {userAccess.routing_priority?.map((rule, index) => (
                      <div key={index}>{rule}</div>
                    ))}
                  </div>
                </div>
              ) : (
                <div style={{padding: '20px', textAlign: 'center', color: '#666'}}>
                  Loading access information...
                </div>
              )}
              
              <h4 style={{color: '#2d3748', fontSize: '0.9rem', marginBottom: '10px'}}>🔍 Natural Language Queries:</h4>
              <p style={{fontSize: '0.8rem', color: '#666', marginBottom: '10px'}}>
                Ask questions in plain English:
              </p>
              {demoNaturalQueries[user.email]?.map((demoQuery, index) => (
                <button
                  key={index}
                  onClick={() => setNaturalQuery(demoQuery)}
                  className="btn"
                  style={{
                    marginBottom: '8px',
                    fontSize: '0.8rem',
                    padding: '6px 10px',
                    background: '#ebf8ff',
                    color: '#2b6cb0',
                    border: '1px solid #90cdf4'
                  }}
                >
                  {demoQuery}
                </button>
              ))}
              
            </div>

            <div className="card">
              <h3>📝 SQL Queries</h3>
              <p style={{fontSize: '0.8rem', color: '#4a5568', marginBottom: '12px'}}>
                Quick access to pre-built queries:
              </p>
              
              <div style={{marginBottom: '15px'}}>
                <h4 style={{color: '#2d3748', fontSize: '0.85rem', marginBottom: '8px'}}>✅ Safe Queries</h4>
                {demoQueries[user.email]?.map((demoQuery, index) => (
                  <button
                    key={index}
                    onClick={() => setQuery(demoQuery)}
                    className="blocked-query-btn"
                    style={{
                      background: '#f0fff4',
                      borderColor: '#9ae6b4',
                      color: '#2f855a',
                      marginBottom: '4px',
                      fontSize: '0.75rem'
                    }}
                  >
                    {demoQuery.substring(0, 35)}...
                  </button>
                ))}
              </div>

              <div>
                <h4 style={{color: '#dc2626', fontSize: '0.85rem', marginBottom: '8px'}}>🚫 Policy Tests</h4>
                <p style={{fontSize: '0.7rem', color: '#7f1d1d', marginBottom: '8px'}}>
                  Test security enforcement by severity:
                </p>
                
                {/* Critical Severity */}
                <div style={{fontSize: '0.65rem', color: '#dc2626', fontWeight: '500', marginBottom: '3px'}}>🔴 Critical</div>
                <button 
                  className="blocked-query-btn"
                  onClick={() => {setQuery("DROP TABLE customers;"); executeQuery();}}
                  style={{background: '#fef2f2', borderColor: '#fecaca', marginBottom: '6px', fontSize: '0.75rem'}}
                >
                  DROP TABLE customers;
                </button>
                
                {/* High Severity */}
                <div style={{fontSize: '0.65rem', color: '#ea580c', fontWeight: '500', marginBottom: '3px'}}>🟠 High</div>
                <button 
                  className="blocked-query-btn"
                  onClick={() => {setQuery("DELETE FROM customers;"); executeQuery();}}
                  style={{background: '#fff7ed', borderColor: '#fdba74', marginBottom: '6px', fontSize: '0.75rem'}}
                >
                  DELETE FROM customers;
                </button>
                
                {/* Medium Severity */}
                <div style={{fontSize: '0.65rem', color: '#d97706', fontWeight: '500', marginBottom: '3px'}}>🟡 Medium</div>
                <button 
                  className="blocked-query-btn"
                  onClick={() => {setQuery("SELECT * FROM customers LIMIT 1000;"); executeQuery();}}
                  style={{background: '#fffbeb', borderColor: '#fbbf24', marginBottom: '4px', fontSize: '0.75rem'}}
                >
                  SELECT * FROM customers LIMIT 1000;
                </button>
              </div>
            </div>

          </div>

          <div className="main-content">
            <div className="card">
              <h3>🤖 Natural Language Interface</h3>
              <div className="form-group">
                <label>Ask in Plain English:</label>
                <textarea
                  value={naturalQuery}
                  onChange={(e) => setNaturalQuery(e.target.value)}
                  placeholder="Show me all high priority tickets from premium customers..."
                  rows={3}
                />
              </div>
              <button 
                onClick={executeNaturalQuery} 
                disabled={loading || !naturalQuery.trim()}
                className="btn"
                style={{marginBottom: '20px'}}
              >
                {loading ? 'Processing...' : '🧠 Ask AI'}
              </button>
            </div>

            <div className="card">
              <h3>🔍 SQL Query Interface</h3>
              <div className="form-group">
                <label>Enter SQL Query:</label>
                <textarea
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="SELECT * FROM customers WHERE..."
                  rows={4}
                />
              </div>
              <button 
                onClick={executeQuery} 
                disabled={loading || !query.trim()}
                className="btn"
              >
                {loading ? 'Executing...' : 'Execute Query'}
              </button>

              {error && <div className="error">{error}</div>}
            </div>

            {queryResult && (
              <div className="card">
                <h3>📈 Query Results</h3>
                <p><strong>Rows returned:</strong> {queryResult.count}</p>
                
                
                <div className={`llm-provider-box ${queryResult.llm_provider ? 'provider-changing' : ''}`}>
                  {queryResult.llm_provider && <div className="provider-change-indicator"></div>}
                  <h4 style={{margin: '0 0 8px 0', color: '#2d3748'}}>🤖 LLM Orchestration</h4>
                  {queryResult.llm_provider ? (
                    <div>
                      <div style={{display: 'flex', flexWrap: 'wrap', gap: '15px', fontSize: '14px'}}>
                        <div>
                          <strong>Provider:</strong> 
                          <span className={`provider-badge ${queryResult.llm_provider.name}`}>
                            {queryResult.llm_provider.name === 'openai' ? '⚡ OpenAI GPT' : 
                             queryResult.llm_provider.name === 'anthropic' ? '🧠 Anthropic Claude' : 
                             '🔒 Local Model'}
                          </span>
                        </div>
                        <div><strong>Tokens:</strong> {queryResult.llm_provider.tokens_used}</div>
                        <div><strong>Duration:</strong> {queryResult.llm_provider.duration}</div>
                      </div>
                      <div className="routing-reason">
                        <strong>Routing Reason:</strong> {queryResult.llm_provider.reason}
                      </div>
                    </div>
                  ) : (
                    <div style={{fontSize: '14px', color: '#4a5568'}}>
                      <div style={{display: 'flex', alignItems: 'center', gap: '10px'}}>
                        <span style={{
                          padding: '2px 8px',
                          borderRadius: '12px',
                          backgroundColor: '#f1f5f9',
                          color: '#475569'
                        }}>
                          Direct SQL
                        </span>
                        <span>No LLM involved - query executed directly</span>
                      </div>
                    </div>
                  )}
                </div>
                
                {queryResult.pii_detected?.length > 0 && (
                  <div style={{margin: '10px 0'}}>
                    <strong>PII Detected:</strong>{' '}
                    {[...new Set(queryResult.pii_detected)].map((pii, index) => (
                      <span key={`${pii}-${index}`} className="pii-badge">{pii}</span>
                    ))}
                    {queryResult.pii_redacted && (
                      <p style={{color: '#c53030', fontSize: '0.9rem', marginTop: '5px'}}>
                        ⚠️ PII has been redacted based on your permissions
                      </p>
                    )}
                  </div>
                )}

                <div className="query-results">
                  {queryResult.results?.length > 0 ? (
                    <table>
                      <thead>
                        <tr>
                          {Object.keys(queryResult.results[0]).map(key => (
                            <th key={key}>{key}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {queryResult.results.map((row, index) => (
                          <tr key={index}>
                            {Object.values(row).map((value, colIndex) => (
                              <td key={colIndex}>
                                {value !== null ? String(value) : 'NULL'}
                              </td>
                            ))}
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  ) : (
                    <p>No results found.</p>
                  )}
                </div>

                {/* Security Audit Trail - Always show most recent audit log or current query */}
                <div className="security-log">
                  <h4>🔐 Current Query Security Audit</h4>
                  {queryResult?.security_log ? (
                    // Show current query audit trail
                    <>
                      <p style={{fontSize: '0.85rem', color: '#22c55e', marginBottom: '10px', fontStyle: 'italic'}}>
                        ✨ Showing details for the query you just executed
                      </p>
                      <p><strong>User:</strong> {queryResult.security_log.user_email}</p>
                      <p><strong>Query:</strong> {queryResult.security_log.query_executed}</p>
                      <p><strong>Access Granted:</strong> {queryResult.security_log.access_granted ? '✅ Yes' : '❌ No'}</p>
                      {!queryResult.security_log.access_granted && (
                        <p><strong>Query failed:</strong> <span style={{color: '#dc2626'}}>Blocked by policy: {queryResult.block_reason || 'security_violation'}</span></p>
                      )}
                      <p><strong>PII Redacted:</strong> {queryResult.security_log.pii_redacted ? '✅ Yes' : '❌ No'}</p>
                      <p><strong>Timestamp:</strong> {new Date(queryResult.security_log.timestamp).toLocaleString()} ({Intl.DateTimeFormat().resolvedOptions().timeZone})</p>
                    </>
                  ) : auditLogs.length > 0 ? (
                    // Show most recent audit log from history
                    <>
                      <p style={{fontSize: '0.85rem', color: '#6366f1', marginBottom: '10px', fontStyle: 'italic'}}>
                        📋 Showing your most recent query from history (no new query executed)
                      </p>
                      <p><strong>User:</strong> {auditLogs[0].user_email}</p>
                      <p><strong>Query:</strong> {auditLogs[0].query_text.substring(0, 100)}{auditLogs[0].query_text.length > 100 ? '...' : ''}</p>
                      <p><strong>Access Granted:</strong> {auditLogs[0].access_granted ? '✅ Yes' : '❌ No'}</p>
                      {!auditLogs[0].access_granted && (
                        <p><strong>Query failed:</strong> <span style={{color: '#dc2626'}}>Blocked by policy: {auditLogs[0].block_reason || 'security_violation'}</span></p>
                      )}
                      <p><strong>PII Detected:</strong> {auditLogs[0].pii_detected?.length > 0 ? '✅ Yes (' + [...new Set(auditLogs[0].pii_detected)].join(', ') + ')' : '❌ No'}</p>
                      <p><strong>Timestamp:</strong> {new Date(auditLogs[0].created_at).toLocaleString()} ({Intl.DateTimeFormat().resolvedOptions().timeZone})</p>
                    </>
                  ) : (
                    <p style={{color: '#666', fontStyle: 'italic'}}>No audit logs available yet. Execute a query to see security audit details.</p>
                  )}
                </div>
              </div>
            )}

            {/* Recent Audit Logs - Shows 2nd-5th most recent entries to avoid duplication */}
            <div className="card">
              <h3>📊 Previous Query History</h3>
              <p style={{fontSize: '0.9rem', color: '#4a5568', marginBottom: '15px'}}>
                Historical queries and security events (most recent activity shown in Current Query Security Audit above):
              </p>
              <div className="audit-log">
                {auditLogs.length > 1 ? auditLogs.slice(1, 5).map(log => (
                  <div key={log.id} className="audit-entry">
                    <h4>{log.user_email}</h4>
                    <p><strong>Query:</strong> {log.query_text.substring(0, 80)}...</p>
                    <p><strong>Results:</strong> {log.results_count} rows</p>
                    {log.pii_detected?.length > 0 && (
                      <p><strong>PII Detected:</strong> {[...new Set(log.pii_detected)].join(', ')}</p>
                    )}
                    {!log.access_granted && (
                      <p><strong>Query failed:</strong> <span style={{color: '#dc2626'}}>Blocked by policy: {log.block_reason || 'security_violation'}</span></p>
                    )}
                    <p><strong>Timestamp:</strong> {new Date(log.created_at).toLocaleString()} ({Intl.DateTimeFormat().resolvedOptions().timeZone})</p>
                  </div>
                )) : (
                  <p style={{color: '#666', fontStyle: 'italic'}}>No additional audit logs available. Execute more queries to see history.</p>
                )}
              </div>
            </div>

          </div>
        </div>
      </div>
      
      {/* Live Monitor Overlay */}
      {showRealtimeMonitor && (
        <LiveMonitor 
          policyMetrics={policyMetrics}
          onClose={() => setShowRealtimeMonitor(false)}
        />
      )}
    </div>
  );
}

function LoginForm({ onLogin, loading, error }) {
  const [email, setEmail] = useState('admin@company.com');
  const [password, setPassword] = useState('AxonFlow2024Demo!');

  const handleSubmit = (e) => {
    e.preventDefault();
    onLogin(email, password);
  };

  const demoUsers = [
    { email: 'admin@company.com', role: 'System Admin', permissions: 'Global access' },
    { email: 'sarah.manager@company.com', role: 'Support Manager', permissions: 'Full PII access' },
    { email: 'john.doe@company.com', role: 'Support Agent (US West)', permissions: 'Limited PII access' },
    { email: 'eu.agent@company.com', role: 'EU Agent', permissions: 'EU data only' }
  ];

  return (
    <div className="container">
      <div className="card">
        <div className="header">
          <h1>🔒 AxonFlow Demo</h1>
          <p>Secure Customer Support AI Platform</p>
          <p style={{fontSize: '1rem', color: '#666', marginTop: '10px'}}>
            Enterprise AI governance with zero-trust data access
          </p>
          <div style={{marginTop: '15px', display: 'flex', justifyContent: 'center'}}>
            <a href="https://www.getaxonflow.com" target="_blank" rel="noopener noreferrer" className="btn" style={{
              display: 'inline-block', 
              textDecoration: 'none', 
              width: 'auto',
              background: '#3182ce',
              padding: '10px 20px',
              color: 'white',
              borderRadius: '6px',
              fontSize: '0.95rem',
              fontWeight: '500'
            }}>
              ℹ️ Learn More About AxonFlow
            </a>
          </div>
        </div>

        <div style={{display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '30px', alignItems: 'start'}}>
          <div>
            <h3 style={{marginBottom: '20px', color: '#2d3748'}}>🚀 Demo Users</h3>
            {demoUsers.map(user => (
              <div 
                key={user.email}
                onClick={() => setEmail(user.email)}
                style={{
                  background: email === user.email ? '#ebf8ff' : '#f7fafc',
                  border: email === user.email ? '2px solid #3182ce' : '1px solid #e2e8f0',
                  borderRadius: '8px',
                  padding: '15px',
                  marginBottom: '10px',
                  cursor: 'pointer',
                  transition: 'all 0.2s'
                }}
              >
                <p style={{fontWeight: 'bold', color: '#2d3748', marginBottom: '5px'}}>
                  {user.role}
                </p>
                <p style={{fontSize: '0.9rem', color: '#4a5568', marginBottom: '5px'}}>
                  {user.email}
                </p>
                <p style={{fontSize: '0.8rem', color: '#718096'}}>
                  {user.permissions}
                </p>
              </div>
            ))}
          </div>

          <div>
            <form onSubmit={handleSubmit} className="login-form">
              <h3 style={{marginBottom: '20px', color: '#2d3748'}}>🔐 Login</h3>
              
              <div className="form-group">
                <label>Email:</label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                />
              </div>

              <div className="form-group">
                <label>Password:</label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />
                <p style={{fontSize: '0.8rem', color: '#718096', marginTop: '5px'}}>
                  Demo password: AxonFlow2024Demo!
                </p>
              </div>

              {error && <div className="error">{error}</div>}

              <button type="submit" disabled={loading} className="btn">
                {loading ? 'Logging in...' : 'Login to Demo'}
              </button>
            </form>

            <div style={{marginTop: '30px', padding: '20px', background: '#f0fff4', borderRadius: '8px', border: '1px solid #9ae6b4'}}>
              <h4 style={{color: '#2f855a', marginBottom: '10px'}}>🎯 Demo Features</h4>
              <ul style={{fontSize: '0.9rem', color: '#2d3748', lineHeight: '1.6'}}>
                <li>Row-level security by region</li>
                <li>Automatic PII detection & redaction</li>
                <li>Real-time audit logging</li>
                <li>Permission-based data access</li>
                <li>Compliance dashboard</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;