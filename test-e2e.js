#!/usr/bin/env node

/**
 * AxonFlow Demo - End-to-End Test Suite
 * Tests all users and all queries (both natural language and SQL)
 * Run before deployment to ensure everything works
 */

const axios = require('axios');

// Configuration
const API_BASE = process.env.API_BASE || 'http://localhost:8080';
const TIMEOUT = 30000; // 30 seconds

// Test users with their expected queries
const TEST_USERS = {
  'john.doe@company.com': {
    name: 'John Doe (Agent)',
    password: 'AxonFlow2024Demo!',
    naturalLanguageQueries: [
      'Show ticket statistics by status',  // Regular (no PII) - routes to Local (agent role)
      'Show customer count by region',  // Regular (no PII) - routes to Local (agent role)
      'Find customer with SSN 123-45-6789',  // PII - routes to Local
      'Show customers with phone numbers',  // PII - routes to Local
      'Show confidential enterprise customer data'  // Confidential - routes to Anthropic
    ],
    sqlQueries: [
      'SELECT * FROM customers WHERE region = \'us-west\' LIMIT 10',
      'SELECT * FROM support_tickets WHERE status = \'open\' LIMIT 5',
      'SELECT name, email FROM customers WHERE support_tier = \'premium\''
    ]
  },
  'sarah.manager@company.com': {
    name: 'Sarah Manager',
    password: 'AxonFlow2024Demo!',
    naturalLanguageQueries: [
      'Show ticket count by priority level',  // OpenAI (no PII)
      'Show customer statistics by support tier',  // OpenAI (no PII)
      'Find customer with SSN 123-45-6789',  // Demo Flow 2 (PII test) - Local
      'Show confidential enterprise customer data',  // Anthropic trigger
      'Find internal escalation tickets'  // Anthropic trigger
    ],
    sqlQueries: [
      'SELECT * FROM customers WHERE support_tier = \'enterprise\'',
      'SELECT * FROM support_tickets WHERE priority = \'high\'',
      'SELECT customer_id, title, description FROM support_tickets WHERE assigned_to LIKE \'%manager%\''
    ]
  },
  'admin@company.com': {
    name: 'Admin User',
    password: 'AxonFlow2024Demo!',
    naturalLanguageQueries: [
      'Show me system usage statistics',
      'Find all customers across all regions',
      'Which users are querying the most data?'
    ],
    sqlQueries: [
      'SELECT * FROM customers LIMIT 10',
      'SELECT * FROM support_tickets WHERE created_at > CURRENT_DATE - INTERVAL \'7 days\'',
      'SELECT user_email, COUNT(*) as query_count FROM audit_log GROUP BY user_email'
    ]
  },
  'eu.agent@company.com': {
    name: 'EU Agent',
    password: 'AxonFlow2024Demo!',
    naturalLanguageQueries: [
      'Show all EU customers',  // GDPR - routes to Local
      'Find customer with phone number 555-0123',  // PII - routes to Local  
      'Show premium customers',  // Regular - routes to Local (EU region)
      'Show confidential enterprise customer data',  // Confidential - routes to Local (EU override)
      'Show me all open support tickets'  // Regular - routes to Local (EU region)
    ],
    sqlQueries: [
      'SELECT * FROM customers WHERE region = \'eu-west\' LIMIT 10',
      'SELECT * FROM support_tickets WHERE status = \'open\' LIMIT 5'
    ]
  }
};

// Test results tracking
let testResults = {
  passed: 0,
  failed: 0,
  errors: []
};

// Utility functions
function logTest(message, success = true) {
  const icon = success ? '✅' : '❌';
  const color = success ? '\x1b[32m' : '\x1b[31m';
  console.log(`${color}${icon} ${message}\x1b[0m`);
}

function logSection(message) {
  console.log(`\n\x1b[34m🔍 ${message}\x1b[0m`);
}

function logError(message, error) {
  console.log(`\x1b[31m❌ ${message}\x1b[0m`);
  if (error) {
    console.log(`   Error: ${error.message || error}`);
    testResults.errors.push({ message, error: error.message || error });
  }
  testResults.failed++;
}

function logSuccess(message) {
  logTest(message, true);
  testResults.passed++;
}

// Main test functions
async function loginUser(email, password) {
  try {
    const response = await axios.post(`${API_BASE}/api/login`, {
      email,
      password
    }, { timeout: TIMEOUT });
    
    return {
      token: response.data.token,
      user: response.data.user
    };
  } catch (error) {
    throw new Error(`Login failed: ${error.response?.data || error.message}`);
  }
}

async function testNaturalLanguageQuery(token, query, userEmail) {
  try {
    const response = await axios.post(`${API_BASE}/api/llm/natural-query`, {
      query: query.trim()
    }, {
      headers: { Authorization: `Bearer ${token}` },
      timeout: TIMEOUT
    });
    
    // Check if response has expected structure
    if (!response.data || typeof response.data.count === 'undefined') {
      throw new Error('Invalid response structure');
    }
    
    const provider = response.data.llm_provider?.name || 'direct';
    const count = response.data.count;
    
    return {
      success: true,
      provider,
      count,
      message: `Query executed successfully (${count} results, provider: ${provider})`
    };
  } catch (error) {
    throw new Error(`Natural language query failed: ${error.response?.data || error.message}`);
  }
}

async function testSQLQuery(token, query, userEmail) {
  try {
    const response = await axios.post(`${API_BASE}/api/query`, {
      query: query.trim()
    }, {
      headers: { Authorization: `Bearer ${token}` },
      timeout: TIMEOUT
    });
    
    // Check if response has expected structure
    if (!response.data || typeof response.data.count === 'undefined') {
      throw new Error('Invalid response structure');
    }
    
    const count = response.data.count;
    const piiDetected = response.data.pii_detected?.length || 0;
    
    return {
      success: true,
      count,
      piiDetected,
      message: `Query executed successfully (${count} results${piiDetected > 0 ? `, ${piiDetected} PII detected` : ''})`
    };
  } catch (error) {
    throw new Error(`SQL query failed: ${error.response?.data || error.message}`);
  }
}

async function testUserAccess(token, userEmail) {
  try {
    const response = await axios.get(`${API_BASE}/api/llm/user-access`, {
      headers: { Authorization: `Bearer ${token}` },
      timeout: TIMEOUT
    });
    
    if (!response.data || !response.data.providers) {
      throw new Error('Invalid user access response');
    }
    
    return {
      success: true,
      providers: Object.keys(response.data.providers).length,
      message: `User access validated (${Object.keys(response.data.providers).length} providers available)`
    };
  } catch (error) {
    throw new Error(`User access check failed: ${error.response?.data || error.message}`);
  }
}

async function testDashboard(token, userEmail) {
  try {
    const response = await axios.get(`${API_BASE}/api/dashboard`, {
      headers: { Authorization: `Bearer ${token}` },
      timeout: TIMEOUT
    });
    
    if (!response.data || typeof response.data.total_queries === 'undefined') {
      throw new Error('Invalid dashboard response');
    }
    
    return {
      success: true,
      totalQueries: response.data.total_queries,
      complianceScore: response.data.compliance_score,
      message: `Dashboard loaded (${response.data.total_queries} queries, ${response.data.compliance_score?.toFixed(1)}% compliance)`
    };
  } catch (error) {
    throw new Error(`Dashboard failed: ${error.response?.data || error.message}`);
  }
}

async function testAPIHealth() {
  try {
    const response = await axios.get(`${API_BASE}/health`, { timeout: TIMEOUT });
    
    if (response.data?.status !== 'healthy') {
      throw new Error('API not healthy');
    }
    
    return {
      success: true,
      message: 'API health check passed'
    };
  } catch (error) {
    throw new Error(`Health check failed: ${error.response?.data || error.message}`);
  }
}

// Main test runner
async function runTests() {
  console.log('\x1b[36m🚀 AxonFlow Demo - End-to-End Test Suite\x1b[0m');
  console.log(`\x1b[36m📊 Testing against: ${API_BASE}\x1b[0m`);
  console.log(`\x1b[36m⏱️  Timeout: ${TIMEOUT/1000}s per request\x1b[0m`);
  
  // Test API Health first
  logSection('API Health Check');
  try {
    const healthResult = await testAPIHealth();
    logSuccess(healthResult.message);
  } catch (error) {
    logError('API Health Check', error);
    console.log('\n❌ API is not healthy, aborting tests');
    return false;
  }
  
  // Test each user
  for (const [email, userData] of Object.entries(TEST_USERS)) {
    logSection(`Testing User: ${userData.name} (${email})`);
    
    let token, user;
    
    // 1. Test Login
    try {
      const loginResult = await loginUser(email, userData.password);
      token = loginResult.token;
      user = loginResult.user;
      logSuccess(`Login successful for ${userData.name}`);
    } catch (error) {
      logError(`Login failed for ${userData.name}`, error);
      continue; // Skip other tests for this user
    }
    
    // 2. Test Dashboard Access
    try {
      const dashboardResult = await testDashboard(token, email);
      logSuccess(`Dashboard: ${dashboardResult.message}`);
    } catch (error) {
      logError(`Dashboard failed for ${userData.name}`, error);
    }
    
    // 3. Test User Access Endpoint
    try {
      const accessResult = await testUserAccess(token, email);
      logSuccess(`User Access: ${accessResult.message}`);
    } catch (error) {
      logError(`User access failed for ${userData.name}`, error);
    }
    
    // 4. Test Natural Language Queries
    console.log(`\n   🧠 Testing Natural Language Queries:`);
    for (let i = 0; i < userData.naturalLanguageQueries.length; i++) {
      const query = userData.naturalLanguageQueries[i];
      try {
        const result = await testNaturalLanguageQuery(token, query, email);
        logSuccess(`   NL Query ${i+1}: ${result.message}`);
      } catch (error) {
        logError(`   NL Query ${i+1} failed: "${query}"`, error);
      }
    }
    
    // 5. Test SQL Queries
    console.log(`\n   📝 Testing SQL Queries:`);
    for (let i = 0; i < userData.sqlQueries.length; i++) {
      const query = userData.sqlQueries[i];
      try {
        const result = await testSQLQuery(token, query, email);
        logSuccess(`   SQL Query ${i+1}: ${result.message}`);
      } catch (error) {
        logError(`   SQL Query ${i+1} failed: "${query}"`, error);
      }
    }
  }
  
  // Final Results
  console.log('\n' + '='.repeat(60));
  console.log('\x1b[36m📊 Test Results Summary\x1b[0m');
  console.log('='.repeat(60));
  
  const total = testResults.passed + testResults.failed;
  const successRate = total > 0 ? ((testResults.passed / total) * 100).toFixed(1) : 0;
  
  console.log(`✅ Passed: ${testResults.passed}`);
  console.log(`❌ Failed: ${testResults.failed}`);
  console.log(`📈 Success Rate: ${successRate}%`);
  
  if (testResults.failed > 0) {
    console.log('\n🔍 Failed Tests Summary:');
    testResults.errors.forEach((error, index) => {
      console.log(`   ${index + 1}. ${error.message}`);
      console.log(`      Error: ${error.error}`);
    });
  }
  
  const overallSuccess = testResults.failed === 0;
  const statusIcon = overallSuccess ? '🎉' : '⚠️';
  const statusColor = overallSuccess ? '\x1b[32m' : '\x1b[33m';
  const statusMessage = overallSuccess ? 'ALL TESTS PASSED - READY FOR DEPLOYMENT!' : 'SOME TESTS FAILED - REVIEW REQUIRED';
  
  console.log(`\n${statusColor}${statusIcon} ${statusMessage}\x1b[0m`);
  
  return overallSuccess;
}

// Export for use as module or run directly
if (require.main === module) {
  runTests().then(success => {
    process.exit(success ? 0 : 1);
  }).catch(error => {
    console.error('\n❌ Test runner crashed:', error.message);
    process.exit(1);
  });
}

module.exports = { runTests, TEST_USERS };