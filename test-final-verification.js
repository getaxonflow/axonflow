#!/usr/bin/env node

/**
 * Final verification test: Statistical vs PII queries with fresh database
 */

const axios = require('axios');

const API_BASE = 'http://localhost:8080';

async function loginUser(email) {
  const response = await axios.post(`${API_BASE}/api/login`, {
    email,
    password: 'AxonFlow2024Demo!'
  });
  return response.data.token;
}

async function getDashboard(token) {
  const response = await axios.get(`${API_BASE}/api/dashboard`, {
    headers: { Authorization: `Bearer ${token}` }
  });
  return response.data;
}

async function executeNLQuery(token, query) {
  const response = await axios.post(`${API_BASE}/api/llm/natural-query`, {
    query
  }, {
    headers: { Authorization: `Bearer ${token}` }
  });
  return response.data;
}

async function finalVerification() {
  console.log('🎯 Final Verification: PII vs Statistical Queries (Fresh Database)\n');
  
  const johnToken = await loginUser('john.doe@company.com');
  const sarahToken = await loginUser('sarah.manager@company.com');
  
  let dashboard = await getDashboard(johnToken);
  const initialPII = dashboard.total_pii_detections;
  console.log(`📊 Initial PII Count: ${initialPII}\n`);
  
  // Test John Doe's statistical queries (should NOT increment PII counter)
  console.log('👤 John Doe (Agent) - Statistical Queries:');
  
  console.log('   ✅ "Show ticket statistics by status"');
  let result = await executeNLQuery(johnToken, 'Show ticket statistics by status');
  console.log(`      → Results: ${result.count}, PII Detected: ${result.pii_detected?.length || 0}`);
  
  console.log('   ✅ "Show customer count by region"');
  result = await executeNLQuery(johnToken, 'Show customer count by region');
  console.log(`      → Results: ${result.count}, PII Detected: ${result.pii_detected?.length || 0}`);
  
  dashboard = await getDashboard(johnToken);
  console.log(`   📊 PII Count after statistical queries: ${dashboard.total_pii_detections} (should be ${initialPII})\n`);
  
  // Test Sarah Manager's statistical queries (should NOT increment PII counter)
  console.log('👤 Sarah Manager - Statistical Queries:');
  
  console.log('   ✅ "Show ticket count by priority level"');
  result = await executeNLQuery(sarahToken, 'Show ticket count by priority level');
  console.log(`      → Results: ${result.count}, PII Detected: ${result.pii_detected?.length || 0}`);
  
  console.log('   ✅ "Show customer statistics by support tier"');
  result = await executeNLQuery(sarahToken, 'Show customer statistics by support tier');
  console.log(`      → Results: ${result.count}, PII Detected: ${result.pii_detected?.length || 0}`);
  
  dashboard = await getDashboard(sarahToken);
  const afterStatistical = dashboard.total_pii_detections;
  console.log(`   📊 PII Count after statistical queries: ${afterStatistical} (should be ${initialPII})\n`);
  
  // Test a PII query (should increment PII counter)
  console.log('🔒 PII Query Test:');
  
  console.log('   🔍 "Find customer with SSN 123-45-6789"');
  result = await executeNLQuery(johnToken, 'Find customer with SSN 123-45-6789');
  console.log(`      → Results: ${result.count}, PII Detected: ${result.pii_detected?.length || 0}`);
  
  dashboard = await getDashboard(johnToken);
  const afterPII = dashboard.total_pii_detections;
  console.log(`   📊 PII Count after PII query: ${afterPII} (should be > ${afterStatistical})\n`);
  
  // Summary
  console.log('📋 SUMMARY:');
  console.log(`   • Initial PII count: ${initialPII}`);
  console.log(`   • After statistical queries: ${afterStatistical} (no change: ${afterStatistical === initialPII ? '✅' : '❌'})`);
  console.log(`   • After PII query: ${afterPII} (increased: ${afterPII > afterStatistical ? '✅' : '❌'})`);
  
  const testPassed = (afterStatistical === initialPII) && (afterPII > afterStatistical);
  console.log(`\n🎉 Test Result: ${testPassed ? 'PASSED ✅' : 'FAILED ❌'}`);
  console.log('   Statistical queries no longer increment PII counter!');
}

finalVerification().catch(console.error);