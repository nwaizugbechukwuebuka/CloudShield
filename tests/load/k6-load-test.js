// K6 Load Testing Script for CloudShield API
// Run with: k6 run k6-load-test.js

import http from 'k6/http';
import { check, group, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const loginDuration = new Trend('login_duration');
const findingsDuration = new Trend('findings_duration');
const scanDuration = new Trend('scan_duration');
const apiCalls = new Counter('api_calls_total');

// Test configuration
export const options = {
  stages: [
    { duration: '2m', target: 50 },   // Ramp up to 50 users
    { duration: '5m', target: 50 },   // Stay at 50 users
    { duration: '2m', target: 100 },  // Ramp up to 100 users
    { duration: '5m', target: 100 },  // Stay at 100 users
    { duration: '2m', target: 200 },  // Spike to 200 users
    { duration: '3m', target: 200 },  // Stay at spike
    { duration: '2m', target: 0 },    // Ramp down
  ],
  thresholds: {
    http_req_duration: ['p(95)<2000', 'p(99)<5000'], // 95% < 2s, 99% < 5s
    http_req_failed: ['rate<0.05'],                   // Error rate < 5%
    errors: ['rate<0.1'],                              // Custom error rate < 10%
    login_duration: ['p(95)<1000'],                    // Login < 1s
    findings_duration: ['p(95)<500'],                  // Findings list < 500ms
  },
};

const BASE_URL = __ENV.API_URL || 'http://localhost:8000';
let authToken = '';

// Setup: Create test users
export function setup() {
  console.log('Setting up test environment...');
  return { baseUrl: BASE_URL };
}

// Main test execution
export default function(data) {
  // Login
  group('Authentication', function() {
    const loginRes = http.post(
      `${data.baseUrl}/auth/login`,
      JSON.stringify({
        email: `loadtest_${__VU}@example.com`,
        password: 'LoadTest123!'
      }),
      {
        headers: { 'Content-Type': 'application/json' },
        tags: { name: 'Login' }
      }
    );

    const loginSuccess = check(loginRes, {
      'login status is 200': (r) => r.status === 200,
      'login has token': (r) => r.json('access_token') !== undefined,
    });

    errorRate.add(!loginSuccess);
    loginDuration.add(loginRes.timings.duration);
    apiCalls.add(1);

    if (loginSuccess) {
      authToken = loginRes.json('access_token');
    } else {
      console.error(`Login failed for VU ${__VU}: ${loginRes.status}`);
      return;
    }
  });

  const headers = {
    'Authorization': `Bearer ${authToken}`,
    'Content-Type': 'application/json'
  };

  sleep(1);

  // Dashboard Overview
  group('Dashboard', function() {
    const dashboardRes = http.get(
      `${data.baseUrl}/dashboard/overview`,
      { headers, tags: { name: 'Dashboard Overview' } }
    );

    check(dashboardRes, {
      'dashboard status is 200': (r) => r.status === 200,
      'dashboard has summary': (r) => r.json('summary') !== undefined,
    });

    errorRate.add(dashboardRes.status !== 200);
    apiCalls.add(1);
  });

  sleep(2);

  // List Findings
  group('Findings', function() {
    const findingsRes = http.get(
      `${data.baseUrl}/findings?risk_level=critical&limit=50`,
      { headers, tags: { name: 'List Findings' } }
    );

    const findingsSuccess = check(findingsRes, {
      'findings status is 200': (r) => r.status === 200,
      'findings response time < 500ms': (r) => r.timings.duration < 500,
      'findings has data': (r) => r.json('findings') !== undefined,
    });

    errorRate.add(!findingsSuccess);
    findingsDuration.add(findingsRes.timings.duration);
    apiCalls.add(1);

    // Get finding details
    if (findingsSuccess && findingsRes.json('findings').length > 0) {
      const findingId = findingsRes.json('findings.0.id');
      const detailRes = http.get(
        `${data.baseUrl}/findings/${findingId}`,
        { headers, tags: { name: 'Get Finding Details' } }
      );

      check(detailRes, {
        'finding detail status is 200': (r) => r.status === 200,
      });

      apiCalls.add(1);
    }
  });

  sleep(1);

  // List Integrations
  group('Integrations', function() {
    const integrationsRes = http.get(
      `${data.baseUrl}/integrations`,
      { headers, tags: { name: 'List Integrations' } }
    );

    check(integrationsRes, {
      'integrations status is 200': (r) => r.status === 200,
      'integrations response time < 300ms': (r) => r.timings.duration < 300,
    });

    errorRate.add(integrationsRes.status !== 200);
    apiCalls.add(1);
  });

  sleep(2);

  // Scan Operations (lighter load)
  if (__ITER % 5 === 0) {  // Only 20% of iterations
    group('Scanning', function() {
      // List scans
      const scansRes = http.get(
        `${data.baseUrl}/scans?limit=20`,
        { headers, tags: { name: 'List Scans' } }
      );

      check(scansRes, {
        'scans status is 200': (r) => r.status === 200,
      });

      errorRate.add(scansRes.status !== 200);
      apiCalls.add(1);
    });
  }

  sleep(1);

  // Risk Trends Analytics
  group('Analytics', function() {
    const trendsRes = http.get(
      `${data.baseUrl}/dashboard/risk-trends?period=30d`,
      { headers, tags: { name: 'Risk Trends' } }
    );

    check(trendsRes, {
      'trends status is 200': (r) => r.status === 200,
      'trends has data points': (r) => r.json('data_points') !== undefined,
    });

    errorRate.add(trendsRes.status !== 200);
    apiCalls.add(1);
  });

  sleep(1);
}

// Spike test - Sudden traffic surge
export function spikeTest() {
  const res = http.get(`${BASE_URL}/health`);
  check(res, {
    'spike - health check OK': (r) => r.status === 200,
  });
}

// Stress test configuration
export const stressOptions = {
  stages: [
    { duration: '2m', target: 100 },
    { duration: '5m', target: 100 },
    { duration: '2m', target: 300 },
    { duration: '5m', target: 300 },
    { duration: '2m', target: 500 },
    { duration: '5m', target: 500 },
    { duration: '5m', target: 0 },
  ],
};

// Soak test configuration (long duration, moderate load)
export const soakOptions = {
  stages: [
    { duration: '5m', target: 100 },
    { duration: '4h', target: 100 },
    { duration: '5m', target: 0 },
  ],
};

// Teardown
export function teardown(data) {
  console.log('Test completed. Check k6 report for results.');
}
