# Load Testing Guide for CloudShield

## Overview

This guide provides comprehensive instructions for load testing CloudShield using Locust and K6.

## Prerequisites

- Python 3.8+ (for Locust)
- Node.js 14+ (for K6)
- Access to CloudShield API

## Installation

### Locust

```bash
pip install locust
```

### K6

**macOS:**
```bash
brew install k6
```

**Linux:**
```bash
sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D69
echo "deb https://dl.k6.io/deb stable main" | sudo tee /etc/apt/sources.list.d/k6.list
sudo apt-get update
sudo apt-get install k6
```

**Windows:**
```powershell
choco install k6
```

## Running Tests

### Locust Tests

**Basic Load Test:**
```bash
cd tests/load
locust -f locustfile.py --host=http://localhost:8000
```

Then open http://localhost:8089 and configure:
- Number of users: 100
- Spawn rate: 10 users/second

**Headless Mode:**
```bash
locust -f locustfile.py --host=http://localhost:8000 \
  --users 100 --spawn-rate 10 --run-time 10m --headless
```

**Generate HTML Report:**
```bash
locust -f locustfile.py --host=http://localhost:8000 \
  --users 100 --spawn-rate 10 --run-time 10m --headless \
  --html=load-test-report.html
```

### K6 Tests

**Standard Load Test:**
```bash
cd tests/load
k6 run k6-load-test.js
```

**With Custom URL:**
```bash
k6 run -e API_URL=https://api.cloudshield.io k6-load-test.js
```

**Stress Test:**
```bash
k6 run --vus 500 --duration 30s k6-load-test.js
```

**Generate JSON Report:**
```bash
k6 run --out json=test-results.json k6-load-test.js
```

**With InfluxDB Output (for Grafana):**
```bash
k6 run --out influxdb=http://localhost:8086/k6 k6-load-test.js
```

## Test Scenarios

### 1. Baseline Test (Current Capacity)
- **Users:** 50
- **Duration:** 10 minutes
- **Purpose:** Establish baseline performance metrics

```bash
locust -f locustfile.py --host=http://localhost:8000 \
  --users 50 --spawn-rate 5 --run-time 10m --headless
```

### 2. Load Test (Expected Traffic)
- **Users:** 100-200
- **Duration:** 30 minutes
- **Purpose:** Test under expected production load

```bash
locust -f locustfile.py --host=http://localhost:8000 \
  --users 200 --spawn-rate 10 --run-time 30m --headless
```

### 3. Stress Test (Peak Traffic)
- **Users:** 500-1000
- **Duration:** 15 minutes
- **Purpose:** Find breaking point

```bash
k6 run --vus 1000 --duration 15m k6-load-test.js
```

### 4. Spike Test (Sudden Traffic)
- **Pattern:** 0 → 500 users in 1 minute
- **Duration:** 10 minutes
- **Purpose:** Test auto-scaling and recovery

```bash
k6 run k6-load-test.js  # Uses spike configuration
```

### 5. Soak Test (Endurance)
- **Users:** 100
- **Duration:** 4 hours
- **Purpose:** Detect memory leaks and degradation

```bash
locust -f locustfile.py --host=http://localhost:8000 \
  --users 100 --spawn-rate 10 --run-time 4h --headless
```

## Performance Targets

### Response Time Targets
| Endpoint | P50 | P95 | P99 | Max |
|----------|-----|-----|-----|-----|
| `/health` | 10ms | 25ms | 50ms | 100ms |
| `/auth/login` | 100ms | 200ms | 500ms | 1000ms |
| `/findings` | 80ms | 200ms | 400ms | 800ms |
| `/scans/start` | 150ms | 300ms | 600ms | 1200ms |
| `/dashboard/overview` | 120ms | 250ms | 500ms | 1000ms |

### Throughput Targets
- **Requests/second:** 500+ (sustained)
- **Concurrent users:** 1000+
- **Error rate:** < 1%

### Resource Targets
- **CPU usage:** < 70% average
- **Memory usage:** < 80%
- **Database connections:** < 80% of pool

## Monitoring During Tests

### Real-time Monitoring

**1. Prometheus Metrics:**
```bash
# Access metrics endpoint
curl http://localhost:8000/metrics
```

**2. Grafana Dashboards:**
- Navigate to http://localhost:3000
- Open "CloudShield Load Testing" dashboard

**3. System Resources:**
```bash
# Monitor system resources
htop  # or top
```

**4. Database Performance:**
```bash
# PostgreSQL connections
psql -c "SELECT count(*) FROM pg_stat_activity;"

# Slow queries
psql -c "SELECT query, calls, total_time FROM pg_stat_statements ORDER BY total_time DESC LIMIT 10;"
```

## Analyzing Results

### Locust Reports

Key metrics to review:
- **Total Requests:** Total number of requests made
- **Failures:** Number and percentage of failed requests
- **Median Response Time:** 50th percentile
- **95th Percentile:** 95% of requests completed within this time
- **RPS:** Requests per second (throughput)
- **Users:** Number of concurrent users

### K6 Results

```
✓ login status is 200................: 100.00%
✓ findings response time < 500ms.....: 98.50%
✓ errors.............................: 2.3%

http_req_duration..............: avg=245ms  min=45ms  med=180ms  max=2.3s  p(90)=450ms p(95)=680ms
http_req_failed................: 2.3%
http_reqs......................: 45678 (761.3/s)
```

### Key Indicators

**✅ Good Performance:**
- P95 response time < target
- Error rate < 1%
- Throughput meets or exceeds target
- CPU and memory stable

**⚠️ Needs Optimization:**
- P95 response time 1.5-2x target
- Error rate 1-5%
- Throughput below target
- Resource usage > 80%

**❌ Critical Issues:**
- P95 response time > 2x target
- Error rate > 5%
- System crashes or OOM errors
- Database connection exhaustion

## Performance Optimization Tips

### Backend Optimization
1. **Database Query Optimization:**
   - Add indexes on frequently queried columns
   - Use connection pooling
   - Implement query result caching

2. **API Response Caching:**
   - Cache expensive computations
   - Use Redis for session and data caching
   - Implement ETags for conditional requests

3. **Async Processing:**
   - Move heavy operations to background tasks
   - Use Celery for long-running scans
   - Implement job queuing

### Infrastructure Optimization
1. **Horizontal Scaling:**
   - Add more API server instances
   - Use load balancer (Nginx/HAProxy)
   - Scale Celery workers

2. **Database Optimization:**
   - Set up read replicas
   - Implement connection pooling
   - Optimize PostgreSQL configuration

3. **CDN and Caching:**
   - Use CDN for static assets
   - Implement response caching
   - Use HTTP/2 or HTTP/3

## Troubleshooting

### High Response Times
- Check database slow query log
- Review Prometheus metrics for bottlenecks
- Check for N+1 query problems
- Verify cache hit rates

### High Error Rates
- Check application logs
- Review error types in monitoring
- Verify database connection pool size
- Check external API rate limits

### Memory Leaks
- Monitor memory usage over time (soak test)
- Use memory profiling tools
- Check for unclosed database connections
- Review Celery task cleanup

## Continuous Performance Testing

### CI/CD Integration

Add to GitHub Actions:

```yaml
- name: Run load tests
  run: |
    pip install locust
    locust -f tests/load/locustfile.py \
      --host=${{ secrets.STAGING_URL }} \
      --users 50 --spawn-rate 5 --run-time 5m --headless \
      --html=load-test-report.html

- name: Upload results
  uses: actions/upload-artifact@v3
  with:
    name: load-test-results
    path: load-test-report.html
```

### Scheduled Testing

Run weekly performance tests:
- **Monday 2 AM:** Baseline test (50 users, 10min)
- **Wednesday 2 AM:** Load test (200 users, 30min)
- **Saturday 2 AM:** Soak test (100 users, 4h)

## Best Practices

1. **Test in staging first:** Never run load tests against production without approval
2. **Warm up the system:** Run a small warm-up before the main test
3. **Monitor everything:** Watch logs, metrics, and resources during tests
4. **Test realistic scenarios:** Use production-like data and workflows
5. **Document baselines:** Keep historical results for comparison
6. **Test regularly:** Run automated tests in CI/CD
7. **Analyze failures:** Investigate every failure to find root causes

## Support

For load testing issues:
- **Internal:** Check #performance-testing Slack channel
- **Documentation:** https://docs.cloudshield.io/testing
- **Tools:** Locust (https://locust.io), K6 (https://k6.io)
