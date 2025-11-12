#!/bin/bash
# Smoke tests for CloudShield deployment verification

set -e

BASE_URL="${1:-http://localhost:8000}"
TIMEOUT=30
RETRY_COUNT=5

echo "🧪 Running smoke tests against: $BASE_URL"

# Function to test endpoint
test_endpoint() {
    local endpoint=$1
    local expected_status=$2
    local description=$3
    
    echo -n "Testing $description... "
    
    for i in $(seq 1 $RETRY_COUNT); do
        response=$(curl -s -o /dev/null -w "%{http_code}" --max-time $TIMEOUT "$BASE_URL$endpoint" || echo "000")
        
        if [ "$response" == "$expected_status" ]; then
            echo "✅ PASSED (HTTP $response)"
            return 0
        fi
        
        if [ $i -lt $RETRY_COUNT ]; then
            echo -n "Retry $i... "
            sleep 2
        fi
    done
    
    echo "❌ FAILED (Expected: $expected_status, Got: $response)"
    return 1
}

# Health check
test_endpoint "/health" "200" "Health endpoint"

# API documentation (if enabled)
test_endpoint "/docs" "200" "API documentation" || true

# Authentication endpoint
test_endpoint "/auth/login" "422" "Login endpoint (validation check)"

# Protected endpoints (should return 401 without auth)
test_endpoint "/api/integrations" "401" "Protected integrations endpoint"
test_endpoint "/api/findings" "401" "Protected findings endpoint"

# Static frontend (if deployed together)
test_endpoint "/" "200" "Frontend root" || echo "⚠️  Frontend check skipped"

echo ""
echo "✅ Smoke tests completed successfully!"
exit 0
