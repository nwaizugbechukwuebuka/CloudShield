#!/bin/bash
# Health check script for production deployment verification

set -e

BASE_URL="${1:-http://localhost:8000}"
MAX_ATTEMPTS=30
SLEEP_DURATION=10

echo "🏥 Running health checks against: $BASE_URL"

check_health() {
    local attempt=1
    
    while [ $attempt -le $MAX_ATTEMPTS ]; do
        echo "Attempt $attempt/$MAX_ATTEMPTS..."
        
        response=$(curl -s "$BASE_URL/health" || echo "{}")
        status=$(echo "$response" | jq -r '.status // "error"')
        
        if [ "$status" == "healthy" ]; then
            echo "✅ Service is healthy!"
            
            # Check database connectivity
            db_status=$(echo "$response" | jq -r '.database // "unknown"')
            echo "   Database: $db_status"
            
            # Check Redis connectivity
            redis_status=$(echo "$response" | jq -r '.redis // "unknown"')
            echo "   Redis: $redis_status"
            
            # Check uptime
            uptime=$(echo "$response" | jq -r '.uptime // "unknown"')
            echo "   Uptime: $uptime"
            
            return 0
        fi
        
        echo "Service not ready yet (status: $status). Waiting ${SLEEP_DURATION}s..."
        sleep $SLEEP_DURATION
        attempt=$((attempt + 1))
    done
    
    echo "❌ Health check failed after $MAX_ATTEMPTS attempts"
    return 1
}

# Run health check
if check_health; then
    echo ""
    echo "✅ All health checks passed!"
    exit 0
else
    echo ""
    echo "❌ Health checks failed!"
    exit 1
fi
