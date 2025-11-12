"""
Rate Limiting Utilities
"""
from fastapi import Request, HTTPException, status
import redis.asyncio as redis
import time
from datetime import datetime, timedelta
from typing import Dict, Optional
import asyncio

from .config import settings
from .logger import get_logger

logger = get_logger(__name__)


class RateLimiter:
    """Advanced rate limiting with multiple strategies"""
    
    def __init__(self, redis_url: str = None):
        self.redis_url = redis_url or settings.REDIS_URL
        self.default_limits = {
            "default": {"requests": 1000, "window": 3600},  # 1000/hour
            "auth": {"requests": 10, "window": 300},         # 10/5min
            "api": {"requests": 100, "window": 60},          # 100/min
            "scan": {"requests": 5, "window": 60},           # 5/min
            "upload": {"requests": 20, "window": 3600}       # 20/hour
        }
    
    async def check_rate_limit(
        self, 
        identifier: str, 
        endpoint_type: str = "default",
        custom_limit: Optional[Dict] = None
    ) -> tuple[bool, Dict]:
        """
        Check rate limit for identifier (IP, user ID, etc.)
        Returns: (is_limited, info_dict)
        """
        
        limit_config = custom_limit or self.default_limits.get(endpoint_type, self.default_limits["default"])
        
        try:
            redis_client = redis.from_url(self.redis_url)
            
            # Sliding window rate limiting
            now = time.time()
            window = limit_config["window"]
            max_requests = limit_config["requests"]
            
            # Use sorted set for sliding window
            key = f"rate_limit:{endpoint_type}:{identifier}"
            
            # Remove expired entries
            await redis_client.zremrangebyscore(key, 0, now - window)
            
            # Count current requests in window
            current_requests = await redis_client.zcard(key)
            
            if current_requests >= max_requests:
                # Get the oldest request time to calculate reset time
                oldest_request = await redis_client.zrange(key, 0, 0, withscores=True)
                reset_time = int((oldest_request[0][1] + window) - now) if oldest_request else window
                
                await redis_client.close()
                return True, {
                    "limited": True,
                    "requests_made": current_requests,
                    "requests_allowed": max_requests,
                    "window_seconds": window,
                    "reset_in_seconds": max(reset_time, 0),
                    "retry_after": max(reset_time, 1)
                }
            
            # Add current request
            await redis_client.zadd(key, {str(now): now})
            await redis_client.expire(key, window)
            
            await redis_client.close()
            
            return False, {
                "limited": False,
                "requests_made": current_requests + 1,
                "requests_allowed": max_requests,
                "window_seconds": window,
                "remaining_requests": max_requests - current_requests - 1
            }
            
        except Exception as e:
            logger.error(f"Rate limiting error: {str(e)}")
            # Fail open - allow request if rate limiting fails
            return False, {"limited": False, "error": "rate_limiting_unavailable"}
    
    async def check_burst_limit(self, identifier: str, burst_limit: int = 10, burst_window: int = 1) -> bool:
        """Check for burst protection (many requests in very short time)"""
        
        try:
            redis_client = redis.from_url(self.redis_url)
            
            key = f"burst_limit:{identifier}"
            now = time.time()
            
            # Remove requests older than burst window
            await redis_client.zremrangebyscore(key, 0, now - burst_window)
            
            # Count requests in burst window
            burst_requests = await redis_client.zcard(key)
            
            if burst_requests >= burst_limit:
                await redis_client.close()
                return True  # Burst limit exceeded
            
            # Add current request
            await redis_client.zadd(key, {str(now): now})
            await redis_client.expire(key, burst_window)
            
            await redis_client.close()
            return False
            
        except Exception as e:
            logger.error(f"Burst limiting error: {str(e)}")
            return False
    
    async def get_rate_limit_status(self, identifier: str, endpoint_type: str = "default") -> Dict:
        """Get current rate limit status for identifier"""
        
        limit_config = self.default_limits.get(endpoint_type, self.default_limits["default"])
        
        try:
            redis_client = redis.from_url(self.redis_url)
            
            key = f"rate_limit:{endpoint_type}:{identifier}"
            now = time.time()
            window = limit_config["window"]
            
            # Remove expired entries
            await redis_client.zremrangebyscore(key, 0, now - window)
            
            # Get current requests count
            current_requests = await redis_client.zcard(key)
            max_requests = limit_config["requests"]
            
            # Get reset time
            oldest_request = await redis_client.zrange(key, 0, 0, withscores=True)
            reset_time = int((oldest_request[0][1] + window) - now) if oldest_request else 0
            
            await redis_client.close()
            
            return {
                "requests_made": current_requests,
                "requests_allowed": max_requests,
                "remaining_requests": max(0, max_requests - current_requests),
                "window_seconds": window,
                "reset_in_seconds": max(reset_time, 0)
            }
            
        except Exception as e:
            logger.error(f"Error getting rate limit status: {str(e)}")
            return {"error": "status_unavailable"}


class AdaptiveRateLimiter:
    """Adaptive rate limiting based on system load and user behavior"""
    
    def __init__(self, redis_url: str = None):
        self.redis_url = redis_url or settings.REDIS_URL
        self.base_limits = RateLimiter(redis_url).default_limits
        
    async def get_adaptive_limit(self, identifier: str, endpoint_type: str, user_tier: str = "free") -> Dict:
        """Get adaptive rate limit based on system load and user tier"""
        
        base_limit = self.base_limits.get(endpoint_type, self.base_limits["default"])
        
        # Tier multipliers
        tier_multipliers = {
            "free": 1.0,
            "premium": 3.0,
            "enterprise": 10.0
        }
        
        # Get system load factor
        load_factor = await self.get_system_load_factor()
        
        # Get user reputation factor
        reputation_factor = await self.get_user_reputation(identifier)
        
        # Calculate adaptive limit
        tier_multiplier = tier_multipliers.get(user_tier, 1.0)
        adaptive_requests = int(base_limit["requests"] * tier_multiplier * load_factor * reputation_factor)
        
        return {
            "requests": max(1, adaptive_requests),  # Always allow at least 1 request
            "window": base_limit["window"],
            "factors": {
                "base": base_limit["requests"],
                "tier_multiplier": tier_multiplier,
                "load_factor": load_factor,
                "reputation_factor": reputation_factor
            }
        }
    
    async def get_system_load_factor(self) -> float:
        """Get current system load factor (0.1 to 1.0)"""
        
        try:
            redis_client = redis.from_url(self.redis_url)
            
            # Check system metrics from monitoring
            cpu_usage = await redis_client.get("system:cpu_usage") or "0"
            memory_usage = await redis_client.get("system:memory_usage") or "0"
            active_connections = await redis_client.get("system:active_connections") or "0"
            
            await redis_client.close()
            
            # Calculate load factor
            cpu_factor = 1.0 - (float(cpu_usage) / 100.0 * 0.5)  # Reduce by up to 50% based on CPU
            memory_factor = 1.0 - (float(memory_usage) / 100.0 * 0.3)  # Reduce by up to 30% based on memory
            
            load_factor = min(cpu_factor, memory_factor)
            return max(0.1, load_factor)  # Never go below 10%
            
        except Exception as e:
            logger.error(f"Error getting system load factor: {str(e)}")
            return 1.0  # Default to no reduction
    
    async def get_user_reputation(self, identifier: str) -> float:
        """Get user reputation factor (0.5 to 2.0)"""
        
        try:
            redis_client = redis.from_url(self.redis_url)
            
            # Check violation history
            violations = await redis_client.get(f"violations:{identifier}") or "0"
            successful_requests = await redis_client.get(f"successful:{identifier}") or "1"
            
            await redis_client.close()
            
            violation_count = int(violations)
            success_count = int(successful_requests)
            
            # Calculate reputation (more successful requests = better reputation)
            if violation_count == 0:
                base_reputation = 1.2  # Bonus for clean record
            else:
                violation_ratio = violation_count / (success_count + violation_count)
                base_reputation = max(0.5, 1.0 - violation_ratio)
            
            # Bonus for long-standing users with many successful requests
            if success_count > 1000:
                base_reputation *= 1.5
            elif success_count > 100:
                base_reputation *= 1.2
            
            return min(2.0, base_reputation)
            
        except Exception as e:
            logger.error(f"Error getting user reputation: {str(e)}")
            return 1.0  # Default reputation


def create_rate_limit_response(rate_limit_info: Dict) -> HTTPException:
    """Create standardized rate limit exceeded response"""
    
    headers = {
        "X-RateLimit-Limit": str(rate_limit_info.get("requests_allowed", 0)),
        "X-RateLimit-Remaining": str(rate_limit_info.get("remaining_requests", 0)),
        "X-RateLimit-Reset": str(int(time.time() + rate_limit_info.get("reset_in_seconds", 0))),
        "Retry-After": str(rate_limit_info.get("retry_after", 60))
    }
    
    detail = {
        "error": "rate_limit_exceeded",
        "message": "Too many requests. Please try again later.",
        "retry_after_seconds": rate_limit_info.get("retry_after", 60),
        **rate_limit_info
    }
    
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail=detail,
        headers=headers
    )