"""
Security Middleware and Utilities
"""
from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
import time
import hashlib
import hmac
from typing import Dict, Set
import redis.asyncio as redis
from datetime import datetime, timedelta
import ipaddress
import re

from .config import settings
from .logger import get_logger, security_logger

logger = get_logger(__name__)


class SecurityMiddleware(BaseHTTPMiddleware):
    """Comprehensive security middleware"""
    
    def __init__(self, app, redis_url: str = None):
        super().__init__(app)
        self.redis_url = redis_url or settings.REDIS_URL
        self.blocked_ips: Set[str] = set()
        self.suspicious_patterns = [
            r"(?i)(union|select|insert|delete|drop|create|alter|exec|script)",
            r"(?i)(<script|javascript:|vbscript:|onload=|onerror=)",
            r"(?i)(\.\.\/|\.\.\\|\/etc\/passwd|\/etc\/shadow)",
            r"(?i)(cmd\.exe|powershell|bash|sh|python|perl)"
        ]
        
    async def dispatch(self, request: Request, call_next):
        """Process security checks for each request"""
        
        # Get client IP
        client_ip = self.get_client_ip(request)
        
        # Check if IP is blocked
        if await self.is_ip_blocked(client_ip):
            security_logger.log_security_event(
                "blocked_ip_access",
                client_ip=client_ip,
                url=str(request.url),
                user_agent=request.headers.get("User-Agent", "")
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="IP address temporarily blocked due to suspicious activity"
            )
        
        # Rate limiting
        if await self.check_rate_limit(client_ip, request):
            await self.block_ip_temporarily(client_ip, "rate_limit_exceeded")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded"
            )
        
        # Input validation
        if await self.detect_malicious_input(request):
            await self.increment_threat_score(client_ip)
            security_logger.log_security_event(
                "malicious_input_detected",
                client_ip=client_ip,
                url=str(request.url),
                method=request.method,
                user_agent=request.headers.get("User-Agent", "")
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid request detected"
            )
        
        # Security headers
        response = await call_next(request)
        response = self.add_security_headers(response)
        
        # Log successful request
        await self.log_request(request, response, client_ip)
        
        return response
    
    def get_client_ip(self, request: Request) -> str:
        """Get the real client IP address"""
        # Check X-Forwarded-For header first (for load balancers/proxies)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Take the first IP in the chain
            return forwarded_for.split(",")[0].strip()
        
        # Check X-Real-IP header
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()
        
        # Fall back to direct connection IP
        return request.client.host
    
    async def is_ip_blocked(self, ip: str) -> bool:
        """Check if IP is temporarily blocked"""
        try:
            redis_client = redis.from_url(self.redis_url)
            blocked = await redis_client.get(f"blocked_ip:{ip}")
            await redis_client.close()
            return blocked is not None
        except Exception as e:
            logger.error(f"Error checking blocked IP: {str(e)}")
            return False
    
    async def check_rate_limit(self, ip: str, request: Request) -> bool:
        """Check if request exceeds rate limits"""
        try:
            redis_client = redis.from_url(self.redis_url)
            
            # Different limits for different endpoints
            if "/auth/" in str(request.url.path):
                limit = 10  # 10 auth requests per minute
                window = 60
            elif "/api/" in str(request.url.path):
                limit = 100  # 100 API requests per minute
                window = 60
            else:
                limit = 200  # 200 general requests per minute
                window = 60
            
            key = f"rate_limit:{ip}:{window}"
            current = await redis_client.get(key)
            
            if current is None:
                await redis_client.setex(key, window, 1)
                await redis_client.close()
                return False
            
            if int(current) >= limit:
                await redis_client.close()
                return True
            
            await redis_client.incr(key)
            await redis_client.close()
            return False
            
        except Exception as e:
            logger.error(f"Error checking rate limit: {str(e)}")
            return False
    
    async def detect_malicious_input(self, request: Request) -> bool:
        """Detect potentially malicious input patterns"""
        try:
            # Check URL path
            path = str(request.url.path)
            for pattern in self.suspicious_patterns:
                if re.search(pattern, path):
                    return True
            
            # Check query parameters
            query_string = str(request.url.query)
            for pattern in self.suspicious_patterns:
                if re.search(pattern, query_string):
                    return True
            
            # Check headers for suspicious content
            user_agent = request.headers.get("User-Agent", "")
            referer = request.headers.get("Referer", "")
            
            for header_value in [user_agent, referer]:
                for pattern in self.suspicious_patterns:
                    if re.search(pattern, header_value):
                        return True
            
            # Check for common attack patterns in headers
            if self.check_suspicious_headers(request):
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error detecting malicious input: {str(e)}")
            return False
    
    def check_suspicious_headers(self, request: Request) -> bool:
        """Check for suspicious header patterns"""
        # Check for missing or suspicious User-Agent
        user_agent = request.headers.get("User-Agent", "")
        if not user_agent or len(user_agent) < 10:
            return True
        
        # Check for automation tools
        automation_patterns = [
            "curl", "wget", "python-requests", "bot", "crawler", "scanner"
        ]
        
        for pattern in automation_patterns:
            if pattern.lower() in user_agent.lower():
                # Allow legitimate tools but log for monitoring
                security_logger.log_security_event(
                    "automation_tool_detected",
                    user_agent=user_agent,
                    client_ip=self.get_client_ip(request)
                )
                break
        
        return False
    
    async def increment_threat_score(self, ip: str):
        """Increment threat score for an IP"""
        try:
            redis_client = redis.from_url(self.redis_url)
            key = f"threat_score:{ip}"
            score = await redis_client.incr(key)
            await redis_client.expire(key, 3600)  # Reset after 1 hour
            
            # Auto-block if threat score exceeds threshold
            if score >= 5:
                await self.block_ip_temporarily(ip, "high_threat_score")
            
            await redis_client.close()
            
        except Exception as e:
            logger.error(f"Error incrementing threat score: {str(e)}")
    
    async def block_ip_temporarily(self, ip: str, reason: str):
        """Temporarily block an IP address"""
        try:
            redis_client = redis.from_url(self.redis_url)
            await redis_client.setex(f"blocked_ip:{ip}", 3600, reason)  # Block for 1 hour
            await redis_client.close()
            
            security_logger.log_security_event(
                "ip_blocked",
                client_ip=ip,
                reason=reason,
                duration="1 hour"
            )
            
        except Exception as e:
            logger.error(f"Error blocking IP: {str(e)}")
    
    def add_security_headers(self, response):
        """Add security headers to response"""
        security_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https:; connect-src 'self' https:; frame-ancestors 'none';",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()"
        }
        
        for header, value in security_headers.items():
            response.headers[header] = value
        
        # Remove server identification
        if "Server" in response.headers:
            del response.headers["Server"]
        
        return response
    
    async def log_request(self, request: Request, response, client_ip: str):
        """Log request for security monitoring"""
        log_data = {
            "client_ip": client_ip,
            "method": request.method,
            "url": str(request.url),
            "status_code": response.status_code,
            "user_agent": request.headers.get("User-Agent", ""),
            "referer": request.headers.get("Referer", ""),
            "content_length": response.headers.get("content-length", "0")
        }
        
        # Log suspicious status codes
        if response.status_code >= 400:
            security_logger.log_security_event("error_response", **log_data)


class CSRFProtection:
    """CSRF protection utility"""
    
    def __init__(self, secret_key: str):
        self.secret_key = secret_key.encode()
    
    def generate_csrf_token(self, session_id: str) -> str:
        """Generate CSRF token for session"""
        timestamp = str(int(time.time()))
        message = f"{session_id}:{timestamp}"
        signature = hmac.new(self.secret_key, message.encode(), hashlib.sha256).hexdigest()
        return f"{timestamp}:{signature}"
    
    def validate_csrf_token(self, token: str, session_id: str, max_age: int = 3600) -> bool:
        """Validate CSRF token"""
        try:
            timestamp_str, signature = token.split(":", 1)
            timestamp = int(timestamp_str)
            
            # Check if token is not expired
            if time.time() - timestamp > max_age:
                return False
            
            # Verify signature
            message = f"{session_id}:{timestamp_str}"
            expected_signature = hmac.new(self.secret_key, message.encode(), hashlib.sha256).hexdigest()
            
            return hmac.compare_digest(signature, expected_signature)
            
        except (ValueError, TypeError):
            return False


def validate_ip_address(ip: str) -> bool:
    """Validate IP address format"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_private_ip(ip: str) -> bool:
    """Check if IP is in private range"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False