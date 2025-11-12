"""
Enhanced Security Middleware for CloudShield API
Implements comprehensive security headers, request validation, and protection mechanisms
"""

from fastapi import Request, Response, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.datastructures import Headers
from typing import Callable, Optional
import re
import hashlib
import secrets
from datetime import datetime, timedelta
import ipaddress

from src.api.utils.logger import get_logger
from src.api.utils.config import settings

logger = get_logger(__name__)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add comprehensive security headers to all responses
    Implements OWASP security header recommendations
    """

    def __init__(self, app, nonce_enabled: bool = True):
        super().__init__(app)
        self.nonce_enabled = nonce_enabled

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Generate CSP nonce if enabled
        nonce = secrets.token_urlsafe(16) if self.nonce_enabled else None
        if nonce:
            request.state.csp_nonce = nonce

        response = await call_next(request)

        # Strict Transport Security (HSTS)
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains; preload"
        )

        # Content Security Policy (CSP)
        csp_directives = [
            "default-src 'self'",
            f"script-src 'self' {'nonce-' + nonce if nonce else ''} 'strict-dynamic'",
            "style-src 'self' 'unsafe-inline'",  # Allow inline styles for Material-UI
            "img-src 'self' data: https:",
            "font-src 'self' data:",
            "connect-src 'self' https://api.cloudshield.io wss://api.cloudshield.io",
            "frame-ancestors 'none'",
            "base-uri 'self'",
            "form-action 'self'",
            "upgrade-insecure-requests",
        ]
        response.headers["Content-Security-Policy"] = "; ".join(csp_directives)

        # X-Frame-Options (defense in depth with CSP frame-ancestors)
        response.headers["X-Frame-Options"] = "DENY"

        # X-Content-Type-Options
        response.headers["X-Content-Type-Options"] = "nosniff"

        # X-XSS-Protection (legacy browsers)
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Referrer Policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Permissions Policy (formerly Feature-Policy)
        permissions_policy = [
            "geolocation=()",
            "microphone=()",
            "camera=()",
            "payment=()",
            "usb=()",
            "magnetometer=()",
            "gyroscope=()",
            "accelerometer=()",
        ]
        response.headers["Permissions-Policy"] = ", ".join(permissions_policy)

        # X-Permitted-Cross-Domain-Policies
        response.headers["X-Permitted-Cross-Domain-Policies"] = "none"

        # Remove server identification headers
        response.headers.pop("Server", None)
        response.headers.pop("X-Powered-By", None)

        # Cache control for sensitive endpoints
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"

        return response


class RequestValidationMiddleware(BaseHTTPMiddleware):
    """
    Middleware for validating incoming requests and blocking malicious patterns
    """

    # Suspicious patterns (basic WAF functionality)
    SUSPICIOUS_PATTERNS = {
        "sql_injection": re.compile(
            r"(\bUNION\b.*\bSELECT\b|\bSELECT\b.*\bFROM\b|;\s*DROP\s+TABLE|INSERT\s+INTO|DELETE\s+FROM)",
            re.IGNORECASE,
        ),
        "xss": re.compile(
            r"(<script[^>]*>|javascript:|onerror\s*=|onload\s*=|<iframe|eval\(|fromCharCode)",
            re.IGNORECASE,
        ),
        "command_injection": re.compile(
            r"(;|\||`|\$\(|\$\{|&&|\.\.\/|\/etc\/passwd|\/bin\/bash|nc\s+|wget\s+|curl\s+)",
            re.IGNORECASE,
        ),
        "path_traversal": re.compile(r"(\.\.\/|\.\.\\|\/etc\/|c:\\|\.\.%2f|\.\.%5c)", re.IGNORECASE),
    }

    # Blocked User-Agent patterns (security scanners)
    BLOCKED_USER_AGENTS = re.compile(
        r"(nikto|sqlmap|nmap|masscan|nessus|openvas|acunetix|burp|metasploit|w3af|skipfish)",
        re.IGNORECASE,
    )

    # IP Blocklist (example - should be loaded from database/config)
    BLOCKED_IPS = set([
        # Add known malicious IPs
        # "192.0.2.1",
        # "198.51.100.50",
    ])

    def __init__(self, app, enable_ip_blocking: bool = True, enable_pattern_detection: bool = True):
        super().__init__(app)
        self.enable_ip_blocking = enable_ip_blocking
        self.enable_pattern_detection = enable_pattern_detection

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        client_ip = self._get_client_ip(request)

        # IP Blocking check
        if self.enable_ip_blocking and client_ip in self.BLOCKED_IPS:
            logger.warning(
                "Blocked request from blacklisted IP",
                extra={"client_ip": client_ip, "path": request.url.path},
            )
            return JSONResponse(
                status_code=403, content={"detail": "Access denied"}, headers={"X-Blocked": "IP"}
            )

        # User-Agent validation
        user_agent = request.headers.get("user-agent", "")
        if self.BLOCKED_USER_AGENTS.search(user_agent):
            logger.warning(
                "Blocked security scanner",
                extra={
                    "client_ip": client_ip,
                    "user_agent": user_agent,
                    "path": request.url.path,
                },
            )
            return JSONResponse(
                status_code=403,
                content={"detail": "Access denied"},
                headers={"X-Blocked": "User-Agent"},
            )

        # Request pattern validation
        if self.enable_pattern_detection:
            try:
                await self._validate_request_patterns(request, client_ip)
            except HTTPException as e:
                return JSONResponse(
                    status_code=e.status_code,
                    content={"detail": e.detail},
                    headers={"X-Blocked": "Pattern"},
                )

        # HTTPS enforcement (if not in development)
        if not settings.DEBUG and request.url.scheme != "https":
            logger.warning(
                "HTTP request blocked - HTTPS required",
                extra={"client_ip": client_ip, "path": request.url.path},
            )
            return JSONResponse(
                status_code=403,
                content={"detail": "HTTPS required"},
                headers={"X-Blocked": "HTTP"},
            )

        # Method validation
        allowed_methods = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
        if request.method not in allowed_methods:
            logger.warning(
                "HTTP method not allowed",
                extra={
                    "client_ip": client_ip,
                    "method": request.method,
                    "path": request.url.path,
                },
            )
            return JSONResponse(
                status_code=405,
                content={"detail": "Method not allowed"},
                headers={"X-Blocked": "Method"},
            )

        response = await call_next(request)
        return response

    async def _validate_request_patterns(self, request: Request, client_ip: str):
        """Validate request for suspicious patterns"""
        # Check query parameters
        for key, value in request.query_params.items():
            for pattern_name, pattern in self.SUSPICIOUS_PATTERNS.items():
                if pattern.search(value):
                    logger.error(
                        f"Suspicious pattern detected: {pattern_name}",
                        extra={
                            "client_ip": client_ip,
                            "path": request.url.path,
                            "parameter": key,
                            "value": value[:100],  # Truncate for logging
                        },
                    )
                    raise HTTPException(
                        status_code=400, detail=f"Invalid request: {pattern_name} detected"
                    )

        # Check request body for POST/PUT/PATCH
        if request.method in ("POST", "PUT", "PATCH"):
            try:
                body = await request.body()
                body_str = body.decode("utf-8", errors="ignore")

                for pattern_name, pattern in self.SUSPICIOUS_PATTERNS.items():
                    if pattern.search(body_str):
                        logger.error(
                            f"Suspicious pattern in body: {pattern_name}",
                            extra={
                                "client_ip": client_ip,
                                "path": request.url.path,
                                "body_preview": body_str[:200],
                            },
                        )
                        raise HTTPException(
                            status_code=400, detail=f"Invalid request: {pattern_name} detected"
                        )
            except UnicodeDecodeError:
                pass  # Binary data, skip pattern check

        # Check URL path
        for pattern_name, pattern in self.SUSPICIOUS_PATTERNS.items():
            if pattern.search(str(request.url)):
                logger.error(
                    f"Suspicious pattern in URL: {pattern_name}",
                    extra={"client_ip": client_ip, "url": str(request.url)},
                )
                raise HTTPException(
                    status_code=400, detail=f"Invalid request: {pattern_name} detected"
                )

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request, considering proxies"""
        # Check X-Forwarded-For header (when behind proxy)
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            # Take the first IP (client IP)
            client_ip = forwarded_for.split(",")[0].strip()
        else:
            # Direct connection
            client_ip = request.client.host if request.client else "unknown"

        return client_ip


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Advanced rate limiting middleware with per-endpoint and per-IP tracking
    """

    def __init__(
        self,
        app,
        default_limit: int = 100,
        window_seconds: int = 60,
        auth_limit: int = 10,
    ):
        super().__init__(app)
        self.default_limit = default_limit
        self.window_seconds = window_seconds
        self.auth_limit = auth_limit
        self.request_counts: dict = {}  # In production, use Redis
        self.auth_attempts: dict = {}

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        client_ip = self._get_client_ip(request)
        endpoint = f"{request.method}:{request.url.path}"

        # Determine rate limit based on endpoint
        if request.url.path.startswith("/auth/"):
            limit = self.auth_limit
            tracking_dict = self.auth_attempts
        else:
            limit = self.default_limit
            tracking_dict = self.request_counts

        # Check rate limit
        current_time = datetime.utcnow()
        key = f"{client_ip}:{endpoint}"

        if key not in tracking_dict:
            tracking_dict[key] = {"count": 0, "reset_time": current_time + timedelta(seconds=self.window_seconds)}

        # Reset counter if window expired
        if current_time >= tracking_dict[key]["reset_time"]:
            tracking_dict[key] = {"count": 0, "reset_time": current_time + timedelta(seconds=self.window_seconds)}

        # Increment counter
        tracking_dict[key]["count"] += 1

        # Check if limit exceeded
        if tracking_dict[key]["count"] > limit:
            retry_after = int((tracking_dict[key]["reset_time"] - current_time).total_seconds())
            logger.warning(
                "Rate limit exceeded",
                extra={
                    "client_ip": client_ip,
                    "endpoint": endpoint,
                    "count": tracking_dict[key]["count"],
                    "limit": limit,
                },
            )
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded", "retry_after": retry_after},
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(int(tracking_dict[key]["reset_time"].timestamp())),
                },
            )

        response = await call_next(request)

        # Add rate limit headers to response
        remaining = max(0, limit - tracking_dict[key]["count"])
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(int(tracking_dict[key]["reset_time"].timestamp()))

        return response

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request"""
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        return request.client.host if request.client else "unknown"


class ContentTypeValidationMiddleware(BaseHTTPMiddleware):
    """
    Middleware to enforce JSON content-type for API endpoints
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Only validate POST, PUT, PATCH requests to API endpoints
        if (
            request.method in ("POST", "PUT", "PATCH")
            and request.url.path.startswith("/api/")
            and not request.url.path.endswith("/upload")  # Exclude file upload endpoints
        ):
            content_type = request.headers.get("content-type", "")
            if not content_type.startswith("application/json"):
                logger.warning(
                    "Invalid Content-Type for API request",
                    extra={
                        "path": request.url.path,
                        "content_type": content_type,
                        "client_ip": request.client.host if request.client else "unknown",
                    },
                )
                return JSONResponse(
                    status_code=415,
                    content={"detail": "Content-Type must be application/json"},
                    headers={"Accept": "application/json"},
                )

        response = await call_next(request)
        return response


def setup_security_middleware(app):
    """
    Setup all security middleware in the correct order
    Order matters: validation -> rate limiting -> security headers
    """
    # 1. Content-Type validation (earliest)
    app.add_middleware(ContentTypeValidationMiddleware)

    # 2. Request validation and pattern detection
    app.add_middleware(
        RequestValidationMiddleware,
        enable_ip_blocking=settings.ENABLE_IP_BLOCKING,
        enable_pattern_detection=settings.ENABLE_PATTERN_DETECTION,
    )

    # 3. Rate limiting
    app.add_middleware(
        RateLimitMiddleware,
        default_limit=settings.RATE_LIMIT_PER_MINUTE,
        window_seconds=60,
        auth_limit=settings.AUTH_RATE_LIMIT,
    )

    # 4. Security headers (last, applied to all responses)
    app.add_middleware(SecurityHeadersMiddleware, nonce_enabled=True)

    logger.info("Security middleware configured successfully")
