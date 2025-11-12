"""
CloudShield SaaS Security Configuration Analyzer
FastAPI Application Entry Point
"""
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer
from starlette.middleware.sessions import SessionMiddleware
import time
import uvicorn
import asyncio
from contextlib import asynccontextmanager

# Import routes
from .routes import auth, integrations, scan, alerts, findings, health
from .routes.dashboard import router as dashboard_router
from .routes.users import router as users_router

# Import utilities
from .utils.config import settings
from .utils.logger import configure_logging, get_logger, security_logger
from .utils.rate_limiting import RateLimiter
from .utils.security import SecurityMiddleware
from .database import create_tables, get_db
from .models import Base
from sqlalchemy.ext.asyncio import create_async_engine

# Import monitoring
from .utils.monitoring import PrometheusMiddleware
from .utils.sentry_integration import initialize_sentry
from .utils.advanced_logging import configure_advanced_logging, get_enhanced_logger
from prometheus_client import make_asgi_app

# Import security middleware
from .middleware.security_middleware import setup_security_middleware

# Configure logging
configure_logging(debug=settings.DEBUG)
configure_advanced_logging(
    log_level='DEBUG' if settings.DEBUG else 'INFO',
    json_logs=not settings.DEBUG,
    log_file='logs/cloudshield.log' if not settings.DEBUG else None
)
logger = get_logger(__name__)
enhanced_logger = get_enhanced_logger(__name__)

# Initialize Sentry for error tracking
initialize_sentry(
    environment='development' if settings.DEBUG else 'production',
    release=settings.APP_VERSION,
    traces_sample_rate=0.1 if not settings.DEBUG else 1.0
)

# Create FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Advanced SaaS Security Configuration Analyzer with OAuth integrations and automated scanning",
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[str(origin) for origin in settings.BACKEND_CORS_ORIGINS],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add trusted host middleware for production
if not settings.DEBUG:
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["localhost", "127.0.0.1", "*.cloudshield.com"]
    )

# Add Prometheus monitoring middleware
app.add_middleware(PrometheusMiddleware)

# Add GZip compression
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Setup comprehensive security middleware (WAF-like protection, security headers, etc.)
setup_security_middleware(app)


# Request logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all HTTP requests for security monitoring"""
    start_time = time.time()
    
    # Get client IP
    client_ip = request.client.host
    if "X-Forwarded-For" in request.headers:
        client_ip = request.headers["X-Forwarded-For"].split(",")[0].strip()
    
    # Log request start
    logger.info(
        "Request started",
        method=request.method,
        url=str(request.url),
        client_ip=client_ip,
        user_agent=request.headers.get("User-Agent", "")
    )
    
    # Process request
    response = await call_next(request)
    
    # Calculate processing time
    process_time = time.time() - start_time
    
    # Log request completion
    logger.info(
        "Request completed",
        method=request.method,
        url=str(request.url),
        status_code=response.status_code,
        process_time=round(process_time, 3),
        client_ip=client_ip
    )
    
    # Log API access for security monitoring
    user_email = "anonymous"
    if hasattr(request.state, "user"):
        user_email = request.state.user.email
    
    security_logger.log_api_access(
        str(request.url.path),
        request.method,
        user_email,
        response.status_code
    )
    
    return response


# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler for unhandled errors"""
    logger.error(
        "Unhandled exception",
        error=str(exc),
        url=str(request.url),
        method=request.method,
        exc_info=True
    )
    
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )


# HTTP exception handler
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions"""
    logger.warning(
        "HTTP exception",
        status_code=exc.status_code,
        detail=exc.detail,
        url=str(request.url),
        method=request.method
    )
    
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail}
    )


# Include routers
app.include_router(auth.router)
app.include_router(users_router)
app.include_router(integrations.router)
app.include_router(scan.router)
app.include_router(alerts.router)
app.include_router(findings.router)
app.include_router(health.router)
app.include_router(dashboard_router)

# Mount Prometheus metrics endpoint
metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)


# Root endpoint
@app.get("/")
async def root():
    """Root endpoint - API information"""
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "description": "SaaS Security Configuration Analyzer API",
        "docs_url": "/docs" if settings.DEBUG else None,
        "endpoints": {
            "authentication": "/auth",
            "integrations": "/integrations", 
            "scanning": "/scans"
        }
    }


# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": time.time(),
        "version": settings.APP_VERSION
    }


# Startup event
@app.on_event("startup")
async def startup_event():
    """Application startup tasks"""
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    
    # Create database tables
    try:
        create_tables()
        logger.info("Database tables created/verified")
    except Exception as e:
        logger.error("Failed to create database tables", error=str(e))
        raise
    
    # Import and register scanners
    try:
        from ..scanner import google_workspace, github, slack
        logger.info("Security scanners registered")
    except Exception as e:
        logger.error("Failed to register scanners", error=str(e))
        # Don't fail startup for scanner registration issues
    
    logger.info("Application startup completed")


# Shutdown event
@app.on_event("shutdown")
async def shutdown_event():
    """Application shutdown tasks"""
    logger.info(f"Shutting down {settings.APP_NAME}")


if __name__ == "__main__":
    # Development server
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
        log_config=None  # Use our custom logging
    )
