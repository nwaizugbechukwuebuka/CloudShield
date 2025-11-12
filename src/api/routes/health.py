"""
Health Check and System Status Endpoints
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
import redis.asyncio as redis
import aiohttp
import time
from datetime import datetime
from typing import Dict, Any

from ..database import get_db
from ..utils.config import settings
from ..utils.logger import get_logger
from ..models.base import Base

router = APIRouter(prefix="/health", tags=["health"])
logger = get_logger(__name__)


@router.get("/")
async def health_check():
    """Basic health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "service": "CloudShield API",
        "version": settings.APP_VERSION
    }


@router.get("/detailed")
async def detailed_health_check(db: AsyncSession = Depends(get_db)):
    """Comprehensive health check with dependency status"""
    start_time = time.time()
    health_status = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "service": "CloudShield API",
        "version": settings.APP_VERSION,
        "checks": {}
    }
    
    # Database health check
    try:
        result = await db.execute(text("SELECT 1"))
        health_status["checks"]["database"] = {
            "status": "healthy",
            "response_time_ms": round((time.time() - start_time) * 1000, 2)
        }
    except Exception as e:
        logger.error(f"Database health check failed: {str(e)}")
        health_status["checks"]["database"] = {
            "status": "unhealthy",
            "error": str(e)
        }
        health_status["status"] = "degraded"
    
    # Redis health check
    redis_start = time.time()
    try:
        redis_client = redis.from_url(settings.REDIS_URL)
        await redis_client.ping()
        await redis_client.close()
        health_status["checks"]["redis"] = {
            "status": "healthy",
            "response_time_ms": round((time.time() - redis_start) * 1000, 2)
        }
    except Exception as e:
        logger.error(f"Redis health check failed: {str(e)}")
        health_status["checks"]["redis"] = {
            "status": "unhealthy",
            "error": str(e)
        }
        health_status["status"] = "degraded"
    
    # External API health checks
    api_checks = await check_external_apis()
    health_status["checks"]["external_apis"] = api_checks
    
    if any(check["status"] != "healthy" for check in api_checks.values()):
        health_status["status"] = "degraded"
    
    health_status["total_response_time_ms"] = round((time.time() - start_time) * 1000, 2)
    
    if health_status["status"] != "healthy":
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=health_status
        )
    
    return health_status


async def check_external_apis() -> Dict[str, Any]:
    """Check external API endpoints"""
    checks = {}
    
    # Google API health
    try:
        async with aiohttp.ClientSession() as session:
            start_time = time.time()
            async with session.get("https://www.googleapis.com/oauth2/v2/userinfo", timeout=5) as response:
                checks["google_api"] = {
                    "status": "reachable" if response.status in [200, 401] else "unreachable",
                    "response_time_ms": round((time.time() - start_time) * 1000, 2),
                    "status_code": response.status
                }
    except Exception as e:
        checks["google_api"] = {"status": "unreachable", "error": str(e)}
    
    # Microsoft Graph API health
    try:
        async with aiohttp.ClientSession() as session:
            start_time = time.time()
            async with session.get("https://graph.microsoft.com/v1.0/me", timeout=5) as response:
                checks["microsoft_graph"] = {
                    "status": "reachable" if response.status in [200, 401] else "unreachable",
                    "response_time_ms": round((time.time() - start_time) * 1000, 2),
                    "status_code": response.status
                }
    except Exception as e:
        checks["microsoft_graph"] = {"status": "unreachable", "error": str(e)}
    
    # Slack API health
    try:
        async with aiohttp.ClientSession() as session:
            start_time = time.time()
            async with session.get("https://slack.com/api/api.test", timeout=5) as response:
                checks["slack_api"] = {
                    "status": "reachable" if response.status == 200 else "unreachable",
                    "response_time_ms": round((time.time() - start_time) * 1000, 2),
                    "status_code": response.status
                }
    except Exception as e:
        checks["slack_api"] = {"status": "unreachable", "error": str(e)}
    
    return checks


@router.get("/readiness")
async def readiness_check(db: AsyncSession = Depends(get_db)):
    """Kubernetes readiness probe"""
    try:
        await db.execute(text("SELECT 1"))
        return {"status": "ready"}
    except Exception as e:
        logger.error(f"Readiness check failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"status": "not_ready", "error": str(e)}
        )


@router.get("/liveness")
async def liveness_check():
    """Kubernetes liveness probe"""
    return {"status": "alive", "timestamp": datetime.utcnow().isoformat()}