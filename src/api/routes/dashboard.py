"""
Dashboard Analytics and Metrics API
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import func, and_, desc
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import json

from ..database import get_db
from ..models.findings import Finding
from ..models.integration import Integration
from ..models.user import User
from ..utils.auth import get_current_active_user
from ..utils.logger import get_logger

router = APIRouter(prefix="/dashboard", tags=["dashboard"])
logger = get_logger(__name__)


@router.get("/overview")
async def get_dashboard_overview(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get main dashboard overview metrics"""
    
    # Total integrations
    total_integrations = await db.scalar(
        func.count(Integration.id).where(Integration.user_id == current_user.id)
    )
    
    # Total findings
    total_findings = await db.scalar(
        func.count(Finding.id).join(Integration).where(Integration.user_id == current_user.id)
    )
    
    # Critical findings
    critical_findings = await db.scalar(
        func.count(Finding.id).join(Integration).where(
            and_(
                Integration.user_id == current_user.id,
                Finding.severity == "critical"
            )
        )
    )
    
    # Recent activity (last 7 days)
    seven_days_ago = datetime.utcnow() - timedelta(days=7)
    recent_findings = await db.scalar(
        func.count(Finding.id).join(Integration).where(
            and_(
                Integration.user_id == current_user.id,
                Finding.created_at >= seven_days_ago
            )
        )
    )
    
    return {
        "total_integrations": total_integrations or 0,
        "total_findings": total_findings or 0,
        "critical_findings": critical_findings or 0,
        "recent_findings": recent_findings or 0,
        "security_score": await calculate_security_score(db, current_user.id)
    }


@router.get("/metrics")
async def get_security_metrics(
    timeframe: str = Query("7d", regex="^(24h|7d|30d|90d)$"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get security metrics over time"""
    
    # Calculate timeframe
    if timeframe == "24h":
        delta = timedelta(hours=24)
        interval = "hour"
    elif timeframe == "7d":
        delta = timedelta(days=7)
        interval = "day"
    elif timeframe == "30d":
        delta = timedelta(days=30)
        interval = "day"
    else:  # 90d
        delta = timedelta(days=90)
        interval = "week"
    
    start_date = datetime.utcnow() - delta
    
    # Findings by severity over time
    findings_by_severity = await get_findings_by_severity(db, current_user.id, start_date)
    
    # Compliance status
    compliance_status = await get_compliance_status(db, current_user.id)
    
    # Platform distribution
    platform_distribution = await get_platform_distribution(db, current_user.id)
    
    # Risk trend
    risk_trend = await get_risk_trend(db, current_user.id, start_date, interval)
    
    return {
        "timeframe": timeframe,
        "findings_by_severity": findings_by_severity,
        "compliance_status": compliance_status,
        "platform_distribution": platform_distribution,
        "risk_trend": risk_trend
    }


@router.get("/recent-findings")
async def get_recent_findings(
    limit: int = Query(10, ge=1, le=50),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get recent security findings"""
    
    query = db.query(Finding).join(Integration).where(Integration.user_id == current_user.id)
    
    if severity:
        query = query.where(Finding.severity == severity)
    
    findings = await query.order_by(desc(Finding.created_at)).limit(limit).offset(offset).all()
    
    return {
        "findings": [
            {
                "id": finding.id,
                "title": finding.title,
                "description": finding.description,
                "severity": finding.severity,
                "platform": finding.integration.platform,
                "created_at": finding.created_at,
                "status": finding.status,
                "risk_score": finding.risk_score
            }
            for finding in findings
        ]
    }


async def calculate_security_score(db: AsyncSession, user_id: str) -> int:
    """Calculate overall security score (0-100)"""
    
    # Get total findings by severity
    critical = await db.scalar(
        func.count(Finding.id).join(Integration).where(
            and_(Integration.user_id == user_id, Finding.severity == "critical")
        )
    ) or 0
    
    high = await db.scalar(
        func.count(Finding.id).join(Integration).where(
            and_(Integration.user_id == user_id, Finding.severity == "high")
        )
    ) or 0
    
    medium = await db.scalar(
        func.count(Finding.id).join(Integration).where(
            and_(Integration.user_id == user_id, Finding.severity == "medium")
        )
    ) or 0
    
    # Base score calculation
    base_score = 100
    base_score -= critical * 15  # Critical findings hurt most
    base_score -= high * 8       # High severity findings
    base_score -= medium * 3     # Medium severity findings
    
    # Ensure score stays within bounds
    return max(0, min(100, base_score))


async def get_findings_by_severity(db: AsyncSession, user_id: str, start_date: datetime) -> Dict[str, int]:
    """Get findings count by severity"""
    
    severities = ["critical", "high", "medium", "low", "info"]
    results = {}
    
    for severity in severities:
        count = await db.scalar(
            func.count(Finding.id).join(Integration).where(
                and_(
                    Integration.user_id == user_id,
                    Finding.severity == severity,
                    Finding.created_at >= start_date
                )
            )
        ) or 0
        results[severity] = count
    
    return results


async def get_compliance_status(db: AsyncSession, user_id: str) -> Dict[str, Any]:
    """Get compliance framework status"""
    
    # Mock compliance data - in production, this would analyze actual findings
    return {
        "soc2": {"score": 85, "status": "compliant"},
        "gdpr": {"score": 92, "status": "compliant"},
        "hipaa": {"score": 78, "status": "non_compliant"},
        "pci_dss": {"score": 88, "status": "compliant"}
    }


async def get_platform_distribution(db: AsyncSession, user_id: str) -> Dict[str, int]:
    """Get distribution of findings by platform"""
    
    platforms = ["google_workspace", "microsoft_365", "slack", "github", "notion"]
    results = {}
    
    for platform in platforms:
        count = await db.scalar(
            func.count(Finding.id).join(Integration).where(
                and_(
                    Integration.user_id == user_id,
                    Integration.platform == platform
                )
            )
        ) or 0
        results[platform] = count
    
    return results


async def get_risk_trend(db: AsyncSession, user_id: str, start_date: datetime, interval: str) -> List[Dict[str, Any]]:
    """Get risk score trend over time"""
    
    # Mock trend data - in production, this would calculate historical risk scores
    trend_data = []
    current_date = start_date
    end_date = datetime.utcnow()
    
    while current_date <= end_date:
        # Simulate risk score calculation for each time period
        risk_score = 85 + (hash(current_date.isoformat()) % 30) - 15  # Mock data
        trend_data.append({
            "date": current_date.isoformat(),
            "risk_score": max(0, min(100, risk_score))
        })
        
        if interval == "hour":
            current_date += timedelta(hours=1)
        elif interval == "day":
            current_date += timedelta(days=1)
        else:  # week
            current_date += timedelta(weeks=1)
    
    return trend_data[-20:]  # Return last 20 data points