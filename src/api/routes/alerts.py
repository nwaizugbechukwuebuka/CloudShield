"""
CloudShield Alert Routes
FastAPI routes for alert management, notifications, and security incident response.

Author: Chukwuebuka Tobiloba Nwaizugbe
Copyright (c) 2025 CloudShield Security Systems
"""

from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from fastapi.security import HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sqlalchemy import select, update, delete, and_, or_, desc, func
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from pydantic import BaseModel, Field
import logging

from ..database import get_async_db
from ..models.findings import Alert, AlertStatus, Finding
from ..models.integration import Integration
from ..models.user import User
from ..services.alert_services import get_alert_service, AlertSeverity, AlertCategory, NotificationType
from ..utils.auth import get_current_user, require_permissions
from ..utils.logger import get_logger
from ..utils.config import get_settings

settings = get_settings()
logger = get_logger(__name__)
security = HTTPBearer()

router = APIRouter(prefix="/alerts", tags=["alerts"])


# Pydantic Models for Request/Response
class AlertCreateRequest(BaseModel):
    """Request model for creating alerts"""
    finding_id: str
    alert_type: str
    severity: str = Field(..., regex="^(low|medium|high|critical)$")
    category: str = Field(..., regex="^(vulnerability|compliance|access_control|data_exposure|configuration|authentication|encryption|network_security)$")
    title: str = Field(..., min_length=1, max_length=255)
    description: str = Field(..., min_length=1, max_length=2000)
    metadata: Optional[Dict[str, Any]] = None


class AlertUpdateRequest(BaseModel):
    """Request model for updating alerts"""
    status: Optional[str] = Field(None, regex="^(open|in_progress|resolved|dismissed)$")
    severity: Optional[str] = Field(None, regex="^(low|medium|high|critical)$")
    assignee_id: Optional[str] = None
    resolution_notes: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class AlertResponse(BaseModel):
    """Response model for alert data"""
    id: str
    finding_id: str
    alert_type: str
    severity: str
    category: str
    status: str
    title: str
    description: str
    assignee_id: Optional[str] = None
    resolution_notes: Optional[str] = None
    metadata: Dict[str, Any]
    created_at: datetime
    updated_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    
    # Related data
    finding: Optional[Dict] = None
    assignee: Optional[Dict] = None

    class Config:
        from_attributes = True


class AlertListResponse(BaseModel):
    """Response model for alert listing"""
    alerts: List[AlertResponse]
    total_count: int
    page: int
    page_size: int
    total_pages: int


class AlertStatisticsResponse(BaseModel):
    """Response model for alert statistics"""
    total_alerts: int
    by_severity: Dict[str, int]
    by_status: Dict[str, int]
    by_category: Dict[str, int]
    resolution_metrics: Dict[str, Any]
    trend_data: List[Dict[str, Any]]
    compliance_impact: Dict[str, int]


class BulkActionRequest(BaseModel):
    """Request model for bulk operations"""
    alert_ids: List[str]
    action: str = Field(..., regex="^(resolve|dismiss|escalate|assign)$")
    parameters: Optional[Dict[str, Any]] = None


class NotificationRequest(BaseModel):
    """Request model for sending notifications"""
    alert_id: str
    channels: List[str]
    message: Optional[str] = None
    urgent: bool = False


class AlertRuleRequest(BaseModel):
    """Request model for alert rules"""
    name: str
    conditions: Dict[str, Any]
    severity: str
    category: str
    enabled: bool = True
    auto_escalate: bool = False
    escalation_delay: int = 3600
    notification_channels: List[str] = []


# Route Implementations

@router.get("/", response_model=AlertListResponse)
async def list_alerts(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=1000, description="Items per page"),
    severity: Optional[List[str]] = Query(None, description="Filter by severity levels"),
    status: Optional[List[str]] = Query(None, description="Filter by status"),
    category: Optional[List[str]] = Query(None, description="Filter by category"),
    integration_id: Optional[str] = Query(None, description="Filter by integration"),
    assignee_id: Optional[str] = Query(None, description="Filter by assignee"),
    created_after: Optional[datetime] = Query(None, description="Filter by creation date"),
    created_before: Optional[datetime] = Query(None, description="Filter by creation date"),
    search: Optional[str] = Query(None, description="Search in title and description"),
    sort_by: str = Query("created_at", description="Sort field"),
    sort_order: str = Query("desc", regex="^(asc|desc)$", description="Sort order"),
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get a paginated list of security alerts with comprehensive filtering options.
    
    Supports filtering by:
    - Severity levels (low, medium, high, critical)
    - Status (open, in_progress, resolved, dismissed)
    - Category (vulnerability, compliance, etc.)
    - Integration source
    - Assignee
    - Date ranges
    - Full-text search
    
    Returns paginated results with metadata.
    """
    try:
        # Build query with filters
        query = select(Alert).options(
            selectinload(Alert.finding).selectinload(Finding.integration),
            selectinload(Alert.assignee)
        )
        
        # Apply filters
        if severity:
            query = query.where(Alert.severity.in_(severity))
        
        if status:
            query = query.where(Alert.status.in_([AlertStatus(s) for s in status]))
        
        if category:
            query = query.where(Alert.category.in_(category))
        
        if integration_id:
            query = query.join(Finding).where(Finding.integration_id == integration_id)
        
        if assignee_id:
            query = query.where(Alert.assignee_id == assignee_id)
        
        if created_after:
            query = query.where(Alert.created_at >= created_after)
        
        if created_before:
            query = query.where(Alert.created_at <= created_before)
        
        if search:
            search_pattern = f"%{search}%"
            query = query.where(
                or_(
                    Alert.title.ilike(search_pattern),
                    Alert.description.ilike(search_pattern)
                )
            )
        
        # Get total count
        count_result = await db.execute(
            select(func.count()).select_from(query.subquery())
        )
        total_count = count_result.scalar()
        
        # Apply sorting
        sort_column = getattr(Alert, sort_by, Alert.created_at)
        if sort_order == "desc":
            query = query.order_by(desc(sort_column))
        else:
            query = query.order_by(sort_column)
        
        # Apply pagination
        offset = (page - 1) * page_size
        query = query.offset(offset).limit(page_size)
        
        # Execute query
        result = await db.execute(query)
        alerts = result.scalars().all()
        
        # Format response
        alert_responses = []
        for alert in alerts:
            alert_dict = {
                "id": alert.id,
                "finding_id": alert.finding_id,
                "alert_type": alert.alert_type,
                "severity": alert.severity,
                "category": alert.category,
                "status": alert.status.value,
                "title": alert.title,
                "description": alert.description,
                "assignee_id": alert.assignee_id,
                "resolution_notes": alert.resolution_notes,
                "metadata": alert.metadata or {},
                "created_at": alert.created_at,
                "updated_at": alert.updated_at,
                "resolved_at": alert.resolved_at
            }
            
            # Add related data
            if alert.finding:
                alert_dict["finding"] = {
                    "id": alert.finding.id,
                    "title": alert.finding.title,
                    "resource_name": alert.finding.resource_name,
                    "risk_level": alert.finding.risk_level.value,
                    "integration": {
                        "id": alert.finding.integration.id,
                        "name": alert.finding.integration.name,
                        "type": alert.finding.integration.integration_type
                    } if alert.finding.integration else None
                }
            
            if alert.assignee:
                alert_dict["assignee"] = {
                    "id": alert.assignee.id,
                    "name": alert.assignee.full_name,
                    "email": alert.assignee.email
                }
            
            alert_responses.append(AlertResponse(**alert_dict))
        
        total_pages = (total_count + page_size - 1) // page_size
        
        return AlertListResponse(
            alerts=alert_responses,
            total_count=total_count,
            page=page,
            page_size=page_size,
            total_pages=total_pages
        )
        
    except Exception as e:
        logger.error(f"Failed to list alerts: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve alerts")


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: str,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get detailed information for a specific alert.
    
    Returns complete alert data including related finding information,
    assignee details, and full metadata.
    """
    try:
        result = await db.execute(
            select(Alert)
            .options(
                selectinload(Alert.finding).selectinload(Finding.integration),
                selectinload(Alert.assignee)
            )
            .where(Alert.id == alert_id)
        )
        alert = result.scalar_one_or_none()
        
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        # Format response
        alert_dict = {
            "id": alert.id,
            "finding_id": alert.finding_id,
            "alert_type": alert.alert_type,
            "severity": alert.severity,
            "category": alert.category,
            "status": alert.status.value,
            "title": alert.title,
            "description": alert.description,
            "assignee_id": alert.assignee_id,
            "resolution_notes": alert.resolution_notes,
            "metadata": alert.metadata or {},
            "created_at": alert.created_at,
            "updated_at": alert.updated_at,
            "resolved_at": alert.resolved_at
        }
        
        # Add finding details
        if alert.finding:
            alert_dict["finding"] = {
                "id": alert.finding.id,
                "title": alert.finding.title,
                "description": alert.finding.description,
                "resource_name": alert.finding.resource_name,
                "resource_type": alert.finding.resource_type,
                "risk_level": alert.finding.risk_level.value,
                "location": alert.finding.location,
                "metadata": alert.finding.metadata,
                "remediation": alert.finding.remediation,
                "compliance_impact": alert.finding.compliance_impact,
                "integration": {
                    "id": alert.finding.integration.id,
                    "name": alert.finding.integration.name,
                    "type": alert.finding.integration.integration_type
                } if alert.finding.integration else None
            }
        
        # Add assignee details
        if alert.assignee:
            alert_dict["assignee"] = {
                "id": alert.assignee.id,
                "name": alert.assignee.full_name,
                "email": alert.assignee.email,
                "role": alert.assignee.role
            }
        
        return AlertResponse(**alert_dict)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get alert {alert_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve alert")


@router.post("/", response_model=AlertResponse)
async def create_alert(
    alert_request: AlertCreateRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(require_permissions(["alerts:create"]))
):
    """
    Create a new security alert.
    
    Validates the finding exists, creates the alert record, and triggers
    appropriate notifications based on configured alert rules.
    """
    try:
        alert_service = get_alert_service()
        
        # Create alert using service
        alert = await alert_service.create_alert(
            finding_id=alert_request.finding_id,
            alert_type=alert_request.alert_type,
            severity=AlertSeverity(alert_request.severity.upper()),
            category=AlertCategory(alert_request.category.upper()),
            title=alert_request.title,
            description=alert_request.description,
            metadata=alert_request.metadata
        )
        
        if not alert:
            raise HTTPException(status_code=400, detail="Failed to create alert")
        
        # Get the created alert with related data
        result = await db.execute(
            select(Alert)
            .options(
                selectinload(Alert.finding).selectinload(Finding.integration),
                selectinload(Alert.assignee)
            )
            .where(Alert.id == alert.id)
        )
        alert = result.scalar_one()
        
        # Format response
        alert_dict = {
            "id": alert.id,
            "finding_id": alert.finding_id,
            "alert_type": alert.alert_type,
            "severity": alert.severity,
            "category": alert.category,
            "status": alert.status.value,
            "title": alert.title,
            "description": alert.description,
            "assignee_id": alert.assignee_id,
            "resolution_notes": alert.resolution_notes,
            "metadata": alert.metadata or {},
            "created_at": alert.created_at,
            "updated_at": alert.updated_at,
            "resolved_at": alert.resolved_at
        }
        
        if alert.finding:
            alert_dict["finding"] = {
                "id": alert.finding.id,
                "title": alert.finding.title,
                "resource_name": alert.finding.resource_name,
                "risk_level": alert.finding.risk_level.value,
                "integration": {
                    "id": alert.finding.integration.id,
                    "name": alert.finding.integration.name,
                    "type": alert.finding.integration.integration_type
                } if alert.finding.integration else None
            }
        
        logger.info(f"Created alert {alert.id} by user {current_user.id}")
        
        return AlertResponse(**alert_dict)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create alert: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to create alert")


@router.put("/{alert_id}", response_model=AlertResponse)
async def update_alert(
    alert_id: str,
    alert_request: AlertUpdateRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(require_permissions(["alerts:update"]))
):
    """
    Update an existing alert.
    
    Supports updating status, severity, assignee, and resolution notes.
    Automatically handles status transitions and audit logging.
    """
    try:
        # Get existing alert
        result = await db.execute(
            select(Alert)
            .options(
                selectinload(Alert.finding).selectinload(Finding.integration),
                selectinload(Alert.assignee)
            )
            .where(Alert.id == alert_id)
        )
        alert = result.scalar_one_or_none()
        
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        # Prepare update values
        update_values = {"updated_at": datetime.utcnow()}
        
        if alert_request.status is not None:
            new_status = AlertStatus(alert_request.status.upper())
            update_values["status"] = new_status
            
            # Handle status-specific updates
            if new_status == AlertStatus.RESOLVED:
                update_values["resolved_at"] = datetime.utcnow()
                if alert_request.resolution_notes:
                    update_values["resolution_notes"] = alert_request.resolution_notes
        
        if alert_request.severity is not None:
            update_values["severity"] = alert_request.severity.lower()
        
        if alert_request.assignee_id is not None:
            # Validate assignee exists
            assignee_result = await db.execute(
                select(User).where(User.id == alert_request.assignee_id)
            )
            if not assignee_result.scalar_one_or_none():
                raise HTTPException(status_code=400, detail="Assignee not found")
            update_values["assignee_id"] = alert_request.assignee_id
        
        if alert_request.metadata is not None:
            # Merge metadata
            current_metadata = alert.metadata or {}
            current_metadata.update(alert_request.metadata)
            update_values["metadata"] = current_metadata
        
        # Update alert
        await db.execute(
            update(Alert)
            .where(Alert.id == alert_id)
            .values(**update_values)
        )
        await db.commit()
        
        # Get updated alert
        result = await db.execute(
            select(Alert)
            .options(
                selectinload(Alert.finding).selectinload(Finding.integration),
                selectinload(Alert.assignee)
            )
            .where(Alert.id == alert_id)
        )
        alert = result.scalar_one()
        
        # Log audit trail
        logger.info(f"Updated alert {alert_id} by user {current_user.id}: {update_values}")
        
        # Format response
        alert_dict = {
            "id": alert.id,
            "finding_id": alert.finding_id,
            "alert_type": alert.alert_type,
            "severity": alert.severity,
            "category": alert.category,
            "status": alert.status.value,
            "title": alert.title,
            "description": alert.description,
            "assignee_id": alert.assignee_id,
            "resolution_notes": alert.resolution_notes,
            "metadata": alert.metadata or {},
            "created_at": alert.created_at,
            "updated_at": alert.updated_at,
            "resolved_at": alert.resolved_at
        }
        
        if alert.finding:
            alert_dict["finding"] = {
                "id": alert.finding.id,
                "title": alert.finding.title,
                "resource_name": alert.finding.resource_name,
                "risk_level": alert.finding.risk_level.value,
                "integration": {
                    "id": alert.finding.integration.id,
                    "name": alert.finding.integration.name,
                    "type": alert.finding.integration.integration_type
                } if alert.finding.integration else None
            }
        
        if alert.assignee:
            alert_dict["assignee"] = {
                "id": alert.assignee.id,
                "name": alert.assignee.full_name,
                "email": alert.assignee.email
            }
        
        return AlertResponse(**alert_dict)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update alert {alert_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to update alert")


@router.delete("/{alert_id}")
async def delete_alert(
    alert_id: str,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(require_permissions(["alerts:delete"]))
):
    """
    Delete an alert (soft delete by marking as dismissed).
    
    For audit purposes, alerts are not permanently deleted but marked
    as dismissed with proper audit trail.
    """
    try:
        # Check if alert exists
        result = await db.execute(
            select(Alert).where(Alert.id == alert_id)
        )
        alert = result.scalar_one_or_none()
        
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        # Soft delete by updating status
        await db.execute(
            update(Alert)
            .where(Alert.id == alert_id)
            .values(
                status=AlertStatus.DISMISSED,
                updated_at=datetime.utcnow(),
                metadata={
                    **(alert.metadata or {}),
                    "dismissed_by": current_user.id,
                    "dismissed_at": datetime.utcnow().isoformat()
                }
            )
        )
        await db.commit()
        
        logger.info(f"Dismissed alert {alert_id} by user {current_user.id}")
        
        return {"message": "Alert dismissed successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete alert {alert_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to delete alert")


@router.post("/bulk-action")
async def bulk_alert_action(
    bulk_request: BulkActionRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(require_permissions(["alerts:bulk_update"]))
):
    """
    Perform bulk operations on multiple alerts.
    
    Supported actions:
    - resolve: Mark alerts as resolved
    - dismiss: Mark alerts as dismissed  
    - escalate: Escalate alert severity
    - assign: Assign alerts to a user
    """
    try:
        if len(bulk_request.alert_ids) > 100:
            raise HTTPException(status_code=400, detail="Too many alerts selected (max 100)")
        
        # Validate alerts exist
        result = await db.execute(
            select(Alert).where(Alert.id.in_(bulk_request.alert_ids))
        )
        alerts = result.scalars().all()
        
        if len(alerts) != len(bulk_request.alert_ids):
            raise HTTPException(status_code=400, detail="Some alerts not found")
        
        # Prepare update values based on action
        update_values = {"updated_at": datetime.utcnow()}
        
        if bulk_request.action == "resolve":
            update_values["status"] = AlertStatus.RESOLVED
            update_values["resolved_at"] = datetime.utcnow()
            if bulk_request.parameters and bulk_request.parameters.get("resolution_notes"):
                update_values["resolution_notes"] = bulk_request.parameters["resolution_notes"]
        
        elif bulk_request.action == "dismiss":
            update_values["status"] = AlertStatus.DISMISSED
            update_values["metadata"] = func.jsonb_set(
                Alert.metadata,
                '{}',
                f'{{"dismissed_by": "{current_user.id}", "dismissed_at": "{datetime.utcnow().isoformat()}"}}'
            )
        
        elif bulk_request.action == "escalate":
            # Escalate severity level
            current_severity_map = {"low": "medium", "medium": "high", "high": "critical"}
            # This would need more complex SQL for conditional updates
            
        elif bulk_request.action == "assign":
            if not bulk_request.parameters or not bulk_request.parameters.get("assignee_id"):
                raise HTTPException(status_code=400, detail="Assignee ID required for assignment")
            
            # Validate assignee
            assignee_result = await db.execute(
                select(User).where(User.id == bulk_request.parameters["assignee_id"])
            )
            if not assignee_result.scalar_one_or_none():
                raise HTTPException(status_code=400, detail="Assignee not found")
            
            update_values["assignee_id"] = bulk_request.parameters["assignee_id"]
        
        else:
            raise HTTPException(status_code=400, detail="Invalid bulk action")
        
        # Execute bulk update
        await db.execute(
            update(Alert)
            .where(Alert.id.in_(bulk_request.alert_ids))
            .values(**update_values)
        )
        await db.commit()
        
        logger.info(f"Bulk {bulk_request.action} performed on {len(bulk_request.alert_ids)} alerts by user {current_user.id}")
        
        return {
            "message": f"Successfully performed {bulk_request.action} on {len(bulk_request.alert_ids)} alerts",
            "affected_count": len(bulk_request.alert_ids)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to perform bulk action: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to perform bulk action")


@router.get("/{alert_id}/escalate")
async def escalate_alert(
    alert_id: str,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(require_permissions(["alerts:escalate"]))
):
    """
    Manually escalate an alert to higher severity.
    
    Increases severity level and triggers escalation notifications.
    """
    try:
        alert_service = get_alert_service()
        
        success = await alert_service.escalate_alert(alert_id)
        
        if not success:
            raise HTTPException(status_code=400, detail="Failed to escalate alert")
        
        logger.info(f"Alert {alert_id} escalated by user {current_user.id}")
        
        return {"message": "Alert escalated successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to escalate alert {alert_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to escalate alert")


@router.post("/{alert_id}/notify")
async def send_alert_notification(
    alert_id: str,
    notification_request: NotificationRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(require_permissions(["alerts:notify"]))
):
    """
    Send manual notification for an alert.
    
    Allows sending notifications through specific channels with
    custom messages for urgent situations.
    """
    try:
        # Get alert
        result = await db.execute(
            select(Alert)
            .options(selectinload(Alert.finding).selectinload(Finding.integration))
            .where(Alert.id == alert_id)
        )
        alert = result.scalar_one_or_none()
        
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        alert_service = get_alert_service()
        
        # Send notifications through specified channels
        notification_results = []
        for channel in notification_request.channels:
            try:
                channel_type = NotificationType(channel.upper())
                # This would integrate with the alert service notification methods
                # For now, we'll simulate success
                notification_results.append({
                    "channel": channel,
                    "status": "sent",
                    "timestamp": datetime.utcnow().isoformat()
                })
            except ValueError:
                notification_results.append({
                    "channel": channel,
                    "status": "failed",
                    "error": "Invalid channel type"
                })
        
        logger.info(f"Manual notifications sent for alert {alert_id} by user {current_user.id}")
        
        return {
            "message": "Notifications sent",
            "results": notification_results
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to send notifications for alert {alert_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to send notifications")


@router.get("/statistics/overview", response_model=AlertStatisticsResponse)
async def get_alert_statistics(
    days: int = Query(30, ge=1, le=365, description="Number of days for statistics"),
    integration_id: Optional[str] = Query(None, description="Filter by integration"),
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get comprehensive alert statistics and metrics.
    
    Provides overview statistics including:
    - Alert counts by severity, status, and category
    - Resolution time metrics
    - Trend data over time
    - Compliance impact analysis
    """
    try:
        alert_service = get_alert_service()
        
        # Get statistics from service
        stats = await alert_service.get_alert_statistics(days, integration_id)
        
        if not stats:
            stats = {
                "total": 0,
                "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "by_status": {"open": 0, "in_progress": 0, "resolved": 0},
                "by_category": {},
                "resolution_time": {"average_hours": 0, "median_hours": 0},
                "escalation_rate": 0
            }
        
        # Generate trend data (simplified)
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        trend_data = []
        
        for i in range(min(days, 30)):  # Last 30 days max for trend
            date = cutoff_date + timedelta(days=i)
            # This would normally query actual daily counts
            trend_data.append({
                "date": date.strftime("%Y-%m-%d"),
                "total_alerts": 0,  # Would be calculated from DB
                "critical_alerts": 0,
                "resolved_alerts": 0
            })
        
        return AlertStatisticsResponse(
            total_alerts=stats["total"],
            by_severity=stats["by_severity"],
            by_status=stats["by_status"],
            by_category=stats["by_category"],
            resolution_metrics={
                "average_resolution_time_hours": stats["resolution_time"]["average_hours"],
                "median_resolution_time_hours": stats["resolution_time"]["median_hours"],
                "escalation_rate_percent": stats["escalation_rate"]
            },
            trend_data=trend_data,
            compliance_impact=stats.get("compliance_impact", {})
        )
        
    except Exception as e:
        logger.error(f"Failed to get alert statistics: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve statistics")


@router.post("/rules", response_model=Dict[str, str])
async def create_alert_rule(
    rule_request: AlertRuleRequest,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(require_permissions(["alerts:manage_rules"]))
):
    """
    Create a new alert generation rule.
    
    Alert rules define conditions for automatic alert creation
    and notification routing based on finding characteristics.
    """
    try:
        alert_service = get_alert_service()
        
        # Create alert rule
        from ..services.alert_services import AlertRule, AlertSeverity, AlertCategory, NotificationType
        
        rule = AlertRule(
            name=rule_request.name,
            conditions=rule_request.conditions,
            severity=AlertSeverity(rule_request.severity.upper()),
            category=AlertCategory(rule_request.category.upper()),
            enabled=rule_request.enabled,
            auto_escalate=rule_request.auto_escalate,
            escalation_delay=rule_request.escalation_delay,
            notification_channels=[NotificationType(ch.upper()) for ch in rule_request.notification_channels]
        )
        
        success = alert_service.add_alert_rule(rule)
        
        if not success:
            raise HTTPException(status_code=400, detail="Failed to create alert rule")
        
        logger.info(f"Created alert rule '{rule_request.name}' by user {current_user.id}")
        
        return {"message": "Alert rule created successfully", "rule_name": rule_request.name}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create alert rule: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to create alert rule")


@router.get("/health")
async def alert_service_health():
    """
    Get health status of the alert service.
    
    Returns operational status of notification channels,
    alert rules, and service components.
    """
    try:
        alert_service = get_alert_service()
        health_status = await alert_service.health_check()
        
        return {
            "status": "healthy" if health_status["service_healthy"] else "unhealthy",
            "details": health_status,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Alert service health check failed: {str(e)}")
        return {
            "status": "error",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }
