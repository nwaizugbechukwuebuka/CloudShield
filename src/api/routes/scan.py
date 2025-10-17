"""
Security scanning routes
"""
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc, func
from pydantic import BaseModel
import asyncio

from ..database import get_db
from ..models.user import User
from ..models.integration import Integration, IntegrationType, IntegrationStatus
from ..models.findings import Finding, FindingType, RiskLevel, FindingStatus
from ..services.risk_engine import risk_engine
from ..utils.logger import get_logger, security_logger
from .auth import get_current_active_user
from ...scanner.common import scanner_registry, ScanResult

logger = get_logger(__name__)
router = APIRouter(prefix="/scans", tags=["scanning"])


class ScanResponse(BaseModel):
    id: str
    integration_id: int
    status: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    findings_count: int
    error_message: Optional[str] = None


class FindingResponse(BaseModel):
    id: int
    title: str
    description: str
    type: str
    risk_level: str
    risk_score: float
    status: str
    resource_name: str
    resource_type: str
    remediation_steps: str
    first_seen_at: datetime
    last_seen_at: datetime
    occurrence_count: int
    integration_name: str
    integration_type: str
    
    class Config:
        from_attributes = True


class FindingUpdate(BaseModel):
    status: Optional[FindingStatus] = None
    resolution_notes: Optional[str] = None


class ScanStats(BaseModel):
    total_findings: int
    findings_by_risk: Dict[str, int]
    findings_by_type: Dict[str, int]
    findings_by_status: Dict[str, int]
    last_scan: Optional[datetime] = None


# In-memory store for scan status (in production, use Redis or database)
active_scans = {}


async def run_security_scan(integration_id: int, db: Session) -> Dict[str, Any]:
    """Run security scan for an integration"""
    scan_id = f"scan_{integration_id}_{datetime.utcnow().timestamp()}"
    
    try:
        # Get integration
        integration = db.query(Integration).filter(Integration.id == integration_id).first()
        if not integration:
            raise HTTPException(status_code=404, detail="Integration not found")
        
        # Update scan status
        active_scans[scan_id] = {
            "id": scan_id,
            "integration_id": integration_id,
            "status": "running",
            "started_at": datetime.utcnow(),
            "completed_at": None,
            "findings_count": 0,
            "error_message": None
        }
        
        # Map integration type to scanner service name
        type_service_map = {
            IntegrationType.GOOGLE_WORKSPACE: "google_workspace",
            IntegrationType.MICROSOFT_365: "microsoft_365",
            IntegrationType.SLACK: "slack",
            IntegrationType.GITHUB: "github",
            IntegrationType.NOTION: "notion"
        }
        
        service_name = type_service_map.get(integration.type)
        if not service_name:
            raise Exception(f"No scanner available for {integration.type}")
        
        # Log scan start
        security_logger.log_scan_started(
            integration_id,
            integration.type.value,
            integration.user.email
        )
        
        scan_start_time = datetime.utcnow()
        
        # Run scan
        scan_results = await scanner_registry.run_scan(
            service_name,
            integration.access_token
        )
        
        # Process scan results and create findings
        findings_created = 0
        
        for result in scan_results:
            # Calculate risk score
            risk_score, risk_level = risk_engine.calculate_risk_score(
                result.finding_type,
                result.evidence
            )
            
            # Check if similar finding already exists
            existing_finding = db.query(Finding).filter(
                Finding.integration_id == integration_id,
                Finding.resource_id == result.resource_id,
                Finding.type == result.finding_type,
                Finding.status.in_([FindingStatus.OPEN, FindingStatus.IN_PROGRESS])
            ).first()
            
            if existing_finding:
                # Update existing finding
                existing_finding.last_seen_at = datetime.utcnow()
                existing_finding.occurrence_count += 1
                existing_finding.evidence = result.evidence
                existing_finding.risk_score = risk_score
                existing_finding.risk_level = risk_level
            else:
                # Create new finding
                finding = Finding(
                    user_id=integration.user_id,
                    integration_id=integration_id,
                    title=result.title,
                    description=result.description,
                    type=result.finding_type,
                    risk_level=risk_level,
                    risk_score=risk_score,
                    resource_id=result.resource_id,
                    resource_name=result.resource_name,
                    resource_type=result.resource_type,
                    evidence=result.evidence,
                    metadata=result.metadata,
                    remediation_steps=result.remediation_steps,
                    first_seen_at=datetime.utcnow(),
                    last_seen_at=datetime.utcnow(),
                    occurrence_count=1
                )
                
                db.add(finding)
                findings_created += 1
                
                # Log critical findings
                if risk_level == RiskLevel.CRITICAL:
                    security_logger.log_critical_finding(
                        finding.id if finding.id else 0,
                        result.finding_type.value,
                        result.resource_name,
                        integration.user.email
                    )
                
                # Log finding creation
                security_logger.log_finding_created(
                    result.finding_type.value,
                    risk_level.value,
                    integration.type.value,
                    integration.user.email
                )
        
        # Update integration scan info
        integration.last_scan_at = datetime.utcnow()
        integration.next_scan_at = datetime.utcnow() + timedelta(hours=integration.scan_frequency_hours)
        
        db.commit()
        
        # Calculate scan duration
        scan_duration = (datetime.utcnow() - scan_start_time).total_seconds()
        
        # Log scan completion
        security_logger.log_scan_completed(
            integration_id,
            len(scan_results),
            scan_duration
        )
        
        # Update scan status
        active_scans[scan_id].update({
            "status": "completed",
            "completed_at": datetime.utcnow(),
            "findings_count": len(scan_results)
        })
        
        logger.info(
            "Security scan completed",
            scan_id=scan_id,
            integration_id=integration_id,
            findings_count=len(scan_results),
            findings_created=findings_created,
            duration_seconds=scan_duration
        )
        
        return active_scans[scan_id]
        
    except Exception as e:
        # Update scan status with error
        active_scans[scan_id].update({
            "status": "failed",
            "completed_at": datetime.utcnow(),
            "error_message": str(e)
        })
        
        logger.error(
            "Security scan failed",
            scan_id=scan_id,
            integration_id=integration_id,
            error=str(e)
        )
        
        raise e


@router.post("/{integration_id}/start", response_model=ScanResponse)
async def start_scan(
    integration_id: int,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Start a security scan for an integration"""
    
    # Get integration
    integration = db.query(Integration).filter(
        Integration.id == integration_id,
        Integration.user_id == current_user.id
    ).first()
    
    if not integration:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Integration not found"
        )
    
    if integration.status != IntegrationStatus.ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Integration is not active"
        )
    
    # Check if scan is already running
    running_scans = [
        scan for scan in active_scans.values()
        if scan["integration_id"] == integration_id and scan["status"] == "running"
    ]
    
    if running_scans:
        return running_scans[0]
    
    try:
        # Start scan in background
        scan_result = await run_security_scan(integration_id, db)
        return scan_result
        
    except Exception as e:
        logger.error(f"Failed to start scan for integration {integration_id}", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to start scan: {str(e)}"
        )


@router.get("/{scan_id}/status", response_model=ScanResponse)
async def get_scan_status(
    scan_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """Get status of a running scan"""
    
    scan_info = active_scans.get(scan_id)
    if not scan_info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    return scan_info


@router.get("/findings", response_model=List[FindingResponse])
async def list_findings(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    risk_level: Optional[RiskLevel] = Query(None),
    finding_type: Optional[FindingType] = Query(None),
    status: Optional[FindingStatus] = Query(None),
    integration_id: Optional[int] = Query(None),
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0)
):
    """List security findings for the current user"""
    
    query = db.query(Finding).filter(Finding.user_id == current_user.id)
    
    # Apply filters
    if risk_level:
        query = query.filter(Finding.risk_level == risk_level)
    
    if finding_type:
        query = query.filter(Finding.type == finding_type)
    
    if status:
        query = query.filter(Finding.status == status)
    
    if integration_id:
        query = query.filter(Finding.integration_id == integration_id)
    
    # Order by risk score and recency
    query = query.order_by(desc(Finding.risk_score), desc(Finding.created_at))
    
    # Apply pagination
    findings = query.offset(offset).limit(limit).all()
    
    # Add integration info to response
    result = []
    for finding in findings:
        finding_dict = finding.to_dict()
        finding_dict["integration_name"] = finding.integration.name
        finding_dict["integration_type"] = finding.integration.type.value
        result.append(FindingResponse(**finding_dict))
    
    return result


@router.get("/findings/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get a specific finding"""
    
    finding = db.query(Finding).filter(
        Finding.id == finding_id,
        Finding.user_id == current_user.id
    ).first()
    
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found"
        )
    
    finding_dict = finding.to_dict()
    finding_dict["integration_name"] = finding.integration.name
    finding_dict["integration_type"] = finding.integration.type.value
    
    return FindingResponse(**finding_dict)


@router.put("/findings/{finding_id}", response_model=FindingResponse)
async def update_finding(
    finding_id: int,
    update_data: FindingUpdate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Update a finding (mark as resolved, add notes, etc.)"""
    
    finding = db.query(Finding).filter(
        Finding.id == finding_id,
        Finding.user_id == current_user.id
    ).first()
    
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found"
        )
    
    # Update fields
    update_dict = update_data.dict(exclude_unset=True)
    
    for field, value in update_dict.items():
        setattr(finding, field, value)
    
    # Set resolved timestamp if status is changed to resolved
    if update_data.status in [FindingStatus.RESOLVED, FindingStatus.FALSE_POSITIVE]:
        finding.resolved_at = datetime.utcnow()
        finding.resolved_by = current_user.email
    
    db.commit()
    db.refresh(finding)
    
    finding_dict = finding.to_dict()
    finding_dict["integration_name"] = finding.integration.name
    finding_dict["integration_type"] = finding.integration.type.value
    
    logger.info(
        "Finding updated",
        finding_id=finding_id,
        user_email=current_user.email,
        updates=update_dict
    )
    
    return FindingResponse(**finding_dict)


@router.get("/stats", response_model=ScanStats)
async def get_scan_statistics(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get scan statistics for the current user"""
    
    # Total findings
    total_findings = db.query(Finding).filter(Finding.user_id == current_user.id).count()
    
    # Findings by risk level
    risk_counts = db.query(
        Finding.risk_level,
        func.count(Finding.id)
    ).filter(Finding.user_id == current_user.id).group_by(Finding.risk_level).all()
    
    findings_by_risk = {level.value: 0 for level in RiskLevel}
    for risk_level, count in risk_counts:
        findings_by_risk[risk_level.value] = count
    
    # Findings by type
    type_counts = db.query(
        Finding.type,
        func.count(Finding.id)
    ).filter(Finding.user_id == current_user.id).group_by(Finding.type).all()
    
    findings_by_type = {}
    for finding_type, count in type_counts:
        findings_by_type[finding_type.value] = count
    
    # Findings by status
    status_counts = db.query(
        Finding.status,
        func.count(Finding.id)
    ).filter(Finding.user_id == current_user.id).group_by(Finding.status).all()
    
    findings_by_status = {status.value: 0 for status in FindingStatus}
    for finding_status, count in status_counts:
        findings_by_status[finding_status.value] = count
    
    # Last scan timestamp
    last_integration_scan = db.query(Integration).filter(
        Integration.user_id == current_user.id,
        Integration.last_scan_at.isnot(None)
    ).order_by(desc(Integration.last_scan_at)).first()
    
    last_scan = last_integration_scan.last_scan_at if last_integration_scan else None
    
    return ScanStats(
        total_findings=total_findings,
        findings_by_risk=findings_by_risk,
        findings_by_type=findings_by_type,
        findings_by_status=findings_by_status,
        last_scan=last_scan
    )
