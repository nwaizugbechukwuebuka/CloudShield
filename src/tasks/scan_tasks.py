"""
Scanning background tasks
"""
from celery import current_task
from datetime import datetime, timedelta
from typing import List
from sqlalchemy.orm import Session
from sqlalchemy import and_

from . import task, logger
from ..api.database import SessionLocal
from ..api.models.integration import Integration, IntegrationStatus
from ..api.models.findings import Finding, FindingType, RiskLevel, FindingStatus
from ..api.services.oauth_services import get_oauth_service, OAuthError
from ..api.services.risk_engine import risk_engine
from ..scanner.common import scanner_registry


def get_db_session():
    """Get database session for tasks"""
    return SessionLocal()


@task(name="src.tasks.scan_tasks.run_scheduled_scans")
def run_scheduled_scans():
    """Run scheduled security scans for all active integrations"""
    logger.info("Starting scheduled scans")
    
    db = get_db_session()
    try:
        # Get integrations that need scanning
        now = datetime.utcnow()
        integrations_to_scan = db.query(Integration).filter(
            and_(
                Integration.status == IntegrationStatus.ACTIVE,
                Integration.scan_enabled == True,
                Integration.next_scan_at <= now
            )
        ).all()
        
        logger.info(f"Found {len(integrations_to_scan)} integrations to scan")
        
        for integration in integrations_to_scan:
            try:
                # Schedule individual scan task
                run_integration_scan.delay(integration.id)
                logger.info(f"Scheduled scan for integration {integration.id}")
                
            except Exception as e:
                logger.error(
                    f"Failed to schedule scan for integration {integration.id}",
                    error=str(e)
                )
        
        return {"scheduled_scans": len(integrations_to_scan)}
        
    except Exception as e:
        logger.error("Failed to run scheduled scans", error=str(e))
        raise
    finally:
        db.close()


@task(name="src.tasks.scan_tasks.run_integration_scan")
def run_integration_scan(integration_id: int):
    """Run security scan for a specific integration"""
    logger.info(f"Starting scan for integration {integration_id}")
    
    db = get_db_session()
    try:
        # Get integration
        integration = db.query(Integration).filter(Integration.id == integration_id).first()
        if not integration:
            logger.error(f"Integration {integration_id} not found")
            return {"error": "Integration not found"}
        
        # Update task progress
        if current_task:
            current_task.update_state(
                state="PROGRESS",
                meta={"integration_id": integration_id, "step": "authenticating"}
            )
        
        # Map integration type to service name
        type_service_map = {
            "google_workspace": "google_workspace",
            "microsoft_365": "microsoft_365", 
            "slack": "slack",
            "github": "github",
            "notion": "notion"
        }
        
        service_name = type_service_map.get(integration.type.value)
        if not service_name:
            error_msg = f"No scanner available for {integration.type.value}"
            logger.error(error_msg)
            return {"error": error_msg}
        
        # Update scan progress
        if current_task:
            current_task.update_state(
                state="PROGRESS",
                meta={"integration_id": integration_id, "step": "scanning"}
            )
        
        # Run the actual scan
        scan_start_time = datetime.utcnow()
        
        try:
            # This is a synchronous call to the async scanner
            # In a real implementation, you'd need to run this properly
            import asyncio
            
            async def run_scan():
                return await scanner_registry.run_scan(
                    service_name,
                    integration.access_token
                )
            
            # Run async scan in event loop
            scan_results = asyncio.run(run_scan())
            
        except Exception as e:
            logger.error(f"Scan failed for integration {integration_id}", error=str(e))
            integration.status = IntegrationStatus.ERROR
            db.commit()
            return {"error": f"Scan failed: {str(e)}"}
        
        # Process scan results
        findings_created = 0
        findings_updated = 0
        
        for result in scan_results:
            # Calculate risk score
            risk_score, risk_level = risk_engine.calculate_risk_score(
                result.finding_type,
                result.evidence
            )
            
            # Check for existing finding
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
                findings_updated += 1
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
                
                # Schedule alert for critical findings
                if risk_level == RiskLevel.CRITICAL:
                    from .alert_tasks import send_critical_finding_alert
                    send_critical_finding_alert.delay(finding.id)
        
        # Update integration scan info
        integration.last_scan_at = datetime.utcnow()
        integration.next_scan_at = datetime.utcnow() + timedelta(hours=integration.scan_frequency_hours)
        
        db.commit()
        
        scan_duration = (datetime.utcnow() - scan_start_time).total_seconds()
        
        result = {
            "integration_id": integration_id,
            "findings_created": findings_created,
            "findings_updated": findings_updated,
            "total_findings": len(scan_results),
            "scan_duration_seconds": scan_duration,
            "status": "completed"
        }
        
        logger.info(
            f"Scan completed for integration {integration_id}",
            **result
        )
        
        return result
        
    except Exception as e:
        logger.error(f"Integration scan failed for {integration_id}", error=str(e))
        raise
    finally:
        db.close()


@task(name="src.tasks.scan_tasks.refresh_integration_tokens")
def refresh_integration_tokens():
    """Refresh OAuth tokens for integrations that are about to expire"""
    logger.info("Starting token refresh process")
    
    db = get_db_session()
    try:
        # Find integrations with tokens expiring in the next hour
        expiry_threshold = datetime.utcnow() + timedelta(hours=1)
        
        integrations = db.query(Integration).filter(
            and_(
                Integration.status == IntegrationStatus.ACTIVE,
                Integration.expires_at <= expiry_threshold,
                Integration.refresh_token.isnot(None)
            )
        ).all()
        
        refreshed_count = 0
        failed_count = 0
        
        for integration in integrations:
            try:
                # Map integration type to provider
                type_provider_map = {
                    "google_workspace": "google",
                    "microsoft_365": "microsoft",
                    "slack": "slack",
                    "github": "github",
                    "notion": "notion"
                }
                
                provider = type_provider_map.get(integration.type.value)
                if not provider:
                    logger.warning(f"No provider mapping for {integration.type.value}")
                    continue
                
                # Get OAuth service and refresh token
                oauth_service = get_oauth_service(provider)
                
                # This is a simplified token refresh - different providers have different mechanisms
                # In a real implementation, you'd need provider-specific refresh logic
                
                # For now, just mark as needing re-authentication
                integration.status = IntegrationStatus.ERROR
                logger.warning(f"Integration {integration.id} needs re-authentication")
                
                failed_count += 1
                
            except Exception as e:
                logger.error(
                    f"Failed to refresh token for integration {integration.id}",
                    error=str(e)
                )
                integration.status = IntegrationStatus.ERROR
                failed_count += 1
        
        db.commit()
        
        result = {
            "total_checked": len(integrations),
            "refreshed": refreshed_count,
            "failed": failed_count
        }
        
        logger.info("Token refresh completed", **result)
        return result
        
    except Exception as e:
        logger.error("Token refresh process failed", error=str(e))
        raise
    finally:
        db.close()


@task(name="src.tasks.scan_tasks.bulk_scan_integrations")
def bulk_scan_integrations(integration_ids: List[int]):
    """Run scans for multiple integrations in bulk"""
    logger.info(f"Starting bulk scan for {len(integration_ids)} integrations")
    
    results = []
    
    for integration_id in integration_ids:
        try:
            result = run_integration_scan.delay(integration_id)
            results.append({
                "integration_id": integration_id,
                "task_id": result.id,
                "status": "scheduled"
            })
        except Exception as e:
            results.append({
                "integration_id": integration_id,
                "status": "failed",
                "error": str(e)
            })
    
    return {
        "total_integrations": len(integration_ids),
        "results": results
    }
