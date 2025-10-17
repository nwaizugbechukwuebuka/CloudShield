"""
Alert and notification background tasks
"""
import json
import httpx
from datetime import datetime, timedelta
from typing import List, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import and_, desc

from . import task, logger
from ..api.database import SessionLocal
from ..api.models.user import User
from ..api.models.integration import Integration
from ..api.models.findings import Finding, RiskLevel, FindingStatus
from ..api.utils.config import settings


def get_db_session():
    """Get database session for tasks"""
    return SessionLocal()


@task(name="src.tasks.alert_tasks.send_critical_finding_alert")
def send_critical_finding_alert(finding_id: int):
    """Send immediate alert for critical security findings"""
    logger.info(f"Sending critical finding alert for finding {finding_id}")
    
    db = get_db_session()
    try:
        # Get finding with user and integration info
        finding = db.query(Finding).filter(Finding.id == finding_id).first()
        if not finding:
            logger.error(f"Finding {finding_id} not found")
            return {"error": "Finding not found"}
        
        user = finding.user
        integration = finding.integration
        
        # Prepare alert message
        alert_data = {
            "finding_id": finding.id,
            "title": finding.title,
            "description": finding.description,
            "risk_level": finding.risk_level.value,
            "risk_score": finding.risk_score,
            "resource_name": finding.resource_name,
            "integration_name": integration.name,
            "integration_type": integration.type.value,
            "user_email": user.email,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Send Slack alert if configured
        if settings.SLACK_WEBHOOK_URL:
            send_slack_alert(alert_data)
        
        # Send email alert if configured
        if settings.SMTP_USERNAME and settings.SMTP_PASSWORD:
            send_email_alert(user.email, alert_data)
        
        logger.info(f"Critical finding alert sent for finding {finding_id}")
        return {"status": "sent", "finding_id": finding_id}
        
    except Exception as e:
        logger.error(f"Failed to send critical finding alert for {finding_id}", error=str(e))
        raise
    finally:
        db.close()


@task(name="src.tasks.alert_tasks.send_alert_digest")
def send_alert_digest():
    """Send periodic digest of security findings to users"""
    logger.info("Starting alert digest generation")
    
    db = get_db_session()
    try:
        # Get all active users
        users = db.query(User).filter(User.is_active == True).all()
        
        digest_sent_count = 0
        
        for user in users:
            try:
                # Get recent findings for this user (last 24 hours)
                since = datetime.utcnow() - timedelta(hours=24)
                
                recent_findings = db.query(Finding).filter(
                    and_(
                        Finding.user_id == user.id,
                        Finding.created_at >= since,
                        Finding.status == FindingStatus.OPEN
                    )
                ).order_by(desc(Finding.risk_score)).all()
                
                if not recent_findings:
                    continue  # No new findings for this user
                
                # Group findings by risk level
                findings_by_risk = {
                    RiskLevel.CRITICAL: [],
                    RiskLevel.HIGH: [],
                    RiskLevel.MEDIUM: [],
                    RiskLevel.LOW: []
                }
                
                for finding in recent_findings:
                    findings_by_risk[finding.risk_level].append(finding)
                
                # Create digest data
                digest_data = {
                    "user_email": user.email,
                    "user_name": user.full_name,
                    "period": "24 hours",
                    "total_findings": len(recent_findings),
                    "findings_by_risk": {
                        risk_level.value: len(findings) 
                        for risk_level, findings in findings_by_risk.items()
                    },
                    "critical_findings": [
                        {
                            "title": f.title,
                            "resource_name": f.resource_name,
                            "integration_name": f.integration.name,
                            "risk_score": f.risk_score
                        }
                        for f in findings_by_risk[RiskLevel.CRITICAL][:5]  # Top 5 critical
                    ],
                    "timestamp": datetime.utcnow().isoformat()
                }
                
                # Send digest
                if settings.SMTP_USERNAME and settings.SMTP_PASSWORD:
                    send_digest_email(user.email, digest_data)
                
                digest_sent_count += 1
                
            except Exception as e:
                logger.error(f"Failed to send digest to {user.email}", error=str(e))
                continue
        
        result = {"digests_sent": digest_sent_count, "total_users": len(users)}
        logger.info("Alert digest completed", **result)
        return result
        
    except Exception as e:
        logger.error("Alert digest failed", error=str(e))
        raise
    finally:
        db.close()


@task(name="src.tasks.alert_tasks.send_compliance_report")
def send_compliance_report(user_id: int, report_type: str = "weekly"):
    """Send compliance and security posture report"""
    logger.info(f"Generating {report_type} compliance report for user {user_id}")
    
    db = get_db_session()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return {"error": "User not found"}
        
        # Calculate report period
        if report_type == "weekly":
            since = datetime.utcnow() - timedelta(days=7)
        elif report_type == "monthly":
            since = datetime.utcnow() - timedelta(days=30)
        else:
            since = datetime.utcnow() - timedelta(days=1)
        
        # Get all findings for user in period
        findings = db.query(Finding).filter(
            and_(
                Finding.user_id == user_id,
                Finding.created_at >= since
            )
        ).all()
        
        # Get user's integrations
        integrations = db.query(Integration).filter(Integration.user_id == user_id).all()
        
        # Calculate compliance metrics
        total_findings = len(findings)
        critical_findings = len([f for f in findings if f.risk_level == RiskLevel.CRITICAL])
        high_findings = len([f for f in findings if f.risk_level == RiskLevel.HIGH])
        resolved_findings = len([f for f in findings if f.status == FindingStatus.RESOLVED])
        
        # Calculate security score (simplified)
        if total_findings > 0:
            security_score = max(0, 100 - (critical_findings * 20 + high_findings * 10))
        else:
            security_score = 100
        
        # Create report data
        report_data = {
            "user_email": user.email,
            "user_name": user.full_name,
            "report_type": report_type,
            "period_start": since.isoformat(),
            "period_end": datetime.utcnow().isoformat(),
            "security_score": security_score,
            "total_integrations": len(integrations),
            "active_integrations": len([i for i in integrations if i.status.value == "active"]),
            "total_findings": total_findings,
            "critical_findings": critical_findings,
            "high_findings": high_findings,
            "resolved_findings": resolved_findings,
            "resolution_rate": (resolved_findings / total_findings * 100) if total_findings > 0 else 0,
            "top_risks": [
                {
                    "type": f.type.value,
                    "count": len([x for x in findings if x.type == f.type])
                }
                for f in sorted(set(findings), key=lambda x: x.risk_score, reverse=True)[:5]
            ]
        }
        
        # Send report
        if settings.SMTP_USERNAME and settings.SMTP_PASSWORD:
            send_compliance_report_email(user.email, report_data)
        
        logger.info(f"Compliance report sent to {user.email}")
        return {"status": "sent", "user_email": user.email, "report_type": report_type}
        
    except Exception as e:
        logger.error(f"Failed to send compliance report to user {user_id}", error=str(e))
        raise
    finally:
        db.close()


async def send_slack_alert(alert_data: Dict[str, Any]):
    """Send alert to Slack webhook"""
    try:
        if not settings.SLACK_WEBHOOK_URL:
            return
        
        # Create Slack message
        message = {
            "text": "🚨 Critical Security Finding Alert",
            "attachments": [
                {
                    "color": "danger",
                    "fields": [
                        {
                            "title": "Finding",
                            "value": alert_data["title"],
                            "short": False
                        },
                        {
                            "title": "Risk Score",
                            "value": f"{alert_data['risk_score']}/100",
                            "short": True
                        },
                        {
                            "title": "Resource",
                            "value": alert_data["resource_name"],
                            "short": True
                        },
                        {
                            "title": "Integration",
                            "value": f"{alert_data['integration_name']} ({alert_data['integration_type']})",
                            "short": False
                        }
                    ],
                    "footer": "CloudShield Security Analyzer",
                    "ts": int(datetime.utcnow().timestamp())
                }
            ]
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                settings.SLACK_WEBHOOK_URL,
                json=message,
                timeout=10.0
            )
            
            if response.status_code == 200:
                logger.info("Slack alert sent successfully")
            else:
                logger.error(f"Slack alert failed with status {response.status_code}")
                
    except Exception as e:
        logger.error("Failed to send Slack alert", error=str(e))


def send_email_alert(email: str, alert_data: Dict[str, Any]):
    """Send email alert (simplified implementation)"""
    try:
        # This is a simplified email implementation
        # In production, you'd use a proper email service
        logger.info(f"Would send email alert to {email} for finding {alert_data['finding_id']}")
        
        # Email content would include:
        # - Finding details
        # - Risk information
        # - Remediation steps
        # - Link to dashboard
        
    except Exception as e:
        logger.error(f"Failed to send email alert to {email}", error=str(e))


def send_digest_email(email: str, digest_data: Dict[str, Any]):
    """Send digest email (simplified implementation)"""
    try:
        logger.info(f"Would send digest email to {email} with {digest_data['total_findings']} findings")
        
        # Email would include:
        # - Summary of findings by risk level
        # - Key security metrics
        # - Trending information
        # - Recommended actions
        
    except Exception as e:
        logger.error(f"Failed to send digest email to {email}", error=str(e))


def send_compliance_report_email(email: str, report_data: Dict[str, Any]):
    """Send compliance report email (simplified implementation)"""
    try:
        logger.info(f"Would send compliance report to {email} - Security Score: {report_data['security_score']}")
        
        # Report would include:
        # - Executive summary
        # - Security posture metrics
        # - Compliance status
        # - Trend analysis
        # - Recommendations
        
    except Exception as e:
        logger.error(f"Failed to send compliance report to {email}", error=str(e))
