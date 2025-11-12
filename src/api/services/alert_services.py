"""
CloudShield Alert Service
Comprehensive alert management system for security notifications, escalations, and integrations.

Author: Chukwuebuka Tobiloba Nwaizugbe
Copyright (c) 2025 CloudShield Security Systems
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from enum import Enum
from dataclasses import dataclass, asdict
import aiohttp
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import jinja2
import slack_sdk
from slack_sdk.errors import SlackApiError
import requests

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sqlalchemy import select, update, delete, and_, or_, desc

from ..database import get_db
from ..models.findings import Finding, Alert, AlertStatus, RiskLevel
from ..models.user import User
from ..models.integration import Integration
from ..utils.config import get_settings
from ..utils.logger import get_logger

settings = get_settings()
logger = get_logger(__name__)


class AlertSeverity(Enum):
    """Alert severity levels for prioritization"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class NotificationType(Enum):
    """Types of notifications supported"""
    EMAIL = "email"
    SLACK = "slack"
    WEBHOOK = "webhook"
    SMS = "sms"
    TEAMS = "teams"
    DISCORD = "discord"


class AlertCategory(Enum):
    """Categories of security alerts"""
    VULNERABILITY = "vulnerability"
    COMPLIANCE = "compliance"
    ACCESS_CONTROL = "access_control"
    DATA_EXPOSURE = "data_exposure"
    CONFIGURATION = "configuration"
    AUTHENTICATION = "authentication"
    ENCRYPTION = "encryption"
    NETWORK_SECURITY = "network_security"


@dataclass
class NotificationConfig:
    """Configuration for notification channels"""
    type: NotificationType
    enabled: bool = True
    config: Dict[str, Any] = None
    templates: Dict[str, str] = None
    rate_limit: int = 10  # Max notifications per minute
    retry_attempts: int = 3
    retry_delay: int = 60  # seconds

    def __post_init__(self):
        if self.config is None:
            self.config = {}
        if self.templates is None:
            self.templates = {}


@dataclass
class AlertRule:
    """Alert generation and escalation rules"""
    name: str
    conditions: Dict[str, Any]
    severity: AlertSeverity
    category: AlertCategory
    enabled: bool = True
    auto_escalate: bool = False
    escalation_delay: int = 3600  # 1 hour
    notification_channels: List[NotificationType] = None
    custom_template: Optional[str] = None

    def __post_init__(self):
        if self.notification_channels is None:
            self.notification_channels = [NotificationType.EMAIL]


class CloudShieldAlertService:
    """
    Comprehensive alert management service for CloudShield security platform
    
    Features:
    - Multi-channel notifications (Email, Slack, Teams, Webhooks)
    - Intelligent alert aggregation and deduplication
    - Escalation workflows and SLA management
    - Custom alert rules and thresholds
    - Template-based notification formatting
    - Rate limiting and throttling
    - Audit logging and analytics
    """
    
    def __init__(self):
        self.notification_configs: Dict[NotificationType, NotificationConfig] = {}
        self.alert_rules: Dict[str, AlertRule] = {}
        self.template_env = jinja2.Environment(
            loader=jinja2.DictLoader({}),
            autoescape=jinja2.select_autoescape(['html', 'xml'])
        )
        
        # Initialize notification channels
        self._initialize_notification_configs()
        self._initialize_alert_rules()
        self._initialize_templates()
        
        # Rate limiting tracking
        self.rate_limits: Dict[str, List[datetime]] = {}
        
    def _initialize_notification_configs(self):
        """Initialize default notification channel configurations"""
        
        # Email configuration
        self.notification_configs[NotificationType.EMAIL] = NotificationConfig(
            type=NotificationType.EMAIL,
            enabled=bool(settings.SMTP_HOST),
            config={
                "smtp_host": settings.SMTP_HOST,
                "smtp_port": settings.SMTP_PORT,
                "username": settings.SMTP_USERNAME,
                "password": settings.SMTP_PASSWORD,
                "use_tls": settings.SMTP_USE_TLS,
                "from_email": settings.ALERT_FROM_EMAIL or "alerts@cloudshield.security",
                "from_name": "CloudShield Security Alerts"
            },
            rate_limit=30  # 30 emails per minute max
        )
        
        # Slack configuration
        self.notification_configs[NotificationType.SLACK] = NotificationConfig(
            type=NotificationType.SLACK,
            enabled=bool(settings.SLACK_BOT_TOKEN),
            config={
                "bot_token": settings.SLACK_BOT_TOKEN,
                "channel": settings.SLACK_ALERT_CHANNEL or "#security-alerts",
                "username": "CloudShield Bot",
                "icon_emoji": ":shield:"
            },
            rate_limit=20  # 20 messages per minute max
        )
        
        # Webhook configuration
        self.notification_configs[NotificationType.WEBHOOK] = NotificationConfig(
            type=NotificationType.WEBHOOK,
            enabled=bool(settings.WEBHOOK_URL),
            config={
                "url": settings.WEBHOOK_URL,
                "headers": {
                    "Content-Type": "application/json",
                    "User-Agent": "CloudShield-AlertService/1.0"
                },
                "timeout": 30,
                "verify_ssl": True
            },
            rate_limit=50  # 50 webhooks per minute max
        )
        
        # Microsoft Teams configuration
        self.notification_configs[NotificationType.TEAMS] = NotificationConfig(
            type=NotificationType.TEAMS,
            enabled=bool(settings.TEAMS_WEBHOOK_URL),
            config={
                "webhook_url": settings.TEAMS_WEBHOOK_URL,
                "timeout": 30
            },
            rate_limit=15  # 15 messages per minute max
        )
    
    def _initialize_alert_rules(self):
        """Initialize default alert rules and thresholds"""
        
        # Critical vulnerability alerts
        self.alert_rules["critical_vulnerability"] = AlertRule(
            name="Critical Vulnerability Detection",
            conditions={
                "risk_level": "CRITICAL",
                "finding_type": "vulnerability",
                "cvss_score": {">=": 9.0}
            },
            severity=AlertSeverity.CRITICAL,
            category=AlertCategory.VULNERABILITY,
            auto_escalate=True,
            escalation_delay=1800,  # 30 minutes
            notification_channels=[NotificationType.EMAIL, NotificationType.SLACK, NotificationType.TEAMS]
        )
        
        # High-risk data exposure
        self.alert_rules["data_exposure"] = AlertRule(
            name="Sensitive Data Exposure",
            conditions={
                "risk_level": ["HIGH", "CRITICAL"],
                "finding_type": "data_exposure",
                "keywords": ["password", "api_key", "secret", "token", "credential"]
            },
            severity=AlertSeverity.HIGH,
            category=AlertCategory.DATA_EXPOSURE,
            auto_escalate=True,
            escalation_delay=3600,  # 1 hour
            notification_channels=[NotificationType.EMAIL, NotificationType.SLACK]
        )
        
        # Compliance violations
        self.alert_rules["compliance_violation"] = AlertRule(
            name="Compliance Violation Detection",
            conditions={
                "risk_level": ["MEDIUM", "HIGH", "CRITICAL"],
                "compliance_frameworks": ["SOC2", "GDPR", "HIPAA", "ISO27001"]
            },
            severity=AlertSeverity.HIGH,
            category=AlertCategory.COMPLIANCE,
            notification_channels=[NotificationType.EMAIL]
        )
        
        # Access control issues
        self.alert_rules["access_control"] = AlertRule(
            name="Access Control Weakness",
            conditions={
                "finding_type": "access_control",
                "risk_level": ["HIGH", "CRITICAL"]
            },
            severity=AlertSeverity.MEDIUM,
            category=AlertCategory.ACCESS_CONTROL,
            notification_channels=[NotificationType.EMAIL, NotificationType.SLACK]
        )
        
        # Configuration security issues
        self.alert_rules["security_misconfiguration"] = AlertRule(
            name="Security Misconfiguration",
            conditions={
                "finding_type": "configuration",
                "risk_level": ["MEDIUM", "HIGH", "CRITICAL"]
            },
            severity=AlertSeverity.MEDIUM,
            category=AlertCategory.CONFIGURATION,
            notification_channels=[NotificationType.EMAIL]
        )
    
    def _initialize_templates(self):
        """Initialize notification templates"""
        
        # Email templates
        email_templates = {
            "critical_alert_subject": "🚨 CRITICAL: {{ alert.title }} - CloudShield Security Alert",
            "critical_alert_html": """
            <html>
            <head>
                <style>
                    .alert-critical { background-color: #dc3545; color: white; padding: 15px; border-radius: 5px; }
                    .alert-high { background-color: #fd7e14; color: white; padding: 15px; border-radius: 5px; }
                    .alert-medium { background-color: #ffc107; color: black; padding: 15px; border-radius: 5px; }
                    .alert-low { background-color: #28a745; color: white; padding: 15px; border-radius: 5px; }
                    .finding-details { background-color: #f8f9fa; padding: 10px; margin: 10px 0; border-left: 4px solid #007bff; }
                </style>
            </head>
            <body>
                <div class="alert-{{ alert.severity.lower() }}">
                    <h2>🛡️ CloudShield Security Alert</h2>
                    <h3>{{ alert.title }}</h3>
                    <p><strong>Severity:</strong> {{ alert.severity.upper() }}</p>
                    <p><strong>Category:</strong> {{ alert.category.replace('_', ' ').title() }}</p>
                    <p><strong>Detected:</strong> {{ alert.created_at.strftime('%Y-%m-%d %H:%M:%S UTC') }}</p>
                </div>
                
                <div class="finding-details">
                    <h4>Finding Details</h4>
                    <p><strong>Integration:</strong> {{ alert.finding.integration.name }}</p>
                    <p><strong>Resource:</strong> {{ alert.finding.resource_name }}</p>
                    <p><strong>Risk Level:</strong> {{ alert.finding.risk_level.value }}</p>
                    <p><strong>Description:</strong> {{ alert.finding.description }}</p>
                    
                    {% if alert.finding.remediation %}
                    <h4>Recommended Actions</h4>
                    <p>{{ alert.finding.remediation }}</p>
                    {% endif %}
                </div>
                
                <p><strong>Alert ID:</strong> {{ alert.id }}</p>
                <p><a href="{{ dashboard_url }}/alerts/{{ alert.id }}">View in CloudShield Dashboard</a></p>
                
                <hr>
                <p><small>This alert was generated by CloudShield Security Configuration Analyzer</small></p>
            </body>
            </html>
            """,
            
            "summary_report_html": """
            <html>
            <body>
                <h2>🛡️ CloudShield Security Summary Report</h2>
                <p><strong>Period:</strong> {{ start_date }} to {{ end_date }}</p>
                
                <h3>📊 Alert Statistics</h3>
                <ul>
                    <li>Critical Alerts: {{ stats.critical }}</li>
                    <li>High Severity: {{ stats.high }}</li>
                    <li>Medium Severity: {{ stats.medium }}</li>
                    <li>Low Severity: {{ stats.low }}</li>
                    <li>Total Alerts: {{ stats.total }}</li>
                </ul>
                
                <h3>🔍 Top Security Issues</h3>
                {% for issue in top_issues %}
                <div class="finding-details">
                    <p><strong>{{ issue.category.replace('_', ' ').title() }}:</strong> {{ issue.count }} occurrences</p>
                </div>
                {% endfor %}
                
                <p><a href="{{ dashboard_url }}">View Full Dashboard</a></p>
            </body>
            </html>
            """
        }
        
        # Slack templates
        slack_templates = {
            "critical_alert": {
                "text": "🚨 CRITICAL Security Alert from CloudShield",
                "attachments": [
                    {
                        "color": "danger",
                        "title": "{{ alert.title }}",
                        "fields": [
                            {
                                "title": "Severity",
                                "value": "{{ alert.severity.upper() }}",
                                "short": True
                            },
                            {
                                "title": "Integration",
                                "value": "{{ alert.finding.integration.name }}",
                                "short": True
                            },
                            {
                                "title": "Resource",
                                "value": "{{ alert.finding.resource_name }}",
                                "short": False
                            },
                            {
                                "title": "Description",
                                "value": "{{ alert.finding.description[:500] }}",
                                "short": False
                            }
                        ],
                        "footer": "CloudShield Security",
                        "ts": "{{ alert.created_at.timestamp() | int }}"
                    }
                ]
            }
        }
        
        # Load templates into Jinja environment
        all_templates = {**email_templates, **slack_templates}
        self.template_env = jinja2.Environment(
            loader=jinja2.DictLoader(all_templates),
            autoescape=jinja2.select_autoescape(['html', 'xml'])
        )
    
    async def create_alert(self, 
                          finding_id: str,
                          alert_type: str,
                          severity: AlertSeverity,
                          category: AlertCategory,
                          title: str,
                          description: str,
                          metadata: Optional[Dict] = None) -> Optional[Alert]:
        """Create a new security alert"""
        try:
            async with get_db() as db:
                # Check if similar alert already exists (deduplication)
                existing_alert = await self._check_duplicate_alert(
                    db, finding_id, alert_type, title
                )
                
                if existing_alert:
                    logger.info(f"Duplicate alert detected, updating existing alert: {existing_alert.id}")
                    return await self._update_existing_alert(db, existing_alert, metadata)
                
                # Create new alert
                alert = Alert(
                    finding_id=finding_id,
                    alert_type=alert_type,
                    severity=severity.value,
                    category=category.value,
                    title=title,
                    description=description,
                    metadata=metadata or {},
                    status=AlertStatus.OPEN,
                    created_at=datetime.utcnow()
                )
                
                db.add(alert)
                await db.commit()
                await db.refresh(alert)
                
                # Load related finding and integration data
                result = await db.execute(
                    select(Alert)
                    .options(
                        selectinload(Alert.finding).selectinload(Finding.integration)
                    )
                    .where(Alert.id == alert.id)
                )
                alert = result.scalar_one()
                
                logger.info(f"Created new alert: {alert.id} for finding: {finding_id}")
                
                # Schedule notifications
                await self._schedule_notifications(alert)
                
                return alert
                
        except Exception as e:
            logger.error(f"Failed to create alert for finding {finding_id}: {str(e)}")
            return None
    
    async def _check_duplicate_alert(self, 
                                   db: AsyncSession,
                                   finding_id: str,
                                   alert_type: str,
                                   title: str) -> Optional[Alert]:
        """Check for duplicate alerts within the last 24 hours"""
        try:
            cutoff_time = datetime.utcnow() - timedelta(hours=24)
            
            result = await db.execute(
                select(Alert)
                .where(
                    and_(
                        Alert.finding_id == finding_id,
                        Alert.alert_type == alert_type,
                        Alert.title == title,
                        Alert.created_at >= cutoff_time,
                        Alert.status.in_([AlertStatus.OPEN, AlertStatus.IN_PROGRESS])
                    )
                )
                .order_by(desc(Alert.created_at))
                .limit(1)
            )
            
            return result.scalar_one_or_none()
            
        except Exception as e:
            logger.error(f"Error checking for duplicate alerts: {str(e)}")
            return None
    
    async def _update_existing_alert(self, 
                                   db: AsyncSession,
                                   alert: Alert,
                                   new_metadata: Optional[Dict]) -> Alert:
        """Update an existing alert with new information"""
        try:
            # Update metadata and occurrence count
            if new_metadata:
                alert.metadata = {**alert.metadata, **new_metadata}
            
            alert.metadata["occurrence_count"] = alert.metadata.get("occurrence_count", 1) + 1
            alert.metadata["last_occurrence"] = datetime.utcnow().isoformat()
            alert.updated_at = datetime.utcnow()
            
            await db.commit()
            await db.refresh(alert)
            
            return alert
            
        except Exception as e:
            logger.error(f"Failed to update existing alert {alert.id}: {str(e)}")
            raise
    
    async def _schedule_notifications(self, alert: Alert):
        """Schedule notifications for the alert based on rules"""
        try:
            # Find matching alert rules
            matching_rules = self._find_matching_rules(alert)
            
            for rule in matching_rules:
                if not rule.enabled:
                    continue
                
                # Schedule notifications for each configured channel
                for channel_type in rule.notification_channels:
                    if channel_type in self.notification_configs:
                        config = self.notification_configs[channel_type]
                        if config.enabled:
                            await self._send_notification(alert, channel_type, rule)
                
                # Schedule escalation if configured
                if rule.auto_escalate:
                    await self._schedule_escalation(alert, rule.escalation_delay)
            
        except Exception as e:
            logger.error(f"Failed to schedule notifications for alert {alert.id}: {str(e)}")
    
    def _find_matching_rules(self, alert: Alert) -> List[AlertRule]:
        """Find alert rules that match the given alert"""
        matching_rules = []
        
        for rule in self.alert_rules.values():
            if self._rule_matches_alert(rule, alert):
                matching_rules.append(rule)
        
        return matching_rules
    
    def _rule_matches_alert(self, rule: AlertRule, alert: Alert) -> bool:
        """Check if an alert rule matches the given alert"""
        try:
            conditions = rule.conditions
            
            # Check severity match
            if rule.severity.value != alert.severity:
                return False
            
            # Check category match
            if rule.category.value != alert.category:
                return False
            
            # Check specific conditions
            for condition_key, condition_value in conditions.items():
                alert_value = getattr(alert, condition_key, None)
                if alert_value is None and hasattr(alert.finding, condition_key):
                    alert_value = getattr(alert.finding, condition_key)
                
                if not self._evaluate_condition(alert_value, condition_value):
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error matching rule {rule.name} to alert {alert.id}: {str(e)}")
            return False
    
    def _evaluate_condition(self, alert_value: Any, condition_value: Any) -> bool:
        """Evaluate a single condition against an alert value"""
        if isinstance(condition_value, dict):
            # Handle comparison operators
            for operator, expected_value in condition_value.items():
                if operator == ">=":
                    return alert_value >= expected_value
                elif operator == "<=":
                    return alert_value <= expected_value
                elif operator == ">":
                    return alert_value > expected_value
                elif operator == "<":
                    return alert_value < expected_value
                elif operator == "!=":
                    return alert_value != expected_value
                elif operator == "in":
                    return alert_value in expected_value
                elif operator == "contains":
                    return expected_value in str(alert_value).lower()
        elif isinstance(condition_value, list):
            return alert_value in condition_value
        else:
            return alert_value == condition_value
        
        return False
    
    async def _send_notification(self, 
                               alert: Alert,
                               channel_type: NotificationType,
                               rule: AlertRule):
        """Send notification through specified channel"""
        try:
            # Check rate limits
            if not self._check_rate_limit(channel_type):
                logger.warning(f"Rate limit exceeded for {channel_type.value}, skipping notification")
                return
            
            config = self.notification_configs[channel_type]
            
            if channel_type == NotificationType.EMAIL:
                await self._send_email_notification(alert, config, rule)
            elif channel_type == NotificationType.SLACK:
                await self._send_slack_notification(alert, config, rule)
            elif channel_type == NotificationType.WEBHOOK:
                await self._send_webhook_notification(alert, config, rule)
            elif channel_type == NotificationType.TEAMS:
                await self._send_teams_notification(alert, config, rule)
            
            # Track rate limit
            self._track_rate_limit(channel_type)
            
        except Exception as e:
            logger.error(f"Failed to send {channel_type.value} notification for alert {alert.id}: {str(e)}")
    
    def _check_rate_limit(self, channel_type: NotificationType) -> bool:
        """Check if we're within rate limits for the channel"""
        config = self.notification_configs[channel_type]
        now = datetime.utcnow()
        cutoff = now - timedelta(minutes=1)
        
        # Clean old entries
        if channel_type.value in self.rate_limits:
            self.rate_limits[channel_type.value] = [
                timestamp for timestamp in self.rate_limits[channel_type.value]
                if timestamp > cutoff
            ]
        else:
            self.rate_limits[channel_type.value] = []
        
        # Check if we're under the limit
        return len(self.rate_limits[channel_type.value]) < config.rate_limit
    
    def _track_rate_limit(self, channel_type: NotificationType):
        """Track a notification for rate limiting"""
        if channel_type.value not in self.rate_limits:
            self.rate_limits[channel_type.value] = []
        
        self.rate_limits[channel_type.value].append(datetime.utcnow())
    
    async def _send_email_notification(self, 
                                     alert: Alert,
                                     config: NotificationConfig,
                                     rule: AlertRule):
        """Send email notification"""
        try:
            # Render email content
            subject_template = self.template_env.get_template("critical_alert_subject")
            html_template = self.template_env.get_template("critical_alert_html")
            
            template_vars = {
                "alert": alert,
                "dashboard_url": settings.DASHBOARD_URL or "http://localhost:3000"
            }
            
            subject = subject_template.render(**template_vars)
            html_body = html_template.render(**template_vars)
            
            # Create email message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = f"{config.config['from_name']} <{config.config['from_email']}>"
            msg['To'] = settings.ALERT_EMAIL_RECIPIENTS or "admin@company.com"
            
            # Add HTML content
            html_part = MIMEText(html_body, 'html')
            msg.attach(html_part)
            
            # Send email
            with smtplib.SMTP(config.config['smtp_host'], config.config['smtp_port']) as server:
                if config.config['use_tls']:
                    server.starttls()
                if config.config['username']:
                    server.login(config.config['username'], config.config['password'])
                server.send_message(msg)
            
            logger.info(f"Email notification sent for alert {alert.id}")
            
        except Exception as e:
            logger.error(f"Failed to send email notification: {str(e)}")
            raise
    
    async def _send_slack_notification(self, 
                                     alert: Alert,
                                     config: NotificationConfig,
                                     rule: AlertRule):
        """Send Slack notification"""
        try:
            client = slack_sdk.WebClient(token=config.config['bot_token'])
            
            # Prepare message
            color_map = {
                AlertSeverity.CRITICAL: "danger",
                AlertSeverity.HIGH: "warning",
                AlertSeverity.MEDIUM: "good",
                AlertSeverity.LOW: "#36a64f"
            }
            
            attachment = {
                "color": color_map.get(AlertSeverity(alert.severity), "warning"),
                "title": alert.title,
                "fields": [
                    {
                        "title": "Severity",
                        "value": alert.severity.upper(),
                        "short": True
                    },
                    {
                        "title": "Integration",
                        "value": alert.finding.integration.name,
                        "short": True
                    },
                    {
                        "title": "Resource",
                        "value": alert.finding.resource_name,
                        "short": False
                    },
                    {
                        "title": "Description",
                        "value": alert.description[:500] + ("..." if len(alert.description) > 500 else ""),
                        "short": False
                    }
                ],
                "footer": "CloudShield Security",
                "ts": int(alert.created_at.timestamp()),
                "actions": [
                    {
                        "type": "button",
                        "text": "View Alert",
                        "url": f"{settings.DASHBOARD_URL}/alerts/{alert.id}"
                    }
                ]
            }
            
            response = client.chat_postMessage(
                channel=config.config['channel'],
                text=f"🚨 {alert.severity.upper()} Security Alert from CloudShield",
                username=config.config['username'],
                icon_emoji=config.config['icon_emoji'],
                attachments=[attachment]
            )
            
            logger.info(f"Slack notification sent for alert {alert.id}: {response['ts']}")
            
        except SlackApiError as e:
            logger.error(f"Slack API error: {e.response['error']}")
            raise
        except Exception as e:
            logger.error(f"Failed to send Slack notification: {str(e)}")
            raise
    
    async def _send_webhook_notification(self, 
                                       alert: Alert,
                                       config: NotificationConfig,
                                       rule: AlertRule):
        """Send webhook notification"""
        try:
            payload = {
                "alert_id": alert.id,
                "severity": alert.severity,
                "category": alert.category,
                "title": alert.title,
                "description": alert.description,
                "finding": {
                    "id": alert.finding.id,
                    "resource_name": alert.finding.resource_name,
                    "risk_level": alert.finding.risk_level.value,
                    "description": alert.finding.description
                },
                "integration": {
                    "id": alert.finding.integration.id,
                    "name": alert.finding.integration.name,
                    "type": alert.finding.integration.integration_type
                },
                "timestamp": alert.created_at.isoformat(),
                "dashboard_url": f"{settings.DASHBOARD_URL}/alerts/{alert.id}"
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    config.config['url'],
                    json=payload,
                    headers=config.config['headers'],
                    timeout=aiohttp.ClientTimeout(total=config.config['timeout']),
                    ssl=config.config['verify_ssl']
                ) as response:
                    if response.status == 200:
                        logger.info(f"Webhook notification sent for alert {alert.id}")
                    else:
                        logger.error(f"Webhook notification failed with status {response.status}")
            
        except Exception as e:
            logger.error(f"Failed to send webhook notification: {str(e)}")
            raise
    
    async def _send_teams_notification(self, 
                                     alert: Alert,
                                     config: NotificationConfig,
                                     rule: AlertRule):
        """Send Microsoft Teams notification"""
        try:
            color_map = {
                AlertSeverity.CRITICAL: "FF0000",
                AlertSeverity.HIGH: "FF8C00",
                AlertSeverity.MEDIUM: "FFD700",
                AlertSeverity.LOW: "008000"
            }
            
            card = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": color_map.get(AlertSeverity(alert.severity), "FFD700"),
                "summary": f"CloudShield Security Alert: {alert.title}",
                "sections": [
                    {
                        "activityTitle": f"🛡️ CloudShield Security Alert",
                        "activitySubtitle": alert.title,
                        "facts": [
                            {"name": "Severity", "value": alert.severity.upper()},
                            {"name": "Category", "value": alert.category.replace('_', ' ').title()},
                            {"name": "Integration", "value": alert.finding.integration.name},
                            {"name": "Resource", "value": alert.finding.resource_name},
                            {"name": "Time", "value": alert.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}
                        ],
                        "markdown": True
                    },
                    {
                        "text": alert.description
                    }
                ],
                "potentialAction": [
                    {
                        "@type": "OpenUri",
                        "name": "View in Dashboard",
                        "targets": [
                            {
                                "os": "default",
                                "uri": f"{settings.DASHBOARD_URL}/alerts/{alert.id}"
                            }
                        ]
                    }
                ]
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    config.config['webhook_url'],
                    json=card,
                    timeout=aiohttp.ClientTimeout(total=config.config['timeout'])
                ) as response:
                    if response.status == 200:
                        logger.info(f"Teams notification sent for alert {alert.id}")
                    else:
                        logger.error(f"Teams notification failed with status {response.status}")
            
        except Exception as e:
            logger.error(f"Failed to send Teams notification: {str(e)}")
            raise
    
    async def _schedule_escalation(self, alert: Alert, delay_seconds: int):
        """Schedule alert escalation"""
        try:
            from ..utils.scheduler import get_scheduler
            
            scheduler = get_scheduler()
            escalation_time = datetime.utcnow() + timedelta(seconds=delay_seconds)
            
            task_id = scheduler.schedule_immediate_task(
                task_path="src.tasks.alert_tasks.escalate_alert",
                kwargs={"alert_id": alert.id},
                eta=escalation_time,
                priority=scheduler.TaskPriority.HIGH,
                queue="alerts"
            )
            
            if task_id:
                # Store escalation task ID in alert metadata
                alert.metadata["escalation_task_id"] = task_id
                async with get_db() as db:
                    await db.commit()
                
                logger.info(f"Scheduled escalation for alert {alert.id} in {delay_seconds} seconds")
            
        except Exception as e:
            logger.error(f"Failed to schedule escalation for alert {alert.id}: {str(e)}")
    
    async def escalate_alert(self, alert_id: str) -> bool:
        """Escalate an alert to higher severity"""
        try:
            async with get_db() as db:
                result = await db.execute(
                    select(Alert)
                    .options(
                        selectinload(Alert.finding).selectinload(Finding.integration)
                    )
                    .where(Alert.id == alert_id)
                )
                alert = result.scalar_one_or_none()
                
                if not alert:
                    logger.error(f"Alert {alert_id} not found for escalation")
                    return False
                
                if alert.status not in [AlertStatus.OPEN, AlertStatus.IN_PROGRESS]:
                    logger.info(f"Alert {alert_id} already resolved, skipping escalation")
                    return False
                
                # Escalate severity
                current_severity = AlertSeverity(alert.severity)
                if current_severity == AlertSeverity.LOW:
                    new_severity = AlertSeverity.MEDIUM
                elif current_severity == AlertSeverity.MEDIUM:
                    new_severity = AlertSeverity.HIGH
                elif current_severity == AlertSeverity.HIGH:
                    new_severity = AlertSeverity.CRITICAL
                else:
                    logger.info(f"Alert {alert_id} already at maximum severity")
                    return False
                
                # Update alert
                alert.severity = new_severity.value
                alert.metadata["escalated"] = True
                alert.metadata["escalated_at"] = datetime.utcnow().isoformat()
                alert.metadata["previous_severity"] = current_severity.value
                alert.updated_at = datetime.utcnow()
                
                await db.commit()
                
                # Send escalated notifications
                await self._send_escalation_notifications(alert, current_severity, new_severity)
                
                logger.info(f"Escalated alert {alert_id} from {current_severity.value} to {new_severity.value}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to escalate alert {alert_id}: {str(e)}")
            return False
    
    async def _send_escalation_notifications(self, 
                                           alert: Alert,
                                           old_severity: AlertSeverity,
                                           new_severity: AlertSeverity):
        """Send notifications for escalated alerts"""
        try:
            # Find rules for the new severity level
            matching_rules = self._find_matching_rules(alert)
            
            for rule in matching_rules:
                if not rule.enabled:
                    continue
                
                # Send escalation notifications
                for channel_type in rule.notification_channels:
                    if channel_type in self.notification_configs:
                        config = self.notification_configs[channel_type]
                        if config.enabled:
                            # Add escalation context to alert
                            original_title = alert.title
                            alert.title = f"🔺 ESCALATED: {alert.title}"
                            alert.description = (f"This alert has been escalated from {old_severity.value.upper()} "
                                               f"to {new_severity.value.upper()} due to lack of response.\n\n"
                                               f"{alert.description}")
                            
                            await self._send_notification(alert, channel_type, rule)
                            
                            # Restore original title
                            alert.title = original_title
            
        except Exception as e:
            logger.error(f"Failed to send escalation notifications for alert {alert.id}: {str(e)}")
    
    async def resolve_alert(self, alert_id: str, resolution_notes: Optional[str] = None) -> bool:
        """Mark an alert as resolved"""
        try:
            async with get_db() as db:
                result = await db.execute(
                    select(Alert).where(Alert.id == alert_id)
                )
                alert = result.scalar_one_or_none()
                
                if not alert:
                    logger.error(f"Alert {alert_id} not found")
                    return False
                
                alert.status = AlertStatus.RESOLVED
                alert.resolved_at = datetime.utcnow()
                alert.updated_at = datetime.utcnow()
                
                if resolution_notes:
                    alert.metadata["resolution_notes"] = resolution_notes
                
                # Cancel escalation if scheduled
                if "escalation_task_id" in alert.metadata:
                    from ..utils.scheduler import get_scheduler
                    scheduler = get_scheduler()
                    scheduler.cancel_task(alert.metadata["escalation_task_id"])
                
                await db.commit()
                logger.info(f"Resolved alert {alert_id}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to resolve alert {alert_id}: {str(e)}")
            return False
    
    async def get_alert_statistics(self, 
                                 days: int = 30,
                                 integration_id: Optional[str] = None) -> Dict:
        """Get alert statistics for the specified period"""
        try:
            async with get_db() as db:
                cutoff_date = datetime.utcnow() - timedelta(days=days)
                
                # Base query
                query = select(Alert).where(Alert.created_at >= cutoff_date)
                
                if integration_id:
                    query = query.join(Finding).where(Finding.integration_id == integration_id)
                
                result = await db.execute(query)
                alerts = result.scalars().all()
                
                # Calculate statistics
                stats = {
                    "total": len(alerts),
                    "by_severity": {
                        "critical": len([a for a in alerts if a.severity == AlertSeverity.CRITICAL.value]),
                        "high": len([a for a in alerts if a.severity == AlertSeverity.HIGH.value]),
                        "medium": len([a for a in alerts if a.severity == AlertSeverity.MEDIUM.value]),
                        "low": len([a for a in alerts if a.severity == AlertSeverity.LOW.value])
                    },
                    "by_status": {
                        "open": len([a for a in alerts if a.status == AlertStatus.OPEN]),
                        "in_progress": len([a for a in alerts if a.status == AlertStatus.IN_PROGRESS]),
                        "resolved": len([a for a in alerts if a.status == AlertStatus.RESOLVED])
                    },
                    "by_category": {},
                    "resolution_time": {
                        "average_hours": 0,
                        "median_hours": 0
                    },
                    "escalation_rate": 0
                }
                
                # Category breakdown
                for category in AlertCategory:
                    stats["by_category"][category.value] = len([
                        a for a in alerts if a.category == category.value
                    ])
                
                # Resolution time analysis
                resolved_alerts = [a for a in alerts if a.resolved_at]
                if resolved_alerts:
                    resolution_times = [
                        (a.resolved_at - a.created_at).total_seconds() / 3600
                        for a in resolved_alerts
                    ]
                    stats["resolution_time"]["average_hours"] = sum(resolution_times) / len(resolution_times)
                    stats["resolution_time"]["median_hours"] = sorted(resolution_times)[len(resolution_times) // 2]
                
                # Escalation rate
                escalated_alerts = len([a for a in alerts if a.metadata.get("escalated")])
                stats["escalation_rate"] = (escalated_alerts / len(alerts) * 100) if alerts else 0
                
                return stats
                
        except Exception as e:
            logger.error(f"Failed to get alert statistics: {str(e)}")
            return {}
    
    async def generate_alert_report(self, 
                                  start_date: datetime,
                                  end_date: datetime,
                                  format_type: str = "html") -> Optional[str]:
        """Generate a comprehensive alert report"""
        try:
            async with get_db() as db:
                # Get alerts in date range
                result = await db.execute(
                    select(Alert)
                    .options(
                        selectinload(Alert.finding).selectinload(Finding.integration)
                    )
                    .where(
                        and_(
                            Alert.created_at >= start_date,
                            Alert.created_at <= end_date
                        )
                    )
                    .order_by(desc(Alert.created_at))
                )
                alerts = result.scalars().all()
                
                # Calculate report statistics
                stats = {
                    "total": len(alerts),
                    "critical": len([a for a in alerts if a.severity == AlertSeverity.CRITICAL.value]),
                    "high": len([a for a in alerts if a.severity == AlertSeverity.HIGH.value]),
                    "medium": len([a for a in alerts if a.severity == AlertSeverity.MEDIUM.value]),
                    "low": len([a for a in alerts if a.severity == AlertSeverity.LOW.value])
                }
                
                # Top issues
                category_counts = {}
                for alert in alerts:
                    category = alert.category
                    category_counts[category] = category_counts.get(category, 0) + 1
                
                top_issues = [
                    {"category": cat, "count": count}
                    for cat, count in sorted(category_counts.items(), 
                                           key=lambda x: x[1], reverse=True)[:10]
                ]
                
                # Render report
                template_vars = {
                    "start_date": start_date.strftime('%Y-%m-%d'),
                    "end_date": end_date.strftime('%Y-%m-%d'),
                    "stats": stats,
                    "top_issues": top_issues,
                    "alerts": alerts[:50],  # Limit to top 50 for report
                    "dashboard_url": settings.DASHBOARD_URL or "http://localhost:3000"
                }
                
                if format_type == "html":
                    template = self.template_env.get_template("summary_report_html")
                    return template.render(**template_vars)
                
                # Add more formats as needed (JSON, PDF, etc.)
                return json.dumps(template_vars, indent=2, default=str)
                
        except Exception as e:
            logger.error(f"Failed to generate alert report: {str(e)}")
            return None
    
    def add_notification_channel(self, 
                               channel_type: NotificationType,
                               config: NotificationConfig) -> bool:
        """Add or update a notification channel"""
        try:
            self.notification_configs[channel_type] = config
            logger.info(f"Added/updated notification channel: {channel_type.value}")
            return True
        except Exception as e:
            logger.error(f"Failed to add notification channel {channel_type.value}: {str(e)}")
            return False
    
    def add_alert_rule(self, rule: AlertRule) -> bool:
        """Add or update an alert rule"""
        try:
            self.alert_rules[rule.name] = rule
            logger.info(f"Added/updated alert rule: {rule.name}")
            return True
        except Exception as e:
            logger.error(f"Failed to add alert rule {rule.name}: {str(e)}")
            return False
    
    async def health_check(self) -> Dict:
        """Perform health check of the alert service"""
        health_status = {
            "service_healthy": True,
            "notification_channels": {},
            "alert_rules": len(self.alert_rules),
            "active_rules": len([r for r in self.alert_rules.values() if r.enabled]),
            "issues": []
        }
        
        # Check notification channels
        for channel_type, config in self.notification_configs.items():
            channel_health = {
                "enabled": config.enabled,
                "configured": bool(config.config),
                "healthy": False
            }
            
            if config.enabled and config.config:
                try:
                    # Basic connectivity check for each channel type
                    if channel_type == NotificationType.EMAIL and config.config.get('smtp_host'):
                        channel_health["healthy"] = True
                    elif channel_type == NotificationType.SLACK and config.config.get('bot_token'):
                        channel_health["healthy"] = True
                    elif channel_type == NotificationType.WEBHOOK and config.config.get('url'):
                        channel_health["healthy"] = True
                    elif channel_type == NotificationType.TEAMS and config.config.get('webhook_url'):
                        channel_health["healthy"] = True
                except Exception as e:
                    health_status["issues"].append(f"{channel_type.value} channel error: {str(e)}")
            
            health_status["notification_channels"][channel_type.value] = channel_health
        
        # Check if at least one notification channel is healthy
        healthy_channels = [
            ch for ch in health_status["notification_channels"].values()
            if ch["healthy"]
        ]
        
        if not healthy_channels:
            health_status["service_healthy"] = False
            health_status["issues"].append("No healthy notification channels available")
        
        return health_status


# Global alert service instance
alert_service = CloudShieldAlertService()


def get_alert_service() -> CloudShieldAlertService:
    """Get the global alert service instance"""
    return alert_service
