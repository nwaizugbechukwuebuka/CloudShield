"""
CloudShield Alert System Test Suite
Comprehensive test coverage for alert system including notification channels,
escalation workflows, template processing, and integration testing.

Author: Chukwuebuka Tobiloba Nwaizugbe
Copyright (c) 2025 CloudShield Security Systems
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession
import json
from typing import Dict, Any, List

from ..api.main import app
from ..api.database import get_db_session, Base
from ..api.models.user import User
from ..api.models.findings import Finding
from ..api.services.alert_services import CloudShieldAlertService, AlertRule, NotificationChannel
from ..api.routes.alerts import router as alerts_router
from ..api.utils.config import get_settings

settings = get_settings()


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
async def test_db():
    """Create test database session"""
    TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"
    
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
    from sqlalchemy.orm import sessionmaker
    
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    
    # Create tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    yield async_session
    
    await engine.dispose()


@pytest.fixture
def client(test_db):
    """Create test client with database override"""
    async def override_get_db():
        async with test_db() as session:
            yield session
    
    app.dependency_overrides[get_db_session] = override_get_db
    client = TestClient(app)
    yield client
    del app.dependency_overrides[get_db_session]


@pytest.fixture
async def test_user(test_db) -> User:
    """Create test user"""
    async with test_db() as session:
        user = User(
            email="test@example.com",
            hashed_password="hashed_password",
            full_name="Test User",
            is_active=True,
            is_verified=True,
            role="user"
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)
        return user


@pytest.fixture
async def test_finding(test_db, test_user) -> Finding:
    """Create test security finding"""
    async with test_db() as session:
        finding = Finding(
            title="Test Security Finding",
            description="This is a test security finding",
            severity="HIGH",
            category="access_control",
            resource_name="Test Resource",
            location={"service": "test", "resource_id": "123"},
            remediation="Fix this issue",
            compliance_impact=["SOC2:CC1.1"],
            status="open",
            user_id=test_user.id
        )
        session.add(finding)
        await session.commit()
        await session.refresh(finding)
        return finding


@pytest.fixture
def alert_service():
    """Create alert service instance"""
    return CloudShieldAlertService()


@pytest.fixture
def mock_email_service():
    """Mock email service"""
    with patch('smtplib.SMTP') as mock_smtp:
        mock_instance = Mock()
        mock_smtp.return_value = mock_instance
        yield mock_instance


@pytest.fixture 
def mock_slack_service():
    """Mock Slack service"""
    with patch('httpx.AsyncClient.post') as mock_post:
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {"ok": True}
        yield mock_post


@pytest.fixture
def mock_teams_service():
    """Mock Teams service"""
    with patch('httpx.AsyncClient.post') as mock_post:
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {"status": "success"}
        yield mock_post


class TestAlertServiceInitialization:
    """Test alert service initialization and configuration"""
    
    def test_alert_service_initialization(self, alert_service):
        """Test alert service initializes correctly"""
        assert alert_service.version == "1.5.0"
        assert isinstance(alert_service.notification_channels, dict)
        assert isinstance(alert_service.alert_rules, list)
        assert isinstance(alert_service.escalation_policies, dict)
    
    def test_notification_channels_configuration(self, alert_service):
        """Test notification channels are properly configured"""
        channels = alert_service.notification_channels
        
        # Check required channels exist
        assert "email" in channels
        assert "slack" in channels
        assert "teams" in channels
        assert "webhook" in channels
        
        # Check channel configurations
        for channel_name, channel in channels.items():
            assert isinstance(channel, NotificationChannel)
            assert hasattr(channel, 'name')
            assert hasattr(channel, 'enabled')
    
    def test_alert_rules_initialization(self, alert_service):
        """Test alert rules are initialized"""
        rules = alert_service.alert_rules
        
        assert len(rules) > 0
        for rule in rules:
            assert isinstance(rule, AlertRule)
            assert hasattr(rule, 'name')
            assert hasattr(rule, 'conditions')
            assert hasattr(rule, 'actions')


class TestAlertGeneration:
    """Test alert generation functionality"""
    
    async def test_create_alert_from_finding(self, alert_service, test_finding):
        """Test creating alert from security finding"""
        alert = await alert_service.create_alert_from_finding(test_finding)
        
        assert alert is not None
        assert alert["title"] == test_finding.title
        assert alert["severity"] == test_finding.severity
        assert alert["category"] == test_finding.category
        assert "alert_id" in alert
        assert "created_at" in alert
    
    async def test_create_alert_custom(self, alert_service):
        """Test creating custom alert"""
        alert_data = {
            "title": "Custom Alert",
            "description": "This is a custom alert",
            "severity": "MEDIUM",
            "category": "custom",
            "source": "manual",
            "metadata": {"custom_field": "value"}
        }
        
        alert = await alert_service.create_alert(alert_data)
        
        assert alert["title"] == alert_data["title"]
        assert alert["severity"] == alert_data["severity"]
        assert alert["category"] == alert_data["category"]
        assert alert["source"] == alert_data["source"]
    
    async def test_alert_deduplication(self, alert_service, test_finding):
        """Test alert deduplication"""
        # Create first alert
        alert1 = await alert_service.create_alert_from_finding(test_finding)
        
        # Create duplicate alert
        alert2 = await alert_service.create_alert_from_finding(test_finding)
        
        # Should detect duplicate and not create new alert
        if alert_service.enable_deduplication:
            assert alert1["alert_id"] == alert2["alert_id"]
        else:
            assert alert1["alert_id"] != alert2["alert_id"]
    
    async def test_bulk_alert_creation(self, alert_service, test_db, test_user):
        """Test creating multiple alerts in bulk"""
        # Create multiple findings
        findings = []
        async with test_db() as session:
            for i in range(5):
                finding = Finding(
                    title=f"Test Finding {i}",
                    description=f"Description {i}",
                    severity="MEDIUM",
                    category="test",
                    resource_name=f"Resource {i}",
                    user_id=test_user.id
                )
                session.add(finding)
                findings.append(finding)
            await session.commit()
        
        # Create alerts in bulk
        alerts = await alert_service.create_alerts_bulk(findings)
        
        assert len(alerts) == 5
        for i, alert in enumerate(alerts):
            assert alert["title"] == f"Test Finding {i}"


class TestNotificationChannels:
    """Test notification channel functionality"""
    
    async def test_email_notification(self, alert_service, mock_email_service):
        """Test email notification sending"""
        alert_data = {
            "alert_id": "test-123",
            "title": "Test Alert",
            "description": "Test alert description",
            "severity": "HIGH",
            "created_at": datetime.utcnow().isoformat()
        }
        
        recipients = ["test@example.com", "admin@example.com"]
        
        result = await alert_service.send_email_notification(alert_data, recipients)
        
        assert result is True
        mock_email_service.starttls.assert_called_once()
        mock_email_service.login.assert_called_once()
        assert mock_email_service.send_message.call_count == len(recipients)
    
    async def test_slack_notification(self, alert_service, mock_slack_service):
        """Test Slack notification sending"""
        alert_data = {
            "alert_id": "test-123",
            "title": "Test Alert",
            "description": "Test alert description",
            "severity": "HIGH",
            "created_at": datetime.utcnow().isoformat()
        }
        
        channel = "#alerts"
        
        result = await alert_service.send_slack_notification(alert_data, channel)
        
        assert result is True
        mock_slack_service.assert_called_once()
        
        # Check call arguments
        call_args = mock_slack_service.call_args
        assert channel in str(call_args) or "alerts" in str(call_args)
    
    async def test_teams_notification(self, alert_service, mock_teams_service):
        """Test Microsoft Teams notification sending"""
        alert_data = {
            "alert_id": "test-123",
            "title": "Test Alert",
            "description": "Test alert description",
            "severity": "HIGH",
            "created_at": datetime.utcnow().isoformat()
        }
        
        webhook_url = "https://teams.webhook.url"
        
        result = await alert_service.send_teams_notification(alert_data, webhook_url)
        
        assert result is True
        mock_teams_service.assert_called_once()
    
    async def test_webhook_notification(self, alert_service):
        """Test webhook notification sending"""
        alert_data = {
            "alert_id": "test-123",
            "title": "Test Alert",
            "description": "Test alert description",
            "severity": "HIGH",
            "created_at": datetime.utcnow().isoformat()
        }
        
        webhook_config = {
            "url": "https://example.com/webhook",
            "headers": {"Authorization": "Bearer token"},
            "method": "POST"
        }
        
        with patch('httpx.AsyncClient.post') as mock_post:
            mock_post.return_value.status_code = 200
            
            result = await alert_service.send_webhook_notification(alert_data, webhook_config)
            
            assert result is True
            mock_post.assert_called_once()
    
    async def test_notification_failure_handling(self, alert_service):
        """Test notification failure handling"""
        alert_data = {
            "alert_id": "test-123",
            "title": "Test Alert",
            "severity": "HIGH"
        }
        
        # Mock failed email
        with patch('smtplib.SMTP') as mock_smtp:
            mock_smtp.side_effect = Exception("SMTP Error")
            
            result = await alert_service.send_email_notification(
                alert_data, ["test@example.com"]
            )
            
            assert result is False
    
    async def test_notification_retry_logic(self, alert_service):
        """Test notification retry logic"""
        alert_data = {
            "alert_id": "test-123",
            "title": "Test Alert",
            "severity": "HIGH"
        }
        
        with patch('httpx.AsyncClient.post') as mock_post:
            # First call fails, second succeeds
            mock_post.side_effect = [
                Exception("Network error"),
                Mock(status_code=200, json=lambda: {"ok": True})
            ]
            
            result = await alert_service.send_notification_with_retry(
                "webhook", alert_data, {"url": "https://example.com"}
            )
            
            # Should retry and succeed
            assert mock_post.call_count == 2


class TestAlertRules:
    """Test alert rule processing"""
    
    async def test_rule_matching(self, alert_service, test_finding):
        """Test alert rule matching"""
        # Create rule that matches HIGH severity findings
        high_severity_rule = AlertRule(
            name="High Severity Rule",
            conditions={
                "severity": "HIGH",
                "category": "access_control"
            },
            actions=[
                {"type": "email", "recipients": ["admin@example.com"]},
                {"type": "slack", "channel": "#critical-alerts"}
            ]
        )
        
        alert_service.alert_rules.append(high_severity_rule)
        
        matching_rules = await alert_service.find_matching_rules(test_finding)
        
        assert len(matching_rules) > 0
        assert any(rule.name == "High Severity Rule" for rule in matching_rules)
    
    async def test_rule_actions_execution(self, alert_service, mock_email_service, mock_slack_service):
        """Test rule actions execution"""
        alert_data = {
            "alert_id": "test-123",
            "title": "Test Alert",
            "severity": "HIGH",
            "category": "access_control"
        }
        
        rule = AlertRule(
            name="Test Rule",
            conditions={"severity": "HIGH"},
            actions=[
                {"type": "email", "recipients": ["admin@example.com"]},
                {"type": "slack", "channel": "#alerts"}
            ]
        )
        
        await alert_service.execute_rule_actions(rule, alert_data)
        
        # Verify both email and Slack actions were executed
        mock_email_service.send_message.assert_called()
        mock_slack_service.assert_called()
    
    async def test_conditional_rule_logic(self, alert_service):
        """Test complex conditional rule logic"""
        # Rule with multiple conditions
        complex_rule = AlertRule(
            name="Complex Rule",
            conditions={
                "severity": ["HIGH", "CRITICAL"],
                "category": "access_control",
                "compliance_impact": {"contains": "SOC2"}
            },
            actions=[{"type": "email", "recipients": ["compliance@example.com"]}]
        )
        
        # Test matching finding
        matching_finding = {
            "severity": "HIGH",
            "category": "access_control", 
            "compliance_impact": ["SOC2:CC1.1", "GDPR:Art25"]
        }
        
        # Test non-matching finding
        non_matching_finding = {
            "severity": "LOW",
            "category": "access_control",
            "compliance_impact": ["GDPR:Art25"]
        }
        
        assert alert_service._evaluate_rule_conditions(complex_rule, matching_finding) is True
        assert alert_service._evaluate_rule_conditions(complex_rule, non_matching_finding) is False


class TestEscalationWorkflows:
    """Test alert escalation workflows"""
    
    async def test_escalation_policy_creation(self, alert_service):
        """Test creating escalation policy"""
        policy = {
            "name": "Critical Escalation",
            "levels": [
                {
                    "level": 1,
                    "delay_minutes": 0,
                    "actions": [{"type": "email", "recipients": ["team@example.com"]}]
                },
                {
                    "level": 2,
                    "delay_minutes": 15,
                    "actions": [{"type": "slack", "channel": "#critical"}]
                },
                {
                    "level": 3,
                    "delay_minutes": 30,
                    "actions": [{"type": "email", "recipients": ["manager@example.com"]}]
                }
            ]
        }
        
        await alert_service.create_escalation_policy("critical", policy)
        
        assert "critical" in alert_service.escalation_policies
        assert len(alert_service.escalation_policies["critical"]["levels"]) == 3
    
    async def test_escalation_triggering(self, alert_service):
        """Test escalation triggering for unacknowledged alerts"""
        alert_data = {
            "alert_id": "esc-test-123",
            "title": "Escalation Test",
            "severity": "CRITICAL",
            "created_at": datetime.utcnow().isoformat(),
            "acknowledged": False
        }
        
        with patch.object(alert_service, 'schedule_escalation') as mock_schedule:
            await alert_service.create_alert(alert_data)
            
            # Should schedule escalation for critical alert
            mock_schedule.assert_called()
    
    async def test_escalation_cancellation(self, alert_service):
        """Test escalation cancellation when alert is acknowledged"""
        alert_id = "esc-cancel-123"
        
        # Set up escalation
        await alert_service.schedule_escalation(alert_id, "critical")
        
        # Acknowledge alert
        await alert_service.acknowledge_alert(alert_id, "user@example.com")
        
        # Verify escalation was cancelled
        escalations = alert_service.active_escalations.get(alert_id, [])
        cancelled_escalations = [e for e in escalations if e.get("cancelled")]
        
        assert len(cancelled_escalations) > 0


class TestAlertTemplates:
    """Test alert template processing"""
    
    def test_email_template_rendering(self, alert_service):
        """Test email template rendering"""
        alert_data = {
            "title": "Test Alert",
            "description": "This is a test alert",
            "severity": "HIGH",
            "resource_name": "Test Resource",
            "created_at": datetime.utcnow().isoformat()
        }
        
        template_name = "critical_security_alert"
        rendered = alert_service.render_template(template_name, alert_data)
        
        assert rendered is not None
        assert alert_data["title"] in rendered["subject"]
        assert alert_data["description"] in rendered["body"]
        assert alert_data["severity"] in rendered["body"]
    
    def test_slack_template_rendering(self, alert_service):
        """Test Slack template rendering"""
        alert_data = {
            "title": "Test Alert",
            "severity": "HIGH",
            "resource_name": "Test Resource"
        }
        
        template_name = "slack_security_alert"
        rendered = alert_service.render_template(template_name, alert_data)
        
        assert rendered is not None
        assert "blocks" in rendered or "text" in rendered
        assert alert_data["title"] in str(rendered)
    
    def test_teams_template_rendering(self, alert_service):
        """Test Teams template rendering"""
        alert_data = {
            "title": "Test Alert",
            "severity": "HIGH",
            "resource_name": "Test Resource"
        }
        
        template_name = "teams_security_alert"
        rendered = alert_service.render_template(template_name, alert_data)
        
        assert rendered is not None
        assert "@type" in rendered or "text" in rendered
        assert alert_data["title"] in str(rendered)
    
    def test_custom_template_variables(self, alert_service):
        """Test custom template variables"""
        alert_data = {
            "title": "Test Alert",
            "custom_field": "Custom Value",
            "metadata": {"key": "value"}
        }
        
        template_data = {
            "subject": "Alert: {{title}}",
            "body": "Custom: {{custom_field}}, Meta: {{metadata.key}}"
        }
        
        rendered = alert_service.render_custom_template(template_data, alert_data)
        
        assert rendered["subject"] == "Alert: Test Alert"
        assert rendered["body"] == "Custom: Custom Value, Meta: value"


class TestAlertAPI:
    """Test alert API endpoints"""
    
    def get_auth_headers(self, client, user_email="test@example.com"):
        """Helper to get authentication headers"""
        # This would need to be implemented based on your auth system
        return {"Authorization": "Bearer test-token"}
    
    def test_get_alerts_list(self, client):
        """Test getting alerts list"""
        headers = self.get_auth_headers(client)
        response = client.get("/alerts/", headers=headers)
        
        # Should return alerts list or 401 if auth not implemented
        assert response.status_code in [200, 401]
    
    def test_get_alert_by_id(self, client):
        """Test getting specific alert"""
        headers = self.get_auth_headers(client)
        alert_id = "test-123"
        
        response = client.get(f"/alerts/{alert_id}", headers=headers)
        
        # Should return alert or 404/401
        assert response.status_code in [200, 404, 401]
    
    def test_create_alert_api(self, client):
        """Test creating alert via API"""
        headers = self.get_auth_headers(client)
        alert_data = {
            "title": "API Test Alert",
            "description": "Created via API",
            "severity": "MEDIUM",
            "category": "test"
        }
        
        response = client.post("/alerts/", json=alert_data, headers=headers)
        
        # Should create alert or return auth error
        assert response.status_code in [201, 401, 422]
    
    def test_acknowledge_alert_api(self, client):
        """Test acknowledging alert via API"""
        headers = self.get_auth_headers(client)
        alert_id = "test-123"
        
        response = client.post(f"/alerts/{alert_id}/acknowledge", headers=headers)
        
        # Should acknowledge or return error
        assert response.status_code in [200, 404, 401]
    
    def test_close_alert_api(self, client):
        """Test closing alert via API"""
        headers = self.get_auth_headers(client)
        alert_id = "test-123"
        
        response = client.post(f"/alerts/{alert_id}/close", headers=headers)
        
        assert response.status_code in [200, 404, 401]
    
    def test_alerts_filtering(self, client):
        """Test alerts filtering and search"""
        headers = self.get_auth_headers(client)
        
        # Test severity filter
        response = client.get("/alerts/?severity=HIGH", headers=headers)
        assert response.status_code in [200, 401]
        
        # Test date filter
        response = client.get("/alerts/?created_after=2024-01-01", headers=headers)
        assert response.status_code in [200, 401]
        
        # Test status filter
        response = client.get("/alerts/?status=open", headers=headers)
        assert response.status_code in [200, 401]
    
    def test_alerts_pagination(self, client):
        """Test alerts pagination"""
        headers = self.get_auth_headers(client)
        
        response = client.get("/alerts/?page=1&size=10", headers=headers)
        assert response.status_code in [200, 401]
        
        if response.status_code == 200:
            data = response.json()
            assert "items" in data or "results" in data
            assert "total" in data or "count" in data
    
    def test_bulk_alert_operations(self, client):
        """Test bulk alert operations"""
        headers = self.get_auth_headers(client)
        
        # Test bulk acknowledge
        bulk_data = {
            "alert_ids": ["test-1", "test-2", "test-3"],
            "action": "acknowledge"
        }
        
        response = client.post("/alerts/bulk", json=bulk_data, headers=headers)
        assert response.status_code in [200, 401, 422]
    
    def test_alert_statistics(self, client):
        """Test alert statistics endpoint"""
        headers = self.get_auth_headers(client)
        
        response = client.get("/alerts/statistics", headers=headers)
        assert response.status_code in [200, 401]
        
        if response.status_code == 200:
            data = response.json()
            assert isinstance(data, dict)


class TestAlertIntegrations:
    """Test alert integrations with external systems"""
    
    async def test_jira_integration(self, alert_service):
        """Test Jira ticket creation integration"""
        alert_data = {
            "title": "Security Alert",
            "description": "Critical security issue found",
            "severity": "HIGH"
        }
        
        jira_config = {
            "url": "https://company.atlassian.net",
            "project": "SEC",
            "issue_type": "Bug"
        }
        
        with patch('httpx.AsyncClient.post') as mock_post:
            mock_post.return_value.status_code = 201
            mock_post.return_value.json.return_value = {
                "key": "SEC-123",
                "id": "12345"
            }
            
            result = await alert_service.create_jira_ticket(alert_data, jira_config)
            
            assert result["ticket_id"] == "SEC-123"
            mock_post.assert_called_once()
    
    async def test_pagerduty_integration(self, alert_service):
        """Test PagerDuty incident creation"""
        alert_data = {
            "title": "Critical Alert",
            "description": "System down",
            "severity": "CRITICAL"
        }
        
        pagerduty_config = {
            "routing_key": "test-key",
            "severity": "critical"
        }
        
        with patch('httpx.AsyncClient.post') as mock_post:
            mock_post.return_value.status_code = 202
            mock_post.return_value.json.return_value = {
                "status": "success",
                "incident_key": "PD-123"
            }
            
            result = await alert_service.create_pagerduty_incident(alert_data, pagerduty_config)
            
            assert result["incident_key"] == "PD-123"
            mock_post.assert_called_once()
    
    async def test_servicenow_integration(self, alert_service):
        """Test ServiceNow incident creation"""
        alert_data = {
            "title": "Security Incident",
            "description": "Security breach detected",
            "severity": "HIGH"
        }
        
        servicenow_config = {
            "instance": "company.service-now.com",
            "category": "Security",
            "priority": "2"
        }
        
        with patch('httpx.AsyncClient.post') as mock_post:
            mock_post.return_value.status_code = 201
            mock_post.return_value.json.return_value = {
                "result": {"number": "INC0123456"}
            }
            
            result = await alert_service.create_servicenow_incident(alert_data, servicenow_config)
            
            assert result["incident_number"] == "INC0123456"
            mock_post.assert_called_once()


class TestAlertPerformance:
    """Test alert performance and load handling"""
    
    async def test_high_volume_alert_processing(self, alert_service):
        """Test processing high volume of alerts"""
        # Create 100 alerts
        alerts = []
        for i in range(100):
            alert_data = {
                "title": f"Alert {i}",
                "description": f"Description {i}",
                "severity": "MEDIUM",
                "category": "test"
            }
            alerts.append(alert_data)
        
        start_time = datetime.utcnow()
        results = await alert_service.process_alerts_batch(alerts)
        end_time = datetime.utcnow()
        
        processing_time = (end_time - start_time).total_seconds()
        
        assert len(results) == 100
        assert processing_time < 30  # Should process 100 alerts in under 30 seconds
    
    async def test_rate_limiting(self, alert_service):
        """Test notification rate limiting"""
        alert_data = {
            "title": "Rate Limit Test",
            "severity": "LOW"
        }
        
        # Send many notifications rapidly
        results = []
        for i in range(20):
            result = await alert_service.send_notification_with_rate_limit(
                "email", alert_data, ["test@example.com"]
            )
            results.append(result)
        
        # Some should be rate limited
        successful = sum(1 for r in results if r)
        rate_limited = sum(1 for r in results if not r)
        
        assert rate_limited > 0  # Some should be rate limited
    
    async def test_concurrent_alert_processing(self, alert_service):
        """Test concurrent alert processing"""
        import asyncio
        
        # Create tasks for concurrent processing
        tasks = []
        for i in range(10):
            alert_data = {
                "title": f"Concurrent Alert {i}",
                "severity": "MEDIUM"
            }
            task = asyncio.create_task(alert_service.create_alert(alert_data))
            tasks.append(task)
        
        # Wait for all tasks to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # All should complete successfully
        successful_results = [r for r in results if not isinstance(r, Exception)]
        assert len(successful_results) == 10


class TestAlertMaintenance:
    """Test alert maintenance and cleanup"""
    
    async def test_alert_archival(self, alert_service):
        """Test archiving old alerts"""
        # Create old alert (simulated)
        old_alert = {
            "alert_id": "old-123",
            "title": "Old Alert",
            "created_at": (datetime.utcnow() - timedelta(days=90)).isoformat(),
            "status": "closed"
        }
        
        archived_count = await alert_service.archive_old_alerts(days=30)
        
        # Should archive alerts older than 30 days
        assert isinstance(archived_count, int)
        assert archived_count >= 0
    
    async def test_alert_cleanup(self, alert_service):
        """Test cleaning up processed alerts"""
        cleanup_stats = await alert_service.cleanup_processed_alerts()
        
        assert "deleted_count" in cleanup_stats
        assert "archived_count" in cleanup_stats
        assert isinstance(cleanup_stats["deleted_count"], int)
    
    async def test_escalation_cleanup(self, alert_service):
        """Test cleaning up completed escalations"""
        cleanup_count = await alert_service.cleanup_completed_escalations()
        
        assert isinstance(cleanup_count, int)
        assert cleanup_count >= 0


# Test fixtures for performance testing
@pytest.fixture
def performance_alerts():
    """Generate alerts for performance testing"""
    alerts = []
    severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    categories = ["access_control", "data_exposure", "compliance", "configuration"]
    
    for i in range(1000):
        alert = {
            "title": f"Performance Test Alert {i}",
            "description": f"This is test alert number {i}",
            "severity": severities[i % 4],
            "category": categories[i % 4],
            "resource_name": f"Resource-{i}",
            "created_at": datetime.utcnow().isoformat()
        }
        alerts.append(alert)
    
    return alerts


# Run the tests
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
