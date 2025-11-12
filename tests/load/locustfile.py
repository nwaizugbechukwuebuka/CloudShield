"""
Locust Load Testing for CloudShield API
Simulates realistic user behavior and API usage patterns
"""
from locust import HttpUser, task, between, SequentialTaskSet
import json
import random
from typing import Dict, Any


class CloudShieldUser(HttpUser):
    """Simulated CloudShield user performing various operations"""
    
    wait_time = between(1, 3)  # Wait 1-3 seconds between tasks
    
    def on_start(self):
        """Login before starting tasks"""
        self.login()
    
    def login(self):
        """Authenticate and store access token"""
        response = self.client.post(
            "/auth/login",
            json={
                "email": f"loadtest_{random.randint(1, 1000)}@example.com",
                "password": "LoadTest123!"
            },
            catch_response=True
        )
        
        if response.status_code == 200:
            data = response.json()
            self.access_token = data.get("access_token")
            self.headers = {"Authorization": f"Bearer {self.access_token}"}
            response.success()
        else:
            response.failure(f"Login failed: {response.status_code}")
    
    @task(5)
    def view_dashboard(self):
        """View dashboard overview"""
        with self.client.get(
            "/dashboard/overview",
            headers=self.headers,
            catch_response=True,
            name="/dashboard/overview"
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Failed to load dashboard: {response.status_code}")
    
    @task(10)
    def list_findings(self):
        """List security findings with various filters"""
        filters = [
            {"risk_level": "critical"},
            {"status": "open"},
            {"risk_level": "high", "status": "open"},
            {}  # No filter
        ]
        
        params = random.choice(filters)
        
        with self.client.get(
            "/findings",
            headers=self.headers,
            params=params,
            catch_response=True,
            name="/findings [filtered]"
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Failed to list findings: {response.status_code}")
    
    @task(3)
    def get_finding_details(self):
        """View details of a specific finding"""
        finding_id = random.randint(1, 100)
        
        with self.client.get(
            f"/findings/{finding_id}",
            headers=self.headers,
            catch_response=True,
            name="/findings/:id"
        ) as response:
            if response.status_code in [200, 404]:  # 404 is acceptable
                response.success()
            else:
                response.failure(f"Failed to get finding: {response.status_code}")
    
    @task(7)
    def list_integrations(self):
        """List all integrations"""
        with self.client.get(
            "/integrations",
            headers=self.headers,
            catch_response=True,
            name="/integrations"
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Failed to list integrations: {response.status_code}")
    
    @task(2)
    def get_integration_details(self):
        """View integration details"""
        integration_id = random.randint(1, 10)
        
        with self.client.get(
            f"/integrations/{integration_id}",
            headers=self.headers,
            catch_response=True,
            name="/integrations/:id"
        ) as response:
            if response.status_code in [200, 404]:
                response.success()
            else:
                response.failure(f"Failed to get integration: {response.status_code}")
    
    @task(1)
    def start_scan(self):
        """Initiate a security scan"""
        integration_id = random.randint(1, 10)
        
        with self.client.post(
            "/scans/start",
            headers=self.headers,
            json={
                "integration_id": integration_id,
                "scan_type": "quick",
                "options": {
                    "deep_scan": False
                }
            },
            catch_response=True,
            name="/scans/start"
        ) as response:
            if response.status_code in [202, 400]:  # 400 if integration doesn't exist
                response.success()
            else:
                response.failure(f"Failed to start scan: {response.status_code}")
    
    @task(4)
    def list_scans(self):
        """List scan history"""
        with self.client.get(
            "/scans",
            headers=self.headers,
            params={"limit": 20},
            catch_response=True,
            name="/scans"
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Failed to list scans: {response.status_code}")
    
    @task(2)
    def get_scan_status(self):
        """Check scan status"""
        # Use a mock scan ID
        scan_id = f"scan_{random.randint(1, 100)}"
        
        with self.client.get(
            f"/scans/{scan_id}",
            headers=self.headers,
            catch_response=True,
            name="/scans/:id"
        ) as response:
            if response.status_code in [200, 404]:
                response.success()
            else:
                response.failure(f"Failed to get scan status: {response.status_code}")
    
    @task(3)
    def view_risk_trends(self):
        """View risk trend analytics"""
        periods = ["7d", "30d", "90d"]
        period = random.choice(periods)
        
        with self.client.get(
            "/dashboard/risk-trends",
            headers=self.headers,
            params={"period": period},
            catch_response=True,
            name="/dashboard/risk-trends"
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Failed to get risk trends: {response.status_code}")
    
    @task(1)
    def update_finding(self):
        """Update a finding status"""
        finding_id = random.randint(1, 100)
        statuses = ["in_progress", "resolved", "ignored"]
        
        with self.client.patch(
            f"/findings/{finding_id}",
            headers=self.headers,
            json={
                "status": random.choice(statuses),
                "resolution_notes": "Load test update"
            },
            catch_response=True,
            name="/findings/:id [update]"
        ) as response:
            if response.status_code in [200, 404]:
                response.success()
            else:
                response.failure(f"Failed to update finding: {response.status_code}")


class AdminUser(HttpUser):
    """Simulated admin user performing administrative tasks"""
    
    wait_time = between(2, 5)
    weight = 1  # Lower weight than regular users
    
    def on_start(self):
        """Login as admin"""
        response = self.client.post(
            "/auth/login",
            json={
                "email": "admin@example.com",
                "password": "AdminPassword123!"
            }
        )
        
        if response.status_code == 200:
            self.access_token = response.json()["access_token"]
            self.headers = {"Authorization": f"Bearer {self.access_token}"}
    
    @task(10)
    def manage_users(self):
        """List and manage users"""
        self.client.get(
            "/users",
            headers=self.headers,
            name="/users [admin]"
        )
    
    @task(5)
    def view_system_stats(self):
        """View system-wide statistics"""
        self.client.get(
            "/dashboard/overview",
            headers=self.headers,
            params={"view": "admin"},
            name="/dashboard/overview [admin]"
        )
    
    @task(3)
    def manage_alert_rules(self):
        """Manage alert configurations"""
        self.client.get(
            "/alerts/rules",
            headers=self.headers,
            name="/alerts/rules [admin]"
        )


class ScanTaskSet(SequentialTaskSet):
    """Sequential scan workflow simulation"""
    
    @task
    def initiate_scan(self):
        """Start a comprehensive scan"""
        response = self.client.post(
            "/scans/start",
            headers=self.parent.headers,
            json={
                "integration_id": 1,
                "scan_type": "full",
                "options": {"deep_scan": True}
            }
        )
        
        if response.status_code == 202:
            self.scan_id = response.json()["scan_id"]
    
    @task
    def monitor_scan_progress(self):
        """Monitor scan progress"""
        if hasattr(self, 'scan_id'):
            for _ in range(5):  # Check 5 times
                self.client.get(
                    f"/scans/{self.scan_id}",
                    headers=self.parent.headers,
                    name="/scans/:id [monitor]"
                )
                self.wait()
    
    @task
    def review_findings(self):
        """Review findings from completed scan"""
        if hasattr(self, 'scan_id'):
            self.client.get(
                "/findings",
                headers=self.parent.headers,
                params={"scan_id": self.scan_id},
                name="/findings [by scan]"
            )
