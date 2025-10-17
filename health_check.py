#!/usr/bin/env python3
"""
CloudShield System Health Check Script

This script validates that all CloudShield components are properly configured
and working together. Run this after deployment to ensure system readiness.
"""

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Dict, Any
import requests
import time
import subprocess

# Color codes for output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_success(message: str):
    print(f"{Colors.GREEN}✓{Colors.END} {message}")

def print_error(message: str):
    print(f"{Colors.RED}✗{Colors.END} {message}")

def print_warning(message: str):
    print(f"{Colors.YELLOW}⚠{Colors.END} {message}")

def print_info(message: str):
    print(f"{Colors.BLUE}ℹ{Colors.END} {message}")

def print_header(message: str):
    print(f"\n{Colors.BOLD}{Colors.BLUE}=== {message} ==={Colors.END}")

class HealthChecker:
    def __init__(self):
        self.base_url = "http://localhost:8000"
        self.frontend_url = "http://localhost:3000"
        self.flower_url = "http://localhost:5555"
        self.results = {}
    
    def check_environment(self) -> bool:
        """Check if required environment files exist."""
        print_header("Environment Configuration")
        
        # Check .env file
        if Path(".env").exists():
            print_success(".env file exists")
            
            # Check required environment variables
            required_vars = [
                'SECRET_KEY', 'DATABASE_URL', 'REDIS_URL'
            ]
            
            missing_vars = []
            with open('.env', 'r') as f:
                content = f.read()
                for var in required_vars:
                    if f"{var}=" not in content:
                        missing_vars.append(var)
            
            if missing_vars:
                print_warning(f"Missing environment variables: {', '.join(missing_vars)}")
                return False
            else:
                print_success("Required environment variables configured")
                return True
        else:
            print_error(".env file not found")
            print_info("Copy .env.example to .env and configure your settings")
            return False
    
    def check_docker_services(self) -> bool:
        """Check if Docker services are running."""
        print_header("Docker Services")
        
        try:
            result = subprocess.run(['docker-compose', 'ps'], 
                                  capture_output=True, text=True, check=True)
            
            services = ['db', 'redis', 'backend', 'frontend', 'celery_worker', 'nginx']
            running_services = []
            
            for service in services:
                if service in result.stdout and 'Up' in result.stdout:
                    running_services.append(service)
                    print_success(f"{service} service is running")
                else:
                    print_error(f"{service} service is not running")
            
            return len(running_services) == len(services)
        
        except subprocess.CalledProcessError:
            print_error("Failed to check Docker services")
            print_info("Run 'docker-compose up -d' to start services")
            return False
    
    def check_database_connection(self) -> bool:
        """Check database connectivity."""
        print_header("Database Connection")
        
        try:
            response = requests.get(f"{self.base_url}/health", timeout=10)
            if response.status_code == 200:
                health_data = response.json()
                if health_data.get('services', {}).get('database') == 'healthy':
                    print_success("Database connection is healthy")
                    return True
                else:
                    print_error("Database connection is unhealthy")
                    return False
            else:
                print_error(f"Health check failed with status {response.status_code}")
                return False
        except requests.RequestException as e:
            print_error(f"Cannot connect to backend: {e}")
            return False
    
    def check_redis_connection(self) -> bool:
        """Check Redis connectivity."""
        print_header("Redis Connection")
        
        try:
            response = requests.get(f"{self.base_url}/health", timeout=10)
            if response.status_code == 200:
                health_data = response.json()
                if health_data.get('services', {}).get('redis') == 'healthy':
                    print_success("Redis connection is healthy")
                    return True
                else:
                    print_error("Redis connection is unhealthy")
                    return False
        except requests.RequestException as e:
            print_error(f"Cannot check Redis connection: {e}")
            return False
    
    def check_api_endpoints(self) -> bool:
        """Check critical API endpoints."""
        print_header("API Endpoints")
        
        endpoints = [
            ('/health', 'GET', 'Health Check'),
            ('/api/auth/register', 'POST', 'User Registration'),
            ('/docs', 'GET', 'API Documentation'),
        ]
        
        success_count = 0
        
        for endpoint, method, name in endpoints:
            try:
                if method == 'GET':
                    response = requests.get(f"{self.base_url}{endpoint}", timeout=5)
                    if response.status_code in [200, 307]:  # 307 for redirects
                        print_success(f"{name} endpoint accessible")
                        success_count += 1
                    else:
                        print_error(f"{name} endpoint returned {response.status_code}")
                
                elif method == 'POST':
                    # Test with invalid data to check endpoint exists
                    response = requests.post(f"{self.base_url}{endpoint}", 
                                           json={}, timeout=5)
                    if response.status_code in [400, 422]:  # Expected validation errors
                        print_success(f"{name} endpoint accessible")
                        success_count += 1
                    else:
                        print_error(f"{name} endpoint returned {response.status_code}")
            
            except requests.RequestException as e:
                print_error(f"{name} endpoint not accessible: {e}")
        
        return success_count == len(endpoints)
    
    def check_frontend_accessibility(self) -> bool:
        """Check frontend accessibility."""
        print_header("Frontend Accessibility")
        
        try:
            response = requests.get(self.frontend_url, timeout=10)
            if response.status_code == 200:
                print_success("Frontend is accessible")
                return True
            else:
                print_error(f"Frontend returned status {response.status_code}")
                return False
        except requests.RequestException as e:
            print_error(f"Cannot access frontend: {e}")
            return False
    
    def check_celery_workers(self) -> bool:
        """Check Celery worker status."""
        print_header("Celery Workers")
        
        try:
            # Check via Flower API
            response = requests.get(f"{self.flower_url}/api/workers", timeout=10)
            if response.status_code == 200:
                workers = response.json()
                if workers:
                    print_success(f"Found {len(workers)} active Celery workers")
                    for worker_name in workers.keys():
                        print_info(f"  - {worker_name}")
                    return True
                else:
                    print_error("No active Celery workers found")
                    return False
            else:
                print_warning("Flower dashboard not accessible")
                # Fallback: check if Celery service is running via docker
                return self.check_docker_service_status('celery_worker')
        
        except requests.RequestException:
            print_warning("Cannot access Flower API, checking Docker service")
            return self.check_docker_service_status('celery_worker')
    
    def check_docker_service_status(self, service_name: str) -> bool:
        """Check if a specific Docker service is running."""
        try:
            result = subprocess.run(['docker-compose', 'ps', service_name], 
                                  capture_output=True, text=True, check=True)
            if 'Up' in result.stdout:
                print_success(f"{service_name} Docker service is running")
                return True
            else:
                print_error(f"{service_name} Docker service is not running")
                return False
        except subprocess.CalledProcessError:
            print_error(f"Failed to check {service_name} service status")
            return False
    
    def test_user_registration_flow(self) -> bool:
        """Test user registration and authentication flow."""
        print_header("Authentication Flow Test")
        
        # Test data
        test_user = {
            "email": "healthcheck@example.com",
            "username": "healthcheck_user",
            "password": "test_password_123"
        }
        
        try:
            # Test registration
            response = requests.post(
                f"{self.base_url}/api/auth/register",
                json=test_user,
                timeout=10
            )
            
            if response.status_code == 201:
                print_success("User registration endpoint working")
                
                # Test login
                login_response = requests.post(
                    f"{self.base_url}/api/auth/login",
                    data={
                        "username": test_user["email"],
                        "password": test_user["password"]
                    },
                    timeout=10
                )
                
                if login_response.status_code == 200:
                    token_data = login_response.json()
                    if "access_token" in token_data:
                        print_success("User login and JWT token generation working")
                        return True
                    else:
                        print_error("Login successful but no access token returned")
                        return False
                else:
                    print_error(f"Login failed with status {login_response.status_code}")
                    return False
            
            elif response.status_code == 400:
                # User might already exist, try login directly
                login_response = requests.post(
                    f"{self.base_url}/api/auth/login",
                    data={
                        "username": test_user["email"],
                        "password": test_user["password"]
                    },
                    timeout=10
                )
                
                if login_response.status_code == 200:
                    print_success("Authentication flow working (user already exists)")
                    return True
                else:
                    print_warning("User registration endpoint working but login failed")
                    return False
            
            else:
                print_error(f"User registration failed with status {response.status_code}")
                return False
                
        except requests.RequestException as e:
            print_error(f"Authentication flow test failed: {e}")
            return False
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate a comprehensive health check report."""
        print_header("System Health Report")
        
        checks = [
            ("Environment Configuration", self.check_environment),
            ("Docker Services", self.check_docker_services),
            ("Database Connection", self.check_database_connection),
            ("Redis Connection", self.check_redis_connection),
            ("API Endpoints", self.check_api_endpoints),
            ("Frontend Accessibility", self.check_frontend_accessibility),
            ("Celery Workers", self.check_celery_workers),
            ("Authentication Flow", self.test_user_registration_flow),
        ]
        
        results = {}
        passed = 0
        total = len(checks)
        
        for check_name, check_func in checks:
            try:
                result = check_func()
                results[check_name] = result
                if result:
                    passed += 1
            except Exception as e:
                print_error(f"Check '{check_name}' failed with error: {e}")
                results[check_name] = False
        
        # Summary
        print_header("Health Check Summary")
        
        if passed == total:
            print_success(f"All {total} health checks passed! ✨")
            print_info("CloudShield is ready for use!")
        else:
            print_warning(f"{passed}/{total} health checks passed")
            
            failed_checks = [name for name, result in results.items() if not result]
            print_error("Failed checks:")
            for check in failed_checks:
                print(f"  - {check}")
        
        print("\nQuick Start URLs:")
        print(f"  🌐 Web Dashboard: {self.frontend_url}")
        print(f"  📋 API Docs:      {self.base_url}/docs")
        print(f"  📊 Task Monitor:  {self.flower_url}")
        
        return {
            "total_checks": total,
            "passed_checks": passed,
            "success_rate": (passed / total) * 100,
            "results": results,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "overall_status": "healthy" if passed == total else "unhealthy"
        }

def main():
    """Main health check execution."""
    print(f"{Colors.BOLD}CloudShield System Health Check{Colors.END}")
    print("=" * 50)
    
    checker = HealthChecker()
    report = checker.generate_report()
    
    # Save report to file
    with open('health_check_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    print_info("\nHealth check report saved to: health_check_report.json")
    
    # Exit with appropriate code
    if report["overall_status"] == "healthy":
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()