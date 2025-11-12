"""
CloudShield Task Scheduler
Advanced Celery Beat configuration and task scheduling utilities for automated security scanning,
alert processing, and maintenance operations.

Author: Chukwuebuka Tobiloba Nwaizugbe
Copyright (c) 2025 CloudShield Security Systems
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from celery import Celery
from celery.schedules import crontab
from dataclasses import dataclass
import redis
import json
from enum import Enum

from ..utils.config import settings
from ..utils.logger import get_logger

logger = get_logger(__name__)


class TaskPriority(Enum):
    """Task priority levels for Celery queue management"""
    LOW = 1
    NORMAL = 5
    HIGH = 7
    CRITICAL = 9


class ScheduleType(Enum):
    """Types of scheduling patterns supported"""
    IMMEDIATE = "immediate"
    PERIODIC = "periodic"
    CRON = "cron"
    DELAYED = "delayed"


@dataclass
class TaskConfig:
    """Configuration for scheduled tasks"""
    name: str
    task_path: str
    schedule: Union[Dict, str, int]
    priority: TaskPriority = TaskPriority.NORMAL
    enabled: bool = True
    max_retries: int = 3
    retry_delay: int = 60
    timeout: int = 300
    queue: str = "default"
    routing_key: str = None
    expires: Optional[datetime] = None
    kwargs: Dict[str, Any] = None

    def __post_init__(self):
        if self.kwargs is None:
            self.kwargs = {}
        if self.routing_key is None:
            self.routing_key = self.queue


class CloudShieldScheduler:
    """
    Advanced task scheduler for CloudShield security operations
    
    Manages:
    - Automated security scanning schedules
    - Alert processing and notifications
    - Database maintenance and cleanup
    - Integration synchronization
    - Performance monitoring
    """
    
    def __init__(self, celery_app: Optional[Celery] = None):
        self.celery_app = celery_app
        self.redis_client = redis.Redis.from_url(settings.REDIS_URL)
        self.task_configs: Dict[str, TaskConfig] = {}
        self.active_schedules: Dict[str, Dict] = {}
        
        # Initialize default task configurations
        self._initialize_default_tasks()
        
    def _initialize_default_tasks(self):
        """Initialize default security scanning and maintenance tasks"""
        
        # Security scanning tasks
        self.task_configs.update({
            # High-frequency security scans
            "github_security_scan": TaskConfig(
                name="GitHub Repository Security Scan",
                task_path="src.tasks.scan_tasks.scan_github_repositories",
                schedule=crontab(minute=0),  # Every hour
                priority=TaskPriority.HIGH,
                queue="security_scans",
                timeout=600,
                max_retries=2
            ),
            
            "google_workspace_scan": TaskConfig(
                name="Google Workspace Security Assessment",
                task_path="src.tasks.scan_tasks.scan_google_workspace",
                schedule=crontab(minute=30, hour="*/4"),  # Every 4 hours
                priority=TaskPriority.HIGH,
                queue="security_scans",
                timeout=900
            ),
            
            "microsoft_365_scan": TaskConfig(
                name="Microsoft 365 Security Scan",
                task_path="src.tasks.scan_tasks.scan_microsoft_365",
                schedule=crontab(minute=45, hour="*/4"),  # Every 4 hours
                priority=TaskPriority.HIGH,
                queue="security_scans",
                timeout=900
            ),
            
            "slack_security_audit": TaskConfig(
                name="Slack Workspace Security Audit",
                task_path="src.tasks.scan_tasks.scan_slack_workspace",
                schedule=crontab(minute=15, hour="*/6"),  # Every 6 hours
                priority=TaskPriority.NORMAL,
                queue="security_scans",
                timeout=300
            ),
            
            "notion_security_check": TaskConfig(
                name="Notion Workspace Security Check",
                task_path="src.tasks.scan_tasks.scan_notion_workspace",
                schedule=crontab(minute=0, hour="*/8"),  # Every 8 hours
                priority=TaskPriority.NORMAL,
                queue="security_scans",
                timeout=300
            ),
            
            # Alert processing tasks
            "process_security_alerts": TaskConfig(
                name="Process Security Alerts",
                task_path="src.tasks.alert_tasks.process_pending_alerts",
                schedule=crontab(minute="*/5"),  # Every 5 minutes
                priority=TaskPriority.CRITICAL,
                queue="alerts",
                timeout=120,
                max_retries=5,
                retry_delay=30
            ),
            
            "send_alert_notifications": TaskConfig(
                name="Send Alert Notifications",
                task_path="src.tasks.alert_tasks.send_alert_notifications",
                schedule=crontab(minute="*/2"),  # Every 2 minutes
                priority=TaskPriority.CRITICAL,
                queue="notifications",
                timeout=60,
                max_retries=3
            ),
            
            "escalate_critical_alerts": TaskConfig(
                name="Escalate Critical Alerts",
                task_path="src.tasks.alert_tasks.escalate_critical_alerts",
                schedule=crontab(minute="*/10"),  # Every 10 minutes
                priority=TaskPriority.CRITICAL,
                queue="alerts",
                timeout=180
            ),
            
            # Maintenance and cleanup tasks
            "database_cleanup": TaskConfig(
                name="Database Maintenance and Cleanup",
                task_path="src.tasks.cleanup_tasks.cleanup_old_records",
                schedule=crontab(minute=0, hour=2),  # Daily at 2 AM
                priority=TaskPriority.LOW,
                queue="maintenance",
                timeout=1800
            ),
            
            "log_rotation": TaskConfig(
                name="Log File Rotation and Archival",
                task_path="src.tasks.cleanup_tasks.rotate_logs",
                schedule=crontab(minute=0, hour=1),  # Daily at 1 AM
                priority=TaskPriority.LOW,
                queue="maintenance",
                timeout=600
            ),
            
            "system_health_check": TaskConfig(
                name="System Health Monitoring",
                task_path="src.tasks.cleanup_tasks.system_health_check",
                schedule=crontab(minute="*/15"),  # Every 15 minutes
                priority=TaskPriority.NORMAL,
                queue="monitoring",
                timeout=120
            ),
            
            # Integration synchronization
            "sync_integrations": TaskConfig(
                name="Synchronize Integration Configurations",
                task_path="src.tasks.scan_tasks.sync_integration_configs",
                schedule=crontab(minute=0, hour="*/12"),  # Every 12 hours
                priority=TaskPriority.NORMAL,
                queue="integrations",
                timeout=600
            ),
            
            # Performance and analytics
            "generate_security_reports": TaskConfig(
                name="Generate Security Analytics Reports",
                task_path="src.tasks.alert_tasks.generate_security_reports",
                schedule=crontab(minute=0, hour=6),  # Daily at 6 AM
                priority=TaskPriority.LOW,
                queue="reports",
                timeout=900
            )
        })
    
    def register_task(self, task_config: TaskConfig) -> bool:
        """Register a new task configuration"""
        try:
            if not task_config.enabled:
                logger.info(f"Task {task_config.name} is disabled, skipping registration")
                return False
                
            self.task_configs[task_config.name] = task_config
            logger.info(f"Successfully registered task: {task_config.name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to register task {task_config.name}: {str(e)}")
            return False
    
    def unregister_task(self, task_name: str) -> bool:
        """Unregister a task configuration"""
        try:
            if task_name in self.task_configs:
                del self.task_configs[task_name]
                logger.info(f"Successfully unregistered task: {task_name}")
                return True
            else:
                logger.warning(f"Task {task_name} not found for unregistration")
                return False
                
        except Exception as e:
            logger.error(f"Failed to unregister task {task_name}: {str(e)}")
            return False
    
    def get_celery_beat_schedule(self) -> Dict[str, Dict]:
        """Generate Celery Beat schedule configuration"""
        beat_schedule = {}
        
        for task_name, config in self.task_configs.items():
            if not config.enabled:
                continue
                
            schedule_config = {
                'task': config.task_path,
                'schedule': config.schedule,
                'options': {
                    'priority': config.priority.value,
                    'queue': config.queue,
                    'routing_key': config.routing_key,
                    'retry': config.max_retries > 0,
                    'retry_policy': {
                        'max_retries': config.max_retries,
                        'interval_start': config.retry_delay,
                        'interval_step': config.retry_delay,
                        'interval_max': config.retry_delay * 10,
                    },
                    'time_limit': config.timeout,
                }
            }
            
            if config.kwargs:
                schedule_config['kwargs'] = config.kwargs
                
            if config.expires:
                schedule_config['expires'] = config.expires
            
            beat_schedule[task_name] = schedule_config
            
        return beat_schedule
    
    def schedule_immediate_task(self, 
                              task_path: str, 
                              args: Optional[List] = None,
                              kwargs: Optional[Dict] = None,
                              priority: TaskPriority = TaskPriority.NORMAL,
                              queue: str = "default",
                              countdown: int = 0,
                              eta: Optional[datetime] = None) -> Optional[str]:
        """Schedule a task for immediate or delayed execution"""
        try:
            if self.celery_app is None:
                logger.error("Celery app not available for immediate task scheduling")
                return None
                
            task_options = {
                'priority': priority.value,
                'queue': queue,
                'routing_key': queue
            }
            
            if countdown > 0:
                task_options['countdown'] = countdown
            elif eta:
                task_options['eta'] = eta
            
            result = self.celery_app.send_task(
                task_path,
                args=args or [],
                kwargs=kwargs or {},
                **task_options
            )
            
            logger.info(f"Scheduled immediate task {task_path} with ID: {result.id}")
            return result.id
            
        except Exception as e:
            logger.error(f"Failed to schedule immediate task {task_path}: {str(e)}")
            return None
    
    def schedule_security_scan(self, 
                             integration_type: str, 
                             integration_id: str,
                             scan_type: str = "full",
                             priority: TaskPriority = TaskPriority.HIGH) -> Optional[str]:
        """Schedule an immediate security scan for a specific integration"""
        
        task_mapping = {
            "github": "src.tasks.scan_tasks.scan_github_repositories",
            "google_workspace": "src.tasks.scan_tasks.scan_google_workspace",
            "microsoft_365": "src.tasks.scan_tasks.scan_microsoft_365",
            "slack": "src.tasks.scan_tasks.scan_slack_workspace",
            "notion": "src.tasks.scan_tasks.scan_notion_workspace"
        }
        
        task_path = task_mapping.get(integration_type.lower())
        if not task_path:
            logger.error(f"Unknown integration type for scanning: {integration_type}")
            return None
        
        return self.schedule_immediate_task(
            task_path=task_path,
            kwargs={
                "integration_id": integration_id,
                "scan_type": scan_type,
                "scheduled_scan": False
            },
            priority=priority,
            queue="security_scans"
        )
    
    def get_task_status(self, task_id: str) -> Optional[Dict]:
        """Get the status of a scheduled task"""
        try:
            if self.celery_app is None:
                return None
                
            result = self.celery_app.AsyncResult(task_id)
            return {
                "task_id": task_id,
                "status": result.status,
                "result": result.result if result.ready() else None,
                "traceback": result.traceback,
                "date_done": result.date_done
            }
            
        except Exception as e:
            logger.error(f"Failed to get task status for {task_id}: {str(e)}")
            return None
    
    def cancel_task(self, task_id: str) -> bool:
        """Cancel a scheduled or running task"""
        try:
            if self.celery_app is None:
                return False
                
            self.celery_app.control.revoke(task_id, terminate=True)
            logger.info(f"Successfully cancelled task: {task_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to cancel task {task_id}: {str(e)}")
            return False
    
    def get_active_tasks(self) -> List[Dict]:
        """Get list of currently active tasks"""
        try:
            if self.celery_app is None:
                return []
                
            inspect = self.celery_app.control.inspect()
            active_tasks = inspect.active()
            
            if not active_tasks:
                return []
            
            tasks = []
            for worker, worker_tasks in active_tasks.items():
                for task in worker_tasks:
                    tasks.append({
                        "worker": worker,
                        "task_id": task.get("id"),
                        "task_name": task.get("name"),
                        "args": task.get("args", []),
                        "kwargs": task.get("kwargs", {}),
                        "time_start": task.get("time_start")
                    })
            
            return tasks
            
        except Exception as e:
            logger.error(f"Failed to get active tasks: {str(e)}")
            return []
    
    def get_task_statistics(self) -> Dict:
        """Get comprehensive task execution statistics"""
        try:
            if self.celery_app is None:
                return {}
            
            inspect = self.celery_app.control.inspect()
            stats = inspect.stats()
            
            if not stats:
                return {}
            
            total_stats = {
                "workers": len(stats),
                "total_tasks": 0,
                "successful_tasks": 0,
                "failed_tasks": 0,
                "retry_tasks": 0,
                "active_tasks": 0,
                "scheduled_tasks": 0
            }
            
            for worker_name, worker_stats in stats.items():
                worker_data = worker_stats.get("total", {})
                total_stats["total_tasks"] += worker_data.get("total", 0)
                
            # Get active and scheduled task counts
            active_tasks = inspect.active() or {}
            scheduled_tasks = inspect.scheduled() or {}
            
            for worker_tasks in active_tasks.values():
                total_stats["active_tasks"] += len(worker_tasks)
                
            for worker_tasks in scheduled_tasks.values():
                total_stats["scheduled_tasks"] += len(worker_tasks)
            
            return total_stats
            
        except Exception as e:
            logger.error(f"Failed to get task statistics: {str(e)}")
            return {}
    
    def health_check(self) -> Dict:
        """Perform scheduler health check"""
        health_status = {
            "scheduler_healthy": True,
            "celery_available": False,
            "redis_available": False,
            "registered_tasks": len(self.task_configs),
            "enabled_tasks": len([t for t in self.task_configs.values() if t.enabled]),
            "workers_online": 0,
            "issues": []
        }
        
        try:
            # Check Redis connection
            self.redis_client.ping()
            health_status["redis_available"] = True
        except Exception as e:
            health_status["redis_available"] = False
            health_status["issues"].append(f"Redis connection failed: {str(e)}")
        
        try:
            # Check Celery workers
            if self.celery_app:
                inspect = self.celery_app.control.inspect()
                stats = inspect.stats()
                health_status["celery_available"] = True
                health_status["workers_online"] = len(stats) if stats else 0
                
                if health_status["workers_online"] == 0:
                    health_status["issues"].append("No Celery workers online")
                    
        except Exception as e:
            health_status["celery_available"] = False
            health_status["issues"].append(f"Celery connection failed: {str(e)}")
        
        # Overall health assessment
        critical_issues = [issue for issue in health_status["issues"] 
                          if "connection failed" in issue.lower()]
        
        if critical_issues or not (health_status["celery_available"] and health_status["redis_available"]):
            health_status["scheduler_healthy"] = False
        
        return health_status
    
    def update_task_schedule(self, task_name: str, new_schedule: Union[Dict, str]) -> bool:
        """Update the schedule for an existing task"""
        try:
            if task_name not in self.task_configs:
                logger.error(f"Task {task_name} not found for schedule update")
                return False
            
            self.task_configs[task_name].schedule = new_schedule
            logger.info(f"Updated schedule for task: {task_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to update schedule for task {task_name}: {str(e)}")
            return False
    
    def enable_task(self, task_name: str) -> bool:
        """Enable a disabled task"""
        try:
            if task_name not in self.task_configs:
                logger.error(f"Task {task_name} not found for enabling")
                return False
                
            self.task_configs[task_name].enabled = True
            logger.info(f"Enabled task: {task_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to enable task {task_name}: {str(e)}")
            return False
    
    def disable_task(self, task_name: str) -> bool:
        """Disable an enabled task"""
        try:
            if task_name not in self.task_configs:
                logger.error(f"Task {task_name} not found for disabling")
                return False
                
            self.task_configs[task_name].enabled = False
            logger.info(f"Disabled task: {task_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to disable task {task_name}: {str(e)}")
            return False


# Global scheduler instance
scheduler = CloudShieldScheduler()


def get_scheduler() -> CloudShieldScheduler:
    """Get the global scheduler instance"""
    return scheduler


def initialize_scheduler(celery_app: Celery) -> CloudShieldScheduler:
    """Initialize the scheduler with Celery app"""
    global scheduler
    scheduler.celery_app = celery_app
    logger.info("CloudShield Scheduler initialized successfully")
    return scheduler


def get_beat_schedule() -> Dict[str, Dict]:
    """Get the complete Celery Beat schedule configuration"""
    return scheduler.get_celery_beat_schedule()


# Emergency task scheduling functions
def schedule_emergency_scan(integration_type: str, integration_id: str) -> Optional[str]:
    """Schedule an emergency security scan with critical priority"""
    return scheduler.schedule_security_scan(
        integration_type=integration_type,
        integration_id=integration_id,
        scan_type="critical",
        priority=TaskPriority.CRITICAL
    )


def schedule_maintenance_window(start_time: datetime, duration_minutes: int = 60) -> List[str]:
    """Schedule maintenance tasks during a specified window"""
    task_ids = []
    
    # Schedule database maintenance
    db_task_id = scheduler.schedule_immediate_task(
        task_path="src.tasks.cleanup_tasks.maintenance_window_cleanup",
        kwargs={"duration_minutes": duration_minutes},
        eta=start_time,
        priority=TaskPriority.LOW,
        queue="maintenance"
    )
    if db_task_id:
        task_ids.append(db_task_id)
    
    # Schedule log rotation
    log_task_id = scheduler.schedule_immediate_task(
        task_path="src.tasks.cleanup_tasks.maintenance_log_rotation",
        kwargs={"archive": True},
        eta=start_time + timedelta(minutes=15),
        priority=TaskPriority.LOW,
        queue="maintenance"
    )
    if log_task_id:
        task_ids.append(log_task_id)
    
    return task_ids
