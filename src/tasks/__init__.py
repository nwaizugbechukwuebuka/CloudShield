"""
Celery configuration and task definitions
"""
from celery import Celery
from datetime import datetime, timedelta
import os

# Import application modules
from src.api.utils.config import settings
from src.api.utils.logger import get_logger

logger = get_logger(__name__)

# Create Celery app
celery_app = Celery(
    "cloudshield",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=[
        "src.tasks.scan_tasks",
        "src.tasks.alert_tasks", 
        "src.tasks.cleanup_tasks"
    ]
)

# Celery configuration
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=30 * 60,  # 30 minutes
    task_soft_time_limit=25 * 60,  # 25 minutes
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=1000,
    
    # Task routing
    task_routes={
        "src.tasks.scan_tasks.*": {"queue": "scanning"},
        "src.tasks.alert_tasks.*": {"queue": "alerts"},
        "src.tasks.cleanup_tasks.*": {"queue": "maintenance"},
    },
    
    # Beat schedule for periodic tasks
    beat_schedule={
        # Run scheduled scans every hour
        "run-scheduled-scans": {
            "task": "src.tasks.scan_tasks.run_scheduled_scans",
            "schedule": 3600.0,  # Every hour
        },
        
        # Send alert digest every 4 hours
        "send-alert-digest": {
            "task": "src.tasks.alert_tasks.send_alert_digest",
            "schedule": 4 * 3600.0,  # Every 4 hours
        },
        
        # Clean up old data daily
        "cleanup-old-data": {
            "task": "src.tasks.cleanup_tasks.cleanup_old_data",
            "schedule": 24 * 3600.0,  # Daily
        },
        
        # Refresh integration tokens every 6 hours
        "refresh-tokens": {
            "task": "src.tasks.scan_tasks.refresh_integration_tokens",
            "schedule": 6 * 3600.0,  # Every 6 hours
        },
    }
)


# Task decorator with default settings
def task(*args, **kwargs):
    """Enhanced task decorator with default settings"""
    kwargs.setdefault("bind", True)
    kwargs.setdefault("autoretry_for", (Exception,))
    kwargs.setdefault("retry_kwargs", {"max_retries": 3, "countdown": 60})
    
    return celery_app.task(*args, **kwargs)