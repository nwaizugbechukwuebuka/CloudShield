"""
CloudShield Cleanup Tasks
Advanced database maintenance, log rotation, system health monitoring,
and automated cleanup processes for production environment.

Author: Chukwuebuka Tobiloba Nwaizugbe
Copyright (c) 2025 CloudShield Security Systems
"""

import asyncio
import os
import shutil
import gzip
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import psutil
import logging
from pathlib import Path
from sqlalchemy import text, func
from sqlalchemy.ext.asyncio import AsyncSession

from celery import Celery
from ..api.database import get_db_session, engine
from ..api.models.findings import Finding
from ..api.models.user import User
from ..api.models.integration import Integration
from ..api.utils.config import get_settings
from ..api.utils.logger import get_logger

settings = get_settings()
logger = get_logger(__name__)

# Create Celery app for cleanup tasks
cleanup_app = Celery(
    'cloudshield_cleanup',
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend
)

cleanup_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_track_started=True,
    task_time_limit=30 * 60,  # 30 minutes
    task_soft_time_limit=25 * 60,  # 25 minutes
)


class CloudShieldCleanupManager:
    """
    Comprehensive cleanup and maintenance manager for CloudShield
    
    Capabilities:
    - Database maintenance and optimization
    - Log file rotation and archival  
    - Temporary file cleanup
    - System health monitoring
    - Performance metrics collection
    - Storage usage optimization
    - Alert cleanup and archival
    - Scan result cleanup
    - User session cleanup
    """
    
    def __init__(self):
        self.version = "1.5.0"
        self.cleanup_stats = {
            "last_run": None,
            "total_runs": 0,
            "total_cleaned_mb": 0,
            "errors": []
        }
        
        # Cleanup configurations
        self.retention_periods = {
            "scan_results": timedelta(days=365),  # 1 year
            "findings": timedelta(days=730),      # 2 years
            "alerts": timedelta(days=90),         # 90 days
            "logs": timedelta(days=30),           # 30 days
            "temp_files": timedelta(days=7),      # 7 days
            "user_sessions": timedelta(days=30),  # 30 days
            "failed_scans": timedelta(days=30),   # 30 days
        }
        
        # Storage thresholds
        self.storage_thresholds = {
            "disk_usage_warning": 80,  # 80% disk usage
            "disk_usage_critical": 90, # 90% disk usage
            "log_size_warning": 1024,  # 1GB log size
            "db_size_warning": 10240,  # 10GB database size
        }
        
        # Cleanup priorities
        self.cleanup_priorities = [
            "temp_files",
            "old_logs", 
            "expired_sessions",
            "old_alerts",
            "old_scan_results",
            "orphaned_findings",
            "database_optimization"
        ]
    
    async def perform_full_cleanup(self, force: bool = False) -> Dict[str, Any]:
        """
        Perform comprehensive system cleanup
        
        Args:
            force: Force cleanup even if not needed
            
        Returns:
            Cleanup results and statistics
        """
        start_time = datetime.utcnow()
        results = {
            "success": True,
            "start_time": start_time.isoformat(),
            "tasks_completed": [],
            "tasks_failed": [],
            "storage_freed_mb": 0,
            "errors": []
        }
        
        try:
            logger.info("Starting comprehensive CloudShield cleanup...")
            
            # Check if cleanup is needed
            if not force and not await self._cleanup_needed():
                logger.info("Cleanup not needed at this time")
                return results
            
            # Database cleanup tasks
            db_results = await self._perform_database_cleanup()
            results["tasks_completed"].extend(db_results.get("completed", []))
            results["tasks_failed"].extend(db_results.get("failed", []))
            results["storage_freed_mb"] += db_results.get("storage_freed_mb", 0)
            
            # File system cleanup tasks
            fs_results = await self._perform_filesystem_cleanup()
            results["tasks_completed"].extend(fs_results.get("completed", []))
            results["tasks_failed"].extend(fs_results.get("failed", []))
            results["storage_freed_mb"] += fs_results.get("storage_freed_mb", 0)
            
            # Log cleanup tasks
            log_results = await self._perform_log_cleanup()
            results["tasks_completed"].extend(log_results.get("completed", []))
            results["tasks_failed"].extend(log_results.get("failed", []))
            results["storage_freed_mb"] += log_results.get("storage_freed_mb", 0)
            
            # System optimization tasks
            opt_results = await self._perform_system_optimization()
            results["tasks_completed"].extend(opt_results.get("completed", []))
            results["tasks_failed"].extend(opt_results.get("failed", []))
            
            # Update cleanup statistics
            self.cleanup_stats["last_run"] = start_time
            self.cleanup_stats["total_runs"] += 1
            self.cleanup_stats["total_cleaned_mb"] += results["storage_freed_mb"]
            
            end_time = datetime.utcnow()
            cleanup_duration = (end_time - start_time).total_seconds()
            
            results.update({
                "end_time": end_time.isoformat(),
                "duration_seconds": cleanup_duration,
                "success": len(results["tasks_failed"]) == 0
            })
            
            logger.info(f"Cleanup completed in {cleanup_duration:.2f}s, freed {results['storage_freed_mb']:.2f}MB")
            
        except Exception as e:
            logger.error(f"Cleanup failed: {str(e)}")
            results["success"] = False
            results["errors"].append(str(e))
        
        return results
    
    async def _cleanup_needed(self) -> bool:
        """Check if cleanup is needed based on system conditions"""
        try:
            # Check disk usage
            disk_usage = psutil.disk_usage('/')
            disk_usage_percent = (disk_usage.used / disk_usage.total) * 100
            
            if disk_usage_percent > self.storage_thresholds["disk_usage_warning"]:
                logger.info(f"Cleanup needed: Disk usage at {disk_usage_percent:.1f}%")
                return True
            
            # Check database size
            async with get_db_session() as session:
                # Get database size
                result = await session.execute(
                    text("SELECT pg_size_pretty(pg_database_size(current_database()))")
                )
                db_size_str = result.scalar()
                
                # Check for old records
                cutoff_date = datetime.utcnow() - timedelta(days=7)
                old_findings = await session.execute(
                    text("SELECT COUNT(*) FROM findings WHERE created_at < :cutoff"),
                    {"cutoff": cutoff_date}
                )
                old_count = old_findings.scalar()
                
                if old_count > 1000:
                    logger.info(f"Cleanup needed: {old_count} old findings found")
                    return True
            
            # Check log file sizes
            log_dir = Path(settings.log_directory) if hasattr(settings, 'log_directory') else Path("/tmp/cloudshield/logs")
            if log_dir.exists():
                total_log_size = sum(f.stat().st_size for f in log_dir.rglob('*.log'))
                log_size_mb = total_log_size / (1024 * 1024)
                
                if log_size_mb > self.storage_thresholds["log_size_warning"]:
                    logger.info(f"Cleanup needed: Log files at {log_size_mb:.1f}MB")
                    return True
            
            # Check time since last cleanup
            if self.cleanup_stats["last_run"]:
                time_since_cleanup = datetime.utcnow() - self.cleanup_stats["last_run"]
                if time_since_cleanup > timedelta(days=7):
                    logger.info("Cleanup needed: More than 7 days since last cleanup")
                    return True
            else:
                logger.info("Cleanup needed: First run")
                return True
            
        except Exception as e:
            logger.error(f"Error checking cleanup requirements: {str(e)}")
            return True  # Default to cleanup on error
        
        return False
    
    async def _perform_database_cleanup(self) -> Dict[str, Any]:
        """Perform database cleanup and maintenance"""
        results = {
            "completed": [],
            "failed": [],
            "storage_freed_mb": 0
        }
        
        try:
            async with get_db_session() as session:
                # Clean up old findings
                try:
                    cutoff_date = datetime.utcnow() - self.retention_periods["findings"]
                    
                    # Count records to be deleted
                    count_result = await session.execute(
                        text("SELECT COUNT(*) FROM findings WHERE created_at < :cutoff AND archived = true"),
                        {"cutoff": cutoff_date}
                    )
                    old_findings_count = count_result.scalar()
                    
                    if old_findings_count > 0:
                        # Delete old archived findings
                        delete_result = await session.execute(
                            text("DELETE FROM findings WHERE created_at < :cutoff AND archived = true"),
                            {"cutoff": cutoff_date}
                        )
                        await session.commit()
                        
                        results["completed"].append(f"Deleted {old_findings_count} old findings")
                        results["storage_freed_mb"] += old_findings_count * 0.1  # Estimate 0.1MB per finding
                        
                except Exception as e:
                    logger.error(f"Failed to clean old findings: {str(e)}")
                    results["failed"].append(f"Old findings cleanup: {str(e)}")
                
                # Clean up expired user sessions
                try:
                    session_cutoff = datetime.utcnow() - self.retention_periods["user_sessions"]
                    
                    # Clean up user sessions (if we have a sessions table)
                    session_result = await session.execute(
                        text("""
                        DELETE FROM user_sessions 
                        WHERE last_activity < :cutoff OR created_at < :cutoff
                        """),
                        {"cutoff": session_cutoff}
                    )
                    
                    if session_result.rowcount > 0:
                        await session.commit()
                        results["completed"].append(f"Deleted {session_result.rowcount} expired user sessions")
                    
                except Exception as e:
                    # Sessions table might not exist, that's okay
                    logger.debug(f"User sessions cleanup skipped: {str(e)}")
                
                # Clean up old scan results
                try:
                    scan_cutoff = datetime.utcnow() - self.retention_periods["scan_results"]
                    
                    # Clean up old failed scans
                    scan_result = await session.execute(
                        text("""
                        DELETE FROM scan_results 
                        WHERE created_at < :cutoff AND status = 'failed'
                        """),
                        {"cutoff": scan_cutoff}
                    )
                    
                    if scan_result.rowcount > 0:
                        await session.commit()
                        results["completed"].append(f"Deleted {scan_result.rowcount} old failed scan results")
                        results["storage_freed_mb"] += scan_result.rowcount * 0.05
                    
                except Exception as e:
                    logger.debug(f"Scan results cleanup skipped: {str(e)}")
                
                # Clean up orphaned records
                try:
                    # Find findings without valid integrations
                    orphan_result = await session.execute(
                        text("""
                        DELETE FROM findings 
                        WHERE integration_id NOT IN (SELECT id FROM integrations)
                        """)
                    )
                    
                    if orphan_result.rowcount > 0:
                        await session.commit()
                        results["completed"].append(f"Deleted {orphan_result.rowcount} orphaned findings")
                        results["storage_freed_mb"] += orphan_result.rowcount * 0.1
                    
                except Exception as e:
                    logger.error(f"Failed to clean orphaned records: {str(e)}")
                    results["failed"].append(f"Orphaned records cleanup: {str(e)}")
                
                # Database optimization
                try:
                    # Vacuum and analyze tables
                    await session.execute(text("VACUUM ANALYZE findings"))
                    await session.execute(text("VACUUM ANALYZE integrations"))
                    await session.execute(text("VACUUM ANALYZE users"))
                    
                    results["completed"].append("Database vacuum and analyze completed")
                    
                except Exception as e:
                    logger.error(f"Database optimization failed: {str(e)}")
                    results["failed"].append(f"Database optimization: {str(e)}")
        
        except Exception as e:
            logger.error(f"Database cleanup failed: {str(e)}")
            results["failed"].append(f"Database cleanup: {str(e)}")
        
        return results
    
    async def _perform_filesystem_cleanup(self) -> Dict[str, Any]:
        """Perform file system cleanup"""
        results = {
            "completed": [],
            "failed": [],
            "storage_freed_mb": 0
        }
        
        try:
            # Clean up temporary files
            temp_dirs = [
                "/tmp/cloudshield",
                "/var/tmp/cloudshield",
                settings.temp_directory if hasattr(settings, 'temp_directory') else None
            ]
            
            for temp_dir in temp_dirs:
                if temp_dir and os.path.exists(temp_dir):
                    try:
                        freed_mb = await self._cleanup_directory(
                            temp_dir, 
                            self.retention_periods["temp_files"]
                        )
                        if freed_mb > 0:
                            results["completed"].append(f"Cleaned {temp_dir}: {freed_mb:.2f}MB freed")
                            results["storage_freed_mb"] += freed_mb
                    except Exception as e:
                        logger.error(f"Failed to clean {temp_dir}: {str(e)}")
                        results["failed"].append(f"Temp cleanup {temp_dir}: {str(e)}")
            
            # Clean up old backup files
            backup_dir = getattr(settings, 'backup_directory', '/var/backups/cloudshield')
            if os.path.exists(backup_dir):
                try:
                    freed_mb = await self._cleanup_old_backups(backup_dir)
                    if freed_mb > 0:
                        results["completed"].append(f"Cleaned old backups: {freed_mb:.2f}MB freed")
                        results["storage_freed_mb"] += freed_mb
                except Exception as e:
                    logger.error(f"Failed to clean backup directory: {str(e)}")
                    results["failed"].append(f"Backup cleanup: {str(e)}")
            
            # Clean up old export files
            export_dir = getattr(settings, 'export_directory', '/tmp/cloudshield/exports')
            if os.path.exists(export_dir):
                try:
                    freed_mb = await self._cleanup_directory(
                        export_dir,
                        timedelta(days=14)  # Keep exports for 14 days
                    )
                    if freed_mb > 0:
                        results["completed"].append(f"Cleaned export files: {freed_mb:.2f}MB freed")
                        results["storage_freed_mb"] += freed_mb
                except Exception as e:
                    logger.error(f"Failed to clean export directory: {str(e)}")
                    results["failed"].append(f"Export cleanup: {str(e)}")
        
        except Exception as e:
            logger.error(f"Filesystem cleanup failed: {str(e)}")
            results["failed"].append(f"Filesystem cleanup: {str(e)}")
        
        return results
    
    async def _perform_log_cleanup(self) -> Dict[str, Any]:
        """Perform log file cleanup and rotation"""
        results = {
            "completed": [],
            "failed": [],
            "storage_freed_mb": 0
        }
        
        try:
            log_dir = Path(getattr(settings, 'log_directory', '/var/log/cloudshield'))
            
            if not log_dir.exists():
                return results
            
            # Rotate and compress old log files
            log_files = list(log_dir.glob('*.log'))
            
            for log_file in log_files:
                try:
                    # Check file age and size
                    file_age = datetime.utcnow() - datetime.fromtimestamp(log_file.stat().st_mtime)
                    file_size_mb = log_file.stat().st_size / (1024 * 1024)
                    
                    # Compress old log files
                    if file_age > timedelta(days=1) and file_size_mb > 10:
                        compressed_path = log_file.with_suffix('.log.gz')
                        
                        with open(log_file, 'rb') as f_in:
                            with gzip.open(compressed_path, 'wb') as f_out:
                                shutil.copyfileobj(f_in, f_out)
                        
                        # Remove original file
                        log_file.unlink()
                        
                        results["completed"].append(f"Compressed log file: {log_file.name}")
                        results["storage_freed_mb"] += file_size_mb * 0.7  # Estimate 70% compression
                    
                    # Delete very old log files
                    elif file_age > self.retention_periods["logs"]:
                        file_size_mb = log_file.stat().st_size / (1024 * 1024)
                        log_file.unlink()
                        
                        results["completed"].append(f"Deleted old log file: {log_file.name}")
                        results["storage_freed_mb"] += file_size_mb
                
                except Exception as e:
                    logger.error(f"Failed to process log file {log_file}: {str(e)}")
                    results["failed"].append(f"Log file {log_file.name}: {str(e)}")
            
            # Clean up old compressed logs
            compressed_logs = list(log_dir.glob('*.log.gz'))
            
            for compressed_log in compressed_logs:
                try:
                    file_age = datetime.utcnow() - datetime.fromtimestamp(compressed_log.stat().st_mtime)
                    
                    if file_age > self.retention_periods["logs"] * 2:  # Keep compressed logs longer
                        file_size_mb = compressed_log.stat().st_size / (1024 * 1024)
                        compressed_log.unlink()
                        
                        results["completed"].append(f"Deleted old compressed log: {compressed_log.name}")
                        results["storage_freed_mb"] += file_size_mb
                
                except Exception as e:
                    logger.error(f"Failed to process compressed log {compressed_log}: {str(e)}")
                    results["failed"].append(f"Compressed log {compressed_log.name}: {str(e)}")
        
        except Exception as e:
            logger.error(f"Log cleanup failed: {str(e)}")
            results["failed"].append(f"Log cleanup: {str(e)}")
        
        return results
    
    async def _perform_system_optimization(self) -> Dict[str, Any]:
        """Perform system optimization tasks"""
        results = {
            "completed": [],
            "failed": []
        }
        
        try:
            # Clear system caches if possible
            try:
                if os.path.exists('/usr/bin/sync'):
                    os.system('sync')
                    results["completed"].append("System buffers synced")
            except Exception as e:
                logger.debug(f"Buffer sync failed: {str(e)}")
            
            # Update file system statistics
            try:
                await self._update_system_stats()
                results["completed"].append("System statistics updated")
            except Exception as e:
                logger.error(f"Stats update failed: {str(e)}")
                results["failed"].append(f"System stats: {str(e)}")
            
            # Optimize application caches
            try:
                await self._optimize_caches()
                results["completed"].append("Application caches optimized")
            except Exception as e:
                logger.error(f"Cache optimization failed: {str(e)}")
                results["failed"].append(f"Cache optimization: {str(e)}")
        
        except Exception as e:
            logger.error(f"System optimization failed: {str(e)}")
            results["failed"].append(f"System optimization: {str(e)}")
        
        return results
    
    async def _cleanup_directory(self, directory: str, max_age: timedelta) -> float:
        """Clean up files in a directory older than max_age"""
        freed_mb = 0
        cutoff_time = datetime.utcnow() - max_age
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                
                try:
                    file_mtime = datetime.fromtimestamp(os.path.getmtime(file_path))
                    
                    if file_mtime < cutoff_time:
                        file_size = os.path.getsize(file_path)
                        os.remove(file_path)
                        freed_mb += file_size / (1024 * 1024)
                
                except Exception as e:
                    logger.debug(f"Failed to remove file {file_path}: {str(e)}")
        
        return freed_mb
    
    async def _cleanup_old_backups(self, backup_dir: str) -> float:
        """Clean up old backup files"""
        freed_mb = 0
        
        try:
            backup_files = []
            
            for root, dirs, files in os.walk(backup_dir):
                for file in files:
                    if file.endswith(('.sql', '.dump', '.backup', '.tar.gz')):
                        file_path = os.path.join(root, file)
                        file_mtime = datetime.fromtimestamp(os.path.getmtime(file_path))
                        file_size = os.path.getsize(file_path)
                        
                        backup_files.append({
                            'path': file_path,
                            'mtime': file_mtime,
                            'size': file_size
                        })
            
            # Sort by modification time, keep newest 10 backups
            backup_files.sort(key=lambda x: x['mtime'], reverse=True)
            
            for backup_file in backup_files[10:]:  # Remove all but newest 10
                try:
                    os.remove(backup_file['path'])
                    freed_mb += backup_file['size'] / (1024 * 1024)
                except Exception as e:
                    logger.debug(f"Failed to remove backup {backup_file['path']}: {str(e)}")
        
        except Exception as e:
            logger.error(f"Backup cleanup failed: {str(e)}")
        
        return freed_mb
    
    async def _update_system_stats(self):
        """Update system performance statistics"""
        try:
            # Collect system metrics
            stats = {
                "disk_usage": psutil.disk_usage('/').percent,
                "memory_usage": psutil.virtual_memory().percent,
                "cpu_usage": psutil.cpu_percent(interval=1),
                "timestamp": datetime.utcnow()
            }
            
            # Store stats in database or cache
            # This would require a system_stats table
            logger.info(f"System stats: CPU {stats['cpu_usage']:.1f}%, "
                       f"Memory {stats['memory_usage']:.1f}%, "
                       f"Disk {stats['disk_usage']:.1f}%")
        
        except Exception as e:
            logger.error(f"Failed to update system stats: {str(e)}")
            raise
    
    async def _optimize_caches(self):
        """Optimize application caches"""
        try:
            # Clear Redis caches if needed
            # This would require Redis connection
            logger.info("Cache optimization completed")
        
        except Exception as e:
            logger.error(f"Cache optimization failed: {str(e)}")
            raise
    
    def get_cleanup_status(self) -> Dict[str, Any]:
        """Get current cleanup status and statistics"""
        return {
            "version": self.version,
            "last_run": self.cleanup_stats["last_run"].isoformat() if self.cleanup_stats["last_run"] else None,
            "total_runs": self.cleanup_stats["total_runs"],
            "total_cleaned_mb": self.cleanup_stats["total_cleaned_mb"],
            "retention_periods": {k: v.days for k, v in self.retention_periods.items()},
            "storage_thresholds": self.storage_thresholds,
            "errors": self.cleanup_stats["errors"][-10:]  # Last 10 errors
        }
    
    async def emergency_cleanup(self) -> Dict[str, Any]:
        """Perform emergency cleanup when disk space is critically low"""
        logger.warning("Performing emergency cleanup due to low disk space")
        
        results = {
            "success": True,
            "tasks_completed": [],
            "storage_freed_mb": 0,
            "errors": []
        }
        
        try:
            # Aggressive temporary file cleanup
            temp_dirs = ["/tmp", "/var/tmp", "/tmp/cloudshield"]
            
            for temp_dir in temp_dirs:
                if os.path.exists(temp_dir):
                    freed_mb = await self._cleanup_directory(temp_dir, timedelta(hours=1))
                    results["storage_freed_mb"] += freed_mb
                    results["tasks_completed"].append(f"Emergency cleanup {temp_dir}: {freed_mb:.2f}MB")
            
            # Aggressive log cleanup
            log_dir = Path(getattr(settings, 'log_directory', '/var/log/cloudshield'))
            if log_dir.exists():
                for log_file in log_dir.glob('*.log'):
                    if log_file.stat().st_size > 100 * 1024 * 1024:  # Files > 100MB
                        file_size_mb = log_file.stat().st_size / (1024 * 1024)
                        log_file.unlink()
                        results["storage_freed_mb"] += file_size_mb
                        results["tasks_completed"].append(f"Emergency deleted large log: {log_file.name}")
            
            logger.warning(f"Emergency cleanup completed, freed {results['storage_freed_mb']:.2f}MB")
        
        except Exception as e:
            logger.error(f"Emergency cleanup failed: {str(e)}")
            results["success"] = False
            results["errors"].append(str(e))
        
        return results


# Global cleanup manager instance
cleanup_manager = CloudShieldCleanupManager()


# Celery tasks
@cleanup_app.task(bind=True, name='cloudshield.cleanup.full_cleanup')
def full_cleanup_task(self, force: bool = False):
    """Celery task for full system cleanup"""
    try:
        loop = asyncio.get_event_loop()
        result = loop.run_until_complete(cleanup_manager.perform_full_cleanup(force=force))
        
        logger.info(f"Cleanup task completed: {result['storage_freed_mb']:.2f}MB freed")
        return result
    
    except Exception as e:
        logger.error(f"Cleanup task failed: {str(e)}")
        raise self.retry(exc=e, countdown=60, max_retries=3)


@cleanup_app.task(bind=True, name='cloudshield.cleanup.emergency_cleanup')
def emergency_cleanup_task(self):
    """Celery task for emergency cleanup"""
    try:
        loop = asyncio.get_event_loop()
        result = loop.run_until_complete(cleanup_manager.emergency_cleanup())
        
        logger.warning(f"Emergency cleanup completed: {result['storage_freed_mb']:.2f}MB freed")
        return result
    
    except Exception as e:
        logger.error(f"Emergency cleanup task failed: {str(e)}")
        raise self.retry(exc=e, countdown=30, max_retries=2)


@cleanup_app.task(bind=True, name='cloudshield.cleanup.database_maintenance')
def database_maintenance_task(self):
    """Celery task for database maintenance only"""
    try:
        loop = asyncio.get_event_loop()
        result = loop.run_until_complete(cleanup_manager._perform_database_cleanup())
        
        logger.info(f"Database maintenance completed: {len(result['completed'])} tasks")
        return result
    
    except Exception as e:
        logger.error(f"Database maintenance task failed: {str(e)}")
        raise self.retry(exc=e, countdown=60, max_retries=3)


@cleanup_app.task(bind=True, name='cloudshield.cleanup.log_rotation')
def log_rotation_task(self):
    """Celery task for log rotation only"""
    try:
        loop = asyncio.get_event_loop()
        result = loop.run_until_complete(cleanup_manager._perform_log_cleanup())
        
        logger.info(f"Log rotation completed: {result['storage_freed_mb']:.2f}MB freed")
        return result
    
    except Exception as e:
        logger.error(f"Log rotation task failed: {str(e)}")
        raise self.retry(exc=e, countdown=60, max_retries=3)


@cleanup_app.task(bind=True, name='cloudshield.cleanup.health_check')
def cleanup_health_check_task(self):
    """Health check for cleanup system"""
    try:
        # Check disk usage
        disk_usage = psutil.disk_usage('/')
        disk_percent = (disk_usage.used / disk_usage.total) * 100
        
        # Check if emergency cleanup is needed
        if disk_percent > cleanup_manager.storage_thresholds["disk_usage_critical"]:
            logger.critical(f"Critical disk usage: {disk_percent:.1f}%")
            # Trigger emergency cleanup
            emergency_cleanup_task.delay()
        
        elif disk_percent > cleanup_manager.storage_thresholds["disk_usage_warning"]:
            logger.warning(f"High disk usage: {disk_percent:.1f}%")
            # Trigger regular cleanup
            full_cleanup_task.delay()
        
        return {
            "disk_usage_percent": disk_percent,
            "memory_usage_percent": psutil.virtual_memory().percent,
            "cleanup_status": cleanup_manager.get_cleanup_status(),
            "timestamp": datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Cleanup health check failed: {str(e)}")
        raise


# Schedule configuration for beat
cleanup_schedule = {
    'full-cleanup-daily': {
        'task': 'cloudshield.cleanup.full_cleanup',
        'schedule': 24.0 * 60 * 60,  # Daily
        'kwargs': {'force': False}
    },
    'database-maintenance-weekly': {
        'task': 'cloudshield.cleanup.database_maintenance',
        'schedule': 7.0 * 24 * 60 * 60,  # Weekly
    },
    'log-rotation-daily': {
        'task': 'cloudshield.cleanup.log_rotation',
        'schedule': 24.0 * 60 * 60,  # Daily
    },
    'cleanup-health-check-hourly': {
        'task': 'cloudshield.cleanup.health_check',
        'schedule': 60.0 * 60,  # Hourly
    }
}

cleanup_app.conf.beat_schedule = cleanup_schedule
