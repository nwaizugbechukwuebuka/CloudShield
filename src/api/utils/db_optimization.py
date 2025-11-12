"""
Database Query Optimization Utilities
Performance monitoring, query analysis, and optimization helpers
"""

import time
import functools
from typing import Callable, Optional, List, Dict, Any
from contextlib import contextmanager
from sqlalchemy import event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session
import logging

logger = logging.getLogger(__name__)


class QueryPerformanceMonitor:
    """Monitor and log slow database queries"""

    def __init__(self, slow_query_threshold: float = 1.0):
        """
        Initialize query performance monitor

        Args:
            slow_query_threshold: Time in seconds to consider a query slow
        """
        self.slow_query_threshold = slow_query_threshold
        self.query_stats: Dict[str, Dict[str, Any]] = {}

    def record_query(self, query: str, duration: float, params: Optional[tuple] = None):
        """Record query execution"""
        query_key = query.strip()[:100]  # Truncate for grouping

        if query_key not in self.query_stats:
            self.query_stats[query_key] = {
                "count": 0,
                "total_time": 0.0,
                "min_time": float('inf'),
                "max_time": 0.0,
                "slow_count": 0
            }

        stats = self.query_stats[query_key]
        stats["count"] += 1
        stats["total_time"] += duration
        stats["min_time"] = min(stats["min_time"], duration)
        stats["max_time"] = max(stats["max_time"], duration)

        if duration >= self.slow_query_threshold:
            stats["slow_count"] += 1
            logger.warning(
                f"Slow query detected ({duration:.3f}s): {query[:200]}",
                extra={
                    "duration": duration,
                    "query": query,
                    "params": params,
                    "threshold": self.slow_query_threshold
                }
            )

    def get_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get query statistics"""
        return {
            query: {
                **stats,
                "avg_time": stats["total_time"] / stats["count"] if stats["count"] > 0 else 0
            }
            for query, stats in self.query_stats.items()
        }

    def get_slow_queries(self) -> List[Dict[str, Any]]:
        """Get queries that have been slow at least once"""
        return [
            {
                "query": query,
                **stats,
                "avg_time": stats["total_time"] / stats["count"]
            }
            for query, stats in self.query_stats.items()
            if stats["slow_count"] > 0
        ]

    def reset_stats(self):
        """Reset all query statistics"""
        self.query_stats.clear()


# Global query monitor instance
query_monitor = QueryPerformanceMonitor(slow_query_threshold=1.0)


def setup_query_monitoring(engine: Engine):
    """
    Setup SQLAlchemy event listeners for query monitoring

    Args:
        engine: SQLAlchemy engine instance
    """

    @event.listens_for(engine, "before_cursor_execute")
    def before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
        conn.info.setdefault("query_start_time", []).append(time.time())

    @event.listens_for(engine, "after_cursor_execute")
    def after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
        total_time = time.time() - conn.info["query_start_time"].pop(-1)
        query_monitor.record_query(statement, total_time, parameters)

    logger.info("Database query monitoring enabled")


@contextmanager
def query_timer(operation_name: str):
    """
    Context manager to time database operations

    Example:
        with query_timer("fetch_all_findings"):
            findings = db.query(Finding).all()
    """
    start_time = time.time()
    try:
        yield
    finally:
        duration = time.time() - start_time
        logger.info(f"{operation_name} completed in {duration:.3f}s")


def optimize_query(func: Callable) -> Callable:
    """
    Decorator to log query execution time

    Example:
        @optimize_query
        async def get_findings(db: Session):
            return db.query(Finding).all()
    """
    @functools.wraps(func)
    async def async_wrapper(*args, **kwargs):
        start_time = time.time()
        try:
            result = await func(*args, **kwargs)
            duration = time.time() - start_time
            logger.debug(f"{func.__name__} query completed in {duration:.3f}s")
            return result
        except Exception as e:
            duration = time.time() - start_time
            logger.error(f"{func.__name__} query failed after {duration:.3f}s: {e}")
            raise

    @functools.wraps(func)
    def sync_wrapper(*args, **kwargs):
        start_time = time.time()
        try:
            result = func(*args, **kwargs)
            duration = time.time() - start_time
            logger.debug(f"{func.__name__} query completed in {duration:.3f}s")
            return result
        except Exception as e:
            duration = time.time() - start_time
            logger.error(f"{func.__name__} query failed after {duration:.3f}s: {e}")
            raise

    if asyncio.iscoroutinefunction(func):
        return async_wrapper
    else:
        return sync_wrapper


class QueryOptimizer:
    """Database query optimization helpers"""

    @staticmethod
    def analyze_query(db: Session, query_str: str) -> Dict[str, Any]:
        """
        Analyze query execution plan (PostgreSQL EXPLAIN)

        Args:
            db: Database session
            query_str: SQL query string

        Returns:
            Dict containing query plan and recommendations
        """
        try:
            # Execute EXPLAIN for the query
            explain_query = f"EXPLAIN (FORMAT JSON, ANALYZE, BUFFERS) {query_str}"
            result = db.execute(text(explain_query))
            plan = result.fetchone()[0]

            # Extract key metrics
            execution_time = None
            planning_time = None

            if isinstance(plan, list) and len(plan) > 0:
                plan_data = plan[0]
                execution_time = plan_data.get("Execution Time")
                planning_time = plan_data.get("Planning Time")

            return {
                "query": query_str,
                "execution_time_ms": execution_time,
                "planning_time_ms": planning_time,
                "plan": plan,
                "recommendations": QueryOptimizer._generate_recommendations(plan)
            }

        except Exception as e:
            logger.error(f"Failed to analyze query: {e}")
            return {
                "query": query_str,
                "error": str(e)
            }

    @staticmethod
    def _generate_recommendations(plan: Any) -> List[str]:
        """Generate optimization recommendations based on query plan"""
        recommendations = []

        plan_str = str(plan).lower()

        # Check for sequential scans on large tables
        if "seq scan" in plan_str:
            recommendations.append(
                "Sequential scan detected - consider adding an index on frequently queried columns"
            )

        # Check for nested loops
        if "nested loop" in plan_str:
            recommendations.append(
                "Nested loop join detected - ensure appropriate indexes exist on join columns"
            )

        # Check for sorts
        if "sort" in plan_str:
            recommendations.append(
                "Sort operation detected - consider adding an index to avoid sorting"
            )

        # Check for high buffer usage
        if "buffers" in plan_str and "shared hit" in plan_str:
            recommendations.append(
                "High buffer usage - consider increasing shared_buffers if queries are slow"
            )

        return recommendations if recommendations else ["Query appears optimized"]

    @staticmethod
    def suggest_indexes(db: Session, table_name: str) -> List[str]:
        """
        Suggest missing indexes based on query patterns (PostgreSQL)

        Args:
            db: Database session
            table_name: Table to analyze

        Returns:
            List of suggested CREATE INDEX statements
        """
        try:
            # Query pg_stat_user_tables for table statistics
            query = text(f"""
                SELECT
                    schemaname,
                    tablename,
                    seq_scan,
                    seq_tup_read,
                    idx_scan,
                    idx_tup_fetch
                FROM pg_stat_user_tables
                WHERE tablename = :table_name
            """)

            result = db.execute(query, {"table_name": table_name}).fetchone()

            suggestions = []

            if result:
                seq_scan, seq_tup_read, idx_scan, idx_tup_fetch = (
                    result[2], result[3], result[4], result[5] or 0
                )

                # If sequential scans are much higher than index scans
                if seq_scan > idx_scan * 10:
                    suggestions.append(
                        f"-- Table '{table_name}' has {seq_scan} sequential scans vs {idx_scan} index scans"
                    )
                    suggestions.append(
                        f"-- Consider adding indexes on frequently queried columns"
                    )

            return suggestions

        except Exception as e:
            logger.error(f"Failed to suggest indexes: {e}")
            return []


# Common query optimization patterns

class QueryPatterns:
    """Common optimized query patterns"""

    @staticmethod
    def paginate_efficiently(query, page: int = 1, page_size: int = 20):
        """
        Efficient pagination using LIMIT/OFFSET

        Args:
            query: SQLAlchemy query object
            page: Page number (1-indexed)
            page_size: Number of items per page

        Returns:
            Paginated query results and total count
        """
        # Get total count (cached or use COUNT(*))
        total = query.count()

        # Apply pagination
        offset = (page - 1) * page_size
        items = query.limit(page_size).offset(offset).all()

        return {
            "items": items,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": (total + page_size - 1) // page_size
        }

    @staticmethod
    def bulk_insert_optimized(db: Session, model_class, records: List[Dict[str, Any]]):
        """
        Optimized bulk insert using bulk_insert_mappings

        Args:
            db: Database session
            model_class: SQLAlchemy model class
            records: List of dictionaries containing record data

        Returns:
            Number of records inserted
        """
        try:
            db.bulk_insert_mappings(model_class, records)
            db.commit()
            logger.info(f"Bulk inserted {len(records)} records into {model_class.__tablename__}")
            return len(records)
        except Exception as e:
            db.rollback()
            logger.error(f"Bulk insert failed: {e}")
            raise

    @staticmethod
    def bulk_update_optimized(db: Session, model_class, records: List[Dict[str, Any]]):
        """
        Optimized bulk update using bulk_update_mappings

        Args:
            db: Database session
            model_class: SQLAlchemy model class
            records: List of dictionaries containing record data (must include 'id')

        Returns:
            Number of records updated
        """
        try:
            db.bulk_update_mappings(model_class, records)
            db.commit()
            logger.info(f"Bulk updated {len(records)} records in {model_class.__tablename__}")
            return len(records)
        except Exception as e:
            db.rollback()
            logger.error(f"Bulk update failed: {e}")
            raise


# Database connection pool optimization

def configure_connection_pool(engine: Engine, **kwargs):
    """
    Configure database connection pool for optimal performance

    Recommended settings for production:
        pool_size=20,              # Number of persistent connections
        max_overflow=10,           # Max additional connections
        pool_recycle=3600,         # Recycle connections after 1 hour
        pool_pre_ping=True,        # Test connections before use
        pool_timeout=30,           # Wait time for connection from pool
        echo_pool=False            # Log pool operations (debug only)
    """
    pool_size = kwargs.get("pool_size", 20)
    max_overflow = kwargs.get("max_overflow", 10)

    logger.info(
        f"Database pool configured: size={pool_size}, max_overflow={max_overflow}"
    )

    # Pool is configured during engine creation, this is informational
    return {
        "pool_size": pool_size,
        "max_overflow": max_overflow,
        "total_connections": pool_size + max_overflow
    }


import asyncio  # Import for iscoroutinefunction check
