"""
Database configuration and session management
"""
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from .models.base import Base
from .models.user import User
from .models.integration import Integration  
from .models.findings import Finding

# Database URL configuration
DATABASE_URL = os.getenv(
    "DATABASE_URL", 
    "sqlite:///./cloudshield.db"  # Default to SQLite for development
)

# Create engine
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    """Dependency to get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_tables():
    """Create all tables"""
    Base.metadata.create_all(bind=engine)


def drop_tables():
    """Drop all tables (for testing/reset)"""
    Base.metadata.drop_all(bind=engine)


# Import models to register them
__all__ = ["User", "Integration", "Finding", "get_db", "create_tables", "drop_tables", "engine"]
