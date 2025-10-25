"""
Database configuration and session management
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool
from contextlib import contextmanager
from typing import Generator
import os

from app.models import Base

# Database URL - defaults to SQLite for development
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./security_behavior.db")

# Create engine
# For SQLite, use StaticPool to allow same thread access in FastAPI
if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool
    )
else:
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db():
    """Initialize database - create all tables"""
    Base.metadata.create_all(bind=engine)
    print("✅ Database initialized successfully")


def drop_db():
    """Drop all tables - USE WITH CAUTION"""
    Base.metadata.drop_all(bind=engine)
    print("⚠️  All tables dropped")


@contextmanager
def get_db() -> Generator[Session, None, None]:
    """
    Get database session context manager.
    
    Usage:
        with get_db() as db:
            # use db session
            pass
    """
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def get_db_session() -> Session:
    """
    Get database session for FastAPI dependency injection.
    
    Usage:
        @app.get("/endpoint")
        def endpoint(db: Session = Depends(get_db_session)):
            # use db session
            pass
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
