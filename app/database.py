"""
Database configuration and session management.
SQLAlchemy 2.0 compatible.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

from app.config import settings

# Create database engine
engine = create_engine(
    settings.DATABASE_URL,
    future=True,   # SQLAlchemy 2.0 style
)

# Create session factory
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

# Base class for models
Base = declarative_base()


def get_db():
    """
    Dependency for getting DB session.
    Used in FastAPI routes.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()