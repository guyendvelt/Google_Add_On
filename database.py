"""SQLAlchemy engine, session factory, and declarative Base.

The connection URL is built from individual POSTGRES_* environment variables
so credentials live in exactly one place. SQLAlchemy's URL.create() handles
percent-encoding of special characters in the password automatically.
"""
from __future__ import annotations

import os

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.engine import URL
from sqlalchemy.orm import DeclarativeBase, sessionmaker

load_dotenv()


def _required(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(
            f"{name} is not set. Copy .env.example to .env and fill it in."
        )
    return value


DATABASE_URL = URL.create(
    drivername="postgresql+psycopg",
    username=_required("POSTGRES_USER"),
    password=_required("POSTGRES_PASSWORD"),
    host=_required("POSTGRES_HOST"),
    port=int(_required("POSTGRES_PORT")),
    database=_required("POSTGRES_DB"),
)

engine = create_engine(DATABASE_URL, pool_pre_ping=True, future=True)

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


def get_db():
    """FastAPI dependency that yields a DB session and always closes it."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
