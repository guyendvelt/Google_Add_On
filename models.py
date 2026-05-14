"""SQLAlchemy ORM models.

PII protection: ScansHistory intentionally stores only the sender's domain
and aggregate metadata — never the email subject or body.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum

from sqlalchemy import (
    DateTime,
    Enum as SAEnum,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from database import Base


class IndicatorType(str, Enum):
    URL = "URL"
    DOMAIN = "DOMAIN"
    FILE_HASH = "FILE_HASH"


class ScansHistory(Base):
    __tablename__ = "scans_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    sender_domain: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    final_score: Mapped[int] = mapped_column(Integer, nullable=False)
    trigger_reason: Mapped[str] = mapped_column(Text, nullable=False)


class IndicatorsCache(Base):
    __tablename__ = "indicators_cache"
    __table_args__ = (
        UniqueConstraint("indicator_value", "type", name="uq_indicator_value_type"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    indicator_value: Mapped[str] = mapped_column(String(2048), index=True, nullable=False)
    type: Mapped[IndicatorType] = mapped_column(
        SAEnum(IndicatorType, name="indicator_type"), nullable=False
    )
    # Number of VirusTotal vendors that flagged this indicator. 0 = clean,
    # 1..N = vendor count.
    # a threshold applied at scoring time (VT_CONFIRMED_THRESHOLD).
    malicious_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_checked: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
