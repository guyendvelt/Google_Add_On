"""Aggregation queries for the admin dashboard (Stage 2).

Surfaces high-level metrics from `scans_history` without exposing PII —
`sender_domain` is already domain-only by construction, and we never
return `trigger_reason` text to callers (it's used only inside the
classification SQL).

Exposed via `GET /api/stats`.
"""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import case, func, or_, select
from sqlalchemy.orm import Session

from database import get_db
from models import ScansHistory

router = APIRouter(prefix="/api", tags=["stats"])

# Verdict bands MUST mirror main._verdict_for_score so the dashboard and
# the analysis endpoint agree on what "Suspicious" means. If you change
# these, change both places (and the new TestVTThreshold suite).
_VERDICT_BANDS: list[tuple[str, int, int]] = [
    ("Safe", 0, 20),
    ("Low Risk", 21, 40),
    ("Suspicious", 41, 60),
    ("High Risk", 61, 80),
    ("Malicious", 81, 100),
]

DAILY_VOLUME_WINDOW_DAYS = 7
TOP_OFFENDERS_LIMIT = 5
# "Threat senders" = sender domains whose mail lands in ANY threat band
# (Suspicious / High Risk / Malicious). 41 is the inclusive Suspicious floor.
SUSPICIOUS_SCORE_FLOOR = 41
RECENT_THREATS_LIMIT = 10
THREAT_SCORE_FLOOR = 61  # High Risk or Malicious — what the dashboard's recent table shows

# Substrings classifying a scan's detection source from its trigger_reason.
# A single scan can be counted in BOTH buckets if both signal types fired —
# the two counts are not mutually exclusive (a scan with phishing keywords
# AND a VT hit contributed to detection from both sources).
_LOCAL_HEURISTIC_PHRASES: tuple[str, ...] = (
    "Deceptive language",
    "Suspicious link",
    "Sender identity",
    "Dangerous file type",
)
_VT_PHRASES: tuple[str, ...] = (
    "threat intelligence",
)


class DailyVolumePoint(BaseModel):
    model_config = ConfigDict(extra="forbid")
    date: str  # ISO YYYY-MM-DD, UTC
    count: int


class RiskDistributionPoint(BaseModel):
    model_config = ConfigDict(extra="forbid")
    verdict: str
    count: int
    percentage: float = Field(ge=0.0, le=100.0)


class TopOffender(BaseModel):
    model_config = ConfigDict(extra="forbid")
    domain: str
    threat_count: int


class DetectionSourceCounts(BaseModel):
    model_config = ConfigDict(extra="forbid")
    local_heuristics: int
    threat_intelligence: int


class RecentThreat(BaseModel):
    model_config = ConfigDict(extra="forbid")
    domain: str
    score: int
    verdict: str
    timestamp: str  # ISO 8601 UTC


class StatsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    total_scans: int
    daily_volume: list[DailyVolumePoint]
    risk_distribution: list[RiskDistributionPoint]
    top_threat_senders: list[TopOffender]
    detection_sources: DetectionSourceCounts
    recent_threats: list[RecentThreat]


# --------------------------------------------------------------------------
# Aggregations
# --------------------------------------------------------------------------

def _compute_daily_volume(db: Session, now_utc: datetime) -> list[DailyVolumePoint]:
    """Scans per UTC day for the trailing 7-day window (oldest first).

    Empty days are filled with 0 so the chart shows a continuous series.
    `func.date(...)` works on both SQLite (tests) and Postgres (prod).
    """
    cutoff = now_utc - timedelta(days=DAILY_VOLUME_WINDOW_DAYS - 1)
    cutoff_date = cutoff.date()

    date_col = func.date(ScansHistory.timestamp)
    rows = db.execute(
        select(date_col.label("d"), func.count().label("c"))
        .where(ScansHistory.timestamp >= cutoff)
        .group_by(date_col)
    ).all()

    counts: dict[date, int] = {}
    for d_val, c in rows:
        # SQLite returns str, Postgres returns date — normalize.
        if isinstance(d_val, str):
            d_val = date.fromisoformat(d_val)
        counts[d_val] = int(c)

    out: list[DailyVolumePoint] = []
    for i in range(DAILY_VOLUME_WINDOW_DAYS):
        day = cutoff_date + timedelta(days=i)
        out.append(DailyVolumePoint(date=day.isoformat(), count=counts.get(day, 0)))
    return out


def _compute_risk_distribution(db: Session, total: int) -> list[RiskDistributionPoint]:
    """Count and percentage of scans in each verdict band.

    Single SQL pass using a CASE expression (one round-trip beats five
    separate counts) — stays self-consistent if a row is committed mid-call.
    """
    band_case = case(
        *((ScansHistory.final_score.between(lo, hi), name) for name, lo, hi in _VERDICT_BANDS),
        else_="Malicious",
    )
    rows = db.execute(
        select(band_case.label("band"), func.count().label("c"))
        .group_by(band_case)
    ).all()
    counts = {band: int(c) for band, c in rows}

    out: list[RiskDistributionPoint] = []
    for name, _, _ in _VERDICT_BANDS:
        c = counts.get(name, 0)
        pct = (100.0 * c / total) if total else 0.0
        out.append(RiskDistributionPoint(
            verdict=name, count=c, percentage=round(pct, 2)
        ))
    return out


def _compute_top_offenders(db: Session) -> list[TopOffender]:
    """Top sender domains across all threat bands (final_score >= 41 —
    Suspicious, High Risk, or Malicious).

    Tie-breaker by domain name (ascending) so output is deterministic for
    tests; without it, Postgres and SQLite can disagree on ordering.
    """
    rows = db.execute(
        select(
            ScansHistory.sender_domain.label("d"),
            func.count().label("c"),
        )
        .where(ScansHistory.final_score >= SUSPICIOUS_SCORE_FLOOR)
        .group_by(ScansHistory.sender_domain)
        .order_by(func.count().desc(), ScansHistory.sender_domain)
        .limit(TOP_OFFENDERS_LIMIT)
    ).all()
    return [TopOffender(domain=d, threat_count=int(c)) for d, c in rows]


def _phrase_match(phrases: tuple[str, ...]):
    """SQL: trigger_reason LIKE '%p1%' OR '%p2%' OR ... — case-sensitive,
    which is fine because the abstracted reasoning constants in main.py
    have fixed casing."""
    return or_(*(ScansHistory.trigger_reason.like(f"%{p}%") for p in phrases))


def _verdict_for_score(score: int) -> str:
    for name, lo, hi in _VERDICT_BANDS:
        if lo <= score <= hi:
            return name
    return "Malicious"


def _compute_recent_threats(db: Session) -> list[RecentThreat]:
    """Last 10 High Risk or Malicious scans, newest first.

    Surfaces only domain + score + verdict + timestamp — never the
    trigger_reason (which could betray which signals fired on which
    senders) or anything resembling email content.
    """
    rows = db.execute(
        select(
            ScansHistory.sender_domain,
            ScansHistory.final_score,
            ScansHistory.timestamp,
        )
        .where(ScansHistory.final_score >= THREAT_SCORE_FLOOR)
        .order_by(ScansHistory.timestamp.desc())
        .limit(RECENT_THREATS_LIMIT)
    ).all()
    return [
        RecentThreat(
            domain=domain,
            score=int(score),
            verdict=_verdict_for_score(int(score)),
            timestamp=ts.astimezone(timezone.utc).isoformat() if ts.tzinfo else ts.replace(tzinfo=timezone.utc).isoformat(),
        )
        for domain, score, ts in rows
    ]


def _compute_detection_sources(db: Session) -> DetectionSourceCounts:
    local = db.scalar(
        select(func.count()).select_from(ScansHistory)
        .where(_phrase_match(_LOCAL_HEURISTIC_PHRASES))
    ) or 0
    vt = db.scalar(
        select(func.count()).select_from(ScansHistory)
        .where(_phrase_match(_VT_PHRASES))
    ) or 0
    return DetectionSourceCounts(
        local_heuristics=int(local),
        threat_intelligence=int(vt),
    )


@router.get("/stats", response_model=StatsResponse)
def get_stats(db: Annotated[Session, Depends(get_db)]) -> StatsResponse:
    """Aggregate metrics for the admin dashboard."""
    now_utc = datetime.now(timezone.utc)
    total = db.scalar(select(func.count()).select_from(ScansHistory)) or 0
    return StatsResponse(
        total_scans=int(total),
        daily_volume=_compute_daily_volume(db, now_utc),
        risk_distribution=_compute_risk_distribution(db, int(total)),
        top_threat_senders=_compute_top_offenders(db),
        detection_sources=_compute_detection_sources(db),
        recent_threats=_compute_recent_threats(db),
    )
