"""VirusTotal v3 client with DB-backed caching.

Two public entry points:

* ``check_url_indicator(db, url)`` — synchronous single-URL lookup. Kept for
  back-compat (tests / scripts).
* ``check_urls_indicators_async(db, urls)`` — concurrent batch lookup used by
  the analysis endpoint. All cache hits short-circuit before any HTTP I/O;
  remaining URLs are queried in parallel via ``httpx.AsyncClient`` inside an
  ``asyncio.gather``, each capped at ``HTTP_TIMEOUT_SECONDS``.

Errors (missing key, 401, 429, timeout, network) are surfaced inside the
result object instead of raised, so the analysis flow can degrade gracefully.
"""
from __future__ import annotations

import asyncio
import base64
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable

import httpx
from dotenv import load_dotenv
from sqlalchemy import select
from sqlalchemy.orm import Session

from models import IndicatorsCache, IndicatorType

load_dotenv()

logger = logging.getLogger("scorer.virustotal")

VT_URLS_BASE = "https://www.virustotal.com/api/v3/urls"
VT_FILES_BASE = "https://www.virustotal.com/api/v3/files"
# Per-call cap so one slow indicator can't blow the whole request budget.
HTTP_TIMEOUT_SECONDS = 5.0
CACHE_TTL = timedelta(hours=24)

# Threshold: how many VT vendors must flag an indicator for it to be treated
# as "confirmed malicious" (absolute score override). Below this, the
# indicator is "isolated" — a suspicious signal that adds points but does
# NOT override the score.
VT_CONFIRMED_THRESHOLD = 3

VT_BASE_URL = VT_URLS_BASE


@dataclass(frozen=True)
class IndicatorResult:
    """One indicator's VT verdict.

    `malicious_count` is the raw number of VT vendors that flagged this
    indicator. Callers decide what the count *means* — the scoring layer
    in main.py applies VT_CONFIRMED_THRESHOLD to distinguish:

      * **clean**     — count == 0
      * **isolated**  — 1 <= count < VT_CONFIRMED_THRESHOLD (1-2 vendors:
                        suspicious signal, additive, never a score override)
      * **confirmed** — count >= VT_CONFIRMED_THRESHOLD (3+ vendors:
                        absolute override → score 100)
    """
    indicator: str
    malicious_count: int
    from_cache: bool
    error: str | None = None

    @property
    def is_confirmed(self) -> bool:
        return self.malicious_count >= VT_CONFIRMED_THRESHOLD

    @property
    def is_isolated(self) -> bool:
        return 0 < self.malicious_count < VT_CONFIRMED_THRESHOLD

    @property
    def is_malicious(self) -> bool:
        return self.is_confirmed


# --------------------------------------------------------------------------
# Auth + URL encoding
# --------------------------------------------------------------------------

def _api_key() -> str | None:
    key = os.getenv("VIRUSTOTAL_API_KEY")
    if not key or key == "your_virustotal_api_key_here":
        return None
    return key


def _encode_url(url: str) -> str:
    # VT expects the URL identifier as URL-safe base64 with no padding.
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


def _encode_file_hash(sha256_hex: str) -> str:
    # VT files endpoint takes the hex digest directly as the path segment.
    return sha256_hex.lower()


@dataclass(frozen=True)
class _IndicatorKind:
    """Per-indicator-type config: which table column, which VT endpoint,
    and how to format the value for the endpoint path."""
    type: IndicatorType
    base_url: str
    encode: Callable[[str], str]


_URL_KIND = _IndicatorKind(IndicatorType.URL, VT_URLS_BASE, _encode_url)
_FILE_KIND = _IndicatorKind(IndicatorType.FILE_HASH, VT_FILES_BASE, _encode_file_hash)


# --------------------------------------------------------------------------
# Response classification — one source of truth shared by sync & async paths
# --------------------------------------------------------------------------

def _classify(status_code: int, body_loader: Callable[[], dict]) -> tuple[int | None, str | None]:
    """Map a VT HTTP response to (malicious_vendor_count, error).

    Returns:
      (count, None) on success — count is the integer from
          `data.attributes.last_analysis_stats.malicious`, or 0 for 404.
      (None, error_message) on auth/rate/network/parse failure.

    Note: this used to return a bool ("is_malicious > 0"). The caller now
    applies a vendor-count threshold (VT_CONFIRMED_THRESHOLD) so a single
    obscure-engine hit does not over-trigger.
    """
    if status_code == 404:
        return 0, None
    if status_code == 401:
        return None, "VT auth failed (check API key)"
    if status_code == 429:
        return None, "VT rate limit / quota exceeded"
    if status_code != 200:
        return None, f"VT HTTP {status_code}"
    try:
        stats = body_loader()["data"]["attributes"]["last_analysis_stats"]
    except (KeyError, ValueError, TypeError):
        return None, "VT response malformed"
    return int(stats.get("malicious", 0)), None


# --------------------------------------------------------------------------
# Live HTTP — sync and async variants
# --------------------------------------------------------------------------

def _query_virustotal(
    value: str, kind: _IndicatorKind = _URL_KIND
) -> tuple[int | None, str | None]:
    """Sync live VT call — used by the synchronous public function."""
    key = _api_key()
    if not key:
        return None, "VT API key not configured"

    endpoint = f"{kind.base_url}/{kind.encode(value)}"
    headers = {"x-apikey": key, "accept": "application/json"}

    try:
        with httpx.Client(timeout=HTTP_TIMEOUT_SECONDS) as client:
            resp = client.get(endpoint, headers=headers)
    except httpx.TimeoutException:
        return None, "VT timeout"
    except httpx.HTTPError as exc:
        return None, f"VT network error: {exc.__class__.__name__}"

    return _classify(resp.status_code, resp.json)


async def _query_virustotal_async(
    client: httpx.AsyncClient,
    value: str,
    api_key: str,
    kind: _IndicatorKind = _URL_KIND,
) -> tuple[int | None, str | None]:
    """Async live VT call — shares the response classifier with the sync path."""
    endpoint = f"{kind.base_url}/{kind.encode(value)}"
    headers = {"x-apikey": api_key, "accept": "application/json"}

    try:
        resp = await client.get(endpoint, headers=headers)
    except httpx.TimeoutException:
        return None, "VT timeout"
    except httpx.HTTPError as exc:
        return None, f"VT network error: {exc.__class__.__name__}"

    return _classify(resp.status_code, resp.json)


# --------------------------------------------------------------------------
# Cache helpers (sync; SQLAlchemy ORM)
# --------------------------------------------------------------------------

def _get_cached(
    db: Session, value: str, indicator_type: IndicatorType = IndicatorType.URL
) -> IndicatorsCache | None:
    return db.scalar(
        select(IndicatorsCache).where(
            IndicatorsCache.indicator_value == value,
            IndicatorsCache.type == indicator_type,
        )
    )


def _is_fresh(cached: IndicatorsCache, now_utc: datetime) -> bool:
    last_checked = cached.last_checked
    if last_checked.tzinfo is None:
        last_checked = last_checked.replace(tzinfo=timezone.utc)
    return now_utc - last_checked < CACHE_TTL


def _upsert(
    db: Session,
    cached: IndicatorsCache | None,
    value: str,
    malicious_count: int,
    now_utc: datetime,
    indicator_type: IndicatorType = IndicatorType.URL,
) -> None:
    if cached is not None:
        cached.malicious_count = malicious_count
        cached.last_checked = now_utc
    else:
        db.add(
            IndicatorsCache(
                indicator_value=value,
                type=indicator_type,
                malicious_count=malicious_count,
                last_checked=now_utc,
            )
        )


# --------------------------------------------------------------------------
# Public sync API — kept for back-compat / direct tests
# --------------------------------------------------------------------------

def check_url_indicator(db: Session, url: str) -> IndicatorResult:
    """Cache-first lookup for a single URL's vendor verdict (sync).

    Returns an IndicatorResult whose `malicious_count` is the number of VT
    vendors that flagged the URL. Callers apply VT_CONFIRMED_THRESHOLD to
    decide whether to treat it as confirmed-malicious or merely isolated.
    """
    now_utc = datetime.now(timezone.utc)
    cached = _get_cached(db, url)

    if cached is not None and _is_fresh(cached, now_utc):
        return IndicatorResult(url, cached.malicious_count, from_cache=True)

    count, error = _query_virustotal(url)

    if error is not None or count is None:
        logger.warning("VT lookup degraded (%s)", error)
        if cached is not None:
            return IndicatorResult(
                url, cached.malicious_count, from_cache=True, error=error
            )
        return IndicatorResult(url, 0, from_cache=False, error=error)

    _upsert(db, cached, url, count, now_utc)
    db.commit()
    return IndicatorResult(url, count, from_cache=False)


# --------------------------------------------------------------------------
# Public async batch API — used by the analysis endpoint
# --------------------------------------------------------------------------

async def _check_indicators_async(
    db: Session, values: list[str], kind: _IndicatorKind
) -> list[IndicatorResult]:
    """Generic engine for the concurrent cache-first batch lookup.

    Mirrors the original 4-phase flow (cache-first → key-missing degrade →
    concurrent gather → upsert + single commit) but parameterized so it
    works for URL endpoints AND file-hash endpoints from one code path.
    """
    if not values:
        return []

    now_utc = datetime.now(timezone.utc)
    results: list[IndicatorResult | None] = [None] * len(values)
    cached_rows: list[IndicatorsCache | None] = [None] * len(values)
    pending: list[int] = []

    # ---- Phase 1: cache first (sync) ----
    for i, val in enumerate(values):
        cached = _get_cached(db, val, kind.type)
        cached_rows[i] = cached
        if cached is not None and _is_fresh(cached, now_utc):
            results[i] = IndicatorResult(val, cached.malicious_count, from_cache=True)
        else:
            pending.append(i)

    if not pending:
        return [r for r in results if r is not None]  # type: ignore[misc]

    # ---- Phase 2: no key → graceful degrade, never hit the network ----
    api_key = _api_key()
    if api_key is None:
        for i in pending:
            val = values[i]
            cached = cached_rows[i]
            results[i] = IndicatorResult(
                val,
                cached.malicious_count if cached is not None else 0,
                from_cache=cached is not None,
                error="VT API key not configured",
            )
        return [r for r in results if r is not None]  # type: ignore[misc]

    # ---- Phase 3: concurrent live VT calls ----
    timeout = httpx.Timeout(HTTP_TIMEOUT_SECONDS)
    async with httpx.AsyncClient(timeout=timeout) as client:
        live_results = await asyncio.gather(
            *(_query_virustotal_async(client, values[i], api_key, kind) for i in pending)
        )

    # ---- Phase 4: merge, upsert, single commit ----
    cache_dirty = False
    for idx, (count, error) in zip(pending, live_results):
        val = values[idx]
        cached = cached_rows[idx]
        if error is not None or count is None:
            logger.warning("VT lookup degraded (%s) kind=%s value=%s", error, kind.type, val)
            if cached is not None:
                results[idx] = IndicatorResult(
                    val, cached.malicious_count, from_cache=True, error=error
                )
            else:
                results[idx] = IndicatorResult(
                    val, 0, from_cache=False, error=error
                )
        else:
            _upsert(db, cached, val, count, now_utc, kind.type)
            cache_dirty = True
            results[idx] = IndicatorResult(val, count, from_cache=False)

    if cache_dirty:
        db.commit()

    return [r for r in results if r is not None]  # type: ignore[misc]


async def check_urls_indicators_async(
    db: Session, urls: list[str]
) -> list[IndicatorResult]:
    """Concurrent cache-first URL batch lookup. See _check_indicators_async."""
    return await _check_indicators_async(db, urls, _URL_KIND)


async def check_files_indicators_async(
    db: Session, sha256_hexes: list[str]
) -> list[IndicatorResult]:
    """Concurrent cache-first file-hash batch lookup. Mirrors the URL path
    but hits VT's /api/v3/files/{sha256} endpoint and caches under
    IndicatorType.FILE_HASH so URL and file caches never collide."""
    # Defensive: ensure lowercase so cache keys match what we store.
    normalized = [h.lower() for h in sha256_hexes]
    return await _check_indicators_async(db, normalized, _FILE_KIND)
