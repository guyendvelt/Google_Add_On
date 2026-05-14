"""FastAPI app entrypoint for the Malicious Email Scorer.

Wires the Phase 4 analysis pipeline:
    sanitize -> keyword regex -> link heuristics -> VirusTotal (cache-first)
    -> deterministic aggregation -> verdict.
"""
from __future__ import annotations

import asyncio
import logging

from fastapi import Depends, FastAPI
from sqlalchemy.orm import Session

from database import get_db
from heuristics import (
    check_attachment_filename,
    check_link_heuristics,
    check_sender_mismatch,
    extract_sender_domain,
    sanitize_text,
    scan_keywords,
)
from models import ScansHistory
from schemas import AnalysisResponse, EmailAnalysisRequest, Verdict
from stats import router as stats_router
from virustotal import (
    IndicatorResult,
    check_files_indicators_async,
    check_urls_indicators_async,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("scorer")

app = FastAPI(
    title="Malicious Email Scorer",
    version="0.3.0",
    description="Deterministic phishing/maliciousness scorer for the Gmail Add-on.",
)

# Admin aggregation endpoint (Stage 2) — feeds the Streamlit dashboard.
app.include_router(stats_router)

# Scoring weights (PLAN.MD §4). VT-confirmed (>= threshold) is an absolute
# override -> 100. VT-isolated (1-2 vendor hits) is suspicious-but-additive.
LINK_HEURISTIC_POINTS = 30
KEYWORD_POINTS = 30
SENDER_MISMATCH_POINTS = 20
ATTACHMENT_HEURISTIC_POINTS = 30
VT_ISOLATED_POINTS = 40

# 5-level risk spectrum (inclusive upper bounds).
SAFE_MAX = 20
LOW_RISK_MAX = 40
SUSPICIOUS_MAX = 60
HIGH_RISK_MAX = 80

# ScansHistory.sender_domain is String(255); clip defensively at the boundary.
MAX_LOGGED_DOMAIN_LEN = 255

# Abstracted, user-facing labels (never leak raw regex tokens or keywords).
REASON_KEYWORDS = "Deceptive language patterns detected"
REASON_LINKS = "Suspicious link structures identified"
REASON_SENDER = "Sender identity does not match displayed brand"
REASON_VT_CONFIRMED_URL = "Multiple threat intelligence sources flagged a malicious URL"
REASON_VT_CONFIRMED_FILE = "Multiple threat intelligence sources flagged a malicious file hash"
REASON_VT_ISOLATED_URL = "Potential URL threat identified by isolated source"
REASON_VT_ISOLATED_FILE = "Potential file hash threat identified by isolated source"
REASON_ATTACHMENT_HEUR = "Dangerous file type detected in attachments"
REASON_VT_UNAVAILABLE = "Threat intelligence service unavailable"
# Polished single-line summary shown when nothing fires (SAFE/0).
REASON_CLEAN_SAFE = (
    "Security scan complete. No known threats or suspicious patterns "
    "were identified in this email."
)

VERDICT_ACTIONS: dict[str, str] = {
    "Safe": "This email appears safe.",
    "Low Risk": "Minor risk indicators present. Stay alert.",
    "Suspicious": "Exercise caution before clicking links or sharing information.",
    "High Risk": "Likely phishing. Avoid clicking links or replying.",
    "Malicious": "Do not interact with this email.",
}


async def _run_vt_batches(
    db: Session, urls: list[str], hashes: list[str]
) -> tuple[list[IndicatorResult], list[IndicatorResult]]:
    """Run URL and file-hash VT batches inside a single event loop.

    `asyncio.gather` lets the two batches' network I/O overlap, so total
    latency stays close to max(url_batch, file_batch) rather than the sum.
    Each batch independently does cache-first + concurrent gather + commit.
    """
    return await asyncio.gather(
        check_urls_indicators_async(db, urls),
        check_files_indicators_async(db, hashes),
    )


def _verdict_for_score(score: int) -> Verdict:
    if score <= SAFE_MAX:
        return "Safe"
    if score <= LOW_RISK_MAX:
        return "Low Risk"
    if score <= SUSPICIOUS_MAX:
        return "Suspicious"
    if score <= HIGH_RISK_MAX:
        return "High Risk"
    return "Malicious"


@app.post("/api/analyze", response_model=AnalysisResponse)
def analyze_email(
    payload: EmailAnalysisRequest,
    db: Session = Depends(get_db),
) -> AnalysisResponse:
    logger.info(
        "POST /api/analyze: subject_len=%d body_len=%d link_count=%d att_count=%d",
        len(payload.subject), len(payload.body),
        len(payload.links), len(payload.attachments),
    )

    # Rule 0: sanitize HTML/scripts before any regex sees the text.
    clean_text = sanitize_text(payload.subject) + "\n" + sanitize_text(payload.body)

    # Rule 3 (PLAN.MD §4): keyword regex on sanitized text.
    keyword_hits = scan_keywords(clean_text)

    # Rule 2: link heuristics on every URL.
    heuristic_hits: dict[str, list[str]] = {}
    for url in payload.links:
        labels = check_link_heuristics(url)
        if labels:
            heuristic_hits[url] = labels

    # Rule 5: filename heuristics (dangerous + double-extension).
    attachment_hits: dict[str, list[str]] = {}
    for att in payload.attachments:
        labels = check_attachment_filename(att.name)
        if labels:
            attachment_hits[att.name] = labels

    # Rule 1 & 6: VirusTotal — concurrent batch for URLs AND file hashes.
    # Two batches share the same event loop run; their network I/O overlaps,
    # so adding the file-hash check doesn't sequentially extend latency.
    file_hashes = [att.sha256 for att in payload.attachments]
    vt_url_results, vt_file_results = asyncio.run(
        _run_vt_batches(db, payload.links, file_hashes)
    )
    # Confirmed vs. isolated VT signals — see virustotal.VT_CONFIRMED_THRESHOLD.
    vt_confirmed_urls = [r.indicator for r in vt_url_results if r.is_confirmed]
    vt_isolated_urls = [r.indicator for r in vt_url_results if r.is_isolated]
    vt_confirmed_hashes = [r.indicator for r in vt_file_results if r.is_confirmed]
    vt_isolated_hashes = [r.indicator for r in vt_file_results if r.is_isolated]
    vt_errors = sorted({
        r.error for r in (*vt_url_results, *vt_file_results) if r.error
    })

    # Rule 4: sender display-name brand impersonation.
    mismatch_hits = check_sender_mismatch(payload.sender)
    sender_domain = extract_sender_domain(payload.sender)

    # --- Aggregation ---
    reasoning_parts: list[str] = []

    # Override per PLAN.MD §4: a CONFIRMED VT verdict (>= threshold vendors
    # agreeing) on any URL or file hash forces 100/Malicious. Isolated
    # signals (1-2 vendors) drop to the additive branch below.
    if vt_confirmed_urls or vt_confirmed_hashes:
        score = 100
        verdict: Verdict = "Malicious"
        if vt_confirmed_urls:
            reasoning_parts.append(REASON_VT_CONFIRMED_URL)
        if vt_confirmed_hashes:
            reasoning_parts.append(REASON_VT_CONFIRMED_FILE)
    else:
        score = 0
        if heuristic_hits:
            score += LINK_HEURISTIC_POINTS
            reasoning_parts.append(REASON_LINKS)
        if keyword_hits:
            score += KEYWORD_POINTS
            reasoning_parts.append(REASON_KEYWORDS)
        if mismatch_hits:
            score += SENDER_MISMATCH_POINTS
            reasoning_parts.append(REASON_SENDER)
        if attachment_hits:
            score += ATTACHMENT_HEURISTIC_POINTS
            reasoning_parts.append(REASON_ATTACHMENT_HEUR)
        # Isolated VT signals are suspicious-but-additive: a single obscure
        # vendor hit can't force "Malicious" on its own, but combined with
        # any other signal it pushes into the High Risk / Malicious bands.
        if vt_isolated_urls:
            score += VT_ISOLATED_POINTS
            reasoning_parts.append(REASON_VT_ISOLATED_URL)
        if vt_isolated_hashes:
            score += VT_ISOLATED_POINTS
            reasoning_parts.append(REASON_VT_ISOLATED_FILE)
        score = min(score, 100)
        verdict = _verdict_for_score(score)

    if vt_errors and not vt_confirmed_urls and not vt_confirmed_hashes:
        reasoning_parts.append(REASON_VT_UNAVAILABLE)

    if reasoning_parts:
        # Append the verdict-specific action line only when there's something
        # to act on. A truly-clean SAFE email gets a single polished summary
        # instead of a redundant two-line ("nothing detected" + "appears safe").
        reasoning_parts.append(VERDICT_ACTIONS[verdict])
    else:
        reasoning_parts.append(REASON_CLEAN_SAFE)

    reasoning_text = " | ".join(reasoning_parts)

    # PII-safe scan logging (PLAN.MD §5): only the sender's domain.
    db.add(
        ScansHistory(
            sender_domain=(sender_domain or "unknown")[:MAX_LOGGED_DOMAIN_LEN],
            final_score=score,
            trigger_reason=reasoning_text,
        )
    )
    db.commit()

    logger.info(
        "Analyzed: score=%d verdict=%s kw=%d heur_urls=%d mismatch=%d "
        "att_heur=%d vt_conf_url=%d vt_iso_url=%d vt_conf_file=%d vt_iso_file=%d vt_err=%d",
        score, verdict, len(keyword_hits), len(heuristic_hits),
        len(mismatch_hits), len(attachment_hits),
        len(vt_confirmed_urls), len(vt_isolated_urls),
        len(vt_confirmed_hashes), len(vt_isolated_hashes), len(vt_errors),
    )

    return AnalysisResponse(
        score=score,
        verdict=verdict,
        reasoning=reasoning_text,
    )
